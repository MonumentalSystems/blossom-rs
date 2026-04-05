//! Embeddable Blossom server (BUD-01 compliant).
//!
//! Provides an Axum router that implements the Blossom HTTP API:
//! - `PUT /upload` — upload blob, returns BlobDescriptor
//! - `GET /<sha256>` — retrieve blob by hash
//! - `HEAD /<sha256>` — check existence
//! - `DELETE /<sha256>` — remove blob (with auth verification)
//! - `GET /status` — server statistics

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, put},
    Json, Router,
};
use tokio::sync::Mutex;

use crate::auth::{verify_blossom_auth, AuthError};
use crate::protocol::{base64url_decode, NostrEvent};
use crate::storage::BlobBackend;

/// Shared server state wrapping a blob backend.
pub type SharedState = Arc<Mutex<ServerState>>;

/// Internal server state.
pub struct ServerState {
    backend: Box<dyn BlobBackend>,
    base_url: String,
    /// If true, uploads require valid kind:24242 auth. Default: false (open).
    require_auth: bool,
}

/// Embeddable Blossom server.
///
/// Create one and call `.router()` to get an Axum router you can mount.
pub struct BlobServer {
    state: SharedState,
}

impl BlobServer {
    /// Create a new server with the given backend and base URL.
    ///
    /// `base_url` is used to construct blob URLs in descriptors (e.g., `http://localhost:3000`).
    pub fn new(backend: impl BlobBackend + 'static, base_url: &str) -> Self {
        let state = Arc::new(Mutex::new(ServerState {
            backend: Box::new(backend),
            base_url: base_url.to_string(),
            require_auth: false,
        }));
        Self { state }
    }

    /// Create a new server with auth verification enabled on uploads.
    pub fn new_with_auth(backend: impl BlobBackend + 'static, base_url: &str) -> Self {
        let state = Arc::new(Mutex::new(ServerState {
            backend: Box::new(backend),
            base_url: base_url.to_string(),
            require_auth: true,
        }));
        Self { state }
    }

    /// Get a clone of the shared state (for custom extensions).
    pub fn shared_state(&self) -> SharedState {
        self.state.clone()
    }

    /// Build the Axum router for this server.
    pub fn router(&self) -> Router {
        Router::new()
            .route("/upload", put(handle_upload))
            .route(
                "/:sha256",
                get(handle_get_blob)
                    .head(handle_head_blob)
                    .delete(handle_delete_blob),
            )
            .route("/status", get(handle_status))
            .with_state(self.state.clone())
            .layer(axum::extract::DefaultBodyLimit::max(256 * 1024 * 1024))
    }
}

/// Extract and verify a Blossom auth event from the Authorization header.
fn extract_auth_event(headers: &HeaderMap) -> Result<NostrEvent, AuthError> {
    let header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(AuthError::InvalidSignature)?;

    if !header.starts_with("Nostr ") {
        return Err(AuthError::InvalidSignature);
    }

    let b64 = &header["Nostr ".len()..];
    let json_bytes = base64url_decode(b64).map_err(|_| AuthError::InvalidSignature)?;
    let event: NostrEvent =
        serde_json::from_slice(&json_bytes).map_err(|_| AuthError::InvalidSignature)?;

    Ok(event)
}

async fn handle_upload(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let data = body.to_vec();
    if data.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "empty body"})),
        );
    }

    let mut s = state.lock().await;

    if s.require_auth {
        match extract_auth_event(&headers) {
            Ok(event) => {
                if let Err(e) = verify_blossom_auth(&event, Some("upload")) {
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(serde_json::json!({"error": e.to_string()})),
                    );
                }
            }
            Err(e) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({"error": e.to_string()})),
                );
            }
        }
    }

    let base_url = s.base_url.clone();
    let descriptor = s.backend.insert(data, &base_url);

    (
        StatusCode::OK,
        Json(serde_json::to_value(descriptor).unwrap()),
    )
}

async fn handle_get_blob(
    State(state): State<SharedState>,
    Path(sha256): Path<String>,
) -> impl IntoResponse {
    let s = state.lock().await;
    match s.backend.get(&sha256) {
        Some(data) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
            data,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn handle_head_blob(
    State(state): State<SharedState>,
    Path(sha256): Path<String>,
) -> StatusCode {
    let s = state.lock().await;
    if s.backend.exists(&sha256) {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

async fn handle_delete_blob(
    State(state): State<SharedState>,
    Path(sha256): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // DELETE always requires auth.
    match extract_auth_event(&headers) {
        Ok(event) => {
            if let Err(e) = verify_blossom_auth(&event, Some("delete")) {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({"error": e.to_string()})),
                );
            }
            let mut s = state.lock().await;
            if s.backend.delete(&sha256) {
                (StatusCode::OK, Json(serde_json::json!({"deleted": true})))
            } else {
                (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({"error": "not found"})),
                )
            }
        }
        Err(_) => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "authorization required for delete"})),
        ),
    }
}

async fn handle_status(State(state): State<SharedState>) -> impl IntoResponse {
    let s = state.lock().await;
    Json(serde_json::json!({
        "blobs": s.backend.len(),
        "total_bytes": s.backend.total_bytes(),
    }))
}

// ---------------------------------------------------------------------------
// S3-compat router (for testing S3 clients against a local server)
// ---------------------------------------------------------------------------

#[cfg(feature = "s3-compat")]
pub fn build_s3_compat_router(state: SharedState) -> Router {
    Router::new()
        .route(
            "/:bucket/*key",
            put(s3_put).get(s3_get).head(s3_head).delete(s3_delete),
        )
        .with_state(state)
        .layer(axum::extract::DefaultBodyLimit::max(256 * 1024 * 1024))
}

#[cfg(feature = "s3-compat")]
async fn s3_put(
    State(state): State<SharedState>,
    Path((_bucket, key)): Path<(String, String)>,
    body: Bytes,
) -> StatusCode {
    let data = body.to_vec();
    let hash_key = key.trim_end_matches(".blob").to_string();
    let size = data.len() as u64;
    let _ = (hash_key, size); // S3 compat stores by content hash like normal
    let mut s = state.lock().await;
    let base_url = s.base_url.clone();
    let _ = s.backend.insert(data, &base_url);
    StatusCode::OK
}

#[cfg(feature = "s3-compat")]
async fn s3_get(
    State(state): State<SharedState>,
    Path((_bucket, key)): Path<(String, String)>,
) -> impl IntoResponse {
    let hash_key = key.trim_end_matches(".blob").to_string();
    let s = state.lock().await;
    match s.backend.get(&hash_key) {
        Some(data) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
            data,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[cfg(feature = "s3-compat")]
async fn s3_head(
    State(state): State<SharedState>,
    Path((_bucket, key)): Path<(String, String)>,
) -> StatusCode {
    let hash_key = key.trim_end_matches(".blob").to_string();
    let s = state.lock().await;
    if s.backend.exists(&hash_key) {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

#[cfg(feature = "s3-compat")]
async fn s3_delete(
    State(state): State<SharedState>,
    Path((_bucket, key)): Path<(String, String)>,
) -> StatusCode {
    let hash_key = key.trim_end_matches(".blob").to_string();
    let mut s = state.lock().await;
    if s.backend.delete(&hash_key) {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::BlobDescriptor;
    use crate::storage::MemoryBackend;

    fn test_server() -> BlobServer {
        BlobServer::new(MemoryBackend::new(), "http://localhost:3000")
    }

    #[tokio::test]
    async fn test_upload_and_get() {
        let server = test_server();
        let app = server.router();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{}", addr);
        tokio::spawn(async move { axum::serve(listener, app).await.ok() });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let http = reqwest::Client::new();

        let data = b"hello blossom world!";
        let resp = http
            .put(format!("{}/upload", url))
            .body(data.to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let desc: BlobDescriptor = resp.json().await.unwrap();
        assert_eq!(desc.size, 20);

        let expected_hash = crate::protocol::sha256_hex(data);
        assert_eq!(desc.sha256, expected_hash);

        let resp = http
            .get(format!("{}/{}", url, desc.sha256))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.bytes().await.unwrap();
        assert_eq!(body.as_ref(), data);
    }

    #[tokio::test]
    async fn test_head_nonexistent() {
        let server = test_server();
        let app = server.router();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{}", addr);
        tokio::spawn(async move { axum::serve(listener, app).await.ok() });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let http = reqwest::Client::new();
        let resp = http
            .head(format!(
                "{}/0000000000000000000000000000000000000000000000000000000000000000",
                url
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 404);
    }

    #[tokio::test]
    async fn test_sha256_integrity() {
        let server = test_server();
        let app = server.router();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{}", addr);
        tokio::spawn(async move { axum::serve(listener, app).await.ok() });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let http = reqwest::Client::new();

        let data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        let expected_hash = crate::protocol::sha256_hex(&data);

        let resp = http
            .put(format!("{}/upload", url))
            .body(data.clone())
            .send()
            .await
            .unwrap();
        let desc: BlobDescriptor = resp.json().await.unwrap();
        assert_eq!(desc.sha256, expected_hash);

        let downloaded = http
            .get(format!("{}/{}", url, expected_hash))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        let actual_hash = crate::protocol::sha256_hex(&downloaded);
        assert_eq!(actual_hash, expected_hash);
    }

    #[tokio::test]
    async fn test_status_endpoint() {
        let server = test_server();
        let app = server.router();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{}", addr);
        tokio::spawn(async move { axum::serve(listener, app).await.ok() });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let http = reqwest::Client::new();

        // Empty initially.
        let resp = http.get(format!("{}/status", url)).send().await.unwrap();
        let status: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(status["blobs"], 0);

        // Upload something.
        http.put(format!("{}/upload", url))
            .body(b"test".to_vec())
            .send()
            .await
            .unwrap();

        let resp = http.get(format!("{}/status", url)).send().await.unwrap();
        let status: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(status["blobs"], 1);
        assert_eq!(status["total_bytes"], 4);
    }
}
