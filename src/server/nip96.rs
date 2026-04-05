//! NIP-96 file storage protocol endpoints.
//!
//! Implements the NIP-96 specification for Nostr-native file storage:
//! - `GET /.well-known/nostr/nip96.json` — server capabilities
//! - `POST /n96` — file upload with metadata
//! - `GET /n96` — paginated file list
//! - `DELETE /n96/:sha256` — file deletion

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};

use tracing::instrument;

use super::verify_auth_event;
use super::{error_json, extract_auth_event, SharedState};
use crate::access::Action;
use crate::db::{DbError, UploadRecord};

/// NIP-96 server info response (`.well-known/nostr/nip96.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Nip96Info {
    /// URL for file uploads (POST).
    pub api_url: String,
    /// Optional download URL prefix.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download_url: Option<String>,
    /// Supported NIP-96 features.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegated_to_url: Option<String>,
    /// Supported MIME types (empty = all).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub supported_nips: Vec<u32>,
    /// Human-readable server name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tos_url: Option<String>,
    /// Content types accepted.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub content_types: Vec<String>,
    /// Plans/tiers offered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plans: Option<serde_json::Value>,
}

/// NIP-96 file upload response.
#[derive(Debug, Serialize)]
struct Nip96UploadResponse {
    status: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    processing_url: Option<String>,
    nip94_event: Nip94Event,
}

/// NIP-94 event tags for a file.
#[derive(Debug, Serialize)]
struct Nip94Event {
    tags: Vec<Vec<String>>,
    content: String,
}

/// Query parameters for NIP-96 file list.
#[derive(Debug, Deserialize)]
pub struct Nip96ListQuery {
    /// Page number (1-based).
    #[serde(default = "default_page")]
    pub page: u32,
    /// Items per page.
    #[serde(default = "default_count")]
    pub count: u32,
}

fn default_page() -> u32 {
    1
}
fn default_count() -> u32 {
    50
}

/// Build the NIP-96 router. Mount this alongside the main Blossom router.
pub fn nip96_router(state: SharedState) -> Router {
    Router::new()
        .route("/.well-known/nostr/nip96.json", get(handle_nip96_info))
        .route("/n96", post(handle_nip96_upload).get(handle_nip96_list))
        .route("/n96/:sha256", delete(handle_nip96_delete))
        .with_state(state)
        .layer(axum::extract::DefaultBodyLimit::max(256 * 1024 * 1024))
}

#[instrument(name = "nip96.info", skip_all)]
async fn handle_nip96_info(State(state): State<SharedState>) -> impl IntoResponse {
    let s = state.lock().await;
    let info = Nip96Info {
        api_url: format!("{}/n96", s.base_url),
        download_url: Some(s.base_url.clone()),
        delegated_to_url: None,
        supported_nips: vec![96, 98],
        tos_url: None,
        content_types: s.requirements.allowed_types.clone(),
        plans: None,
    };
    Json(info)
}

#[instrument(name = "nip96.upload", skip_all, fields(blob.size, blob.sha256, auth.pubkey))]
async fn handle_nip96_upload(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let data = body.to_vec();
    if data.is_empty() {
        return (StatusCode::BAD_REQUEST, error_json("empty body"));
    }

    // NIP-96 requires NIP-98 auth (kind:27235) or Blossom auth (kind:24242).
    // We support Blossom auth for simplicity.
    let pubkey = match extract_auth_event(&headers) {
        Ok(event) => {
            if let Err(e) = verify_auth_event(&event, Some("upload")) {
                return (StatusCode::UNAUTHORIZED, error_json(&e.to_string()));
            }
            event.pubkey
        }
        Err(e) => {
            return (StatusCode::UNAUTHORIZED, error_json(&e.to_string()));
        }
    };

    let mut s = state.lock().await;

    // Size check.
    if let Some(max) = s.requirements.max_size {
        if data.len() as u64 > max {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                error_json(&format!("exceeds max size of {} bytes", max)),
            );
        }
    }

    // Access control.
    if !s.access.is_allowed(&pubkey, Action::Upload) {
        return (StatusCode::FORBIDDEN, error_json("upload not allowed"));
    }

    // Quota check.
    if let Err(DbError::QuotaExceeded {
        used,
        requested,
        limit,
    }) = s.database.check_quota(&pubkey, data.len() as u64)
    {
        return (
            StatusCode::INSUFFICIENT_STORAGE,
            error_json(&format!(
                "quota exceeded: {} + {} > {}",
                used, requested, limit
            )),
        );
    }

    let base_url = s.base_url.clone();
    let descriptor = s.backend.insert(data, &base_url);

    // Record in database.
    let record = UploadRecord {
        sha256: descriptor.sha256.clone(),
        size: descriptor.size,
        mime_type: descriptor
            .content_type
            .clone()
            .unwrap_or_else(|| "application/octet-stream".to_string()),
        pubkey,
        created_at: descriptor.uploaded.unwrap_or(0),
        phash: None,
    };
    let _ = s.database.record_upload(&record);

    let url = descriptor
        .url
        .clone()
        .unwrap_or_else(|| format!("{}/{}", base_url, descriptor.sha256));

    let response = Nip96UploadResponse {
        status: "success".to_string(),
        message: "Upload successful".to_string(),
        processing_url: None,
        nip94_event: Nip94Event {
            tags: vec![
                vec!["url".to_string(), url],
                vec![
                    "ox".to_string(),
                    descriptor.sha256.clone(),
                    format!("{}/{}", base_url, descriptor.sha256),
                ],
                vec!["x".to_string(), descriptor.sha256],
                vec!["size".to_string(), descriptor.size.to_string()],
                vec!["m".to_string(), record.mime_type],
            ],
            content: String::new(),
        },
    };

    (
        StatusCode::OK,
        Json(serde_json::to_value(response).unwrap()),
    )
}

#[instrument(name = "nip96.list", skip_all, fields(auth.pubkey))]
async fn handle_nip96_list(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(params): Query<Nip96ListQuery>,
) -> impl IntoResponse {
    // List requires auth to identify the user.
    let pubkey = match extract_auth_event(&headers) {
        Ok(event) => {
            if let Err(e) = verify_auth_event(&event, Some("get")) {
                return (StatusCode::UNAUTHORIZED, error_json(&e.to_string()));
            }
            event.pubkey
        }
        Err(e) => {
            return (StatusCode::UNAUTHORIZED, error_json(&e.to_string()));
        }
    };

    let s = state.lock().await;

    match s.database.list_uploads_by_pubkey(&pubkey) {
        Ok(records) => {
            let total = records.len();
            let start = ((params.page.saturating_sub(1)) * params.count) as usize;
            let page_records: Vec<_> = records
                .into_iter()
                .skip(start)
                .take(params.count as usize)
                .collect();

            let files: Vec<serde_json::Value> = page_records
                .into_iter()
                .map(|r| {
                    serde_json::json!({
                        "tags": [
                            ["url", format!("{}/{}", s.base_url, r.sha256)],
                            ["ox", r.sha256, format!("{}/{}", s.base_url, r.sha256)],
                            ["size", r.size.to_string()],
                            ["m", r.mime_type],
                        ],
                        "content": "",
                        "created_at": r.created_at,
                    })
                })
                .collect();

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "count": files.len(),
                    "total": total,
                    "page": params.page,
                    "files": files,
                })),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            error_json(&e.to_string()),
        ),
    }
}

#[instrument(name = "nip96.delete", skip_all, fields(blob.sha256 = %sha256))]
async fn handle_nip96_delete(
    State(state): State<SharedState>,
    Path(sha256): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let pubkey = match extract_auth_event(&headers) {
        Ok(event) => {
            if let Err(e) = verify_auth_event(&event, Some("delete")) {
                return (StatusCode::UNAUTHORIZED, error_json(&e.to_string()));
            }
            event.pubkey
        }
        Err(e) => {
            return (StatusCode::UNAUTHORIZED, error_json(&e.to_string()));
        }
    };

    let mut s = state.lock().await;

    if !s.access.is_allowed(&pubkey, Action::Delete) {
        return (StatusCode::FORBIDDEN, error_json("delete not allowed"));
    }

    if s.backend.delete(&sha256) {
        let _ = s.database.delete_upload(&sha256);
        (
            StatusCode::OK,
            Json(serde_json::json!({"status": "success", "message": "File deleted"})),
        )
    } else {
        (StatusCode::NOT_FOUND, error_json("file not found"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::BlobServer;
    use crate::storage::MemoryBackend;

    async fn spawn_nip96_server() -> String {
        let server = BlobServer::new(MemoryBackend::new(), "http://localhost:3000");
        let state = server.shared_state();
        let app = server.router().merge(nip96_router(state));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{}", addr);
        tokio::spawn(async move { axum::serve(listener, app).await.ok() });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        url
    }

    #[tokio::test]
    async fn test_nip96_info() {
        let url = spawn_nip96_server().await;
        let http = reqwest::Client::new();

        let resp = http
            .get(format!("{}/.well-known/nostr/nip96.json", url))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let info: Nip96Info = resp.json().await.unwrap();
        assert!(info.api_url.contains("/n96"));
        assert!(info.supported_nips.contains(&96));
    }

    #[tokio::test]
    async fn test_nip96_upload_requires_auth() {
        let url = spawn_nip96_server().await;
        let http = reqwest::Client::new();

        let resp = http
            .post(format!("{}/n96", url))
            .body(b"test data".to_vec())
            .send()
            .await
            .unwrap();
        // Should fail without auth.
        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn test_nip96_upload_with_auth() {
        let url = spawn_nip96_server().await;
        let http = reqwest::Client::new();
        let signer = crate::auth::Signer::generate();

        let data = b"nip96 test blob";
        let auth_event = crate::auth::build_blossom_auth(
            &signer,
            "upload",
            Some(&crate::protocol::sha256_hex(data)),
            None,
            "",
        );
        let auth_header = crate::auth::auth_header_value(&auth_event);

        let resp = http
            .post(format!("{}/n96", url))
            .header("Authorization", &auth_header)
            .body(data.to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["status"], "success");
        assert!(!body["nip94_event"]["tags"].as_array().unwrap().is_empty());
    }

    /// Helper to upload a blob via NIP-96 with auth, returning the sha256.
    async fn nip96_upload(
        http: &reqwest::Client,
        url: &str,
        signer: &crate::auth::Signer,
        data: &[u8],
    ) -> String {
        let auth_event = crate::auth::build_blossom_auth(
            signer,
            "upload",
            Some(&crate::protocol::sha256_hex(data)),
            None,
            "",
        );
        let auth_header = crate::auth::auth_header_value(&auth_event);

        let resp = http
            .post(format!("{}/n96", url))
            .header("Authorization", &auth_header)
            .body(data.to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        // Extract sha256 from the "x" tag.
        let tags = body["nip94_event"]["tags"].as_array().unwrap();
        tags.iter().find(|t| t[0] == "x").unwrap()[1]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn test_nip96_upload_list_delete_lifecycle() {
        let url = spawn_nip96_server().await;
        let http = reqwest::Client::new();
        let signer = crate::auth::Signer::generate();

        // Upload two blobs.
        let sha1 = nip96_upload(&http, &url, &signer, b"blob one").await;
        let sha2 = nip96_upload(&http, &url, &signer, b"blob two").await;
        assert_ne!(sha1, sha2);

        // List — requires auth with "get" action.
        let list_event = crate::auth::build_blossom_auth(&signer, "get", None, None, "");
        let list_header = crate::auth::auth_header_value(&list_event);

        let resp = http
            .get(format!("{}/n96", url))
            .header("Authorization", &list_header)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["total"], 2);
        assert_eq!(body["files"].as_array().unwrap().len(), 2);

        // Delete one.
        let del_event = crate::auth::build_blossom_auth(&signer, "delete", None, None, "");
        let del_header = crate::auth::auth_header_value(&del_event);

        let resp = http
            .delete(format!("{}/n96/{}", url, sha1))
            .header("Authorization", &del_header)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["status"], "success");

        // Delete nonexistent.
        let del_event2 = crate::auth::build_blossom_auth(&signer, "delete", None, None, "");
        let del_header2 = crate::auth::auth_header_value(&del_event2);

        let resp = http
            .delete(format!("{}/n96/{}", url, "0".repeat(64)))
            .header("Authorization", &del_header2)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 404);
    }

    #[tokio::test]
    async fn test_nip96_empty_upload_rejected() {
        let url = spawn_nip96_server().await;
        let http = reqwest::Client::new();
        let signer = crate::auth::Signer::generate();

        let auth_event = crate::auth::build_blossom_auth(&signer, "upload", None, None, "");
        let auth_header = crate::auth::auth_header_value(&auth_event);

        let resp = http
            .post(format!("{}/n96", url))
            .header("Authorization", &auth_header)
            .body(Vec::<u8>::new())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400);
    }

    #[tokio::test]
    async fn test_nip96_list_requires_auth() {
        let url = spawn_nip96_server().await;
        let http = reqwest::Client::new();

        let resp = http.get(format!("{}/n96", url)).send().await.unwrap();
        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn test_nip96_delete_requires_auth() {
        let url = spawn_nip96_server().await;
        let http = reqwest::Client::new();

        let resp = http
            .delete(format!("{}/n96/{}", url, "a".repeat(64)))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn test_nip96_list_pagination() {
        let url = spawn_nip96_server().await;
        let http = reqwest::Client::new();
        let signer = crate::auth::Signer::generate();

        // Upload 5 blobs.
        for i in 0u8..5 {
            nip96_upload(&http, &url, &signer, &[i; 20]).await;
        }

        let list_event = crate::auth::build_blossom_auth(&signer, "get", None, None, "");
        let list_header = crate::auth::auth_header_value(&list_event);

        // Page 1, count 2.
        let resp = http
            .get(format!("{}/n96?page=1&count=2", url))
            .header("Authorization", &list_header)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["total"], 5);
        assert_eq!(body["files"].as_array().unwrap().len(), 2);
        assert_eq!(body["page"], 1);
    }

    #[tokio::test]
    async fn test_nip96_size_limit() {
        let server = BlobServer::builder(MemoryBackend::new(), "http://localhost:3000")
            .max_upload_size(10)
            .build();
        let state = server.shared_state();
        let app = server.router().merge(nip96_router(state));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{}", addr);
        tokio::spawn(async move { axum::serve(listener, app).await.ok() });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let http = reqwest::Client::new();
        let signer = crate::auth::Signer::generate();

        let data = b"this exceeds 10 bytes limit!";
        let auth_event = crate::auth::build_blossom_auth(
            &signer,
            "upload",
            Some(&crate::protocol::sha256_hex(data)),
            None,
            "",
        );
        let auth_header = crate::auth::auth_header_value(&auth_event);

        let resp = http
            .post(format!("{}/n96", url))
            .header("Authorization", &auth_header)
            .body(data.to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 413);
    }
}
