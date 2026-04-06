//! Admin API endpoints for server management.
//!
//! Provides user management, blob management, server statistics, and
//! per-user quota CRUD. All admin endpoints require authentication and
//! the `Admin` access control action.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, put},
    Json, Router,
};
use serde::Deserialize;
use tracing::instrument;

use super::{error_json, extract_auth_event, verify_auth_event, SharedState};
use crate::access::Action;

/// Build the admin router. Mount at `/admin` alongside the main router.
///
/// All endpoints require auth with the `Admin` action in access control.
pub fn admin_router(state: SharedState) -> Router {
    Router::new()
        .route("/admin/stats", get(handle_admin_stats))
        .route("/admin/users", get(handle_list_users))
        .route("/admin/users/:pubkey", get(handle_get_user))
        .route("/admin/users/:pubkey/quota", put(handle_set_quota))
        .route("/admin/users/:pubkey/role", put(handle_set_role))
        .route("/admin/roles", get(handle_list_roles))
        .route("/admin/blobs", get(handle_list_all_blobs))
        .route("/admin/blobs/:sha256", delete(handle_admin_delete_blob))
        .route("/admin/whitelist", get(handle_whitelist_list))
        .route(
            "/admin/whitelist/:pubkey",
            put(handle_whitelist_add).delete(handle_whitelist_remove),
        )
        .with_state(state)
}

/// Extract and verify admin auth — requires valid auth + Admin action.
fn extract_admin_pubkey(
    headers: &HeaderMap,
    access: &dyn crate::access::AccessControl,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let event = extract_auth_event(headers)
        .map_err(|e| (StatusCode::UNAUTHORIZED, error_json(&e.to_string())))?;

    verify_auth_event(&event, None)
        .map_err(|e| (StatusCode::UNAUTHORIZED, error_json(&e.to_string())))?;

    if !access.is_allowed(&event.pubkey, Action::Admin) {
        return Err((StatusCode::FORBIDDEN, error_json("admin access required")));
    }

    Ok(event.pubkey)
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

#[instrument(name = "admin.stats", skip_all)]
async fn handle_admin_stats(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let s = state.lock().await;
    if let Err(e) = extract_admin_pubkey(&headers, &*s.access) {
        return e;
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "blobs": s.backend.len(),
            "total_bytes": s.backend.total_bytes(),
            "uploads": s.database.upload_count(),
            "users": s.database.user_count(),
            "tracked_stats": s.stats.tracked_count(),
        })),
    )
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

#[instrument(name = "admin.list_users", skip_all)]
async fn handle_list_users(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let s = state.lock().await;
    if let Err(e) = extract_admin_pubkey(&headers, &*s.access) {
        return e;
    }

    // Return user count — full user listing would require a new trait method.
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "user_count": s.database.user_count(),
        })),
    )
}

#[instrument(name = "admin.get_user", skip_all, fields(user.pubkey = %pubkey))]
async fn handle_get_user(
    State(state): State<SharedState>,
    Path(pubkey): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let mut s = state.lock().await;
    if let Err(e) = extract_admin_pubkey(&headers, &*s.access) {
        return e;
    }

    match s.database.get_or_create_user(&pubkey) {
        Ok(user) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "pubkey": user.pubkey,
                "quota_bytes": user.quota_bytes,
                "used_bytes": user.used_bytes,
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            error_json(&e.to_string()),
        ),
    }
}

#[derive(Deserialize)]
struct SetQuotaRequest {
    /// Quota in bytes. `null` means unlimited.
    quota_bytes: Option<u64>,
}

#[instrument(name = "admin.set_quota", skip_all, fields(user.pubkey = %pubkey))]
async fn handle_set_quota(
    State(state): State<SharedState>,
    Path(pubkey): Path<String>,
    headers: HeaderMap,
    Json(req): Json<SetQuotaRequest>,
) -> impl IntoResponse {
    let mut s = state.lock().await;
    if let Err(e) = extract_admin_pubkey(&headers, &*s.access) {
        return e;
    }

    match s.database.set_quota(&pubkey, req.quota_bytes) {
        Ok(()) => {
            tracing::info!(
                user.pubkey = %pubkey,
                quota_bytes = ?req.quota_bytes,
                "quota updated"
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "pubkey": pubkey,
                    "quota_bytes": req.quota_bytes,
                })),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            error_json(&e.to_string()),
        ),
    }
}

// ---------------------------------------------------------------------------
// Blobs
// ---------------------------------------------------------------------------

#[instrument(name = "admin.list_blobs", skip_all)]
async fn handle_list_all_blobs(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let s = state.lock().await;
    if let Err(e) = extract_admin_pubkey(&headers, &*s.access) {
        return e;
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "blob_count": s.backend.len(),
            "total_bytes": s.backend.total_bytes(),
        })),
    )
}

#[instrument(name = "admin.delete_blob", skip_all, fields(blob.sha256 = %sha256))]
async fn handle_admin_delete_blob(
    State(state): State<SharedState>,
    Path(sha256): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let mut s = state.lock().await;
    if let Err(e) = extract_admin_pubkey(&headers, &*s.access) {
        return e;
    }

    if s.backend.delete(&sha256) {
        let _ = s.database.delete_upload(&sha256);
        tracing::info!(blob.sha256 = %sha256, "admin deleted blob");
        (StatusCode::OK, Json(serde_json::json!({"deleted": true})))
    } else {
        (StatusCode::NOT_FOUND, error_json("blob not found"))
    }
}

// ---------------------------------------------------------------------------
// Whitelist management
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Role management
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct SetRoleRequest {
    role: String,
}

#[instrument(name = "admin.set_role", skip_all, fields(target.pubkey = %pubkey))]
async fn handle_set_role(
    State(state): State<SharedState>,
    Path(pubkey): Path<String>,
    headers: HeaderMap,
    Json(body): Json<SetRoleRequest>,
) -> impl IntoResponse {
    let mut s = state.lock().await;
    if let Err(e) = extract_admin_pubkey(&headers, &*s.access) {
        return e;
    }

    let normalized = crate::access::normalize_pubkey(&pubkey).unwrap_or(pubkey);
    let role = body.role.to_lowercase();
    if !matches!(role.as_str(), "admin" | "member" | "denied") {
        return (
            StatusCode::BAD_REQUEST,
            error_json("role must be 'admin', 'member', or 'denied'"),
        );
    }

    if let Err(e) = s.database.set_role(&normalized, &role) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            error_json(&format!("set role: {e}")),
        );
    }

    tracing::info!(target.pubkey = %normalized, role = %role, "role updated via admin API");
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "pubkey": normalized,
            "role": role,
        })),
    )
}

#[instrument(name = "admin.list_roles", skip_all)]
async fn handle_list_roles(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let s = state.lock().await;
    if let Err(e) = extract_admin_pubkey(&headers, &*s.access) {
        return e;
    }

    let admins = s
        .database
        .list_users_by_role("admin")
        .unwrap_or_default()
        .into_iter()
        .map(|u| u.pubkey)
        .collect::<Vec<_>>();
    let members = s
        .database
        .list_users_by_role("member")
        .unwrap_or_default()
        .into_iter()
        .map(|u| u.pubkey)
        .collect::<Vec<_>>();
    let denied = s
        .database
        .list_users_by_role("denied")
        .unwrap_or_default()
        .into_iter()
        .map(|u| u.pubkey)
        .collect::<Vec<_>>();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "admins": admins,
            "members": members,
            "denied": denied,
        })),
    )
}

// ---------------------------------------------------------------------------
// Whitelist management
// ---------------------------------------------------------------------------

#[instrument(name = "admin.whitelist_list", skip_all)]
async fn handle_whitelist_list(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let s = state.lock().await;
    if let Err(e) = extract_admin_pubkey(&headers, &*s.access) {
        return e;
    }

    match &s.whitelist {
        Some(wl) => {
            let keys: Vec<String> = wl.list().await;
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "count": keys.len(),
                    "pubkeys": keys,
                })),
            )
        }
        None => (StatusCode::NOT_FOUND, error_json("no whitelist configured")),
    }
}

#[instrument(name = "admin.whitelist_add", skip_all, fields(whitelist.pubkey = %pubkey))]
async fn handle_whitelist_add(
    State(state): State<SharedState>,
    Path(pubkey): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let s = state.lock().await;
    if let Err(e) = extract_admin_pubkey(&headers, &*s.access) {
        return e;
    }

    match &s.whitelist {
        Some(wl) => {
            wl.add(pubkey.clone()).await;
            tracing::info!(whitelist.pubkey = %pubkey, "pubkey added to whitelist");
            (StatusCode::OK, Json(serde_json::json!({"added": pubkey})))
        }
        None => (StatusCode::NOT_FOUND, error_json("no whitelist configured")),
    }
}

#[instrument(name = "admin.whitelist_remove", skip_all, fields(whitelist.pubkey = %pubkey))]
async fn handle_whitelist_remove(
    State(state): State<SharedState>,
    Path(pubkey): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let s = state.lock().await;
    if let Err(e) = extract_admin_pubkey(&headers, &*s.access) {
        return e;
    }

    match &s.whitelist {
        Some(wl) => {
            wl.remove(&pubkey).await;
            tracing::info!(whitelist.pubkey = %pubkey, "pubkey removed from whitelist");
            (StatusCode::OK, Json(serde_json::json!({"removed": pubkey})))
        }
        None => (StatusCode::NOT_FOUND, error_json("no whitelist configured")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::{AccessControl, Action, Whitelist};
    use crate::auth::{auth_header_value, build_blossom_auth, Signer};
    use crate::db::MemoryDatabase;
    use crate::server::nip96::nip96_router;
    use crate::storage::MemoryBackend;
    use crate::{BlobServer, BlossomSigner};
    use std::collections::HashSet;

    async fn spawn_admin_server() -> (String, Signer) {
        let admin_signer = Signer::generate();
        let admin_pubkey = admin_signer.public_key_hex();

        // Whitelist with admin pubkey.
        let mut keys = HashSet::new();
        keys.insert(admin_pubkey);
        let whitelist = Whitelist::new(keys);

        let server = BlobServer::builder(MemoryBackend::new(), "http://localhost:3000")
            .database(MemoryDatabase::new())
            .access_control(whitelist)
            .require_auth()
            .build();
        let state = server.shared_state();
        let app = server
            .router()
            .merge(nip96_router(state.clone()))
            .merge(admin_router(state));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{}", addr);
        tokio::spawn(async move { axum::serve(listener, app).await.ok() });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        (url, admin_signer)
    }

    fn admin_auth(signer: &Signer) -> String {
        let event = build_blossom_auth(signer, "admin", None, None, "");
        auth_header_value(&event)
    }

    #[tokio::test]
    async fn test_admin_stats() {
        let (url, signer) = spawn_admin_server().await;
        let http = reqwest::Client::new();

        let resp = http
            .get(format!("{}/admin/stats", url))
            .header("Authorization", admin_auth(&signer))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["blobs"], 0);
    }

    #[tokio::test]
    async fn test_admin_requires_auth() {
        let (url, _signer) = spawn_admin_server().await;
        let http = reqwest::Client::new();

        let resp = http
            .get(format!("{}/admin/stats", url))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn test_admin_non_admin_rejected() {
        let (url, _signer) = spawn_admin_server().await;
        let http = reqwest::Client::new();

        // Use a different signer not in the whitelist.
        let other = Signer::generate();
        let resp = http
            .get(format!("{}/admin/stats", url))
            .header("Authorization", admin_auth(&other))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403);
    }

    #[tokio::test]
    async fn test_admin_set_and_get_quota() {
        let (url, signer) = spawn_admin_server().await;
        let http = reqwest::Client::new();
        let target_pubkey = "a".repeat(64);

        // Set quota.
        let resp = http
            .put(format!("{}/admin/users/{}/quota", url, target_pubkey))
            .header("Authorization", admin_auth(&signer))
            .json(&serde_json::json!({"quota_bytes": 1048576}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["quota_bytes"], 1048576);

        // Get user.
        let resp = http
            .get(format!("{}/admin/users/{}", url, target_pubkey))
            .header("Authorization", admin_auth(&signer))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["quota_bytes"], 1048576);
        assert_eq!(body["used_bytes"], 0);
    }

    #[tokio::test]
    async fn test_admin_delete_blob() {
        let (url, signer) = spawn_admin_server().await;
        let http = reqwest::Client::new();

        // Upload a blob (with auth since require_auth is on).
        let data = b"admin delete test";
        let upload_event = build_blossom_auth(&signer, "upload", None, None, "");
        let auth = auth_header_value(&upload_event);
        let resp = http
            .put(format!("{}/upload", url))
            .header("Authorization", &auth)
            .body(data.to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let desc: serde_json::Value = resp.json().await.unwrap();
        let sha = desc["sha256"].as_str().unwrap();

        // Admin delete.
        let resp = http
            .delete(format!("{}/admin/blobs/{}", url, sha))
            .header("Authorization", admin_auth(&signer))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        // Verify gone.
        let resp = http.head(format!("{}/{}", url, sha)).send().await.unwrap();
        assert_eq!(resp.status(), 404);
    }
}
