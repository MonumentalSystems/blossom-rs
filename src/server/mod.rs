//! Embeddable Blossom server (BUD-01/02/04/06 compliant).
//!
//! Provides an Axum router that implements the Blossom HTTP API:
//! - `PUT /upload` — upload blob, returns BlobDescriptor (BUD-01)
//! - `GET /<sha256>` — retrieve blob by hash (BUD-01)
//! - `HEAD /<sha256>` — check existence (BUD-01)
//! - `DELETE /<sha256>` — remove blob (BUD-01, auth required)
//! - `GET /list/:pubkey` — list blobs by uploader pubkey (BUD-02)
//! - `PUT /mirror` — mirror a blob from a remote URL (BUD-04)
//! - `GET /upload-requirements` — server upload constraints (BUD-06)
//! - `GET /status` — server statistics
//!
//! NIP-96 endpoints are available via the [`nip96`] submodule.

pub mod admin;
pub mod locks;
pub mod nip96;

use std::sync::Arc;

use crate::access::{AccessControl, Action, OpenAccess, Role};
use crate::auth::{verify_blossom_auth, verify_nip98_auth, AuthError};
use crate::db::{BlobDatabase, DbError, MemoryDatabase, UploadRecord};
use crate::lfs::{compress, LfsContext, LfsFileVersion, LfsStorageType, LfsVersionDatabase};
use crate::locks::LockDatabase;
use crate::media::MediaProcessor;
use crate::protocol::{base64url_decode, BlobDescriptor, NostrEvent};
use crate::ratelimit::RateLimiter;
use crate::stats::StatsAccumulator;
use crate::storage::BlobBackend;
use crate::webhooks::{self, EventType, NoopNotifier, WebhookNotifier};
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, put},
    Json, Router,
};
use tokio::sync::Mutex;
use tracing::{info, instrument, warn};

/// Shared server state wrapping a blob backend.
pub type SharedState = Arc<Mutex<ServerState>>;

/// Upload requirements configuration (BUD-06).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct UploadRequirements {
    /// Maximum upload size in bytes. `None` means no limit (beyond body limit).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_size: Option<u64>,
    /// Allowed MIME types. Empty means all types allowed.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub allowed_types: Vec<String>,
    /// Whether authentication is required for uploads.
    pub require_auth: bool,
}

/// Internal server state.
pub struct ServerState {
    backend: Box<dyn BlobBackend>,
    database: Box<dyn BlobDatabase>,
    access: Box<dyn AccessControl>,
    /// Live whitelist handle for runtime add/remove (if whitelist is in use).
    pub whitelist: Option<Arc<crate::access::Whitelist>>,
    stats: StatsAccumulator,
    rate_limiter: Option<RateLimiter>,
    notifier: Box<dyn WebhookNotifier>,
    media_processor: Option<Box<dyn MediaProcessor>>,
    base_url: String,
    requirements: UploadRequirements,
    pub lock_db: Option<Box<dyn LockDatabase>>,
    pub lfs_version_db: Option<Box<dyn LfsVersionDatabase>>,
}

impl ServerState {
    /// Flush accumulated access statistics to the database.
    ///
    /// Call this periodically (e.g., every 60s) or on graceful shutdown
    /// to persist egress/access counters.
    pub fn flush_stats(&mut self) {
        self.stats.flush(&mut *self.database);
    }

    /// Replace the access control policy at runtime.
    ///
    /// Useful for hot-reloading a whitelist file without restarting.
    pub fn set_access_control(&mut self, ac: Box<dyn AccessControl>) {
        self.access = ac;
    }
}

/// Builder for configuring a BlobServer.
pub struct BlobServerBuilder {
    backend: Box<dyn BlobBackend>,
    base_url: String,
    database: Option<Box<dyn BlobDatabase>>,
    access: Option<Box<dyn AccessControl>>,
    whitelist: Option<Arc<crate::access::Whitelist>>,
    requirements: UploadRequirements,
    body_limit: usize,
    rate_limiter: Option<RateLimiter>,
    notifier: Option<Box<dyn WebhookNotifier>>,
    media_processor: Option<Box<dyn MediaProcessor>>,
    lock_db: Option<Box<dyn LockDatabase>>,
    lfs_version_db: Option<Box<dyn LfsVersionDatabase>>,
}

impl BlobServerBuilder {
    /// Set a database backend for metadata persistence.
    pub fn database(mut self, db: impl BlobDatabase + 'static) -> Self {
        self.database = Some(Box::new(db));
        self
    }

    /// Set a database backend from a boxed trait object.
    pub fn database_boxed(mut self, db: Box<dyn BlobDatabase>) -> Self {
        self.database = Some(db);
        self
    }

    /// Set an access control policy.
    pub fn access_control(mut self, ac: impl AccessControl + 'static) -> Self {
        self.access = Some(Box::new(ac));
        self
    }

    /// Set a whitelist as the access control policy with a live handle
    /// for runtime add/remove via admin endpoints.
    pub fn whitelist(mut self, wl: Arc<crate::access::Whitelist>) -> Self {
        self.access = Some(Box::new(wl.clone()));
        self.whitelist = Some(wl);
        self
    }

    /// Set a role-based access control policy with a live handle for
    /// runtime admin/member management.
    pub fn role_based_access(mut self, rba: Arc<crate::access::RoleBasedAccess>) -> Self {
        self.access = Some(Box::new(rba));
        self
    }

    /// Require auth for uploads.
    pub fn require_auth(mut self) -> Self {
        self.requirements.require_auth = true;
        self
    }

    /// Set maximum upload size in bytes.
    pub fn max_upload_size(mut self, bytes: u64) -> Self {
        self.requirements.max_size = Some(bytes);
        self
    }

    /// Set allowed MIME types for upload.
    pub fn allowed_types(mut self, types: Vec<String>) -> Self {
        self.requirements.allowed_types = types;
        self
    }

    /// Set the maximum HTTP body size in bytes (default: 256 MB).
    pub fn body_limit(mut self, bytes: usize) -> Self {
        self.body_limit = bytes;
        self
    }

    /// Set a rate limiter for request throttling.
    pub fn rate_limiter(mut self, limiter: RateLimiter) -> Self {
        self.rate_limiter = Some(limiter);
        self
    }

    /// Set a webhook notifier for blob lifecycle events.
    pub fn webhook_notifier(mut self, notifier: impl WebhookNotifier + 'static) -> Self {
        self.notifier = Some(Box::new(notifier));
        self
    }

    /// Set a media processor for image/video handling on `PUT /media` (BUD-05).
    pub fn media_processor(mut self, processor: impl MediaProcessor + 'static) -> Self {
        self.media_processor = Some(Box::new(processor));
        self
    }

    /// Set a lock database for LFS file locking (BUD-19).
    /// When set, lock API endpoints are mounted. When unset, lock endpoints
    /// return 404 (Git LFS treats this as "locking unsupported").
    pub fn lock_database(mut self, db: impl LockDatabase + 'static) -> Self {
        self.lock_db = Some(Box::new(db));
        self
    }

    /// Set an LFS version database for compression and delta encoding (BUD-20).
    /// When set, LFS-tagged uploads are compressed and delta-encoded.
    pub fn lfs_version_database(mut self, db: impl LfsVersionDatabase + 'static) -> Self {
        self.lfs_version_db = Some(Box::new(db));
        self
    }

    /// Build the BlobServer.
    pub fn build(self) -> BlobServer {
        let has_locks = self.lock_db.is_some();
        let state = Arc::new(Mutex::new(ServerState {
            backend: self.backend,
            database: self
                .database
                .unwrap_or_else(|| Box::new(MemoryDatabase::new())),
            access: self.access.unwrap_or_else(|| Box::new(OpenAccess)),
            whitelist: self.whitelist,
            stats: StatsAccumulator::new(),
            rate_limiter: self.rate_limiter,
            notifier: self.notifier.unwrap_or_else(|| Box::new(NoopNotifier)),
            media_processor: self.media_processor,
            base_url: self.base_url,
            requirements: self.requirements,
            lock_db: self.lock_db,
            lfs_version_db: self.lfs_version_db,
        }));
        BlobServer {
            state,
            body_limit: self.body_limit,
            has_locks,
        }
    }
}

/// Embeddable Blossom server.
///
/// Create one and call `.router()` to get an Axum router you can mount.
///
/// # Examples
///
/// Simple open server:
/// ```rust,ignore
/// let server = BlobServer::new(MemoryBackend::new(), "http://localhost:3000");
/// ```
///
/// Configured server with auth, quotas, and access control:
/// ```rust,ignore
/// let server = BlobServer::builder(backend, "http://localhost:3000")
///     .database(my_db)
///     .access_control(my_whitelist)
///     .require_auth()
///     .max_upload_size(50 * 1024 * 1024)
///     .build();
/// ```
pub struct BlobServer {
    state: SharedState,
    body_limit: usize,
    has_locks: bool,
}

impl BlobServer {
    /// Create a new server with the given backend and base URL.
    ///
    /// `base_url` is used to construct blob URLs in descriptors (e.g., `http://localhost:3000`).
    pub fn new(backend: impl BlobBackend + 'static, base_url: &str) -> Self {
        Self::builder(backend, base_url).build()
    }

    /// Create a new server with auth verification enabled on uploads.
    pub fn new_with_auth(backend: impl BlobBackend + 'static, base_url: &str) -> Self {
        Self::builder(backend, base_url).require_auth().build()
    }

    /// Create a builder for advanced configuration.
    pub fn builder(backend: impl BlobBackend + 'static, base_url: &str) -> BlobServerBuilder {
        BlobServerBuilder {
            backend: Box::new(backend),
            base_url: base_url.to_string(),
            database: None,
            access: None,
            whitelist: None,
            requirements: UploadRequirements::default(),
            body_limit: 256 * 1024 * 1024, // 256 MB default
            rate_limiter: None,
            notifier: None,
            media_processor: None,
            lock_db: None,
            lfs_version_db: None,
        }
    }

    /// Get a clone of the shared state (for custom extensions).
    pub fn shared_state(&self) -> SharedState {
        self.state.clone()
    }

    /// Build the Axum router for this server.
    ///
    /// The router includes a `tower_http::trace::TraceLayer` that emits
    /// structured spans for every HTTP request. When a `tracing` subscriber
    /// is configured (e.g., `tracing-opentelemetry` for OTLP export, or
    /// `tracing-subscriber` for JSON logs to Seq), each request produces
    /// spans with `http.method`, `http.route`, and `http.status_code` fields
    /// following OTEL semantic conventions.
    pub fn router(&self) -> Router {
        let mut router = Router::new()
            .route("/upload", put(handle_upload))
            .route(
                "/:sha256",
                get(handle_get_blob)
                    .head(handle_head_blob)
                    .delete(handle_delete_blob),
            )
            .route("/list/:pubkey", get(handle_list))
            .route("/mirror", put(handle_mirror))
            .route("/media", put(handle_media_upload))
            .route("/upload-requirements", get(handle_upload_requirements))
            .route("/status", get(handle_status))
            .route("/health", get(handle_health))
            .with_state(self.state.clone());

        if self.has_locks {
            router = router.merge(locks::locks_router(self.state.clone()));
        }

        router
            .layer(axum::extract::DefaultBodyLimit::max(self.body_limit))
            .layer(
                tower_http::trace::TraceLayer::new_for_http()
                    .make_span_with(|request: &axum::http::Request<_>| {
                        tracing::info_span!(
                            "blossom.http.request",
                            http.method = %request.method(),
                            http.route = %request.uri().path(),
                            http.status_code = tracing::field::Empty,
                            otel.name = %format!("{} {}", request.method(), request.uri().path()),
                            otel.kind = "server",
                        )
                    })
                    .on_response(
                        |response: &axum::http::Response<_>,
                         latency: std::time::Duration,
                         span: &tracing::Span| {
                            span.record("http.status_code", response.status().as_u16());
                            tracing::info!(
                                parent: span,
                                http.status_code = response.status().as_u16(),
                                latency_ms = latency.as_millis() as u64,
                                "response"
                            );
                        },
                    ),
            )
    }
}

/// Extract a Nostr auth event from the `Authorization: Nostr <base64url>` header.
///
/// Supports both kind:24242 (Blossom/BUD-01) and kind:27235 (NIP-98) events.
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

/// Verify an auth event, accepting either kind:24242 (Blossom) or kind:27235 (NIP-98).
fn verify_auth_event(event: &NostrEvent, expected_action: Option<&str>) -> Result<(), AuthError> {
    match event.kind {
        24242 => verify_blossom_auth(event, expected_action),
        27235 => verify_nip98_auth(event, None, None),
        other => Err(AuthError::WrongKind(other)),
    }
}

fn error_json(msg: &str) -> Json<serde_json::Value> {
    Json(serde_json::json!({"error": msg}))
}

/// Serialize a value to JSON for HTTP response. Falls back to error JSON on failure.
fn to_json_response(value: &impl serde::Serialize) -> (StatusCode, Json<serde_json::Value>) {
    match serde_json::to_value(value) {
        Ok(v) => (StatusCode::OK, Json(v)),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            error_json(&format!("serialization error: {e}")),
        ),
    }
}

/// Validate that a string is a valid SHA256 hex hash (64 lowercase hex chars).
fn is_valid_sha256(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Extract Content-Type from request headers. If missing or generic
/// (`application/octet-stream`), returns `None` so the caller can
/// fall back to magic byte detection.
fn extract_content_type(headers: &HeaderMap) -> Option<String> {
    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())?;
    if ct == "application/octet-stream" {
        None
    } else {
        Some(ct.to_string())
    }
}

/// Detect MIME type from magic bytes in the data.
fn detect_mime(data: &[u8]) -> String {
    if data.len() < 4 {
        return "application/octet-stream".to_string();
    }
    match &data[..4] {
        [0x89, b'P', b'N', b'G'] => "image/png",
        [0xFF, 0xD8, 0xFF, _] => "image/jpeg",
        [b'G', b'I', b'F', b'8'] => "image/gif",
        [b'R', b'I', b'F', b'F'] if data.len() > 12 && &data[8..12] == b"WEBP" => "image/webp",
        [0x25, b'P', b'D', b'F'] => "application/pdf",
        [b'P', b'K', 0x03, 0x04] => "application/zip",
        [0x1F, 0x8B, _, _] => "application/gzip",
        _ if data.len() > 8 && &data[4..8] == b"ftyp" => "video/mp4",
        _ => "application/octet-stream",
    }
    .to_string()
}

// ---------------------------------------------------------------------------
// BUD-20: Delta reconstruction
// ---------------------------------------------------------------------------

const MAX_DELTA_CHAIN_DEPTH: usize = 10;

fn reconstruct_blob(
    _delta_data: &[u8],
    version: &LfsFileVersion,
    lfs_db: &dyn LfsVersionDatabase,
    backend: &dyn BlobBackend,
) -> Result<Vec<u8>, String> {
    let mut chain: Vec<LfsFileVersion> = Vec::new();
    let mut current_hash = version.sha256.clone();

    for _ in 0..MAX_DELTA_CHAIN_DEPTH {
        match lfs_db.get_by_sha256(&current_hash) {
            Ok(Some(v)) => {
                if v.storage == LfsStorageType::Delta {
                    if let Some(ref base) = v.base_sha256 {
                        let base_hash = base.clone();
                        chain.push(v);
                        current_hash = base_hash;
                        continue;
                    }
                }
                chain.push(v);
                break;
            }
            _ => return Err("delta chain broken".into()),
        }
    }

    chain.reverse();

    let base_hash = chain
        .first()
        .and_then(|v| {
            if v.storage != LfsStorageType::Delta {
                Some(v.sha256.clone())
            } else {
                v.base_sha256.clone()
            }
        })
        .ok_or_else(|| "no base in chain")?;

    let mut result = backend
        .get(&base_hash)
        .ok_or_else(|| format!("base blob {} not found", base_hash))?;

    if let Ok(Some(base_v)) = lfs_db.get_by_sha256(&base_hash) {
        if base_v.storage == LfsStorageType::Compressed {
            result = compress::decompress(&result).unwrap_or(result);
        }
    }

    for v in &chain {
        if v.storage == LfsStorageType::Delta {
            let delta_raw = backend
                .get(&v.sha256)
                .ok_or_else(|| format!("delta blob {} not found", v.sha256))?;
            let delta_decoded = compress::decompress(&delta_raw).unwrap_or(delta_raw);
            result = compress::decode_delta(&result, &delta_decoded)?;
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// BUD-01: Upload
// ---------------------------------------------------------------------------

#[instrument(name = "blossom.upload", skip_all, fields(blob.size, blob.sha256, auth.pubkey))]
async fn handle_upload(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let data = body.to_vec();
    tracing::Span::current().record("blob.size", data.len() as u64);
    if data.is_empty() {
        warn!("upload rejected: empty body");
        return (StatusCode::BAD_REQUEST, error_json("empty body"));
    }

    let mut s = state.lock().await;

    // Rate limit check (keyed by source IP placeholder — use pubkey if available).
    if let Some(ref limiter) = s.rate_limiter {
        let key = extract_auth_event(&headers)
            .ok()
            .map(|e| e.pubkey)
            .unwrap_or_else(|| "anonymous".to_string());
        if !limiter.check(&key) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                error_json("rate limit exceeded"),
            );
        }
    }

    // BUD-06: Check upload requirements.
    if let Some(max) = s.requirements.max_size {
        if data.len() as u64 > max {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                error_json(&format!("exceeds max upload size of {} bytes", max)),
            );
        }
    }

    // Auth check.
    let pubkey = if s.requirements.require_auth {
        match extract_auth_event(&headers) {
            Ok(event) => {
                if let Err(e) = verify_auth_event(&event, Some("upload")) {
                    return (StatusCode::UNAUTHORIZED, error_json(&e.to_string()));
                }
                // Access control check.
                if !s.access.is_allowed(&event.pubkey, Action::Upload) {
                    return (
                        StatusCode::FORBIDDEN,
                        error_json("upload not allowed for this pubkey"),
                    );
                }
                // Quota check.
                if let Err(DbError::QuotaExceeded {
                    used,
                    requested,
                    limit,
                }) = s.database.check_quota(&event.pubkey, data.len() as u64)
                {
                    return (
                        StatusCode::INSUFFICIENT_STORAGE,
                        error_json(&format!(
                            "quota exceeded: used {} + requested {} > limit {}",
                            used, requested, limit
                        )),
                    );
                }
                Some(event.pubkey.clone())
            }
            Err(e) => {
                return (StatusCode::UNAUTHORIZED, error_json(&e.to_string()));
            }
        }
    } else {
        // Try to extract pubkey if auth header is present (optional).
        extract_auth_event(&headers).ok().map(|e| e.pubkey)
    };

    // Detect Content-Type before moving data into backend.
    let content_type = extract_content_type(&headers).unwrap_or_else(|| detect_mime(&data));

    // Compute SHA-256 of original data (content identity).
    let original_sha256 = crate::protocol::sha256_hex(&data);
    let original_size = data.len() as u64;

    // Parse LFS context from auth event tags.
    let lfs_ctx = extract_auth_event(&headers)
        .map(|e| LfsContext::from_event(&e))
        .unwrap_or_default();

    // BUD-20: LFS compression/delta pipeline.
    let (stored_data, storage_type, base_sha256) = if lfs_ctx.is_lfs
        && s.lfs_version_db.is_some()
        && !lfs_ctx.is_manifest
    {
        if let Some(ref base_hash) = lfs_ctx.base {
            let (base_version, base_data) = {
                let lfs_db = s.lfs_version_db.as_ref().unwrap();
                let bv = lfs_db.get_by_sha256(base_hash).ok().flatten();
                let bd = s.backend.get(base_hash);
                (bv, bd)
            };

            if let (Some(base_version), Some(base_data)) = (base_version, base_data) {
                let base_decompressed = match base_version.storage {
                    LfsStorageType::Compressed => {
                        compress::decompress(&base_data).unwrap_or_else(|_| base_data.clone())
                    }
                    LfsStorageType::Delta => {
                        let lfs_db = s.lfs_version_db.as_ref().unwrap();
                        reconstruct_blob(&base_data, &base_version, lfs_db.as_ref(), &*s.backend)
                            .unwrap_or_else(|_| base_data.clone())
                    }
                    _ => base_data.clone(),
                };

                match compress::encode_delta(&base_decompressed, &data) {
                    Ok(delta) if compress::delta_is_worthwhile(delta.len(), data.len()) => {
                        match compress::compress(&delta) {
                            Ok(compressed_delta) => {
                                info!(
                                    blob.sha256 = %original_sha256,
                                    lfs.storage = "delta",
                                    lfs.base = %base_hash,
                                    lfs.delta_bytes = delta.len(),
                                    lfs.compressed_bytes = compressed_delta.len(),
                                    lfs.original_bytes = original_size,
                                    "LFS delta stored"
                                );
                                (
                                    compressed_delta,
                                    LfsStorageType::Delta,
                                    Some(base_hash.clone()),
                                )
                            }
                            Err(_) => {
                                let compressed =
                                    compress::compress(&data).unwrap_or_else(|_| data.clone());
                                (compressed, LfsStorageType::Compressed, None)
                            }
                        }
                    }
                    _ => {
                        let compressed = compress::compress(&data).unwrap_or_else(|_| data.clone());
                        (compressed, LfsStorageType::Compressed, None)
                    }
                }
            } else {
                let compressed = compress::compress(&data).unwrap_or_else(|_| data.clone());
                (compressed, LfsStorageType::Compressed, None)
            }
        } else {
            let compressed = compress::compress(&data).unwrap_or_else(|_| data.clone());
            (compressed, LfsStorageType::Compressed, None)
        }
    } else {
        (data.clone(), LfsStorageType::Raw, None)
    };

    let base_url = s.base_url.clone();
    let descriptor = {
        let desc =
            crate::storage::make_descriptor_from_hash(&original_sha256, original_size, &base_url);
        if !s.backend.exists(&original_sha256) {
            s.backend
                .insert_with_hash(stored_data, &original_sha256, original_size, &base_url);
        }
        desc
    };

    // Record LFS version if applicable.
    if lfs_ctx.is_lfs && s.lfs_version_db.is_some() {
        if let (Some(repo), Some(path)) = (&lfs_ctx.repo, &lfs_ctx.path) {
            let lfs_db = s.lfs_version_db.as_mut().unwrap();
            let next_version = lfs_db
                .get_latest_version(repo, path)
                .ok()
                .flatten()
                .map(|v| v.version + 1)
                .unwrap_or(1);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            let record = LfsFileVersion {
                repo_id: repo.clone(),
                path: path.clone(),
                version: next_version,
                sha256: original_sha256.clone(),
                base_sha256: base_sha256.clone(),
                storage: storage_type.clone(),
                delta_algo: if storage_type == LfsStorageType::Delta {
                    Some("xdelta3".into())
                } else {
                    None
                },
                original_size: original_size as i64,
                stored_size: descriptor.size as i64,
                created_at: now,
            };
            let _ = lfs_db.record_version(&record);
        }
    }

    // Record span fields now that we know the sha256.
    tracing::Span::current().record("blob.sha256", descriptor.sha256.as_str());

    let upload_pubkey = pubkey.unwrap_or_else(|| "anonymous".to_string());
    tracing::Span::current().record("auth.pubkey", upload_pubkey.as_str());
    let record = UploadRecord {
        sha256: descriptor.sha256.clone(),
        size: descriptor.size,
        mime_type: content_type,
        pubkey: upload_pubkey,
        created_at: descriptor.uploaded.unwrap_or(0),
        phash: None,
    };
    let _ = s.database.record_upload(&record);

    // Fire webhook.
    s.notifier.notify(webhooks::make_payload(
        EventType::Upload,
        &descriptor.sha256,
        descriptor.size,
        &record.pubkey,
        None,
    ));

    info!(blob.sha256 = %descriptor.sha256, blob.size = descriptor.size, "blob uploaded");

    (
        StatusCode::OK,
        serde_json::to_value(&descriptor)
            .map(Json)
            .unwrap_or_else(|_| error_json("serialization error")),
    )
}

// ---------------------------------------------------------------------------
// BUD-01: Get / Head / Delete
// ---------------------------------------------------------------------------

#[instrument(name = "blossom.get", skip_all, fields(blob.sha256 = %sha256))]
async fn handle_get_blob(
    State(state): State<SharedState>,
    Path(sha256): Path<String>,
) -> impl IntoResponse {
    let sha256 = sha256.split('.').next().unwrap_or(&sha256).to_string();
    if !is_valid_sha256(&sha256) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let s = state.lock().await;
    match s.backend.get(&sha256) {
        Some(raw_data) => {
            let data = if let Some(ref lfs_db) = s.lfs_version_db {
                if let Ok(Some(version)) = lfs_db.get_by_sha256(&sha256) {
                    match version.storage {
                        LfsStorageType::Compressed => {
                            compress::decompress(&raw_data).unwrap_or(raw_data)
                        }
                        LfsStorageType::Delta => {
                            match reconstruct_blob(&raw_data, &version, &**lfs_db, &*s.backend) {
                                Ok(reconstructed) => reconstructed,
                                Err(e) => {
                                    warn!(blob.sha256 = %sha256, error.message = %e, "delta reconstruction failed");
                                    raw_data
                                }
                            }
                        }
                        _ => raw_data,
                    }
                } else {
                    raw_data
                }
            } else {
                raw_data
            };
            let size = data.len() as u64;
            s.stats.record_access(&sha256, size);
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                data,
            )
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[instrument(name = "blossom.head", skip_all, fields(blob.sha256 = %sha256))]
async fn handle_head_blob(
    State(state): State<SharedState>,
    Path(sha256): Path<String>,
) -> impl IntoResponse {
    let sha256 = sha256.split('.').next().unwrap_or(&sha256).to_string();
    if !is_valid_sha256(&sha256) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let s = state.lock().await;
    match s.backend.get(&sha256) {
        Some(_) => {
            let content_length = if let Some(ref lfs_db) = s.lfs_version_db {
                lfs_db
                    .get_by_sha256(&sha256)
                    .ok()
                    .flatten()
                    .map(|v| v.original_size as usize)
            } else {
                None
            };
            let size = content_length
                .unwrap_or_else(|| s.backend.get(&sha256).map(|d| d.len()).unwrap_or(0));
            (
                StatusCode::OK,
                [
                    (axum::http::header::CONTENT_LENGTH, size.to_string()),
                    (
                        axum::http::header::CONTENT_TYPE,
                        "application/octet-stream".to_string(),
                    ),
                ],
            )
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[instrument(name = "blossom.delete", skip_all, fields(blob.sha256 = %sha256))]
async fn handle_delete_blob(
    State(state): State<SharedState>,
    Path(sha256): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // DELETE always requires auth.
    match extract_auth_event(&headers) {
        Ok(event) => {
            if let Err(e) = verify_auth_event(&event, Some("delete")) {
                return (StatusCode::UNAUTHORIZED, error_json(&e.to_string()));
            }
            let mut s = state.lock().await;
            let role = s.access.role(&event.pubkey);
            if role == Role::Denied {
                return (
                    StatusCode::FORBIDDEN,
                    error_json("delete not allowed for this pubkey"),
                );
            }
            // Members may only delete their own blobs. Anonymous uploads
            // (pubkey "anonymous") have no owner, so anyone may delete them.
            if role != Role::Admin {
                if let Ok(record) = s.database.get_upload(&sha256) {
                    if record.pubkey != "anonymous" && record.pubkey != event.pubkey {
                        return (StatusCode::FORBIDDEN, error_json("not the blob owner"));
                    }
                }
            }
            if s.backend.delete(&sha256) {
                let _ = s.database.delete_upload(&sha256);
                s.notifier.notify(webhooks::make_payload(
                    EventType::Delete,
                    &sha256,
                    0,
                    &event.pubkey,
                    None,
                ));
                (StatusCode::OK, Json(serde_json::json!({"deleted": true})))
            } else {
                (StatusCode::NOT_FOUND, error_json("not found"))
            }
        }
        Err(_) => (
            StatusCode::UNAUTHORIZED,
            error_json("authorization required for delete"),
        ),
    }
}

// ---------------------------------------------------------------------------
// BUD-02: List by pubkey
// ---------------------------------------------------------------------------

#[instrument(name = "blossom.list", skip_all, fields(list.pubkey = %pubkey))]
async fn handle_list(
    State(state): State<SharedState>,
    Path(pubkey): Path<String>,
) -> impl IntoResponse {
    let s = state.lock().await;
    match s.database.list_uploads_by_pubkey(&pubkey) {
        Ok(records) => {
            let descriptors: Vec<BlobDescriptor> = records
                .into_iter()
                .map(|r| BlobDescriptor {
                    sha256: r.sha256.clone(),
                    size: r.size,
                    content_type: Some(r.mime_type),
                    url: Some(format!("{}/{}", s.base_url, r.sha256)),
                    uploaded: Some(r.created_at),
                })
                .collect();
            to_json_response(&descriptors)
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            error_json(&e.to_string()),
        ),
    }
}

// ---------------------------------------------------------------------------
// BUD-04: Mirror
// ---------------------------------------------------------------------------

/// Request body for the mirror endpoint.
#[derive(serde::Deserialize)]
struct MirrorRequest {
    url: String,
}

#[instrument(name = "blossom.mirror", skip_all, fields(mirror.source_url))]
async fn handle_mirror(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<MirrorRequest>,
) -> impl IntoResponse {
    tracing::Span::current().record("mirror.source_url", req.url.as_str());

    // Mirror requires auth.
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

    // Fetch the remote blob.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let resp = match client.get(&req.url).send().await {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            return (
                StatusCode::BAD_GATEWAY,
                error_json(&format!("remote returned status {}", r.status())),
            );
        }
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                error_json(&format!("failed to fetch remote: {e}")),
            );
        }
    };

    let data = match resp.bytes().await {
        Ok(b) => b.to_vec(),
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                error_json(&format!("failed to read remote body: {e}")),
            );
        }
    };

    if data.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            error_json("remote returned empty body"),
        );
    }

    let mut s = state.lock().await;

    // Check size limit.
    if let Some(max) = s.requirements.max_size {
        if data.len() as u64 > max {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                error_json(&format!("mirrored blob exceeds max size of {} bytes", max)),
            );
        }
    }

    // Access control.
    if !s.access.is_allowed(&pubkey, Action::Mirror) {
        return (
            StatusCode::FORBIDDEN,
            error_json("mirror not allowed for this pubkey"),
        );
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
                "quota exceeded: used {} + requested {} > limit {}",
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

    // Fire webhook with source URL as metadata.
    s.notifier.notify(webhooks::make_payload(
        EventType::Mirror,
        &descriptor.sha256,
        descriptor.size,
        &record.pubkey,
        Some(serde_json::json!({"source_url": req.url})),
    ));

    to_json_response(&descriptor)
}

// ---------------------------------------------------------------------------
// BUD-05: Media upload (server-side processing)
// ---------------------------------------------------------------------------

#[instrument(name = "blossom.media_upload", skip_all, fields(blob.size, blob.sha256, auth.pubkey))]
async fn handle_media_upload(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let data = body.to_vec();
    tracing::Span::current().record("blob.size", data.len() as u64);
    if data.is_empty() {
        return (StatusCode::BAD_REQUEST, error_json("empty body"));
    }

    let mut s = state.lock().await;

    // Media processor required.
    let processor = match s.media_processor {
        Some(ref p) => p,
        None => {
            return (
                StatusCode::NOT_IMPLEMENTED,
                error_json("media processing not enabled on this server"),
            );
        }
    };

    // Auth required for media uploads.
    let pubkey = match extract_auth_event(&headers) {
        Ok(event) => {
            if let Err(e) = verify_auth_event(&event, Some("upload")) {
                return (StatusCode::UNAUTHORIZED, error_json(&e.to_string()));
            }
            if !s.access.is_allowed(&event.pubkey, Action::Upload) {
                return (
                    StatusCode::FORBIDDEN,
                    error_json("upload not allowed for this pubkey"),
                );
            }
            event.pubkey
        }
        Err(e) => {
            return (StatusCode::UNAUTHORIZED, error_json(&e.to_string()));
        }
    };

    // Detect MIME type from content (simple heuristic).
    let mime = detect_mime(&data);

    // Process the media.
    let result = match processor.process(&data, &mime) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                error_json(&format!("media processing failed: {e}")),
            );
        }
    };

    // Store the processed data.
    let base_url = s.base_url.clone();
    let descriptor = s.backend.insert(result.data, &base_url);
    tracing::Span::current().record("blob.sha256", descriptor.sha256.as_str());

    // Record in database with phash.
    let record = UploadRecord {
        sha256: descriptor.sha256.clone(),
        size: descriptor.size,
        mime_type: result.mime_type,
        pubkey: pubkey.clone(),
        created_at: descriptor.uploaded.unwrap_or(0),
        phash: result.phash,
    };
    let _ = s.database.record_upload(&record);

    s.notifier.notify(webhooks::make_payload(
        EventType::Upload,
        &descriptor.sha256,
        descriptor.size,
        &pubkey,
        None,
    ));

    // Build response with media metadata.
    let mut response = serde_json::to_value(&descriptor).unwrap_or_default();
    if let Some(bh) = result.blurhash {
        response["blurhash"] = serde_json::Value::String(bh);
    }
    if let Some(w) = result.width {
        response["width"] = serde_json::Value::Number(w.into());
    }
    if let Some(h) = result.height {
        response["height"] = serde_json::Value::Number(h.into());
    }
    if let Some(ph) = result.phash {
        response["phash"] = serde_json::Value::Number(ph.into());
    }

    info!(
        blob.sha256 = %descriptor.sha256,
        blob.size = descriptor.size,
        "media blob processed and uploaded"
    );

    (StatusCode::OK, Json(response))
}

// detect_mime is defined above, shared by upload and media handlers.

// ---------------------------------------------------------------------------
// BUD-06: Upload requirements
// ---------------------------------------------------------------------------

#[instrument(name = "blossom.upload_requirements", skip_all)]
async fn handle_upload_requirements(State(state): State<SharedState>) -> impl IntoResponse {
    let s = state.lock().await;
    serde_json::to_value(&s.requirements)
        .map(Json)
        .unwrap_or_else(|e| Json(serde_json::json!({"error": e.to_string()})))
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

#[instrument(name = "blossom.status", skip_all)]
async fn handle_status(State(state): State<SharedState>) -> impl IntoResponse {
    let s = state.lock().await;
    let mut status = serde_json::json!({
        "blobs": s.backend.len(),
        "total_bytes": s.backend.total_bytes(),
        "uploads": s.database.upload_count(),
        "users": s.database.user_count(),
        "tracked_stats": s.stats.tracked_count(),
    });
    // Include build integrity info if available.
    let integrity = crate::integrity::runtime_integrity_info(
        option_env!("BLOSSOM_SOURCE_BUILD_HASH"),
        option_env!("BLOSSOM_BUILD_TARGET"),
    );
    status["integrity"] = serde_json::to_value(&integrity).unwrap_or_default();
    Json(status)
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

async fn handle_health() -> StatusCode {
    StatusCode::OK
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
    let _ = (hash_key, size);
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

    async fn spawn_server(server: BlobServer) -> String {
        let app = server.router();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{}", addr);
        tokio::spawn(async move { axum::serve(listener, app).await.ok() });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        url
    }

    #[tokio::test]
    async fn test_upload_and_get() {
        let url = spawn_server(test_server()).await;
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
        let url = spawn_server(test_server()).await;
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
        let url = spawn_server(test_server()).await;
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
        let url = spawn_server(test_server()).await;
        let http = reqwest::Client::new();

        let resp = http.get(format!("{}/status", url)).send().await.unwrap();
        let status: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(status["blobs"], 0);

        http.put(format!("{}/upload", url))
            .body(b"test".to_vec())
            .send()
            .await
            .unwrap();

        let resp = http.get(format!("{}/status", url)).send().await.unwrap();
        let status: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(status["blobs"], 1);
        assert_eq!(status["total_bytes"], 4);
        assert_eq!(status["uploads"], 1);
    }

    #[tokio::test]
    async fn test_list_by_pubkey() {
        let url = spawn_server(test_server()).await;
        let http = reqwest::Client::new();

        // Upload some data (anonymous, so pubkey will be "anonymous").
        http.put(format!("{}/upload", url))
            .body(b"blob1".to_vec())
            .send()
            .await
            .unwrap();

        let resp = http
            .get(format!("{}/list/anonymous", url))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let list: Vec<BlobDescriptor> = resp.json().await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].size, 5);
    }

    #[tokio::test]
    async fn test_upload_requirements() {
        let server = BlobServer::builder(MemoryBackend::new(), "http://localhost:3000")
            .require_auth()
            .max_upload_size(1024 * 1024)
            .allowed_types(vec!["image/png".into(), "image/jpeg".into()])
            .build();

        let url = spawn_server(server).await;
        let http = reqwest::Client::new();

        let resp = http
            .get(format!("{}/upload-requirements", url))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let reqs: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(reqs["max_size"], 1024 * 1024);
        assert_eq!(reqs["require_auth"], true);
        assert_eq!(reqs["allowed_types"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_max_upload_size_enforced() {
        let server = BlobServer::builder(MemoryBackend::new(), "http://localhost:3000")
            .max_upload_size(10)
            .build();

        let url = spawn_server(server).await;
        let http = reqwest::Client::new();

        // Should succeed — 5 bytes < 10.
        let resp = http
            .put(format!("{}/upload", url))
            .body(b"small".to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        // Should fail — 20 bytes > 10.
        let resp = http
            .put(format!("{}/upload", url))
            .body(b"this is way too large".to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 413);
    }

    #[tokio::test]
    async fn test_builder_pattern() {
        let server = BlobServer::builder(MemoryBackend::new(), "http://localhost:3000")
            .database(MemoryDatabase::new())
            .require_auth()
            .max_upload_size(50 * 1024 * 1024)
            .build();

        // Just verify it builds and the router works.
        let _router = server.router();
    }

    #[tokio::test]
    async fn test_empty_list() {
        let url = spawn_server(test_server()).await;
        let http = reqwest::Client::new();

        let resp = http
            .get(format!("{}/list/{}", url, "a".repeat(64)))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let list: Vec<BlobDescriptor> = resp.json().await.unwrap();
        assert!(list.is_empty());
    }

    #[tokio::test]
    async fn test_status_tracks_users() {
        let url = spawn_server(test_server()).await;
        let http = reqwest::Client::new();

        // Upload creates an "anonymous" user.
        http.put(format!("{}/upload", url))
            .body(b"data".to_vec())
            .send()
            .await
            .unwrap();

        let resp = http.get(format!("{}/status", url)).send().await.unwrap();
        let status: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(status["users"], 1);
    }

    #[tokio::test]
    async fn test_get_nonexistent_blob() {
        let url = spawn_server(test_server()).await;
        let http = reqwest::Client::new();

        let resp = http
            .get(format!("{}/{}", url, "0".repeat(64)))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 404);
    }

    #[tokio::test]
    async fn test_empty_upload_rejected() {
        let url = spawn_server(test_server()).await;
        let http = reqwest::Client::new();

        let resp = http
            .put(format!("{}/upload", url))
            .body(Vec::<u8>::new())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400);
    }

    #[tokio::test]
    async fn test_auth_with_wrong_action_rejected() {
        let server = BlobServer::new_with_auth(MemoryBackend::new(), "http://localhost:3000");
        let url = spawn_server(server).await;
        let http = reqwest::Client::new();
        let signer = crate::auth::Signer::generate();

        // Sign with "delete" action, but try to upload.
        let auth_event = crate::auth::build_blossom_auth(&signer, "delete", None, None, "");
        let auth_header = crate::auth::auth_header_value(&auth_event);

        let resp = http
            .put(format!("{}/upload", url))
            .header("Authorization", &auth_header)
            .body(b"wrong action".to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn test_delete_nonexistent_with_auth() {
        let url = spawn_server(test_server()).await;
        let http = reqwest::Client::new();
        let signer = crate::auth::Signer::generate();

        let auth_event = crate::auth::build_blossom_auth(&signer, "delete", None, None, "");
        let auth_header = crate::auth::auth_header_value(&auth_event);

        let resp = http
            .delete(format!("{}/{}", url, "0".repeat(64)))
            .header("Authorization", &auth_header)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 404);
    }

    #[tokio::test]
    async fn test_mirror_requires_auth() {
        let url = spawn_server(test_server()).await;
        let http = reqwest::Client::new();

        let resp = http
            .put(format!("{}/mirror", url))
            .json(&serde_json::json!({"url": "http://example.com/blob"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn test_mirror_bad_remote_url() {
        let url = spawn_server(test_server()).await;
        let http = reqwest::Client::new();
        let signer = crate::auth::Signer::generate();

        let auth_event = crate::auth::build_blossom_auth(&signer, "upload", None, None, "");
        let auth_header = crate::auth::auth_header_value(&auth_event);

        let resp = http
            .put(format!("{}/mirror", url))
            .header("Authorization", &auth_header)
            .json(&serde_json::json!({"url": "http://127.0.0.1:1/nonexistent"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 502);
    }

    #[tokio::test]
    async fn test_mirror_success() {
        // Spin up a source server with a blob.
        let source = test_server();
        let source_url = spawn_server(source).await;
        let http = reqwest::Client::new();

        let data = b"mirror me!";
        let resp = http
            .put(format!("{}/upload", source_url))
            .body(data.to_vec())
            .send()
            .await
            .unwrap();
        let desc: BlobDescriptor = resp.json().await.unwrap();

        // Spin up a destination server.
        let dest = test_server();
        let dest_url = spawn_server(dest).await;
        let signer = crate::auth::Signer::generate();

        let auth_event = crate::auth::build_blossom_auth(&signer, "upload", None, None, "");
        let auth_header = crate::auth::auth_header_value(&auth_event);

        // Mirror from source to dest.
        let resp = http
            .put(format!("{}/mirror", dest_url))
            .header("Authorization", &auth_header)
            .json(&serde_json::json!({"url": format!("{}/{}", source_url, desc.sha256)}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let mirrored: BlobDescriptor = serde_json::from_value(resp.json().await.unwrap()).unwrap();
        assert_eq!(mirrored.sha256, desc.sha256);

        // Verify it's on dest.
        let resp = http
            .get(format!("{}/{}", dest_url, desc.sha256))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.bytes().await.unwrap().as_ref(), data);
    }

    #[tokio::test]
    async fn test_upload_with_invalid_auth_header() {
        let server = BlobServer::new_with_auth(MemoryBackend::new(), "http://localhost:3000");
        let url = spawn_server(server).await;
        let http = reqwest::Client::new();

        // Garbage auth header.
        let resp = http
            .put(format!("{}/upload", url))
            .header("Authorization", "Nostr not-valid-base64!!!")
            .body(b"test".to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);

        // Wrong prefix.
        let resp = http
            .put(format!("{}/upload", url))
            .header("Authorization", "Bearer token123")
            .body(b"test".to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn test_head_existing_blob() {
        let url = spawn_server(test_server()).await;
        let http = reqwest::Client::new();

        let data = b"head check";
        let resp = http
            .put(format!("{}/upload", url))
            .body(data.to_vec())
            .send()
            .await
            .unwrap();
        let desc: BlobDescriptor = resp.json().await.unwrap();

        let resp = http
            .head(format!("{}/{}", url, desc.sha256))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn test_access_stats_tracked() {
        let url = spawn_server(test_server()).await;
        let http = reqwest::Client::new();

        let data = b"track my downloads";
        let resp = http
            .put(format!("{}/upload", url))
            .body(data.to_vec())
            .send()
            .await
            .unwrap();
        let desc: BlobDescriptor = resp.json().await.unwrap();

        // Download 3 times.
        for _ in 0..3 {
            http.get(format!("{}/{}", url, desc.sha256))
                .send()
                .await
                .unwrap();
        }

        let resp = http.get(format!("{}/status", url)).send().await.unwrap();
        let status: serde_json::Value = resp.json().await.unwrap();
        assert!(status["tracked_stats"].as_u64().unwrap() >= 1);
    }

    // --- Ownership-enforced delete tests ---

    #[tokio::test]
    async fn test_member_cannot_delete_others_blob() {
        let server = BlobServer::new(MemoryBackend::new(), "http://localhost:3000");
        let url = spawn_server(server).await;
        let http = reqwest::Client::new();

        // Alice uploads a blob.
        let alice = crate::auth::Signer::generate();
        let auth = crate::auth::build_blossom_auth(&alice, "upload", None, None, "");
        let resp = http
            .put(format!("{}/upload", url))
            .header("Authorization", crate::auth::auth_header_value(&auth))
            .body(b"alice's data".to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let desc: serde_json::Value = resp.json().await.unwrap();
        let sha = desc["sha256"].as_str().unwrap().to_string();

        // Bob tries to delete Alice's blob — should fail.
        let bob = crate::auth::Signer::generate();
        let del_auth = crate::auth::build_blossom_auth(&bob, "delete", None, None, "");
        let resp = http
            .delete(format!("{}/{}", url, sha))
            .header("Authorization", crate::auth::auth_header_value(&del_auth))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403);

        // Alice can delete her own blob.
        let del_auth = crate::auth::build_blossom_auth(&alice, "delete", None, None, "");
        let resp = http
            .delete(format!("{}/{}", url, sha))
            .header("Authorization", crate::auth::auth_header_value(&del_auth))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn test_anyone_can_delete_anonymous_blob() {
        let server = BlobServer::new(MemoryBackend::new(), "http://localhost:3000");
        let url = spawn_server(server).await;
        let http = reqwest::Client::new();

        // Anonymous upload (no auth).
        let resp = http
            .put(format!("{}/upload", url))
            .body(b"anonymous data".to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let desc: serde_json::Value = resp.json().await.unwrap();
        let sha = desc["sha256"].as_str().unwrap().to_string();

        // Anyone with auth can delete anonymous blobs.
        let signer = crate::auth::Signer::generate();
        let del_auth = crate::auth::build_blossom_auth(&signer, "delete", None, None, "");
        let resp = http
            .delete(format!("{}/{}", url, sha))
            .header("Authorization", crate::auth::auth_header_value(&del_auth))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }
}
