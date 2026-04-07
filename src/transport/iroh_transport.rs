//! Iroh QUIC transport for Blossom.
//!
//! Implements `ProtocolHandler` to serve Blossom blob operations over
//! iroh's QUIC-based P2P connections. Peers connect by node ID — no
//! IP/DNS required.

use std::sync::Arc;

use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use tokio::sync::Mutex;
use tracing::{info, instrument, warn};

use super::wire::{self, Op, Request, Response, Status};
use crate::access::{AccessControl, Action, Role};
use crate::auth::{verify_blossom_auth, verify_nip98_auth};
use crate::db::{BlobDatabase, UploadRecord};
use crate::lfs::{
    compress, reconstruct_blob, LfsContext, LfsFileVersion, LfsStorageType, LfsVersionDatabase,
};
use crate::locks::{LockDatabase, LockFilters};
use crate::protocol::{base64url_decode, BlobDescriptor, NostrEvent};
use crate::storage::BlobBackend;

/// ALPN protocol identifier for Blossom over iroh.
pub const BLOSSOM_ALPN: &[u8] = b"/blossom/1";

/// Shared state for the iroh transport handler.
pub struct IrohState {
    pub backend: Box<dyn BlobBackend>,
    pub database: Box<dyn BlobDatabase>,
    pub access: Box<dyn AccessControl>,
    pub base_url: String,
    pub max_upload_size: Option<u64>,
    pub require_auth: bool,
    pub lock_db: Option<Box<dyn LockDatabase>>,
    pub lfs_version_db: Option<Box<dyn LfsVersionDatabase>>,
}

impl std::fmt::Debug for IrohState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IrohState")
            .field("base_url", &self.base_url)
            .finish()
    }
}

/// Blossom protocol handler for iroh connections.
///
/// Each incoming connection spawns a loop that accepts bidirectional
/// streams. Each stream carries one request + response.
#[derive(Debug, Clone)]
pub struct BlossomProtocol {
    state: Arc<Mutex<IrohState>>,
}

impl BlossomProtocol {
    /// Create a new protocol handler with the given state.
    pub fn new(state: Arc<Mutex<IrohState>>) -> Self {
        Self { state }
    }
}

impl ProtocolHandler for BlossomProtocol {
    fn accept(
        &self,
        conn: Connection,
    ) -> impl std::future::Future<Output = Result<(), AcceptError>> + Send {
        let state = self.state.clone();
        async move {
            let remote = conn.remote_id();
            info!(peer.id = %remote, "iroh connection accepted");

            loop {
                let (send, recv) = match conn.accept_bi().await {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let state = state.clone();
                tokio::spawn(handle_stream(send, recv, state));
            }

            Ok(())
        }
    }
}

/// Handle a single bidi stream (one request + response).
#[instrument(name = "blossom.iroh.stream", skip_all)]
async fn handle_stream(
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    state: Arc<Mutex<IrohState>>,
) {
    // Read the request JSON line.
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    loop {
        match recv.read(&mut tmp).await {
            Ok(Some(n)) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.contains(&b'\n') {
                    break;
                }
            }
            Ok(None) => break,
            Err(e) => {
                warn!(error.message = %e, "failed to read request");
                return;
            }
        }
    }

    let (req, header_len) = match wire::decode_line::<Request>(&buf) {
        Ok(v) => v,
        Err(e) => {
            let resp = Response {
                status: Status::Error,
                body_len: 0,
                content_type: String::new(),
                error: e.to_string(),
                descriptor: None,
            };
            let _ = send.write_all(&wire::encode_response(&resp)).await;
            let _ = send.finish();
            return;
        }
    };

    // Read remaining body bytes for UPLOAD.
    let body = if req.op == Op::Upload && req.body_len > 0 {
        let mut already_read = buf[header_len..].to_vec();
        let remaining = (req.body_len as usize).saturating_sub(already_read.len());
        if remaining > 0 {
            let mut rest = vec![0u8; remaining];
            if let Err(e) = recv.read_exact(&mut rest).await {
                warn!(error.message = %e, "failed to read upload body");
                return;
            }
            already_read.extend_from_slice(&rest);
        }
        already_read
    } else {
        vec![]
    };

    // Verify auth if provided.
    let auth_pubkey = if !req.auth.is_empty() {
        match verify_auth(&req.auth, &req.op) {
            Ok(pk) => Some(pk),
            Err(e) => {
                let resp = Response {
                    status: Status::Unauthorized,
                    body_len: 0,
                    content_type: String::new(),
                    error: e,
                    descriptor: None,
                };
                let _ = send.write_all(&wire::encode_response(&resp)).await;
                let _ = send.finish();
                return;
            }
        }
    } else {
        None
    };

    // Dispatch by operation.
    let mut s = state.lock().await;
    match req.op {
        Op::Get => handle_get(&mut send, &req.sha256, &s).await,
        Op::Head => handle_head(&mut send, &req.sha256, &s).await,
        Op::Upload => {
            handle_upload(&mut send, body, &req, auth_pubkey, &mut s).await;
        }
        Op::Delete => handle_delete(&mut send, &req.sha256, auth_pubkey, &mut s).await,
        Op::List => handle_list(&mut send, &req.pubkey, &s).await,
        Op::LockCreate => handle_lock_create(&mut send, &req, auth_pubkey, &mut s).await,
        Op::LockDelete => handle_lock_delete(&mut send, &req, auth_pubkey, &mut s).await,
        Op::LockList => handle_lock_list(&mut send, &req, &s).await,
        Op::LockVerify => handle_lock_verify(&mut send, &req, auth_pubkey, &s).await,
    }

    let _ = send.finish();
}

fn parse_lfs_from_request(req: &Request) -> LfsContext {
    let is_lfs = !req.lfs_path.is_empty() || !req.lfs_repo.is_empty();
    LfsContext {
        is_lfs,
        path: if req.lfs_path.is_empty() {
            None
        } else {
            Some(req.lfs_path.clone())
        },
        repo: if req.lfs_repo.is_empty() {
            None
        } else {
            Some(req.lfs_repo.clone())
        },
        base: if req.lfs_base.is_empty() {
            None
        } else {
            Some(req.lfs_base.clone())
        },
        is_manifest: req.lfs_manifest,
    }
}

/// Verify auth from the wire protocol. Accepts both kind:24242 and kind:27235.
fn verify_auth(auth_header: &str, op: &Op) -> Result<String, String> {
    let b64 = auth_header.strip_prefix("Nostr ").unwrap_or(auth_header);

    let json_bytes = base64url_decode(b64).map_err(|e| format!("invalid auth encoding: {e}"))?;
    let event: NostrEvent =
        serde_json::from_slice(&json_bytes).map_err(|e| format!("invalid auth event: {e}"))?;

    let action = match op {
        Op::Upload => "upload",
        Op::Delete => "delete",
        Op::Get => "get",
        Op::List => "get",
        Op::Head => "get",
        Op::LockCreate | Op::LockDelete | Op::LockList | Op::LockVerify => "lock",
    };

    match event.kind {
        24242 => verify_blossom_auth(&event, Some(action)).map_err(|e| e.to_string())?,
        27235 => verify_nip98_auth(&event, None, None).map_err(|e| e.to_string())?,
        _ => return Err(format!("unsupported auth kind: {}", event.kind)),
    }

    Ok(event.pubkey)
}

async fn handle_get(send: &mut iroh::endpoint::SendStream, sha256: &str, state: &IrohState) {
    match state.backend.get(sha256) {
        Some(raw_data) => {
            let data = if let Some(ref lfs_db) = state.lfs_version_db {
                if let Ok(Some(version)) = lfs_db.get_by_sha256(sha256) {
                    match version.storage {
                        LfsStorageType::Compressed => {
                            compress::decompress(&raw_data).unwrap_or(raw_data)
                        }
                        LfsStorageType::Delta => {
                            match reconstruct_blob(&version, &**lfs_db, &*state.backend) {
                                Ok(reconstructed) => reconstructed,
                                Err(e) => {
                                    warn!(
                                        blob.sha256 = %sha256,
                                        error.message = %e,
                                        "delta reconstruction failed"
                                    );
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
            let resp = Response {
                status: Status::Ok,
                body_len: data.len() as u64,
                content_type: "application/octet-stream".into(),
                error: String::new(),
                descriptor: None,
            };
            let _ = send.write_all(&wire::encode_response(&resp)).await;
            let _ = send.write_all(&data).await;
        }
        None => {
            let resp = Response {
                status: Status::NotFound,
                body_len: 0,
                content_type: String::new(),
                error: "not found".into(),
                descriptor: None,
            };
            let _ = send.write_all(&wire::encode_response(&resp)).await;
        }
    }
}

async fn handle_head(send: &mut iroh::endpoint::SendStream, sha256: &str, state: &IrohState) {
    let exists = state.backend.exists(sha256);
    let status = if exists { Status::Ok } else { Status::NotFound };
    let original_size = if exists {
        state
            .lfs_version_db
            .as_ref()
            .and_then(|lfs_db| lfs_db.get_by_sha256(sha256).ok().flatten())
            .map(|v| v.original_size as u64)
    } else {
        None
    };
    let resp = Response {
        status,
        body_len: original_size.unwrap_or(0),
        content_type: String::new(),
        error: String::new(),
        descriptor: None,
    };
    let _ = send.write_all(&wire::encode_response(&resp)).await;
}

async fn handle_upload(
    send: &mut iroh::endpoint::SendStream,
    data: Vec<u8>,
    req: &Request,
    auth_pubkey: Option<String>,
    state: &mut IrohState,
) {
    if data.is_empty() {
        let resp = Response {
            status: Status::Error,
            body_len: 0,
            content_type: String::new(),
            error: "empty body".into(),
            descriptor: None,
        };
        let _ = send.write_all(&wire::encode_response(&resp)).await;
        return;
    }

    if state.require_auth && auth_pubkey.is_none() {
        let resp = Response {
            status: Status::Unauthorized,
            body_len: 0,
            content_type: String::new(),
            error: "auth required for upload".into(),
            descriptor: None,
        };
        let _ = send.write_all(&wire::encode_response(&resp)).await;
        return;
    }

    let pubkey = auth_pubkey.unwrap_or_else(|| "anonymous".to_string());

    if !state.access.is_allowed(&pubkey, Action::Upload) {
        let resp = Response {
            status: Status::Forbidden,
            body_len: 0,
            content_type: String::new(),
            error: "upload not allowed for this pubkey".into(),
            descriptor: None,
        };
        let _ = send.write_all(&wire::encode_response(&resp)).await;
        return;
    }

    let size = data.len() as u64;

    if let Some(max) = state.max_upload_size {
        if size > max {
            let resp = Response {
                status: Status::Error,
                body_len: 0,
                content_type: String::new(),
                error: format!("exceeds max upload size of {max} bytes"),
                descriptor: None,
            };
            let _ = send.write_all(&wire::encode_response(&resp)).await;
            return;
        }
    }

    if let Err(e) = state.database.check_quota(&pubkey, size) {
        let resp = Response {
            status: Status::Forbidden,
            body_len: 0,
            content_type: String::new(),
            error: e.to_string(),
            descriptor: None,
        };
        let _ = send.write_all(&wire::encode_response(&resp)).await;
        return;
    }

    let original_sha256 = crate::protocol::sha256_hex(&data);
    let original_size = size;

    let lfs_ctx = parse_lfs_from_request(req);

    let (stored_data, storage_type, base_sha256) = if let Some(ref lfs_db) = state.lfs_version_db {
        if lfs_ctx.is_lfs && !lfs_ctx.is_manifest {
            if let Some(ref base_hash) = lfs_ctx.base {
                let (base_version, base_data) = {
                    let bv = lfs_db.get_by_sha256(base_hash).ok().flatten();
                    let bd = state.backend.get(base_hash);
                    (bv, bd)
                };

                if let (Some(base_version), Some(base_data)) = (base_version, base_data) {
                    let base_decompressed = match base_version.storage {
                        LfsStorageType::Compressed => {
                            compress::decompress(&base_data).unwrap_or_else(|_| base_data.clone())
                        }
                        LfsStorageType::Delta => {
                            let lfs_db_ref = state.lfs_version_db.as_ref().unwrap();
                            reconstruct_blob(&base_version, lfs_db_ref.as_ref(), &*state.backend)
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
                                        "LFS delta stored via iroh"
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
                            let compressed =
                                compress::compress(&data).unwrap_or_else(|_| data.clone());
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
        }
    } else {
        (data.clone(), LfsStorageType::Raw, None)
    };

    let base_url = state.base_url.clone();
    let descriptor = {
        let desc =
            crate::storage::make_descriptor_from_hash(&original_sha256, original_size, &base_url);
        if !state.backend.exists(&original_sha256) {
            state
                .backend
                .insert_with_hash(stored_data, &original_sha256, original_size, &base_url);
        }
        desc
    };

    if let Some(ref mut lfs_db) = state.lfs_version_db {
        if lfs_ctx.is_lfs {
            if let (Some(repo), Some(path)) = (&lfs_ctx.repo, &lfs_ctx.path) {
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
    }

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
    let _ = state.database.record_upload(&record);

    info!(
        blob.sha256 = %descriptor.sha256,
        blob.size = descriptor.size,
        "blob uploaded via iroh"
    );

    let desc_json = serde_json::to_value(&descriptor).unwrap_or_default();
    let resp = Response {
        status: Status::Ok,
        body_len: 0,
        content_type: String::new(),
        error: String::new(),
        descriptor: Some(desc_json),
    };
    let _ = send.write_all(&wire::encode_response(&resp)).await;
}

async fn handle_delete(
    send: &mut iroh::endpoint::SendStream,
    sha256: &str,
    auth_pubkey: Option<String>,
    state: &mut IrohState,
) {
    let pubkey = match auth_pubkey {
        Some(pk) => pk,
        None => {
            let resp = Response {
                status: Status::Unauthorized,
                body_len: 0,
                content_type: String::new(),
                error: "auth required for delete".into(),
                descriptor: None,
            };
            let _ = send.write_all(&wire::encode_response(&resp)).await;
            return;
        }
    };

    let role = state.access.role(&pubkey);
    if role == Role::Denied {
        let resp = Response {
            status: Status::Forbidden,
            body_len: 0,
            content_type: String::new(),
            error: "delete not allowed for this pubkey".into(),
            descriptor: None,
        };
        let _ = send.write_all(&wire::encode_response(&resp)).await;
        return;
    }

    // Members may only delete their own blobs. Anonymous uploads can be
    // deleted by anyone.
    if role != Role::Admin {
        if let Ok(record) = state.database.get_upload(sha256) {
            if record.pubkey != "anonymous" && record.pubkey != pubkey {
                let resp = Response {
                    status: Status::Forbidden,
                    body_len: 0,
                    content_type: String::new(),
                    error: "not the blob owner".into(),
                    descriptor: None,
                };
                let _ = send.write_all(&wire::encode_response(&resp)).await;
                return;
            }
        }
    }

    let base_url_clone = state.base_url.clone();
    let deltas_to_rebase = state
        .lfs_version_db
        .as_ref()
        .and_then(|lfs_db| lfs_db.get_deltas_for_base(sha256).ok());

    if let Some(ref deltas) = deltas_to_rebase {
        for delta_version in deltas {
            let base_decompressed_opt = {
                let lfs_db = state.lfs_version_db.as_ref().unwrap();
                state
                    .backend
                    .get(&delta_version.sha256)
                    .and_then(|_delta_data| {
                        reconstruct_blob(delta_version, lfs_db.as_ref(), &*state.backend).ok()
                    })
            };

            if let Some(base_decompressed) = base_decompressed_opt {
                let compressed = compress::compress(&base_decompressed)
                    .unwrap_or_else(|_| base_decompressed.clone());
                state.backend.insert_with_hash(
                    compressed,
                    &delta_version.sha256,
                    delta_version.original_size as u64,
                    &base_url_clone,
                );
                if let Some(ref mut lfs_db) = state.lfs_version_db {
                    let _ = lfs_db.update_version(
                        &delta_version.sha256,
                        LfsStorageType::Compressed,
                        None,
                        base_decompressed.len() as i64,
                    );
                }
            }
        }
    }

    if state.backend.delete(sha256) {
        let _ = state.database.delete_upload(sha256);

        if let Some(ref mut lfs_db) = state.lfs_version_db {
            let _ = lfs_db.delete_by_sha256(sha256);
        }

        let resp = Response {
            status: Status::Ok,
            body_len: 0,
            content_type: String::new(),
            error: String::new(),
            descriptor: None,
        };
        let _ = send.write_all(&wire::encode_response(&resp)).await;
    } else {
        let resp = Response {
            status: Status::NotFound,
            body_len: 0,
            content_type: String::new(),
            error: "not found".into(),
            descriptor: None,
        };
        let _ = send.write_all(&wire::encode_response(&resp)).await;
    }
}

async fn handle_list(send: &mut iroh::endpoint::SendStream, pubkey: &str, state: &IrohState) {
    match state.database.list_uploads_by_pubkey(pubkey) {
        Ok(records) => {
            let descriptors: Vec<BlobDescriptor> = records
                .into_iter()
                .map(|r| BlobDescriptor {
                    sha256: r.sha256.clone(),
                    size: r.size,
                    content_type: Some(r.mime_type),
                    url: Some(format!("{}/{}", state.base_url, r.sha256)),
                    uploaded: Some(r.created_at),
                })
                .collect();
            let body = serde_json::to_vec(&descriptors).unwrap_or_default();
            let resp = Response {
                status: Status::Ok,
                body_len: body.len() as u64,
                content_type: "application/json".into(),
                error: String::new(),
                descriptor: None,
            };
            let _ = send.write_all(&wire::encode_response(&resp)).await;
            let _ = send.write_all(&body).await;
        }
        Err(e) => {
            let resp = Response {
                status: Status::Error,
                body_len: 0,
                content_type: String::new(),
                error: e.to_string(),
                descriptor: None,
            };
            let _ = send.write_all(&wire::encode_response(&resp)).await;
        }
    }
}

async fn handle_lock_create(
    send: &mut iroh::endpoint::SendStream,
    req: &Request,
    auth_pubkey: Option<String>,
    state: &mut IrohState,
) {
    let pubkey = match auth_pubkey {
        Some(pk) => pk,
        None => {
            let resp = Response {
                status: Status::Unauthorized,
                body_len: 0,
                content_type: String::new(),
                error: "auth required for lock".into(),
                descriptor: None,
            };
            let _ = send.write_all(&wire::encode_response(&resp)).await;
            return;
        }
    };

    if !state.access.is_allowed(&pubkey, Action::Lock) {
        let resp = Response {
            status: Status::Forbidden,
            body_len: 0,
            content_type: String::new(),
            error: "lock not allowed".into(),
            descriptor: None,
        };
        let _ = send.write_all(&wire::encode_response(&resp)).await;
        return;
    }

    let lock_db = match state.lock_db.as_mut() {
        Some(db) => db,
        None => {
            let resp = Response {
                status: Status::NotFound,
                body_len: 0,
                content_type: String::new(),
                error: "lock support not configured".into(),
                descriptor: None,
            };
            let _ = send.write_all(&wire::encode_response(&resp)).await;
            return;
        }
    };

    match lock_db.create_lock(&req.repo_id, &req.lock_path, &pubkey) {
        Ok(record) => {
            let desc = serde_json::to_value(&record).unwrap_or_default();
            let resp = Response {
                status: Status::Ok,
                body_len: 0,
                content_type: String::new(),
                error: String::new(),
                descriptor: Some(desc),
            };
            let _ = send.write_all(&wire::encode_response(&resp)).await;
        }
        Err(crate::locks::LockError::Conflict(_)) => {
            let resp = Response {
                status: Status::Conflict,
                body_len: 0,
                content_type: String::new(),
                error: "path already locked".into(),
                descriptor: None,
            };
            let _ = send.write_all(&wire::encode_response(&resp)).await;
        }
        Err(e) => {
            let resp = Response {
                status: Status::Error,
                body_len: 0,
                content_type: String::new(),
                error: e.to_string(),
                descriptor: None,
            };
            let _ = send.write_all(&wire::encode_response(&resp)).await;
        }
    }
}

async fn handle_lock_delete(
    send: &mut iroh::endpoint::SendStream,
    req: &Request,
    auth_pubkey: Option<String>,
    state: &mut IrohState,
) {
    let pubkey = match auth_pubkey {
        Some(pk) => pk,
        None => {
            let resp = Response {
                status: Status::Unauthorized,
                body_len: 0,
                content_type: String::new(),
                error: "auth required for unlock".into(),
                descriptor: None,
            };
            let _ = send.write_all(&wire::encode_response(&resp)).await;
            return;
        }
    };

    let is_admin = state.access.role(&pubkey) == Role::Admin;

    let lock_db = match state.lock_db.as_mut() {
        Some(db) => db,
        None => {
            let resp = Response {
                status: Status::NotFound,
                body_len: 0,
                content_type: String::new(),
                error: "lock support not configured".into(),
                descriptor: None,
            };
            let _ = send.write_all(&wire::encode_response(&resp)).await;
            return;
        }
    };

    let force = req.force || is_admin;

    match lock_db.delete_lock(&req.repo_id, &req.lock_id, force, &pubkey) {
        Ok(record) => {
            let desc = serde_json::to_value(&record).unwrap_or_default();
            let resp = Response {
                status: Status::Ok,
                body_len: 0,
                content_type: String::new(),
                error: String::new(),
                descriptor: Some(desc),
            };
            let _ = send.write_all(&wire::encode_response(&resp)).await;
        }
        Err(crate::locks::LockError::NotFound) => {
            let resp = Response {
                status: Status::NotFound,
                body_len: 0,
                content_type: String::new(),
                error: "lock not found".into(),
                descriptor: None,
            };
            let _ = send.write_all(&wire::encode_response(&resp)).await;
        }
        Err(crate::locks::LockError::Forbidden(msg)) => {
            let resp = Response {
                status: Status::Forbidden,
                body_len: 0,
                content_type: String::new(),
                error: msg,
                descriptor: None,
            };
            let _ = send.write_all(&wire::encode_response(&resp)).await;
        }
        Err(e) => {
            let resp = Response {
                status: Status::Error,
                body_len: 0,
                content_type: String::new(),
                error: e.to_string(),
                descriptor: None,
            };
            let _ = send.write_all(&wire::encode_response(&resp)).await;
        }
    }
}

async fn handle_lock_list(send: &mut iroh::endpoint::SendStream, req: &Request, state: &IrohState) {
    let lock_db = match state.lock_db.as_ref() {
        Some(db) => db,
        None => {
            let resp = Response {
                status: Status::NotFound,
                body_len: 0,
                content_type: String::new(),
                error: "lock support not configured".into(),
                descriptor: None,
            };
            let _ = send.write_all(&wire::encode_response(&resp)).await;
            return;
        }
    };

    let filters = LockFilters {
        path: None,
        id: None,
        cursor: if req.cursor.is_empty() {
            None
        } else {
            Some(req.cursor.clone())
        },
        limit: if req.limit == 0 {
            None
        } else {
            Some(req.limit)
        },
    };

    match lock_db.list_locks(&req.repo_id, &filters) {
        Ok((records, next_cursor)) => {
            let result = serde_json::json!({
                "locks": records,
                "next_cursor": next_cursor,
            });
            let resp = Response {
                status: Status::Ok,
                body_len: 0,
                content_type: String::new(),
                error: String::new(),
                descriptor: Some(result),
            };
            let _ = send.write_all(&wire::encode_response(&resp)).await;
        }
        Err(e) => {
            let resp = Response {
                status: Status::Error,
                body_len: 0,
                content_type: String::new(),
                error: e.to_string(),
                descriptor: None,
            };
            let _ = send.write_all(&wire::encode_response(&resp)).await;
        }
    }
}

async fn handle_lock_verify(
    send: &mut iroh::endpoint::SendStream,
    req: &Request,
    auth_pubkey: Option<String>,
    state: &IrohState,
) {
    let pubkey = match auth_pubkey {
        Some(pk) => pk,
        None => {
            let resp = Response {
                status: Status::Unauthorized,
                body_len: 0,
                content_type: String::new(),
                error: "auth required for verify".into(),
                descriptor: None,
            };
            let _ = send.write_all(&wire::encode_response(&resp)).await;
            return;
        }
    };

    let lock_db = match state.lock_db.as_ref() {
        Some(db) => db,
        None => {
            let resp = Response {
                status: Status::NotFound,
                body_len: 0,
                content_type: String::new(),
                error: "lock support not configured".into(),
                descriptor: None,
            };
            let _ = send.write_all(&wire::encode_response(&resp)).await;
            return;
        }
    };

    let filters = LockFilters {
        path: None,
        id: None,
        cursor: if req.cursor.is_empty() {
            None
        } else {
            Some(req.cursor.clone())
        },
        limit: if req.limit == 0 {
            None
        } else {
            Some(req.limit)
        },
    };

    match lock_db.list_locks(&req.repo_id, &filters) {
        Ok((records, next_cursor)) => {
            let mut ours = Vec::new();
            let mut theirs = Vec::new();
            for record in records {
                if record.pubkey == pubkey {
                    ours.push(record);
                } else {
                    theirs.push(record);
                }
            }
            let result = serde_json::json!({
                "ours": ours,
                "theirs": theirs,
                "next_cursor": next_cursor,
            });
            let resp = Response {
                status: Status::Ok,
                body_len: 0,
                content_type: String::new(),
                error: String::new(),
                descriptor: Some(result),
            };
            let _ = send.write_all(&wire::encode_response(&resp)).await;
        }
        Err(e) => {
            let resp = Response {
                status: Status::Error,
                body_len: 0,
                content_type: String::new(),
                error: e.to_string(),
                descriptor: None,
            };
            let _ = send.write_all(&wire::encode_response(&resp)).await;
        }
    }
}
