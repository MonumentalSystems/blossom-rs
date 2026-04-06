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
    /// Maximum upload size in bytes. `None` = no limit.
    pub max_upload_size: Option<u64>,
    /// Require auth for uploads.
    pub require_auth: bool,
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
                error: format!("invalid request: {e}"),
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
            handle_upload(&mut send, body, auth_pubkey, &mut s).await;
        }
        Op::Delete => handle_delete(&mut send, &req.sha256, auth_pubkey, &mut s).await,
        Op::List => handle_list(&mut send, &req.pubkey, &s).await,
    }

    let _ = send.finish();
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
        Some(data) => {
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
    let status = if state.backend.exists(sha256) {
        Status::Ok
    } else {
        Status::NotFound
    };
    let resp = Response {
        status,
        body_len: 0,
        content_type: String::new(),
        error: String::new(),
        descriptor: None,
    };
    let _ = send.write_all(&wire::encode_response(&resp)).await;
}

async fn handle_upload(
    send: &mut iroh::endpoint::SendStream,
    data: Vec<u8>,
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

    // Require auth if configured.
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

    // Check upload permission.
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

    // Check max upload size.
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

    // Check quota.
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

    let mut cursor = std::io::Cursor::new(data);
    let descriptor = match state
        .backend
        .insert_stream(&mut cursor, size, &state.base_url)
    {
        Ok(desc) => desc,
        Err(e) => {
            let resp = Response {
                status: Status::Error,
                body_len: 0,
                content_type: String::new(),
                error: format!("storage error: {e}"),
                descriptor: None,
            };
            let _ = send.write_all(&wire::encode_response(&resp)).await;
            return;
        }
    };
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

    if state.backend.delete(sha256) {
        let _ = state.database.delete_upload(sha256);
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
