//! Iroh QUIC transport for Blossom.
//!
//! Implements `ProtocolHandler` to serve Blossom blob operations over
//! iroh's QUIC-based P2P connections. Peers connect by node ID — no
//! IP/DNS required.

use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use std::collections::{HashMap, VecDeque};
use tracing::{info, instrument, warn};

use super::wire::{self, Op, Request, Response, Status};
use crate::access::{Action, Role};
use crate::auth::verify_blossom_auth;
use crate::db::UploadRecord;
use crate::lfs::{compress, reconstruct_blob, LfsContext, LfsFileVersion, LfsStorageType};
use crate::locks::LockFilters;
use crate::protocol::{base64url_decode, BlobDescriptor, NostrEvent};
use crate::server::{ServerState, SharedState};

/// ALPN protocol identifier for Blossom over iroh.
pub const BLOSSOM_ALPN: &[u8] = b"/blossom/1";
const MAX_WIRE_HEADER: usize = 16 * 1024;
const DEFAULT_MAX_IROH_BODY: u64 = 256 * 1024 * 1024;
const STREAM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const MAX_CONCURRENT_STREAMS: usize = 64;
const MAX_IN_FLIGHT_IROH_BODY_BYTES: u32 = 256 * 1024 * 1024;
const MAX_REPLAY_ENTRIES: usize = 10_000;
const MAX_REPLAY_ENTRIES_PER_PRINCIPAL: usize = 256;

/// Blossom protocol handler for iroh connections.
///
/// Each incoming connection spawns a loop that accepts bidirectional
/// streams. Each stream carries one request + response.
///
/// Uses the same `SharedState` as the HTTP server, so both transports
/// share a single backend, database, lock DB, and LFS version DB.
#[derive(Debug, Clone)]
pub struct BlossomProtocol {
    state: SharedState,
    receiver: String,
    streams: std::sync::Arc<tokio::sync::Semaphore>,
    body_budget: InFlightBodyBudget,
}

impl BlossomProtocol {
    /// Create a new protocol handler sharing the given `SharedState`.
    pub fn new(state: SharedState, receiver_id: iroh::EndpointId) -> Self {
        Self {
            state,
            receiver: iroh_server_identity(&receiver_id),
            streams: std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_STREAMS)),
            body_budget: InFlightBodyBudget::new(MAX_IN_FLIGHT_IROH_BODY_BYTES),
        }
    }
}

impl ProtocolHandler for BlossomProtocol {
    fn accept(
        &self,
        conn: Connection,
    ) -> impl std::future::Future<Output = Result<(), AcceptError>> + Send {
        let state = self.state.clone();
        let receiver = self.receiver.clone();
        let streams = self.streams.clone();
        let body_budget = self.body_budget.clone();
        async move {
            let remote = conn.remote_id();
            info!(peer.id = %remote, "iroh connection accepted");

            loop {
                let (send, recv) = match conn.accept_bi().await {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let state = state.clone();
                let receiver = receiver.clone();
                let body_budget = body_budget.clone();
                let permit = match streams.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        warn!(peer.id = %remote, "iroh stream concurrency limit reached");
                        continue;
                    }
                };
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ = tokio::time::timeout(
                        STREAM_TIMEOUT,
                        handle_stream(send, recv, state, &receiver, body_budget),
                    )
                    .await;
                });
            }

            Ok(())
        }
    }
}

#[derive(Debug, Clone)]
struct InFlightBodyBudget {
    permits: std::sync::Arc<tokio::sync::Semaphore>,
    max_bytes: u32,
}

impl InFlightBodyBudget {
    fn new(max_bytes: u32) -> Self {
        Self {
            permits: std::sync::Arc::new(tokio::sync::Semaphore::new(max_bytes as usize)),
            max_bytes,
        }
    }

    fn try_reserve(&self, bytes: u64) -> Result<tokio::sync::OwnedSemaphorePermit, &'static str> {
        let bytes = u32::try_from(bytes).map_err(|_| "upload exceeds aggregate byte budget")?;
        if bytes > self.max_bytes {
            return Err("upload exceeds aggregate byte budget");
        }
        self.permits
            .clone()
            .try_acquire_many_owned(bytes)
            .map_err(|_| "iroh upload byte budget is exhausted")
    }
}

/// Handle a single bidi stream (one request + response).
#[instrument(name = "blossom.iroh.stream", skip_all)]
async fn handle_stream(
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    state: SharedState,
    receiver: &str,
    body_budget: InFlightBodyBudget,
) {
    // Read the request JSON line.
    let mut buf = Vec::with_capacity(4096);
    let mut byte = [0u8; 1];
    loop {
        match recv.read(&mut byte).await {
            Ok(Some(n)) => {
                debug_assert_eq!(n, 1);
                buf.push(byte[0]);
                if buf.len() > MAX_WIRE_HEADER {
                    warn!("iroh request header exceeds limit");
                    return;
                }
                if byte[0] == b'\n' {
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

    let (req, _) = match wire::decode_line::<Request>(&buf) {
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

    if matches!(req.op, Op::Get | Op::Head | Op::Delete | Op::Upload)
        && !crate::server::is_valid_sha256(&req.sha256)
    {
        reject_stream(&mut send, Status::Error, "invalid SHA256 hash").await;
        return;
    }

    let verified_auth = if !req.auth.is_empty() {
        match verify_auth(&req.auth, &req, receiver) {
            Ok(auth) => Some(auth),
            Err(e) => {
                reject_stream(&mut send, Status::Unauthorized, &e).await;
                return;
            }
        }
    } else {
        None
    };

    let auth_pubkey = verified_auth.as_ref().map(|auth| auth.pubkey.clone());

    let (_body_permit, body) = if req.op == Op::Upload {
        let max_body = state
            .lock()
            .await
            .requirements
            .max_size
            .unwrap_or(DEFAULT_MAX_IROH_BODY);
        if req.body_len == 0 {
            reject_stream(&mut send, Status::Error, "empty body").await;
            return;
        }
        if req.body_len > max_body {
            reject_stream(
                &mut send,
                Status::Error,
                &format!("body exceeds maximum of {max_body} bytes"),
            )
            .await;
            return;
        }

        let preflight = {
            let s = state.lock().await;
            preflight_upload(&s, &req, verified_auth.as_ref())
        };
        if let Err(error) = preflight {
            reject_stream(&mut send, error.status, &error.message).await;
            return;
        }

        let permit = match body_budget.try_reserve(req.body_len) {
            Ok(permit) => permit,
            Err(error) => {
                reject_stream(&mut send, Status::Error, error).await;
                return;
            }
        };
        if let Some(auth) = verified_auth.as_ref() {
            if !commit_auth_event(auth) {
                reject_stream(
                    &mut send,
                    Status::Unauthorized,
                    "authorization event has already been used",
                )
                .await;
                return;
            }
        }

        let body_len = match usize::try_from(req.body_len) {
            Ok(len) => len,
            Err(_) => {
                reject_stream(&mut send, Status::Error, "upload body is too large").await;
                return;
            }
        };
        let mut body = vec![0u8; body_len];
        if let Err(error) = recv.read_exact(&mut body).await {
            warn!(error.message = %error, "failed to read upload body");
            return;
        }
        (Some(permit), body)
    } else {
        if request_auth_binding(&req).is_some() {
            let auth = match verified_auth.as_ref() {
                Some(auth) => auth,
                None => {
                    reject_stream(&mut send, Status::Unauthorized, "auth required").await;
                    return;
                }
            };
            let preflight = {
                let s = state.lock().await;
                preflight_mutation(&s, &req, auth)
            };
            if let Err(error) = preflight {
                reject_stream(&mut send, error.status, &error.message).await;
                return;
            }
            if !commit_auth_event(auth) {
                reject_stream(
                    &mut send,
                    Status::Unauthorized,
                    "authorization event has already been used",
                )
                .await;
                return;
            }
        }
        (None, Vec::new())
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

async fn reject_stream(send: &mut iroh::endpoint::SendStream, status: Status, error: &str) {
    let response = Response {
        status,
        body_len: 0,
        content_type: String::new(),
        error: error.to_string(),
        descriptor: None,
    };
    let _ = send.write_all(&wire::encode_response(&response)).await;
    let _ = send.finish();
}

#[derive(Debug)]
struct GateError {
    status: Status,
    message: String,
}

fn gate_error(status: Status, message: impl Into<String>) -> GateError {
    GateError {
        status,
        message: message.into(),
    }
}

fn preflight_upload(
    state: &ServerState,
    req: &Request,
    auth: Option<&VerifiedAuth>,
) -> Result<(), GateError> {
    if state.requirements.require_auth && auth.is_none() {
        return Err(gate_error(Status::Unauthorized, "auth required for upload"));
    }
    let principal = auth.map_or("anonymous", |auth| auth.pubkey.as_str());
    if !state.access.is_allowed(principal, Action::Upload) {
        return Err(gate_error(
            Status::Forbidden,
            "upload not allowed for this pubkey",
        ));
    }
    let additional_bytes = if state
        .database
        .is_upload_owner(&req.sha256, principal)
        .unwrap_or(false)
    {
        0
    } else {
        req.body_len
    };
    state
        .database
        .check_quota(principal, additional_bytes)
        .map_err(|error| gate_error(Status::Forbidden, error.to_string()))?;
    check_rate_limit(state, principal)
}

fn preflight_mutation(
    state: &ServerState,
    req: &Request,
    auth: &VerifiedAuth,
) -> Result<(), GateError> {
    let allowed = match &req.op {
        Op::Delete => {
            let role = state.access.role(&auth.pubkey);
            role != Role::Denied
                && (role == Role::Admin
                    || state
                        .database
                        .is_upload_owner(&req.sha256, &auth.pubkey)
                        .unwrap_or(false))
        }
        Op::LockCreate | Op::LockDelete | Op::LockVerify => {
            state.access.is_allowed(&auth.pubkey, Action::Lock)
        }
        _ => true,
    };
    if !allowed {
        return Err(gate_error(
            Status::Forbidden,
            "operation not allowed for this pubkey",
        ));
    }
    if req.op == Op::LockDelete {
        if let Some(lock_db) = state.lock_db.as_ref() {
            if let Ok(record) = lock_db.get_lock(&req.repo_id, &req.lock_id) {
                let is_admin = state.access.role(&auth.pubkey) == Role::Admin;
                if record.pubkey != auth.pubkey && !is_admin {
                    return Err(gate_error(
                        Status::Forbidden,
                        "only the lock owner or an admin can unlock",
                    ));
                }
            }
        }
    }
    check_rate_limit(state, &auth.pubkey)
}

fn check_rate_limit(state: &ServerState, principal: &str) -> Result<(), GateError> {
    if state
        .rate_limiter
        .as_ref()
        .is_some_and(|limiter| !limiter.check(principal))
    {
        return Err(gate_error(Status::Error, "rate limit exceeded"));
    }
    Ok(())
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

/// Verify transport-specific Blossom auth. NIP-98 is HTTP-only and is not
/// accepted on the iroh protocol.
#[derive(Debug)]
struct VerifiedAuth {
    pubkey: String,
    event_id: String,
}

fn verify_auth(auth_header: &str, req: &Request, receiver: &str) -> Result<VerifiedAuth, String> {
    let b64 = auth_header.strip_prefix("Nostr ").unwrap_or(auth_header);

    let json_bytes = base64url_decode(b64).map_err(|e| format!("invalid auth encoding: {e}"))?;
    let event: NostrEvent =
        serde_json::from_slice(&json_bytes).map_err(|e| format!("invalid auth event: {e}"))?;

    let action = match &req.op {
        Op::Upload => "upload",
        Op::Delete => "delete",
        Op::Get => "get",
        Op::List => "get",
        Op::Head => "get",
        Op::LockCreate | Op::LockDelete | Op::LockList | Op::LockVerify => "lock",
    };

    if event.kind != 24242 {
        return Err("iroh requires a Blossom kind:24242 authorization event".into());
    }
    verify_blossom_auth(&event, Some(action)).map_err(|e| e.to_string())?;
    if request_auth_binding(req).is_some() {
        let servers: Vec<_> = event
            .tags
            .iter()
            .filter(|tag| tag.first().is_some_and(|value| value == "server"))
            .collect();
        if servers.len() != 1 || servers[0].len() != 2 || servers[0][1] != receiver {
            return Err("authorization is for a different iroh server".into());
        }
    }
    if let Some(expected_binding) = request_auth_binding(req) {
        let hashes: Vec<_> = event
            .tags
            .iter()
            .filter(|tag| tag.len() == 2 && tag[0] == "x")
            .collect();
        if hashes.len() != 1 || hashes[0][1] != expected_binding {
            return Err("authorization is not bound to this request".into());
        }
    }
    if req.op == Op::Upload {
        verify_lfs_auth_binding(&event, req)?;
    }
    Ok(VerifiedAuth {
        pubkey: event.pubkey,
        event_id: event.id,
    })
}

pub(super) fn iroh_server_identity(id: &iroh::EndpointId) -> String {
    format!("iroh://{id}")
}

pub(super) fn request_auth_binding(req: &Request) -> Option<String> {
    match &req.op {
        Op::Upload | Op::Delete => Some(req.sha256.clone()),
        Op::LockCreate => Some(crate::protocol::sha256_hex(
            serde_json::to_vec(&("lock-create", &req.repo_id, &req.lock_path))
                .unwrap_or_default()
                .as_slice(),
        )),
        Op::LockDelete => Some(crate::protocol::sha256_hex(
            serde_json::to_vec(&("lock-delete", &req.repo_id, &req.lock_id, req.force))
                .unwrap_or_default()
                .as_slice(),
        )),
        Op::LockVerify => Some(crate::protocol::sha256_hex(
            serde_json::to_vec(&("lock-verify", &req.repo_id, &req.cursor, req.limit))
                .unwrap_or_default()
                .as_slice(),
        )),
        _ => None,
    }
}

fn verify_lfs_auth_binding(event: &NostrEvent, req: &Request) -> Result<(), String> {
    let unique = |name: &str| -> Result<Option<&str>, String> {
        let tags: Vec<_> = event
            .tags
            .iter()
            .filter(|tag| tag.first().is_some_and(|value| value == name))
            .collect();
        match tags.as_slice() {
            [] => Ok(None),
            [tag] if tag.len() == 2 => Ok(Some(tag[1].as_str())),
            _ => Err(format!("malformed or duplicate {name} authorization tag")),
        }
    };
    let lfs_tags = event
        .tags
        .iter()
        .filter(|tag| {
            tag.first()
                .is_some_and(|value| value == "t" && tag.get(1).is_some_and(|value| value == "lfs"))
        })
        .count();
    let manifest_tags = event
        .tags
        .iter()
        .filter(|tag| tag.as_slice() == ["manifest"])
        .count();
    let matches = lfs_tags == usize::from(!req.lfs_path.is_empty() || !req.lfs_repo.is_empty())
        && unique("path")? == (!req.lfs_path.is_empty()).then_some(req.lfs_path.as_str())
        && unique("repo")? == (!req.lfs_repo.is_empty()).then_some(req.lfs_repo.as_str())
        && unique("base")? == (!req.lfs_base.is_empty()).then_some(req.lfs_base.as_str())
        && manifest_tags == usize::from(req.lfs_manifest);
    if matches {
        Ok(())
    } else {
        Err("authorization is not bound to this LFS context".into())
    }
}

#[derive(Debug)]
struct ReplayEntry {
    principal: String,
    expires_at: u64,
}

#[derive(Debug)]
struct ReplayCache {
    entries: HashMap<String, ReplayEntry>,
    order: VecDeque<String>,
    per_principal: HashMap<String, usize>,
    max_entries: usize,
    max_per_principal: usize,
}

impl ReplayCache {
    fn new(max_entries: usize, max_per_principal: usize) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            per_principal: HashMap::new(),
            max_entries,
            max_per_principal,
        }
    }

    fn commit(&mut self, event_id: &str, principal: &str, now: u64) -> bool {
        self.prune_expired(now);
        if self.entries.contains_key(event_id) {
            return false;
        }

        while self.per_principal.get(principal).copied().unwrap_or(0) >= self.max_per_principal {
            if !self.evict_oldest_for(principal) {
                break;
            }
        }
        while self.entries.len() >= self.max_entries {
            if !self.evict_oldest() {
                break;
            }
        }

        self.entries.insert(
            event_id.to_string(),
            ReplayEntry {
                principal: principal.to_string(),
                expires_at: now.saturating_add(120),
            },
        );
        self.order.push_back(event_id.to_string());
        *self.per_principal.entry(principal.to_string()).or_default() += 1;
        true
    }

    fn prune_expired(&mut self, now: u64) {
        while let Some(event_id) = self.order.front() {
            let expired = self
                .entries
                .get(event_id)
                .is_none_or(|entry| entry.expires_at <= now);
            if !expired {
                break;
            }
            self.evict_oldest();
        }
    }

    fn evict_oldest(&mut self) -> bool {
        let Some(event_id) = self.order.pop_front() else {
            return false;
        };
        self.remove_entry(&event_id);
        true
    }

    fn evict_oldest_for(&mut self, principal: &str) -> bool {
        let Some(position) = self.order.iter().position(|event_id| {
            self.entries
                .get(event_id)
                .is_some_and(|entry| entry.principal == principal)
        }) else {
            return false;
        };
        let event_id = self.order.remove(position).expect("position was found");
        self.remove_entry(&event_id);
        true
    }

    fn remove_entry(&mut self, event_id: &str) {
        let Some(entry) = self.entries.remove(event_id) else {
            return;
        };
        if let Some(count) = self.per_principal.get_mut(&entry.principal) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.per_principal.remove(&entry.principal);
            }
        }
    }
}

fn commit_auth_event(auth: &VerifiedAuth) -> bool {
    static SEEN: std::sync::OnceLock<std::sync::Mutex<ReplayCache>> = std::sync::OnceLock::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    SEEN.get_or_init(|| {
        std::sync::Mutex::new(ReplayCache::new(
            MAX_REPLAY_ENTRIES,
            MAX_REPLAY_ENTRIES_PER_PRINCIPAL,
        ))
    })
    .lock()
    .unwrap_or_else(|poisoned| poisoned.into_inner())
    .commit(&auth.event_id, &auth.pubkey, now)
}

async fn handle_get(send: &mut iroh::endpoint::SendStream, sha256: &str, state: &ServerState) {
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

async fn handle_head(send: &mut iroh::endpoint::SendStream, sha256: &str, state: &ServerState) {
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
    state: &mut ServerState,
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

    if state.requirements.require_auth && auth_pubkey.is_none() {
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

    if let Some(max) = state.requirements.max_size {
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

    let additional_bytes = if state
        .database
        .is_upload_owner(&req.sha256, &pubkey)
        .unwrap_or(false)
    {
        0
    } else {
        size
    };
    if let Err(e) = state.database.check_quota(&pubkey, additional_bytes) {
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
    if original_sha256 != req.sha256 {
        let resp = Response {
            status: Status::Error,
            body_len: 0,
            content_type: String::new(),
            error: "upload body SHA256 does not match request".into(),
            descriptor: None,
        };
        let _ = send.write_all(&wire::encode_response(&resp)).await;
        return;
    }

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
            if let Err(error) = state.backend.try_insert_with_hash(
                stored_data,
                &original_sha256,
                original_size,
                &base_url,
            ) {
                let resp = Response {
                    status: Status::Error,
                    body_len: 0,
                    content_type: String::new(),
                    error: format!("storage write failed: {error}"),
                    descriptor: None,
                };
                let _ = send.write_all(&wire::encode_response(&resp)).await;
                return;
            }
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
    if let Err(error) = state.database.record_upload(&record) {
        let resp = Response {
            status: Status::Error,
            body_len: 0,
            content_type: String::new(),
            error: format!("metadata write failed: {error}"),
            descriptor: None,
        };
        let _ = send.write_all(&wire::encode_response(&resp)).await;
        return;
    }

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
    state: &mut ServerState,
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

    // Members remove only their own ownership reference. Keep shared content
    // until its final owner removes it.
    if role != Role::Admin {
        if !state
            .database
            .is_upload_owner(sha256, &pubkey)
            .unwrap_or(false)
        {
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
        let owner_count = match state.database.upload_owner_count(sha256) {
            Ok(count) => count,
            Err(_) => {
                let resp = Response {
                    status: Status::Error,
                    body_len: 0,
                    content_type: String::new(),
                    error: "failed to count blob owners".into(),
                    descriptor: None,
                };
                let _ = send.write_all(&wire::encode_response(&resp)).await;
                return;
            }
        };
        if owner_count > 1 && state.database.delete_upload_owner(sha256, &pubkey).is_err() {
            let resp = Response {
                status: Status::Error,
                body_len: 0,
                content_type: String::new(),
                error: "failed to update blob ownership".into(),
                descriptor: None,
            };
            let _ = send.write_all(&wire::encode_response(&resp)).await;
            return;
        }
        if owner_count > 1 {
            let resp = Response {
                status: Status::Ok,
                body_len: 0,
                content_type: String::new(),
                error: String::new(),
                descriptor: None,
            };
            let _ = send.write_all(&wire::encode_response(&resp)).await;
            return;
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
                if let Err(error) = state.backend.try_insert_with_hash(
                    compressed,
                    &delta_version.sha256,
                    delta_version.original_size as u64,
                    &base_url_clone,
                ) {
                    let resp = Response {
                        status: Status::Error,
                        body_len: 0,
                        content_type: String::new(),
                        error: format!("delta rebase storage failed: {error}"),
                        descriptor: None,
                    };
                    let _ = send.write_all(&wire::encode_response(&resp)).await;
                    return;
                }
                if let Some(ref mut lfs_db) = state.lfs_version_db {
                    if let Err(error) = lfs_db.update_version(
                        &delta_version.sha256,
                        LfsStorageType::Compressed,
                        None,
                        base_decompressed.len() as i64,
                    ) {
                        let resp = Response {
                            status: Status::Error,
                            body_len: 0,
                            content_type: String::new(),
                            error: format!("delta metadata update failed: {error}"),
                            descriptor: None,
                        };
                        let _ = send.write_all(&wire::encode_response(&resp)).await;
                        return;
                    }
                }
            }
        }
    }

    match state.backend.try_delete(sha256) {
        Ok(true) => {
            if let Err(error) = state.database.delete_upload(sha256) {
                let resp = Response {
                    status: Status::Error,
                    body_len: 0,
                    content_type: String::new(),
                    error: format!("metadata delete failed: {error}"),
                    descriptor: None,
                };
                let _ = send.write_all(&wire::encode_response(&resp)).await;
                return;
            }

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
        }
        Ok(false) => {
            let resp = Response {
                status: Status::NotFound,
                body_len: 0,
                content_type: String::new(),
                error: "not found".into(),
                descriptor: None,
            };
            let _ = send.write_all(&wire::encode_response(&resp)).await;
        }
        Err(error) => {
            let resp = Response {
                status: Status::Error,
                body_len: 0,
                content_type: String::new(),
                error: format!("storage delete failed: {error}"),
                descriptor: None,
            };
            let _ = send.write_all(&wire::encode_response(&resp)).await;
        }
    }
}

async fn handle_list(send: &mut iroh::endpoint::SendStream, pubkey: &str, state: &ServerState) {
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
    state: &mut ServerState,
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
    state: &mut ServerState,
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

    let force = req.force && is_admin;

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

async fn handle_lock_list(
    send: &mut iroh::endpoint::SendStream,
    req: &Request,
    state: &ServerState,
) {
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
    state: &ServerState,
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

#[cfg(test)]
mod auth_tests {
    use super::*;
    use crate::auth::{auth_header_value, build_blossom_auth, BlossomSigner, Signer};

    #[test]
    fn mutation_auth_is_bound_to_receiving_iroh_server() {
        let signer = Signer::generate();
        let hash = crate::protocol::sha256_hex(b"receiver-bound upload");
        let receiver_a = "iroh://server-a";
        let requests = [
            Request {
                op: Op::Upload,
                sha256: hash.clone(),
                ..Default::default()
            },
            Request {
                op: Op::Delete,
                sha256: hash,
                ..Default::default()
            },
            Request {
                op: Op::LockCreate,
                repo_id: "repo".into(),
                lock_path: "assets/model.bin".into(),
                ..Default::default()
            },
            Request {
                op: Op::LockDelete,
                repo_id: "repo".into(),
                lock_id: "lock-1".into(),
                ..Default::default()
            },
            Request {
                op: Op::LockVerify,
                repo_id: "repo".into(),
                limit: 100,
                ..Default::default()
            },
        ];

        for mut request in requests {
            let action = match &request.op {
                Op::Upload => "upload",
                Op::Delete => "delete",
                _ => "lock",
            };
            let binding = request_auth_binding(&request).unwrap();
            let event = build_blossom_auth(&signer, action, Some(&binding), Some(receiver_a), "");
            request.auth = auth_header_value(&event);

            assert!(verify_auth(&request.auth, &request, "iroh://server-b").is_err());
            assert_eq!(
                verify_auth(&request.auth, &request, receiver_a)
                    .unwrap()
                    .pubkey,
                signer.public_key_hex()
            );
        }
    }

    #[test]
    fn replay_validation_and_commit_are_separate() {
        let signer = Signer::generate();
        let hash = crate::protocol::sha256_hex(b"deferred replay commitment");
        let receiver = "iroh://server-replay";
        let event = build_blossom_auth(&signer, "upload", Some(&hash), Some(receiver), "");
        let request = Request {
            op: Op::Upload,
            sha256: hash,
            auth: auth_header_value(&event),
            ..Default::default()
        };

        let first = verify_auth(&request.auth, &request, receiver).unwrap();
        let second = verify_auth(&request.auth, &request, receiver).unwrap();
        assert_eq!(first.event_id, second.event_id);
        assert!(commit_auth_event(&first));
        assert!(!commit_auth_event(&second));
    }

    #[test]
    fn replay_cache_evicts_without_global_fail_closed_dos() {
        let mut cache = ReplayCache::new(3, 2);
        assert!(cache.commit("alice-1", "alice", 1));
        assert!(cache.commit("alice-2", "alice", 1));
        assert!(cache.commit("alice-3", "alice", 1));
        assert!(!cache.entries.contains_key("alice-1"));
        assert!(cache.entries.contains_key("alice-3"));

        assert!(cache.commit("bob-1", "bob", 1));
        assert!(cache.commit("bob-2", "bob", 1));
        assert!(cache.entries.len() <= 3);
        assert!(cache.entries.contains_key("bob-2"));
        assert!(!cache.commit("bob-2", "bob", 1));

        assert!(cache.commit("bob-2", "bob", 122));
    }

    #[test]
    fn aggregate_body_budget_is_hard_and_released_with_permit() {
        let budget = InFlightBodyBudget::new(10);
        let first = budget.try_reserve(7).unwrap();
        assert!(budget.try_reserve(4).is_err());
        assert!(budget.try_reserve(11).is_err());
        drop(first);
        assert!(budget.try_reserve(10).is_ok());
    }

    #[tokio::test]
    async fn rate_rejection_happens_before_replay_commitment() {
        let signer = Signer::generate();
        let hash = crate::protocol::sha256_hex(b"rate limited body");
        let receiver = "iroh://rate-limited-server";
        let event = build_blossom_auth(&signer, "upload", Some(&hash), Some(receiver), "");
        let request = Request {
            op: Op::Upload,
            sha256: hash,
            auth: auth_header_value(&event),
            body_len: 17,
            ..Default::default()
        };
        let auth = verify_auth(&request.auth, &request, receiver).unwrap();
        let server = crate::BlobServer::builder(
            crate::storage::MemoryBackend::new(),
            "iroh://rate-limited-server",
        )
        .require_auth()
        .rate_limiter(crate::ratelimit::RateLimiter::new(
            crate::ratelimit::RateLimitConfig {
                max_tokens: 0,
                refill_rate: 0.0,
            },
        ))
        .build();
        let state = server.shared_state();
        let guard = state.lock().await;

        let error = preflight_upload(&guard, &request, Some(&auth)).unwrap_err();
        assert_eq!(error.message, "rate limit exceeded");
        drop(guard);
        assert!(commit_auth_event(&auth));
    }
}
