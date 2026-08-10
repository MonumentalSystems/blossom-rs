//! GRASP git HTTP smart protocol server.
//!
//! Serves git repositories over HTTP for clone/push operations.
//! Repositories are organized as `{npub}/{repo_name}.git` on the filesystem.

pub mod command;
pub mod pktline;
pub mod validation;

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::extract::{OriginalUri, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use nostr::nips::nip19::FromBech32;
use sha2::{Digest, Sha256};

use crate::Nip34State;

/// Resolve an existing bare repository without creating state for an
/// unauthenticated discovery request.
async fn ensure_repo(
    state: &Nip34State,
    npub: &str,
    repo_name: &str,
) -> Option<std::path::PathBuf> {
    let path = state.repo_path(npub, repo_name)?;
    path.join("HEAD").exists().then_some(path)
}

/// Build the git HTTP router.
///
/// Routes:
/// - `GET /{npub}/{repo}/info/refs` — advertise refs
/// - `POST /{npub}/{repo}/git-upload-pack` — fetch objects (public)
/// - `POST /{npub}/{repo}/git-receive-pack` — push objects (auth required)
pub fn git_router() -> axum::Router<Arc<Nip34State>> {
    // {repo} captures both "test-repo" and "test-repo.git" — handlers
    // strip the .git suffix. This is compatible with ngit/git-remote-nostr
    // which appends .git to clone URLs.
    axum::Router::new()
        .route("/{npub}/{repo}/info/refs", axum::routing::get(info_refs))
        .route(
            "/{npub}/{repo}/git-upload-pack",
            axum::routing::post(upload_pack),
        )
        .route(
            "/{npub}/{repo}/git-receive-pack",
            axum::routing::post(receive_pack),
        )
}

/// Verify that the Authorization header contains a valid Nostr event
/// signed by the expected npub. Returns the pubkey hex on success.
struct VerifiedPushAuth {
    pubkey: String,
    event_id: String,
    now: u64,
}

fn verify_push_auth_claims(
    headers: &HeaderMap,
    expected_npub: &str,
    repo_name: &str,
    expected_url: &str,
    method: &str,
    body_hash: Option<&str>,
) -> Result<VerifiedPushAuth, &'static str> {
    let auth_value = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or("push requires Authorization header")?;

    // Accept "Nostr <base64>" format
    let b64 = auth_value
        .strip_prefix("Nostr ")
        .ok_or("authorization must use 'Nostr <base64>' format")?;

    use base64::Engine;
    let json_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(b64))
        .map_err(|_| "invalid base64 in authorization")?;

    let event: nostr::Event =
        serde_json::from_slice(&json_bytes).map_err(|_| "invalid Nostr event in authorization")?;

    // Verify event signature
    event.verify().map_err(|_| "invalid event signature")?;

    // Check that the event pubkey matches the expected npub
    let expected_pubkey = if expected_npub.starts_with("npub1") {
        nostr::PublicKey::from_bech32(expected_npub)
            .map(|pk| pk.to_hex())
            .map_err(|_| "invalid npub in URL")?
    } else {
        expected_npub.to_string()
    };

    if event.pubkey.to_hex() != expected_pubkey {
        return Err("authorization pubkey does not match repository owner");
    }

    let value = serde_json::to_value(&event).map_err(|_| "invalid authorization event")?;
    let created_at = value
        .get("created_at")
        .and_then(|v| v.as_u64())
        .ok_or("missing created_at")?;
    let kind = value.get("kind").and_then(|v| v.as_u64()).unwrap_or(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if kind != 24242 || created_at > now.saturating_add(30) || now.saturating_sub(created_at) > 60 {
        return Err("push authorization is stale, future-dated, or wrong kind");
    }
    let tags = value
        .get("tags")
        .and_then(|v| v.as_array())
        .ok_or("missing authorization tags")?;
    let unique = |name: &str| -> Option<String> {
        let matching: Vec<_> = tags
            .iter()
            .filter_map(|tag| tag.as_array())
            .filter(|tag| tag.first().and_then(|v| v.as_str()) == Some(name))
            .collect();
        if matching.len() != 1 || matching[0].len() != 2 {
            return None;
        }
        matching[0]
            .get(1)
            .and_then(|value| value.as_str())
            .map(str::to_string)
    };
    if unique("t").as_deref() != Some("git-push")
        || unique("repo").as_deref() != Some(repo_name)
        || !unique("method").is_some_and(|v| v.eq_ignore_ascii_case(method))
    {
        return Err("push authorization is not bound to this operation");
    }
    let url = unique("u").ok_or("push authorization missing URL")?;
    url::Url::parse(&url).map_err(|_| "push authorization URL is invalid")?;
    if url != expected_url {
        return Err("push authorization is for a different repository or server");
    }
    let expiration = unique("expiration")
        .and_then(|v| v.parse::<u64>().ok())
        .ok_or("push authorization missing expiration")?;
    if expiration < now || expiration > created_at.saturating_add(120) {
        return Err("push authorization expired");
    }
    if let Some(hash) = body_hash {
        if unique("x").as_deref() != Some(hash) {
            return Err("push authorization is for a different request body");
        }
    }
    let nonce_present = match unique("nonce") {
        Some(nonce) => !nonce.is_empty(),
        None => false,
    };
    if !nonce_present {
        return Err("push authorization is missing a nonce");
    }
    Ok(VerifiedPushAuth {
        pubkey: event.pubkey.to_hex(),
        event_id: event.id.to_hex(),
        now,
    })
}

fn verify_push_auth(
    headers: &HeaderMap,
    expected_npub: &str,
    repo_name: &str,
    expected_url: &str,
    method: &str,
    body_hash: Option<&str>,
) -> Result<String, &'static str> {
    let verified = verify_push_auth_claims(
        headers,
        expected_npub,
        repo_name,
        expected_url,
        method,
        body_hash,
    )?;
    if !mark_auth_event_once(&verified.pubkey, &verified.event_id, verified.now) {
        return Err("push authorization has already been used");
    }
    Ok(verified.pubkey)
}

const REPLAY_CACHE_CAPACITY: usize = 10_000;
const REPLAY_CACHE_PER_PRINCIPAL: usize = 256;

struct ReplayEntry {
    principal: String,
    expires_at: u64,
}

struct ReplayCache {
    entries: HashMap<String, ReplayEntry>,
    insertion_order: VecDeque<String>,
    by_principal: HashMap<String, VecDeque<String>>,
    capacity: usize,
    per_principal: usize,
}

impl ReplayCache {
    fn new(capacity: usize, per_principal: usize) -> Self {
        Self {
            entries: HashMap::new(),
            insertion_order: VecDeque::new(),
            by_principal: HashMap::new(),
            capacity,
            per_principal,
        }
    }

    fn remove(&mut self, event_id: &str) {
        let Some(entry) = self.entries.remove(event_id) else {
            return;
        };
        if let Some(ids) = self.by_principal.get_mut(&entry.principal) {
            ids.retain(|id| id != event_id);
            if ids.is_empty() {
                self.by_principal.remove(&entry.principal);
            }
        }
    }

    fn prune_expired(&mut self, now: u64) {
        while let Some(event_id) = self.insertion_order.front().cloned() {
            match self.entries.get(&event_id) {
                None => {
                    self.insertion_order.pop_front();
                }
                Some(entry) if entry.expires_at <= now => {
                    self.insertion_order.pop_front();
                    self.remove(&event_id);
                }
                Some(_) => break,
            }
        }
    }

    fn check_and_insert(
        &mut self,
        principal: &str,
        event_id: &str,
        now: u64,
        expires_at: u64,
    ) -> bool {
        self.prune_expired(now);
        if self.entries.contains_key(event_id) {
            return false;
        }
        while self
            .by_principal
            .get(principal)
            .is_some_and(|ids| ids.len() >= self.per_principal)
        {
            let oldest = self
                .by_principal
                .get_mut(principal)
                .and_then(VecDeque::pop_front);
            if let Some(oldest) = oldest {
                self.remove(&oldest);
            } else {
                break;
            }
        }
        while self.entries.len() >= self.capacity {
            let Some(oldest) = self.insertion_order.pop_front() else {
                break;
            };
            self.remove(&oldest);
        }
        self.entries.insert(
            event_id.to_string(),
            ReplayEntry {
                principal: principal.to_string(),
                expires_at,
            },
        );
        self.insertion_order.push_back(event_id.to_string());
        self.by_principal
            .entry(principal.to_string())
            .or_default()
            .push_back(event_id.to_string());
        true
    }
}

fn mark_auth_event_once(principal: &str, event_id: &str, now: u64) -> bool {
    static SEEN: std::sync::OnceLock<std::sync::Mutex<ReplayCache>> = std::sync::OnceLock::new();
    let mut seen = SEEN
        .get_or_init(|| {
            std::sync::Mutex::new(ReplayCache::new(
                REPLAY_CACHE_CAPACITY,
                REPLAY_CACHE_PER_PRINCIPAL,
            ))
        })
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    seen.check_and_insert(principal, event_id, now, now.saturating_add(120))
}

/// GET /{npub}/{repo}/info/refs?service=git-upload-pack
async fn info_refs(
    State(state): State<Arc<Nip34State>>,
    Path((npub, repo)): Path<(String, String)>,
    OriginalUri(original_uri): OriginalUri,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let repo_name = repo.trim_end_matches(".git");
    let repo_path = match ensure_repo(&state, &npub, repo_name).await {
        Some(p) => p,
        None => return (StatusCode::NOT_FOUND, "repository not found").into_response(),
    };

    let service = params
        .get("service")
        .map(String::as_str)
        .unwrap_or("git-upload-pack");
    if !matches!(service, "git-upload-pack" | "git-receive-pack") {
        return (StatusCode::BAD_REQUEST, "unsupported git service").into_response();
    }
    if service == "git-receive-pack"
        && verify_push_auth(
            &headers,
            &npub,
            repo_name,
            &format!(
                "{}{}",
                state.config.server_url.trim_end_matches('/'),
                original_uri
            ),
            "GET",
            None,
        )
        .is_err()
    {
        return (
            StatusCode::UNAUTHORIZED,
            "valid push authorization required",
        )
            .into_response();
    }

    let git_cmd = command::GitCommand::new(&state.config.git_path, &repo_path);
    let is_v2 = false; // TODO: detect git protocol version from headers

    match git_cmd.refs(service, is_v2).await {
        Ok(body) => {
            let content_type = format!("application/x-{}-advertisement", service);
            let pkt_header = format!("# service={}\n", service);
            let pkt_len = pkt_header.len() + 4;
            let pkt_line = format!("{:04x}{}", pkt_len, pkt_header);

            let mut output = pkt_line.into_bytes();
            output.extend_from_slice(b"0000");
            output.extend_from_slice(&body);

            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, content_type)],
                output,
            )
                .into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    }
}

/// POST /{npub}/{repo}/git-upload-pack (public — no auth required)
async fn upload_pack(
    State(state): State<Arc<Nip34State>>,
    Path((npub, repo)): Path<(String, String)>,
    body: Body,
) -> impl IntoResponse {
    let repo_name = repo.trim_end_matches(".git");
    let repo_path = match ensure_repo(&state, &npub, repo_name).await {
        Some(p) => p,
        None => return (StatusCode::NOT_FOUND, "repository not found").into_response(),
    };
    let _body_permit = match GIT_BODY_BUFFER_LIMIT.try_acquire() {
        Ok(permit) => permit,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "git body capacity exhausted",
            )
                .into_response()
        }
    };
    let body = match to_bytes(body, 256 * 1024 * 1024).await {
        Ok(body) => body,
        Err(_) => {
            return (StatusCode::PAYLOAD_TOO_LARGE, "git request body too large").into_response()
        }
    };

    let git_cmd = command::GitCommand::new(&state.config.git_path, &repo_path);

    match git_cmd.upload_pack(&body, false).await {
        Ok(output) => (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                "application/x-git-upload-pack-result".to_string(),
            )],
            output,
        )
            .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    }
}

/// POST /{npub}/{repo}/git-receive-pack
///
/// GRASP push validation: checks ref updates against Nostr relay state
/// (kind:30617 maintainers + kind:30618 expected refs).
/// Also accepts optional `Authorization: Nostr <base64>` header for
/// additional auth (not required per GRASP spec).
async fn receive_pack(
    State(state): State<Arc<Nip34State>>,
    Path((npub, repo)): Path<(String, String)>,
    OriginalUri(original_uri): OriginalUri,
    headers: HeaderMap,
    body: Body,
) -> impl IntoResponse {
    let repo_name = repo.trim_end_matches(".git");
    let expected_url = format!(
        "{}{}",
        state.config.server_url.trim_end_matches('/'),
        original_uri
    );
    if let Err(error) =
        verify_push_auth_claims(&headers, &npub, repo_name, &expected_url, "POST", None)
    {
        return (StatusCode::UNAUTHORIZED, error).into_response();
    }
    let _body_permit = match GIT_BODY_BUFFER_LIMIT.try_acquire() {
        Ok(permit) => permit,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "git body capacity exhausted",
            )
                .into_response()
        }
    };
    let body = match to_bytes(body, 256 * 1024 * 1024).await {
        Ok(body) => body,
        Err(_) => {
            return (StatusCode::PAYLOAD_TOO_LARGE, "git request body too large").into_response()
        }
    };
    let body_hash = hex::encode(Sha256::digest(&body));
    if let Err(error) = verify_push_auth(
        &headers,
        &npub,
        repo_name,
        &expected_url,
        "POST",
        Some(&body_hash),
    ) {
        return (StatusCode::UNAUTHORIZED, error).into_response();
    }
    let repo_path = match state.repo_path(&npub, repo_name) {
        Some(path) if path.join("HEAD").exists() => path,
        Some(_) => match state.create_bare_repo(&npub, repo_name, "").await {
            Ok(path) => path,
            Err(error) => return (StatusCode::INTERNAL_SERVER_ERROR, error).into_response(),
        },
        None => {
            return (StatusCode::BAD_REQUEST, "invalid repository owner or name").into_response()
        }
    };

    // Parse ref updates from the pkt-line body
    let ref_updates = match pktline::parse_ref_updates(&body) {
        Ok(updates) => updates,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };

    // Resolve author pubkey from npub
    let author_hex = if npub.starts_with("npub1") {
        match nostr::nips::nip19::FromBech32::from_bech32(&npub) {
            Ok(pk) => nostr::PublicKey::to_hex(&pk),
            Err(_) => return (StatusCode::BAD_REQUEST, "invalid npub").into_response(),
        }
    } else {
        npub.clone()
    };

    // GRASP validation: check against relay state
    // Check if repo is empty. Authentication is still mandatory for the first
    // push; relay-state validation begins once refs exist.
    let is_empty_repo = !repo_path.join("refs/heads").exists()
        || std::fs::read_dir(repo_path.join("refs/heads"))
            .map(|mut d| d.next().is_none())
            .unwrap_or(true);

    if !is_empty_repo {
        match validation::validate_push(&ref_updates, &state.database, &author_hex, repo_name).await
        {
            Ok(errors) if errors.is_empty() => {
                // All refs accepted
            }
            Ok(errors) => {
                let msg = errors
                    .iter()
                    .map(|(r, e)| format!("{}: {}", r, e))
                    .collect::<Vec<_>>()
                    .join("; ");
                return (StatusCode::FORBIDDEN, msg).into_response();
            }
            Err((status, msg)) => {
                let sc = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                return (sc, msg).into_response();
            }
        }
    }

    let git_cmd = command::GitCommand::new(&state.config.git_path, &repo_path);

    match git_cmd.receive_pack(&body).await {
        Ok(output) => (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                "application/x-git-receive-pack-result".to_string(),
            )],
            output,
        )
            .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    }
}

// A Git pack may consume the full 256 MiB endpoint limit. Keep the permit for
// the subprocess lifetime so aggregate buffered pack input remains bounded.
static GIT_BODY_BUFFER_LIMIT: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll};

    struct PendingBody {
        polled: Arc<AtomicBool>,
    }

    impl futures_core::Stream for PendingBody {
        type Item = Result<axum::body::Bytes, Infallible>;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            self.polled.store(true, Ordering::SeqCst);
            Poll::Pending
        }
    }

    #[test]
    fn replay_cache_saturation_does_not_reject_authorized_traffic() {
        let mut cache = ReplayCache::new(3, 2);
        assert!(cache.check_and_insert("attacker", "a1", 1, 100));
        assert!(cache.check_and_insert("attacker", "a2", 1, 100));
        assert!(cache.check_and_insert("attacker", "a3", 1, 100));
        assert!(cache.check_and_insert("other-attacker", "b1", 1, 100));
        assert!(cache.check_and_insert("authorized", "good", 1, 100));
        assert!(!cache.check_and_insert("authorized", "good", 1, 100));
    }

    #[tokio::test]
    async fn receive_pack_denial_does_not_read_request_body() {
        let temp = tempfile::tempdir().unwrap();
        let config = crate::Nip34Config {
            lmdb_path: temp.path().join("lmdb"),
            repos_path: temp.path().join("repos"),
            ..Default::default()
        };
        let state = Arc::new(crate::Nip34State::new(config).await.unwrap());
        let polled = Arc::new(AtomicBool::new(false));
        let body = Body::from_stream(PendingBody {
            polled: polled.clone(),
        });
        let response = receive_pack(
            State(state),
            Path(("00".repeat(32), "repo".to_string())),
            OriginalUri("/00/repo/git-receive-pack".parse().unwrap()),
            HeaderMap::new(),
            body,
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(!polled.load(Ordering::SeqCst));
    }

    fn push_headers(keys: &nostr::Keys, url: &str, repo: &str, body_hash: &str) -> HeaderMap {
        use nostr::prelude::*;
        let expiration = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 60;
        let event = EventBuilder::new(Kind::Custom(24242), "")
            .tags([
                Tag::custom(TagKind::custom("t"), ["git-push"]),
                Tag::custom(TagKind::custom("repo"), [repo]),
                Tag::custom(TagKind::custom("method"), ["POST"]),
                Tag::custom(TagKind::custom("u"), [url]),
                Tag::custom(TagKind::custom("x"), [body_hash]),
                Tag::custom(TagKind::custom("nonce"), [uuid::Uuid::new_v4().to_string()]),
                Tag::custom(TagKind::custom("expiration"), [expiration.to_string()]),
            ])
            .sign_with_keys(keys)
            .unwrap();
        let json = serde_json::to_vec(&event).unwrap();
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &json);
        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Nostr {b64}").parse().unwrap());
        headers
    }

    #[test]
    fn test_verify_push_auth_missing_header() {
        let headers = HeaderMap::new();
        assert!(verify_push_auth(
            &headers,
            "npub1test",
            "repo",
            "http://localhost/repo",
            "POST",
            None
        )
        .is_err());
    }

    #[test]
    fn test_verify_push_auth_wrong_format() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer token".parse().unwrap());
        assert!(verify_push_auth(
            &headers,
            "npub1test",
            "repo",
            "http://localhost/repo",
            "POST",
            None
        )
        .is_err());
    }

    #[test]
    fn test_verify_push_auth_rejects_unbound_public_event() {
        use nostr::prelude::*;

        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::Custom(24242), "push auth")
            .sign_with_keys(&keys)
            .unwrap();

        let json = serde_json::to_vec(&event).unwrap();
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &json);

        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Nostr {}", b64).parse().unwrap());

        // A valid public event from the owner is not push authorization.
        let npub = keys.public_key().to_bech32().unwrap();
        assert!(verify_push_auth(
            &headers,
            &npub,
            "repo",
            &format!("http://localhost/{npub}/repo/git-receive-pack"),
            "POST",
            None,
        )
        .is_err());

        // Should fail when npub doesn't match
        let other_keys = Keys::generate();
        let other_npub = other_keys.public_key().to_bech32().unwrap();
        assert!(verify_push_auth(
            &headers,
            &other_npub,
            "repo",
            "http://localhost/repo",
            "POST",
            None,
        )
        .is_err());
    }

    #[test]
    fn push_auth_requires_exact_canonical_url_and_body() {
        use nostr::prelude::*;
        let keys = Keys::generate();
        let npub = keys.public_key().to_bech32().unwrap();
        let expected = format!("https://git.example:8443/{npub}/repo/git-receive-pack?tenant=a");
        let body_hash = hex::encode(Sha256::digest(b"pack-a"));

        let headers = push_headers(&keys, &expected, "repo", &body_hash);
        assert!(
            verify_push_auth(&headers, &npub, "repo", &expected, "POST", Some(&body_hash),).is_ok()
        );

        for changed in [
            expected.replacen("https://", "http://", 1),
            expected.replace(":8443", ":9443"),
            expected.replace("tenant=a", "tenant=b"),
        ] {
            let headers = push_headers(&keys, &changed, "repo", &body_hash);
            assert!(
                verify_push_auth(&headers, &npub, "repo", &expected, "POST", Some(&body_hash),)
                    .is_err()
            );
        }

        let headers = push_headers(&keys, &expected, "repo", &body_hash);
        let swapped_hash = hex::encode(Sha256::digest(b"pack-b"));
        assert!(verify_push_auth(
            &headers,
            &npub,
            "repo",
            &expected,
            "POST",
            Some(&swapped_hash),
        )
        .is_err());
    }
}
