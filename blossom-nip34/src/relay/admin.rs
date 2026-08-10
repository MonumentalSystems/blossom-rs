//! Relay admin HTTP endpoints for runtime policy management.
//!
//! All endpoints modify the in-memory policy and persist to the database.
//! Mounted at `/relay/admin/*`.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::Nip34State;

/// Build the relay admin router.
pub fn relay_admin_router(state: Arc<Nip34State>) -> axum::Router<Arc<Nip34State>> {
    axum::Router::new()
        .route("/relay/admin/policy", axum::routing::get(get_policy))
        .route(
            "/relay/admin/whitelist",
            axum::routing::get(get_whitelist)
                .put(add_whitelist)
                .delete(remove_whitelist),
        )
        .route(
            "/relay/admin/blacklist",
            axum::routing::get(get_blacklist)
                .put(add_blacklist)
                .delete(remove_blacklist),
        )
        .route(
            "/relay/admin/admins",
            axum::routing::get(get_admins).put(add_admin),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            state,
            require_relay_admin,
        ))
}

async fn require_relay_admin(
    State(state): State<Arc<Nip34State>>,
    request: Request,
    next: Next,
) -> Response {
    let (parts, body) = request.into_parts();
    let mutation = matches!(parts.method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE");
    let path_and_query = parts
        .uri
        .path_and_query()
        .map_or(parts.uri.path(), |value| value.as_str());
    let expected_url = format!(
        "{}{}",
        state.config.server_url.trim_end_matches('/'),
        path_and_query
    );
    let Some(event) = parts
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Nostr "))
        .and_then(decode_auth_event)
    else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "fresh, request-bound relay admin authorization required"})),
        )
            .into_response();
    };
    if !verify_admin_event_claims(&event, &state, &expected_url, parts.method.as_str(), None) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "fresh, request-bound relay admin authorization required"})),
        )
            .into_response();
    }

    if !mutation {
        if !mark_auth_event_once(&event.id.to_hex(), current_unix_time()) {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        return next.run(Request::from_parts(parts, body)).await;
    }

    let body = match to_bytes(body, 64 * 1024).await {
        Ok(body) => body,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    let payload_hash = hex::encode(Sha256::digest(&body));
    if !verify_admin_event(
        &event,
        &state,
        &expected_url,
        parts.method.as_str(),
        Some(&payload_hash),
    ) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    next.run(Request::from_parts(parts, Body::from(body))).await
}

fn current_unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn decode_auth_event(encoded: &str) -> Option<nostr::Event> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(encoded))
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn verify_admin_event(
    event: &nostr::Event,
    state: &Nip34State,
    expected_url: &str,
    method: &str,
    payload_hash: Option<&str>,
) -> bool {
    verify_admin_event_claims(event, state, expected_url, method, payload_hash)
        && mark_auth_event_once(&event.id.to_hex(), current_unix_time())
}

fn verify_admin_event_claims(
    event: &nostr::Event,
    state: &Nip34State,
    expected_url: &str,
    method: &str,
    payload_hash: Option<&str>,
) -> bool {
    if event.verify().is_err()
        || !state
            .policy
            .admins
            .read()
            .unwrap()
            .contains(&event.pubkey.to_hex())
    {
        return false;
    }
    let value = match serde_json::to_value(event) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let created_at = value
        .get("created_at")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let kind = value.get("kind").and_then(|v| v.as_u64()).unwrap_or(0);
    let now = current_unix_time();
    if created_at > now.saturating_add(30) || now.saturating_sub(created_at) > 60 {
        return false;
    }
    let tags = value
        .get("tags")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
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
    let Some(url) = unique("u") else { return false };
    let Some(tag_method) = unique("method") else {
        return false;
    };
    if url::Url::parse(&url).is_err()
        || url != expected_url
        || !tag_method.eq_ignore_ascii_case(method)
    {
        return false;
    }
    if let Some(hash) = payload_hash {
        let binding = if kind == 27235 { "payload" } else { "x" };
        if unique(binding).as_deref() != Some(hash) {
            return false;
        }
    }
    let valid = (kind == 27235
        || kind == 24242
            && unique("t").as_deref() == Some("admin")
            && unique("expiration")
                .and_then(|v| v.parse::<u64>().ok())
                .is_some_and(|expiration| expiration >= now && expiration <= created_at + 120))
        && unique("nonce").is_some_and(|nonce| !nonce.is_empty());
    valid
}

const ADMIN_REPLAY_CAPACITY: usize = 10_000;

struct AdminReplayCache {
    entries: std::collections::HashMap<String, u64>,
    insertion_order: std::collections::VecDeque<String>,
    capacity: usize,
}

impl AdminReplayCache {
    fn new(capacity: usize) -> Self {
        Self {
            entries: std::collections::HashMap::new(),
            insertion_order: std::collections::VecDeque::new(),
            capacity,
        }
    }

    fn check_and_insert(&mut self, event_id: &str, now: u64) -> bool {
        while let Some(oldest) = self.insertion_order.front().cloned() {
            match self.entries.get(&oldest) {
                None => {
                    self.insertion_order.pop_front();
                }
                Some(expires_at) if *expires_at <= now => {
                    self.insertion_order.pop_front();
                    self.entries.remove(&oldest);
                }
                Some(_) => break,
            }
        }
        if self.entries.contains_key(event_id) {
            return false;
        }
        while self.entries.len() >= self.capacity {
            let Some(oldest) = self.insertion_order.pop_front() else {
                break;
            };
            self.entries.remove(&oldest);
        }
        self.entries
            .insert(event_id.to_string(), now.saturating_add(120));
        self.insertion_order.push_back(event_id.to_string());
        true
    }
}

impl Default for AdminReplayCache {
    fn default() -> Self {
        Self::new(ADMIN_REPLAY_CAPACITY)
    }
}

fn mark_auth_event_once(event_id: &str, now: u64) -> bool {
    static SEEN: std::sync::OnceLock<std::sync::Mutex<AdminReplayCache>> =
        std::sync::OnceLock::new();
    let mut seen = SEEN
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    seen.check_and_insert(event_id, now)
}

#[derive(Deserialize)]
struct PubkeyRequest {
    pubkey: String,
}

/// GET /relay/admin/policy — current policy summary
async fn get_policy(State(state): State<Arc<Nip34State>>) -> impl IntoResponse {
    let policy = &state.policy;
    let admins: Vec<String> = policy.admins.read().unwrap().iter().cloned().collect();
    let whitelist: Vec<String> = policy.whitelist.read().unwrap().iter().cloned().collect();
    let blacklist: Vec<String> = policy.blacklist.read().unwrap().iter().cloned().collect();
    let allowed_kinds: Vec<u16> = policy
        .allowed_kinds
        .read()
        .unwrap()
        .iter()
        .map(|k| k.as_u16())
        .collect();
    let disallowed_kinds: Vec<u16> = policy
        .disallowed_kinds
        .read()
        .unwrap()
        .iter()
        .map(|k| k.as_u16())
        .collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "admins": admins,
            "whitelist": whitelist,
            "blacklist": blacklist,
            "max_event_size": policy.max_event_size,
            "allowed_kinds": allowed_kinds,
            "disallowed_kinds": disallowed_kinds,
        })),
    )
}

/// GET /relay/admin/whitelist
async fn get_whitelist(State(state): State<Arc<Nip34State>>) -> impl IntoResponse {
    let list: Vec<String> = state
        .policy
        .whitelist
        .read()
        .unwrap()
        .iter()
        .cloned()
        .collect();
    Json(serde_json::json!({ "whitelist": list }))
}

/// PUT /relay/admin/whitelist — add pubkey (persisted)
async fn add_whitelist(
    State(state): State<Arc<Nip34State>>,
    Json(req): Json<PubkeyRequest>,
) -> impl IntoResponse {
    state.policy.add_whitelist(&req.pubkey);
    let _ = state.policy_db.add("whitelist", &req.pubkey).await;
    tracing::info!(pubkey = %req.pubkey, "added to relay whitelist");
    (
        StatusCode::OK,
        Json(serde_json::json!({ "added": req.pubkey })),
    )
}

/// DELETE /relay/admin/whitelist — remove pubkey (persisted)
async fn remove_whitelist(
    State(state): State<Arc<Nip34State>>,
    Json(req): Json<PubkeyRequest>,
) -> impl IntoResponse {
    state.policy.remove_whitelist(&req.pubkey);
    let _ = state.policy_db.remove("whitelist", &req.pubkey).await;
    tracing::info!(pubkey = %req.pubkey, "removed from relay whitelist");
    (
        StatusCode::OK,
        Json(serde_json::json!({ "removed": req.pubkey })),
    )
}

/// GET /relay/admin/blacklist
async fn get_blacklist(State(state): State<Arc<Nip34State>>) -> impl IntoResponse {
    let list: Vec<String> = state
        .policy
        .blacklist
        .read()
        .unwrap()
        .iter()
        .cloned()
        .collect();
    Json(serde_json::json!({ "blacklist": list }))
}

/// PUT /relay/admin/blacklist — add pubkey (persisted)
async fn add_blacklist(
    State(state): State<Arc<Nip34State>>,
    Json(req): Json<PubkeyRequest>,
) -> impl IntoResponse {
    state.policy.add_blacklist(&req.pubkey);
    let _ = state.policy_db.add("blacklist", &req.pubkey).await;
    tracing::info!(pubkey = %req.pubkey, "added to relay blacklist");
    (
        StatusCode::OK,
        Json(serde_json::json!({ "added": req.pubkey })),
    )
}

/// DELETE /relay/admin/blacklist — remove pubkey (persisted)
async fn remove_blacklist(
    State(state): State<Arc<Nip34State>>,
    Json(req): Json<PubkeyRequest>,
) -> impl IntoResponse {
    state.policy.remove_blacklist(&req.pubkey);
    let _ = state.policy_db.remove("blacklist", &req.pubkey).await;
    tracing::info!(pubkey = %req.pubkey, "removed from relay blacklist");
    (
        StatusCode::OK,
        Json(serde_json::json!({ "removed": req.pubkey })),
    )
}

/// GET /relay/admin/admins
async fn get_admins(State(state): State<Arc<Nip34State>>) -> impl IntoResponse {
    let list: Vec<String> = state
        .policy
        .admins
        .read()
        .unwrap()
        .iter()
        .cloned()
        .collect();
    Json(serde_json::json!({ "admins": list }))
}

/// PUT /relay/admin/admins — add admin pubkey (persisted)
async fn add_admin(
    State(state): State<Arc<Nip34State>>,
    Json(req): Json<PubkeyRequest>,
) -> impl IntoResponse {
    state.policy.add_admin(&req.pubkey);
    let _ = state.policy_db.add("admin", &req.pubkey).await;
    tracing::info!(pubkey = %req.pubkey, "added relay admin");
    (
        StatusCode::OK,
        Json(serde_json::json!({ "added": req.pubkey })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::prelude::*;

    fn admin_event(keys: &Keys, url: &str, method: &str, payload: &str) -> Event {
        EventBuilder::new(Kind::Custom(27235), "")
            .tags([
                Tag::custom(TagKind::custom("u"), [url]),
                Tag::custom(TagKind::custom("method"), [method]),
                Tag::custom(TagKind::custom("payload"), [payload]),
                Tag::custom(TagKind::custom("nonce"), [uuid::Uuid::new_v4().to_string()]),
            ])
            .sign_with_keys(keys)
            .unwrap()
    }

    fn blossom_admin_event(keys: &Keys, url: &str, method: &str, payload: &str) -> Event {
        let expiration = Timestamp::now().as_secs() + 60;
        EventBuilder::new(Kind::Custom(24242), "")
            .tags([
                Tag::custom(TagKind::custom("t"), ["admin"]),
                Tag::custom(TagKind::custom("u"), [url]),
                Tag::custom(TagKind::custom("method"), [method]),
                Tag::custom(TagKind::custom("x"), [payload]),
                Tag::custom(TagKind::custom("nonce"), [uuid::Uuid::new_v4().to_string()]),
                Tag::custom(TagKind::custom("expiration"), [expiration.to_string()]),
            ])
            .sign_with_keys(keys)
            .unwrap()
    }

    #[tokio::test]
    async fn relay_admin_auth_binds_exact_url_and_json_body() {
        let keys = Keys::generate();
        let temp = tempfile::tempdir().unwrap();
        let config = crate::Nip34Config {
            server_url: "https://relay.example:8443".into(),
            lmdb_path: temp.path().join("lmdb"),
            repos_path: temp.path().join("repos"),
            admin_pubkeys: vec![keys.public_key().to_hex()],
            ..Default::default()
        };
        let state = Nip34State::new(config).await.unwrap();
        let expected = "https://relay.example:8443/relay/admin/whitelist?tenant=a";
        let body_a = hex::encode(Sha256::digest(br#"{"pubkey":"a"}"#));
        let body_b = hex::encode(Sha256::digest(br#"{"pubkey":"b"}"#));

        let valid = admin_event(&keys, expected, "PUT", &body_a);
        assert!(verify_admin_event(
            &valid,
            &state,
            expected,
            "PUT",
            Some(&body_a)
        ));

        for changed in [
            expected.replacen("https://", "http://", 1),
            expected.replace(":8443", ":9443"),
            expected.replace("tenant=a", "tenant=b"),
        ] {
            let event = admin_event(&keys, &changed, "PUT", &body_a);
            assert!(!verify_admin_event(
                &event,
                &state,
                expected,
                "PUT",
                Some(&body_a)
            ));
        }

        let swapped = admin_event(&keys, expected, "PUT", &body_a);
        assert!(!verify_admin_event(
            &swapped,
            &state,
            expected,
            "PUT",
            Some(&body_b)
        ));

        let blossom = blossom_admin_event(&keys, expected, "PUT", &body_a);
        assert!(!verify_admin_event(
            &blossom,
            &state,
            expected,
            "PUT",
            Some(&body_b)
        ));
    }

    #[test]
    fn relay_admin_replay_cache_evicts_instead_of_failing_closed() {
        let mut cache = AdminReplayCache::new(2);
        assert!(cache.check_and_insert("a", 1));
        assert!(cache.check_and_insert("b", 1));
        assert!(!cache.check_and_insert("b", 1));
        assert!(cache.check_and_insert("c", 1));
    }
}
