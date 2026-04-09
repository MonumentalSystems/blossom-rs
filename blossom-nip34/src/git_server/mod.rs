//! GRASP git HTTP smart protocol server.
//!
//! Serves git repositories over HTTP for clone/push operations.
//! Repositories are organized as `{npub}/{repo_name}.git` on the filesystem.

pub mod command;
pub mod pktline;
pub mod validation;

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use nostr::nips::nip19::FromBech32;

use crate::Nip34State;

/// Ensure a bare repo exists on disk. If it doesn't exist but the npub has
/// a repo path, create it (lazy repo creation for GRASP).
async fn ensure_repo(
    state: &Nip34State,
    npub: &str,
    repo_name: &str,
) -> Option<std::path::PathBuf> {
    let path = state.repo_path(npub, repo_name)?;
    if path.join("HEAD").exists() {
        return Some(path);
    }
    // Auto-create bare repo
    state.create_bare_repo(npub, repo_name, "").await.ok()
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
fn verify_push_auth(headers: &HeaderMap, expected_npub: &str) -> Result<String, &'static str> {
    let auth_value = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or("push requires Authorization header")?;

    // Accept "Nostr <base64>" format
    let b64 = auth_value
        .strip_prefix("Nostr ")
        .ok_or("authorization must use 'Nostr <base64>' format")?;

    let json_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64)
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

    Ok(event.pubkey.to_hex())
}

/// GET /{npub}/{repo}/info/refs?service=git-upload-pack
async fn info_refs(
    State(state): State<Arc<Nip34State>>,
    Path((npub, repo)): Path<(String, String)>,
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
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let repo_name = repo.trim_end_matches(".git");
    let repo_path = match ensure_repo(&state, &npub, repo_name).await {
        Some(p) => p,
        None => return (StatusCode::NOT_FOUND, "repository not found").into_response(),
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
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let repo_name = repo.trim_end_matches(".git");
    let repo_path = match ensure_repo(&state, &npub, repo_name).await {
        Some(p) => p,
        None => return (StatusCode::NOT_FOUND, "repository not found").into_response(),
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
    // Optional: if Nostr auth header present, verify it as additional auth
    let has_nostr_auth = verify_push_auth(&headers, &npub).is_ok();

    if !has_nostr_auth {
        // Fall back to GRASP relay-based validation
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_push_auth_missing_header() {
        let headers = HeaderMap::new();
        assert!(verify_push_auth(&headers, "npub1test").is_err());
    }

    #[test]
    fn test_verify_push_auth_wrong_format() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer token".parse().unwrap());
        assert!(verify_push_auth(&headers, "npub1test").is_err());
    }

    #[test]
    fn test_verify_push_auth_valid() {
        use nostr::prelude::*;

        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::Custom(24242), "push auth")
            .sign_with_keys(&keys)
            .unwrap();

        let json = serde_json::to_vec(&event).unwrap();
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &json);

        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Nostr {}", b64).parse().unwrap());

        // Should succeed when npub matches the signer
        let npub = keys.public_key().to_bech32().unwrap();
        assert!(verify_push_auth(&headers, &npub).is_ok());

        // Should fail when npub doesn't match
        let other_keys = Keys::generate();
        let other_npub = other_keys.public_key().to_bech32().unwrap();
        assert!(verify_push_auth(&headers, &other_npub).is_err());
    }
}
