//! BIP-340 Schnorr authentication for Blossom.
//!
//! Implements kind:24242 Nostr event construction and verification for
//! Blossom blob authorization.

pub mod nip98;
mod signer;

pub use nip98::{build_nip98_auth, verify_nip98_auth};
pub use signer::{BlossomSigner, Signer};

use crate::protocol::{base64url_encode, compute_event_id, NostrEvent};
use tracing::instrument;

/// Build and sign a kind:24242 Blossom auth event.
///
/// The event contains tags for the action type, optional blob SHA256,
/// optional server URL, and a 60-second expiration for replay protection.
#[instrument(name = "blossom.auth.build", skip(signer, content), fields(auth.action = action, auth.pubkey))]
pub fn build_blossom_auth(
    signer: &dyn BlossomSigner,
    action: &str,
    blob_sha256: Option<&str>,
    server_url: Option<&str>,
    content: &str,
) -> NostrEvent {
    build_blossom_auth_with_extra_tags(signer, action, blob_sha256, server_url, content, &[])
}

/// Build a Blossom authorization event bound to one HTTP request.
pub fn build_blossom_auth_for_request(
    signer: &dyn BlossomSigner,
    action: &str,
    blob_sha256: Option<&str>,
    server_url: &str,
    request_url: &str,
    method: &str,
    content: &str,
) -> NostrEvent {
    build_blossom_auth_for_request_with_extra_tags(
        signer,
        action,
        blob_sha256,
        server_url,
        request_url,
        method,
        content,
        &[],
    )
}

/// Build a request-bound Blossom event with protocol-specific extra tags.
#[allow(clippy::too_many_arguments)]
pub fn build_blossom_auth_for_request_with_extra_tags(
    signer: &dyn BlossomSigner,
    action: &str,
    blob_sha256: Option<&str>,
    server_url: &str,
    request_url: &str,
    method: &str,
    content: &str,
    extra_tags: &[Vec<String>],
) -> NostrEvent {
    let mut extra = vec![
        vec!["u".to_string(), request_url.to_string()],
        vec!["method".to_string(), method.to_ascii_uppercase()],
    ];
    extra.extend_from_slice(extra_tags);
    build_blossom_auth_with_extra_tags(
        signer,
        action,
        blob_sha256,
        Some(server_url.trim_end_matches('/')),
        content,
        &extra,
    )
}

/// Build and sign a kind:24242 Blossom auth event with additional tags.
///
/// Additional tags are appended before the expiration tag.
/// Used by BUD-20 to include LFS context tags (`["t","lfs"]`, `["path",...]`,
/// `["repo",...]`, `["base",...]`, `["manifest"]`).
pub fn build_blossom_auth_with_extra_tags(
    signer: &dyn BlossomSigner,
    action: &str,
    blob_sha256: Option<&str>,
    server_url: Option<&str>,
    content: &str,
    extra_tags: &[Vec<String>],
) -> NostrEvent {
    let pubkey = signer.public_key_hex();
    tracing::Span::current().record("auth.pubkey", pubkey.as_str());
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let kind = 24242;

    let mut tags = vec![vec!["t".to_string(), action.to_string()]];
    if let Some(hash) = blob_sha256 {
        tags.push(vec!["x".to_string(), hash.to_string()]);
    }
    if let Some(url) = server_url {
        tags.push(vec!["server".to_string(), url.to_string()]);
    }
    for extra in extra_tags {
        tags.push(extra.clone());
    }
    tags.push(vec!["nonce".to_string(), uuid::Uuid::new_v4().to_string()]);
    let expiration = created_at + 60;
    tags.push(vec!["expiration".to_string(), expiration.to_string()]);

    let id_bytes = compute_event_id(&pubkey, created_at, kind, &tags, content);
    let id = hex::encode(id_bytes);
    let sig = signer.sign_schnorr(&id_bytes);

    NostrEvent {
        id,
        pubkey,
        created_at,
        kind,
        tags,
        content: content.to_string(),
        sig,
    }
}

/// Build the `Authorization` header value: `Nostr <base64url(json(event))>`.
pub fn auth_header_value(event: &NostrEvent) -> String {
    let json = serde_json::to_string(event).expect("NostrEvent serializes");
    let encoded = base64url_encode(json.as_bytes());
    format!("Nostr {}", encoded)
}

/// Verify a kind:24242 Blossom auth event.
///
/// Checks:
/// - Event kind is 24242
/// - Event signature is valid BIP-340 Schnorr
/// - Event has not expired
/// - Action tag matches expected action (if provided)
#[instrument(name = "blossom.auth.verify", skip(event), fields(auth.pubkey = %event.pubkey, auth.kind = event.kind))]
pub fn verify_blossom_auth(
    event: &NostrEvent,
    expected_action: Option<&str>,
) -> Result<(), AuthError> {
    if event.kind != 24242 {
        return Err(AuthError::WrongKind(event.kind));
    }

    // Blossom authorization events are bearer credentials. Require a tight,
    // unambiguous validity window instead of treating expiration as optional.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if event.created_at > now.saturating_add(30) {
        return Err(AuthError::FutureDated);
    }
    if now.saturating_sub(event.created_at) > 60 {
        return Err(AuthError::Expired);
    }

    let expiration_tags: Vec<_> = event
        .tags
        .iter()
        .filter(|t| t.first().is_some_and(|v| v == "expiration"))
        .collect();
    if expiration_tags.len() != 1 {
        return Err(if expiration_tags.is_empty() {
            AuthError::MissingTag("expiration")
        } else {
            AuthError::DuplicateTag("expiration")
        });
    }
    let exp_tag = expiration_tags[0];
    if exp_tag.len() != 2 {
        return Err(AuthError::MalformedTag("expiration"));
    }
    let exp = exp_tag[1]
        .parse::<u64>()
        .map_err(|_| AuthError::MalformedTag("expiration"))?;
    if now > exp || exp > event.created_at.saturating_add(120) {
        return Err(AuthError::Expired);
    }

    // Check action tag.
    if let Some(expected) = expected_action {
        let matching_actions = event
            .tags
            .iter()
            .filter(|t| t.len() == 2 && t[0] == "t" && t[1] == expected)
            .count();
        if matching_actions != 1 {
            return Err(if matching_actions == 0 {
                if event
                    .tags
                    .iter()
                    .any(|t| t.first().is_some_and(|v| v == "t"))
                {
                    AuthError::WrongAction
                } else {
                    AuthError::MissingTag("t")
                }
            } else {
                AuthError::DuplicateTag("t")
            });
        }
    }

    // Verify event ID.
    let computed_id = compute_event_id(
        &event.pubkey,
        event.created_at,
        event.kind,
        &event.tags,
        &event.content,
    );
    if hex::encode(computed_id) != event.id {
        return Err(AuthError::InvalidEventId);
    }

    // Verify BIP-340 Schnorr signature.
    if !Signer::verify(&event.pubkey, &computed_id, &event.sig) {
        return Err(AuthError::InvalidSignature);
    }

    Ok(())
}

/// Verify a Blossom event and bind it to the expected server and resource.
pub fn verify_blossom_auth_bound(
    event: &NostrEvent,
    expected_action: &str,
    expected_server: &str,
    expected_url: &str,
    expected_method: &str,
    expected_hash: Option<&str>,
) -> Result<(), AuthError> {
    verify_blossom_auth(event, Some(expected_action))?;
    verify_unique_tag(event, "server", expected_server, AuthError::WrongServer)?;
    verify_unique_tag(event, "u", expected_url, AuthError::WrongResource)?;
    verify_unique_tag(
        event,
        "method",
        &expected_method.to_ascii_uppercase(),
        AuthError::WrongAction,
    )?;
    if let Some(hash) = expected_hash {
        verify_unique_tag(event, "x", hash, AuthError::WrongResource)?;
    }
    Ok(())
}

fn verify_unique_tag(
    event: &NostrEvent,
    name: &'static str,
    expected: &str,
    mismatch: AuthError,
) -> Result<(), AuthError> {
    let tags: Vec<_> = event
        .tags
        .iter()
        .filter(|t| t.first().is_some_and(|v| v == name))
        .collect();
    if tags.is_empty() {
        return Err(AuthError::MissingTag(name));
    }
    if tags.len() != 1 {
        return Err(AuthError::DuplicateTag(name));
    }
    if tags[0].len() != 2 {
        return Err(AuthError::MalformedTag(name));
    }
    if tags[0][1] != expected {
        return Err(mismatch);
    }
    Ok(())
}

/// Errors from Blossom auth verification.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("wrong event kind: expected 24242, got {0}")]
    WrongKind(u32),
    #[error("auth event has expired")]
    Expired,
    #[error("auth event is dated too far in the future")]
    FutureDated,
    #[error("missing required auth tag: {0}")]
    MissingTag(&'static str),
    #[error("duplicate auth tag: {0}")]
    DuplicateTag(&'static str),
    #[error("malformed auth tag: {0}")]
    MalformedTag(&'static str),
    #[error("action tag does not match expected action")]
    WrongAction,
    #[error("auth event is for a different server")]
    WrongServer,
    #[error("auth event is for a different resource")]
    WrongResource,
    #[error("event ID does not match computed hash")]
    InvalidEventId,
    #[error("BIP-340 signature verification failed")]
    InvalidSignature,
    #[error("authorization event has already been used")]
    Replay,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_and_verify_auth() {
        let signer = Signer::generate();
        let event = build_blossom_auth(&signer, "upload", Some("abcd1234"), None, "");

        assert_eq!(event.kind, 24242);
        assert!(event
            .tags
            .iter()
            .any(|t| t.len() >= 2 && t[0] == "t" && t[1] == "upload"));
        assert!(event
            .tags
            .iter()
            .any(|t| t.len() >= 2 && t[0] == "x" && t[1] == "abcd1234"));
        assert!(event
            .tags
            .iter()
            .any(|t| t.len() >= 2 && t[0] == "expiration"));

        // Should verify successfully.
        verify_blossom_auth(&event, Some("upload")).unwrap();
    }

    #[test]
    fn test_auth_header_format() {
        let signer = Signer::generate();
        let event = build_blossom_auth(&signer, "upload", None, None, "");
        let header = auth_header_value(&event);

        assert!(header.starts_with("Nostr "));
        let b64_part = &header["Nostr ".len()..];
        assert!(!b64_part.contains('+'));
        assert!(!b64_part.contains('/'));
        assert!(!b64_part.contains('='));
    }

    #[test]
    fn test_wrong_action_rejected() {
        let signer = Signer::generate();
        let event = build_blossom_auth(&signer, "upload", None, None, "");
        let result = verify_blossom_auth(&event, Some("delete"));
        assert!(matches!(result, Err(AuthError::WrongAction)));
    }
}
