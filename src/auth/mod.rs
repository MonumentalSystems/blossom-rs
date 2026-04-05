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

    // Check expiration.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if let Some(exp_tag) = event
        .tags
        .iter()
        .find(|t| t.len() >= 2 && t[0] == "expiration")
    {
        if let Ok(exp) = exp_tag[1].parse::<u64>() {
            if now > exp {
                return Err(AuthError::Expired);
            }
        }
    }

    // Check action tag.
    if let Some(expected) = expected_action {
        let has_action = event
            .tags
            .iter()
            .any(|t| t.len() >= 2 && t[0] == "t" && t[1] == expected);
        if !has_action {
            return Err(AuthError::WrongAction);
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

/// Errors from Blossom auth verification.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("wrong event kind: expected 24242, got {0}")]
    WrongKind(u32),
    #[error("auth event has expired")]
    Expired,
    #[error("action tag does not match expected action")]
    WrongAction,
    #[error("event ID does not match computed hash")]
    InvalidEventId,
    #[error("BIP-340 signature verification failed")]
    InvalidSignature,
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
