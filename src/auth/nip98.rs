//! NIP-98 HTTP auth verification.
//!
//! NIP-98 uses kind:27235 Nostr events for HTTP request authentication.
//! The event includes the request URL and method in tags.

use crate::protocol::{compute_event_id, NostrEvent};

use super::signer::Signer;
use super::AuthError;

/// Verify a NIP-98 (kind:27235) HTTP auth event.
///
/// Checks:
/// - Event kind is 27235
/// - Event has not expired
/// - URL tag matches the request URL (if provided)
/// - Method tag matches the HTTP method (if provided)
/// - Event ID is correctly computed
/// - BIP-340 Schnorr signature is valid
pub fn verify_nip98_auth(
    event: &NostrEvent,
    expected_url: Option<&str>,
    expected_method: Option<&str>,
) -> Result<(), AuthError> {
    if event.kind != 27235 {
        return Err(AuthError::WrongKind(event.kind));
    }

    // Check expiration.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // NIP-98 events should be recent (within 60 seconds).
    if now.saturating_sub(event.created_at) > 60 {
        return Err(AuthError::Expired);
    }

    // Check URL tag.
    if let Some(url) = expected_url {
        let has_url = event
            .tags
            .iter()
            .any(|t| t.len() >= 2 && t[0] == "u" && t[1] == url);
        if !has_url {
            return Err(AuthError::WrongAction);
        }
    }

    // Check method tag.
    if let Some(method) = expected_method {
        let has_method = event
            .tags
            .iter()
            .any(|t| t.len() >= 2 && t[0] == "method" && t[1].eq_ignore_ascii_case(method));
        if !has_method {
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

/// Build a NIP-98 auth event for an HTTP request.
pub fn build_nip98_auth(signer: &dyn super::BlossomSigner, url: &str, method: &str) -> NostrEvent {
    let pubkey = signer.public_key_hex();
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let kind = 27235;

    let tags = vec![
        vec!["u".to_string(), url.to_string()],
        vec!["method".to_string(), method.to_string()],
    ];

    let id_bytes = compute_event_id(&pubkey, created_at, kind, &tags, "");
    let id = hex::encode(id_bytes);
    let sig = signer.sign_schnorr(&id_bytes);

    NostrEvent {
        id,
        pubkey,
        created_at,
        kind,
        tags,
        content: String::new(),
        sig,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Signer;

    #[test]
    fn test_build_and_verify_nip98() {
        let signer = Signer::generate();
        let event = build_nip98_auth(&signer, "http://localhost:3000/upload", "PUT");

        assert_eq!(event.kind, 27235);
        verify_nip98_auth(&event, Some("http://localhost:3000/upload"), Some("PUT")).unwrap();
    }

    #[test]
    fn test_wrong_url_rejected() {
        let signer = Signer::generate();
        let event = build_nip98_auth(&signer, "http://localhost:3000/upload", "PUT");
        let result = verify_nip98_auth(&event, Some("http://other.com/upload"), Some("PUT"));
        assert!(matches!(result, Err(AuthError::WrongAction)));
    }

    #[test]
    fn test_wrong_method_rejected() {
        let signer = Signer::generate();
        let event = build_nip98_auth(&signer, "http://localhost:3000/upload", "PUT");
        let result = verify_nip98_auth(&event, Some("http://localhost:3000/upload"), Some("GET"));
        assert!(matches!(result, Err(AuthError::WrongAction)));
    }

    #[test]
    fn test_wrong_kind_rejected() {
        let signer = Signer::generate();
        // Build a kind:24242 event (Blossom, not NIP-98).
        let event = crate::auth::build_blossom_auth(&signer, "upload", None, None, "");
        let result = verify_nip98_auth(&event, None, None);
        assert!(matches!(result, Err(AuthError::WrongKind(24242))));
    }
}
