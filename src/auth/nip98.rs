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
    verify_nip98_auth_with_payload(event, expected_url, expected_method, None)
}

/// Verify a NIP-98 event, including the `payload` SHA-256 tag when a request
/// body affects the authorized operation.
pub fn verify_nip98_auth_with_payload(
    event: &NostrEvent,
    expected_url: Option<&str>,
    expected_method: Option<&str>,
    expected_payload: Option<&str>,
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
    if event.created_at > now.saturating_add(30) {
        return Err(AuthError::FutureDated);
    }
    if now.saturating_sub(event.created_at) > 60 {
        return Err(AuthError::Expired);
    }

    // Check URL tag.
    if let Some(url) = expected_url {
        let tags: Vec<_> = event
            .tags
            .iter()
            .filter(|t| t.first().is_some_and(|v| v == "u"))
            .collect();
        if tags.len() != 1 || tags[0].len() != 2 || tags[0][1] != url {
            return Err(AuthError::WrongAction);
        }
    }

    // Check method tag.
    if let Some(method) = expected_method {
        let tags: Vec<_> = event
            .tags
            .iter()
            .filter(|t| t.first().is_some_and(|v| v == "method"))
            .collect();
        if tags.len() != 1 || tags[0].len() != 2 || !tags[0][1].eq_ignore_ascii_case(method) {
            return Err(AuthError::WrongAction);
        }
    }

    if let Some(payload) = expected_payload {
        let tags: Vec<_> = event
            .tags
            .iter()
            .filter(|t| t.first().is_some_and(|v| v == "payload"))
            .collect();
        if tags.len() != 1 || tags[0].len() != 2 || tags[0][1] != payload {
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
    build_nip98_auth_with_payload(signer, url, method, None)
}

/// Build a NIP-98 event with an optional SHA-256 hash of the exact HTTP body.
pub fn build_nip98_auth_with_payload(
    signer: &dyn super::BlossomSigner,
    url: &str,
    method: &str,
    payload_hash: Option<&str>,
) -> NostrEvent {
    let pubkey = signer.public_key_hex();
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let kind = 27235;

    let mut tags = vec![
        vec!["u".to_string(), url.to_string()],
        vec!["method".to_string(), method.to_string()],
        vec!["nonce".to_string(), uuid::Uuid::new_v4().to_string()],
    ];
    if let Some(hash) = payload_hash {
        tags.push(vec!["payload".to_string(), hash.to_string()]);
    }

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

    #[test]
    fn payload_hash_prevents_body_swap() {
        let signer = Signer::generate();
        let first = crate::protocol::sha256_hex(br#"{"role":"admin"}"#);
        let swapped = crate::protocol::sha256_hex(br#"{"role":"user"}"#);
        let event = build_nip98_auth_with_payload(
            &signer,
            "https://example.com:8443/admin?tenant=a",
            "PUT",
            Some(&first),
        );

        verify_nip98_auth_with_payload(
            &event,
            Some("https://example.com:8443/admin?tenant=a"),
            Some("PUT"),
            Some(&first),
        )
        .unwrap();
        assert!(matches!(
            verify_nip98_auth_with_payload(
                &event,
                Some("https://example.com:8443/admin?tenant=a"),
                Some("PUT"),
                Some(&swapped),
            ),
            Err(AuthError::WrongAction)
        ));
    }
}
