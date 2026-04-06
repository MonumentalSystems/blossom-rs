//! Property-based tests for blossom-rs.

use proptest::prelude::*;

use blossom_rs::protocol::{base64url_decode, base64url_encode, sha256_hex};

proptest! {
    /// base64url encode/decode is a perfect round-trip for any byte sequence.
    #[test]
    fn base64url_roundtrip(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let encoded = base64url_encode(&data);
        let decoded = base64url_decode(&encoded).unwrap();
        prop_assert_eq!(decoded, data);
    }

    /// base64url encoding never contains `+`, `/`, or `=`.
    #[test]
    fn base64url_no_special_chars(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let encoded = base64url_encode(&data);
        prop_assert!(!encoded.contains('+'));
        prop_assert!(!encoded.contains('/'));
        prop_assert!(!encoded.contains('='));
    }

    /// SHA256 always produces a 64-char hex string.
    #[test]
    fn sha256_hex_length(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let hash = sha256_hex(&data);
        prop_assert_eq!(hash.len(), 64);
        prop_assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// SHA256 is deterministic.
    #[test]
    fn sha256_deterministic(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let h1 = sha256_hex(&data);
        let h2 = sha256_hex(&data);
        prop_assert_eq!(h1, h2);
    }

    /// Different data produces different SHA256 (with overwhelming probability).
    #[test]
    fn sha256_different_data(
        data1 in proptest::collection::vec(any::<u8>(), 1..100),
        data2 in proptest::collection::vec(any::<u8>(), 1..100),
    ) {
        prop_assume!(data1 != data2);
        let h1 = sha256_hex(&data1);
        let h2 = sha256_hex(&data2);
        prop_assert_ne!(h1, h2);
    }

    /// Wire protocol request roundtrip — encode then decode.
    #[test]
    fn wire_request_roundtrip(
        sha256 in "[0-9a-f]{64}",
        auth in "[a-zA-Z0-9]{0,100}",
    ) {
        use blossom_rs::transport::wire::{encode_request, decode_line, Request, Op};
        let req = Request {
            op: Op::Get,
            sha256,
            pubkey: String::new(),
            auth,
            content_type: String::new(),
            body_len: 0,
        };
        let encoded = encode_request(&req);
        let (decoded, consumed): (Request, usize) = decode_line(&encoded).unwrap();
        prop_assert_eq!(decoded.sha256, req.sha256);
        prop_assert_eq!(decoded.auth, req.auth);
        prop_assert_eq!(consumed, encoded.len());
    }

    /// Wire protocol response roundtrip.
    #[test]
    fn wire_response_roundtrip(
        body_len in 0u64..1_000_000,
        error in "[a-zA-Z0-9 ]{0,50}",
    ) {
        use blossom_rs::transport::wire::{encode_response, decode_line, Response, Status};
        let resp = Response {
            status: Status::Ok,
            body_len,
            content_type: "application/octet-stream".into(),
            error,
            descriptor: None,
        };
        let encoded = encode_response(&resp);
        let (decoded, _): (Response, usize) = decode_line(&encoded).unwrap();
        prop_assert_eq!(decoded.body_len, resp.body_len);
        prop_assert_eq!(decoded.error, resp.error);
    }
}
