//! Blossom wire protocol for QUIC streams.
//!
//! Each bidirectional stream carries one request + response using a
//! JSON-line header followed by optional binary payload. This is the
//! "hybrid" framing: human-readable headers, zero-copy blob transfer.
//!
//! ## Request format
//! ```text
//! {"op":"get","sha256":"abc...","auth":"Nostr base64..."}\n
//! [optional binary payload for upload]
//! ```
//!
//! ## Response format
//! ```text
//! {"status":"ok","size":12345,"type":"image/jpeg"}\n
//! [binary blob bytes for GET, or BlobDescriptor JSON for UPLOAD]
//! ```

use serde::{Deserialize, Serialize};

/// Wire protocol operation codes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Op {
    Get,
    Head,
    Upload,
    Delete,
    List,
    LockCreate,
    LockDelete,
    LockList,
    LockVerify,
}

/// Request frame sent over a QUIC stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub op: Op,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sha256: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pubkey: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub auth: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub content_type: String,
    #[serde(default)]
    pub body_len: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub repo_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub lock_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub lock_path: String,
    #[serde(default)]
    pub force: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cursor: String,
    #[serde(default)]
    pub limit: u32,
}

/// Response status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    NotFound,
    Unauthorized,
    Forbidden,
    Conflict,
    Error,
}

/// Response frame sent over a QUIC stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    /// Status code.
    pub status: Status,
    /// Body length (bytes following the JSON line).
    #[serde(default)]
    pub body_len: u64,
    /// Content type (for GET responses).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub content_type: String,
    /// Error message (for error responses).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
    /// Descriptor JSON (for UPLOAD and LIST responses, inline).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub descriptor: Option<serde_json::Value>,
}

/// Encode a request as a JSON line (with trailing newline).
pub fn encode_request(req: &Request) -> Vec<u8> {
    let mut buf = serde_json::to_vec(req).expect("Request serializes");
    buf.push(b'\n');
    buf
}

/// Encode a response as a JSON line (with trailing newline).
pub fn encode_response(resp: &Response) -> Vec<u8> {
    let mut buf = serde_json::to_vec(resp).expect("Response serializes");
    buf.push(b'\n');
    buf
}

/// Read a JSON line from a byte buffer, returning the parsed value and
/// the number of bytes consumed (including the newline).
pub fn decode_line<T: serde::de::DeserializeOwned>(buf: &[u8]) -> Result<(T, usize), String> {
    let newline_pos = buf
        .iter()
        .position(|&b| b == b'\n')
        .ok_or_else(|| "no newline found in buffer".to_string())?;
    let json_bytes = &buf[..newline_pos];
    let value: T =
        serde_json::from_slice(json_bytes).map_err(|e| format!("parse JSON line: {e}"))?;
    Ok((value, newline_pos + 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_roundtrip() {
        let req = Request {
            op: Op::Get,
            sha256: "a".repeat(64),
            pubkey: String::new(),
            auth: "Nostr abc123".into(),
            content_type: String::new(),
            body_len: 0,
            repo_id: String::new(),
            lock_id: String::new(),
            lock_path: String::new(),
            force: false,
            cursor: String::new(),
            limit: 0,
        };
        let encoded = encode_request(&req);
        assert!(encoded.ends_with(b"\n"));

        let (decoded, consumed): (Request, usize) = decode_line(&encoded).unwrap();
        assert_eq!(decoded.op, Op::Get);
        assert_eq!(decoded.sha256, "a".repeat(64));
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn test_response_roundtrip() {
        let resp = Response {
            status: Status::Ok,
            body_len: 1024,
            content_type: "image/png".into(),
            error: String::new(),
            descriptor: None,
        };
        let encoded = encode_response(&resp);
        let (decoded, _): (Response, usize) = decode_line(&encoded).unwrap();
        assert_eq!(decoded.status, Status::Ok);
        assert_eq!(decoded.body_len, 1024);
    }

    #[test]
    fn test_upload_request() {
        let req = Request {
            op: Op::Upload,
            sha256: String::new(),
            pubkey: String::new(),
            auth: "Nostr xyz".into(),
            content_type: "application/octet-stream".into(),
            body_len: 5000,
            repo_id: String::new(),
            lock_id: String::new(),
            lock_path: String::new(),
            force: false,
            cursor: String::new(),
            limit: 0,
        };
        let encoded = encode_request(&req);
        let (decoded, _): (Request, usize) = decode_line(&encoded).unwrap();
        assert_eq!(decoded.op, Op::Upload);
        assert_eq!(decoded.body_len, 5000);
        assert_eq!(decoded.content_type, "application/octet-stream");
    }

    #[test]
    fn test_error_response() {
        let resp = Response {
            status: Status::Error,
            body_len: 0,
            content_type: String::new(),
            error: "something went wrong".into(),
            descriptor: None,
        };
        let encoded = encode_response(&resp);
        let (decoded, _): (Response, usize) = decode_line(&encoded).unwrap();
        assert_eq!(decoded.status, Status::Error);
        assert_eq!(decoded.error, "something went wrong");
    }

    #[test]
    fn test_list_request() {
        let req = Request {
            op: Op::List,
            sha256: String::new(),
            pubkey: "b".repeat(64),
            auth: "Nostr list_auth".into(),
            content_type: String::new(),
            body_len: 0,
            repo_id: String::new(),
            lock_id: String::new(),
            lock_path: String::new(),
            force: false,
            cursor: String::new(),
            limit: 0,
        };
        let encoded = encode_request(&req);
        let (decoded, _): (Request, usize) = decode_line(&encoded).unwrap();
        assert_eq!(decoded.op, Op::List);
        assert_eq!(decoded.pubkey, "b".repeat(64));
    }

    #[test]
    fn test_descriptor_in_response() {
        let desc = serde_json::json!({
            "sha256": "abc123",
            "size": 42,
        });
        let resp = Response {
            status: Status::Ok,
            body_len: 0,
            content_type: String::new(),
            error: String::new(),
            descriptor: Some(desc),
        };
        let encoded = encode_response(&resp);
        let (decoded, _): (Response, usize) = decode_line(&encoded).unwrap();
        assert_eq!(decoded.descriptor.unwrap()["sha256"], "abc123");
    }
}
