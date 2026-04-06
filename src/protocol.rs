//! Blossom protocol types.
//!
//! NIP-01 Nostr events, BlobDescriptor, and base64url encoding for
//! Blossom authorization headers.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// NIP-01 Nostr event (minimal subset for Blossom auth).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NostrEvent {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

/// Blob descriptor returned by the server after upload (BUD-01).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobDescriptor {
    pub sha256: String,
    pub size: u64,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none", default)]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub uploaded: Option<u64>,
}

/// Compute NIP-01 event ID: SHA256 of the canonical serialization.
///
/// The serialized form is: `[0,"<pubkey>",<created_at>,<kind>,<tags>,"<content>"]`
pub fn compute_event_id(
    pubkey: &str,
    created_at: u64,
    kind: u32,
    tags: &[Vec<String>],
    content: &str,
) -> [u8; 32] {
    let tags_json = serde_json::to_string(tags).unwrap_or_else(|_| "[]".to_string());
    let serialized = format!(
        "[0,\"{}\",{},{},{},\"{}\"]",
        pubkey,
        created_at,
        kind,
        tags_json,
        content.replace('\\', "\\\\").replace('"', "\\\"")
    );
    let mut hasher = Sha256::new();
    hasher.update(serialized.as_bytes());
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Encode bytes as base64url (no padding).
pub fn base64url_encode(data: &[u8]) -> String {
    const CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        }
    }
    result.replace('+', "-").replace('/', "_")
}

/// Decode base64url (no padding) to bytes.
pub fn base64url_decode(s: &str) -> Result<Vec<u8>, String> {
    // Convert base64url back to standard base64.
    let standard = s.replace('-', "+").replace('_', "/");
    // Add padding.
    let padded = match standard.len() % 4 {
        2 => format!("{}==", standard),
        3 => format!("{}=", standard),
        0 => standard,
        _ => return Err("invalid base64url length".into()),
    };

    // Decode standard base64.
    let mut out = Vec::with_capacity(padded.len() * 3 / 4);
    let chars: Vec<u8> = padded
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => 0,
            _ => 255,
        })
        .collect();

    let padded_bytes = padded.as_bytes();
    for (i, chunk) in chars.chunks(4).enumerate() {
        if chunk.len() < 4 {
            break;
        }
        if chunk.contains(&255) {
            return Err("invalid base64 character".into());
        }
        let triple = ((chunk[0] as u32) << 18)
            | ((chunk[1] as u32) << 12)
            | ((chunk[2] as u32) << 6)
            | (chunk[3] as u32);
        out.push((triple >> 16) as u8);
        if padded_bytes.get(i * 4 + 2) != Some(&b'=') {
            out.push((triple >> 8) as u8);
        }
        if padded_bytes.get(i * 4 + 3) != Some(&b'=') {
            out.push(triple as u8);
        }
    }
    Ok(out)
}

/// Compute SHA256 of data and return as hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Stream chunk size for hashing and I/O (256 KB).
pub const STREAM_CHUNK_SIZE: usize = 256 * 1024;

/// Compute SHA256 incrementally from a reader in 256 KB chunks.
///
/// Returns `(hex_hash, bytes_read)`. Never buffers the full content.
pub fn sha256_stream(reader: &mut dyn std::io::Read) -> std::io::Result<(String, u64)> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; STREAM_CHUNK_SIZE];
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((hex::encode(hasher.finalize()), total))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_id_deterministic() {
        let pubkey = "a".repeat(64);
        let tags: Vec<Vec<String>> = vec![vec!["t".to_string(), "upload".to_string()]];
        let id1 = compute_event_id(&pubkey, 1700000000, 24242, &tags, "test");
        let id2 = compute_event_id(&pubkey, 1700000000, 24242, &tags, "test");
        assert_eq!(id1, id2);

        let id3 = compute_event_id(&pubkey, 1700000000, 24242, &tags, "other");
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_base64url_no_special_chars() {
        let data = b"hello blossom world! this is a test of base64url encoding";
        let encoded = base64url_encode(data);
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains('='));
    }

    #[test]
    fn test_sha256_hex_known() {
        let hash = sha256_hex(b"hello");
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_sha256_stream_matches_hex() {
        let data = b"streaming hash test with multiple chunks of data that we want to verify";
        let expected = sha256_hex(data);
        let mut cursor = std::io::Cursor::new(data);
        let (hash, size) = sha256_stream(&mut cursor).unwrap();
        assert_eq!(hash, expected);
        assert_eq!(size, data.len() as u64);
    }

    #[test]
    fn test_sha256_stream_empty() {
        let mut cursor = std::io::Cursor::new(b"");
        let (hash, size) = sha256_stream(&mut cursor).unwrap();
        assert_eq!(hash, sha256_hex(b""));
        assert_eq!(size, 0);
    }

    #[test]
    fn test_blob_descriptor_serde() {
        let desc = BlobDescriptor {
            sha256: "abc123".into(),
            size: 42,
            content_type: Some("application/octet-stream".into()),
            url: Some("http://example.com/abc123".into()),
            uploaded: Some(1700000000),
        };
        let json = serde_json::to_string(&desc).unwrap();
        let parsed: BlobDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.sha256, "abc123");
        assert_eq!(parsed.size, 42);
    }
}
