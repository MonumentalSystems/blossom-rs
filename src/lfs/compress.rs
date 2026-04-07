//! Compression and delta encoding for LFS-aware storage (BUD-20).
//!
//! Provides zstd compression for full LFS blobs and xdelta3 delta
//! encoding for successive versions of the same file.

const ZSTD_COMPRESSION_LEVEL: i32 = 3;
pub const DELTA_THRESHOLD: f64 = 0.8;

/// Compress data with zstd.
pub fn compress(data: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::Write;
    let mut encoder = zstd::Encoder::new(Vec::new(), ZSTD_COMPRESSION_LEVEL)
        .map_err(|e| format!("zstd encoder init: {e}"))?;
    encoder
        .write_all(data)
        .map_err(|e| format!("zstd compress: {e}"))?;
    encoder.finish().map_err(|e| format!("zstd flush: {e}"))
}

/// Decompress zstd data.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>, String> {
    zstd::decode_all(data).map_err(|e| format!("zstd decompress: {e}"))
}

/// Encode a delta between a base blob and new data using xdelta3.
pub fn encode_delta(base: &[u8], new: &[u8]) -> Result<Vec<u8>, String> {
    xdelta3::encode(new, base).ok_or_else(|| "xdelta3 encode failed".into())
}

/// Decode a delta against a base blob using xdelta3.
pub fn decode_delta(base: &[u8], delta: &[u8]) -> Result<Vec<u8>, String> {
    xdelta3::decode(delta, base).ok_or_else(|| "xdelta3 decode failed".into())
}

/// Decide whether a delta is worth storing vs falling back to full compressed.
/// Returns true if the delta is smaller than `threshold` fraction of original.
pub fn delta_is_worthwhile(delta_len: usize, original_len: usize) -> bool {
    if original_len == 0 {
        return false;
    }
    let ratio = delta_len as f64 / original_len as f64;
    ratio < DELTA_THRESHOLD
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_decompress_roundtrip() {
        let data = b"hello world, this is some test data for compression that should compress well because it has repeated patterns repeated patterns repeated patterns";
        let compressed = compress(data).unwrap();
        assert!(compressed.len() < data.len());
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_delta_roundtrip_small() {
        let base: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        let mut new = base.clone();
        new[500..510]
            .copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x13, 0x37]);
        let delta = encode_delta(&base, &new).unwrap();
        assert!(
            delta.len() < new.len() / 2,
            "delta should be smaller than original"
        );
        let reconstructed = decode_delta(&base, &delta).unwrap();
        assert_eq!(reconstructed, new);
    }

    #[test]
    fn test_delta_is_worthwhile() {
        assert!(delta_is_worthwhile(100, 1000));
        assert!(!delta_is_worthwhile(900, 1000));
        assert!(!delta_is_worthwhile(0, 0));
    }

    #[test]
    fn test_large_delta_roundtrip() {
        let base: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
        let mut new = base.clone();
        new[50_000..50_010]
            .copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x13, 0x37]);

        let delta = encode_delta(&base, &new).unwrap();
        assert!(delta.len() < new.len() / 2, "delta should be much smaller");

        let reconstructed = decode_delta(&base, &delta).unwrap();
        assert_eq!(reconstructed, new);
    }
}
