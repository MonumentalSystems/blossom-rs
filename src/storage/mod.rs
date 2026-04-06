//! Pluggable blob storage backends.
//!
//! All backends are content-addressed by SHA256 hash.

mod memory;

#[cfg(feature = "filesystem")]
mod filesystem;

#[cfg(feature = "s3")]
mod s3;

pub use memory::MemoryBackend;

#[cfg(feature = "filesystem")]
pub use filesystem::FilesystemBackend;

#[cfg(feature = "s3")]
pub use self::s3::{S3Backend, S3Config};

use crate::protocol::BlobDescriptor;

/// Trait for raw blob storage backends.
///
/// All operations are keyed by SHA256 hex hash. Implementations must be
/// thread-safe (`Send + Sync`).
pub trait BlobBackend: Send + Sync {
    /// Store a blob. Returns the blob descriptor with SHA256 hash and size.
    fn insert(&mut self, data: Vec<u8>, base_url: &str) -> BlobDescriptor;

    /// Retrieve a blob by SHA256 hash.
    fn get(&self, sha256: &str) -> Option<Vec<u8>>;

    /// Check if a blob exists.
    fn exists(&self, sha256: &str) -> bool;

    /// Delete a blob. Returns true if it existed.
    fn delete(&mut self, sha256: &str) -> bool;

    /// Number of stored blobs.
    fn len(&self) -> usize;

    /// Whether the store is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Total bytes stored.
    fn total_bytes(&self) -> u64;

    /// Store a blob from a streaming reader without buffering the full
    /// content in memory. Returns the blob descriptor with SHA256 hash.
    ///
    /// The default implementation reads everything into a `Vec` and calls
    /// [`insert`](BlobBackend::insert). Override for backends that can
    /// stream directly to storage (filesystem, S3).
    fn insert_stream(
        &mut self,
        reader: &mut dyn std::io::Read,
        size: u64,
        base_url: &str,
    ) -> Result<BlobDescriptor, String> {
        let mut data = Vec::with_capacity(size as usize);
        reader
            .read_to_end(&mut data)
            .map_err(|e| format!("read stream: {e}"))?;
        Ok(self.insert(data, base_url))
    }
}

/// Helper to compute SHA256 and build a BlobDescriptor.
pub(crate) fn make_descriptor(data: &[u8], base_url: &str) -> BlobDescriptor {
    let hash = crate::protocol::sha256_hex(data);
    make_descriptor_from_hash(&hash, data.len() as u64, base_url)
}

/// Build a BlobDescriptor from a pre-computed hash and size.
pub(crate) fn make_descriptor_from_hash(hash: &str, size: u64, base_url: &str) -> BlobDescriptor {
    let url = format!("{}/{}", base_url, hash);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    BlobDescriptor {
        sha256: hash.to_string(),
        size,
        content_type: Some("application/octet-stream".into()),
        url: Some(url),
        uploaded: Some(ts),
    }
}
