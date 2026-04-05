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
}

/// Helper to compute SHA256 and build a BlobDescriptor.
pub(crate) fn make_descriptor(data: &[u8], base_url: &str) -> BlobDescriptor {
    let hash = crate::protocol::sha256_hex(data);
    let size = data.len() as u64;
    let url = format!("{}/{}", base_url, hash);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    BlobDescriptor {
        sha256: hash,
        size,
        content_type: Some("application/octet-stream".into()),
        url: Some(url),
        uploaded: Some(ts),
    }
}
