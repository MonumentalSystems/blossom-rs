//! Database backends for blob metadata persistence.
//!
//! The [`BlobDatabase`] trait abstracts over metadata storage (upload records,
//! user quotas, file statistics). Blob data itself lives in [`BlobBackend`](crate::storage::BlobBackend);
//! the database only tracks metadata.

mod memory;

#[cfg(feature = "db-sqlite")]
mod sqlite;

#[cfg(feature = "db-postgres")]
mod postgres;

pub use memory::MemoryDatabase;

#[cfg(feature = "db-sqlite")]
pub use sqlite::SqliteDatabase;

#[cfg(feature = "db-postgres")]
pub use postgres::PostgresDatabase;

use serde::{Deserialize, Serialize};

/// Metadata record for an uploaded blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadRecord {
    /// SHA256 hex hash of the blob content.
    pub sha256: String,
    /// Size in bytes.
    pub size: u64,
    /// MIME type (e.g., `application/octet-stream`).
    pub mime_type: String,
    /// Hex-encoded x-only public key of the uploader.
    pub pubkey: String,
    /// Unix timestamp of upload.
    pub created_at: u64,
    /// Perceptual hash for image deduplication (optional).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub phash: Option<u64>,
}

/// Per-user record for quota tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRecord {
    /// Hex-encoded x-only public key.
    pub pubkey: String,
    /// Maximum bytes this user may store. `None` means unlimited.
    pub quota_bytes: Option<u64>,
    /// Current total bytes stored by this user.
    pub used_bytes: u64,
}

/// Per-blob access statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileStats {
    /// SHA256 hex hash.
    pub sha256: String,
    /// Total egress bytes served.
    pub egress_bytes: u64,
    /// Unix timestamp of last access.
    pub last_accessed: u64,
}

/// Errors from database operations.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("quota exceeded: used {used} + {requested} > limit {limit}")]
    QuotaExceeded {
        used: u64,
        requested: u64,
        limit: u64,
    },
    #[error("not found")]
    NotFound,
    #[error("database error: {0}")]
    Internal(String),
}

/// Trait for blob metadata persistence.
///
/// Implementations store upload records, user quotas, and access statistics.
/// All methods are synchronous; the server wraps in `Arc<Mutex<>>` like `BlobBackend`.
pub trait BlobDatabase: Send + Sync {
    // --- Upload records ---

    /// Record a new upload. If the sha256 already exists for this pubkey, this is a no-op.
    fn record_upload(&mut self, record: &UploadRecord) -> Result<(), DbError>;

    /// Get the upload record for a blob.
    fn get_upload(&self, sha256: &str) -> Result<UploadRecord, DbError>;

    /// List uploads by a pubkey, ordered by created_at descending.
    fn list_uploads_by_pubkey(&self, pubkey: &str) -> Result<Vec<UploadRecord>, DbError>;

    /// Delete an upload record. Returns true if it existed.
    fn delete_upload(&mut self, sha256: &str) -> Result<bool, DbError>;

    // --- User / quota ---

    /// Get or create a user record.
    fn get_or_create_user(&mut self, pubkey: &str) -> Result<UserRecord, DbError>;

    /// Set a user's quota limit. Pass `None` for unlimited.
    fn set_quota(&mut self, pubkey: &str, quota_bytes: Option<u64>) -> Result<(), DbError>;

    /// Check if a user can upload `additional_bytes` within their quota.
    /// Returns `Ok(())` if allowed, `Err(DbError::QuotaExceeded)` if not.
    fn check_quota(&self, pubkey: &str, additional_bytes: u64) -> Result<(), DbError>;

    /// Update a user's used_bytes (called after upload or delete).
    fn update_used_bytes(&mut self, pubkey: &str, used_bytes: u64) -> Result<(), DbError>;

    // --- File statistics ---

    /// Record an access event (download) for a blob.
    fn record_access(&mut self, sha256: &str, bytes_served: u64) -> Result<(), DbError>;

    /// Get statistics for a blob.
    fn get_stats(&self, sha256: &str) -> Result<FileStats, DbError>;

    /// Total number of upload records.
    fn upload_count(&self) -> usize;

    /// Total number of registered users.
    fn user_count(&self) -> usize;

    // --- Perceptual hash dedup ---

    /// Find uploads with a matching perceptual hash (for image dedup).
    /// Returns uploads whose phash matches within a Hamming distance threshold.
    fn find_by_phash(&self, phash: u64) -> Result<Vec<UploadRecord>, DbError> {
        // Default implementation: no phash support.
        let _ = phash;
        Ok(vec![])
    }
}
