//! LFS-aware storage (BUD-20).
//!
//! Parses LFS context tags from kind:24242 auth events and provides
//! the storage pipeline for compression and delta encoding.

pub mod compress;

use crate::protocol::NostrEvent;
use crate::storage::BlobBackend;

const MAX_DELTA_CHAIN_DEPTH: usize = 10;

/// LFS context extracted from auth event tags.
#[derive(Debug, Clone, Default)]
pub struct LfsContext {
    pub is_lfs: bool,
    pub path: Option<String>,
    pub repo: Option<String>,
    pub base: Option<String>,
    pub is_manifest: bool,
}

impl LfsContext {
    /// Parse LFS tags from a kind:24242 auth event.
    pub fn from_event(event: &NostrEvent) -> Self {
        let mut ctx = LfsContext::default();

        for tag in &event.tags {
            if tag.is_empty() {
                continue;
            }
            match tag[0].as_str() {
                "t" if tag.len() >= 2 && tag[1] == "lfs" => ctx.is_lfs = true,
                "path" if tag.len() >= 2 => ctx.path = Some(tag[1].clone()),
                "repo" if tag.len() >= 2 => ctx.repo = Some(tag[1].clone()),
                "base" if tag.len() >= 2 => ctx.base = Some(tag[1].clone()),
                "manifest" => ctx.is_manifest = true,
                _ => {}
            }
        }

        ctx
    }
}

/// Storage type for an LFS blob.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LfsStorageType {
    Raw,
    Compressed,
    Delta,
}

impl std::fmt::Display for LfsStorageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Raw => write!(f, "raw"),
            Self::Compressed => write!(f, "compressed"),
            Self::Delta => write!(f, "delta"),
        }
    }
}

/// Reconstruct the original blob data from a potentially compressed or
/// delta-encoded storage form.
///
/// Walks the delta chain (up to [`MAX_DELTA_CHAIN_DEPTH`] hops), fetches
/// base data from the backend, decompresses as needed, and applies deltas
/// in order.
pub fn reconstruct_blob(
    version: &LfsFileVersion,
    lfs_db: &dyn LfsVersionDatabase,
    backend: &dyn BlobBackend,
) -> Result<Vec<u8>, String> {
    let mut chain: Vec<LfsFileVersion> = Vec::new();
    let mut current_hash = version.sha256.clone();

    for _ in 0..MAX_DELTA_CHAIN_DEPTH {
        match lfs_db.get_by_sha256(&current_hash) {
            Ok(Some(v)) => {
                if v.storage == LfsStorageType::Delta {
                    if let Some(ref base) = v.base_sha256 {
                        let base_hash = base.clone();
                        chain.push(v);
                        current_hash = base_hash;
                        continue;
                    }
                }
                chain.push(v);
                break;
            }
            _ => return Err("delta chain broken".into()),
        }
    }

    chain.reverse();

    let base_hash = chain
        .first()
        .and_then(|v| {
            if v.storage != LfsStorageType::Delta {
                Some(v.sha256.clone())
            } else {
                v.base_sha256.clone()
            }
        })
        .ok_or("no base in chain")?;

    let mut result = backend
        .get(&base_hash)
        .ok_or_else(|| format!("base blob {} not found", base_hash))?;

    if let Ok(Some(base_v)) = lfs_db.get_by_sha256(&base_hash) {
        if base_v.storage == LfsStorageType::Compressed {
            result = compress::decompress(&result).unwrap_or(result);
        }
    }

    for v in &chain {
        if v.storage == LfsStorageType::Delta {
            let delta_raw = backend
                .get(&v.sha256)
                .ok_or_else(|| format!("delta blob {} not found", v.sha256))?;
            let delta_decoded = compress::decompress(&delta_raw).unwrap_or(delta_raw);
            result = compress::decode_delta(&result, &delta_decoded)?;
        }
    }

    Ok(result)
}

/// Record for a version of an LFS file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LfsFileVersion {
    pub repo_id: String,
    pub path: String,
    pub version: i64,
    pub sha256: String,
    pub base_sha256: Option<String>,
    pub storage: LfsStorageType,
    pub delta_algo: Option<String>,
    pub original_size: i64,
    pub stored_size: i64,
    pub created_at: i64,
}

/// Errors from LFS version database operations.
#[derive(Debug, thiserror::Error)]
pub enum LfsVersionError {
    #[error("not found")]
    NotFound,
    #[error("database error: {0}")]
    Internal(String),
}

/// Trait for LFS file version persistence.
pub trait LfsVersionDatabase: Send + Sync {
    /// Record a new file version. Returns the assigned version number.
    fn record_version(&mut self, record: &LfsFileVersion) -> Result<i64, LfsVersionError>;

    /// Look up version info by SHA-256.
    fn get_by_sha256(&self, sha256: &str) -> Result<Option<LfsFileVersion>, LfsVersionError>;

    /// Get the latest version for a repo+path.
    fn get_latest_version(
        &self,
        repo_id: &str,
        path: &str,
    ) -> Result<Option<LfsFileVersion>, LfsVersionError>;

    /// Delete all version records for a SHA-256.
    fn delete_by_sha256(&mut self, sha256: &str) -> Result<(), LfsVersionError>;

    /// Get all deltas that reference this SHA-256 as their base.
    fn get_deltas_for_base(
        &self,
        base_sha256: &str,
    ) -> Result<Vec<LfsFileVersion>, LfsVersionError>;

    /// Update the storage info for a version (used when rebasing deltas).
    fn update_version(
        &mut self,
        sha256: &str,
        storage: LfsStorageType,
        base_sha256: Option<&str>,
        stored_size: i64,
    ) -> Result<(), LfsVersionError>;

    /// Get aggregate storage stats.
    fn lfs_stats(&self) -> Result<LfsStorageStats, LfsVersionError>;
}

/// Aggregate storage statistics for LFS blobs.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct LfsStorageStats {
    pub total_versions: i64,
    pub total_original_bytes: i64,
    pub total_stored_bytes: i64,
    pub by_storage_type: std::collections::HashMap<String, LfsStorageTypeStats>,
}

/// Per-storage-type statistics.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct LfsStorageTypeStats {
    pub count: i64,
    pub original_bytes: i64,
    pub stored_bytes: i64,
}

/// In-memory LFS version database (for testing).
pub struct MemoryLfsVersionDatabase {
    versions: Vec<LfsFileVersion>,
}

impl MemoryLfsVersionDatabase {
    pub fn new() -> Self {
        Self {
            versions: Vec::new(),
        }
    }
}

impl Default for MemoryLfsVersionDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl LfsVersionDatabase for MemoryLfsVersionDatabase {
    fn record_version(&mut self, record: &LfsFileVersion) -> Result<i64, LfsVersionError> {
        let version = record.version;
        self.versions.push(record.clone());
        Ok(version)
    }

    fn get_by_sha256(&self, sha256: &str) -> Result<Option<LfsFileVersion>, LfsVersionError> {
        Ok(self.versions.iter().find(|v| v.sha256 == sha256).cloned())
    }

    fn get_latest_version(
        &self,
        repo_id: &str,
        path: &str,
    ) -> Result<Option<LfsFileVersion>, LfsVersionError> {
        Ok(self
            .versions
            .iter()
            .filter(|v| v.repo_id == repo_id && v.path == path)
            .max_by_key(|v| v.version)
            .cloned())
    }

    fn delete_by_sha256(&mut self, sha256: &str) -> Result<(), LfsVersionError> {
        self.versions.retain(|v| v.sha256 != sha256);
        Ok(())
    }

    fn get_deltas_for_base(
        &self,
        base_sha256: &str,
    ) -> Result<Vec<LfsFileVersion>, LfsVersionError> {
        Ok(self
            .versions
            .iter()
            .filter(|v| {
                v.storage == LfsStorageType::Delta && v.base_sha256.as_deref() == Some(base_sha256)
            })
            .cloned()
            .collect())
    }

    fn update_version(
        &mut self,
        sha256: &str,
        storage: LfsStorageType,
        base_sha256: Option<&str>,
        stored_size: i64,
    ) -> Result<(), LfsVersionError> {
        if let Some(v) = self.versions.iter_mut().find(|v| v.sha256 == sha256) {
            v.storage = storage;
            v.base_sha256 = base_sha256.map(|s| s.to_string());
            v.stored_size = stored_size;
        }
        Ok(())
    }

    fn lfs_stats(&self) -> Result<LfsStorageStats, LfsVersionError> {
        let mut stats = LfsStorageStats::default();
        let mut by_type: std::collections::HashMap<String, LfsStorageTypeStats> =
            std::collections::HashMap::new();

        for v in &self.versions {
            stats.total_versions += 1;
            stats.total_original_bytes += v.original_size;
            stats.total_stored_bytes += v.stored_size;

            let key = v.storage.to_string();
            let entry = by_type.entry(key).or_default();
            entry.count += 1;
            entry.original_bytes += v.original_size;
            entry.stored_bytes += v.stored_size;
        }

        stats.by_storage_type = by_type;
        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_lfs_tags() {
        let event = NostrEvent {
            id: String::new(),
            pubkey: String::new(),
            created_at: 0,
            kind: 24242,
            tags: vec![
                vec!["t".into(), "upload".into()],
                vec!["t".into(), "lfs".into()],
                vec!["path".into(), "assets/model.bin".into()],
                vec!["repo".into(), "github.com/org/repo".into()],
                vec!["base".into(), "a1b2c3".into()],
                vec!["expiration".into(), "9999999999".into()],
            ],
            content: String::new(),
            sig: String::new(),
        };

        let ctx = LfsContext::from_event(&event);
        assert!(ctx.is_lfs);
        assert_eq!(ctx.path.as_deref(), Some("assets/model.bin"));
        assert_eq!(ctx.repo.as_deref(), Some("github.com/org/repo"));
        assert_eq!(ctx.base.as_deref(), Some("a1b2c3"));
        assert!(!ctx.is_manifest);
    }

    #[test]
    fn test_parse_manifest_tag() {
        let event = NostrEvent {
            id: String::new(),
            pubkey: String::new(),
            created_at: 0,
            kind: 24242,
            tags: vec![
                vec!["t".into(), "upload".into()],
                vec!["t".into(), "lfs".into()],
                vec!["manifest".into()],
                vec!["expiration".into(), "9999999999".into()],
            ],
            content: String::new(),
            sig: String::new(),
        };

        let ctx = LfsContext::from_event(&event);
        assert!(ctx.is_lfs);
        assert!(ctx.is_manifest);
    }

    #[test]
    fn test_no_lfs_tags() {
        let event = NostrEvent {
            id: String::new(),
            pubkey: String::new(),
            created_at: 0,
            kind: 24242,
            tags: vec![
                vec!["t".into(), "upload".into()],
                vec!["x".into(), "abc123".into()],
                vec!["expiration".into(), "9999999999".into()],
            ],
            content: String::new(),
            sig: String::new(),
        };

        let ctx = LfsContext::from_event(&event);
        assert!(!ctx.is_lfs);
    }

    #[test]
    fn test_memory_lfs_version_db() {
        let mut db = MemoryLfsVersionDatabase::new();

        let v1 = LfsFileVersion {
            repo_id: "github.com/org/repo".into(),
            path: "model.bin".into(),
            version: 1,
            sha256: "aaa111".into(),
            base_sha256: None,
            storage: LfsStorageType::Compressed,
            delta_algo: Some("zstd".into()),
            original_size: 1000,
            stored_size: 500,
            created_at: 100,
        };
        db.record_version(&v1).unwrap();

        let v2 = LfsFileVersion {
            repo_id: "github.com/org/repo".into(),
            path: "model.bin".into(),
            version: 2,
            sha256: "bbb222".into(),
            base_sha256: Some("aaa111".into()),
            storage: LfsStorageType::Delta,
            delta_algo: Some("xdelta3".into()),
            original_size: 1000,
            stored_size: 100,
            created_at: 200,
        };
        db.record_version(&v2).unwrap();

        let latest = db
            .get_latest_version("github.com/org/repo", "model.bin")
            .unwrap()
            .unwrap();
        assert_eq!(latest.version, 2);
        assert_eq!(latest.sha256, "bbb222");

        let by_hash = db.get_by_sha256("aaa111").unwrap().unwrap();
        assert_eq!(by_hash.storage, LfsStorageType::Compressed);

        let deltas = db.get_deltas_for_base("aaa111").unwrap();
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].sha256, "bbb222");

        let stats = db.lfs_stats().unwrap();
        assert_eq!(stats.total_versions, 2);
        assert_eq!(stats.total_original_bytes, 2000);
        assert_eq!(stats.total_stored_bytes, 600);
    }
}
