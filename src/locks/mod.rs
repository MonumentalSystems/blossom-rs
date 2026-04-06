//! LFS file locking database (BUD-08).
//!
//! Provides lock storage for Git LFS file locking support. Locks are scoped
//! by repo ID and owned by Nostr pubkeys. Includes an in-memory
//! implementation for testing and as a default.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// A single lock record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockRecord {
    /// UUID v4, server-assigned.
    pub id: String,
    /// Repository namespace (e.g., "github.com/user/repo").
    pub repo_id: String,
    /// File path relative to repo root.
    pub path: String,
    /// Hex-encoded x-only Nostr pubkey of the lock owner.
    pub pubkey: String,
    /// Unix timestamp of lock creation.
    pub locked_at: u64,
}

/// Filters for listing locks.
#[derive(Debug, Clone, Default)]
pub struct LockFilters {
    pub path: Option<String>,
    pub id: Option<String>,
    pub cursor: Option<String>,
    pub limit: Option<u32>,
}

/// Errors from lock database operations.
#[derive(Debug, thiserror::Error)]
pub enum LockError {
    #[error("path already locked: {0}")]
    Conflict(String),
    #[error("not found")]
    NotFound,
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("lock database error: {0}")]
    Internal(String),
}

/// Trait for lock persistence.
///
/// Implementations store LFS locks scoped by repo ID. All methods are
/// synchronous; the server wraps in `Arc<Mutex<>>`.
pub trait LockDatabase: Send + Sync {
    /// Create a new lock for `path` in `repo`, owned by `pubkey`.
    /// Returns the created lock or `LockError::Conflict` if already locked.
    fn create_lock(
        &mut self,
        repo: &str,
        path: &str,
        pubkey: &str,
    ) -> Result<LockRecord, LockError>;

    /// Delete a lock by ID. If `force` is false, only the owner can unlock.
    /// Admins can always force-unlock.
    fn delete_lock(
        &mut self,
        repo: &str,
        id: &str,
        force: bool,
        requester: &str,
    ) -> Result<LockRecord, LockError>;

    /// List locks for a repo with optional filters.
    /// Returns (locks, next_cursor).
    fn list_locks(
        &self,
        repo: &str,
        filters: &LockFilters,
    ) -> Result<(Vec<LockRecord>, Option<String>), LockError>;

    /// Get a lock by ID.
    fn get_lock(&self, repo: &str, id: &str) -> Result<LockRecord, LockError>;

    /// Get a lock by path (for conflict checking).
    fn get_lock_by_path(&self, repo: &str, path: &str) -> Result<LockRecord, LockError>;
}

/// In-memory lock database for testing.
pub struct MemoryLockDatabase {
    locks: HashMap<String, LockRecord>,
}

impl MemoryLockDatabase {
    pub fn new() -> Self {
        Self {
            locks: HashMap::new(),
        }
    }
}

impl Default for MemoryLockDatabase {
    fn default() -> Self {
        Self::new()
    }
}

fn lock_key(repo: &str, id: &str) -> String {
    format!("{}:{}", repo, id)
}

fn path_key(repo: &str, path: &str) -> String {
    format!("{}:{}", repo, path)
}

impl LockDatabase for MemoryLockDatabase {
    fn create_lock(
        &mut self,
        repo: &str,
        path: &str,
        pubkey: &str,
    ) -> Result<LockRecord, LockError> {
        let pk = path_key(repo, path);
        if let Some(existing) = self
            .locks
            .values()
            .find(|l| path_key(&l.repo_id, &l.path) == pk)
        {
            return Err(LockError::Conflict(existing.id.clone()));
        }

        let id = uuid::Uuid::new_v4().to_string();
        let locked_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let record = LockRecord {
            id: id.clone(),
            repo_id: repo.to_string(),
            path: path.to_string(),
            pubkey: pubkey.to_string(),
            locked_at,
        };

        let key = lock_key(repo, &id);
        self.locks.insert(key, record.clone());
        Ok(record)
    }

    fn delete_lock(
        &mut self,
        repo: &str,
        id: &str,
        force: bool,
        requester: &str,
    ) -> Result<LockRecord, LockError> {
        let key = lock_key(repo, id);
        let lock = self.locks.get(&key).cloned().ok_or(LockError::NotFound)?;

        if !force && lock.pubkey != requester {
            return Err(LockError::Forbidden(
                "only the lock owner or an admin can unlock".to_string(),
            ));
        }

        self.locks.remove(&key);
        Ok(lock)
    }

    fn list_locks(
        &self,
        repo: &str,
        filters: &LockFilters,
    ) -> Result<(Vec<LockRecord>, Option<String>), LockError> {
        let mut locks: Vec<LockRecord> = self
            .locks
            .values()
            .filter(|l| l.repo_id == repo)
            .filter(|l| filters.path.as_ref().map_or(true, |p| l.path == *p))
            .filter(|l| filters.id.as_ref().map_or(true, |id| l.id == *id))
            .cloned()
            .collect();

        locks.sort_by_key(|l| l.locked_at);

        let limit = filters.limit.unwrap_or(100) as usize;
        let cursor_val = filters
            .cursor
            .as_ref()
            .and_then(|c| c.parse::<usize>().ok());

        let start = cursor_val.unwrap_or(0);
        let end = std::cmp::min(start + limit, locks.len());

        if start >= locks.len() {
            return Ok((vec![], None));
        }

        let next_cursor = if end < locks.len() {
            Some(end.to_string())
        } else {
            None
        };

        Ok((locks[start..end].to_vec(), next_cursor))
    }

    fn get_lock(&self, repo: &str, id: &str) -> Result<LockRecord, LockError> {
        let key = lock_key(repo, id);
        self.locks.get(&key).cloned().ok_or(LockError::NotFound)
    }

    fn get_lock_by_path(&self, repo: &str, path: &str) -> Result<LockRecord, LockError> {
        self.locks
            .values()
            .find(|l| l.repo_id == repo && l.path == path)
            .cloned()
            .ok_or(LockError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_lock() {
        let mut db = MemoryLockDatabase::new();
        let lock = db.create_lock("repo1", "file.txt", "pk1").unwrap();
        assert_eq!(lock.repo_id, "repo1");
        assert_eq!(lock.path, "file.txt");
        assert_eq!(lock.pubkey, "pk1");
        assert!(!lock.id.is_empty());
    }

    #[test]
    fn test_create_lock_conflict() {
        let mut db = MemoryLockDatabase::new();
        db.create_lock("repo1", "file.txt", "pk1").unwrap();
        let result = db.create_lock("repo1", "file.txt", "pk2");
        assert!(matches!(result, Err(LockError::Conflict(_))));
    }

    #[test]
    fn test_create_lock_different_repos_same_path() {
        let mut db = MemoryLockDatabase::new();
        db.create_lock("repo1", "file.txt", "pk1").unwrap();
        let result = db.create_lock("repo2", "file.txt", "pk2");
        assert!(result.is_ok());
    }

    #[test]
    fn test_delete_lock_owner() {
        let mut db = MemoryLockDatabase::new();
        let lock = db.create_lock("repo1", "file.txt", "pk1").unwrap();
        let deleted = db.delete_lock("repo1", &lock.id, false, "pk1").unwrap();
        assert_eq!(deleted.id, lock.id);
    }

    #[test]
    fn test_delete_lock_non_owner_no_force() {
        let mut db = MemoryLockDatabase::new();
        let lock = db.create_lock("repo1", "file.txt", "pk1").unwrap();
        let result = db.delete_lock("repo1", &lock.id, false, "pk2");
        assert!(matches!(result, Err(LockError::Forbidden(_))));
    }

    #[test]
    fn test_delete_lock_non_owner_force() {
        let mut db = MemoryLockDatabase::new();
        let lock = db.create_lock("repo1", "file.txt", "pk1").unwrap();
        let deleted = db.delete_lock("repo1", &lock.id, true, "pk2").unwrap();
        assert_eq!(deleted.id, lock.id);
    }

    #[test]
    fn test_delete_lock_not_found() {
        let mut db = MemoryLockDatabase::new();
        let result = db.delete_lock("repo1", "nonexistent", false, "pk1");
        assert!(matches!(result, Err(LockError::NotFound)));
    }

    #[test]
    fn test_list_locks() {
        let mut db = MemoryLockDatabase::new();
        db.create_lock("repo1", "a.txt", "pk1").unwrap();
        db.create_lock("repo1", "b.txt", "pk1").unwrap();
        db.create_lock("repo2", "c.txt", "pk1").unwrap();

        let (locks, cursor) = db.list_locks("repo1", &LockFilters::default()).unwrap();
        assert_eq!(locks.len(), 2);
        assert!(cursor.is_none());
    }

    #[test]
    fn test_list_locks_with_path_filter() {
        let mut db = MemoryLockDatabase::new();
        db.create_lock("repo1", "a.txt", "pk1").unwrap();
        db.create_lock("repo1", "b.txt", "pk1").unwrap();

        let filters = LockFilters {
            path: Some("a.txt".to_string()),
            ..Default::default()
        };
        let (locks, _) = db.list_locks("repo1", &filters).unwrap();
        assert_eq!(locks.len(), 1);
        assert_eq!(locks[0].path, "a.txt");
    }

    #[test]
    fn test_list_locks_pagination() {
        let mut db = MemoryLockDatabase::new();
        for i in 0..5 {
            db.create_lock("repo1", &format!("file{}.txt", i), "pk1")
                .unwrap();
        }

        let filters = LockFilters {
            limit: Some(2),
            ..Default::default()
        };
        let (locks, cursor) = db.list_locks("repo1", &filters).unwrap();
        assert_eq!(locks.len(), 2);
        assert!(cursor.is_some());

        let filters2 = LockFilters {
            limit: Some(2),
            cursor,
            ..Default::default()
        };
        let (locks2, cursor2) = db.list_locks("repo1", &filters2).unwrap();
        assert_eq!(locks2.len(), 2);
        assert!(cursor2.is_some());

        let filters3 = LockFilters {
            limit: Some(2),
            cursor: cursor2,
            ..Default::default()
        };
        let (locks3, cursor3) = db.list_locks("repo1", &filters3).unwrap();
        assert_eq!(locks3.len(), 1);
        assert!(cursor3.is_none());
    }

    #[test]
    fn test_get_lock_by_path() {
        let mut db = MemoryLockDatabase::new();
        let lock = db.create_lock("repo1", "file.txt", "pk1").unwrap();
        let found = db.get_lock_by_path("repo1", "file.txt").unwrap();
        assert_eq!(found.id, lock.id);
    }

    #[test]
    fn test_get_lock_by_path_not_found() {
        let db = MemoryLockDatabase::new();
        let result = db.get_lock_by_path("repo1", "nonexistent.txt");
        assert!(matches!(result, Err(LockError::NotFound)));
    }
}
