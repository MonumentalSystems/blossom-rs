//! SQLite-backed lock database (BUD-19).
//!
//! Persistent lock storage using the same SQLx pool as `SqliteDatabase`.
//! Behind the `db-sqlite` feature flag.

use sqlx::sqlite::SqlitePool;

use super::{LockDatabase, LockError, LockFilters, LockRecord};

/// SQLite-backed lock database.
///
/// Stores locks in an `lfs_locks` table. Uses `block_in_place` for sync trait
/// compat, same pattern as `SqliteDatabase`.
pub struct SqliteLockDatabase {
    pool: SqlitePool,
}

impl SqliteLockDatabase {
    /// Create a new SQLite lock database, running migrations.
    pub async fn new(pool: SqlitePool) -> Result<Self, LockError> {
        let db = Self { pool };
        db.run_migrations().await?;
        Ok(db)
    }

    /// Create from a SQLite connection URL.
    pub async fn from_url(url: &str) -> Result<Self, LockError> {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(5)
            .connect(url)
            .await
            .map_err(|e| LockError::Internal(format!("sqlite connect: {e}")))?;
        Self::new(pool).await
    }

    async fn run_migrations(&self) -> Result<(), LockError> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS lfs_locks (
                id        TEXT NOT NULL,
                repo_id   TEXT NOT NULL,
                path      TEXT NOT NULL,
                pubkey    TEXT NOT NULL,
                locked_at INTEGER NOT NULL,
                PRIMARY KEY (repo_id, id),
                UNIQUE (repo_id, path)
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| LockError::Internal(format!("lock migration: {e}")))?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_lfs_locks_repo ON lfs_locks(repo_id)")
            .execute(&self.pool)
            .await
            .map_err(|e| LockError::Internal(format!("lock migration: {e}")))?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_lfs_locks_repo_path ON lfs_locks(repo_id, path)",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| LockError::Internal(format!("lock migration: {e}")))?;

        Ok(())
    }

    fn block_on<F: std::future::Future<Output = T>, T>(future: F) -> T {
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(future))
    }
}

impl LockDatabase for SqliteLockDatabase {
    fn create_lock(
        &mut self,
        repo: &str,
        path: &str,
        pubkey: &str,
    ) -> Result<LockRecord, LockError> {
        Self::block_on(async {
            // Check for existing lock on this path.
            let existing: Option<(String,)> =
                sqlx::query_as("SELECT id FROM lfs_locks WHERE repo_id = ? AND path = ?")
                    .bind(repo)
                    .bind(path)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(|e| LockError::Internal(format!("check conflict: {e}")))?;

            if let Some((id,)) = existing {
                return Err(LockError::Conflict(id));
            }

            let id = uuid::Uuid::new_v4().to_string();
            let locked_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            sqlx::query(
                "INSERT INTO lfs_locks (id, repo_id, path, pubkey, locked_at) VALUES (?, ?, ?, ?, ?)",
            )
            .bind(&id)
            .bind(repo)
            .bind(path)
            .bind(pubkey)
            .bind(locked_at as i64)
            .execute(&self.pool)
            .await
            .map_err(|e| LockError::Internal(format!("insert lock: {e}")))?;

            Ok(LockRecord {
                id,
                repo_id: repo.to_string(),
                path: path.to_string(),
                pubkey: pubkey.to_string(),
                locked_at,
            })
        })
    }

    fn delete_lock(
        &mut self,
        repo: &str,
        id: &str,
        force: bool,
        requester: &str,
    ) -> Result<LockRecord, LockError> {
        Self::block_on(async {
            let row: Option<(String, String, String, String, i64)> = sqlx::query_as(
                "SELECT id, repo_id, path, pubkey, locked_at FROM lfs_locks WHERE repo_id = ? AND id = ?",
            )
            .bind(repo)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| LockError::Internal(format!("find lock: {e}")))?;

            let (lid, repo_id, path, pubkey, locked_at) = row.ok_or(LockError::NotFound)?;

            if !force && pubkey != requester {
                return Err(LockError::Forbidden(
                    "only the lock owner or an admin can unlock".to_string(),
                ));
            }

            sqlx::query("DELETE FROM lfs_locks WHERE repo_id = ? AND id = ?")
                .bind(repo)
                .bind(id)
                .execute(&self.pool)
                .await
                .map_err(|e| LockError::Internal(format!("delete lock: {e}")))?;

            Ok(LockRecord {
                id: lid,
                repo_id,
                path,
                pubkey,
                locked_at: locked_at as u64,
            })
        })
    }

    fn list_locks(
        &self,
        repo: &str,
        filters: &LockFilters,
    ) -> Result<(Vec<LockRecord>, Option<String>), LockError> {
        Self::block_on(async {
            let limit = filters.limit.unwrap_or(100) as i64;
            let offset = filters
                .cursor
                .as_ref()
                .and_then(|c| c.parse::<i64>().ok())
                .unwrap_or(0);

            // Build query dynamically based on filters.
            let mut sql = String::from(
                "SELECT id, repo_id, path, pubkey, locked_at FROM lfs_locks WHERE repo_id = ?",
            );
            if filters.path.is_some() {
                sql.push_str(" AND path = ?");
            }
            if filters.id.is_some() {
                sql.push_str(" AND id = ?");
            }
            sql.push_str(" ORDER BY locked_at ASC LIMIT ? OFFSET ?");

            let mut query =
                sqlx::query_as::<_, (String, String, String, String, i64)>(&sql).bind(repo);
            if let Some(ref p) = filters.path {
                query = query.bind(p);
            }
            if let Some(ref id) = filters.id {
                query = query.bind(id);
            }
            query = query.bind(limit + 1).bind(offset);

            let rows: Vec<(String, String, String, String, i64)> = query
                .fetch_all(&self.pool)
                .await
                .map_err(|e| LockError::Internal(format!("list locks: {e}")))?;

            let has_more = rows.len() as i64 > limit;
            let take = std::cmp::min(rows.len(), limit as usize);

            let locks: Vec<LockRecord> = rows[..take]
                .iter()
                .map(|r| LockRecord {
                    id: r.0.clone(),
                    repo_id: r.1.clone(),
                    path: r.2.clone(),
                    pubkey: r.3.clone(),
                    locked_at: r.4 as u64,
                })
                .collect();

            let next_cursor = if has_more {
                Some((offset + limit).to_string())
            } else {
                None
            };

            Ok((locks, next_cursor))
        })
    }

    fn get_lock(&self, repo: &str, id: &str) -> Result<LockRecord, LockError> {
        Self::block_on(async {
            let row: (String, String, String, String, i64) = sqlx::query_as(
                "SELECT id, repo_id, path, pubkey, locked_at FROM lfs_locks WHERE repo_id = ? AND id = ?",
            )
            .bind(repo)
            .bind(id)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| match e {
                sqlx::Error::RowNotFound => LockError::NotFound,
                _ => LockError::Internal(format!("get lock: {e}")),
            })?;

            Ok(LockRecord {
                id: row.0,
                repo_id: row.1,
                path: row.2,
                pubkey: row.3,
                locked_at: row.4 as u64,
            })
        })
    }

    fn get_lock_by_path(&self, repo: &str, path: &str) -> Result<LockRecord, LockError> {
        Self::block_on(async {
            let row: (String, String, String, String, i64) = sqlx::query_as(
                "SELECT id, repo_id, path, pubkey, locked_at FROM lfs_locks WHERE repo_id = ? AND path = ?",
            )
            .bind(repo)
            .bind(path)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| match e {
                sqlx::Error::RowNotFound => LockError::NotFound,
                _ => LockError::Internal(format!("get lock by path: {e}")),
            })?;

            Ok(LockRecord {
                id: row.0,
                repo_id: row.1,
                path: row.2,
                pubkey: row.3,
                locked_at: row.4 as u64,
            })
        })
    }
}
