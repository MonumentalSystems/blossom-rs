//! SQLite metadata backend via SQLx.
//!
//! Behind the `db-sqlite` feature flag. Requires a SQLite database file path.

use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};

use super::{BlobDatabase, DbError, FileStats, UploadRecord, UserRecord};
use crate::lfs::{
    LfsFileVersion, LfsStorageStats, LfsStorageType, LfsVersionDatabase, LfsVersionError,
};

type VersionRow = (
    String,
    String,
    i64,
    String,
    Option<String>,
    String,
    Option<String>,
    i64,
    i64,
    i64,
);

/// SQLite-backed metadata database.
///
/// Uses SQLx for async queries, but implements `BlobDatabase` synchronously
/// by blocking on the current tokio runtime handle (same pattern as S3Backend).
pub struct SqliteDatabase {
    pool: SqlitePool,
}

impl SqliteDatabase {
    /// Connect to a SQLite database and run migrations.
    ///
    /// `url` is a SQLite connection string, e.g., `sqlite:blobs.db?mode=rwc`.
    pub async fn new(url: &str) -> Result<Self, DbError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(url)
            .await
            .map_err(|e| DbError::Internal(format!("sqlite connect: {e}")))?;

        let db = Self { pool };
        db.run_migrations().await?;
        Ok(db)
    }

    /// Create a second instance sharing the same connection pool.
    ///
    /// Useful for passing the same database to both `BlobDatabase` and
    /// `LfsVersionDatabase` builder methods.
    pub fn share(&self) -> Self {
        Self {
            pool: self.pool.clone(),
        }
    }

    /// Current schema version. Bump this when adding new migrations.
    const SCHEMA_VERSION: i64 = 5;

    async fn run_migrations(&self) -> Result<(), DbError> {
        // Create version tracking table.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER NOT NULL
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| DbError::Internal(format!("migration: {e}")))?;

        let current: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(version), 0) FROM schema_version")
                .fetch_one(&self.pool)
                .await
                .unwrap_or(0);

        if current < 1 {
            self.migrate_v1().await?;
        }
        if current < 2 {
            self.migrate_v2().await?;
        }
        if current < 3 {
            self.migrate_v3().await?;
        }

        if current < 4 {
            self.migrate_v4().await?;
        }
        if current < 5 {
            self.migrate_v5().await?;
        }

        if current < Self::SCHEMA_VERSION {
            sqlx::query("DELETE FROM schema_version")
                .execute(&self.pool)
                .await
                .map_err(|e| DbError::Internal(format!("migration: {e}")))?;
            sqlx::query("INSERT INTO schema_version (version) VALUES (?)")
                .bind(Self::SCHEMA_VERSION)
                .execute(&self.pool)
                .await
                .map_err(|e| DbError::Internal(format!("migration: {e}")))?;

            tracing::info!(
                db.schema_version = Self::SCHEMA_VERSION,
                db.previous_version = current,
                "database migrated"
            );
        }

        Ok(())
    }

    /// V1: Initial schema — uploads, users, file_stats.
    async fn migrate_v1(&self) -> Result<(), DbError> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS uploads (
                sha256 TEXT PRIMARY KEY,
                size INTEGER NOT NULL,
                mime_type TEXT NOT NULL,
                pubkey TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| DbError::Internal(format!("v1 migration: {e}")))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS users (
                pubkey TEXT PRIMARY KEY,
                quota_bytes INTEGER,
                used_bytes INTEGER NOT NULL DEFAULT 0
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| DbError::Internal(format!("v1 migration: {e}")))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS file_stats (
                sha256 TEXT PRIMARY KEY,
                egress_bytes INTEGER NOT NULL DEFAULT 0,
                last_accessed INTEGER NOT NULL DEFAULT 0
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| DbError::Internal(format!("v1 migration: {e}")))?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_uploads_pubkey ON uploads(pubkey)")
            .execute(&self.pool)
            .await
            .map_err(|e| DbError::Internal(format!("v1 migration: {e}")))?;

        Ok(())
    }

    /// V2: Add perceptual hash column for dedup.
    async fn migrate_v2(&self) -> Result<(), DbError> {
        // SQLite ALTER TABLE ADD COLUMN is idempotent-safe with IF NOT EXISTS check.
        let has_phash: bool = sqlx::query_scalar(
            "SELECT COUNT(*) > 0 FROM pragma_table_info('uploads') WHERE name = 'phash'",
        )
        .fetch_one(&self.pool)
        .await
        .unwrap_or(false);

        if !has_phash {
            sqlx::query("ALTER TABLE uploads ADD COLUMN phash INTEGER")
                .execute(&self.pool)
                .await
                .map_err(|e| DbError::Internal(format!("v2 migration: {e}")))?;

            sqlx::query("CREATE INDEX IF NOT EXISTS idx_uploads_phash ON uploads(phash)")
                .execute(&self.pool)
                .await
                .map_err(|e| DbError::Internal(format!("v2 migration: {e}")))?;
        }

        Ok(())
    }

    /// V3: Add role column to users table.
    async fn migrate_v3(&self) -> Result<(), DbError> {
        let has_role: bool = sqlx::query_scalar(
            "SELECT COUNT(*) > 0 FROM pragma_table_info('users') WHERE name = 'role'",
        )
        .fetch_one(&self.pool)
        .await
        .unwrap_or(false);

        if !has_role {
            sqlx::query("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'member'")
                .execute(&self.pool)
                .await
                .map_err(|e| DbError::Internal(format!("v3 migration: {e}")))?;
        }

        Ok(())
    }

    /// V4: LFS file versions table (BUD-20).
    async fn migrate_v4(&self) -> Result<(), DbError> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS lfs_file_versions (
                repo_id       TEXT NOT NULL,
                path          TEXT NOT NULL,
                version       INTEGER NOT NULL,
                sha256        TEXT NOT NULL,
                base_sha256   TEXT,
                storage       TEXT NOT NULL DEFAULT 'full',
                delta_algo    TEXT,
                original_size INTEGER NOT NULL,
                stored_size   INTEGER NOT NULL,
                created_at    INTEGER NOT NULL,
                PRIMARY KEY (repo_id, path, version)
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| DbError::Internal(format!("v4 migration: {e}")))?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_lfs_v_sha ON lfs_file_versions(sha256)")
            .execute(&self.pool)
            .await
            .map_err(|e| DbError::Internal(format!("v4 migration: {e}")))?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_lfs_v_base ON lfs_file_versions(base_sha256)")
            .execute(&self.pool)
            .await
            .map_err(|e| DbError::Internal(format!("v4 migration: {e}")))?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_lfs_v_repo_path ON lfs_file_versions(repo_id, path)",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| DbError::Internal(format!("v4 migration: {e}")))?;

        Ok(())
    }

    /// V5: Track an independent ownership reference for each uploader.
    async fn migrate_v5(&self) -> Result<(), DbError> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS upload_owners (
                sha256 TEXT NOT NULL,
                pubkey TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (sha256, pubkey),
                FOREIGN KEY (sha256) REFERENCES uploads(sha256) ON DELETE CASCADE
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| DbError::Internal(format!("v5 migration: {e}")))?;

        sqlx::query(
            "INSERT OR IGNORE INTO upload_owners (sha256, pubkey, created_at)
             SELECT sha256, pubkey, created_at FROM uploads",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| DbError::Internal(format!("v5 migration backfill: {e}")))?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_upload_owners_pubkey ON upload_owners(pubkey)")
            .execute(&self.pool)
            .await
            .map_err(|e| DbError::Internal(format!("v5 migration: {e}")))?;
        Ok(())
    }

    fn block_on<F: std::future::Future<Output = T>, T>(future: F) -> T {
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(future))
    }
}

impl BlobDatabase for SqliteDatabase {
    fn record_upload(&mut self, record: &UploadRecord) -> Result<(), DbError> {
        Self::block_on(async {
            let mut tx = self
                .pool
                .begin()
                .await
                .map_err(|e| DbError::Internal(format!("begin upload transaction: {e}")))?;
            sqlx::query(
                "INSERT OR IGNORE INTO uploads (sha256, size, mime_type, pubkey, created_at)
                 VALUES (?, ?, ?, ?, ?)",
            )
            .bind(&record.sha256)
            .bind(record.size as i64)
            .bind(&record.mime_type)
            .bind(&record.pubkey)
            .bind(record.created_at as i64)
            .execute(&mut *tx)
            .await
            .map_err(|e| DbError::Internal(format!("insert upload: {e}")))?;

            let owner = sqlx::query(
                "INSERT OR IGNORE INTO upload_owners (sha256, pubkey, created_at)
                 VALUES (?, ?, ?)",
            )
            .bind(&record.sha256)
            .bind(&record.pubkey)
            .bind(record.created_at as i64)
            .execute(&mut *tx)
            .await
            .map_err(|e| DbError::Internal(format!("insert upload owner: {e}")))?;

            if owner.rows_affected() == 0 {
                tx.commit()
                    .await
                    .map_err(|e| DbError::Internal(format!("commit upload: {e}")))?;
                return Ok(());
            }

            // Upsert user and update used_bytes.
            sqlx::query(
                "INSERT INTO users (pubkey, used_bytes) VALUES (?, ?)
                 ON CONFLICT(pubkey) DO UPDATE SET used_bytes = used_bytes + ?",
            )
            .bind(&record.pubkey)
            .bind(record.size as i64)
            .bind(record.size as i64)
            .execute(&mut *tx)
            .await
            .map_err(|e| DbError::Internal(format!("upsert user: {e}")))?;

            tx.commit()
                .await
                .map_err(|e| DbError::Internal(format!("commit upload: {e}")))?;

            Ok(())
        })
    }

    fn get_upload(&self, sha256: &str) -> Result<UploadRecord, DbError> {
        Self::block_on(async {
            let row: (String, i64, String, String, i64) = sqlx::query_as(
                "SELECT sha256, size, mime_type, pubkey, created_at FROM uploads WHERE sha256 = ?",
            )
            .bind(sha256)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| match e {
                sqlx::Error::RowNotFound => DbError::NotFound,
                _ => DbError::Internal(format!("get upload: {e}")),
            })?;

            Ok(UploadRecord {
                sha256: row.0,
                size: row.1 as u64,
                mime_type: row.2,
                pubkey: row.3,
                created_at: row.4 as u64,
                phash: None,
            })
        })
    }

    fn list_uploads_by_pubkey(&self, pubkey: &str) -> Result<Vec<UploadRecord>, DbError> {
        Self::block_on(async {
            let rows: Vec<(String, i64, String, String, i64)> = sqlx::query_as(
                "SELECT u.sha256, u.size, u.mime_type, o.pubkey, o.created_at
                 FROM upload_owners o JOIN uploads u ON u.sha256 = o.sha256
                 WHERE o.pubkey = ? ORDER BY o.created_at DESC",
            )
            .bind(pubkey)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| DbError::Internal(format!("list uploads: {e}")))?;

            Ok(rows
                .into_iter()
                .map(|r| UploadRecord {
                    sha256: r.0,
                    size: r.1 as u64,
                    mime_type: r.2,
                    pubkey: r.3,
                    created_at: r.4 as u64,
                    phash: None,
                })
                .collect())
        })
    }

    fn delete_upload(&mut self, sha256: &str) -> Result<bool, DbError> {
        Self::block_on(async {
            let mut tx = self
                .pool
                .begin()
                .await
                .map_err(|e| DbError::Internal(format!("begin delete transaction: {e}")))?;
            let owners: Vec<(String, i64)> =
                sqlx::query_as("SELECT o.pubkey, u.size FROM upload_owners o JOIN uploads u ON u.sha256 = o.sha256 WHERE o.sha256 = ?")
                    .bind(sha256)
                    .fetch_all(&mut *tx)
                    .await
                    .map_err(|e| DbError::Internal(format!("find upload: {e}")))?;

            let result = sqlx::query("DELETE FROM uploads WHERE sha256 = ?")
                .bind(sha256)
                .execute(&mut *tx)
                .await
                .map_err(|e| DbError::Internal(format!("delete upload: {e}")))?;

            for (pubkey, size) in owners {
                sqlx::query(
                    "UPDATE users SET used_bytes = MAX(0, used_bytes - ?) WHERE pubkey = ?",
                )
                .bind(size)
                .bind(&pubkey)
                .execute(&mut *tx)
                .await
                .map_err(|e| DbError::Internal(format!("update used_bytes: {e}")))?;
            }

            sqlx::query("DELETE FROM file_stats WHERE sha256 = ?")
                .bind(sha256)
                .execute(&mut *tx)
                .await
                .map_err(|e| DbError::Internal(format!("delete file stats: {e}")))?;

            tx.commit()
                .await
                .map_err(|e| DbError::Internal(format!("commit delete: {e}")))?;

            Ok(result.rows_affected() > 0)
        })
    }

    fn is_upload_owner(&self, sha256: &str, pubkey: &str) -> Result<bool, DbError> {
        Self::block_on(async {
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM upload_owners WHERE sha256 = ? AND pubkey = ?)",
            )
            .bind(sha256)
            .bind(pubkey)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| DbError::Internal(format!("check upload owner: {e}")))
        })
    }

    fn upload_owner_count(&self, sha256: &str) -> Result<usize, DbError> {
        Self::block_on(async {
            let count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM upload_owners WHERE sha256 = ?")
                    .bind(sha256)
                    .fetch_one(&self.pool)
                    .await
                    .map_err(|e| DbError::Internal(format!("count upload owners: {e}")))?;
            Ok(count as usize)
        })
    }

    fn delete_upload_owner(&mut self, sha256: &str, pubkey: &str) -> Result<bool, DbError> {
        Self::block_on(async {
            let mut tx =
                self.pool.begin().await.map_err(|e| {
                    DbError::Internal(format!("begin owner delete transaction: {e}"))
                })?;
            let size: Option<i64> = sqlx::query_scalar(
                "SELECT u.size FROM upload_owners o JOIN uploads u ON u.sha256 = o.sha256
                 WHERE o.sha256 = ? AND o.pubkey = ?",
            )
            .bind(sha256)
            .bind(pubkey)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| DbError::Internal(format!("find upload owner: {e}")))?;
            let Some(size) = size else {
                tx.commit()
                    .await
                    .map_err(|e| DbError::Internal(format!("commit owner delete: {e}")))?;
                return Ok(false);
            };

            let result = sqlx::query("DELETE FROM upload_owners WHERE sha256 = ? AND pubkey = ?")
                .bind(sha256)
                .bind(pubkey)
                .execute(&mut *tx)
                .await
                .map_err(|e| DbError::Internal(format!("delete upload owner: {e}")))?;
            if result.rows_affected() > 0 {
                sqlx::query(
                    "UPDATE users SET used_bytes = MAX(0, used_bytes - ?) WHERE pubkey = ?",
                )
                .bind(size)
                .bind(pubkey)
                .execute(&mut *tx)
                .await
                .map_err(|e| DbError::Internal(format!("update used_bytes: {e}")))?;
            }
            tx.commit()
                .await
                .map_err(|e| DbError::Internal(format!("commit owner delete: {e}")))?;
            Ok(result.rows_affected() > 0)
        })
    }

    fn get_or_create_user(&mut self, pubkey: &str) -> Result<UserRecord, DbError> {
        Self::block_on(async {
            sqlx::query(
                "INSERT OR IGNORE INTO users (pubkey, used_bytes, role) VALUES (?, 0, 'member')",
            )
            .bind(pubkey)
            .execute(&self.pool)
            .await
            .map_err(|e| DbError::Internal(format!("create user: {e}")))?;

            let row: (String, Option<i64>, i64, String) = sqlx::query_as(
                "SELECT pubkey, quota_bytes, used_bytes, role FROM users WHERE pubkey = ?",
            )
            .bind(pubkey)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| DbError::Internal(format!("get user: {e}")))?;

            Ok(UserRecord {
                pubkey: row.0,
                quota_bytes: row.1.map(|v| v as u64),
                used_bytes: row.2 as u64,
                role: row.3,
            })
        })
    }

    fn set_quota(&mut self, pubkey: &str, quota_bytes: Option<u64>) -> Result<(), DbError> {
        Self::block_on(async {
            let quota_bytes = quota_bytes
                .map(i64::try_from)
                .transpose()
                .map_err(|_| DbError::Internal("quota exceeds database range".into()))?;
            sqlx::query(
                "INSERT INTO users (pubkey, quota_bytes, used_bytes) VALUES (?, ?, 0)
                 ON CONFLICT(pubkey) DO UPDATE SET quota_bytes = ?",
            )
            .bind(pubkey)
            .bind(quota_bytes)
            .bind(quota_bytes)
            .execute(&self.pool)
            .await
            .map_err(|e| DbError::Internal(format!("set quota: {e}")))?;
            Ok(())
        })
    }

    fn check_quota(&self, pubkey: &str, additional_bytes: u64) -> Result<(), DbError> {
        Self::block_on(async {
            let row: Option<(Option<i64>, i64)> =
                sqlx::query_as("SELECT quota_bytes, used_bytes FROM users WHERE pubkey = ?")
                    .bind(pubkey)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(|e| DbError::Internal(format!("check quota: {e}")))?;

            if let Some((Some(limit), used)) = row {
                let limit = limit as u64;
                let used = used as u64;
                if used + additional_bytes > limit {
                    return Err(DbError::QuotaExceeded {
                        used,
                        requested: additional_bytes,
                        limit,
                    });
                }
            }
            Ok(())
        })
    }

    fn update_used_bytes(&mut self, pubkey: &str, used_bytes: u64) -> Result<(), DbError> {
        Self::block_on(async {
            sqlx::query("UPDATE users SET used_bytes = ? WHERE pubkey = ?")
                .bind(used_bytes as i64)
                .bind(pubkey)
                .execute(&self.pool)
                .await
                .map_err(|e| DbError::Internal(format!("update used_bytes: {e}")))?;
            Ok(())
        })
    }

    fn record_access(&mut self, sha256: &str, bytes_served: u64) -> Result<(), DbError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self::block_on(async {
            sqlx::query(
                "INSERT INTO file_stats (sha256, egress_bytes, last_accessed) VALUES (?, ?, ?)
                 ON CONFLICT(sha256) DO UPDATE SET
                     egress_bytes = egress_bytes + ?,
                     last_accessed = ?",
            )
            .bind(sha256)
            .bind(bytes_served as i64)
            .bind(now as i64)
            .bind(bytes_served as i64)
            .bind(now as i64)
            .execute(&self.pool)
            .await
            .map_err(|e| DbError::Internal(format!("record access: {e}")))?;
            Ok(())
        })
    }

    fn get_stats(&self, sha256: &str) -> Result<FileStats, DbError> {
        Self::block_on(async {
            let row: (String, i64, i64) = sqlx::query_as(
                "SELECT sha256, egress_bytes, last_accessed FROM file_stats WHERE sha256 = ?",
            )
            .bind(sha256)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| match e {
                sqlx::Error::RowNotFound => DbError::NotFound,
                _ => DbError::Internal(format!("get stats: {e}")),
            })?;

            Ok(FileStats {
                sha256: row.0,
                egress_bytes: row.1 as u64,
                last_accessed: row.2 as u64,
            })
        })
    }

    fn upload_count(&self) -> usize {
        Self::block_on(async {
            let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM uploads")
                .fetch_one(&self.pool)
                .await
                .unwrap_or((0,));
            row.0 as usize
        })
    }

    fn user_count(&self) -> usize {
        Self::block_on(async {
            let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
                .fetch_one(&self.pool)
                .await
                .unwrap_or((0,));
            row.0 as usize
        })
    }

    fn set_role(&mut self, pubkey: &str, role: &str) -> Result<(), DbError> {
        Self::block_on(async {
            sqlx::query(
                "INSERT INTO users (pubkey, used_bytes, role) VALUES (?, 0, ?)
                 ON CONFLICT(pubkey) DO UPDATE SET role = ?",
            )
            .bind(pubkey)
            .bind(role)
            .bind(role)
            .execute(&self.pool)
            .await
            .map_err(|e| DbError::Internal(format!("set role: {e}")))?;
            Ok(())
        })
    }

    fn get_role(&self, pubkey: &str) -> String {
        Self::block_on(async {
            let row: Option<(String,)> = sqlx::query_as("SELECT role FROM users WHERE pubkey = ?")
                .bind(pubkey)
                .fetch_optional(&self.pool)
                .await
                .unwrap_or(None);
            row.map(|r| r.0).unwrap_or_else(|| "member".to_string())
        })
    }

    fn list_users_by_role(&self, role: &str) -> Result<Vec<UserRecord>, DbError> {
        Self::block_on(async {
            let rows: Vec<(String, Option<i64>, i64, String)> = sqlx::query_as(
                "SELECT pubkey, quota_bytes, used_bytes, role FROM users WHERE role = ?",
            )
            .bind(role)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| DbError::Internal(format!("list by role: {e}")))?;

            Ok(rows
                .into_iter()
                .map(|r| UserRecord {
                    pubkey: r.0,
                    quota_bytes: r.1.map(|v| v as u64),
                    used_bytes: r.2 as u64,
                    role: r.3,
                })
                .collect())
        })
    }
}

impl LfsVersionDatabase for SqliteDatabase {
    fn record_version(&mut self, record: &LfsFileVersion) -> Result<i64, LfsVersionError> {
        Self::block_on(async {
            sqlx::query(
                "INSERT INTO lfs_file_versions (repo_id, path, version, sha256, base_sha256, storage, delta_algo, original_size, stored_size, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&record.repo_id)
            .bind(&record.path)
            .bind(record.version)
            .bind(&record.sha256)
            .bind(&record.base_sha256)
            .bind(record.storage.to_string())
            .bind(&record.delta_algo)
            .bind(record.original_size)
            .bind(record.stored_size)
            .bind(record.created_at)
            .execute(&self.pool)
            .await
            .map_err(|e| LfsVersionError::Internal(format!("insert version: {e}")))?;
            Ok(record.version)
        })
    }

    fn get_by_sha256(&self, sha256: &str) -> Result<Option<LfsFileVersion>, LfsVersionError> {
        Self::block_on(async {
            let row: Option<VersionRow> =
                sqlx::query_as(
                    "SELECT repo_id, path, version, sha256, base_sha256, storage, delta_algo, original_size, stored_size, created_at
                     FROM lfs_file_versions WHERE sha256 = ?",
                )
                .bind(sha256)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| LfsVersionError::Internal(format!("get by sha256: {e}")))?;

            Ok(row.map(row_to_version))
        })
    }

    fn get_latest_version(
        &self,
        repo_id: &str,
        path: &str,
    ) -> Result<Option<LfsFileVersion>, LfsVersionError> {
        Self::block_on(async {
            let row: Option<VersionRow> =
                sqlx::query_as(
                    "SELECT repo_id, path, version, sha256, base_sha256, storage, delta_algo, original_size, stored_size, created_at
                     FROM lfs_file_versions WHERE repo_id = ? AND path = ? ORDER BY version DESC LIMIT 1",
                )
                .bind(repo_id)
                .bind(path)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| LfsVersionError::Internal(format!("get latest: {e}")))?;

            Ok(row.map(row_to_version))
        })
    }

    fn delete_by_sha256(&mut self, sha256: &str) -> Result<(), LfsVersionError> {
        Self::block_on(async {
            sqlx::query("DELETE FROM lfs_file_versions WHERE sha256 = ?")
                .bind(sha256)
                .execute(&self.pool)
                .await
                .map_err(|e| LfsVersionError::Internal(format!("delete version: {e}")))?;
            Ok(())
        })
    }

    fn get_deltas_for_base(
        &self,
        base_sha256: &str,
    ) -> Result<Vec<LfsFileVersion>, LfsVersionError> {
        Self::block_on(async {
            let rows: Vec<VersionRow> =
                sqlx::query_as(
                    "SELECT repo_id, path, version, sha256, base_sha256, storage, delta_algo, original_size, stored_size, created_at
                     FROM lfs_file_versions WHERE base_sha256 = ? AND storage = 'delta'",
                )
                .bind(base_sha256)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| LfsVersionError::Internal(format!("get deltas: {e}")))?;

            Ok(rows.into_iter().map(row_to_version).collect())
        })
    }

    fn update_version(
        &mut self,
        sha256: &str,
        storage: LfsStorageType,
        base_sha256: Option<&str>,
        stored_size: i64,
    ) -> Result<(), LfsVersionError> {
        Self::block_on(async {
            sqlx::query(
                "UPDATE lfs_file_versions SET storage = ?, base_sha256 = ?, stored_size = ? WHERE sha256 = ?",
            )
            .bind(storage.to_string())
            .bind(base_sha256)
            .bind(stored_size)
            .bind(sha256)
            .execute(&self.pool)
            .await
            .map_err(|e| LfsVersionError::Internal(format!("update version: {e}")))?;
            Ok(())
        })
    }

    fn lfs_stats(&self) -> Result<LfsStorageStats, LfsVersionError> {
        Self::block_on(async {
            let total: (i64, i64, i64) = sqlx::query_as(
                "SELECT COUNT(*), COALESCE(SUM(original_size), 0), COALESCE(SUM(stored_size), 0) FROM lfs_file_versions",
            )
            .fetch_one(&self.pool)
            .await
            .map_err(|e| LfsVersionError::Internal(format!("stats: {e}")))?;

            let by_type: Vec<(String, i64, i64, i64)> = sqlx::query_as(
                "SELECT storage, COUNT(*), COALESCE(SUM(original_size), 0), COALESCE(SUM(stored_size), 0)
                 FROM lfs_file_versions GROUP BY storage",
            )
            .fetch_all(&self.pool)
            .await
            .map_err(|e| LfsVersionError::Internal(format!("stats by type: {e}")))?;

            use std::collections::HashMap;
            let mut by_storage_type = HashMap::new();
            for (storage, count, orig, stored) in by_type {
                by_storage_type.insert(
                    storage,
                    crate::lfs::LfsStorageTypeStats {
                        count,
                        original_bytes: orig,
                        stored_bytes: stored,
                    },
                );
            }

            Ok(LfsStorageStats {
                total_versions: total.0,
                total_original_bytes: total.1,
                total_stored_bytes: total.2,
                by_storage_type,
            })
        })
    }
}

fn row_to_version(r: VersionRow) -> LfsFileVersion {
    LfsFileVersion {
        repo_id: r.0,
        path: r.1,
        version: r.2,
        sha256: r.3,
        base_sha256: r.4,
        storage: match r.5.as_str() {
            "compressed" => LfsStorageType::Compressed,
            "delta" => LfsStorageType::Delta,
            _ => LfsStorageType::Raw,
        },
        delta_algo: r.6,
        original_size: r.7,
        stored_size: r.8,
        created_at: r.9,
    }
}
