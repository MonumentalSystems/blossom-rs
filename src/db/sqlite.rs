//! SQLite metadata backend via SQLx.
//!
//! Behind the `db-sqlite` feature flag. Requires a SQLite database file path.

use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};

use super::{BlobDatabase, DbError, FileStats, UploadRecord, UserRecord};

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

    /// Current schema version. Bump this when adding new migrations.
    const SCHEMA_VERSION: i64 = 3;

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

    fn block_on<F: std::future::Future<Output = T>, T>(future: F) -> T {
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(future))
    }
}

impl BlobDatabase for SqliteDatabase {
    fn record_upload(&mut self, record: &UploadRecord) -> Result<(), DbError> {
        Self::block_on(async {
            sqlx::query(
                "INSERT OR IGNORE INTO uploads (sha256, size, mime_type, pubkey, created_at)
                 VALUES (?, ?, ?, ?, ?)",
            )
            .bind(&record.sha256)
            .bind(record.size as i64)
            .bind(&record.mime_type)
            .bind(&record.pubkey)
            .bind(record.created_at as i64)
            .execute(&self.pool)
            .await
            .map_err(|e| DbError::Internal(format!("insert upload: {e}")))?;

            // Upsert user and update used_bytes.
            sqlx::query(
                "INSERT INTO users (pubkey, used_bytes) VALUES (?, ?)
                 ON CONFLICT(pubkey) DO UPDATE SET used_bytes = used_bytes + ?",
            )
            .bind(&record.pubkey)
            .bind(record.size as i64)
            .bind(record.size as i64)
            .execute(&self.pool)
            .await
            .map_err(|e| DbError::Internal(format!("upsert user: {e}")))?;

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
                "SELECT sha256, size, mime_type, pubkey, created_at
                 FROM uploads WHERE pubkey = ? ORDER BY created_at DESC",
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
            // Get the record first to update used_bytes.
            let record: Option<(String, i64)> =
                sqlx::query_as("SELECT pubkey, size FROM uploads WHERE sha256 = ?")
                    .bind(sha256)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(|e| DbError::Internal(format!("find upload: {e}")))?;

            let result = sqlx::query("DELETE FROM uploads WHERE sha256 = ?")
                .bind(sha256)
                .execute(&self.pool)
                .await
                .map_err(|e| DbError::Internal(format!("delete upload: {e}")))?;

            if let Some((pubkey, size)) = record {
                sqlx::query(
                    "UPDATE users SET used_bytes = MAX(0, used_bytes - ?) WHERE pubkey = ?",
                )
                .bind(size)
                .bind(&pubkey)
                .execute(&self.pool)
                .await
                .map_err(|e| DbError::Internal(format!("update used_bytes: {e}")))?;
            }

            let _ = sqlx::query("DELETE FROM file_stats WHERE sha256 = ?")
                .bind(sha256)
                .execute(&self.pool)
                .await;

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
            sqlx::query(
                "INSERT INTO users (pubkey, quota_bytes, used_bytes) VALUES (?, ?, 0)
                 ON CONFLICT(pubkey) DO UPDATE SET quota_bytes = ?",
            )
            .bind(pubkey)
            .bind(quota_bytes.map(|v| v as i64))
            .bind(quota_bytes.map(|v| v as i64))
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
