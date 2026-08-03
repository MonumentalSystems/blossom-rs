//! PostgreSQL metadata backend via SQLx.
//!
//! Behind the `db-postgres` feature flag.

use sqlx::postgres::{PgPool, PgPoolOptions};

use super::{BlobDatabase, DbError, FileStats, UploadRecord, UserRecord};

/// PostgreSQL-backed metadata database.
pub struct PostgresDatabase {
    pool: PgPool,
}

impl PostgresDatabase {
    /// Connect to a PostgreSQL database and run migrations.
    ///
    /// `url` is a Postgres connection string, e.g., `postgres://user:pass@localhost/blobs`.
    pub async fn new(url: &str) -> Result<Self, DbError> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(url)
            .await
            .map_err(|e| DbError::Internal(format!("postgres connect: {e}")))?;

        let db = Self { pool };
        db.run_migrations().await?;
        Ok(db)
    }

    const SCHEMA_VERSION: i64 = 4;

    async fn run_migrations(&self) -> Result<(), DbError> {
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

        if current < Self::SCHEMA_VERSION {
            sqlx::query("DELETE FROM schema_version")
                .execute(&self.pool)
                .await
                .map_err(|e| DbError::Internal(format!("migration: {e}")))?;
            sqlx::query("INSERT INTO schema_version (version) VALUES ($1)")
                .bind(Self::SCHEMA_VERSION)
                .execute(&self.pool)
                .await
                .map_err(|e| DbError::Internal(format!("migration: {e}")))?;

            tracing::info!(
                db.schema_version = Self::SCHEMA_VERSION,
                db.previous_version = current,
                "postgres database migrated"
            );
        }

        Ok(())
    }

    async fn migrate_v1(&self) -> Result<(), DbError> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS uploads (
                sha256 TEXT PRIMARY KEY,
                size BIGINT NOT NULL,
                mime_type TEXT NOT NULL,
                pubkey TEXT NOT NULL,
                created_at BIGINT NOT NULL
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| DbError::Internal(format!("v1 migration: {e}")))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS users (
                pubkey TEXT PRIMARY KEY,
                quota_bytes BIGINT,
                used_bytes BIGINT NOT NULL DEFAULT 0
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| DbError::Internal(format!("v1 migration: {e}")))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS file_stats (
                sha256 TEXT PRIMARY KEY,
                egress_bytes BIGINT NOT NULL DEFAULT 0,
                last_accessed BIGINT NOT NULL DEFAULT 0
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

    async fn migrate_v2(&self) -> Result<(), DbError> {
        // Add phash column if not present.
        let has_phash: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'uploads' AND column_name = 'phash'
            )",
        )
        .fetch_one(&self.pool)
        .await
        .unwrap_or(false);

        if !has_phash {
            sqlx::query("ALTER TABLE uploads ADD COLUMN phash BIGINT")
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
            "SELECT COUNT(*) > 0 FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'role'",
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

    /// V4: Track an independent ownership reference for each uploader.
    async fn migrate_v4(&self) -> Result<(), DbError> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS upload_owners (
                sha256 TEXT NOT NULL REFERENCES uploads(sha256) ON DELETE CASCADE,
                pubkey TEXT NOT NULL,
                created_at BIGINT NOT NULL,
                PRIMARY KEY (sha256, pubkey)
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| DbError::Internal(format!("v4 migration: {e}")))?;
        sqlx::query(
            "INSERT INTO upload_owners (sha256, pubkey, created_at)
             SELECT sha256, pubkey, created_at FROM uploads ON CONFLICT DO NOTHING",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| DbError::Internal(format!("v4 migration backfill: {e}")))?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_upload_owners_pubkey ON upload_owners(pubkey)")
            .execute(&self.pool)
            .await
            .map_err(|e| DbError::Internal(format!("v4 migration: {e}")))?;
        Ok(())
    }

    fn block_on<F: std::future::Future<Output = T>, T>(future: F) -> T {
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(future))
    }
}

impl BlobDatabase for PostgresDatabase {
    fn record_upload(&mut self, record: &UploadRecord) -> Result<(), DbError> {
        Self::block_on(async {
            let mut tx = self
                .pool
                .begin()
                .await
                .map_err(|e| DbError::Internal(format!("begin upload transaction: {e}")))?;
            sqlx::query(
                "INSERT INTO uploads (sha256, size, mime_type, pubkey, created_at)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (sha256) DO NOTHING",
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
                "INSERT INTO upload_owners (sha256, pubkey, created_at) VALUES ($1, $2, $3)
                 ON CONFLICT DO NOTHING",
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

            sqlx::query(
                "INSERT INTO users (pubkey, used_bytes) VALUES ($1, $2)
                 ON CONFLICT (pubkey) DO UPDATE SET used_bytes = users.used_bytes + $2",
            )
            .bind(&record.pubkey)
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
                "SELECT sha256, size, mime_type, pubkey, created_at FROM uploads WHERE sha256 = $1",
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
                 WHERE o.pubkey = $1 ORDER BY o.created_at DESC",
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
                sqlx::query_as("SELECT o.pubkey, u.size FROM upload_owners o JOIN uploads u ON u.sha256 = o.sha256 WHERE o.sha256 = $1")
                    .bind(sha256)
                    .fetch_all(&mut *tx)
                    .await
                    .map_err(|e| DbError::Internal(format!("find upload: {e}")))?;

            let result = sqlx::query("DELETE FROM uploads WHERE sha256 = $1")
                .bind(sha256)
                .execute(&mut *tx)
                .await
                .map_err(|e| DbError::Internal(format!("delete upload: {e}")))?;

            for (pubkey, size) in owners {
                sqlx::query(
                    "UPDATE users SET used_bytes = GREATEST(0, used_bytes - $1) WHERE pubkey = $2",
                )
                .bind(size)
                .bind(&pubkey)
                .execute(&mut *tx)
                .await
                .map_err(|e| DbError::Internal(format!("update used_bytes: {e}")))?;
            }

            sqlx::query("DELETE FROM file_stats WHERE sha256 = $1")
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
                "SELECT EXISTS(SELECT 1 FROM upload_owners WHERE sha256 = $1 AND pubkey = $2)",
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
                sqlx::query_scalar("SELECT COUNT(*) FROM upload_owners WHERE sha256 = $1")
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
                 WHERE o.sha256 = $1 AND o.pubkey = $2",
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

            let result = sqlx::query("DELETE FROM upload_owners WHERE sha256 = $1 AND pubkey = $2")
                .bind(sha256)
                .bind(pubkey)
                .execute(&mut *tx)
                .await
                .map_err(|e| DbError::Internal(format!("delete upload owner: {e}")))?;
            if result.rows_affected() > 0 {
                sqlx::query(
                    "UPDATE users SET used_bytes = GREATEST(0, used_bytes - $1) WHERE pubkey = $2",
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
                "INSERT INTO users (pubkey, used_bytes, role) VALUES ($1, 0, 'member')
                 ON CONFLICT (pubkey) DO NOTHING",
            )
            .bind(pubkey)
            .execute(&self.pool)
            .await
            .map_err(|e| DbError::Internal(format!("create user: {e}")))?;

            let row: (String, Option<i64>, i64, String) = sqlx::query_as(
                "SELECT pubkey, quota_bytes, used_bytes, role FROM users WHERE pubkey = $1",
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
                "INSERT INTO users (pubkey, quota_bytes, used_bytes) VALUES ($1, $2, 0)
                 ON CONFLICT (pubkey) DO UPDATE SET quota_bytes = $2",
            )
            .bind(pubkey)
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
                sqlx::query_as("SELECT quota_bytes, used_bytes FROM users WHERE pubkey = $1")
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
            sqlx::query("UPDATE users SET used_bytes = $1 WHERE pubkey = $2")
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
                "INSERT INTO file_stats (sha256, egress_bytes, last_accessed) VALUES ($1, $2, $3)
                 ON CONFLICT (sha256) DO UPDATE SET
                     egress_bytes = file_stats.egress_bytes + $2,
                     last_accessed = $3",
            )
            .bind(sha256)
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
                "SELECT sha256, egress_bytes, last_accessed FROM file_stats WHERE sha256 = $1",
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
                "INSERT INTO users (pubkey, used_bytes, role) VALUES ($1, 0, $2)
                 ON CONFLICT (pubkey) DO UPDATE SET role = $2",
            )
            .bind(pubkey)
            .bind(role)
            .execute(&self.pool)
            .await
            .map_err(|e| DbError::Internal(format!("set role: {e}")))?;
            Ok(())
        })
    }

    fn get_role(&self, pubkey: &str) -> String {
        Self::block_on(async {
            let row: Option<(String,)> = sqlx::query_as("SELECT role FROM users WHERE pubkey = $1")
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
                "SELECT pubkey, quota_bytes, used_bytes, role FROM users WHERE role = $1",
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
