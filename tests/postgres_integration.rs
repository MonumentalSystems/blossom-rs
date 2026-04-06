//! PostgreSQL integration tests.
//!
//! Spins up a single Postgres Docker container, runs all tests sequentially,
//! then tears it down.
//!
//! SKIPPED unless `RUN_POSTGRES_TESTS=1` is set.
//!
//! Run with: `RUN_POSTGRES_TESTS=1 cargo test --features db-postgres --test postgres_integration -- --test-threads=1`

#![cfg(feature = "db-postgres")]

use blossom_rs::db::{BlobDatabase, DbError, PostgresDatabase, UploadRecord};

static PORT: u16 = 25432;

fn container_name() -> String {
    "blossom_pg_integration_test".to_string()
}

fn start_postgres() -> Option<String> {
    if std::env::var("RUN_POSTGRES_TESTS").unwrap_or_default() != "1" {
        return None;
    }

    let name = container_name();

    // Remove any stale container.
    let _ = std::process::Command::new("docker")
        .args(["rm", "-f", &name])
        .output();

    let status = std::process::Command::new("docker")
        .args([
            "run",
            "-d",
            "--name",
            &name,
            "-e",
            "POSTGRES_USER=blossom",
            "-e",
            "POSTGRES_PASSWORD=blossom",
            "-e",
            "POSTGRES_DB=blossom_test",
            "-p",
            &format!("{}:5432", PORT),
            "postgres:16-alpine",
        ])
        .output()
        .ok()?;

    if !status.status.success() {
        eprintln!(
            "Failed to start Postgres: {}",
            String::from_utf8_lossy(&status.stderr)
        );
        return None;
    }

    // Wait for ready.
    for _ in 0..30 {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let check = std::process::Command::new("docker")
            .args(["exec", &name, "pg_isready", "-U", "blossom"])
            .output()
            .ok();
        if let Some(out) = check {
            if out.status.success() {
                // Extra settle time for Postgres to fully accept connections.
                std::thread::sleep(std::time::Duration::from_secs(1));
                return Some(format!(
                    "postgres://blossom:blossom@localhost:{}/blossom_test",
                    PORT
                ));
            }
        }
    }

    let _ = std::process::Command::new("docker")
        .args(["rm", "-f", &name])
        .output();
    None
}

fn stop_postgres() {
    let _ = std::process::Command::new("docker")
        .args(["rm", "-f", &container_name()])
        .output();
}

/// Single test that starts Postgres, runs all assertions, then cleans up.
/// This avoids multiple containers and parallel conflicts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_postgres_all() {
    let url = match start_postgres() {
        Some(u) => u,
        None => {
            eprintln!("SKIPPED: RUN_POSTGRES_TESTS not set or Docker unavailable");
            return;
        }
    };

    let result = run_all_postgres_tests(&url).await;
    stop_postgres();
    result.unwrap();
}

async fn run_all_postgres_tests(url: &str) -> Result<(), String> {
    // --- Full lifecycle ---
    {
        let mut db = PostgresDatabase::new(url)
            .await
            .map_err(|e| format!("connect: {e}"))?;

        let record = UploadRecord {
            sha256: "a".repeat(64),
            size: 1024,
            mime_type: "text/plain".into(),
            pubkey: "b".repeat(64),
            created_at: 1700000000,
            phash: None,
        };
        db.record_upload(&record)
            .map_err(|e| format!("record: {e}"))?;

        let retrieved = db
            .get_upload(&record.sha256)
            .map_err(|e| format!("get: {e}"))?;
        assert_eq!(retrieved.sha256, record.sha256, "sha256 mismatch");
        assert_eq!(retrieved.size, 1024, "size mismatch");

        let list = db
            .list_uploads_by_pubkey(&record.pubkey)
            .map_err(|e| format!("list: {e}"))?;
        assert_eq!(list.len(), 1, "list len");

        assert_eq!(db.upload_count(), 1, "upload count");
        assert_eq!(db.user_count(), 1, "user count");

        assert!(
            db.delete_upload(&record.sha256)
                .map_err(|e| format!("delete: {e}"))?,
            "delete should return true"
        );
        assert_eq!(db.upload_count(), 0, "upload count after delete");
    }

    // --- Quota enforcement ---
    {
        let mut db = PostgresDatabase::new(url)
            .await
            .map_err(|e| format!("connect: {e}"))?;
        let pubkey = "c".repeat(64);

        db.set_quota(&pubkey, Some(1000))
            .map_err(|e| format!("set quota: {e}"))?;
        let user = db
            .get_or_create_user(&pubkey)
            .map_err(|e| format!("get user: {e}"))?;
        assert_eq!(user.quota_bytes, Some(1000), "quota");

        db.check_quota(&pubkey, 500)
            .map_err(|e| format!("check quota: {e}"))?;
        db.update_used_bytes(&pubkey, 800)
            .map_err(|e| format!("update used: {e}"))?;

        match db.check_quota(&pubkey, 300) {
            Err(DbError::QuotaExceeded { .. }) => {} // Expected.
            other => return Err(format!("expected QuotaExceeded, got {:?}", other)),
        }

        db.check_quota(&pubkey, 100)
            .map_err(|e| format!("should fit: {e}"))?;
    }

    // --- File stats ---
    {
        let mut db = PostgresDatabase::new(url)
            .await
            .map_err(|e| format!("connect: {e}"))?;
        let sha = "d".repeat(64);

        db.record_access(&sha, 500)
            .map_err(|e| format!("access: {e}"))?;
        db.record_access(&sha, 300)
            .map_err(|e| format!("access: {e}"))?;

        let stats = db.get_stats(&sha).map_err(|e| format!("stats: {e}"))?;
        assert_eq!(stats.egress_bytes, 800, "egress");
        assert!(stats.last_accessed > 0, "last_accessed");
    }

    // --- Dedup ---
    {
        let mut db = PostgresDatabase::new(url)
            .await
            .map_err(|e| format!("connect: {e}"))?;
        let record = UploadRecord {
            sha256: "e".repeat(64),
            size: 512,
            mime_type: "text/plain".into(),
            pubkey: "f".repeat(64),
            created_at: 1700000000,
            phash: None,
        };

        db.record_upload(&record)
            .map_err(|e| format!("upload1: {e}"))?;
        db.record_upload(&record)
            .map_err(|e| format!("upload2: {e}"))?;
        // Count includes records from earlier tests since we reuse the DB,
        // but the dedup should mean this sha256 appears only once.
        let list = db
            .list_uploads_by_pubkey(&record.pubkey)
            .map_err(|e| format!("list: {e}"))?;
        assert_eq!(list.len(), 1, "dedup failed");
    }

    // --- Not found ---
    {
        let db = PostgresDatabase::new(url)
            .await
            .map_err(|e| format!("connect: {e}"))?;
        match db.get_upload(&"0".repeat(64)) {
            Err(DbError::NotFound) => {}
            other => return Err(format!("expected NotFound, got {:?}", other)),
        }
    }

    eprintln!("All Postgres tests passed");
    Ok(())
}
