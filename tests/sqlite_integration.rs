//! Integration tests for SqliteDatabase.
//!
//! These tests exercise the SQLite backend through the BlobDatabase trait,
//! verifying migrations, CRUD, quotas, and stats with a real SQLite file.

#![cfg(feature = "db-sqlite")]

use blossom_rs::db::{BlobDatabase, DbError, SqliteDatabase, UploadRecord};

async fn temp_db() -> SqliteDatabase {
    let path = std::env::temp_dir().join(format!("blossom_sqlite_{}.db", rand::random::<u32>()));
    let url = format!("sqlite:{}?mode=rwc", path.display());
    SqliteDatabase::new(&url).await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sqlite_record_and_get_upload() {
    let mut db = temp_db().await;
    let record = UploadRecord {
        sha256: "a".repeat(64),
        size: 1024,
        mime_type: "text/plain".into(),
        pubkey: "b".repeat(64),
        created_at: 1700000000,
        phash: None,
    };

    db.record_upload(&record).unwrap();
    let retrieved = db.get_upload(&record.sha256).unwrap();
    assert_eq!(retrieved.sha256, record.sha256);
    assert_eq!(retrieved.size, 1024);
    assert_eq!(retrieved.pubkey, "b".repeat(64));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sqlite_list_by_pubkey() {
    let mut db = temp_db().await;
    let pubkey = "c".repeat(64);

    let r1 = UploadRecord {
        sha256: "1".repeat(64),
        size: 100,
        mime_type: "text/plain".into(),
        pubkey: pubkey.clone(),
        created_at: 1000,
        phash: None,
    };
    let r2 = UploadRecord {
        sha256: "2".repeat(64),
        size: 200,
        mime_type: "image/png".into(),
        pubkey: pubkey.clone(),
        created_at: 2000,
        phash: None,
    };
    let r3 = UploadRecord {
        sha256: "3".repeat(64),
        size: 300,
        mime_type: "video/mp4".into(),
        pubkey: "d".repeat(64),
        created_at: 3000,
        phash: None,
    };

    db.record_upload(&r1).unwrap();
    db.record_upload(&r2).unwrap();
    db.record_upload(&r3).unwrap();

    let list = db.list_uploads_by_pubkey(&pubkey).unwrap();
    assert_eq!(list.len(), 2);
    // Most recent first.
    assert_eq!(list[0].created_at, 2000);
    assert_eq!(list[1].created_at, 1000);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sqlite_delete_upload() {
    let mut db = temp_db().await;
    let record = UploadRecord {
        sha256: "e".repeat(64),
        size: 500,
        mime_type: "text/plain".into(),
        pubkey: "f".repeat(64),
        created_at: 1700000000,
        phash: None,
    };

    db.record_upload(&record).unwrap();
    assert_eq!(db.upload_count(), 1);

    assert!(db.delete_upload(&record.sha256).unwrap());
    assert_eq!(db.upload_count(), 0);

    // Delete nonexistent returns false.
    assert!(!db.delete_upload(&record.sha256).unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sqlite_user_quota() {
    let mut db = temp_db().await;
    let pubkey = "a".repeat(64);

    // Create user with quota.
    db.set_quota(&pubkey, Some(1000)).unwrap();
    let user = db.get_or_create_user(&pubkey).unwrap();
    assert_eq!(user.quota_bytes, Some(1000));
    assert_eq!(user.used_bytes, 0);

    // Should pass.
    db.check_quota(&pubkey, 500).unwrap();

    // Simulate usage.
    db.update_used_bytes(&pubkey, 800).unwrap();

    // Should fail — 800 + 300 > 1000.
    let result = db.check_quota(&pubkey, 300);
    assert!(matches!(result, Err(DbError::QuotaExceeded { .. })));

    // Should pass — 800 + 100 < 1000.
    db.check_quota(&pubkey, 100).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sqlite_no_quota_unlimited() {
    let mut db = temp_db().await;
    let pubkey = "b".repeat(64);

    db.get_or_create_user(&pubkey).unwrap();
    // No quota set — anything goes.
    db.check_quota(&pubkey, u64::MAX).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sqlite_file_stats() {
    let mut db = temp_db().await;
    let sha = "c".repeat(64);

    db.record_access(&sha, 500).unwrap();
    db.record_access(&sha, 300).unwrap();

    let stats = db.get_stats(&sha).unwrap();
    assert_eq!(stats.egress_bytes, 800);
    assert!(stats.last_accessed > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sqlite_upload_updates_used_bytes() {
    let mut db = temp_db().await;
    let pubkey = "d".repeat(64);

    let record = UploadRecord {
        sha256: "e".repeat(64),
        size: 1024,
        mime_type: "text/plain".into(),
        pubkey: pubkey.clone(),
        created_at: 1700000000,
        phash: None,
    };

    db.record_upload(&record).unwrap();
    let user = db.get_or_create_user(&pubkey).unwrap();
    assert_eq!(user.used_bytes, 1024);

    // Delete should reduce used_bytes.
    db.delete_upload(&record.sha256).unwrap();
    let user = db.get_or_create_user(&pubkey).unwrap();
    assert_eq!(user.used_bytes, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sqlite_dedup_upload() {
    let mut db = temp_db().await;
    let record = UploadRecord {
        sha256: "f".repeat(64),
        size: 512,
        mime_type: "text/plain".into(),
        pubkey: "a".repeat(64),
        created_at: 1700000000,
        phash: None,
    };

    db.record_upload(&record).unwrap();
    db.record_upload(&record).unwrap();

    // Only 1 upload record.
    assert_eq!(db.upload_count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sqlite_counts() {
    let mut db = temp_db().await;
    assert_eq!(db.upload_count(), 0);
    assert_eq!(db.user_count(), 0);

    let record = UploadRecord {
        sha256: "a".repeat(64),
        size: 100,
        mime_type: "text/plain".into(),
        pubkey: "b".repeat(64),
        created_at: 1700000000,
        phash: None,
    };
    db.record_upload(&record).unwrap();

    assert_eq!(db.upload_count(), 1);
    assert_eq!(db.user_count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sqlite_get_nonexistent() {
    let db = temp_db().await;
    let result = db.get_upload(&"0".repeat(64));
    assert!(matches!(result, Err(DbError::NotFound)));
}
