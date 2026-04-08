//! Integration tests for SQLite-backed lock database (BUD-19).
//!
//! Tests the full HTTP lock API using SqliteLockDatabase for persistence,
//! including restart survival.

use blossom_rs::auth::{auth_header_value, build_blossom_auth, Signer};
use blossom_rs::locks::SqliteLockDatabase;
use blossom_rs::server::BlobServer;
use blossom_rs::storage::MemoryBackend;
use blossom_rs::BlossomSigner;

fn lock_auth(signer: &Signer) -> String {
    let event = build_blossom_auth(signer, "lock", None, None, "");
    auth_header_value(&event)
}

async fn sqlite_lock_server(db_path: &str) -> BlobServer {
    let url = format!("sqlite:{}?mode=rwc", db_path);
    let lock_db = SqliteLockDatabase::from_url(&url).await.unwrap();
    BlobServer::builder(MemoryBackend::new(), "http://localhost:3000")
        .lock_database(lock_db)
        .build()
}

async fn spawn_server(server: BlobServer) -> String {
    let app = server.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    url
}

#[tokio::test(flavor = "multi_thread")]
async fn test_sqlite_create_lock() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db_path = tmp.path().to_str().unwrap();
    let server = sqlite_lock_server(db_path).await;
    let url = spawn_server(server).await;
    let signer = Signer::generate();
    let auth = lock_auth(&signer);

    let resp = reqwest::Client::new()
        .post(format!("{}/lfs/myrepo/locks", url))
        .header("Authorization", auth)
        .json(&serde_json::json!({"path": "assets/big-file.bin"}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    let lock = &body["lock"];
    assert_eq!(lock["path"], "assets/big-file.bin");
    assert_eq!(lock["owner"]["name"], signer.public_key_hex());
    assert!(!lock["id"].as_str().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_sqlite_lock_conflict() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db_path = tmp.path().to_str().unwrap();
    let server = sqlite_lock_server(db_path).await;
    let url = spawn_server(server).await;
    let signer = Signer::generate();
    let auth = lock_auth(&signer);
    let client = reqwest::Client::new();

    let resp1 = client
        .post(format!("{}/lfs/myrepo/locks", url))
        .header("Authorization", &auth)
        .json(&serde_json::json!({"path": "file.txt"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp1.status(), 201);

    let resp2 = client
        .post(format!("{}/lfs/myrepo/locks", url))
        .header("Authorization", &auth)
        .json(&serde_json::json!({"path": "file.txt"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp2.status(), 409);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_sqlite_unlock_by_owner() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db_path = tmp.path().to_str().unwrap();
    let server = sqlite_lock_server(db_path).await;
    let url = spawn_server(server).await;
    let signer = Signer::generate();
    let auth = lock_auth(&signer);
    let client = reqwest::Client::new();

    let create_resp: serde_json::Value = client
        .post(format!("{}/lfs/myrepo/locks", url))
        .header("Authorization", &auth)
        .json(&serde_json::json!({"path": "file.txt"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let lock_id = create_resp["lock"]["id"].as_str().unwrap();

    let unlock_resp = client
        .post(format!("{}/lfs/myrepo/locks/{}/unlock", url, lock_id))
        .header("Authorization", &auth)
        .json(&serde_json::json!({"force": false}))
        .send()
        .await
        .unwrap();

    assert_eq!(unlock_resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_sqlite_unlock_non_owner_forbidden() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db_path = tmp.path().to_str().unwrap();
    let server = sqlite_lock_server(db_path).await;
    let url = spawn_server(server).await;
    let owner = Signer::generate();
    let other = Signer::generate();
    let client = reqwest::Client::new();

    let create_resp: serde_json::Value = client
        .post(format!("{}/lfs/myrepo/locks", url))
        .header("Authorization", lock_auth(&owner))
        .json(&serde_json::json!({"path": "file.txt"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let lock_id = create_resp["lock"]["id"].as_str().unwrap();

    let unlock_resp = client
        .post(format!("{}/lfs/myrepo/locks/{}/unlock", url, lock_id))
        .header("Authorization", lock_auth(&other))
        .json(&serde_json::json!({"force": false}))
        .send()
        .await
        .unwrap();

    assert_eq!(unlock_resp.status(), 403);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_sqlite_list_locks() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db_path = tmp.path().to_str().unwrap();
    let server = sqlite_lock_server(db_path).await;
    let url = spawn_server(server).await;
    let signer = Signer::generate();
    let auth = lock_auth(&signer);
    let client = reqwest::Client::new();

    client
        .post(format!("{}/lfs/myrepo/locks", url))
        .header("Authorization", &auth)
        .json(&serde_json::json!({"path": "a.txt"}))
        .send()
        .await
        .unwrap();

    client
        .post(format!("{}/lfs/myrepo/locks", url))
        .header("Authorization", &auth)
        .json(&serde_json::json!({"path": "b.txt"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .get(format!("{}/lfs/myrepo/locks", url))
        .header("Authorization", &auth)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let locks = body["locks"].as_array().unwrap();
    assert_eq!(locks.len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_sqlite_list_locks_with_path_filter() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db_path = tmp.path().to_str().unwrap();
    let server = sqlite_lock_server(db_path).await;
    let url = spawn_server(server).await;
    let signer = Signer::generate();
    let auth = lock_auth(&signer);
    let client = reqwest::Client::new();

    client
        .post(format!("{}/lfs/myrepo/locks", url))
        .header("Authorization", &auth)
        .json(&serde_json::json!({"path": "a.txt"}))
        .send()
        .await
        .unwrap();

    client
        .post(format!("{}/lfs/myrepo/locks", url))
        .header("Authorization", &auth)
        .json(&serde_json::json!({"path": "b.txt"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .get(format!("{}/lfs/myrepo/locks?path=a.txt", url))
        .header("Authorization", &auth)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let locks = body["locks"].as_array().unwrap();
    assert_eq!(locks.len(), 1);
    assert_eq!(locks[0]["path"], "a.txt");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_sqlite_verify_locks_ours_theirs() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db_path = tmp.path().to_str().unwrap();
    let server = sqlite_lock_server(db_path).await;
    let url = spawn_server(server).await;
    let owner = Signer::generate();
    let other = Signer::generate();
    let client = reqwest::Client::new();

    client
        .post(format!("{}/lfs/myrepo/locks", url))
        .header("Authorization", lock_auth(&owner))
        .json(&serde_json::json!({"path": "owner-file.txt"}))
        .send()
        .await
        .unwrap();

    client
        .post(format!("{}/lfs/myrepo/locks", url))
        .header("Authorization", lock_auth(&other))
        .json(&serde_json::json!({"path": "other-file.txt"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(format!("{}/lfs/myrepo/locks/verify", url))
        .header("Authorization", lock_auth(&owner))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let ours = body["ours"].as_array().unwrap();
    let theirs = body["theirs"].as_array().unwrap();
    assert_eq!(ours.len(), 1);
    assert_eq!(ours[0]["path"], "owner-file.txt");
    assert_eq!(theirs.len(), 1);
    assert_eq!(theirs[0]["path"], "other-file.txt");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_sqlite_cross_repo_isolation() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db_path = tmp.path().to_str().unwrap();
    let server = sqlite_lock_server(db_path).await;
    let url = spawn_server(server).await;
    let signer = Signer::generate();
    let auth = lock_auth(&signer);
    let client = reqwest::Client::new();

    let resp1 = client
        .post(format!("{}/lfs/repo1/locks", url))
        .header("Authorization", &auth)
        .json(&serde_json::json!({"path": "file.txt"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp1.status(), 201);

    // Same path, different repo — should succeed (no conflict).
    let resp2 = client
        .post(format!("{}/lfs/repo2/locks", url))
        .header("Authorization", &auth)
        .json(&serde_json::json!({"path": "file.txt"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp2.status(), 201);

    // Listing repo1 should only show 1 lock.
    let list = client
        .get(format!("{}/lfs/repo1/locks", url))
        .header("Authorization", &auth)
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = list.json().await.unwrap();
    assert_eq!(body["locks"].as_array().unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_sqlite_full_lifecycle() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db_path = tmp.path().to_str().unwrap();
    let server = sqlite_lock_server(db_path).await;
    let url = spawn_server(server).await;
    let signer = Signer::generate();
    let auth = lock_auth(&signer);
    let client = reqwest::Client::new();

    // Create
    let create_resp = client
        .post(format!("{}/lfs/myrepo/locks", url))
        .header("Authorization", &auth)
        .json(&serde_json::json!({"path": "big-file.bin"}))
        .send()
        .await
        .unwrap();
    assert_eq!(create_resp.status(), 201);
    let create_body: serde_json::Value = create_resp.json().await.unwrap();
    let lock_id = create_body["lock"]["id"].as_str().unwrap().to_string();

    // List — should have 1 lock
    let list_resp = client
        .get(format!("{}/lfs/myrepo/locks", url))
        .header("Authorization", &auth)
        .send()
        .await
        .unwrap();
    assert_eq!(list_resp.status(), 200);
    let list_body: serde_json::Value = list_resp.json().await.unwrap();
    assert_eq!(list_body["locks"].as_array().unwrap().len(), 1);

    // Verify — should be in "ours"
    let verify_resp = client
        .post(format!("{}/lfs/myrepo/locks/verify", url))
        .header("Authorization", &auth)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(verify_resp.status(), 200);
    let verify_body: serde_json::Value = verify_resp.json().await.unwrap();
    assert_eq!(verify_body["ours"].as_array().unwrap().len(), 1);
    assert_eq!(verify_body["theirs"].as_array().unwrap().len(), 0);

    // Unlock
    let unlock_resp = client
        .post(format!("{}/lfs/myrepo/locks/{}/unlock", url, lock_id))
        .header("Authorization", &auth)
        .json(&serde_json::json!({"force": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(unlock_resp.status(), 200);

    // List — should be empty
    let list_after = client
        .get(format!("{}/lfs/myrepo/locks", url))
        .header("Authorization", &auth)
        .send()
        .await
        .unwrap();
    let list_after_body: serde_json::Value = list_after.json().await.unwrap();
    assert!(list_after_body["locks"].as_array().unwrap().is_empty());
}

/// Locks survive server restart — the key persistence test.
#[tokio::test(flavor = "multi_thread")]
async fn test_sqlite_locks_persist_across_restart() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db_path = tmp.path().to_str().unwrap().to_string();
    let signer = Signer::generate();
    let auth = lock_auth(&signer);
    let client = reqwest::Client::new();

    // Server instance 1: create a lock
    let server1 = sqlite_lock_server(&db_path).await;
    let url1 = spawn_server(server1).await;

    let create_resp = client
        .post(format!("{}/lfs/myrepo/locks", url1))
        .header("Authorization", &auth)
        .json(&serde_json::json!({"path": "persistent-file.bin"}))
        .send()
        .await
        .unwrap();
    assert_eq!(create_resp.status(), 201);
    let create_body: serde_json::Value = create_resp.json().await.unwrap();
    let lock_id = create_body["lock"]["id"].as_str().unwrap().to_string();

    // Server instance 2: same SQLite file, fresh server — lock should still exist
    let server2 = sqlite_lock_server(&db_path).await;
    let url2 = spawn_server(server2).await;

    let list_resp = client
        .get(format!("{}/lfs/myrepo/locks", url2))
        .header("Authorization", &auth)
        .send()
        .await
        .unwrap();
    assert_eq!(list_resp.status(), 200);
    let list_body: serde_json::Value = list_resp.json().await.unwrap();
    let locks = list_body["locks"].as_array().unwrap();
    assert_eq!(locks.len(), 1);
    assert_eq!(locks[0]["id"], lock_id);
    assert_eq!(locks[0]["path"], "persistent-file.bin");

    // Unlock on the new server instance
    let unlock_resp = client
        .post(format!("{}/lfs/myrepo/locks/{}/unlock", url2, lock_id))
        .header("Authorization", &auth)
        .json(&serde_json::json!({"force": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(unlock_resp.status(), 200);

    // Verify it's gone
    let list_after = client
        .get(format!("{}/lfs/myrepo/locks", url2))
        .header("Authorization", &auth)
        .send()
        .await
        .unwrap();
    let list_after_body: serde_json::Value = list_after.json().await.unwrap();
    assert!(list_after_body["locks"].as_array().unwrap().is_empty());
}
