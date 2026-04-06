//! Iroh P2P transport integration tests.
//!
//! Spins up two iroh nodes in-process: a server and a client.
//! Tests full blob lifecycle over QUIC streams.

#![cfg(feature = "iroh-transport")]

use std::sync::Arc;

use blossom_rs::access::OpenAccess;
use blossom_rs::auth::Signer;
use blossom_rs::db::MemoryDatabase;
use blossom_rs::locks::MemoryLockDatabase;
use blossom_rs::protocol::sha256_hex;
use blossom_rs::storage::MemoryBackend;
use blossom_rs::transport::{BlossomProtocol, IrohBlossomClient, IrohState, BLOSSOM_ALPN};
use blossom_rs::BlossomSigner;
use iroh::endpoint::presets::N0;
use iroh::protocol::Router;
use iroh::EndpointAddr;
use serial_test::serial;
use tokio::sync::Mutex;

/// Spawn an iroh server node and return its addr + router handle.
async fn spawn_iroh_server() -> (EndpointAddr, Router) {
    let state = Arc::new(Mutex::new(IrohState {
        backend: Box::new(MemoryBackend::new()),
        database: Box::new(MemoryDatabase::new()),
        access: Box::new(OpenAccess),
        base_url: "iroh://test".to_string(),
        max_upload_size: None,
        require_auth: false,
        lock_db: None,
    }));

    let endpoint = iroh::Endpoint::builder(N0)
        .bind()
        .await
        .expect("bind server endpoint");

    let addr = endpoint.addr();

    let router = Router::builder(endpoint)
        .accept(BLOSSOM_ALPN.to_vec(), Arc::new(BlossomProtocol::new(state)))
        .spawn();

    // Give the router a moment to start accepting.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    (addr, router)
}

/// Create an iroh client.
async fn make_client(signer: Signer) -> IrohBlossomClient {
    let endpoint = iroh::Endpoint::builder(N0)
        .bind()
        .await
        .expect("bind client endpoint");

    IrohBlossomClient::new(endpoint, signer)
}

#[tokio::test]
#[serial]
async fn test_iroh_upload_and_download() {
    let (server_addr, _router) = spawn_iroh_server().await;
    let signer = Signer::generate();
    let client = make_client(signer).await;

    let data = b"hello iroh blossom!";
    let desc = client.upload(server_addr.clone(), data).await.unwrap();
    assert_eq!(desc.size, data.len() as u64);
    assert_eq!(desc.sha256, sha256_hex(data));

    let downloaded = client.download(server_addr, &desc.sha256).await.unwrap();
    assert_eq!(downloaded, data);
}

#[tokio::test]
#[serial]
async fn test_iroh_exists() {
    let (server_addr, _router) = spawn_iroh_server().await;
    let signer = Signer::generate();
    let client = make_client(signer).await;

    let data = b"exists test data";
    let desc = client.upload(server_addr.clone(), data).await.unwrap();

    assert!(client
        .exists(server_addr.clone(), &desc.sha256)
        .await
        .unwrap());
    assert!(!client.exists(server_addr, &"0".repeat(64)).await.unwrap());
}

#[tokio::test]
#[serial]
async fn test_iroh_delete() {
    let (server_addr, _router) = spawn_iroh_server().await;
    let signer = Signer::generate();
    let client = make_client(signer).await;

    let data = b"delete me via iroh";
    let desc = client.upload(server_addr.clone(), data).await.unwrap();

    assert!(client
        .delete(server_addr.clone(), &desc.sha256)
        .await
        .unwrap());
    assert!(!client.exists(server_addr, &desc.sha256).await.unwrap());
}

#[tokio::test]
#[serial]
async fn test_iroh_download_nonexistent() {
    let (server_addr, _router) = spawn_iroh_server().await;
    let signer = Signer::generate();
    let client = make_client(signer).await;

    let result = client.download(server_addr, &"f".repeat(64)).await;
    assert!(result.is_err());
}

#[tokio::test]
#[serial]
async fn test_iroh_large_blob() {
    let (server_addr, _router) = spawn_iroh_server().await;
    let signer = Signer::generate();
    let client = make_client(signer).await;

    // 100KB blob.
    let data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
    let expected_hash = sha256_hex(&data);

    let desc = client.upload(server_addr.clone(), &data).await.unwrap();
    assert_eq!(desc.sha256, expected_hash);

    let downloaded = client.download(server_addr, &desc.sha256).await.unwrap();
    assert_eq!(sha256_hex(&downloaded), expected_hash);
    assert_eq!(downloaded.len(), 100_000);
}

#[tokio::test]
#[serial]
async fn test_iroh_sha256_integrity() {
    let (server_addr, _router) = spawn_iroh_server().await;
    let signer = Signer::generate();
    let client = make_client(signer).await;

    let data = b"integrity verification test";
    let expected = sha256_hex(data);

    let desc = client.upload(server_addr.clone(), data).await.unwrap();
    assert_eq!(desc.sha256, expected);

    let downloaded = client.download(server_addr, &expected).await.unwrap();
    assert_eq!(sha256_hex(&downloaded), expected);
}

#[tokio::test]
#[serial]
async fn test_iroh_list() {
    let (server_addr, _router) = spawn_iroh_server().await;
    let signer = Signer::generate();
    let pubkey = signer.public_key_hex();
    let client = make_client(signer).await;

    // Upload two blobs.
    let data1 = b"list test blob one";
    let data2 = b"list test blob two";
    let desc1 = client.upload(server_addr.clone(), data1).await.unwrap();
    let desc2 = client.upload(server_addr.clone(), data2).await.unwrap();

    // List by pubkey.
    let list = client.list(server_addr.clone(), &pubkey).await.unwrap();
    assert_eq!(list.len(), 2);

    let hashes: Vec<&str> = list.iter().map(|d| d.sha256.as_str()).collect();
    assert!(hashes.contains(&desc1.sha256.as_str()));
    assert!(hashes.contains(&desc2.sha256.as_str()));

    // List for unknown pubkey returns empty.
    let empty = client.list(server_addr, &"0".repeat(64)).await.unwrap();
    assert!(empty.is_empty());
}

async fn spawn_iroh_lock_server() -> (EndpointAddr, Router) {
    let state = Arc::new(Mutex::new(IrohState {
        backend: Box::new(MemoryBackend::new()),
        database: Box::new(MemoryDatabase::new()),
        access: Box::new(OpenAccess),
        base_url: "iroh://test".to_string(),
        max_upload_size: None,
        require_auth: false,
        lock_db: Some(Box::new(MemoryLockDatabase::new())),
    }));

    let endpoint = iroh::Endpoint::builder(N0)
        .bind()
        .await
        .expect("bind server endpoint");

    let addr = endpoint.addr();

    let router = Router::builder(endpoint)
        .accept(BLOSSOM_ALPN.to_vec(), Arc::new(BlossomProtocol::new(state)))
        .spawn();

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    (addr, router)
}

#[tokio::test]
#[serial]
async fn test_iroh_create_lock() {
    let (server_addr, _router) = spawn_iroh_lock_server().await;
    let signer = Signer::generate();
    let client = make_client(signer).await;

    let lock = client
        .create_lock(&server_addr, "myrepo", "assets/big-file.bin")
        .await
        .unwrap();
    assert_eq!(lock.path, "assets/big-file.bin");
    assert!(!lock.id.is_empty());
}

#[tokio::test]
#[serial]
async fn test_iroh_create_lock_conflict() {
    let (server_addr, _router) = spawn_iroh_lock_server().await;
    let signer = Signer::generate();
    let client = make_client(signer).await;

    client
        .create_lock(&server_addr, "myrepo", "file.txt")
        .await
        .unwrap();

    let err = client
        .create_lock(&server_addr, "myrepo", "file.txt")
        .await
        .unwrap_err();
    assert!(err.contains("already locked"));
}

#[tokio::test]
#[serial]
async fn test_iroh_create_lock_different_repos_same_path() {
    let (server_addr, _router) = spawn_iroh_lock_server().await;
    let signer = Signer::generate();
    let client = make_client(signer).await;

    let lock1 = client
        .create_lock(&server_addr, "repo1", "file.txt")
        .await
        .unwrap();
    let lock2 = client
        .create_lock(&server_addr, "repo2", "file.txt")
        .await
        .unwrap();
    assert_ne!(lock1.id, lock2.id);
}

#[tokio::test]
#[serial]
async fn test_iroh_delete_lock_by_owner() {
    let (server_addr, _router) = spawn_iroh_lock_server().await;
    let signer = Signer::generate();
    let client = make_client(signer).await;

    let lock = client
        .create_lock(&server_addr, "myrepo", "file.txt")
        .await
        .unwrap();

    let deleted = client
        .delete_lock(&server_addr, "myrepo", &lock.id, false)
        .await
        .unwrap();
    assert_eq!(deleted.id, lock.id);
}

#[tokio::test]
#[serial]
async fn test_iroh_delete_lock_by_non_owner_forbidden() {
    let (server_addr, _router) = spawn_iroh_lock_server().await;
    let owner = Signer::generate();
    let other = Signer::generate();
    let owner_client = make_client(owner).await;
    let other_client = make_client(other).await;

    let lock = owner_client
        .create_lock(&server_addr, "myrepo", "file.txt")
        .await
        .unwrap();

    let err = other_client
        .delete_lock(&server_addr, "myrepo", &lock.id, false)
        .await
        .unwrap_err();
    assert!(err.to_lowercase().contains("owner") || err.to_lowercase().contains("forbidden"));
}

#[tokio::test]
#[serial]
async fn test_iroh_delete_lock_not_found() {
    let (server_addr, _router) = spawn_iroh_lock_server().await;
    let signer = Signer::generate();
    let client = make_client(signer).await;

    let err = client
        .delete_lock(&server_addr, "myrepo", "nonexistent-id", false)
        .await
        .unwrap_err();
    assert!(err.contains("not found"));
}

#[tokio::test]
#[serial]
async fn test_iroh_list_locks() {
    let (server_addr, _router) = spawn_iroh_lock_server().await;
    let signer = Signer::generate();
    let client = make_client(signer).await;

    client
        .create_lock(&server_addr, "myrepo", "a.txt")
        .await
        .unwrap();
    client
        .create_lock(&server_addr, "myrepo", "b.txt")
        .await
        .unwrap();

    let (locks, _) = client
        .list_locks(&server_addr, "myrepo", None, None)
        .await
        .unwrap();
    assert_eq!(locks.len(), 2);
}

#[tokio::test]
#[serial]
async fn test_iroh_list_locks_empty() {
    let (server_addr, _router) = spawn_iroh_lock_server().await;
    let signer = Signer::generate();
    let client = make_client(signer).await;

    let (locks, _) = client
        .list_locks(&server_addr, "empty-repo", None, None)
        .await
        .unwrap();
    assert!(locks.is_empty());
}

#[tokio::test]
#[serial]
async fn test_iroh_verify_locks_splits_ours_and_theirs() {
    let (server_addr, _router) = spawn_iroh_lock_server().await;
    let owner = Signer::generate();
    let other = Signer::generate();
    let owner_client = make_client(owner).await;
    let other_client = make_client(other).await;

    owner_client
        .create_lock(&server_addr, "myrepo", "owner-file.txt")
        .await
        .unwrap();
    other_client
        .create_lock(&server_addr, "myrepo", "other-file.txt")
        .await
        .unwrap();

    let (ours, theirs, _) = owner_client
        .verify_locks(&server_addr, "myrepo", None, None)
        .await
        .unwrap();

    assert_eq!(ours.len(), 1);
    assert_eq!(ours[0].path, "owner-file.txt");
    assert_eq!(theirs.len(), 1);
    assert_eq!(theirs[0].path, "other-file.txt");
}

#[tokio::test]
#[serial]
async fn test_iroh_lock_without_lock_db_returns_not_found() {
    let (server_addr, _router) = spawn_iroh_server().await;
    let signer = Signer::generate();
    let client = make_client(signer).await;

    let err = client
        .create_lock(&server_addr, "myrepo", "file.txt")
        .await
        .unwrap_err();
    assert!(err.contains("not configured"));
}

#[tokio::test]
#[serial]
async fn test_iroh_lock_lifecycle() {
    let (server_addr, _router) = spawn_iroh_lock_server().await;
    let signer = Signer::generate();
    let client = make_client(signer).await;

    let lock = client
        .create_lock(&server_addr, "lifecycle", "big-file.bin")
        .await
        .unwrap();

    let (ours, theirs, _) = client
        .verify_locks(&server_addr, "lifecycle", None, None)
        .await
        .unwrap();
    assert_eq!(ours.len(), 1);
    assert_eq!(theirs.len(), 0);

    let (locks, _) = client
        .list_locks(&server_addr, "lifecycle", None, None)
        .await
        .unwrap();
    assert_eq!(locks.len(), 1);

    client
        .delete_lock(&server_addr, "lifecycle", &lock.id, false)
        .await
        .unwrap();

    let (locks_after, _) = client
        .list_locks(&server_addr, "lifecycle", None, None)
        .await
        .unwrap();
    assert!(locks_after.is_empty());
}
