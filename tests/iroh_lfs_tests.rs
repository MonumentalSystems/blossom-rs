//! Iroh LFS (BUD-20) integration tests.
//!
//! Tests LFS compression, delta encoding, and reconstruction over
//! the iroh QUIC transport.

#![cfg(feature = "iroh-transport")]

use std::sync::Arc;

use blossom_rs::access::OpenAccess;
use blossom_rs::auth::Signer;
use blossom_rs::db::MemoryDatabase;
use blossom_rs::locks::MemoryLockDatabase;
use blossom_rs::protocol::sha256_hex;
use blossom_rs::storage::MemoryBackend;
use blossom_rs::transport::{BlossomProtocol, IrohBlossomClient, IrohState, BLOSSOM_ALPN};
use blossom_rs::MemoryLfsVersionDatabase;
use iroh::endpoint::presets::N0;
use iroh::protocol::Router;
use iroh::EndpointAddr;
use serial_test::serial;
use tokio::sync::Mutex;

async fn spawn_iroh_lfs_server() -> (EndpointAddr, Router) {
    let state = Arc::new(Mutex::new(IrohState {
        backend: Box::new(MemoryBackend::new()),
        database: Box::new(MemoryDatabase::new()),
        access: Box::new(OpenAccess),
        base_url: "iroh://test".to_string(),
        max_upload_size: None,
        require_auth: false,
        lock_db: Some(Box::new(MemoryLockDatabase::new())),
        lfs_version_db: Some(Box::new(MemoryLfsVersionDatabase::new())),
    }));

    let endpoint = iroh::Endpoint::builder(N0)
        .bind()
        .await
        .expect("bind server endpoint");

    let addr = endpoint.addr();

    let router = Router::builder(endpoint)
        .accept(BLOSSOM_ALPN, Arc::new(BlossomProtocol::new(state)))
        .spawn();

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    (addr, router)
}

async fn make_client(signer: Signer) -> IrohBlossomClient {
    let endpoint = iroh::Endpoint::builder(N0)
        .bind()
        .await
        .expect("bind client endpoint");

    IrohBlossomClient::new(endpoint, signer)
}

#[tokio::test]
#[serial]
async fn test_iroh_lfs_compressed_round_trip() {
    let (server_addr, _router) = spawn_iroh_lfs_server().await;
    let signer = Signer::generate();
    let client = make_client(signer).await;

    let data = vec![42u8; 10_000];
    let expected_sha = sha256_hex(&data);

    let desc = client
        .upload_lfs(
            server_addr.clone(),
            &data,
            "application/octet-stream",
            "model.bin",
            "github.com/org/repo",
            None,
            false,
        )
        .await
        .unwrap();

    assert_eq!(desc.sha256, expected_sha);
    assert_eq!(desc.size, 10_000);

    let downloaded = client.download(server_addr, &desc.sha256).await.unwrap();
    assert_eq!(downloaded.len(), 10_000);
    assert_eq!(sha256_hex(&downloaded), expected_sha);
}

#[tokio::test]
#[serial]
async fn test_iroh_lfs_delta_round_trip() {
    let (server_addr, _router) = spawn_iroh_lfs_server().await;
    let signer = Signer::generate();
    let client = make_client(signer).await;

    let v1_data: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
    let v1_sha = sha256_hex(&v1_data);

    let desc_v1 = client
        .upload_lfs(
            server_addr.clone(),
            &v1_data,
            "application/octet-stream",
            "model.bin",
            "github.com/org/repo",
            None,
            false,
        )
        .await
        .unwrap();
    assert_eq!(desc_v1.sha256, v1_sha);

    let mut v2_data = v1_data.clone();
    v2_data[5000..5010]
        .copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x13, 0x37]);
    let v2_sha = sha256_hex(&v2_data);

    let desc_v2 = client
        .upload_lfs(
            server_addr.clone(),
            &v2_data,
            "application/octet-stream",
            "model.bin",
            "github.com/org/repo",
            Some(&v1_sha),
            false,
        )
        .await
        .unwrap();
    assert_eq!(desc_v2.sha256, v2_sha);

    let downloaded = client.download(server_addr, &v2_sha).await.unwrap();
    assert_eq!(sha256_hex(&downloaded), v2_sha);
    assert_eq!(downloaded.as_slice(), v2_data.as_slice());
}

#[tokio::test]
#[serial]
async fn test_iroh_lfs_manifest_stored_raw() {
    let (server_addr, _router) = spawn_iroh_lfs_server().await;
    let signer = Signer::generate();
    let client = make_client(signer).await;

    let manifest = r#"{"version":"1.0","file_size":1000,"chunks":1}"#;
    let data = manifest.as_bytes().to_vec();
    let expected_sha = sha256_hex(&data);

    let desc = client
        .upload_lfs(
            server_addr.clone(),
            &data,
            "application/json",
            "model.bin",
            "github.com/org/repo",
            None,
            true,
        )
        .await
        .unwrap();

    assert_eq!(desc.sha256, expected_sha);

    let downloaded = client.download(server_addr, &desc.sha256).await.unwrap();
    assert_eq!(downloaded.as_slice(), manifest.as_bytes());
}

#[tokio::test]
#[serial]
async fn test_iroh_lfs_non_lfs_upload_unchanged() {
    let (server_addr, _router) = spawn_iroh_lfs_server().await;
    let signer = Signer::generate();
    let client = make_client(signer).await;

    let data = b"plain old blob data";
    let expected_sha = sha256_hex(data);

    let desc = client.upload(server_addr.clone(), data).await.unwrap();

    assert_eq!(desc.sha256, expected_sha);

    let downloaded = client.download(server_addr, &desc.sha256).await.unwrap();
    assert_eq!(downloaded.as_slice(), data.as_slice());
}

#[tokio::test]
#[serial]
async fn test_iroh_lfs_head_returns_original_size() {
    let (server_addr, _router) = spawn_iroh_lfs_server().await;
    let signer = Signer::generate();
    let client = make_client(signer).await;

    let data = vec![42u8; 10_000];
    let expected_sha = sha256_hex(&data);

    client
        .upload_lfs(
            server_addr.clone(),
            &data,
            "application/octet-stream",
            "model.bin",
            "github.com/org/repo",
            None,
            false,
        )
        .await
        .unwrap();

    assert!(client.exists(server_addr, &expected_sha).await.unwrap());
}

#[tokio::test]
#[serial]
async fn test_iroh_lfs_delete_rebases_delta() {
    let (server_addr, _router) = spawn_iroh_lfs_server().await;
    let signer = Signer::generate();
    let client = make_client(signer).await;

    let v1_data = vec![0x42u8; 10_000];
    let v1_sha = sha256_hex(&v1_data);

    client
        .upload_lfs(
            server_addr.clone(),
            &v1_data,
            "application/octet-stream",
            "model.bin",
            "github.com/org/repo",
            None,
            false,
        )
        .await
        .unwrap();

    let mut v2_data = v1_data.clone();
    v2_data[5000] = 0xFF;
    let v2_sha = sha256_hex(&v2_data);

    client
        .upload_lfs(
            server_addr.clone(),
            &v2_data,
            "application/octet-stream",
            "model.bin",
            "github.com/org/repo",
            Some(&v1_sha),
            false,
        )
        .await
        .unwrap();

    let downloaded = client.download(server_addr.clone(), &v2_sha).await.unwrap();
    assert_eq!(
        downloaded.as_slice(),
        v2_data.as_slice(),
        "v2 mismatch before delete"
    );

    assert!(client.delete(server_addr.clone(), &v1_sha).await.unwrap());

    let downloaded = client.download(server_addr, &v2_sha).await.unwrap();
    assert_eq!(
        downloaded.as_slice(),
        v2_data.as_slice(),
        "v2 mismatch after delete"
    );
}

#[tokio::test]
#[serial]
async fn test_iroh_lfs_delta_chain_max_depth() {
    let (server_addr, _router) = spawn_iroh_lfs_server().await;
    let signer = Signer::generate();
    let client = make_client(signer).await;

    let mut prev_data: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
    let prev_sha = sha256_hex(&prev_data);

    client
        .upload_lfs(
            server_addr.clone(),
            &prev_data,
            "application/octet-stream",
            "model.bin",
            "github.com/org/repo",
            None,
            false,
        )
        .await
        .unwrap();

    let mut prev_sha = prev_sha;

    for i in 2..=11u8 {
        let mut new_data = prev_data.clone();
        new_data[i as usize * 100] = 0xFF;
        let new_sha = sha256_hex(&new_data);

        client
            .upload_lfs(
                server_addr.clone(),
                &new_data,
                "application/octet-stream",
                "model.bin",
                "github.com/org/repo",
                Some(&prev_sha),
                false,
            )
            .await
            .unwrap();

        prev_data = new_data;
        prev_sha = new_sha;
    }

    let downloaded = client.download(server_addr, &prev_sha).await.unwrap();
    assert_eq!(
        downloaded.as_slice(),
        prev_data.as_slice(),
        "v11 content mismatch"
    );
}
