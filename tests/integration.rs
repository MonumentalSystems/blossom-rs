//! Integration tests for blossom-rs.
//!
//! These tests exercise end-to-end workflows: client → server → storage → database.

use blossom_rs::{
    auth::{auth_header_value, build_blossom_auth},
    protocol::sha256_hex,
    server::BlobServer,
    BlobBackend, BlobDatabase, BlossomClient, MemoryBackend, MemoryDatabase, Signer,
};

async fn spawn_server(server: BlobServer) -> String {
    let app = server.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    url
}

// ---------------------------------------------------------------------------
// Client ↔ Server integration
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_client_upload_download_roundtrip() {
    let signer = Signer::generate();
    let server = BlobServer::new(MemoryBackend::new(), "http://localhost:3000");
    let url = spawn_server(server).await;

    let client = BlossomClient::new(vec![url], signer);

    let data = b"hello from the integration test!";
    let desc = client.upload(data, "text/plain").await.unwrap();
    assert_eq!(desc.size, data.len() as u64);

    let downloaded = client.download(&desc.sha256).await.unwrap();
    assert_eq!(downloaded, data);
}

#[tokio::test]
async fn test_client_exists_check() {
    let signer = Signer::generate();
    let server = BlobServer::new(MemoryBackend::new(), "http://localhost:3000");
    let url = spawn_server(server).await;

    let client = BlossomClient::new(vec![url], signer);

    // Upload.
    let data = b"existence check data";
    let desc = client
        .upload(data, "application/octet-stream")
        .await
        .unwrap();

    // Should exist.
    assert!(client.exists(&desc.sha256).await.unwrap());

    // Should not exist.
    let fake_hash = "0".repeat(64);
    assert!(!client.exists(&fake_hash).await.unwrap());
}

#[tokio::test]
async fn test_client_multi_server_failover() {
    let signer = Signer::generate();
    let server = BlobServer::new(MemoryBackend::new(), "http://localhost:3000");
    let good_url = spawn_server(server).await;

    // First server is unreachable, second is good.
    let client = BlossomClient::new(vec!["http://127.0.0.1:1".to_string(), good_url], signer);

    let data = b"failover test data";
    let desc = client
        .upload(data, "application/octet-stream")
        .await
        .unwrap();
    assert_eq!(desc.size, data.len() as u64);
}

// ---------------------------------------------------------------------------
// Auth enforcement
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_auth_required_upload_rejected_without_auth() {
    let server = BlobServer::new_with_auth(MemoryBackend::new(), "http://localhost:3000");
    let url = spawn_server(server).await;
    let http = reqwest::Client::new();

    let resp = http
        .put(format!("{}/upload", url))
        .body(b"unauthorized".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_auth_required_upload_succeeds_with_auth() {
    let server = BlobServer::new_with_auth(MemoryBackend::new(), "http://localhost:3000");
    let url = spawn_server(server).await;
    let http = reqwest::Client::new();
    let signer = Signer::generate();

    let data = b"authorized upload";
    let auth_event = build_blossom_auth(&signer, "upload", Some(&sha256_hex(data)), None, "");
    let auth_header = auth_header_value(&auth_event);

    let resp = http
        .put(format!("{}/upload", url))
        .header("Authorization", &auth_header)
        .body(data.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_delete_requires_auth() {
    let server = BlobServer::new(MemoryBackend::new(), "http://localhost:3000");
    let url = spawn_server(server).await;
    let http = reqwest::Client::new();

    // Upload first.
    let data = b"to be deleted";
    let resp = http
        .put(format!("{}/upload", url))
        .body(data.to_vec())
        .send()
        .await
        .unwrap();
    let desc: blossom_rs::BlobDescriptor = resp.json().await.unwrap();

    // Delete without auth should fail.
    let resp = http
        .delete(format!("{}/{}", url, desc.sha256))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Delete with auth should succeed.
    let signer = Signer::generate();
    let auth_event = build_blossom_auth(&signer, "delete", None, None, "");
    let auth_header = auth_header_value(&auth_event);

    let resp = http
        .delete(format!("{}/{}", url, desc.sha256))
        .header("Authorization", &auth_header)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Should be gone now.
    let resp = http
        .head(format!("{}/{}", url, desc.sha256))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

// ---------------------------------------------------------------------------
// Builder pattern + quota
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_server_builder_with_database() {
    let mut db = MemoryDatabase::new();
    db.set_quota("test_user", Some(100)).unwrap();

    let server = BlobServer::builder(MemoryBackend::new(), "http://localhost:3000")
        .database(db)
        .build();
    let url = spawn_server(server).await;

    let http = reqwest::Client::new();

    // Upload should work (no auth required, anonymous user).
    let resp = http
        .put(format!("{}/upload", url))
        .body(b"small".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Status should show the upload.
    let resp = http.get(format!("{}/status", url)).send().await.unwrap();
    let status: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(status["uploads"], 1);
}

// ---------------------------------------------------------------------------
// Content integrity
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_large_blob_integrity() {
    let signer = Signer::generate();
    let server = BlobServer::new(MemoryBackend::new(), "http://localhost:3000");
    let url = spawn_server(server).await;

    let client = BlossomClient::new(vec![url], signer);

    // 100KB of pseudo-random data.
    let data: Vec<u8> = (0..100_000).map(|i| (i * 7 + 13) as u8).collect();
    let expected_hash = sha256_hex(&data);

    let desc = client
        .upload(&data, "application/octet-stream")
        .await
        .unwrap();
    assert_eq!(desc.sha256, expected_hash);
    assert_eq!(desc.size, 100_000);

    let downloaded = client.download(&desc.sha256).await.unwrap();
    assert_eq!(sha256_hex(&downloaded), expected_hash);
    assert_eq!(downloaded.len(), 100_000);
}

#[tokio::test]
async fn test_deduplication_across_uploads() {
    let server = BlobServer::new(MemoryBackend::new(), "http://localhost:3000");
    let url = spawn_server(server).await;
    let http = reqwest::Client::new();

    let data = b"deduplicate me";

    // Upload twice.
    let resp1 = http
        .put(format!("{}/upload", url))
        .body(data.to_vec())
        .send()
        .await
        .unwrap();
    let desc1: blossom_rs::BlobDescriptor = resp1.json().await.unwrap();

    let resp2 = http
        .put(format!("{}/upload", url))
        .body(data.to_vec())
        .send()
        .await
        .unwrap();
    let desc2: blossom_rs::BlobDescriptor = resp2.json().await.unwrap();

    // Same hash, one blob stored.
    assert_eq!(desc1.sha256, desc2.sha256);

    let resp = http.get(format!("{}/status", url)).send().await.unwrap();
    let status: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(status["blobs"], 1);
}

// ---------------------------------------------------------------------------
// BUD-02: List endpoint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_list_multiple_uploads() {
    let server = BlobServer::new(MemoryBackend::new(), "http://localhost:3000");
    let url = spawn_server(server).await;
    let http = reqwest::Client::new();

    // Upload 3 different blobs.
    for i in 0..3u8 {
        http.put(format!("{}/upload", url))
            .body(vec![i; 10])
            .send()
            .await
            .unwrap();
    }

    // All uploads are anonymous.
    let resp = http
        .get(format!("{}/list/anonymous", url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let list: Vec<blossom_rs::BlobDescriptor> = resp.json().await.unwrap();
    assert_eq!(list.len(), 3);
}

// ---------------------------------------------------------------------------
// BUD-06: Upload size enforcement
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_upload_size_limit_exact_boundary() {
    let server = BlobServer::builder(MemoryBackend::new(), "http://localhost:3000")
        .max_upload_size(10)
        .build();
    let url = spawn_server(server).await;
    let http = reqwest::Client::new();

    // Exactly 10 bytes should succeed.
    let resp = http
        .put(format!("{}/upload", url))
        .body(vec![0u8; 10])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // 11 bytes should fail.
    let resp = http
        .put(format!("{}/upload", url))
        .body(vec![0u8; 11])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 413);
}

// ---------------------------------------------------------------------------
// Filesystem backend
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_filesystem_backend_server() {
    let dir = std::env::temp_dir().join(format!("blossom_int_{}", rand::random::<u32>()));
    let backend = blossom_rs::FilesystemBackend::new(dir.to_str().unwrap()).unwrap();
    let server = BlobServer::new(backend, "http://localhost:3000");
    let url = spawn_server(server).await;

    let http = reqwest::Client::new();

    let data = b"filesystem integration test";
    let resp = http
        .put(format!("{}/upload", url))
        .body(data.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let desc: blossom_rs::BlobDescriptor = resp.json().await.unwrap();

    // Verify file exists on disk.
    let blob_path = dir.join(format!("{}.blob", desc.sha256));
    assert!(blob_path.exists());

    // Download and verify.
    let resp = http
        .get(format!("{}/{}", url, desc.sha256))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), data);

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Client error paths
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_client_download_nonexistent() {
    let signer = Signer::generate();
    let server = BlobServer::new(MemoryBackend::new(), "http://localhost:3000");
    let url = spawn_server(server).await;

    let client = BlossomClient::new(vec![url], signer);
    let result = client.download(&"0".repeat(64)).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not found"));
}

#[tokio::test]
async fn test_client_upload_all_servers_fail() {
    let signer = Signer::generate();
    // Both servers unreachable.
    let client = BlossomClient::new(
        vec![
            "http://127.0.0.1:1".to_string(),
            "http://127.0.0.1:2".to_string(),
        ],
        signer,
    );

    let result = client.upload(b"data", "text/plain").await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("all Blossom servers failed"));
}

#[tokio::test]
async fn test_client_download_all_servers_fail() {
    let signer = Signer::generate();
    let client = BlossomClient::new(vec!["http://127.0.0.1:1".to_string()], signer);

    let result = client.download(&"a".repeat(64)).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_client_exists_all_servers_fail() {
    let signer = Signer::generate();
    let client = BlossomClient::new(vec!["http://127.0.0.1:1".to_string()], signer);

    // Should return false (not found), not error.
    let result = client.exists(&"a".repeat(64)).await.unwrap();
    assert!(!result);
}

#[tokio::test]
async fn test_client_upload_failover_non_success() {
    let signer = Signer::generate();

    // First server returns 401 (requires auth), second is open.
    let bad_server = BlobServer::new_with_auth(MemoryBackend::new(), "http://localhost:3000");
    let bad_url = spawn_server(bad_server).await;

    let good_server = BlobServer::new(MemoryBackend::new(), "http://localhost:3000");
    let good_url = spawn_server(good_server).await;

    let client = BlossomClient::new(vec![bad_url, good_url], signer);

    let data = b"failover on 401";
    let desc = client.upload(data, "text/plain").await.unwrap();
    assert_eq!(desc.size, data.len() as u64);
}

#[tokio::test]
async fn test_client_download_failover_across_servers() {
    let signer = Signer::generate();

    // Server 1 has nothing, server 2 has the blob.
    let empty_server = BlobServer::new(MemoryBackend::new(), "http://localhost:3000");
    let empty_url = spawn_server(empty_server).await;

    let full_server = BlobServer::new(MemoryBackend::new(), "http://localhost:3000");
    let full_url = spawn_server(full_server).await;

    // Upload to server 2 directly.
    let http = reqwest::Client::new();
    let data = b"only on server 2";
    let resp = http
        .put(format!("{}/upload", full_url))
        .body(data.to_vec())
        .send()
        .await
        .unwrap();
    let desc: blossom_rs::BlobDescriptor = resp.json().await.unwrap();

    // Client tries server 1 (404), then server 2 (success).
    let client = BlossomClient::new(vec![empty_url, full_url], signer);
    let downloaded = client.download(&desc.sha256).await.unwrap();
    assert_eq!(downloaded, data);
}

// ---------------------------------------------------------------------------
// Concurrent uploads
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_concurrent_uploads() {
    let server = BlobServer::new(MemoryBackend::new(), "http://localhost:3000");
    let url = spawn_server(server).await;
    let http = reqwest::Client::new();

    // Spawn 20 concurrent uploads with different data.
    let mut handles = Vec::new();
    for i in 0u8..20 {
        let http = http.clone();
        let url = url.clone();
        handles.push(tokio::spawn(async move {
            let data = vec![i; 1000];
            let resp = http
                .put(format!("{}/upload", url))
                .body(data.clone())
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 200);
            let desc: blossom_rs::BlobDescriptor = resp.json().await.unwrap();
            assert_eq!(desc.size, 1000);
            assert_eq!(desc.sha256, sha256_hex(&data));
            desc.sha256
        }));
    }

    let mut hashes = std::collections::HashSet::new();
    for handle in handles {
        hashes.insert(handle.await.unwrap());
    }

    // All 20 should be unique (different data).
    assert_eq!(hashes.len(), 20);

    // Status should show all blobs.
    let resp = http.get(format!("{}/status", url)).send().await.unwrap();
    let status: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(status["blobs"], 20);
}

#[tokio::test]
async fn test_concurrent_upload_download() {
    let signer = Signer::generate();
    let server = BlobServer::new(MemoryBackend::new(), "http://localhost:3000");
    let url = spawn_server(server).await;

    let client = std::sync::Arc::new(BlossomClient::new(
        vec![url],
        Signer::from_secret_hex(&signer.secret_key_hex()).unwrap(),
    ));

    // Upload 10 blobs.
    let mut descs = Vec::new();
    for i in 0u8..10 {
        let data = vec![i; 500];
        let desc = client
            .upload(&data, "application/octet-stream")
            .await
            .unwrap();
        descs.push((desc.sha256.clone(), data));
    }

    // Download all 10 concurrently and verify.
    let mut handles = Vec::new();
    for (sha256, expected_data) in descs {
        let client = client.clone();
        handles.push(tokio::spawn(async move {
            let downloaded = client.download(&sha256).await.unwrap();
            assert_eq!(downloaded, expected_data);
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }
}

// ---------------------------------------------------------------------------
// Streaming upload tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn test_streaming_file_upload() {
    let signer = Signer::generate();
    let server = BlobServer::new(MemoryBackend::new(), "http://localhost:3000");
    let url = spawn_server(server).await;

    let client = BlossomClient::new(vec![url], signer);

    // Write a temp file.
    let tmp_dir =
        std::env::temp_dir().join(format!("blossom_stream_test_{}", rand::random::<u32>()));
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let tmp_file = tmp_dir.join("test_data.bin");
    let data: Vec<u8> = (0..50_000u32).map(|i| (i % 256) as u8).collect();
    let expected_hash = sha256_hex(&data);
    std::fs::write(&tmp_file, &data).unwrap();

    // Upload via streaming.
    let desc = client
        .upload_file(&tmp_file, "application/octet-stream")
        .await
        .unwrap();

    assert_eq!(desc.sha256, expected_hash);
    assert_eq!(desc.size, data.len() as u64);

    // Download and verify.
    let downloaded = client.download(&desc.sha256).await.unwrap();
    assert_eq!(downloaded, data);

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_batch_upload() {
    use std::sync::Arc;

    let signer = Signer::generate();
    let server = BlobServer::new(MemoryBackend::new(), "http://localhost:3000");
    let url = spawn_server(server).await;

    let client = Arc::new(BlossomClient::new(vec![url], signer));

    let tmp_dir =
        std::env::temp_dir().join(format!("blossom_batch_test_{}", rand::random::<u32>()));
    std::fs::create_dir_all(&tmp_dir).unwrap();

    let mut files = Vec::new();
    let mut expected_hashes = Vec::new();
    for i in 0..5 {
        let file = tmp_dir.join(format!("file_{i}.txt"));
        let data = format!("batch file {i} content");
        expected_hashes.push(sha256_hex(data.as_bytes()));
        std::fs::write(&file, &data).unwrap();
        files.push(file);
    }

    let results = blossom_rs::upload_batch_concurrent(client, &(), files, 3).await;

    assert_eq!(results.len(), 5);
    for (i, result) in results.iter().enumerate() {
        let desc = result.as_ref().unwrap();
        assert_eq!(desc.sha256, expected_hashes[i]);
    }

    let _ = std::fs::remove_dir_all(&tmp_dir);
}
