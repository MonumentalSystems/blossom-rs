//! End-to-end integration tests for blossom-server.
//!
//! Spins up an in-memory server and exercises all endpoints via HTTP
//! and the BlossomClient library.

use blossom_rs::auth::{auth_header_value, build_blossom_auth};
use blossom_rs::db::MemoryDatabase;
use blossom_rs::protocol::BlobDescriptor;
use blossom_rs::server::nip96::nip96_router;
use blossom_rs::{BlobServer, BlossomClient, BlossomSigner, MemoryBackend, Signer};

async fn spawn_test_server() -> (String, Signer) {
    let server = BlobServer::new(MemoryBackend::new(), "http://localhost:3000");
    let state = server.shared_state();
    let app = server.router().merge(nip96_router(state));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let signer = Signer::generate();
    (url, signer)
}

#[tokio::test]
async fn test_full_lifecycle() {
    let (url, signer) = spawn_test_server().await;
    let client = BlossomClient::new(
        vec![url.clone()],
        Signer::from_secret_hex(&signer.secret_key_hex()).unwrap(),
    );
    let http = reqwest::Client::new();

    // 1. Status — empty server.
    let resp = http.get(format!("{}/status", url)).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let status: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(status["blobs"], 0);

    // 2. Upload via client library.
    let data = b"integration test blob data";
    let desc = client.upload(data, "text/plain").await.unwrap();
    assert_eq!(desc.size, data.len() as u64);
    assert!(desc.sha256.len() == 64);

    // 3. Download and verify integrity.
    let downloaded = client.download(&desc.sha256).await.unwrap();
    assert_eq!(downloaded, data);

    // 4. Exists check.
    assert!(client.exists(&desc.sha256).await.unwrap());
    assert!(!client.exists(&"0".repeat(64)).await.unwrap());

    // 5. Status — should have 1 blob.
    let resp = http.get(format!("{}/status", url)).send().await.unwrap();
    let status: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(status["blobs"], 1);
    assert_eq!(status["uploads"], 1);

    // 6. List by pubkey.
    let pubkey = signer.public_key_hex();
    let resp = http
        .get(format!("{}/list/{}", url, pubkey))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let list: Vec<BlobDescriptor> = resp.json().await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].sha256, desc.sha256);

    // 7. Delete with auth.
    let auth_event = build_blossom_auth(&signer, "delete", None, None, "");
    let auth_header = auth_header_value(&auth_event);
    let resp = http
        .delete(format!("{}/{}", url, desc.sha256))
        .header("Authorization", &auth_header)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // 8. Verify deleted.
    assert!(!client.exists(&desc.sha256).await.unwrap());

    // 9. Status — back to 0.
    let resp = http.get(format!("{}/status", url)).send().await.unwrap();
    let status: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(status["blobs"], 0);
}

#[tokio::test]
async fn test_mirror_endpoint() {
    let (source_url, source_signer) = spawn_test_server().await;
    let (dest_url, dest_signer) = spawn_test_server().await;

    // Upload to source.
    let source_client = BlossomClient::new(
        vec![source_url.clone()],
        Signer::from_secret_hex(&source_signer.secret_key_hex()).unwrap(),
    );
    let data = b"mirror this blob";
    let desc = source_client.upload(data, "text/plain").await.unwrap();

    // Mirror from source to dest.
    let http = reqwest::Client::new();
    let auth_event = build_blossom_auth(&dest_signer, "upload", None, None, "");
    let auth_header = auth_header_value(&auth_event);
    let resp = http
        .put(format!("{}/mirror", dest_url))
        .header("Authorization", &auth_header)
        .json(&serde_json::json!({"url": format!("{}/{}", source_url, desc.sha256)}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let mirrored: BlobDescriptor = resp.json().await.unwrap();
    assert_eq!(mirrored.sha256, desc.sha256);

    // Verify it's on dest.
    let dest_client = BlossomClient::new(
        vec![dest_url],
        Signer::from_secret_hex(&dest_signer.secret_key_hex()).unwrap(),
    );
    let downloaded = dest_client.download(&desc.sha256).await.unwrap();
    assert_eq!(downloaded, data);
}

#[tokio::test]
async fn test_nip96_endpoints() {
    let (url, signer) = spawn_test_server().await;
    let http = reqwest::Client::new();

    // NIP-96 info.
    let resp = http
        .get(format!("{}/.well-known/nostr/nip96.json", url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let info: serde_json::Value = resp.json().await.unwrap();
    assert!(info["api_url"].as_str().unwrap().contains("/n96"));

    // NIP-96 upload.
    let data = b"nip96 e2e test";
    let auth_event = build_blossom_auth(
        &signer,
        "upload",
        Some(&blossom_rs::protocol::sha256_hex(data)),
        None,
        "",
    );
    let auth_header = auth_header_value(&auth_event);
    let resp = http
        .post(format!("{}/n96", url))
        .header("Authorization", &auth_header)
        .body(data.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "success");

    // NIP-96 list.
    let list_event = build_blossom_auth(&signer, "get", None, None, "");
    let list_header = auth_header_value(&list_event);
    let resp = http
        .get(format!("{}/n96", url))
        .header("Authorization", &list_header)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["total"], 1);
}

#[tokio::test]
async fn test_upload_requirements() {
    let server = BlobServer::builder(MemoryBackend::new(), "http://localhost:3000")
        .database(MemoryDatabase::new())
        .require_auth()
        .max_upload_size(100)
        .build();
    let state = server.shared_state();
    let app = server.router().merge(nip96_router(state));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let http = reqwest::Client::new();

    // Check requirements.
    let resp = http
        .get(format!("{}/upload-requirements", url))
        .send()
        .await
        .unwrap();
    let reqs: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(reqs["require_auth"], true);
    assert_eq!(reqs["max_size"], 100);

    // Upload without auth should fail.
    let resp = http
        .put(format!("{}/upload", url))
        .body(b"no auth".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Upload over size limit with auth should fail.
    let signer = Signer::generate();
    let auth_event = build_blossom_auth(&signer, "upload", None, None, "");
    let auth_header = auth_header_value(&auth_event);
    let resp = http
        .put(format!("{}/upload", url))
        .header("Authorization", &auth_header)
        .body(vec![0u8; 200])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 413);
}

#[tokio::test]
async fn test_multiple_uploads_and_dedup() {
    let (url, signer) = spawn_test_server().await;
    let client = BlossomClient::new(
        vec![url.clone()],
        Signer::from_secret_hex(&signer.secret_key_hex()).unwrap(),
    );

    // Upload same content twice.
    let data = b"dedup test data";
    let desc1 = client.upload(data, "text/plain").await.unwrap();
    let desc2 = client.upload(data, "text/plain").await.unwrap();
    assert_eq!(desc1.sha256, desc2.sha256);

    // Should still be 1 blob.
    let http = reqwest::Client::new();
    let resp = http.get(format!("{}/status", url)).send().await.unwrap();
    let status: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(status["blobs"], 1);
}
