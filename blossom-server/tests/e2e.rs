//! End-to-end integration tests for blossom-server.
//!
//! Spins up an in-memory server and exercises all endpoints via HTTP
//! and the BlossomClient library.

use std::collections::HashSet;

use std::sync::Arc;

use blossom_rs::access::Whitelist;
use blossom_rs::auth::{auth_header_value, build_blossom_auth};
use blossom_rs::db::{MemoryDatabase, SqliteDatabase};
use blossom_rs::media::PassthroughProcessor;
use blossom_rs::protocol::BlobDescriptor;
use blossom_rs::ratelimit::{RateLimitConfig, RateLimiter};
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sqlite_server_lifecycle() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db_url = format!("sqlite:{}?mode=rwc", tmp.path().display());
    let db = SqliteDatabase::new(&db_url).await.unwrap();

    let server = BlobServer::builder(MemoryBackend::new(), "http://localhost:3000")
        .database(db)
        .build();
    let state = server.shared_state();
    let app = server.router().merge(nip96_router(state));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let signer = Signer::generate();
    let client = BlossomClient::new(
        vec![url.clone()],
        Signer::from_secret_hex(&signer.secret_key_hex()).unwrap(),
    );
    let http = reqwest::Client::new();

    // Upload.
    let data = b"sqlite e2e test blob";
    let desc = client.upload(data, "text/plain").await.unwrap();
    assert_eq!(desc.size, data.len() as u64);

    // Status should reflect 1 upload and 1 user (tracked in SQLite).
    let resp = http.get(format!("{}/status", url)).send().await.unwrap();
    let status: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(status["blobs"], 1);
    assert_eq!(status["uploads"], 1);
    assert_eq!(status["users"], 1);

    // List by pubkey (stored in SQLite).
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

    // Download and verify.
    let downloaded = client.download(&desc.sha256).await.unwrap();
    assert_eq!(downloaded, data);

    // Delete.
    let auth_event = build_blossom_auth(&signer, "delete", None, None, "");
    let auth_header = auth_header_value(&auth_event);
    let resp = http
        .delete(format!("{}/{}", url, desc.sha256))
        .header("Authorization", &auth_header)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Status after delete — upload record removed from SQLite.
    let resp = http.get(format!("{}/status", url)).send().await.unwrap();
    let status: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(status["blobs"], 0);
    assert_eq!(status["uploads"], 0);
}

#[tokio::test]
async fn test_health_endpoint() {
    let (url, _signer) = spawn_test_server().await;
    let http = reqwest::Client::new();

    let resp = http.get(format!("{}/health", url)).send().await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_cors_headers() {
    let server = BlobServer::new(MemoryBackend::new(), "http://localhost:3000");
    let state = server.shared_state();
    let cors = tower_http::cors::CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods(tower_http::cors::Any)
        .allow_headers(tower_http::cors::Any);
    let app = server.router().merge(nip96_router(state)).layer(cors);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let http = reqwest::Client::new();

    // Preflight OPTIONS.
    let resp = http
        .request(reqwest::Method::OPTIONS, format!("{}/status", url))
        .header("Origin", "https://example.com")
        .header("Access-Control-Request-Method", "GET")
        .send()
        .await
        .unwrap();
    assert!(resp.headers().contains_key("access-control-allow-origin"));

    // Regular request should have CORS header.
    let resp = http
        .get(format!("{}/status", url))
        .header("Origin", "https://example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.headers().get("access-control-allow-origin").unwrap(),
        "*"
    );
}

#[tokio::test]
async fn test_body_limit_configurable() {
    let server = BlobServer::builder(MemoryBackend::new(), "http://localhost:3000")
        .body_limit(50)
        .build();
    let state = server.shared_state();
    let app = server.router().merge(nip96_router(state));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let http = reqwest::Client::new();

    // 30 bytes should succeed.
    let resp = http
        .put(format!("{}/upload", url))
        .body(vec![0u8; 30])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // 100 bytes should be rejected by body limit (before our handler even runs).
    let resp = http
        .put(format!("{}/upload", url))
        .body(vec![0u8; 100])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 413);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_stats_flush_to_db() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db_url = format!("sqlite:{}?mode=rwc", tmp.path().display());
    let db = SqliteDatabase::new(&db_url).await.unwrap();

    let server = BlobServer::builder(MemoryBackend::new(), "http://localhost:3000")
        .database(db)
        .build();
    let state = server.shared_state();
    let app = server.router().merge(nip96_router(state.clone()));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let http = reqwest::Client::new();

    // Upload a blob.
    let resp = http
        .put(format!("{}/upload", url))
        .body(b"stats test".to_vec())
        .send()
        .await
        .unwrap();
    let desc: BlobDescriptor = resp.json().await.unwrap();

    // Download it to generate access stats.
    http.get(format!("{}/{}", url, desc.sha256))
        .send()
        .await
        .unwrap();

    // Stats should be tracked but not flushed yet.
    let resp = http.get(format!("{}/status", url)).send().await.unwrap();
    let status: serde_json::Value = resp.json().await.unwrap();
    assert!(status["tracked_stats"].as_u64().unwrap() >= 1);

    // Manually flush stats.
    {
        let mut s = state.lock().await;
        s.flush_stats();
    }

    // After flush, tracked stats should be 0.
    let resp = http.get(format!("{}/status", url)).send().await.unwrap();
    let status: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(status["tracked_stats"], 0);
}

#[tokio::test]
async fn test_whitelist_access_control() {
    let signer = Signer::generate();
    let allowed_pubkey = signer.public_key_hex();

    let mut keys = HashSet::new();
    keys.insert(allowed_pubkey.clone());
    let whitelist = Whitelist::new(keys);

    let server = BlobServer::builder(MemoryBackend::new(), "http://localhost:3000")
        .require_auth()
        .access_control(whitelist)
        .build();
    let state = server.shared_state();
    let app = server.router().merge(nip96_router(state));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let http = reqwest::Client::new();

    // Allowed signer should succeed.
    let data = b"whitelist allowed";
    let auth_event = build_blossom_auth(
        &signer,
        "upload",
        Some(&blossom_rs::protocol::sha256_hex(data)),
        None,
        "",
    );
    let auth_header = auth_header_value(&auth_event);
    let resp = http
        .put(format!("{}/upload", url))
        .header("Authorization", &auth_header)
        .body(data.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Unlisted signer should be rejected (403).
    let other_signer = Signer::generate();
    let data2 = b"whitelist blocked";
    let auth_event2 = build_blossom_auth(
        &other_signer,
        "upload",
        Some(&blossom_rs::protocol::sha256_hex(data2)),
        None,
        "",
    );
    let auth_header2 = auth_header_value(&auth_event2);
    let resp = http
        .put(format!("{}/upload", url))
        .header("Authorization", &auth_header2)
        .body(data2.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_media_upload_without_processor() {
    // Server without media processor should return 501.
    let (url, signer) = spawn_test_server().await;
    let http = reqwest::Client::new();

    let auth_event = build_blossom_auth(&signer, "upload", None, None, "");
    let auth_header = auth_header_value(&auth_event);

    let resp = http
        .put(format!("{}/media", url))
        .header("Authorization", &auth_header)
        .body(b"some data".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 501);
}

#[tokio::test]
async fn test_media_upload_with_processor() {
    let server = BlobServer::builder(MemoryBackend::new(), "http://localhost:3000")
        .media_processor(PassthroughProcessor)
        .build();
    let state = server.shared_state();
    let app = server.router().merge(nip96_router(state));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let http = reqwest::Client::new();
    let signer = Signer::generate();

    let auth_event = build_blossom_auth(&signer, "upload", None, None, "");
    let auth_header = auth_header_value(&auth_event);

    let resp = http
        .put(format!("{}/media", url))
        .header("Authorization", &auth_header)
        .body(b"media content".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["sha256"].is_string());
}

#[tokio::test]
async fn test_media_upload_requires_auth() {
    let server = BlobServer::builder(MemoryBackend::new(), "http://localhost:3000")
        .media_processor(PassthroughProcessor)
        .build();
    let state = server.shared_state();
    let app = server.router().merge(nip96_router(state));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let http = reqwest::Client::new();
    let resp = http
        .put(format!("{}/media", url))
        .body(b"no auth".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_rate_limiting() {
    let server = BlobServer::builder(MemoryBackend::new(), "http://localhost:3000")
        .rate_limiter(RateLimiter::new(RateLimitConfig {
            max_tokens: 2,
            refill_rate: 0.0, // No refill.
        }))
        .build();
    let state = server.shared_state();
    let app = server.router().merge(nip96_router(state));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let http = reqwest::Client::new();

    // First two should succeed.
    for _ in 0..2 {
        let resp = http
            .put(format!("{}/upload", url))
            .body(b"rate test".to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    // Third should be rate limited.
    let resp = http
        .put(format!("{}/upload", url))
        .body(b"rate test 3".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429);
}

#[tokio::test]
async fn test_nip98_auth_accepted() {
    let server = BlobServer::new_with_auth(MemoryBackend::new(), "http://localhost:3000");
    let state = server.shared_state();
    let app = server.router().merge(nip96_router(state));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let http = reqwest::Client::new();
    let signer = Signer::generate();

    // Use NIP-98 auth (kind:27235) instead of Blossom auth.
    let nip98_event =
        blossom_rs::auth::build_nip98_auth(&signer, &format!("{}/upload", url), "PUT");
    let auth_header = auth_header_value(&nip98_event);

    let resp = http
        .put(format!("{}/upload", url))
        .header("Authorization", &auth_header)
        .body(b"nip98 upload".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["sha256"].is_string());
}
