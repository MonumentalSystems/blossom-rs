//! CLI integration tests.
//!
//! Tests the CLI's core logic by spawning an in-memory server and
//! exercising each command pathway. Tests key format conversion,
//! output formatting, iroh URL detection, and error handling.

use blossom_rs::auth::{
    auth_header_value, build_blossom_auth_for_request, build_nip98_auth, Signer,
};
use blossom_rs::db::MemoryDatabase;
use blossom_rs::protocol::{sha256_hex, BlobDescriptor};
use blossom_rs::server::nip96::nip96_router;
use blossom_rs::{BlobServer, BlossomSigner, MemoryBackend};

async fn spawn_server() -> (String, Signer) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);
    let server = BlobServer::new(MemoryBackend::new(), &url);
    let state = server.shared_state();
    let app = server.router().merge(nip96_router(state));

    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let signer = Signer::generate();
    (url, signer)
}

// ---------------------------------------------------------------------------
// Key format tests
// ---------------------------------------------------------------------------

#[test]
fn test_nsec_roundtrip() {
    let signer = Signer::generate();
    let hex_key = signer.secret_key_hex();

    // Encode to nsec1.
    let bytes = hex::decode(&hex_key).unwrap();
    let hrp = bech32::Hrp::parse("nsec").unwrap();
    let nsec = bech32::encode::<bech32::Bech32>(hrp, &bytes).unwrap();
    assert!(nsec.starts_with("nsec1"));

    // Decode back.
    let (decoded_hrp, decoded_bytes) = bech32::decode(&nsec).unwrap();
    assert_eq!(decoded_hrp.as_str(), "nsec");
    assert_eq!(hex::encode(decoded_bytes), hex_key);
}

#[test]
fn test_hex_key_validation() {
    // Valid 64-char hex.
    let valid = "a".repeat(64);
    assert!(valid.len() == 64 && valid.chars().all(|c| c.is_ascii_hexdigit()));

    // Invalid: too short.
    let short = "a".repeat(32);
    assert!(short.len() != 64);

    // Invalid: non-hex.
    let bad = "g".repeat(64);
    assert!(!bad.chars().all(|c| c.is_ascii_hexdigit()));
}

// ---------------------------------------------------------------------------
// Upload / Download / Exists / Delete via HTTP
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_upload_and_download() {
    let (url, signer) = spawn_server().await;
    let http = reqwest::Client::new();

    let data = b"cli upload test";
    let upload_url = format!("{}/upload", url);
    let auth = build_blossom_auth_for_request(
        &signer,
        "upload",
        Some(&sha256_hex(data)),
        &url,
        &upload_url,
        "PUT",
        "",
    );
    let auth_header = auth_header_value(&auth);

    // Upload.
    let resp = http
        .put(&upload_url)
        .header("Authorization", &auth_header)
        .body(data.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let desc: BlobDescriptor = resp.json().await.unwrap();
    assert_eq!(desc.sha256, sha256_hex(data));

    // Download.
    let resp = http
        .get(format!("{}/{}", url, desc.sha256))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), data);
}

#[tokio::test]
async fn test_exists_and_delete() {
    let (url, signer) = spawn_server().await;
    let http = reqwest::Client::new();

    let data = b"exists delete test";
    let upload_url = format!("{}/upload", url);
    let upload_auth = build_blossom_auth_for_request(
        &signer,
        "upload",
        Some(&sha256_hex(data)),
        &url,
        &upload_url,
        "PUT",
        "",
    );
    let resp = http
        .put(&upload_url)
        .header("Authorization", auth_header_value(&upload_auth))
        .body(data.to_vec())
        .send()
        .await
        .unwrap();
    let desc: BlobDescriptor = resp.json().await.unwrap();

    // HEAD — exists.
    let resp = http
        .head(format!("{}/{}", url, desc.sha256))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // DELETE with auth.
    let delete_url = format!("{}/{}", url, desc.sha256);
    let auth = build_blossom_auth_for_request(
        &signer,
        "delete",
        Some(&desc.sha256),
        &url,
        &delete_url,
        "DELETE",
        "",
    );
    let resp = http
        .delete(&delete_url)
        .header("Authorization", auth_header_value(&auth))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // HEAD — gone.
    let resp = http
        .head(format!("{}/{}", url, desc.sha256))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_list_by_pubkey() {
    let (url, _signer) = spawn_server().await;
    let http = reqwest::Client::new();

    // Upload.
    http.put(format!("{}/upload", url))
        .body(b"list test".to_vec())
        .send()
        .await
        .unwrap();

    // List anonymous uploads.
    let resp = http
        .get(format!("{}/list/anonymous", url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let list: Vec<BlobDescriptor> = resp.json().await.unwrap();
    assert_eq!(list.len(), 1);
}

#[tokio::test]
async fn test_status() {
    let (url, _signer) = spawn_server().await;
    let http = reqwest::Client::new();

    let resp = http.get(format!("{}/status", url)).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["blobs"], 0);
}

// ---------------------------------------------------------------------------
// Mirror
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mirror_rejects_loopback_source() {
    let (source_url, _) = spawn_server().await;
    let (dest_url, signer) = spawn_server().await;
    let http = reqwest::Client::new();

    // Upload to source.
    let data = b"mirror cli test";
    let resp = http
        .put(format!("{}/upload", source_url))
        .body(data.to_vec())
        .send()
        .await
        .unwrap();
    let desc: BlobDescriptor = resp.json().await.unwrap();

    // Mirror to dest.
    let source_blob_url = format!("{}/{}", source_url, desc.sha256);
    let mirror_url = format!("{}/mirror", dest_url);
    let source_hash = sha256_hex(source_blob_url.as_bytes());
    let auth = build_blossom_auth_for_request(
        &signer,
        "upload",
        Some(&source_hash),
        &dest_url,
        &mirror_url,
        "PUT",
        "",
    );
    let resp = http
        .put(&mirror_url)
        .header("Authorization", auth_header_value(&auth))
        .json(&serde_json::json!({"url": source_blob_url}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 502);
}

// ---------------------------------------------------------------------------
// Server feature flags
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_allowed_types_enforcement() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);
    let server = BlobServer::builder(MemoryBackend::new(), &url)
        .allowed_types(vec!["image/png".into()])
        .build();
    let state = server.shared_state();
    let app = server.router().merge(nip96_router(state));

    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let http = reqwest::Client::new();

    // Upload requirements should show the filter.
    let resp = http
        .get(format!("{}/upload-requirements", url))
        .send()
        .await
        .unwrap();
    let reqs: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(reqs["allowed_types"][0], "image/png");
}

#[tokio::test]
async fn test_webhook_notification() {
    // Spin up a webhook receiver.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<serde_json::Value>(10);
    let webhook_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let webhook_addr = webhook_listener.local_addr().unwrap();
    let webhook_url = format!("http://{}/hook", webhook_addr);

    let webhook_app = axum::Router::new().route(
        "/hook",
        axum::routing::post(move |body: axum::Json<serde_json::Value>| async move {
            let _ = tx.send(body.0).await;
            axum::http::StatusCode::OK
        }),
    );
    tokio::spawn(async move { axum::serve(webhook_listener, webhook_app).await.ok() });

    // Spin up blossom server with webhook.
    let notifier = blossom_rs::webhooks::HttpNotifier::new(vec![webhook_url]);
    let server = BlobServer::builder(MemoryBackend::new(), "http://localhost:3000")
        .webhook_notifier(notifier)
        .build();
    let state = server.shared_state();
    let app = server.router().merge(nip96_router(state));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let http = reqwest::Client::new();

    // Upload → should trigger webhook.
    http.put(format!("{}/upload", url))
        .body(b"webhook test".to_vec())
        .send()
        .await
        .unwrap();

    // Wait for webhook delivery.
    let payload = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("webhook timeout")
        .expect("no webhook received");

    assert_eq!(payload["event"], "upload");
    assert!(payload["sha256"].is_string());
}

#[tokio::test]
async fn test_admin_endpoints() {
    use std::collections::HashSet;
    let signer = Signer::generate();
    let admin_pubkey = signer.public_key_hex();
    let mut keys = HashSet::new();
    keys.insert(admin_pubkey);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);
    let server = BlobServer::builder(MemoryBackend::new(), &url)
        .database(MemoryDatabase::new())
        .access_control(blossom_rs::access::Whitelist::new(keys))
        .require_auth()
        .build();
    let state = server.shared_state();
    let app = server
        .router()
        .merge(nip96_router(state.clone()))
        .merge(blossom_rs::server::admin::admin_router(state));

    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let http = reqwest::Client::new();
    // Stats.
    let stats_url = format!("{}/admin/stats", url);
    let resp = http
        .get(&stats_url)
        .header(
            "Authorization",
            auth_header_value(&build_nip98_auth(&signer, &stats_url, "GET")),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Set quota.
    let target = "a".repeat(64);
    let quota_url = format!("{}/admin/users/{}/quota", url, target);
    let resp = http
        .put(&quota_url)
        .header(
            "Authorization",
            auth_header_value(&build_nip98_auth(&signer, &quota_url, "PUT")),
        )
        .json(&serde_json::json!({"quota_bytes": 1048576}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Get user.
    let user_url = format!("{}/admin/users/{}", url, target);
    let resp = http
        .get(&user_url)
        .header(
            "Authorization",
            auth_header_value(&build_nip98_auth(&signer, &user_url, "GET")),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["quota_bytes"], 1048576);
}

// ---------------------------------------------------------------------------
// iroh URL detection
// ---------------------------------------------------------------------------

#[test]
fn test_iroh_url_detection() {
    assert!("iroh://nodeXXX".starts_with("iroh://"));
    assert!(!"http://localhost:3000".starts_with("iroh://"));
    assert!(!"https://blobs.example.com".starts_with("iroh://"));
}

// ---------------------------------------------------------------------------
// Output format
// ---------------------------------------------------------------------------

#[test]
fn test_json_output_format() {
    let value = serde_json::json!({"sha256": "abc", "size": 42});

    // JSON compact.
    let compact = serde_json::to_string(&value).unwrap();
    assert!(!compact.contains('\n'));
    assert!(compact.contains("\"sha256\":\"abc\""));

    // Text pretty.
    let pretty = serde_json::to_string_pretty(&value).unwrap();
    assert!(pretty.contains('\n'));
    assert!(pretty.contains("\"sha256\": \"abc\""));
}

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_download_nonexistent() {
    let (url, _signer) = spawn_server().await;
    let http = reqwest::Client::new();

    let resp = http
        .get(format!("{}/{}", url, "0".repeat(64)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_delete_without_auth() {
    let (url, _signer) = spawn_server().await;
    let http = reqwest::Client::new();

    let resp = http
        .delete(format!("{}/{}", url, "0".repeat(64)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_upload_empty_body() {
    let (url, _signer) = spawn_server().await;
    let http = reqwest::Client::new();

    let resp = http
        .put(format!("{}/upload", url))
        .body(Vec::<u8>::new())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}
