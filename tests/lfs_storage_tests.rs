//! Integration tests for BUD-20: LFS-aware storage efficiency.

use blossom_rs::auth::{auth_header_value, build_blossom_auth, Signer};
use blossom_rs::lfs::{LfsContext, LfsVersionDatabase};
use blossom_rs::server::BlobServer;
use blossom_rs::storage::MemoryBackend;
use blossom_rs::{BlossomSigner, MemoryDatabase, MemoryLfsVersionDatabase};

fn lfs_server() -> BlobServer {
    BlobServer::builder(MemoryBackend::new(), "http://localhost:3000")
        .database(MemoryDatabase::new())
        .require_auth()
        .lfs_version_database(MemoryLfsVersionDatabase::new())
        .build()
}

async fn spawn(server: BlobServer) -> String {
    let app = server.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    url
}

fn lfs_upload_auth(signer: &Signer, sha256: &str, lfs_ctx: &LfsContext) -> String {
    let mut tags = vec![vec!["t".into(), "upload".into()]];
    if lfs_ctx.is_lfs {
        tags.push(vec!["t".into(), "lfs".into()]);
    }
    if let Some(ref path) = lfs_ctx.path {
        tags.push(vec!["path".into(), path.clone()]);
    }
    if let Some(ref repo) = lfs_ctx.repo {
        tags.push(vec!["repo".into(), repo.clone()]);
    }
    if let Some(ref base) = lfs_ctx.base {
        tags.push(vec!["base".into(), base.clone()]);
    }
    if lfs_ctx.is_manifest {
        tags.push(vec!["manifest".into()]);
    }

    let pubkey = signer.public_key_hex();
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expiration = created_at + 60;
    tags.push(vec!["x".into(), sha256.to_string()]);
    tags.push(vec!["expiration".into(), expiration.to_string()]);

    let id_bytes = blossom_rs::protocol::compute_event_id(&pubkey, created_at, 24242, &tags, "");
    let id = hex::encode(id_bytes);
    let sig = signer.sign_schnorr(&id_bytes);

    let event = blossom_rs::NostrEvent {
        id,
        pubkey,
        created_at,
        kind: 24242,
        tags,
        content: String::new(),
        sig,
    };

    auth_header_value(&event)
}

#[tokio::test]
async fn test_lfs_upload_and_download_compressed() {
    let server = lfs_server();
    let url = spawn(server).await;
    let signer = Signer::generate();
    let http = reqwest::Client::new();

    let data = vec![42u8; 10_000];
    let sha256 = blossom_rs::protocol::sha256_hex(&data);

    let ctx = LfsContext {
        is_lfs: true,
        path: Some("model.bin".into()),
        repo: Some("github.com/org/repo".into()),
        ..Default::default()
    };
    let auth = lfs_upload_auth(&signer, &sha256, &ctx);

    let resp = http
        .put(format!("{}/upload", url))
        .header("Authorization", auth)
        .header("Content-Type", "application/octet-stream")
        .body(data.clone())
        .send()
        .await
        .unwrap();

    let status = resp.status();
    if status != 200 {
        let body = resp.text().await.unwrap();
        panic!("Upload failed with status {}: {}", status, body);
    }
    let desc: blossom_rs::BlobDescriptor = resp.json().await.unwrap();
    assert_eq!(desc.sha256, sha256);
    assert_eq!(desc.size, 10_000);

    // Download and verify
    let get_auth = build_blossom_auth(&signer, "get", None, None, "");
    let resp = http
        .get(format!("{}/{}", url, sha256))
        .header("Authorization", auth_header_value(&get_auth))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.len(), 10_000);
    assert_eq!(blossom_rs::protocol::sha256_hex(&body), sha256);
}

#[tokio::test]
async fn test_lfs_delta_upload_and_download() {
    let server = lfs_server();
    let url = spawn(server).await;
    let signer = Signer::generate();
    let http = reqwest::Client::new();

    // Upload v1 (compressed)
    let v1_data: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
    let v1_sha = blossom_rs::protocol::sha256_hex(&v1_data);

    let ctx_v1 = LfsContext {
        is_lfs: true,
        path: Some("model.bin".into()),
        repo: Some("github.com/org/repo".into()),
        ..Default::default()
    };
    let auth_v1 = lfs_upload_auth(&signer, &v1_sha, &ctx_v1);

    let resp = http
        .put(format!("{}/upload", url))
        .header("Authorization", auth_v1)
        .header("Content-Type", "application/octet-stream")
        .body(v1_data.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Upload v2 with base=v1 (delta)
    let mut v2_data = v1_data.clone();
    v2_data[5000..5010]
        .copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x13, 0x37]);
    let v2_sha = blossom_rs::protocol::sha256_hex(&v2_data);

    let ctx_v2 = LfsContext {
        is_lfs: true,
        path: Some("model.bin".into()),
        repo: Some("github.com/org/repo".into()),
        base: Some(v1_sha.clone()),
        ..Default::default()
    };
    let auth_v2 = lfs_upload_auth(&signer, &v2_sha, &ctx_v2);

    let resp = http
        .put(format!("{}/upload", url))
        .header("Authorization", auth_v2)
        .header("Content-Type", "application/octet-stream")
        .body(v2_data.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let desc: blossom_rs::BlobDescriptor = resp.json().await.unwrap();
    assert_eq!(desc.sha256, v2_sha);

    // Download v2 and verify roundtrip
    let get_auth = build_blossom_auth(&signer, "get", None, None, "");
    let resp = http
        .get(format!("{}/{}", url, v2_sha))
        .header("Authorization", auth_header_value(&get_auth))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.len(), v2_data.len());
    assert_eq!(
        blossom_rs::protocol::sha256_hex(&body),
        v2_sha,
        "downloaded v2 content hash mismatch"
    );
    assert_eq!(&body[..], &v2_data[..]);
}

#[tokio::test]
async fn test_non_lfs_upload_unchanged() {
    let server = lfs_server();
    let url = spawn(server).await;
    let signer = Signer::generate();
    let http = reqwest::Client::new();

    let data = vec![42u8; 1000];
    let sha256 = blossom_rs::protocol::sha256_hex(&data);

    let auth = build_blossom_auth(&signer, "upload", Some(&sha256), None, "");
    let auth_header = auth_header_value(&auth);

    let resp = http
        .put(format!("{}/upload", url))
        .header("Authorization", auth_header)
        .header("Content-Type", "application/octet-stream")
        .body(data.clone())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let desc: blossom_rs::BlobDescriptor = resp.json().await.unwrap();
    assert_eq!(desc.sha256, sha256);

    let get_auth = build_blossom_auth(&signer, "get", None, None, "");
    let resp = http
        .get(format!("{}/{}", url, sha256))
        .header("Authorization", auth_header_value(&get_auth))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    assert_eq!(&body[..], &data[..]);
}

#[tokio::test]
async fn test_lfs_manifest_stored_raw() {
    let server = lfs_server();
    let url = spawn(server).await;
    let signer = Signer::generate();
    let http = reqwest::Client::new();

    let manifest = r#"{"version":"1.0","file_size":1000,"chunks":1}"#;
    let data = manifest.as_bytes().to_vec();
    let sha256 = blossom_rs::protocol::sha256_hex(&data);

    let ctx = LfsContext {
        is_lfs: true,
        is_manifest: true,
        path: Some("model.bin".into()),
        repo: Some("github.com/org/repo".into()),
        ..Default::default()
    };
    let auth = lfs_upload_auth(&signer, &sha256, &ctx);

    let resp = http
        .put(format!("{}/upload", url))
        .header("Authorization", auth)
        .header("Content-Type", "application/json")
        .body(data.clone())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let desc: blossom_rs::BlobDescriptor = resp.json().await.unwrap();
    assert_eq!(desc.sha256, sha256);

    // Download and verify raw content
    let get_auth = build_blossom_auth(&signer, "get", None, None, "");
    let resp = http
        .get(format!("{}/{}", url, sha256))
        .header("Authorization", auth_header_value(&get_auth))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    assert_eq!(&body[..], manifest.as_bytes());
}

#[tokio::test]
async fn test_lfs_version_tracking() {
    let server = lfs_server();
    let url = spawn(server).await;
    let signer = Signer::generate();
    let http = reqwest::Client::new();

    let v1 = vec![1u8; 5000];
    let v1_sha = blossom_rs::protocol::sha256_hex(&v1);

    let ctx = LfsContext {
        is_lfs: true,
        path: Some("data.bin".into()),
        repo: Some("github.com/test/repo".into()),
        ..Default::default()
    };
    let auth = lfs_upload_auth(&signer, &v1_sha, &ctx);
    let resp = http
        .put(format!("{}/upload", url))
        .header("Authorization", auth)
        .header("Content-Type", "application/octet-stream")
        .body(v1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_lfs_head_returns_original_size() {
    let server = lfs_server();
    let url = spawn(server).await;
    let signer = Signer::generate();
    let http = reqwest::Client::new();

    let data = vec![42u8; 10_000];
    let sha256 = blossom_rs::protocol::sha256_hex(&data);

    let ctx = LfsContext {
        is_lfs: true,
        path: Some("model.bin".into()),
        repo: Some("github.com/org/repo".into()),
        ..Default::default()
    };
    let auth = lfs_upload_auth(&signer, &sha256, &ctx);

    http.put(format!("{}/upload", url))
        .header("Authorization", auth)
        .header("Content-Type", "application/octet-stream")
        .body(data)
        .send()
        .await
        .unwrap();

    let get_auth = build_blossom_auth(&signer, "get", None, None, "");
    let resp = http
        .head(format!("{}/{}", url, sha256))
        .header("Authorization", auth_header_value(&get_auth))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let content_length: u64 = resp
        .headers()
        .get("content-length")
        .unwrap()
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(content_length, 10_000);
}
