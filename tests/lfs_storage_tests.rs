//! Integration tests for BUD-20: LFS-aware storage efficiency.

use blossom_rs::auth::{
    auth_header_value, build_blossom_auth_for_request,
    build_blossom_auth_for_request_with_extra_tags, Signer,
};
use blossom_rs::lfs::LfsContext;
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
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);
    server.shared_state().lock().await.set_base_url(url.clone());
    let app = server.router();
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    url
}

fn lfs_upload_auth(
    signer: &Signer,
    sha256: &str,
    lfs_ctx: &LfsContext,
    server_url: &str,
) -> String {
    let mut tags = Vec::new();
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

    let event = build_blossom_auth_for_request_with_extra_tags(
        signer,
        "upload",
        Some(sha256),
        server_url,
        &format!("{server_url}/upload"),
        "PUT",
        "",
        &tags,
    );

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
    let auth = lfs_upload_auth(&signer, &sha256, &ctx, &url);

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
    let get_auth = build_blossom_auth_for_request(
        &signer,
        "get",
        None,
        &url,
        &format!("{url}/{sha256}"),
        "GET",
        "",
    );
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
    let auth_v1 = lfs_upload_auth(&signer, &v1_sha, &ctx_v1, &url);

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
    let auth_v2 = lfs_upload_auth(&signer, &v2_sha, &ctx_v2, &url);

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
    let get_auth = build_blossom_auth_for_request(
        &signer,
        "get",
        None,
        &url,
        &format!("{url}/{v2_sha}"),
        "GET",
        "",
    );
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

    let auth = build_blossom_auth_for_request(
        &signer,
        "upload",
        Some(&sha256),
        &url,
        &format!("{url}/upload"),
        "PUT",
        "",
    );
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

    let get_auth = build_blossom_auth_for_request(
        &signer,
        "get",
        None,
        &url,
        &format!("{url}/{sha256}"),
        "GET",
        "",
    );
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
    let auth = lfs_upload_auth(&signer, &sha256, &ctx, &url);

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
    let get_auth = build_blossom_auth_for_request(
        &signer,
        "get",
        None,
        &url,
        &format!("{url}/{sha256}"),
        "GET",
        "",
    );
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
    let auth = lfs_upload_auth(&signer, &v1_sha, &ctx, &url);
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
    let auth = lfs_upload_auth(&signer, &sha256, &ctx, &url);

    http.put(format!("{}/upload", url))
        .header("Authorization", auth)
        .header("Content-Type", "application/octet-stream")
        .body(data)
        .send()
        .await
        .unwrap();

    let get_auth = build_blossom_auth_for_request(
        &signer,
        "get",
        None,
        &url,
        &format!("{url}/{sha256}"),
        "GET",
        "",
    );
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

#[tokio::test]
async fn test_lfs_delete_rebases_delta() {
    let server = lfs_server();
    let url = spawn(server).await;
    let signer = Signer::generate();
    let http = reqwest::Client::new();

    let v1_data = vec![0x42u8; 10_000];
    let v1_sha = blossom_rs::protocol::sha256_hex(&v1_data);

    let ctx_v1 = LfsContext {
        is_lfs: true,
        path: Some("model.bin".into()),
        repo: Some("github.com/org/repo".into()),
        ..Default::default()
    };
    let auth_v1 = lfs_upload_auth(&signer, &v1_sha, &ctx_v1, &url);
    let resp = http
        .put(format!("{}/upload", url))
        .header("Authorization", auth_v1)
        .header("Content-Type", "application/octet-stream")
        .body(v1_data.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let mut v2_data = v1_data.clone();
    v2_data[5000] = 0xFF;
    let v2_sha = blossom_rs::protocol::sha256_hex(&v2_data);

    let ctx_v2 = LfsContext {
        is_lfs: true,
        path: Some("model.bin".into()),
        repo: Some("github.com/org/repo".into()),
        base: Some(v1_sha.clone()),
        ..Default::default()
    };
    let auth_v2 = lfs_upload_auth(&signer, &v2_sha, &ctx_v2, &url);
    let resp = http
        .put(format!("{}/upload", url))
        .header("Authorization", auth_v2)
        .header("Content-Type", "application/octet-stream")
        .body(v2_data.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let get_auth = build_blossom_auth_for_request(
        &signer,
        "get",
        None,
        &url,
        &format!("{url}/{v2_sha}"),
        "GET",
        "",
    );
    let resp = http
        .get(format!("{}/{}", url, v2_sha))
        .header("Authorization", auth_header_value(&get_auth))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    assert_eq!(&body[..], &v2_data[..], "v2 mismatch before delete");

    let delete_auth = build_blossom_auth_for_request(
        &signer,
        "delete",
        Some(&v1_sha),
        &url,
        &format!("{url}/{v1_sha}"),
        "DELETE",
        "",
    );
    let resp = http
        .delete(format!("{}/{}", url, v1_sha))
        .header("Authorization", auth_header_value(&delete_auth))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let get_auth = build_blossom_auth_for_request(
        &signer,
        "get",
        None,
        &url,
        &format!("{url}/{v2_sha}"),
        "GET",
        "",
    );
    let resp = http
        .get(format!("{}/{}", url, v2_sha))
        .header("Authorization", auth_header_value(&get_auth))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    assert_eq!(&body[..], &v2_data[..], "v2 mismatch after delete");
}

#[tokio::test]
async fn test_lfs_delta_chain_max_depth() {
    let server = lfs_server();
    let url = spawn(server).await;
    let signer = Signer::generate();
    let http = reqwest::Client::new();

    let mut prev_data: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
    let prev_sha = blossom_rs::protocol::sha256_hex(&prev_data);

    let ctx_v1 = LfsContext {
        is_lfs: true,
        path: Some("model.bin".into()),
        repo: Some("github.com/org/repo".into()),
        ..Default::default()
    };
    let auth_v1 = lfs_upload_auth(&signer, &prev_sha, &ctx_v1, &url);
    let resp = http
        .put(format!("{}/upload", url))
        .header("Authorization", auth_v1)
        .header("Content-Type", "application/octet-stream")
        .body(prev_data.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let mut prev_sha = prev_sha;

    for i in 2..=11u8 {
        let mut new_data = prev_data.clone();
        new_data[i as usize * 100] = 0xFF;
        let new_sha = blossom_rs::protocol::sha256_hex(&new_data);

        let ctx = LfsContext {
            is_lfs: true,
            path: Some("model.bin".into()),
            repo: Some("github.com/org/repo".into()),
            base: Some(prev_sha.clone()),
            ..Default::default()
        };
        let auth = lfs_upload_auth(&signer, &new_sha, &ctx, &url);
        let resp = http
            .put(format!("{}/upload", url))
            .header("Authorization", auth)
            .header("Content-Type", "application/octet-stream")
            .body(new_data.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "upload v{} failed", i);

        prev_data = new_data;
        prev_sha = new_sha;
    }

    let get_auth = build_blossom_auth_for_request(
        &signer,
        "get",
        None,
        &url,
        &format!("{url}/{prev_sha}"),
        "GET",
        "",
    );
    let resp = http
        .get(format!("{}/{}", url, prev_sha))
        .header("Authorization", auth_header_value(&get_auth))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    assert_eq!(&body[..], &prev_data[..], "v11 content mismatch");
}

#[tokio::test]
async fn test_auth_expired_event_rejected() {
    let server = lfs_server();
    let url = spawn(server).await;
    let signer = Signer::generate();
    let http = reqwest::Client::new();

    let data = vec![42u8; 1000];
    let sha256 = blossom_rs::protocol::sha256_hex(&data);

    let pubkey = signer.public_key_hex();
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expiration = created_at - 30;
    let tags = vec![
        vec!["t".into(), "upload".into()],
        vec!["x".into(), sha256.clone()],
        vec!["server".into(), url.clone()],
        vec!["u".into(), format!("{url}/upload")],
        vec!["method".into(), "PUT".into()],
        vec!["nonce".into(), uuid::Uuid::new_v4().to_string()],
        vec!["expiration".into(), expiration.to_string()],
    ];
    let id_bytes = blossom_rs::protocol::compute_event_id(&pubkey, created_at, 24242, &tags, "");
    let id = hex::encode(id_bytes);
    let sig = signer.sign_schnorr(&id_bytes);
    let expired_event = blossom_rs::NostrEvent {
        id,
        pubkey,
        created_at,
        kind: 24242,
        tags,
        content: String::new(),
        sig,
    };

    let expired_auth = auth_header_value(&expired_event);
    let resp = http
        .put(format!("{}/upload", url))
        .header("Authorization", expired_auth)
        .header("Content-Type", "application/octet-stream")
        .body(data.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "expired auth should be rejected");

    let valid_auth = build_blossom_auth_for_request(
        &signer,
        "upload",
        Some(&sha256),
        &url,
        &format!("{url}/upload"),
        "PUT",
        "",
    );
    let resp = http
        .put(format!("{}/upload", url))
        .header("Authorization", auth_header_value(&valid_auth))
        .header("Content-Type", "application/octet-stream")
        .body(data)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "valid auth should succeed");
}

#[tokio::test]
async fn test_auth_wrong_action_rejected() {
    let server = lfs_server();
    let url = spawn(server).await;
    let signer = Signer::generate();
    let http = reqwest::Client::new();

    let data = vec![42u8; 1000];
    let sha256 = blossom_rs::protocol::sha256_hex(&data);

    let wrong_auth = build_blossom_auth_for_request(
        &signer,
        "get",
        Some(&sha256),
        &url,
        &format!("{url}/upload"),
        "PUT",
        "",
    );
    let resp = http
        .put(format!("{}/upload", url))
        .header("Authorization", auth_header_value(&wrong_auth))
        .header("Content-Type", "application/octet-stream")
        .body(data)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "wrong action should be rejected");
}
