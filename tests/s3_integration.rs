//! S3/R2 integration tests.
//!
//! These tests run against a real S3-compatible backend (Cloudflare R2, AWS S3, MinIO).
//! They are SKIPPED unless the following environment variables are set:
//!
//! - `R2_ENDPOINT` — S3-compatible endpoint URL
//! - `R2_BUCKET` — Bucket name
//! - `R2_ACCESS_KEY_ID` — S3 access key
//! - `R2_SECRET_ACCESS_KEY` — S3 secret key
//! - `R2_REGION` — Region (use `auto` for R2)

#![cfg(feature = "s3")]

use blossom_rs::protocol::sha256_hex;
use blossom_rs::storage::{BlobBackend, S3Backend, S3Config};

fn get_config() -> Option<S3Config> {
    let endpoint = std::env::var("R2_ENDPOINT").ok()?;
    let bucket = std::env::var("R2_BUCKET").ok()?;
    let region = std::env::var("R2_REGION").unwrap_or_else(|_| "auto".to_string());

    // Set AWS env vars for the SDK.
    if let Ok(key) = std::env::var("R2_ACCESS_KEY_ID") {
        std::env::set_var("AWS_ACCESS_KEY_ID", &key);
    }
    if let Ok(secret) = std::env::var("R2_SECRET_ACCESS_KEY") {
        std::env::set_var("AWS_SECRET_ACCESS_KEY", &secret);
    }

    Some(S3Config {
        endpoint: Some(endpoint),
        bucket,
        region,
        public_url: None,
    })
}

macro_rules! skip_without_r2 {
    () => {
        match get_config() {
            Some(c) => c,
            None => {
                eprintln!("SKIPPED: R2_ENDPOINT not set");
                return;
            }
        }
    };
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_s3_insert_and_get() {
    let config = skip_without_r2!();
    let mut backend = S3Backend::new(config).await.unwrap();

    let data = b"s3 integration test blob";
    let desc = backend.insert(data.to_vec(), "http://test");
    assert_eq!(desc.size, data.len() as u64);
    assert_eq!(desc.sha256, sha256_hex(data));

    let retrieved = backend.get(&desc.sha256).unwrap();
    assert_eq!(retrieved, data);

    // Cleanup.
    backend.delete(&desc.sha256);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_s3_exists() {
    let config = skip_without_r2!();
    let mut backend = S3Backend::new(config).await.unwrap();

    let data = b"s3 exists test";
    let desc = backend.insert(data.to_vec(), "http://test");

    assert!(backend.exists(&desc.sha256));
    assert!(!backend.exists(&"0".repeat(64)));

    // Cleanup.
    backend.delete(&desc.sha256);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_s3_delete() {
    let config = skip_without_r2!();
    let mut backend = S3Backend::new(config).await.unwrap();

    let data = b"s3 delete test";
    let desc = backend.insert(data.to_vec(), "http://test");

    assert!(backend.exists(&desc.sha256));
    assert!(backend.delete(&desc.sha256));
    assert!(!backend.exists(&desc.sha256));
    assert!(backend.get(&desc.sha256).is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_s3_deduplication() {
    let config = skip_without_r2!();
    let mut backend = S3Backend::new(config).await.unwrap();

    let data = b"s3 dedup content";
    let desc1 = backend.insert(data.to_vec(), "http://test");
    let desc2 = backend.insert(data.to_vec(), "http://test");

    assert_eq!(desc1.sha256, desc2.sha256);
    assert_eq!(backend.len(), backend.len()); // Same count.

    // Cleanup.
    backend.delete(&desc1.sha256);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_s3_large_blob() {
    let config = skip_without_r2!();
    let mut backend = S3Backend::new(config).await.unwrap();

    // 1MB blob.
    let data: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
    let expected_hash = sha256_hex(&data);

    let desc = backend.insert(data.clone(), "http://test");
    assert_eq!(desc.sha256, expected_hash);
    assert_eq!(desc.size, 1_000_000);

    let retrieved = backend.get(&desc.sha256).unwrap();
    assert_eq!(sha256_hex(&retrieved), expected_hash);
    assert_eq!(retrieved.len(), 1_000_000);

    // Cleanup.
    backend.delete(&desc.sha256);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_s3_len_and_total_bytes() {
    let config = skip_without_r2!();
    let mut backend = S3Backend::new(config).await.unwrap();

    let initial_len = backend.len();
    let initial_bytes = backend.total_bytes();

    let data = b"s3 stats test blob content";
    let desc = backend.insert(data.to_vec(), "http://test");

    assert_eq!(backend.len(), initial_len + 1);
    assert_eq!(backend.total_bytes(), initial_bytes + data.len() as u64);

    backend.delete(&desc.sha256);
    assert_eq!(backend.len(), initial_len);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_s3_cdn_url() {
    let mut config = skip_without_r2!();
    config.public_url = Some("https://cdn.example.com/blobs".to_string());

    let mut backend = S3Backend::new(config).await.unwrap();

    let data = b"cdn url test";
    let desc = backend.insert(data.to_vec(), "http://fallback");

    // URL should use CDN prefix, not base_url.
    assert!(desc
        .url
        .as_ref()
        .unwrap()
        .starts_with("https://cdn.example.com/blobs/"));

    // Cleanup.
    backend.delete(&desc.sha256);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_s3_rebuild_index() {
    let config = skip_without_r2!();
    let mut backend = S3Backend::new(config.clone()).await.unwrap();

    // Insert a blob.
    let data = b"s3 rebuild index test";
    let desc = backend.insert(data.to_vec(), "http://test");
    let sha = desc.sha256.clone();

    // Create a new backend instance — should rebuild index from bucket.
    let backend2 = S3Backend::new(config).await.unwrap();
    assert!(backend2.exists(&sha));

    // Cleanup.
    backend.delete(&sha);
}
