//! PKARR integration tests — publish and resolve via live relays.
//!
//! These tests hit real pkarr relay infrastructure. They are SKIPPED
//! unless `RUN_PKARR_TESTS=1` is set.

#![cfg(feature = "pkarr-discovery")]

use blossom_rs::transport::pkarr_discovery::{
    resolve_blossom_endpoints, PkarrConfig, PkarrPublisher,
};

fn should_run() -> bool {
    std::env::var("RUN_PKARR_TESTS").unwrap_or_default() == "1"
}

#[tokio::test]
async fn test_publish_and_resolve() {
    if !should_run() {
        eprintln!("SKIPPED: RUN_PKARR_TESTS not set");
        return;
    }

    // Generate a unique keypair for this test run.
    let secret_bytes: [u8; 32] = rand::random();

    let publisher = PkarrPublisher::new(
        &secret_bytes,
        PkarrConfig {
            http_url: Some("https://test-blossom.example.com".into()),
            iroh_node_id: Some("test-node-id-12345".into()),
            ttl: 300,
            ..Default::default()
        },
    );

    let public_key = publisher.public_key();
    eprintln!("Publishing as: {}", public_key);

    // Publish.
    publisher.publish().await.expect("publish failed");
    eprintln!("Published successfully");

    // Small delay for relay propagation.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Resolve.
    let (http_url, iroh_node_id) = resolve_blossom_endpoints(&public_key)
        .await
        .expect("resolve failed");

    assert_eq!(
        http_url.as_deref(),
        Some("https://test-blossom.example.com"),
        "HTTP URL mismatch"
    );
    assert_eq!(
        iroh_node_id.as_deref(),
        Some("test-node-id-12345"),
        "iroh node ID mismatch"
    );
    eprintln!("Resolved: http={:?}, iroh={:?}", http_url, iroh_node_id);
}

#[tokio::test]
async fn test_publish_update_and_resolve() {
    if !should_run() {
        eprintln!("SKIPPED: RUN_PKARR_TESTS not set");
        return;
    }

    let secret_bytes: [u8; 32] = rand::random();

    // Publish initial record.
    let publisher = PkarrPublisher::new(
        &secret_bytes,
        PkarrConfig {
            http_url: Some("https://v1.example.com".into()),
            iroh_node_id: Some("node-v1".into()),
            ttl: 300,
            ..Default::default()
        },
    );

    let public_key = publisher.public_key();
    publisher.publish().await.expect("initial publish failed");
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Verify initial.
    let (url, _) = resolve_blossom_endpoints(&public_key)
        .await
        .expect("resolve v1 failed");
    assert_eq!(url.as_deref(), Some("https://v1.example.com"));

    // Publish updated record (same keypair, new data).
    let publisher_v2 = PkarrPublisher::new(
        &secret_bytes,
        PkarrConfig {
            http_url: Some("https://v2.example.com".into()),
            iroh_node_id: Some("node-v2".into()),
            ttl: 300,
            ..Default::default()
        },
    );
    publisher_v2.publish().await.expect("update publish failed");
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Verify updated.
    let (url, node_id) = resolve_blossom_endpoints(&public_key)
        .await
        .expect("resolve v2 failed");
    assert_eq!(url.as_deref(), Some("https://v2.example.com"));
    assert_eq!(node_id.as_deref(), Some("node-v2"));
    eprintln!("Update verified: {:?}", url);
}

#[tokio::test]
async fn test_resolve_nonexistent() {
    if !should_run() {
        eprintln!("SKIPPED: RUN_PKARR_TESTS not set");
        return;
    }

    // Random key that was never published.
    let random_bytes: [u8; 32] = rand::random();
    let kp = pkarr::Keypair::from_secret_key(&random_bytes);
    let result = resolve_blossom_endpoints(&kp.public_key()).await;
    assert!(result.is_err(), "should fail for nonexistent key");
}

#[tokio::test]
async fn test_unified_identity_publish_resolve() {
    if !should_run() {
        eprintln!("SKIPPED: RUN_PKARR_TESTS not set");
        return;
    }

    // Same secret key for iroh and pkarr — verify they share identity.
    let secret_bytes: [u8; 32] = rand::random();

    let iroh_key = iroh::SecretKey::from_bytes(&secret_bytes);
    let iroh_pub = iroh_key.public();

    let publisher = PkarrPublisher::new(
        &secret_bytes,
        PkarrConfig {
            http_url: Some("https://unified.example.com".into()),
            iroh_node_id: Some(iroh_pub.to_string()),
            ttl: 300,
            ..Default::default()
        },
    );

    // Public keys match.
    assert_eq!(
        iroh_pub.as_bytes(),
        publisher.public_key().to_bytes().as_slice(),
    );

    publisher.publish().await.expect("publish failed");
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let (_, node_id) = resolve_blossom_endpoints(&publisher.public_key())
        .await
        .expect("resolve failed");

    // The resolved iroh node ID should match the iroh public key.
    assert_eq!(
        node_id.as_deref(),
        Some(iroh_pub.to_string().as_str()),
        "resolved iroh node ID should match"
    );
}
