//! Integration tests for blossom-nip34.

use std::sync::Arc;

use blossom_nip34::{Nip34Config, Nip34State};

async fn test_state(tmp: &std::path::Path) -> Arc<Nip34State> {
    let config = Nip34Config {
        domain: "test.localhost".into(),
        lmdb_path: tmp.join("relay_db"),
        repos_path: tmp.join("repos"),
        ..Default::default()
    };
    Arc::new(Nip34State::new(config).await.unwrap())
}

// ---------------------------------------------------------------------------
// Config defaults
// ---------------------------------------------------------------------------

#[test]
fn test_config_defaults() {
    let config = Nip34Config::default();
    assert_eq!(config.domain, "localhost");
    assert_eq!(config.git_path, "git");
    assert_eq!(config.max_event_size, 150 * 1024);
    assert_eq!(config.rate_limit_events_per_min, 120);
}

// ---------------------------------------------------------------------------
// NIP-34 types
// ---------------------------------------------------------------------------

#[test]
fn test_nip34_kinds() {
    use blossom_nip34::nip34_types::*;
    assert!(is_nip34_kind(REPO_ANNOUNCEMENT));
    assert!(is_nip34_kind(PATCH));
    assert!(is_nip34_kind(ISSUE));
    assert!(is_nip34_kind(STATUS_OPEN));
    assert!(!is_nip34_kind(nostr::Kind::Custom(1)));
    assert!(is_status_kind(STATUS_APPLIED));
    assert!(!is_status_kind(PATCH));
}

// ---------------------------------------------------------------------------
// State: repo path validation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_repo_path_valid() {
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(tmp.path()).await;

    let path = state.repo_path("npub1test", "my-repo");
    assert!(path.is_some());
    let path = path.unwrap();
    assert!(path.ends_with("npub1test/my-repo.git"));
}

#[tokio::test]
async fn test_repo_path_invalid_name() {
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(tmp.path()).await;

    assert!(state.repo_path("npub1test", "").is_none());
    assert!(state.repo_path("npub1test", "has spaces").is_none());
    assert!(state
        .repo_path("npub1test", "way-too-long-name-that-exceeds-limit")
        .is_none());
    assert!(state.repo_path("npub1test", "has/slash").is_none());
}

#[tokio::test]
async fn test_repo_path_valid_names() {
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(tmp.path()).await;

    assert!(state.repo_path("npub1test", "my-repo").is_some());
    assert!(state.repo_path("npub1test", "my_repo").is_some());
    assert!(state.repo_path("npub1test", "MyRepo123").is_some());
    assert!(state.repo_path("npub1test", "a").is_some());
}

// ---------------------------------------------------------------------------
// State: bare repo creation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_create_bare_repo() {
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(tmp.path()).await;

    let path = state
        .create_bare_repo("npub1abc", "test-repo", "A test repository")
        .await
        .unwrap();

    assert!(path.join("HEAD").exists());
    assert!(path.join("description").exists());

    let desc = std::fs::read_to_string(path.join("description")).unwrap();
    assert_eq!(desc, "A test repository");
}

#[tokio::test]
async fn test_create_bare_repo_idempotent() {
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(tmp.path()).await;

    let path1 = state
        .create_bare_repo("npub1abc", "test-repo", "First")
        .await
        .unwrap();
    let path2 = state
        .create_bare_repo("npub1abc", "test-repo", "Second")
        .await
        .unwrap();

    assert_eq!(path1, path2);
    // Description should NOT be overwritten on second call
    assert!(path1.join("HEAD").exists());
}

#[tokio::test]
async fn test_create_bare_repo_invalid_name() {
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(tmp.path()).await;

    let result = state
        .create_bare_repo("npub1abc", "invalid name!", "desc")
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_repo_exists() {
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(tmp.path()).await;

    assert!(!state.repo_exists("npub1abc", "test-repo"));

    state
        .create_bare_repo("npub1abc", "test-repo", "desc")
        .await
        .unwrap();

    assert!(state.repo_exists("npub1abc", "test-repo"));
    assert!(!state.repo_exists("npub1abc", "other-repo"));
}

// ---------------------------------------------------------------------------
// Git command: basic operations on a bare repo
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_git_refs_on_empty_repo() {
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(tmp.path()).await;

    let path = state
        .create_bare_repo("npub1abc", "test-repo", "desc")
        .await
        .unwrap();

    let cmd = blossom_nip34::git_server::command::GitCommand::new("git", &path);
    let refs = cmd.refs("git-upload-pack", false).await;
    // Empty repo should still return something (capabilities line)
    assert!(refs.is_ok());
}

// ---------------------------------------------------------------------------
// NIP-11 handler
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_nip11_response() {
    let tmp = tempfile::tempdir().unwrap();
    let config = Nip34Config {
        domain: "test.localhost".into(),
        lmdb_path: tmp.path().join("relay_db"),
        repos_path: tmp.path().join("repos"),
        ..Default::default()
    };

    let router = blossom_nip34::build_nip34_router(config).await.unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);
    tokio::spawn(async move { axum::serve(listener, router).await.ok() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let client = reqwest::Client::new();

    // NIP-11 request
    let resp = client
        .get(&url)
        .header("accept", "application/nostr+json")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["name"], "blossom-nip34");
    assert!(body["supported_nips"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!(34)));

    // Default request (no nostr+json accept)
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let text = resp.text().await.unwrap();
    assert!(text.contains("NIP-34"));
}

// ---------------------------------------------------------------------------
// Git HTTP server: clone an empty repo
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_git_info_refs_endpoint() {
    let tmp = tempfile::tempdir().unwrap();
    let config = Nip34Config {
        domain: "test.localhost".into(),
        lmdb_path: tmp.path().join("relay_db"),
        repos_path: tmp.path().join("repos"),
        ..Default::default()
    };

    let state = Arc::new(Nip34State::new(config.clone()).await.unwrap());

    // Create a bare repo
    state
        .create_bare_repo("npub1test", "hello", "test repo")
        .await
        .unwrap();

    let router = blossom_nip34::build_nip34_router(config).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);
    tokio::spawn(async move { axum::serve(listener, router).await.ok() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let client = reqwest::Client::new();

    // info/refs
    let resp = client
        .get(format!(
            "{}/npub1test/hello/info/refs?service=git-upload-pack",
            url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(ct, "application/x-git-upload-pack-advertisement");
}

#[tokio::test]
async fn test_git_info_refs_not_found() {
    let tmp = tempfile::tempdir().unwrap();
    let config = Nip34Config {
        domain: "test.localhost".into(),
        lmdb_path: tmp.path().join("relay_db"),
        repos_path: tmp.path().join("repos"),
        ..Default::default()
    };

    let router = blossom_nip34::build_nip34_router(config).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);
    tokio::spawn(async move { axum::serve(listener, router).await.ok() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let resp = reqwest::Client::new()
        .get(format!(
            "{}/npub1test/nonexistent/info/refs?service=git-upload-pack",
            url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}
