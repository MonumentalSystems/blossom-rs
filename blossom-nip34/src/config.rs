//! NIP-34 relay and GRASP git server configuration.

use std::path::PathBuf;

use nostr::Kind;

/// Configuration for the NIP-34 relay and GRASP git server.
#[derive(Debug, Clone)]
pub struct Nip34Config {
    /// Relay domain (e.g., "relay.example.com"). Used in NIP-11 and GRASP validation.
    pub domain: String,
    /// LMDB database directory for Nostr event storage.
    pub lmdb_path: PathBuf,
    /// Directory for bare git repositories (`{npub}/{repo}.git`).
    pub repos_path: PathBuf,
    /// Path to git binary.
    pub git_path: String,
    /// Maximum Nostr event size in bytes (0 = unlimited).
    pub max_event_size: usize,
    /// Maximum concurrent WebSocket connections.
    pub max_connections: Option<u32>,
    /// Rate limit: events per minute per connection.
    pub rate_limit_events_per_min: u32,
    /// Admin pubkeys (hex) — bypass all relay restrictions.
    pub admin_pubkeys: Vec<String>,
    /// Whitelisted pubkeys (hex) — if non-empty, only these can write.
    pub whitelist_pubkeys: Vec<String>,
    /// Blacklisted pubkeys (hex) — always rejected.
    pub blacklist_pubkeys: Vec<String>,
    /// Allowed event kinds — if non-empty, only these accepted.
    pub allowed_kinds: Vec<Kind>,
    /// Disallowed event kinds — always rejected.
    pub disallowed_kinds: Vec<Kind>,
    /// NIP-11 relay information.
    pub nip11: Nip11Info,
}

/// NIP-11 relay information document fields.
#[derive(Debug, Clone)]
pub struct Nip11Info {
    pub name: String,
    pub description: String,
    pub contact: Option<String>,
    pub supported_nips: Vec<u32>,
}

impl Default for Nip34Config {
    fn default() -> Self {
        Self {
            domain: "localhost".into(),
            lmdb_path: PathBuf::from("./relay_db"),
            repos_path: PathBuf::from("./repos"),
            git_path: "git".into(),
            max_event_size: 150 * 1024, // 150 KB
            max_connections: Some(256),
            rate_limit_events_per_min: 120,
            admin_pubkeys: Vec::new(),
            whitelist_pubkeys: Vec::new(),
            blacklist_pubkeys: Vec::new(),
            allowed_kinds: Vec::new(),
            disallowed_kinds: Vec::new(),
            nip11: Nip11Info::default(),
        }
    }
}

impl Default for Nip11Info {
    fn default() -> Self {
        Self {
            name: "blossom-nip34".into(),
            description: "Blossom NIP-34 relay with GRASP git server".into(),
            contact: None,
            supported_nips: vec![1, 11, 34, 42],
        }
    }
}
