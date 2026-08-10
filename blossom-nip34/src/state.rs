//! Shared state for the NIP-34 relay and git server.

use std::path::PathBuf;
use std::sync::Arc;

use nostr::nips::nip19::FromBech32;
use nostr_database::NostrDatabase;
use nostr_relay_builder::LocalRelay;

use crate::config::Nip34Config;
use crate::relay;
use crate::relay::policies::RelayPolicy;
use crate::relay::policy_db::PolicyDb;

/// Shared state for all NIP-34 handlers.
pub struct Nip34State {
    pub config: Nip34Config,
    pub relay: Arc<LocalRelay>,
    pub database: Arc<dyn NostrDatabase>,
    /// Runtime-mutable relay policy (whitelist, blacklist, admin, kind filters).
    pub policy: Arc<RelayPolicy>,
    /// SQLite-backed policy persistence.
    pub policy_db: PolicyDb,
}

impl Nip34State {
    /// Create a new NIP-34 state, initializing the LMDB database and relay.
    pub async fn new(mut config: Nip34Config) -> Result<Self, Box<dyn std::error::Error>> {
        let public_url = url::Url::parse(&config.server_url)
            .map_err(|error| format!("invalid NIP-34 server_url: {error}"))?;
        if !matches!(public_url.scheme(), "http" | "https")
            || public_url.host_str().is_none()
            || !public_url.username().is_empty()
            || public_url.password().is_some()
            || public_url.query().is_some()
            || public_url.fragment().is_some()
        {
            return Err(
                "NIP-34 server_url must be an HTTP(S) URL without credentials, query, or fragment"
                    .into(),
            );
        }
        config.server_url = public_url.as_str().trim_end_matches('/').to_string();

        // Ensure repos directory exists
        tokio::fs::create_dir_all(&config.repos_path).await?;

        // Initialize LMDB event database
        let database: Arc<dyn NostrDatabase> =
            Arc::new(nostr_lmdb::NostrLMDB::open(&config.lmdb_path)?);

        // Build policy (shared with relay for runtime mutation)
        let policy = Arc::new(RelayPolicy::with_config(
            config.admin_pubkeys.clone(),
            config.max_event_size,
            config.rate_limit_events_per_min,
        ));
        for pk in &config.whitelist_pubkeys {
            policy.add_whitelist(pk);
        }
        for pk in &config.blacklist_pubkeys {
            policy.add_blacklist(pk);
        }
        if !config.allowed_kinds.is_empty() {
            policy.set_allowed_kinds(config.allowed_kinds.clone());
        }
        for kind in &config.disallowed_kinds {
            policy.add_disallowed_kind(*kind);
        }

        // Open policy database (alongside LMDB dir)
        let policy_db_path = config
            .lmdb_path
            .parent()
            .unwrap_or(&config.lmdb_path)
            .join("relay_policy.db");
        let policy_db = PolicyDb::open_sqlite(policy_db_path.to_str().unwrap_or("relay_policy.db"))
            .await
            .map_err(|e| format!("policy db: {e}"))?;

        // Load persisted policy state from DB
        policy_db
            .load_into(&policy)
            .await
            .map_err(|e| format!("load policy: {e}"))?;

        // Build the relay with the shared policy
        let local_relay = relay::build_relay(&config, database.clone(), policy.clone()).await?;

        Ok(Self {
            config,
            relay: Arc::new(local_relay),
            database,
            policy,
            policy_db,
        })
    }

    /// Get the filesystem path for a repository.
    pub fn repo_path(&self, npub: &str, repo_name: &str) -> Option<PathBuf> {
        if repo_name.is_empty()
            || repo_name.len() > 30
            || !repo_name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return None;
        }

        let owner = if npub.starts_with("npub1") {
            nostr::PublicKey::from_bech32(npub).ok()?.to_hex()
        } else if npub.len() == 64
            && npub
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            npub.to_string()
        } else {
            return None;
        };

        Some(
            self.config
                .repos_path
                .join(owner)
                .join(format!("{}.git", repo_name)),
        )
    }

    /// Check if a repository exists on disk.
    pub fn repo_exists(&self, npub: &str, repo_name: &str) -> bool {
        self.repo_path(npub, repo_name)
            .map(|p| p.join("HEAD").exists())
            .unwrap_or(false)
    }

    /// Create a bare git repository for a given npub/repo.
    pub async fn create_bare_repo(
        &self,
        npub: &str,
        repo_name: &str,
        description: &str,
    ) -> Result<PathBuf, String> {
        let path = self
            .repo_path(npub, repo_name)
            .ok_or_else(|| format!("invalid repo name: {}", repo_name))?;

        if path.join("HEAD").exists() {
            return Ok(path);
        }

        tokio::fs::create_dir_all(&path)
            .await
            .map_err(|e| format!("create repo dir: {e}"))?;

        let status = tokio::process::Command::new(&self.config.git_path)
            .args(["init", "--bare", "--quiet", "."])
            .current_dir(&path)
            .status()
            .await
            .map_err(|e| format!("git init: {e}"))?;

        if !status.success() {
            return Err("git init --bare failed".into());
        }

        let desc_path = path.join("description");
        tokio::fs::write(&desc_path, description)
            .await
            .map_err(|e| format!("write description: {e}"))?;

        tracing::info!(
            repo.npub = %npub,
            repo.name = %repo_name,
            repo.path = %path.display(),
            "created bare git repository"
        );

        Ok(path)
    }
}
