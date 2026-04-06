//! Pluggable access control for Blossom servers.
//!
//! The [`AccessControl`] trait lets you authorize or reject operations
//! based on the caller's public key and the requested action.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Normalize a pubkey from hex (64 chars) or npub1 bech32 to hex.
/// Returns `None` if the input is not a valid pubkey.
pub fn normalize_pubkey(input: &str) -> Option<String> {
    let input = input.trim();
    if input.starts_with("npub1") {
        // Decode bech32 npub1 to hex.
        let (hrp, data) = bech32::decode(input).ok()?;
        if hrp.as_str() != "npub" || data.len() != 32 {
            return None;
        }
        Some(hex::encode(data))
    } else if input.len() == 64 && input.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(input.to_string())
    } else {
        None
    }
}

/// Actions that can be authorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Upload,
    Download,
    Delete,
    List,
    Mirror,
    Admin,
}

/// Role assigned to a pubkey for authorization decisions.
///
/// Admins have unrestricted access including admin endpoints and the
/// ability to delete any blob. Members can upload, download, list, and
/// mirror, but may only delete their own blobs. Denied pubkeys have no
/// access at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Full access — admin endpoints, delete any blob.
    Admin,
    /// Standard access — upload/download/list/mirror, delete own blobs only.
    Member,
    /// No access.
    Denied,
}

/// Trait for pluggable access control decisions.
///
/// Implementations decide whether a given pubkey is allowed to perform
/// a given action. Return `true` to allow, `false` to deny.
///
/// The [`role`](AccessControl::role) method determines a pubkey's role
/// for ownership-based authorization (e.g., only blob owners or admins
/// can delete). The default implementation derives the role from
/// `is_allowed` calls for backward compatibility with existing
/// implementations.
pub trait AccessControl: Send + Sync {
    /// Check if `pubkey` is authorized for `action`.
    fn is_allowed(&self, pubkey: &str, action: Action) -> bool;

    /// Determine the role for `pubkey`.
    ///
    /// Override this for explicit role assignment. The default derives
    /// the role from `is_allowed`: if `Action::Admin` is allowed the
    /// role is `Admin`; if `Action::Upload` is allowed the role is
    /// `Member`; otherwise `Denied`.
    fn role(&self, pubkey: &str) -> Role {
        if self.is_allowed(pubkey, Action::Admin) {
            Role::Admin
        } else if self.is_allowed(pubkey, Action::Upload) {
            Role::Member
        } else {
            Role::Denied
        }
    }
}

/// Open access — allows everything. Default when no access control is configured.
pub struct OpenAccess;

impl AccessControl for OpenAccess {
    fn is_allowed(&self, _pubkey: &str, _action: Action) -> bool {
        true
    }

    fn role(&self, _pubkey: &str) -> Role {
        // Open servers grant member access, not admin.
        Role::Member
    }
}

/// Pubkey whitelist access control.
///
/// Only pubkeys in the whitelist are allowed to perform any action.
/// Supports loading from a file (one hex pubkey per line) and hot-reload.
pub struct Whitelist {
    pubkeys: Arc<RwLock<HashSet<String>>>,
}

impl Whitelist {
    /// Create a whitelist from a set of hex-encoded pubkeys.
    pub fn new(pubkeys: HashSet<String>) -> Self {
        Self {
            pubkeys: Arc::new(RwLock::new(pubkeys)),
        }
    }

    /// Load a whitelist from a file (one hex pubkey per line).
    /// Empty lines and lines starting with `#` are ignored.
    pub fn from_file(path: &Path) -> std::io::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let pubkeys = Self::parse_pubkeys(&content);
        Ok(Self::new(pubkeys))
    }

    /// Reload the whitelist from a file. Call this periodically or on file change.
    pub async fn reload(&self, path: &Path) -> std::io::Result<()> {
        let content = tokio::fs::read_to_string(path).await?;
        let new_keys = Self::parse_pubkeys(&content);
        let mut keys = self.pubkeys.write().await;
        *keys = new_keys;
        tracing::info!(
            access.backend = "whitelist",
            access.pubkey_count = keys.len(),
            "whitelist reloaded"
        );
        Ok(())
    }

    /// Add a pubkey to the whitelist at runtime.
    /// Accepts hex or npub1 format.
    pub async fn add(&self, pubkey: String) {
        let normalized = normalize_pubkey(&pubkey).unwrap_or(pubkey);
        self.pubkeys.write().await.insert(normalized);
    }

    /// Remove a pubkey from the whitelist at runtime.
    /// Accepts hex or npub1 format.
    pub async fn remove(&self, pubkey: &str) {
        let normalized = normalize_pubkey(pubkey).unwrap_or_else(|| pubkey.to_string());
        self.pubkeys.write().await.remove(&normalized);
    }

    /// Check if a pubkey is whitelisted (async version for direct use).
    pub async fn contains(&self, pubkey: &str) -> bool {
        self.pubkeys.read().await.contains(pubkey)
    }

    /// Number of whitelisted pubkeys.
    pub async fn len(&self) -> usize {
        self.pubkeys.read().await.len()
    }

    /// Whether the whitelist is empty.
    pub async fn is_empty(&self) -> bool {
        self.pubkeys.read().await.is_empty()
    }

    /// List all whitelisted pubkeys.
    pub async fn list(&self) -> Vec<String> {
        self.pubkeys.read().await.iter().cloned().collect()
    }

    fn parse_pubkeys(content: &str) -> HashSet<String> {
        content
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .filter_map(normalize_pubkey)
            .collect()
    }
}

impl AccessControl for Whitelist {
    fn is_allowed(&self, pubkey: &str, _action: Action) -> bool {
        // Use try_read to avoid blocking. If we can't acquire the lock,
        // deny access (fail closed).
        match self.pubkeys.try_read() {
            Ok(keys) => keys.contains(pubkey),
            Err(_) => false,
        }
    }

    fn role(&self, pubkey: &str) -> Role {
        if self.is_allowed(pubkey, Action::Upload) {
            Role::Member
        } else {
            Role::Denied
        }
    }
}

impl AccessControl for Arc<Whitelist> {
    fn is_allowed(&self, pubkey: &str, action: Action) -> bool {
        (**self).is_allowed(pubkey, action)
    }

    fn role(&self, pubkey: &str) -> Role {
        (**self).role(pubkey)
    }
}

/// Role-based access control with explicit admin and member sets.
///
/// Admins have unrestricted access to all operations including admin
/// endpoints and deleting any blob. Members can upload, download, list,
/// mirror, and delete their own blobs. Pubkeys not in either set are
/// denied.
pub struct RoleBasedAccess {
    admins: Arc<RwLock<HashSet<String>>>,
    members: Arc<RwLock<HashSet<String>>>,
}

impl RoleBasedAccess {
    /// Create from explicit admin and member sets (hex pubkeys).
    pub fn new(admins: HashSet<String>, members: HashSet<String>) -> Self {
        Self {
            admins: Arc::new(RwLock::new(admins)),
            members: Arc::new(RwLock::new(members)),
        }
    }

    /// Load from two files: one for admins, one for members.
    /// Each file has one pubkey per line (hex or npub1). Lines starting
    /// with `#` and blank lines are ignored.
    pub fn from_files(admin_path: &Path, member_path: &Path) -> std::io::Result<Self> {
        let admins = Self::parse_file(admin_path)?;
        let members = Self::parse_file(member_path)?;
        Ok(Self::new(admins, members))
    }

    /// Reload both files.
    pub async fn reload(&self, admin_path: &Path, member_path: &Path) -> std::io::Result<()> {
        let new_admins = Self::parse_file(admin_path)?;
        let new_members = Self::parse_file(member_path)?;
        *self.admins.write().await = new_admins;
        *self.members.write().await = new_members;
        tracing::info!(access.backend = "role_based", "role-based access reloaded");
        Ok(())
    }

    /// Add a pubkey as admin at runtime. Accepts hex or npub1.
    pub async fn add_admin(&self, pubkey: &str) {
        let normalized = normalize_pubkey(pubkey).unwrap_or_else(|| pubkey.to_string());
        self.admins.write().await.insert(normalized);
    }

    /// Add a pubkey as member at runtime. Accepts hex or npub1.
    pub async fn add_member(&self, pubkey: &str) {
        let normalized = normalize_pubkey(pubkey).unwrap_or_else(|| pubkey.to_string());
        self.members.write().await.insert(normalized);
    }

    /// Remove a pubkey from both admin and member sets.
    pub async fn remove(&self, pubkey: &str) {
        let normalized = normalize_pubkey(pubkey).unwrap_or_else(|| pubkey.to_string());
        self.admins.write().await.remove(&normalized);
        self.members.write().await.remove(&normalized);
    }

    /// List all admin pubkeys.
    pub async fn list_admins(&self) -> Vec<String> {
        self.admins.read().await.iter().cloned().collect()
    }

    /// List all member pubkeys.
    pub async fn list_members(&self) -> Vec<String> {
        self.members.read().await.iter().cloned().collect()
    }

    fn parse_file(path: &Path) -> std::io::Result<HashSet<String>> {
        let content = std::fs::read_to_string(path)?;
        Ok(content
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .filter_map(normalize_pubkey)
            .collect())
    }
}

impl AccessControl for RoleBasedAccess {
    fn is_allowed(&self, pubkey: &str, action: Action) -> bool {
        match self.role(pubkey) {
            Role::Admin => true,
            Role::Member => !matches!(action, Action::Admin),
            Role::Denied => false,
        }
    }

    fn role(&self, pubkey: &str) -> Role {
        if let Ok(admins) = self.admins.try_read() {
            if admins.contains(pubkey) {
                return Role::Admin;
            }
        }
        if let Ok(members) = self.members.try_read() {
            if members.contains(pubkey) {
                return Role::Member;
            }
        }
        Role::Denied
    }
}

impl AccessControl for Arc<RoleBasedAccess> {
    fn is_allowed(&self, pubkey: &str, action: Action) -> bool {
        (**self).is_allowed(pubkey, action)
    }

    fn role(&self, pubkey: &str) -> Role {
        (**self).role(pubkey)
    }
}

impl RoleBasedAccess {
    /// Load roles from a database, populating the admin and member sets
    /// from persisted user records. Call at startup after DB migrations.
    pub async fn load_from_database(db: &mut dyn crate::db::BlobDatabase) -> Self {
        let admins: HashSet<String> = db
            .list_users_by_role("admin")
            .unwrap_or_default()
            .into_iter()
            .map(|u| u.pubkey)
            .collect();
        let members: HashSet<String> = db
            .list_users_by_role("member")
            .unwrap_or_default()
            .into_iter()
            .map(|u| u.pubkey)
            .collect();
        tracing::info!(
            admins = admins.len(),
            members = members.len(),
            "loaded roles from database"
        );
        Self::new(admins, members)
    }

    /// Promote a pubkey to admin in both the in-memory set and the database.
    pub async fn promote_admin(
        &self,
        pubkey: &str,
        db: &mut dyn crate::db::BlobDatabase,
    ) -> Result<(), crate::db::DbError> {
        let normalized = normalize_pubkey(pubkey).unwrap_or_else(|| pubkey.to_string());
        db.set_role(&normalized, "admin")?;
        self.admins.write().await.insert(normalized.clone());
        self.members.write().await.remove(&normalized);
        Ok(())
    }

    /// Demote a pubkey to member in both the in-memory set and the database.
    pub async fn demote_to_member(
        &self,
        pubkey: &str,
        db: &mut dyn crate::db::BlobDatabase,
    ) -> Result<(), crate::db::DbError> {
        let normalized = normalize_pubkey(pubkey).unwrap_or_else(|| pubkey.to_string());
        db.set_role(&normalized, "member")?;
        self.admins.write().await.remove(&normalized);
        self.members.write().await.insert(normalized);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_access_allows_all() {
        let ac = OpenAccess;
        assert!(ac.is_allowed("anything", Action::Upload));
        assert!(ac.is_allowed("anything", Action::Delete));
        assert!(ac.is_allowed("anything", Action::Admin));
    }

    #[test]
    fn test_whitelist_allows_listed() {
        let pubkey = "a".repeat(64);
        let mut keys = HashSet::new();
        keys.insert(pubkey.clone());
        let wl = Whitelist::new(keys);

        assert!(wl.is_allowed(&pubkey, Action::Upload));
        assert!(wl.is_allowed(&pubkey, Action::Download));
    }

    #[test]
    fn test_whitelist_denies_unlisted() {
        let wl = Whitelist::new(HashSet::new());
        let pubkey = "b".repeat(64);
        assert!(!wl.is_allowed(&pubkey, Action::Upload));
    }

    #[test]
    fn test_parse_pubkeys_from_content() {
        let content = format!(
            "# This is a comment\n\n{}\n{}\ninvalid-short\n  \n{}",
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
        );
        let keys = Whitelist::parse_pubkeys(&content);
        assert_eq!(keys.len(), 3);
        assert!(keys.contains(&"a".repeat(64)));
        assert!(!keys.contains("invalid-short"));
    }

    #[tokio::test]
    async fn test_whitelist_add_remove() {
        let wl = Whitelist::new(HashSet::new());
        let pk = "d".repeat(64);

        assert!(!wl.contains(&pk).await);
        wl.add(pk.clone()).await;
        assert!(wl.contains(&pk).await);
        assert_eq!(wl.len().await, 1);

        wl.remove(&pk).await;
        assert!(!wl.contains(&pk).await);
        assert!(wl.is_empty().await);
    }

    #[test]
    fn test_whitelist_from_file() {
        let dir = std::env::temp_dir().join(format!("blossom_wl_{}", rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("whitelist.txt");

        let content = format!("# allowed users\n{}\n{}\n", "e".repeat(64), "f".repeat(64),);
        std::fs::write(&file, &content).unwrap();

        let wl = Whitelist::from_file(&file).unwrap();
        assert!(wl.is_allowed(&"e".repeat(64), Action::Upload));
        assert!(wl.is_allowed(&"f".repeat(64), Action::Download));
        assert!(!wl.is_allowed(&"0".repeat(64), Action::Upload));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_normalize_pubkey_hex() {
        let hex = "a".repeat(64);
        assert_eq!(normalize_pubkey(&hex), Some(hex));
    }

    #[test]
    fn test_normalize_pubkey_npub() {
        // Generate a known keypair and encode as npub1.
        let hex_key = "a".repeat(64);
        let bytes = hex::decode(&hex_key).unwrap();
        let hrp = bech32::Hrp::parse("npub").unwrap();
        let npub = bech32::encode::<bech32::Bech32>(hrp, &bytes).unwrap();
        assert!(npub.starts_with("npub1"));

        let normalized = normalize_pubkey(&npub).unwrap();
        assert_eq!(normalized, hex_key);
    }

    #[test]
    fn test_normalize_pubkey_invalid() {
        assert_eq!(normalize_pubkey("too_short"), None);
        assert_eq!(normalize_pubkey("g".repeat(64).as_str()), None);
        assert_eq!(normalize_pubkey("npub1invalid"), None);
        assert_eq!(normalize_pubkey(""), None);
    }

    #[test]
    fn test_whitelist_file_with_npub() {
        let dir = std::env::temp_dir().join(format!("blossom_npub_{}", rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("whitelist.txt");

        let hex_key = "b".repeat(64);
        let bytes = hex::decode(&hex_key).unwrap();
        let hrp = bech32::Hrp::parse("npub").unwrap();
        let npub = bech32::encode::<bech32::Bech32>(hrp, &bytes).unwrap();

        // Mix hex and npub formats in the same file.
        let content = format!("# mixed formats\n{}\n{}\n", "a".repeat(64), npub);
        std::fs::write(&file, &content).unwrap();

        let wl = Whitelist::from_file(&file).unwrap();
        assert!(wl.is_allowed(&"a".repeat(64), Action::Upload));
        assert!(wl.is_allowed(&hex_key, Action::Upload)); // npub decoded to hex
        assert!(!wl.is_allowed(&"c".repeat(64), Action::Upload));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_whitelist_list() {
        let mut keys = HashSet::new();
        keys.insert("a".repeat(64));
        keys.insert("b".repeat(64));
        let wl = Whitelist::new(keys);

        let list = wl.list().await;
        assert_eq!(list.len(), 2);
        assert!(list.contains(&"a".repeat(64)));
        assert!(list.contains(&"b".repeat(64)));
    }

    // --- Role tests ---

    #[test]
    fn test_open_access_role_is_member() {
        let ac = OpenAccess;
        assert_eq!(ac.role("anything"), Role::Member);
    }

    #[test]
    fn test_whitelist_role_is_member() {
        let pk = "a".repeat(64);
        let mut keys = HashSet::new();
        keys.insert(pk.clone());
        let wl = Whitelist::new(keys);

        assert_eq!(wl.role(&pk), Role::Member);
        assert_eq!(wl.role(&"b".repeat(64)), Role::Denied);
    }

    #[test]
    fn test_role_based_access_admin() {
        let admin = "a".repeat(64);
        let member = "b".repeat(64);
        let nobody = "c".repeat(64);

        let mut admins = HashSet::new();
        admins.insert(admin.clone());
        let mut members = HashSet::new();
        members.insert(member.clone());

        let rba = RoleBasedAccess::new(admins, members);

        // Admin can do everything.
        assert_eq!(rba.role(&admin), Role::Admin);
        assert!(rba.is_allowed(&admin, Action::Admin));
        assert!(rba.is_allowed(&admin, Action::Upload));
        assert!(rba.is_allowed(&admin, Action::Delete));

        // Member can do most things but not admin.
        assert_eq!(rba.role(&member), Role::Member);
        assert!(rba.is_allowed(&member, Action::Upload));
        assert!(rba.is_allowed(&member, Action::Delete));
        assert!(rba.is_allowed(&member, Action::Download));
        assert!(rba.is_allowed(&member, Action::List));
        assert!(rba.is_allowed(&member, Action::Mirror));
        assert!(!rba.is_allowed(&member, Action::Admin));

        // Nobody is denied.
        assert_eq!(rba.role(&nobody), Role::Denied);
        assert!(!rba.is_allowed(&nobody, Action::Upload));
        assert!(!rba.is_allowed(&nobody, Action::Admin));
    }

    #[tokio::test]
    async fn test_role_based_access_add_remove() {
        let rba = RoleBasedAccess::new(HashSet::new(), HashSet::new());
        let pk = "d".repeat(64);

        assert_eq!(rba.role(&pk), Role::Denied);

        rba.add_member(&pk).await;
        assert_eq!(rba.role(&pk), Role::Member);

        rba.add_admin(&pk).await;
        assert_eq!(rba.role(&pk), Role::Admin);

        rba.remove(&pk).await;
        assert_eq!(rba.role(&pk), Role::Denied);
    }

    #[test]
    fn test_role_based_access_from_files() {
        let dir = std::env::temp_dir().join(format!("blossom_rba_{}", rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();

        let admin_file = dir.join("admins.txt");
        let member_file = dir.join("members.txt");

        std::fs::write(&admin_file, format!("{}\n", "a".repeat(64))).unwrap();
        std::fs::write(
            &member_file,
            format!("{}\n{}\n", "b".repeat(64), "c".repeat(64)),
        )
        .unwrap();

        let rba = RoleBasedAccess::from_files(&admin_file, &member_file).unwrap();
        assert_eq!(rba.role(&"a".repeat(64)), Role::Admin);
        assert_eq!(rba.role(&"b".repeat(64)), Role::Member);
        assert_eq!(rba.role(&"c".repeat(64)), Role::Member);
        assert_eq!(rba.role(&"d".repeat(64)), Role::Denied);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
