//! Relay write/query policies for admin control.
//!
//! Implements `WritePolicy` and `QueryPolicy` from nostr-relay-builder
//! for pubkey whitelists/blacklists, event size limits, kind filtering,
//! and admin bypass.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};

use nostr::{Event, Kind};
use nostr_relay_builder::prelude::*;

/// Combined relay policy that enforces admin controls.
///
/// Policies are checked in order:
/// 1. Admin pubkeys bypass all restrictions
/// 2. Blacklisted pubkeys are rejected
/// 3. If whitelist is non-empty, only whitelisted pubkeys are accepted
/// 4. Event size is checked against max limit
/// 5. Event kind is checked against allowed/disallowed lists
#[derive(Debug)]
pub struct RelayPolicy {
    /// Admin pubkeys (hex) — bypass all restrictions.
    pub admins: RwLock<HashSet<String>>,
    /// Blacklisted pubkeys (hex) — always rejected.
    pub blacklist: RwLock<HashSet<String>>,
    /// Whitelisted pubkeys (hex) — if non-empty, only these can write.
    pub whitelist: RwLock<HashSet<String>>,
    /// Maximum event size in bytes (0 = unlimited).
    pub max_event_size: usize,
    /// Allowed event kinds — if non-empty, only these kinds accepted.
    pub allowed_kinds: RwLock<HashSet<Kind>>,
    /// Disallowed event kinds — always rejected.
    pub disallowed_kinds: RwLock<HashSet<Kind>>,
    /// Per-connection event rate limit (zero disables the limit).
    pub event_rate_per_min: u32,
    event_rates: Mutex<HashMap<IpAddr, (u64, u32)>>,
}

impl RelayPolicy {
    /// Create a new policy with no restrictions.
    pub fn new() -> Self {
        Self {
            admins: RwLock::new(HashSet::new()),
            blacklist: RwLock::new(HashSet::new()),
            whitelist: RwLock::new(HashSet::new()),
            max_event_size: 0,
            allowed_kinds: RwLock::new(HashSet::new()),
            disallowed_kinds: RwLock::new(HashSet::new()),
            event_rate_per_min: 120,
            event_rates: Mutex::new(HashMap::new()),
        }
    }

    /// Create a policy with admin pubkeys and event size limit.
    pub fn with_config(
        admins: Vec<String>,
        max_event_size: usize,
        event_rate_per_min: u32,
    ) -> Self {
        Self {
            admins: RwLock::new(admins.into_iter().collect()),
            max_event_size,
            event_rate_per_min,
            ..Self::new()
        }
    }

    /// Add an admin pubkey (hex).
    pub fn add_admin(&self, pubkey: &str) {
        self.admins.write().unwrap().insert(pubkey.to_string());
    }

    /// Add a blacklisted pubkey (hex).
    pub fn add_blacklist(&self, pubkey: &str) {
        self.blacklist.write().unwrap().insert(pubkey.to_string());
    }

    /// Remove from blacklist.
    pub fn remove_blacklist(&self, pubkey: &str) {
        self.blacklist.write().unwrap().remove(pubkey);
    }

    /// Add a whitelisted pubkey (hex).
    pub fn add_whitelist(&self, pubkey: &str) {
        self.whitelist.write().unwrap().insert(pubkey.to_string());
    }

    /// Remove from whitelist.
    pub fn remove_whitelist(&self, pubkey: &str) {
        self.whitelist.write().unwrap().remove(pubkey);
    }

    /// Set allowed kinds (empty = allow all).
    pub fn set_allowed_kinds(&self, kinds: Vec<Kind>) {
        *self.allowed_kinds.write().unwrap() = kinds.into_iter().collect();
    }

    /// Add a single allowed kind.
    pub fn add_allowed_kind(&self, kind: Kind) {
        self.allowed_kinds.write().unwrap().insert(kind);
    }

    /// Add a disallowed kind.
    pub fn add_disallowed_kind(&self, kind: Kind) {
        self.disallowed_kinds.write().unwrap().insert(kind);
    }

    fn check_event(&self, event: &Event, addr: &SocketAddr) -> PolicyResult {
        if self.event_rate_per_min > 0 {
            let minute = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                / 60;
            let mut rates = self
                .event_rates
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if rates.len() >= 10_000 {
                rates.retain(|_, (window, _)| *window == minute);
            }
            let entry = rates.entry(addr.ip()).or_insert((minute, 0));
            if entry.0 != minute {
                *entry = (minute, 0);
            }
            if entry.1 >= self.event_rate_per_min {
                return PolicyResult::Reject("event rate limit exceeded".into());
            }
            entry.1 += 1;
        }

        let pubkey_hex = event.pubkey.to_hex();

        // 1. Admins bypass all restrictions
        if self.admins.read().unwrap().contains(&pubkey_hex) {
            return PolicyResult::Accept;
        }

        // 2. Blacklist check
        if self.blacklist.read().unwrap().contains(&pubkey_hex) {
            return PolicyResult::Reject("pubkey is blacklisted".into());
        }

        // 3. Whitelist check (if non-empty)
        let whitelist = self.whitelist.read().unwrap();
        if !whitelist.is_empty() && !whitelist.contains(&pubkey_hex) {
            return PolicyResult::Reject("pubkey not in whitelist".into());
        }
        drop(whitelist);

        // 4. Event size check
        if self.max_event_size > 0 {
            let size = serde_json::to_vec(event).map(|v| v.len()).unwrap_or(0);
            if size > self.max_event_size {
                return PolicyResult::Reject(format!(
                    "event too large: {} bytes (max {})",
                    size, self.max_event_size
                ));
            }
        }

        // 5. Kind filtering
        let disallowed = self.disallowed_kinds.read().unwrap();
        if disallowed.contains(&event.kind) {
            return PolicyResult::Reject(format!("event kind {} is not allowed", event.kind));
        }
        drop(disallowed);

        let allowed = self.allowed_kinds.read().unwrap();
        if !allowed.is_empty() && !allowed.contains(&event.kind) {
            return PolicyResult::Reject(format!(
                "event kind {} is not in allowed list",
                event.kind
            ));
        }

        PolicyResult::Accept
    }
}

impl Default for RelayPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl WritePolicy for RelayPolicy {
    fn admit_event<'a>(
        &'a self,
        event: &'a Event,
        addr: &'a SocketAddr,
    ) -> BoxedFuture<'a, PolicyResult> {
        Box::pin(async move { self.check_event(event, addr) })
    }
}

/// Wrapper to share `RelayPolicy` via `Arc` with the relay builder.
#[derive(Debug)]
pub struct SharedRelayPolicy(pub Arc<RelayPolicy>);

impl WritePolicy for SharedRelayPolicy {
    fn admit_event<'a>(
        &'a self,
        event: &'a Event,
        addr: &'a SocketAddr,
    ) -> BoxedFuture<'a, PolicyResult> {
        Box::pin(async move { self.0.check_event(event, addr) })
    }
}

impl QueryPolicy for SharedRelayPolicy {
    fn admit_query<'a>(
        &'a self,
        _query: &'a nostr::Filter,
        _addr: &'a SocketAddr,
    ) -> BoxedFuture<'a, PolicyResult> {
        Box::pin(async { PolicyResult::Accept })
    }
}

impl QueryPolicy for RelayPolicy {
    fn admit_query<'a>(
        &'a self,
        _query: &'a nostr::Filter,
        _addr: &'a SocketAddr,
    ) -> BoxedFuture<'a, PolicyResult> {
        // Queries are always allowed — policy only restricts writes
        Box::pin(async { PolicyResult::Accept })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::{EventBuilder, Keys, Kind};

    fn make_event(keys: &Keys, kind: Kind) -> Event {
        EventBuilder::new(kind, "test")
            .sign_with_keys(keys)
            .unwrap()
    }

    fn check(policy: &RelayPolicy, event: &Event) -> PolicyResult {
        policy.check_event(event, &SocketAddr::from(([127, 0, 0, 1], 12345)))
    }

    #[test]
    fn test_no_restrictions() {
        let policy = RelayPolicy::new();
        let keys = Keys::generate();
        let event = make_event(&keys, Kind::TextNote);
        assert!(matches!(check(&policy, &event), PolicyResult::Accept));
    }

    #[test]
    fn test_blacklist() {
        let policy = RelayPolicy::new();
        let keys = Keys::generate();
        policy.add_blacklist(&keys.public_key().to_hex());

        let event = make_event(&keys, Kind::TextNote);
        assert!(matches!(check(&policy, &event), PolicyResult::Reject(_)));
    }

    #[test]
    fn test_whitelist() {
        let policy = RelayPolicy::new();
        let allowed = Keys::generate();
        let denied = Keys::generate();
        policy.add_whitelist(&allowed.public_key().to_hex());

        let ok_event = make_event(&allowed, Kind::TextNote);
        let bad_event = make_event(&denied, Kind::TextNote);

        assert!(matches!(check(&policy, &ok_event), PolicyResult::Accept));
        assert!(matches!(
            check(&policy, &bad_event),
            PolicyResult::Reject(_)
        ));
    }

    #[test]
    fn test_admin_bypasses_blacklist() {
        let policy = RelayPolicy::new();
        let keys = Keys::generate();
        let hex = keys.public_key().to_hex();
        policy.add_blacklist(&hex);
        policy.add_admin(&hex);

        let event = make_event(&keys, Kind::TextNote);
        assert!(matches!(check(&policy, &event), PolicyResult::Accept));
    }

    #[test]
    fn test_event_size_limit() {
        let policy = RelayPolicy::with_config(vec![], 100, 120);
        let keys = Keys::generate();
        // A normal event is > 100 bytes when serialized
        let event = make_event(&keys, Kind::TextNote);
        assert!(matches!(check(&policy, &event), PolicyResult::Reject(_)));
    }

    #[test]
    fn test_disallowed_kinds() {
        let policy = RelayPolicy::new();
        policy.add_disallowed_kind(Kind::TextNote);

        let keys = Keys::generate();
        let bad = make_event(&keys, Kind::TextNote);
        let ok = make_event(&keys, Kind::Custom(30617));

        assert!(matches!(check(&policy, &bad), PolicyResult::Reject(_)));
        assert!(matches!(check(&policy, &ok), PolicyResult::Accept));
    }

    #[test]
    fn test_allowed_kinds() {
        let policy = RelayPolicy::new();
        policy.set_allowed_kinds(vec![Kind::Custom(30617), Kind::Custom(1617)]);

        let keys = Keys::generate();
        let ok = make_event(&keys, Kind::Custom(30617));
        let bad = make_event(&keys, Kind::TextNote);

        assert!(matches!(check(&policy, &ok), PolicyResult::Accept));
        assert!(matches!(check(&policy, &bad), PolicyResult::Reject(_)));
    }

    #[test]
    fn test_admin_bypasses_whitelist_and_kind_filter() {
        let policy = RelayPolicy::new();
        let admin_keys = Keys::generate();
        let other_keys = Keys::generate();

        policy.add_admin(&admin_keys.public_key().to_hex());
        policy.add_whitelist(&other_keys.public_key().to_hex());
        policy.set_allowed_kinds(vec![Kind::Custom(30617)]);

        // Admin can send any kind even though not whitelisted for that kind
        let event = make_event(&admin_keys, Kind::TextNote);
        assert!(matches!(check(&policy, &event), PolicyResult::Accept));
    }
}
