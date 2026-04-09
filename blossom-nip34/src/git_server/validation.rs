//! GRASP push validation — check ref updates against Nostr relay state.
//!
//! Per the GRASP spec, pushes are validated by checking:
//! 1. A kind:30617 repo announcement exists for this repo
//! 2. A kind:30618 repo state event exists from the author or maintainers
//! 3. The ref updates match what the state event declares

use std::collections::HashMap;
use std::sync::Arc;

use nostr::{Event, Filter, TagKind};
use nostr_database::NostrDatabase;

use super::pktline::RefUpdate;
use crate::nip34_types;

/// Result of push validation — maps refname to error message for rejected refs.
pub type PushErrors<'a> = HashMap<&'a str, &'static str>;

/// Validate a push against the Nostr relay state.
///
/// Returns `Ok(empty map)` if all refs are accepted.
/// Returns `Ok(map with errors)` if some refs are rejected.
/// Returns `Err` if the validation itself fails (missing repo announcement, DB error).
pub async fn validate_push<'a>(
    ref_updates: &[RefUpdate<'a>],
    database: &Arc<dyn NostrDatabase>,
    author_hex: &str,
    repo_id: &str,
) -> Result<PushErrors<'a>, (u16, &'static str)> {
    let author_pubkey =
        nostr::PublicKey::from_hex(author_hex).map_err(|_| (400u16, "invalid author pubkey"))?;

    // 1. Look up kind:30617 repo announcement
    let announcement = database
        .query(
            Filter::new()
                .author(author_pubkey)
                .identifier(repo_id)
                .kind(nip34_types::REPO_ANNOUNCEMENT),
        )
        .await
        .map_err(|_| (500u16, "database error looking up repo announcement"))?;

    let announcement = announcement.first().ok_or((
        404u16,
        "no repository announcement found — publish kind:30617 first",
    ))?;

    // 2. Get maintainers from announcement
    let maintainers = extract_maintainers(announcement);

    // 3. Look up kind:30618 repo state from author or maintainers
    let mut state_filter = Filter::new()
        .identifier(repo_id)
        .kind(nip34_types::REPO_STATE)
        .author(author_pubkey);

    for m in &maintainers {
        if let Ok(pk) = nostr::PublicKey::from_hex(m) {
            state_filter = state_filter.author(pk);
        }
    }

    let state_events = database
        .query(state_filter)
        .await
        .map_err(|_| (500u16, "database error looking up repo state"))?;

    let state_event = state_events.first().ok_or((
        400u16,
        "no repository state found — publish kind:30618 first",
    ))?;

    // 4. Validate each ref update against state
    let state_refs = extract_state_refs(state_event);
    let mut errors = HashMap::new();

    for update in ref_updates {
        if let Err(reason) = check_ref_update(update, &state_refs) {
            errors.insert(update.refname, reason);
        }
    }

    Ok(errors)
}

/// Check a single ref update against the repo state refs.
fn check_ref_update(
    update: &RefUpdate<'_>,
    state_refs: &HashMap<String, String>,
) -> Result<(), &'static str> {
    let state_oid = state_refs.get(update.refname);

    match (state_oid, update.is_delete(), update.is_create()) {
        // Ref exists in state, not a delete — new oid must match state
        (Some(expected), false, _) => {
            if update.new_oid != expected {
                Err("ref update doesn't match repository state")
            } else {
                Ok(())
            }
        }
        // Ref not in state, creating — ok (new ref)
        (None, false, true) => Ok(()),
        // Ref not in state, not create/delete — error
        (None, false, false) => Err("ref not found in repository state"),
        // Delete where ref exists in state — not allowed
        (Some(_), true, _) => Err("cannot delete ref that exists in repository state"),
        // Delete where ref not in state — ok (already gone)
        (None, true, _) => Ok(()),
    }
}

/// Extract maintainer pubkeys from a kind:30617 event's tags.
fn extract_maintainers(event: &Event) -> Vec<String> {
    event
        .tags
        .iter()
        .filter(|t| t.kind() == TagKind::custom("maintainers"))
        .filter_map(|t| t.content().map(|c| c.to_string()))
        .collect()
}

/// Extract ref → oid mappings from a kind:30618 state event.
fn extract_state_refs(event: &Event) -> HashMap<String, String> {
    let mut refs = HashMap::new();
    for tag in event.tags.iter() {
        let kind_str = tag.kind().to_string();
        if kind_str.starts_with("refs/") {
            if let Some(oid) = tag.content() {
                refs.insert(kind_str, oid.to_string());
            }
        }
    }
    refs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git_server::pktline::NULL_OID;

    fn make_state_refs(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn make_update<'a>(old: &'a str, new: &'a str, refname: &'a str) -> RefUpdate<'a> {
        RefUpdate {
            old_oid: old,
            new_oid: new,
            refname,
            capabilities: None,
        }
    }

    #[test]
    fn test_ref_update_matches_state() {
        let state = make_state_refs(&[(
            "refs/heads/main",
            "abc123abc123abc123abc123abc123abc123abc1",
        )]);
        let update = make_update(
            "0000000000000000000000000000000000000000",
            "abc123abc123abc123abc123abc123abc123abc1",
            "refs/heads/main",
        );
        assert!(check_ref_update(&update, &state).is_ok());
    }

    #[test]
    fn test_ref_update_mismatch() {
        let state = make_state_refs(&[(
            "refs/heads/main",
            "abc123abc123abc123abc123abc123abc123abc1",
        )]);
        let update = make_update(
            "0000000000000000000000000000000000000000",
            "def456def456def456def456def456def456def4",
            "refs/heads/main",
        );
        assert!(check_ref_update(&update, &state).is_err());
    }

    #[test]
    fn test_new_ref_creation() {
        let state = make_state_refs(&[]);
        let update = make_update(
            NULL_OID,
            "abc123abc123abc123abc123abc123abc123abc1",
            "refs/heads/new-branch",
        );
        assert!(check_ref_update(&update, &state).is_ok());
    }

    #[test]
    fn test_delete_ref_not_in_state() {
        let state = make_state_refs(&[]);
        let update = make_update(
            "abc123abc123abc123abc123abc123abc123abc1",
            NULL_OID,
            "refs/heads/gone",
        );
        assert!(check_ref_update(&update, &state).is_ok());
    }

    #[test]
    fn test_delete_ref_still_in_state() {
        let state = make_state_refs(&[(
            "refs/heads/main",
            "abc123abc123abc123abc123abc123abc123abc1",
        )]);
        let update = make_update(
            "abc123abc123abc123abc123abc123abc123abc1",
            NULL_OID,
            "refs/heads/main",
        );
        assert!(check_ref_update(&update, &state).is_err());
    }
}
