//! GRASP validation plugins for NIP-34 events.
//!
//! Clean-room implementation from the NIP-34 public specification.
//! <https://github.com/nostr-protocol/nips/blob/master/34.md>

use nostr::{Event, TagKind};

use crate::nip34_types;

/// Maximum allowed repository name length.
pub const MAX_REPO_NAME_LEN: usize = 30;

/// Validate a repository announcement event (kind 30617).
///
/// Checks:
/// - Has a `d` tag (repository identifier)
/// - Identifier is valid: ≤30 chars, ASCII alphanumeric + hyphens + underscores
/// - Has at least one `clone` tag with a URL
/// - Has at least one `relays` tag
pub fn validate_repo_announcement(event: &Event) -> Result<(), &'static str> {
    if event.kind != nip34_types::REPO_ANNOUNCEMENT {
        return Ok(()); // not our concern
    }

    // Must have d tag
    let d_tag = event
        .tags
        .iter()
        .find(|t| t.kind() == TagKind::d())
        .and_then(|t| t.content())
        .ok_or("repository announcement missing 'd' tag")?;

    let d_value = d_tag.to_string();

    // Validate identifier
    if d_value.is_empty() || d_value.len() > MAX_REPO_NAME_LEN {
        return Err("repository name must be 1-30 characters");
    }
    if !d_value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err("repository name must be alphanumeric, hyphens, or underscores");
    }

    // Must have clone URL(s)
    let has_clone = event
        .tags
        .iter()
        .any(|t| t.kind() == TagKind::custom("clone"));
    if !has_clone {
        return Err("repository announcement missing 'clone' tag");
    }

    // Must have relay(s)
    let has_relays = event
        .tags
        .iter()
        .any(|t| t.kind() == TagKind::custom("relays"));
    if !has_relays {
        return Err("repository announcement missing 'relays' tag");
    }

    Ok(())
}

/// Validate a repository state event (kind 30618).
///
/// Checks:
/// - Has a `d` tag matching a repo identifier
/// - Has a HEAD ref tag
/// - All ref values look like valid SHA1 hex (40 chars)
pub fn validate_repo_state(event: &Event) -> Result<(), &'static str> {
    if event.kind != nip34_types::REPO_STATE {
        return Ok(());
    }

    // Must have d tag
    let _d_tag = event
        .tags
        .iter()
        .find(|t| t.kind() == TagKind::d())
        .and_then(|t| t.content())
        .ok_or("repository state missing 'd' tag")?;

    // Must have HEAD
    let has_head = event
        .tags
        .iter()
        .any(|t| t.kind() == TagKind::custom("HEAD"));
    if !has_head {
        return Err("repository state missing 'HEAD' tag");
    }

    // Validate ref SHA1 format for refs/ tags
    for tag in event.tags.iter() {
        let kind_str = tag.kind().to_string();
        if kind_str.starts_with("refs/") {
            if let Some(sha) = tag.content() {
                let sha_str = sha.to_string();
                if sha_str.len() != 40 || !sha_str.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err("invalid SHA1 hash in ref tag");
                }
            }
        }
    }

    Ok(())
}

/// Check if a domain appears in the relay and clone tags of a repo announcement.
pub fn repo_has_domain(event: &Event, domain: &str) -> bool {
    if event.kind != nip34_types::REPO_ANNOUNCEMENT {
        return false;
    }

    let domain_in_relays = event.tags.iter().any(|t| {
        t.kind() == TagKind::custom("relays")
            && t.content()
                .map(|c| c.to_string().contains(domain))
                .unwrap_or(false)
    });

    let domain_in_clone = event.tags.iter().any(|t| {
        t.kind() == TagKind::custom("clone")
            && t.content()
                .map(|c| c.to_string().contains(domain))
                .unwrap_or(false)
    });

    domain_in_relays && domain_in_clone
}

/// Extract the repository identifier (`d` tag) from a NIP-34 event.
pub fn extract_repo_id(event: &Event) -> Option<String> {
    event
        .tags
        .iter()
        .find(|t| t.kind() == TagKind::d())
        .and_then(|t| t.content())
        .map(|c| c.to_string())
}

/// Extract the repository description from a repo announcement.
pub fn extract_description(event: &Event) -> Option<String> {
    event
        .tags
        .iter()
        .find(|t| t.kind() == TagKind::custom("description"))
        .and_then(|t| t.content())
        .map(|c| c.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::prelude::*;

    fn make_repo_announcement(d_tag: &str, clone_url: &str, relay_url: &str) -> Event {
        let keys = Keys::generate();
        EventBuilder::new(nip34_types::REPO_ANNOUNCEMENT, "")
            .tag(Tag::identifier(d_tag))
            .tag(Tag::custom(TagKind::custom("clone"), [clone_url]))
            .tag(Tag::custom(TagKind::custom("relays"), [relay_url]))
            .sign_with_keys(&keys)
            .unwrap()
    }

    fn make_repo_state(d_tag: &str, head_ref: &str, sha: &str) -> Event {
        let keys = Keys::generate();
        EventBuilder::new(nip34_types::REPO_STATE, "")
            .tag(Tag::identifier(d_tag))
            .tag(Tag::custom(TagKind::custom("HEAD"), [head_ref]))
            .tag(Tag::custom(TagKind::custom(head_ref), [sha]))
            .sign_with_keys(&keys)
            .unwrap()
    }

    #[test]
    fn test_valid_repo_announcement() {
        let event = make_repo_announcement(
            "my-repo",
            "https://example.com/npub1.../my-repo.git",
            "wss://relay.example.com",
        );
        assert!(validate_repo_announcement(&event).is_ok());
    }

    #[test]
    fn test_repo_name_too_long() {
        let event = make_repo_announcement(
            "this-name-is-way-too-long-for-a-repo",
            "https://example.com/repo.git",
            "wss://relay.example.com",
        );
        assert!(validate_repo_announcement(&event).is_err());
    }

    #[test]
    fn test_repo_name_invalid_chars() {
        let event = make_repo_announcement(
            "repo with spaces",
            "https://example.com/repo.git",
            "wss://relay.example.com",
        );
        assert!(validate_repo_announcement(&event).is_err());
    }

    #[test]
    fn test_valid_repo_state() {
        let sha = "a".repeat(40);
        let event = make_repo_state("my-repo", "refs/heads/main", &sha);
        assert!(validate_repo_state(&event).is_ok());
    }

    #[test]
    fn test_repo_state_invalid_sha() {
        let event = make_repo_state("my-repo", "refs/heads/main", "not-a-sha");
        assert!(validate_repo_state(&event).is_err());
    }

    #[test]
    fn test_repo_has_domain() {
        let event = make_repo_announcement(
            "my-repo",
            "https://git.example.com/npub1.../my-repo.git",
            "wss://git.example.com",
        );
        assert!(repo_has_domain(&event, "git.example.com"));
        assert!(!repo_has_domain(&event, "other.com"));
    }

    #[test]
    fn test_extract_repo_id() {
        let event = make_repo_announcement(
            "test-repo",
            "https://example.com/repo.git",
            "wss://relay.example.com",
        );
        assert_eq!(extract_repo_id(&event), Some("test-repo".into()));
    }
}
