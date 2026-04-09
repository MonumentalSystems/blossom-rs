//! Git pkt-line parser for receive-pack ref updates.
//!
//! Parses the ref update commands from a git-receive-pack request body.
//! Format per git pack-protocol: `<old-oid> <new-oid> <refname>[\0capabilities]`

/// Null OID (40 zeros) — indicates ref creation or deletion.
pub const NULL_OID: &str = "0000000000000000000000000000000000000000";

/// A parsed ref update from a receive-pack request.
#[derive(Debug, Clone)]
pub struct RefUpdate<'a> {
    pub old_oid: &'a str,
    pub new_oid: &'a str,
    pub refname: &'a str,
    pub capabilities: Option<&'a str>,
}

impl<'a> RefUpdate<'a> {
    /// Is this a new branch/ref creation?
    pub fn is_create(&self) -> bool {
        self.old_oid == NULL_OID
    }

    /// Is this a ref deletion?
    pub fn is_delete(&self) -> bool {
        self.new_oid == NULL_OID
    }
}

/// Check if a string is a valid 40-char hex SHA1.
fn is_valid_sha1(s: &str) -> bool {
    s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Parse a single ref update payload (without the 4-byte length prefix).
fn parse_ref_update(payload: &[u8]) -> Result<RefUpdate<'_>, &'static str> {
    let payload = payload.strip_suffix(b"\n").unwrap_or(payload);
    let s = std::str::from_utf8(payload).map_err(|_| "invalid UTF-8 in pkt-line")?;

    let mut parts = s.splitn(3, ' ');
    let old_oid = parts.next().ok_or("missing old oid")?;
    let new_oid = parts.next().ok_or("missing new oid")?;
    let ref_with_caps = parts.next().ok_or("missing refname")?;

    let (refname, capabilities) = match ref_with_caps.split_once('\0') {
        Some((name, caps)) => (name, Some(caps.trim())),
        None => (ref_with_caps, None),
    };

    if !is_valid_sha1(old_oid) {
        return Err("invalid old oid");
    }
    if !is_valid_sha1(new_oid) {
        return Err("invalid new oid");
    }
    if !refname.starts_with("refs/") {
        return Err("refname must start with refs/");
    }

    Ok(RefUpdate {
        old_oid,
        new_oid,
        refname,
        capabilities,
    })
}

/// Parse pkt-line formatted ref updates from a receive-pack body.
///
/// Stops at flush packet (0000) or end of data.
pub fn parse_ref_updates(body: &[u8]) -> Result<Vec<RefUpdate<'_>>, &'static str> {
    let mut updates = Vec::new();
    let mut pos = 0;

    while pos + 4 <= body.len() {
        let len_str =
            std::str::from_utf8(&body[pos..pos + 4]).map_err(|_| "invalid pkt-line length")?;

        let len = u16::from_str_radix(len_str, 16).map_err(|_| "invalid hex in pkt-line length")?
            as usize;

        // flush/delimiter/response-end
        if len <= 2 {
            break;
        }
        if len < 4 {
            return Err("pkt-line length too short");
        }
        if pos + len > body.len() {
            return Err("pkt-line extends beyond body");
        }

        let payload = &body[pos + 4..pos + len];

        // Only parse lines that look like ref updates (start with two SHA1s)
        if let Ok(s) = std::str::from_utf8(payload) {
            let mut parts = s.split(' ');
            if is_valid_sha1(parts.next().unwrap_or(""))
                && is_valid_sha1(parts.next().unwrap_or(""))
            {
                updates.push(parse_ref_update(payload)?);
            }
        }

        pos += len;
    }

    Ok(updates)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_ref_update() {
        let data = b"0067ac281124fd463f368106445a4fe4eb251d9c7d7a 4559b8048c334a7e61c76a622cf7cd578a6af406 refs/heads/master";
        let updates = parse_ref_updates(data).unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].refname, "refs/heads/master");
        assert_eq!(
            updates[0].old_oid,
            "ac281124fd463f368106445a4fe4eb251d9c7d7a"
        );
        assert_eq!(
            updates[0].new_oid,
            "4559b8048c334a7e61c76a622cf7cd578a6af406"
        );
        assert!(!updates[0].is_create());
        assert!(!updates[0].is_delete());
    }

    #[test]
    fn test_parse_create_branch() {
        let payload = b"0000000000000000000000000000000000000000 53e284c5c3e8b8310077a43d09fd391456f582df refs/heads/new-branch";
        let update = parse_ref_update(payload).unwrap();
        assert!(update.is_create());
        assert!(!update.is_delete());
    }

    #[test]
    fn test_parse_delete_branch() {
        let payload = b"53e284c5c3e8b8310077a43d09fd391456f582df 0000000000000000000000000000000000000000 refs/heads/old-branch";
        let update = parse_ref_update(payload).unwrap();
        assert!(update.is_delete());
    }

    #[test]
    fn test_flush_stops_parsing() {
        let mut data = Vec::new();
        data.extend_from_slice(b"00ab0000000000000000000000000000000000000000 ac281124fd463f368106445a4fe4eb251d9c7d7a refs/heads/master\0report-status-v2 side-band-64k object-format=sha1 agent=git/2.51.2\n");
        data.extend_from_slice(b"0000");
        data.extend_from_slice(b"PACK\x00\x00\x00\x02");

        let updates = parse_ref_updates(&data).unwrap();
        assert_eq!(updates.len(), 1);
        assert!(updates[0].is_create());
        assert!(updates[0].capabilities.is_some());
    }

    #[test]
    fn test_two_ref_updates() {
        let mut data = Vec::new();
        data.extend_from_slice(b"00acac281124fd463f368106445a4fe4eb251d9c7d7a 4559b8048c334a7e61c76a622cf7cd578a6af406 refs/heads/master\0 report-status-v2 side-band-64k object-format=sha1 agent=git/2.51.2\n");
        data.extend_from_slice(b"00684559b8048c334a7e61c76a622cf7cd578a6af406 53e284c5c3e8b8310077a43d09fd391456f582df refs/heads/develop");
        data.extend_from_slice(b"0000");

        let updates = parse_ref_updates(&data).unwrap();
        assert_eq!(updates.len(), 2);
        assert_eq!(updates[0].refname, "refs/heads/master");
        assert_eq!(updates[1].refname, "refs/heads/develop");
    }
}
