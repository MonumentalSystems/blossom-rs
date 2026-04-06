# BUD-08: LFS File Locking

**Status:** Draft
**Version:** 1.0
**Authors:** MonumentalSystems

## Abstract

Defines how a Blossom server can support Git LFS file locking. This
enables exclusive file access for collaborative workflows, push
protection via lock verification, and admin override for force-unlock.
Supports both HTTP and iroh QUIC transports.

## Motivation

Git LFS uses file locking to prevent conflicting edits on binary assets.
Locking is a separate HTTP API from blob transfer — Git LFS makes lock
requests directly to a lock server. By adding lock support to Blossom
servers, teams can use a single Blossom deployment for both blob storage
and file locking.

## Namespacing

Locks are scoped by **repo ID** — an arbitrary string chosen by the
client, typically derived from the git remote URL (e.g.,
`"github.com/user/repo"`). All lock endpoints include the repo ID in the
URL path. This allows a single Blossom server to serve locks for multiple
repositories.

## Lock Object

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "path": "assets/big-file.bin",
  "locked_at": "2024-04-06T12:34:56Z",
  "owner": {
    "name": "a1b2c3d4...hex_pubkey"
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | UUID v4, server-assigned |
| `path` | string | File path relative to repo root |
| `locked_at` | string | RFC 3339 timestamp (UTC) |
| `owner.name` | string | Hex-encoded x-only Nostr pubkey of the lock owner |

## Authentication

All lock endpoints require authentication via a Nostr event. Accepted
kinds:

- **kind 24242** (Blossom auth) with action tag `"lock"`
- **kind 27235** (NIP-98)

The pubkey from the verified auth event identifies the lock owner.

## HTTP Endpoints

### Create Lock — `POST /lfs/{repo_id}/locks`

**Request:**
```json
{
  "path": "assets/big-file.bin"
}
```

**Response (201 Created):**
```json
{
  "lock": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "path": "assets/big-file.bin",
    "locked_at": "2024-04-06T12:34:56Z",
    "owner": { "name": "a1b2c3..." }
  }
}
```

**Response (409 Conflict):** Path already locked. Returns the existing
lock:
```json
{
  "lock": { ... },
  "message": "path already locked"
}
```

**Response (403 Forbidden):** User does not have lock permission.

### List Locks — `GET /lfs/{repo_id}/locks`

**Query parameters:** `path`, `id`, `cursor`, `limit` (all optional)

**Response (200 OK):**
```json
{
  "locks": [ ... ],
  "next_cursor": "optional-pagination-cursor"
}
```

Empty repos return `{ "locks": [] }`.

### Verify Locks — `POST /lfs/{repo_id}/locks/verify`

Called during `git push` to check for lock conflicts.

**Request:**
```json
{
  "cursor": "optional",
  "limit": 100
}
```

**Response (200 OK):**
```json
{
  "ours": [ ... ],
  "theirs": [ ... ],
  "next_cursor": "optional"
}
```

- **`ours`** — locks owned by the authenticated user
- **`theirs`** — locks owned by other users (pushing these files halts
  the push)

If the server returns **404**, Git LFS treats locking as unsupported and
does not block the push.

### Unlock — `POST /lfs/{repo_id}/locks/{id}/unlock`

**Request:**
```json
{
  "force": false
}
```

**Authorization rules:**

| Requester | Result |
|-----------|--------|
| Lock owner | Success (200) |
| Admin (any role) | Success (200) — implicit force |
| Non-owner, non-admin | 403 Forbidden (regardless of `force`) |

**Response (200 OK):** Returns the deleted lock.

**Response (404 Not Found):** Lock ID does not exist.

## iroh Wire Protocol

Lock operations are carried over the existing Blossom ALPN (`/blossom/1`)
using new `Op` variants:

| Op | Description | Key Request Fields |
|----|-------------|-------------------|
| `lock_create` | Create a lock | `repo_id`, `lock_path` |
| `lock_delete` | Delete a lock | `repo_id`, `lock_id`, `force` |
| `lock_list` | List locks | `repo_id`, `cursor`, `limit` |
| `lock_verify` | Verify locks | `repo_id`, `cursor`, `limit` |

All lock operations require auth. The `verify_auth` function maps all
lock ops to action `"lock"`.

### Wire Request Fields (additions to `Request`)

| Field | Type | Description |
|-------|------|-------------|
| `repo_id` | string | Repository namespace |
| `lock_id` | string | Lock UUID (for `lock_delete`) |
| `lock_path` | string | File path (for `lock_create`) |
| `force` | bool | Force unlock flag |
| `cursor` | string | Pagination cursor |
| `limit` | uint | Page size limit |

### Wire Response

Lock responses use `Status::Ok` with lock data in the `descriptor`
field as JSON:

- **Single lock:** `descriptor` = `LfsLock` JSON
- **Lock list:** `descriptor` = `{ "locks": [...], "next_cursor": "..." }`
- **Verify:** `descriptor` = `{ "ours": [...], "theirs": [...], "next_cursor": "..." }`
- **Conflict:** `Status::Conflict` with existing lock in `descriptor`

A new `Status::Conflict` variant is added for duplicate lock creation
attempts.

## Database Schema

```sql
CREATE TABLE lfs_locks (
    id          TEXT PRIMARY KEY,
    repo_id     TEXT NOT NULL,
    path        TEXT NOT NULL,
    pubkey      TEXT NOT NULL,
    locked_at   INTEGER NOT NULL,
    UNIQUE(repo_id, path)
);
CREATE INDEX idx_locks_repo ON lfs_locks(repo_id);
CREATE INDEX idx_locks_pubkey ON lfs_locks(pubkey);
```

## Admin Endpoints

Admin users (determined by `AccessControl.role(pubkey) == Admin`) have
additional capabilities:

1. **Force-unlock** any lock by posting to the unlock endpoint — admin
   role bypasses ownership check
2. **Admin API** (if `--enable-admin` is set on the server):
   - `GET /admin/locks` — list all locks across all repos
   - `GET /admin/locks?repo_id={repo}` — list locks for a specific repo
   - `DELETE /admin/locks/{id}` — force unlock any lock

## Server Configuration

Lock support is **opt-in**. A Blossom server enables it by providing a
`LockDatabase` implementation:

```rust
BlobServer::builder(backend, base_url)
    .lock_database(lock_db)  // None = lock endpoints return 404
    .build()
```

When no lock database is configured, all lock endpoints return 404. Git
LFS treats this as "locking unsupported" and does not block pushes.

## Daemon Mode (blossom-lfs)

Since Git LFS makes lock API calls via HTTP, a local daemon bridges Git
LFS to the Blossom server:

1. `blossom-lfs daemon` starts a local HTTP server on `127.0.0.1:31921`
2. `blossom-lfs setup-locks` configures `lfs.locksurl` in git config
3. The daemon extracts the repo filesystem path from the URL (base64url
   encoded), reads the repo's existing Blossom config (server, nsec,
   transport), and forwards lock requests to the Blossom server

URL format: `http://localhost:31921/lfs/<base64url(repo_path)>/locks`

The daemon supports both HTTP and iroh transports for forwarding,
using the repo's configured transport.

## Backward Compatibility

- Servers without `LockDatabase` configured return 404 on all lock
  endpoints — Git LFS treats this as unsupported
- Lock operations do not affect blob storage or existing BUD-01 through
  BUD-06 functionality
- iroh clients that do not support lock ops will receive an `Error`
  response with a descriptive message for unknown `Op` variants

## Security Considerations

- All lock endpoints require authentication (Nostr event)
- Lock ownership is tied to the Nostr pubkey — users can only unlock
  their own locks unless they are an admin
- The daemon binds to loopback only (`127.0.0.1`) — lock requests are
  not exposed to the network
- Repo filesystem paths in URLs are base64url-encoded to be URL-safe;
  the daemon validates that decoded paths contain `.git/` before reading
  config
