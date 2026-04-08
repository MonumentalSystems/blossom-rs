# Release Notes

## v0.5.0

### Major: NIP-34 Decentralized Git Hosting

blossom-server is now a fully decentralized GitHub alternative — a single binary providing blob storage, Nostr relay, and GRASP git server.

#### New Crate: `blossom-nip34`

MIT-licensed NIP-34 Nostr relay + GRASP git server library. Enabled by default in blossom-server.

- **Nostr relay** — NIP-34 event storage (repos, patches, issues, status) via WebSocket, backed by LMDB
- **GRASP git server** — HTTP smart protocol (`git clone`/`git push`) at `/{npub}/{repo}.git/*`
- **Push auth** — `git push` requires Nostr signature from the repo owner (npub in URL)
- **NIP-11** — relay information document at `/` with `Accept: application/nostr+json`
- **GRASP validation plugins** — repo announcement validation (name rules, clone/relay URLs), repo state validation (HEAD ref, SHA1 format)
- **Relay admin policies** — runtime-mutable whitelist/blacklist/admin pubkeys, event size limits, kind filtering. All persisted to SQLite or PostgreSQL.
- **Admin HTTP endpoints** — `GET/PUT/DELETE /relay/admin/{policy,whitelist,blacklist,admins}`
- **Auto repo creation** — bare git repos created on filesystem when kind:30617 events arrive

#### NIP-34 Event Kinds Supported

| Kind | Event |
|------|-------|
| 30617 | Repository Announcement |
| 30618 | Repository State |
| 1617 | Patches |
| 1618 | Pull Requests |
| 1619 | PR Updates |
| 1621 | Issues |
| 1630–1633 | Status (Open/Applied/Closed/Draft) |
| 10317 | User Grasp List |

### Nostr Event Publishing

- **NIP-94 file metadata (kind:1063)** — `blossom-cli upload` publishes file metadata events (URL, SHA256, MIME, size) to the server's relay after upload
- **BUD-03 server list (kind:10063)** — publishes user's server list after upload
- Both enabled by default, `--no-publish` to opt out
- New `nostr_events` module in blossom-rs library

### Axum 0.8 Migration

- Entire workspace upgraded from axum 0.7 → 0.8
- Route syntax updated: `:param` → `{param}`, `*path` → `{*path}`
- axum-server 0.7 → 0.8 for TLS

### CLI: Relay Admin Commands

New `blossom-cli relay` subcommand group:
- `relay policy` — view full policy summary
- `relay whitelist-list/add/remove` — manage relay whitelist
- `relay blacklist-list/add/remove` — manage relay blacklist
- `relay admin-list/add` — manage relay admin pubkeys

### PKARR Discovery

- `_nostr` TXT record — relay WebSocket URL published alongside `_blossom` and `_iroh` records
- `resolve_all_endpoints()` — returns HTTP URL, iroh node ID, and Nostr relay URL
- `ResolvedEndpoints` struct for structured resolution

### Default Changes

- **NIP-34 relay enabled by default** in blossom-server (`--no-relay` to disable)
- **JSON logs by default** (`--log-pretty` for human-readable)
- **Per-binary manifest naming** — `<binary-name>.manifest.json` (supports multiple binaries in same directory)

### Build & Integrity

- **Vendored xdelta3** — bindgen 0.52 → 0.71, eliminates all future-Rust deprecation warnings
- **CI signs release manifests** — `blossom-server.manifest.json` and `blossom-cli.manifest.json` uploaded to GitHub releases
- **Integrity logged at startup** — verified/unsigned/mismatch status

### Fixes

- pkarr: DHT feature removed for crates.io publishability (mainline digest conflict)
- Runtime DB files (.db, relay_db/) added to .gitignore
- CI: `fmt → clippy → test` order, dropped redundant `cargo build` step

---

## v0.4.2

### New Features

- **`GET /admin/lfs-stats`** — Admin endpoint exposing LFS storage efficiency metrics: total original bytes vs stored bytes, savings percentage, and per-storage-type breakdown (raw, compressed, delta).
- **`blossom-cli admin lfs-stats`** — CLI command to query LFS storage statistics from the server.
- **PKARR DHT support** — pkarr now publishes/resolves via Mainline DHT directly (in addition to relays). Resolves `digest` version conflict between `mainline` and `iroh` via cargo patch.
- **Default features now include iroh + pkarr** — `cargo build` gives you HTTP, iroh QUIC transport, and PKARR DHT discovery out of the box.

### Improvements

- **Vendor xdelta3 crate** — Replaced crates.io `xdelta3 0.1.5` (bindgen 0.52, cexpr 0.3.6, nom 4.2.3) with vendored `xdelta3-rs` using bindgen 0.71. Eliminates all "code will be rejected by a future version of Rust" warnings. Drops `libc` and `rand 0.6` deps. Replaces runtime sizeof detection with compile-time constants.

---

## v0.4.1

### Bug Fixes

- **`blossom-server --enable-locks`** — Add CLI flag to enable BUD-19 file locking endpoints. Previously, lock endpoints were implemented in the library but never wired up in the server binary, causing all lock requests to return 404.
- Lock endpoints (`POST/GET /lfs/{repo_id}/locks`, `POST /lfs/{repo_id}/locks/verify`, `POST /lfs/{repo_id}/locks/{id}/unlock`) are now mounted when `--enable-locks` is passed.
- Server uses `SqliteLockDatabase` by default (persistent across restarts); falls back to `MemoryLockDatabase` with `--memory`.

### Persistent Lock Databases

- **`SqliteLockDatabase`** — SQLite-backed lock persistence (feature `db-sqlite`). Creates `lfs_locks` table with auto-migration. Locks survive server restarts.
- **`PostgresLockDatabase`** — PostgreSQL-backed lock persistence (feature `db-postgres`). Same schema and behavior as SQLite variant.
- Both implement the `LockDatabase` trait and can be used with `.lock_database()` on the server builder.

### Tests

- 10 SQLite lock integration tests: create, conflict, unlock (owner/non-owner), list, path filter, verify ours/theirs, cross-repo isolation, full lifecycle, and **persistence across server restart**.

### Documentation

- README protocol support table now lists BUD-19 (LFS File Locking).
- Server builder example includes `.lock_database()`.
- Architecture section lists `LockDatabase` trait.

---

## v0.4.0

### Breaking Changes

- `BlobBackend` trait gains `insert_with_hash()` method for storing data under a pre-computed SHA-256 (required for BUD-20 compressed storage)
- `BlobServer::builder()` now accepts `lock_database()` and `lfs_version_database()` builder methods
- `ServerState` has new fields: `lock_db`, `lfs_version_db`
- V4 SQLite migration adds `lfs_file_versions` table
- New public modules: `locks`, `lfs`
- New public types: `LockDatabase`, `LockError`, `LockFilters`, `LockRecord`, `MemoryLockDatabase`, `LfsContext`, `LfsFileVersion`, `LfsStorageType`, `LfsStorageStats`, `LfsVersionDatabase`, `MemoryLfsVersionDatabase`
- `build_blossom_auth_with_extra_tags()` added to `auth` module for arbitrary extra tags in auth events
- `BlossomClient::upload_lfs()` method added with LFS context tags (path, repo, base, manifest)

### BUD-17: Chunked Storage

- `docs/BUD-17.md` — Spec for BUD-07 chunked blob storage with Merkle tree manifests
- Foundation for efficient storage of large files via chunking + manifest upload

### BUD-19: LFS File Locking

- **`locks` module** — `LockDatabase` trait, `LockError`, `LockFilters`, `LockRecord`, `MemoryLockDatabase` implementation
- **Lock HTTP endpoints** — `POST/GET /lfs/{repo_id}/locks`, `POST /lfs/{repo_id}/locks/verify`, `POST /lfs/{repo_id}/locks/{id}/unlock`
- **Admin force unlock** — Admin role holders can unlock any lock (server sets `force=true` implicitly)
- **Ownership enforcement** — Only the lock owner can unlock (unless admin or force)
- **iroh transport** — Wire protocol lock operations + iroh client lock methods
- **Integration tests** — 13 HTTP lock tests, 6 iroh lock tests

### BUD-20: LFS-Aware Storage Efficiency

- **`docs/BUD-20.md`** — Full spec covering auth tags, storage pipeline, download reconstruction, database schema
- **`lfs` module** — `LfsContext` (tag parsing from auth events), `LfsVersionDatabase` trait, `MemoryLfsVersionDatabase`, `LfsFileVersion`, `LfsStorageType`, `LfsStorageStats`
- **`lfs/compress`** — zstd compress/decompress (level 3), xdelta3 encode/decode, delta threshold check (80%)
- **Storage pipeline**:
  - No LFS tags → raw storage (unchanged)
  - LFS + manifest → raw storage
  - LFS + no base → zstd compress → store
  - LFS + base tag → xdelta3 delta → if delta < 80% of original, store delta; else fall back to compressed
- **Transparent download** — GET/HEAD reconstruct original bytes via decompression and delta chain walking (max depth 10)
- **DELETE handler** — Rebases dependent deltas into full compressed blobs before deleting base
- **SQLite V4 migration** — `lfs_file_versions` table with `LfsVersionDatabase` impl
- **Client `upload_lfs()`** — Upload with LFS context tags (path, repo, base, manifest)
- **Integration tests** — 6 LFS storage tests (compressed upload/download, delta round-trip, non-LFS unchanged, manifest raw, HEAD original size, version tracking)

### Fixes

- iroh client download used `Op::Head` instead of `Op::Get`
- iroh tests run serially to avoid FD exhaustion
- Clippy clean across full workspace (`cargo clippy --workspace --all-targets -- -D warnings`)
- 184+ tests passing

---

## v0.3.0

### Breaking Changes

- `IrohState` has new required fields: `access`, `max_upload_size`, `require_auth`
- `UserRecord` now includes `role` field (defaults to `"member"` via serde)
- `BlobDatabase` trait gains `set_role()`, `get_role()`, `list_users_by_role()` methods
- `BlobBackend` trait gains `insert_stream()` method (default impl buffers to Vec for backward compat)
- `BlobClient` trait gains `upload_file()` method
- V3 schema migration adds `role TEXT NOT NULL DEFAULT 'member'` to `users` table (SQLite/Postgres)

### Role-Based Access Control

- **Admin/Member/Denied roles** — `Role` enum with `RoleBasedAccess` struct backed by DB persistence
- **`--admin npub1...`** server flag — bootstrap admin pubkeys on first startup, persisted across restarts
- **Ownership-enforced delete** — members can only delete their own blobs, admins can delete any blob, anonymous uploads deletable by anyone
- Consistent enforcement across HTTP, NIP-96, and iroh QUIC transports
- **Admin API** — `PUT /admin/users/:pubkey/role` (set role), `GET /admin/roles` (list by role)
- `AccessControl` trait gains `role()` method with backward-compatible default

### Unified Client & Transport Preference

- **`BlobClient` trait** — transport-agnostic async interface using RPITIT (no `async_trait` dep needed)
- **`MultiTransportClient`** — iroh for uploads/deletes (direct P2P), HTTP for downloads (CDN caching), automatic fallback on failure
- **Full method parity** — both HTTP and iroh clients now support upload, download, exists, delete, list
- CLI: `--iroh <endpoint>` and `--iroh-only` flags; all commands use `MultiTransportClient`

### Streaming & Memory Efficiency

- **`insert_stream()`** on `BlobBackend` — FilesystemBackend and S3Backend stream to storage via temp file + incremental SHA256 in 256KB chunks, never buffering full blobs in memory
- **`upload_file()`** — two-pass streaming file upload (hash pass + send pass) on both HTTP and iroh clients
- **`upload_batch_concurrent()`** — parallel file uploads with `Arc<C>` + `Semaphore` (default 8 concurrent streams)
- **`sha256_stream()`** — incremental SHA256 from any `Read` impl
- CLI: `batch-upload` command with `--concurrency` flag, `upload` command now streams (no `std::fs::read`)

### Iroh Transport Parity

- `AccessControl` added to `IrohState` — upload permission, quota, max size, and require_auth enforcement matching HTTP
- `list()` added to `IrohBlossomClient`
- `upload_file()` streams file chunks directly to QUIC `SendStream`

### Build Integrity

- **Deterministic source hashing** — `build.rs` on blossom-server and blossom-cli hashes all workspace source files via `git ls-files`, embeds aggregate hash via `rustc-env`
- **`integrity.rs`** — `RuntimeIntegrityInfo` exposed on `GET /status`, signed release manifests with BIP-340 signature verification, Merkle tree attestation for zero-knowledge selective file disclosure
- **xtask** — `sign-release-manifest`, `source-build-manifest`, `source-merkle-tree`, `verify-source-file`

### Fixes

- **OpenTelemetry** — add missing `tracing-subscriber` dep, update to `opentelemetry_sdk` 0.27 API
- NIP-96 delete handler now enforces ownership checks
- 140+ tests across workspace

---

## v0.2.1

### Bug Fixes

- **HEAD `/:sha256` returns `Content-Length`** — was returning 0, now returns actual blob size.

### New Features

- **`blossom-cli media <FILE>`** — upload with server-side processing (BUD-05 `PUT /media`). Returns optimized blob descriptor with blurhash, dimensions, and perceptual hash.
- **`blossom-cli admin` subcommand** — CLI interface for admin endpoints:
  - `admin stats` — server statistics
  - `admin get-user <PUBKEY>` — user info + quota
  - `admin set-quota <PUBKEY> [BYTES]` — set user quota (omit for unlimited)
  - `admin list-blobs` — blob count + total size
  - `admin delete-blob <SHA256>` — admin delete (no ownership check)
  - `admin whitelist-list` — list all whitelisted pubkeys
  - `admin whitelist-add <PUBKEY>` — add pubkey to whitelist at runtime
  - `admin whitelist-remove <PUBKEY>` — remove pubkey from whitelist at runtime
- **Live whitelist management API** — `PUT/DELETE /admin/whitelist/:pubkey` and `GET /admin/whitelist` endpoints for runtime access control changes without server restart.
- **`BlobServerBuilder::whitelist()`** — new builder method that sets access control and stores a live handle for admin endpoints.
- **`Whitelist::list()`** — new method to enumerate all whitelisted pubkeys.
- **`blossom-cli upload --content-type <MIME>`** — override auto-detected Content-Type.
- **Server-side MIME auto-detection** — server detects Content-Type from magic bytes (PNG, JPEG, GIF, WebP, PDF, ZIP, GZIP, MP4) when header is missing or generic.

---

## v0.2.0

### Breaking Changes

- `BlossomClient::with_timeout()` — new constructor for custom timeout (default still 30s).
- SHA256 path parameters are now validated (64-char hex) — invalid paths return 400 instead of 404.
- Upload handler uses `Content-Type` request header instead of hardcoding `application/octet-stream`.
- `GET /<sha256>.ext` — file extension is now stripped (BUD-01 compliance).

### New Features

- **Server `--s3-endpoint`** — S3/R2/MinIO blob storage backend from CLI (with `--s3-bucket`, `--s3-region`, `--s3-public-url`).
- **Server `--db-postgres`** — PostgreSQL metadata backend from CLI.
- **Postgres versioned migrations** — `schema_version` table with V1 (initial) and V2 (phash column), matching SQLite.
- **Iroh connection caching** — `IrohBlossomClient` reuses QUIC connections per node ID.
- **Concurrent upload tests** — 20 parallel uploads + 10 parallel download verification.
- **Wire protocol fuzz tests** — proptest for request/response roundtrip.
- **Dockerfile** — Multi-stage build for `blossom-server`.
- **MSRV** — Minimum Supported Rust Version: 1.80.
- **CI iroh tests** — `cargo test --features iroh-transport --test iroh_integration` in CI pipeline.

### Improvements

- Server warns when using `--memory` + `--iroh` (separate blob stores).
- `to_json_response()` helper replaces remaining `unwrap()` in production HTTP handlers.
- SHA256 parameter validation on GET/HEAD/DELETE endpoints.
- `Content-Type` from upload request header recorded in database.
- VitLabeler and LlmLabeler marked as TODO in source.
- 207 total tests.

---

## v0.1.5

### New Features

- **PKARR discovery** merged to master (`pkarr-discovery` feature flag). Publish blossom endpoints (`_blossom` + `_iroh` TXT records) to Mainline DHT via PKARR relays. Unified Ed25519 identity with iroh transport.
- **`blossom-cli resolve`** — Resolve a PKARR public key (`pk:z<base32>`) to HTTP URL + iroh node ID.
- **Server `--pkarr` flag** — Auto-publish endpoints with background republish loop.

### Improvements

- **CLI integration tests** — 15 new tests covering all commands, key formats, output formatting, webhook delivery, admin endpoints, error handling.
- **Unwrap cleanup** — Replaced 8 `serde_json::to_value().unwrap()` calls in HTTP handlers with `to_json_response()` helper (returns 500 instead of panicking).
- Removed unused imports across test files.
- 184 total tests.

---

## v0.1.4

### New Features

- **iroh P2P transport** (`iroh-transport` feature) — Blossom blob operations over iroh QUIC connections, addressed by node ID. No IP/DNS required. Wire protocol uses JSON-line headers + binary payload over `/blossom/1` ALPN.
- **PKARR discovery** (`pkarr-discovery` feature) — Publish blossom endpoints (`_blossom` + `_iroh` TXT records) to Mainline DHT via PKARR relays. Unified Ed25519 identity: same secret key for iroh node ID and PKARR public key.
- **`blossom-cli resolve`** — New command to resolve PKARR public keys to HTTP + iroh endpoints.
- **Server `--iroh` flag** — Enable iroh transport alongside HTTP, with persistent node ID via `--iroh-key-file`.
- **Server `--pkarr` flag** — Auto-publish endpoints to PKARR relays with background republish loop.
- **CLI iroh support** — Auto-detects `iroh://<node-id>` in `--server` URL for upload/download/exists/delete.

### Documentation

- `docs/iroh-transport.md` — Full wire protocol specification with mermaid architecture and sequence diagrams, server/client usage, PKARR discovery section, auth reuse, key constraints.
- Updated all READMEs with iroh/PKARR feature flags, protocol support, CLI options.
- Added RELEASE_NOTES.md.

### Tests

- 6 iroh integration tests (upload+download, exists, delete, nonexistent, large blob, integrity)
- 4 PKARR unit tests (keypair, packet building, config, unified identity proof)
- 4 PKARR live integration tests (publish+resolve, update, nonexistent, unified identity)
- 169 total tests across workspace

---

## v0.1.2

### New Features

- **BUD-05 `PUT /media`** — Server-side media processing via `MediaProcessor` trait. Processes images to extract thumbnails, blurhash, perceptual hash. Enabled via `--media` flag or `.media_processor()` builder.
- **NIP-98 auth** (kind:27235) — Server accepts both kind:24242 (Blossom) and kind:27235 (NIP-98) auth events automatically.
- **Admin API** — `/admin/stats`, `/admin/users/:pubkey`, `/admin/users/:pubkey/quota`, `/admin/blobs`, `/admin/blobs/:sha256`. All require Admin access control action.
- **Rate limiting** — Token-bucket per-key throttling via `RateLimiter`. Configurable max tokens and refill rate. Returns 429 when exhausted.
- **Webhook notifications** — `WebhookNotifier` trait, `HttpNotifier` (fire-and-forget POST on upload/delete/mirror).
- **Configurable CORS** — `--cors-origins` flag for specific origin list (default: allow all).
- **Versioned DB migrations** — `schema_version` table, V1 (initial schema), V2 (phash column).
- **Perceptual hash field** — `UploadRecord.phash`, `find_by_phash()` trait method, phash index in SQLite.
- **Per-user quota API** — Admin endpoints for get/set quota via HTTP.
- **CLI delete confirmation** — Prompts `[y/N]`, skip with `--yes`.
- **CLI `--format json|text`** — Output format flag for all commands.
- **Postgres integration tests** — Docker-based (postgres:16-alpine), full lifecycle.
- **S3/R2 integration tests** — Verified against live Cloudflare R2 (8 tests).
- **Media feature tests** — 19 ImageProcessor tests with programmatic image generation.

### Bug Fixes

- Fixed `base64url_decode` pointer arithmetic bug (was using cross-allocation pointers).
- Fixed `block_in_place` nested runtime panic in SQLite/Postgres/S3 backends.
- Fixed `blurhash` `usize` to `u32` type error that prevented `media` feature from compiling.
- Fixed S3 build errors from `aws-sdk-s3` API changes (`contents()` returns slice, not `Option`).

---

## v0.1.1

### New Features

- **`blossom-server`** binary crate — Full API server with filesystem storage, SQLite metadata, NIP-96, auth enforcement, whitelist access control, CORS, TLS, graceful shutdown, structured JSON tracing.
- **`blossom-cli`** binary crate — CLI client with upload, download, exists, delete, list, mirror, status, keygen. Supports hex and nsec1 bech32 keys.
- **Workspace conversion** — 3 crate workspace (blossom-rs lib, blossom-server, blossom-cli).
- **OTEL instrumentation** — `#[tracing::instrument]` on all handlers and client methods with OTEL semantic convention field names. `TraceLayer` on router.
- **`otel` feature flag** — Optional `tracing-opentelemetry` + OTLP export with `init_tracing()` helper.
- **Database layer** — `BlobDatabase` trait, `MemoryDatabase`, `SqliteDatabase`, `PostgresDatabase`.
- **S3 backend** — Full `BlobBackend` impl for S3/R2/MinIO with CDN URL support.
- **Access control** — `AccessControl` trait, `OpenAccess`, `Whitelist` with hot-reload.
- **File statistics** — `StatsAccumulator` with DashMap + atomic counters, DB flush.
- **NIP-96** — Full endpoint support (info, upload, list, delete).
- **BUD-02/04/06** — List by pubkey, mirror from URL, upload requirements.
- **Server builder pattern** — `BlobServer::builder()` with database, access control, auth, size limits.
- **CI/CD** — GitHub Actions with self-hosted runners, fork PR sandboxing, crates.io publish pipeline.

---

## v0.1.0

### Initial Release

- Core Blossom (BUD-01) server library for Rust.
- Content-addressed blob storage over HTTP with BIP-340 Schnorr authorization via Nostr kind:24242 events.
- `BlossomSigner` trait for pluggable identity.
- `BlobBackend` trait with `MemoryBackend` and `FilesystemBackend`.
- `BlossomClient` with multi-server failover and SHA256 integrity checks.
- Axum 0.7 router with PUT/GET/HEAD/DELETE endpoints.
- 19 tests.
