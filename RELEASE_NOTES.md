# Release Notes

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
