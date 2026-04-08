# CLAUDE.md — blossom-rs

## Project Overview

**blossom-rs** is an embeddable Blossom (BUD-01) blob storage library for Rust.
Content-addressed blob storage over HTTP with BIP-340 Schnorr authorization via
Nostr kind:24242 and NIP-98 kind:27235 events. Published to crates.io.

Repository: `MonumentalSystems/blossom-rs`

## Workspace Structure

```
blossom-rs/          — Core library (crates.io: blossom-rs)
blossom-server/      — API server binary (crates.io: blossom-server)
blossom-cli/         — CLI client binary (crates.io: blossom-cli)
xdelta3-rs/          — Vendored xdelta3 bindings (bindgen 0.71)
xtask/               — Build tasks (sign-release-manifest, source-merkle-tree)
```

## Build & Test Commands

```bash
cargo build --workspace              # Build all crates
cargo build --all-features           # Build everything including s3, otel, media, etc.
cargo test --workspace               # Run all tests (207 tests)
cargo clippy --workspace -- -D warnings  # Lint all crates
cargo fmt --all --check              # Format check all crates
cargo fmt --all                      # Auto-format all crates
cargo doc --no-deps --open           # Generate and view docs
cargo llvm-cov --features db-sqlite  # Coverage report
cargo publish --dry-run -p blossom-rs  # Verify crates.io packaging

# Run server
cargo run -p blossom-server                           # Default: filesystem + SQLite
cargo run -p blossom-server -- --memory               # In-memory mode
cargo run -p blossom-server -- --enable-admin          # With admin endpoints
cargo run -p blossom-server -- --no-locks              # Disable BUD-19 locking (on by default)

# Run CLI client
cargo run -p blossom-cli -- keygen                    # Generate keypair
cargo run -p blossom-cli -- -k <key> upload file.txt  # Upload
cargo run -p blossom-cli -- status                    # Server status
```

## Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `server` | yes | Axum BlobServer, router, admin, TraceLayer |
| `client` | yes | reqwest BlossomClient with multi-server failover |
| `filesystem` | yes | FilesystemBackend (persistent, restart-safe) |
| `s3` | no | S3/R2/MinIO backend via aws-sdk-s3 |
| `s3-compat` | no | S3-compat test router (requires `server`) |
| `db-sqlite` | no | SQLite metadata backend via SQLx (versioned migrations) |
| `db-postgres` | no | PostgreSQL metadata backend via SQLx |
| `media` | no | Image processing (WebP, thumbnails, blurhash, EXIF) |
| `labels` | no | Content labeling (Vision Transformer, LLM API) |
| `iroh-transport` | yes | P2P QUIC transport via iroh (node-ID addressed) |
| `pkarr-discovery` | yes | PKARR endpoint publishing via DHT + relays (implies iroh-transport) |
| `otel` | yes | OpenTelemetry OTLP export (Jaeger, Tempo, Seq) |

## Architecture

### Module Map

```
src/
├── lib.rs              — Public API, feature-gated re-exports
├── protocol.rs         — NostrEvent, BlobDescriptor, base64url, sha256_hex
├── otel.rs             — OTEL init helper, TracingGuard (feature-gated)
├── ratelimit.rs        — RateLimiter, RateLimitConfig (token bucket)
├── webhooks.rs         — WebhookNotifier trait, HttpNotifier, NoopNotifier
├── stats.rs            — StatsAccumulator (DashMap + atomic counters)
├── auth/
│   ├── mod.rs          — build_blossom_auth, verify_blossom_auth, AuthError
│   ├── nip98.rs        — build_nip98_auth, verify_nip98_auth (kind:27235)
│   └── signer.rs       — BlossomSigner trait, default Signer (secp256k1 BIP-340)
├── storage/
│   ├── mod.rs          — BlobBackend trait, make_descriptor helper
│   ├── memory.rs       — MemoryBackend (HashMap, for testing)
│   ├── filesystem.rs   — FilesystemBackend (sha256.blob files, index scan)
│   └── s3.rs           — S3Backend (aws-sdk-s3, optional CDN URL)
├── db/
│   ├── mod.rs          — BlobDatabase trait, UploadRecord (with phash), DbError
│   ├── memory.rs       — MemoryDatabase (in-process, no persistence)
│   ├── sqlite.rs       — SqliteDatabase (SQLx, versioned migrations V1/V2)
│   └── postgres.rs     — PostgresDatabase (SQLx)
├── locks/
│   ├── mod.rs          — LockDatabase trait, MemoryLockDatabase
│   ├── sqlite.rs       — SqliteLockDatabase (feature-gated: db-sqlite)
│   └── postgres.rs     — PostgresLockDatabase (feature-gated: db-postgres)
├── server/
│   ├── mod.rs          — BlobServer, BlobServerBuilder, ServerState, handlers
│   ├── admin.rs        — Admin endpoints (users, quotas, blobs, stats, LFS stats)
│   ├── locks.rs        — BUD-19 lock endpoints (create, list, verify, unlock)
│   └── nip96.rs        — NIP-96 endpoints (info, upload, list, delete)
├── client/
│   └── mod.rs          — BlossomClient with failover + SHA256 integrity
├── access/
│   └── mod.rs          — AccessControl trait, OpenAccess, Whitelist
├── media/
│   ├── mod.rs          — MediaProcessor trait, PassthroughProcessor
│   └── image_processor.rs — ImageProcessor (feature-gated)
├── transport/
│   ├── mod.rs          — Transport module re-exports
│   ├── wire.rs         — Wire protocol codec (JSON-line + binary framing)
│   ├── iroh_transport.rs — BlossomProtocol (iroh ProtocolHandler, feature-gated)
│   ├── iroh_client.rs  — IrohBlossomClient (P2P client, feature-gated)
│   └── pkarr_discovery.rs — PkarrPublisher, resolve (feature-gated)
└── labels/
    └── mod.rs          — MediaLabeler trait, NoopLabeler, BlockAllLabeler
```

### Key Traits

- **`BlossomSigner`** — BIP-340 signing. Implement for your identity type.
- **`BlobBackend`** — Blob storage (Memory, Filesystem, S3). Wrapped in `Arc<Mutex<>>`.
- **`BlobDatabase`** — Metadata persistence (uploads, users, quotas, stats, phash).
- **`LockDatabase`** — BUD-19 file locks (Memory, SQLite, Postgres).
- **`AccessControl`** — Authorization (OpenAccess, Whitelist, custom).
- **`WebhookNotifier`** — Event notifications (Noop, HTTP POST, custom).
- **`MediaProcessor`** — Image/video processing pipeline.
- **`MediaLabeler`** — Content classification.

### Design Conventions

- Content-addressed: SHA256 = blob key = natural deduplication
- Traits for all extension points; concrete types behind feature flags
- Sync trait interfaces wrapped in `Arc<Mutex<>>` for async handlers
- `tokio::task::block_in_place` for async-to-sync bridging (SQLite, S3)
- `thiserror` for all error enums
- `tracing` with `#[instrument]` and OTEL semantic convention field names
- `serde` derive on all public types; optional fields use `skip_serializing_if`
- Axum 0.7 route syntax (`:param` not `{param}`)
- Versioned DB migrations with `schema_version` table

### Tracing / Observability

All key functions instrumented with `#[tracing::instrument]`. OTEL field naming:

- `http.method`, `http.route`, `http.status_code` — from TraceLayer
- `blob.sha256`, `blob.size`, `blob.content_type` — blob identity
- `auth.pubkey`, `auth.action`, `auth.kind` — Nostr auth context
- `storage.backend`, `storage.data_dir`, `storage.bucket` — backend info
- `server.url`, `webhook.url` — remote endpoints
- `error.message` — structured error context
- `otel.name`, `otel.kind` — span metadata

## Testing Conventions

- 207 tests: 114 lib unit + 18 lib integration + 5 property + 10 SQLite + 16 server e2e + 6 iroh
- Unit tests in `#[cfg(test)] mod tests` at bottom of each module
- Async integration tests use `#[tokio::test]` with ephemeral TCP listeners
- SQLite tests use `#[tokio::test(flavor = "multi_thread")]` for block_in_place
- Server tests spawn a real Axum server on `127.0.0.1:0` (random port)
- Filesystem tests use `std::env::temp_dir()` with random suffixes, clean up after
- All new public functions must have tests
- Use `MemoryBackend` / `MemoryDatabase` in tests to avoid external dependencies
- Property tests with `proptest` where data integrity matters

## CI/CD

- **CI** (`.github/workflows/ci.yml`): On push/PR to master — fmt, build, test, clippy (workspace)
- **Publish** (`.github/workflows/publish.yml`): On `v*` tags — test → publish lib → publish server + cli → build release binaries → sign with `BLOSSOM_RELEASE_NSEC` → upload to GitHub release
- Self-hosted runner for trusted pushes; GitHub-hosted for fork PRs
- GPG signing disabled for CI commits

## Git Conventions

- Branch: `master`
- Commit messages: imperative, concise, focus on "why"
- No GPG signing required (`gpg nosign`)
- Tag releases as `v0.1.0`, `v0.1.1`, etc.

## Protocol References

- **BUD-01**: Core blob upload/download/delete (implemented)
- **BUD-02**: List blobs by pubkey (implemented)
- **BUD-04**: Mirror from remote URL (implemented)
- **BUD-06**: Upload requirements advertisement (implemented)
- **BUD-17**: Chunked storage with Merkle tree manifests (implemented)
- **BUD-19**: LFS file locking with ownership enforcement (implemented)
- **BUD-20**: LFS-aware storage efficiency — zstd + xdelta3 (implemented)
- **NIP-96**: Nostr file storage protocol (implemented)
- **NIP-98**: HTTP auth via kind:27235 events (implemented)
- **NIP-01**: Nostr event format (used for auth)
- **BIP-340**: Schnorr signatures on secp256k1

## Dependencies Policy

- Minimal dependency tree for core (crypto + serde + tokio + tracing + dashmap)
- Optional deps behind feature flags
- `secp256k1` 0.29 for BIP-340 (matches ecosystem)
- `axum` 0.7 for server
- `reqwest` 0.12 for client
- `sqlx` for database backends
- `tracing` + `tracing-opentelemetry` for observability
- No `unsafe` code
