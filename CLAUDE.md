# CLAUDE.md — blossom-rs

## Project Overview

**blossom-rs** is an embeddable Blossom (BUD-01) blob storage library for Rust.
Content-addressed blob storage over HTTP with BIP-340 Schnorr authorization via
Nostr kind:24242 events. Targets crates.io publication.

Repository: `MonumentalSystems/blossom-rs`

## Workspace Structure

```
blossom-rs/          — Core library (crates.io: blossom-rs)
blossom-server/      — Example API server binary (all features)
blossom-cli/         — CLI client binary (upload/download/keygen/etc.)
```

## Build & Test Commands

```bash
cargo build --workspace              # Build all crates
cargo build --all-features           # Build everything including s3, otel, media, etc.
cargo test --workspace               # Run all tests (101 tests)
cargo clippy --workspace -- -D warnings  # Lint all crates
cargo fmt --all --check              # Format check all crates
cargo fmt --all                      # Auto-format all crates
cargo doc --no-deps --open           # Generate and view docs
cargo llvm-cov                       # Coverage report (~92-95% line coverage)
cargo publish --dry-run              # Verify crates.io packaging (lib only)

# Run example server
cargo run -p blossom-server                           # Default: filesystem + SQLite
cargo run -p blossom-server -- --memory               # In-memory mode

# Run CLI client
cargo run -p blossom-cli -- keygen                    # Generate keypair
cargo run -p blossom-cli -- -k <key> upload file.txt  # Upload
cargo run -p blossom-cli -- status                    # Server status
```

## Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `server` | yes | Axum BlobServer and router with TraceLayer |
| `client` | yes | reqwest BlossomClient with multi-server failover |
| `filesystem` | yes | FilesystemBackend (persistent, restart-safe) |
| `s3` | no | S3/R2/MinIO backend via aws-sdk-s3 |
| `s3-compat` | no | S3-compat test router (requires `server`) |
| `db-sqlite` | no | SQLite metadata backend via SQLx |
| `db-postgres` | no | PostgreSQL metadata backend via SQLx |
| `media` | no | Image processing (WebP, thumbnails, blurhash, EXIF) |
| `labels` | no | Content labeling (Vision Transformer, LLM API) |
| `otel` | no | OpenTelemetry OTLP export (Jaeger, Tempo, Seq) |

## Architecture

### Module Map

```
src/
├── lib.rs              — Public API, feature-gated re-exports
├── protocol.rs         — NostrEvent, BlobDescriptor, base64url, sha256_hex, compute_event_id
├── otel.rs             — OTEL init helper, TracingGuard (feature-gated)
├── auth/
│   ├── mod.rs          — build_blossom_auth, verify_blossom_auth, AuthError
│   └── signer.rs       — BlossomSigner trait, default Signer (secp256k1 BIP-340)
├── storage/
│   ├── mod.rs          — BlobBackend trait, make_descriptor helper
│   ├── memory.rs       — MemoryBackend (HashMap, for testing)
│   ├── filesystem.rs   — FilesystemBackend (sha256.blob files, index scan on startup)
│   └── s3.rs           — S3Backend (aws-sdk-s3, optional CDN URL)
├── db/
│   ├── mod.rs          — BlobDatabase trait, UploadRecord, UserRecord, FileStats, DbError
│   ├── memory.rs       — MemoryDatabase (in-process, no persistence)
│   ├── sqlite.rs       — SqliteDatabase (SQLx)
│   └── postgres.rs     — PostgresDatabase (SQLx)
├── server/
│   ├── mod.rs          — BlobServer, BlobServerBuilder, HTTP handlers, TraceLayer
│   └── nip96.rs        — NIP-96 endpoints (info, upload, list, delete)
├── client/
│   └── mod.rs          — BlossomClient with failover + SHA256 integrity
├── access/
│   └── mod.rs          — AccessControl trait, OpenAccess, Whitelist (hot-reload)
├── media/
│   ├── mod.rs          — MediaProcessor trait, PassthroughProcessor
│   └── image_processor.rs — ImageProcessor (feature-gated: WebP, thumbnail, blurhash, EXIF)
├── labels/
│   └── mod.rs          — MediaLabeler trait, NoopLabeler, BlockAllLabeler
└── stats.rs            — StatsAccumulator (DashMap + atomic counters, DB flush)
```

### Key Traits

- **`BlossomSigner`** — BIP-340 signing. Implement for your identity type.
- **`BlobBackend`** — Synchronous blob storage (Memory, Filesystem, S3). Wrapped in `Arc<Mutex<>>` by server.
- **`BlobDatabase`** — Metadata persistence (uploads, users, quotas, stats).
- **`AccessControl`** — Authorization decisions (OpenAccess, Whitelist, custom).
- **`MediaProcessor`** — Image/video processing pipeline.
- **`MediaLabeler`** — Content classification.

### Design Conventions

- Content-addressed: SHA256 = blob key = natural deduplication
- Traits for all extension points; concrete types behind feature flags
- Sync trait interfaces wrapped in `Arc<Mutex<>>` for async handlers
- `thiserror` for all error enums
- `tracing` with `#[instrument]` and OTEL semantic convention field names
- `serde` derive on all public types; optional fields use `skip_serializing_if`
- Axum 0.7 route syntax (`:param` not `{param}`)

### Tracing / Observability

All key functions are instrumented with `#[tracing::instrument]`. Field naming
follows OTEL semantic conventions:

- `http.method`, `http.route`, `http.status_code` — from TraceLayer
- `blob.sha256`, `blob.size`, `blob.content_type` — blob identity
- `auth.pubkey`, `auth.action`, `auth.kind` — Nostr auth context
- `storage.backend`, `storage.data_dir`, `storage.bucket` — backend info
- `server.url` — which server handled a client request
- `error.message` — structured error context
- `otel.name`, `otel.kind` — span metadata

Zero-cost when no `tracing` subscriber is configured. Enable the `otel`
feature for OTLP export to Jaeger, Grafana Tempo, Seq, etc.

## Testing Conventions

- 96 tests: 73 unit + 18 integration + 5 property (proptest)
- 92% line coverage across all modules
- Unit tests in `#[cfg(test)] mod tests` at bottom of each module
- Async integration tests use `#[tokio::test]` with ephemeral TCP listeners
- Server tests spawn a real Axum server on `127.0.0.1:0` (random port)
- Filesystem tests use `std::env::temp_dir()` with random suffixes, clean up after
- All new public functions must have tests
- Use `MemoryBackend` / `MemoryDatabase` in tests to avoid external dependencies
- Property tests with `proptest` where data integrity matters

## CI/CD

- **CI** (`.github/workflows/ci.yml`): On push/PR to master — fmt check, build all targets, test, clippy
- **Publish** (`.github/workflows/publish.yml`): On `v*` tags — test then `cargo publish`
- Self-hosted runner, `dtolnay/rust-toolchain@stable`
- GPG signing disabled for CI commits

## Git Conventions

- Branch: `master`
- Commit messages: imperative, concise, focus on "why"
- No GPG signing required (`gpg nosign`)
- Tag releases as `v0.1.0`, `v0.2.0`, etc.

## Protocol References

- **BUD-01**: Core blob upload/download/delete (implemented)
- **BUD-02**: List blobs by pubkey (implemented)
- **BUD-04**: Mirror from remote URL (implemented)
- **BUD-06**: Upload requirements advertisement (implemented)
- **NIP-96**: Nostr file storage protocol (implemented)
- **NIP-01**: Nostr event format (used for auth)
- **BIP-340**: Schnorr signatures on secp256k1

## Dependencies Policy

- Minimal dependency tree for core (crypto + serde + tokio + tracing)
- Optional deps behind feature flags
- `secp256k1` 0.29 for BIP-340 (matches ecosystem)
- `axum` 0.7 for server
- `reqwest` 0.12 for client
- `sqlx` for database backends
- `tracing` + `tracing-opentelemetry` for observability
- No `unsafe` code
