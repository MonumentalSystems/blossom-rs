# blossom-rs

Full-featured [Blossom](https://github.com/hzrd149/blossom) blob storage library for Rust.

Content-addressed blob storage over HTTP with BIP-340 Schnorr authorization via Nostr kind:24242/NIP-98 events.

[![CI](https://github.com/MonumentalSystems/blossom-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/MonumentalSystems/blossom-rs/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/blossom-rs.svg)](https://crates.io/crates/blossom-rs)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Workspace

| Crate | Description | Install |
|-------|-------------|---------|
| **blossom-rs** | Core library — embeddable server, async client, all traits | `cargo add blossom-rs` |
| **blossom-server** | API server — blob storage + NIP-34 relay + GRASP git server | `cargo install blossom-server` |
| **blossom-cli** | CLI client — upload/download/mirror/keygen/relay admin | `cargo install blossom-cli` |
| **blossom-nip34** | NIP-34 relay + GRASP git server library | `cargo add blossom-nip34` |

## Features

- **Decentralized git hosting** — NIP-34 Nostr relay + GRASP git HTTP server (enabled by default)
- **Blob storage** — content-addressed BUD-01 with SHA256 integrity
- **BUD-19 file locking** — Git LFS lock/unlock/verify with ownership enforcement
- **BUD-20 compression** — zstd + xdelta3 delta encoding for LFS blobs
- **BUD-03 server list** — auto-publish kind:10063 events after upload
- **NIP-94 file metadata** — auto-publish kind:1063 events after upload
- **Dual auth** — kind:24242 (Blossom) and kind:27235 (NIP-98) Nostr event authentication
- **Pluggable storage** — memory (testing), filesystem, S3-compatible backends
- **Database layer** — SQLite/Postgres via SQLx, versioned migrations
- **Relay admin** — runtime whitelist/blacklist/admin pubkeys, kind filtering, persisted to DB
- **Access control** — whitelist with hot-reload, role-based, custom policies via trait
- **Admin API** — user management, quota CRUD, blob management, LFS stats, relay policy
- **Rate limiting** — token-bucket per-key throttling
- **iroh P2P transport** — QUIC transport for uploads with HTTP download fallback
- **PKARR DHT discovery** — publish `_blossom`, `_iroh`, `_nostr` TXT records
- **Observability** — OTEL-compatible structured tracing with OTLP export
- **NIP-96** — Nostr file storage protocol endpoints
- **Build integrity** — signed release manifests, source Merkle tree attestation
- **TLS, CORS, graceful shutdown** — production-ready defaults
- **Trait-based** — `BlossomSigner`, `BlobBackend`, `BlobDatabase`, `LockDatabase`, `AccessControl`, `MediaProcessor`, `WebhookNotifier`

## Quick Start

```rust
use blossom_rs::{BlobServer, FilesystemBackend, Signer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server = BlobServer::new(
        FilesystemBackend::new("./blobs")?,
        "http://localhost:3000",
    );

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, server.router()).await?;
    Ok(())
}
```

### Full-Featured Server

```rust
use blossom_rs::{BlobServer, MemoryBackend, MemoryDatabase};
use blossom_rs::access::Whitelist;
use blossom_rs::ratelimit::{RateLimiter, RateLimitConfig};
use blossom_rs::webhooks::HttpNotifier;
use std::collections::HashSet;

let mut db = MemoryDatabase::new();
db.set_quota("pubkey_hex...", Some(50 * 1024 * 1024)).unwrap();

let server = BlobServer::builder(MemoryBackend::new(), "http://localhost:3000")
    .database(db)
    .access_control(Whitelist::new(HashSet::from(["pubkey_hex...".into()])))
    .require_auth()
    .max_upload_size(10 * 1024 * 1024)
    .body_limit(50 * 1024 * 1024)
    .rate_limiter(RateLimiter::new(RateLimitConfig { max_tokens: 60, refill_rate: 1.0 }))
    .webhook_notifier(HttpNotifier::new(vec!["https://hooks.example.com/blossom".into()]))
    .build();
```

### Client

Keys are accepted as hex (64 chars) or nsec1 bech32 format.

```rust
use blossom_rs::{BlossomClient, Signer};

let signer = Signer::generate();
let client = BlossomClient::new(
    vec!["https://blossom.example.com".into()],
    signer,
);

let desc = client.upload(b"hello", "text/plain").await?;
let data = client.download(&desc.sha256).await?;
```

## Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `server` | yes | Axum BlobServer, router, admin, TraceLayer |
| `client` | yes | reqwest BlossomClient with multi-server failover |
| `filesystem` | yes | FilesystemBackend (persistent, restart-safe) |
| `s3` | no | S3/R2/MinIO backend via `aws-sdk-s3` |
| `s3-compat` | no | S3-protocol compatibility test router |
| `db-sqlite` | yes | SQLite metadata backend via SQLx (versioned migrations) |
| `db-postgres` | no | PostgreSQL metadata backend via SQLx |
| `media` | no | Image processing (WebP, thumbnails, blurhash, EXIF) |
| `labels` | no | Content classification (Vision Transformer, LLM API) |
| `iroh-transport` | yes | P2P QUIC transport via iroh (node-ID addressed, hole-punching) |
| `pkarr-discovery` | yes | Publish endpoints to Mainline DHT via PKARR (unified Ed25519 identity) |
| `otel` | yes | OpenTelemetry OTLP export (Jaeger, Tempo, Seq, Honeycomb) |

## Protocol Support

| Protocol | Status | Endpoints |
|----------|--------|-----------|
| **BUD-01** | Implemented | `PUT /upload`, `GET/HEAD/DELETE /{sha256}` |
| **BUD-02** | Implemented | `GET /list/{pubkey}` |
| **BUD-03** | Implemented | kind:10063 server list (auto-published by CLI on upload) |
| **BUD-04** | Implemented | `PUT /mirror` |
| **BUD-06** | Implemented | `GET /upload-requirements` |
| **BUD-19** | Implemented | `POST/GET /lfs/{repo_id}/locks`, verify, unlock (default on) |
| **BUD-20** | Implemented | zstd + xdelta3 LFS compression/delta (server-side) |
| **NIP-34** | Implemented | Nostr relay (WebSocket) + GRASP git HTTP server (default on) |
| **NIP-94** | Implemented | kind:1063 file metadata (auto-published by CLI on upload) |
| **NIP-96** | Implemented | `GET /.well-known/nostr/nip96.json`, `POST/GET/DELETE /n96` |
| **NIP-98** | Implemented | kind:27235 HTTP auth (accepted alongside kind:24242) |
| **BIP-340** | Implemented | Schnorr signature auth on all write operations |
| **Admin** | Implemented | `/admin/*` (stats, users, quotas, blobs, LFS stats) + `/relay/admin/*` |
| **S3-compat** | Implemented | `PUT/GET/HEAD/DELETE /{bucket}/{*key}` (feature-gated) |
| **Health** | Implemented | `GET /health` |
| **Status** | Implemented | `GET /status` (with build integrity) |
| **iroh** | Implemented | P2P QUIC via `/blossom/1` ALPN |
| **PKARR** | Implemented | `_blossom`, `_iroh`, `_nostr` TXT records |

## Architecture

All extension points are trait-based:

```
BlossomSigner   — BIP-340 signing (bring your own identity)
BlobBackend     — blob storage (Memory, Filesystem, S3)
BlobDatabase    — metadata persistence (Memory, SQLite, Postgres)
LockDatabase    — BUD-19 file locks (Memory, SQLite, Postgres)
AccessControl   — authorization (OpenAccess, Whitelist, custom)
WebhookNotifier — event notifications (Noop, HTTP POST, custom)
MediaProcessor  — image/video processing (Passthrough, ImageProcessor)
MediaLabeler    — content classification (Noop, BlockAll, custom)
```

### Server Builder

```rust
BlobServer::builder(backend, "http://localhost:3000")
    .database(db)               // BlobDatabase impl
    .access_control(whitelist)  // AccessControl impl
    .require_auth()             // Enforce auth on uploads
    .max_upload_size(10_000_000) // BUD-06 size limit
    .allowed_types(vec!["image/png".into()]) // BUD-06 type filter
    .body_limit(50_000_000)     // HTTP body size limit
    .rate_limiter(limiter)      // Token-bucket rate limiting
    .webhook_notifier(notifier) // Lifecycle event webhooks
    .media_processor(processor) // BUD-05 image processing on PUT /media
    .lock_database(blossom_rs::locks::MemoryLockDatabase::new()) // BUD-19 file locking
    .build();
```

## Observability

All key functions are instrumented with `#[tracing::instrument]` using [OTEL semantic conventions](https://opentelemetry.io/docs/specs/semconv/):

| Namespace | Fields |
|-----------|--------|
| `http.*` | `method`, `route`, `status_code` |
| `blob.*` | `sha256`, `size`, `content_type` |
| `auth.*` | `pubkey`, `action`, `kind` |
| `storage.*` | `backend`, `data_dir`, `bucket` |
| `server.*` | `url` |
| `error.*` | `message` |

**Zero-cost by default** — `tracing` is a no-op without a subscriber.

**Opt-in OTLP export** for Jaeger, Grafana Tempo, Seq, Honeycomb, etc.:

```toml
blossom-rs = { version = "0.1", features = ["otel"] }
```

```rust
let _guard = blossom_rs::otel::init_tracing("my-server", "info")?;
```

## Testing

```bash
cargo test --workspace                          # 207 tests
cargo test --workspace --features db-sqlite     # Include SQLite backend tests
cargo llvm-cov --workspace --features db-sqlite # Coverage report

# Optional integration tests (require external services):
R2_ENDPOINT=... cargo test --features s3 --test s3_integration
RUN_POSTGRES_TESTS=1 cargo test --features db-postgres --test postgres_integration
```

## CI/CD

- **CI**: On push/PR to master — `cargo fmt --all --check`, `cargo build --workspace`, `cargo test --workspace`, `cargo clippy --workspace`
- **Publish**: On `v*` tags — test, then publish `blossom-rs` → `blossom-server` + `blossom-cli` to crates.io
- Self-hosted runner for trusted pushes; GitHub-hosted for fork PRs

## Acknowledgments

This library draws on patterns and design decisions from:

- **[route96](https://github.com/v0l/route96)** by v0l — Rust Blossom/NIP-96 server implementation. Reference for NIP-96 protocol, database schema patterns, media processing pipeline, EXIF validation, content labeling traits, whitelist access control, and file statistics. Licensed under MIT.

- **[hzrd149/blossom](https://github.com/hzrd149/blossom)** — The Blossom protocol specification (BUD-01 through BUD-06).

- The broader [Nostr](https://github.com/nostr-protocol/nostr) ecosystem for NIP-01, NIP-96, NIP-98, and BIP-340 standards.

## License

MIT
