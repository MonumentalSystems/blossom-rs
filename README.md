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
| **blossom-server** | API server binary — filesystem + SQLite, CORS, TLS, admin, rate limiting | `cargo install blossom-server` |
| **blossom-cli** | CLI client — upload/download/mirror/keygen, hex + nsec1 key support | `cargo install blossom-cli` |

## Features

- **Embeddable server** — mount a Blossom-compliant Axum router into your app
- **Async client** — upload/download with multi-server failover and SHA256 integrity
- **Dual auth** — kind:24242 (Blossom) and kind:27235 (NIP-98) Nostr event authentication
- **Pluggable storage** — memory (testing), filesystem, S3-compatible backends
- **Database layer** — metadata persistence with SQLite/Postgres via SQLx, versioned migrations
- **Access control** — whitelist with hot-reload, custom policies via trait
- **Admin API** — user management, quota CRUD, blob management, server stats
- **Rate limiting** — token-bucket per-key throttling with configurable refill
- **Webhook notifications** — fire-and-forget HTTP POST on upload/delete/mirror events
- **File statistics** — lock-free egress tracking with DashMap accumulator, periodic DB flush
- **Observability** — OTEL-compatible structured tracing with opt-in OTLP export
- **NIP-96** — Nostr file storage protocol endpoints
- **BUD-01/02/04/06** — core Blossom protocol + list, mirror, upload requirements
- **Health check** — `GET /health` for load balancer probes
- **CORS** — configurable origins or allow-all for browser clients
- **TLS** — optional rustls-based HTTPS via `axum-server`
- **Graceful shutdown** — flushes stats to DB on Ctrl+C
- **Media processing** — WebP conversion, thumbnails, blurhash, EXIF validation (feature-gated)
- **Content labeling** — pluggable classification traits for moderation (feature-gated)
- **Perceptual hashing** — image dedup support via phash field in upload records
- **Trait-based** — implement `BlossomSigner`, `BlobBackend`, `BlobDatabase`, `AccessControl`, `MediaProcessor`, `MediaLabeler`, or `WebhookNotifier` for your own types

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
| `db-sqlite` | no | SQLite metadata backend via SQLx (versioned migrations) |
| `db-postgres` | no | PostgreSQL metadata backend via SQLx |
| `media` | no | Image processing (WebP, thumbnails, blurhash, EXIF) |
| `labels` | no | Content classification (Vision Transformer, LLM API) |
| `iroh-transport` | no | P2P QUIC transport via iroh (node-ID addressed, hole-punching) |
| `pkarr-discovery` | no | Publish endpoints to Mainline DHT via PKARR (unified Ed25519 identity) |
| `otel` | no | OpenTelemetry OTLP export (Jaeger, Tempo, Seq, Honeycomb) |

## Protocol Support

| Protocol | Status | Endpoints |
|----------|--------|-----------|
| **BUD-01** | Implemented | `PUT /upload`, `GET/HEAD/DELETE /:sha256` |
| **BUD-02** | Implemented | `GET /list/:pubkey` |
| **BUD-04** | Implemented | `PUT /mirror` |
| **BUD-06** | Implemented | `GET /upload-requirements` |
| **NIP-96** | Implemented | `GET /.well-known/nostr/nip96.json`, `POST/GET/DELETE /n96` |
| **NIP-98** | Implemented | kind:27235 HTTP auth (accepted alongside kind:24242) |
| **BIP-340** | Implemented | Schnorr signature auth on all write operations |
| **Admin** | Implemented | `GET/PUT/DELETE /admin/*` (stats, users, quotas, blobs) |
| **S3-compat** | Implemented | `PUT/GET/HEAD/DELETE /:bucket/*key` (feature-gated) |
| **Health** | Implemented | `GET /health` |
| **Status** | Implemented | `GET /status` |
| **iroh** | Implemented | P2P QUIC via `/blossom/1` ALPN (feature-gated) |
| **PKARR** | Implemented | DHT endpoint discovery via `_blossom` / `_iroh` TXT records (feature-gated) |

## Architecture

All extension points are trait-based:

```
BlossomSigner   — BIP-340 signing (bring your own identity)
BlobBackend     — blob storage (Memory, Filesystem, S3)
BlobDatabase    — metadata persistence (Memory, SQLite, Postgres)
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
