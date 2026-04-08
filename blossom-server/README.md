# blossom-server

Blossom blob storage API server built on [blossom-rs](https://github.com/MonumentalSystems/blossom-rs).

[![crates.io](https://img.shields.io/crates/v/blossom-server.svg)](https://crates.io/crates/blossom-server)

## What You Get Out of the Box

A plain `cargo install blossom-server && blossom-server` gives you:

- **BUD-19 file locking** — enabled by default with SQLite persistence (opt out with `--no-locks`)
- **SQLite metadata** — uploads, users, quotas, LFS file versions, lock database
- **iroh hybrid transport** — P2P QUIC uploads + HTTP downloads (activate with `--iroh`)
- **PKARR DHT discovery** — publish endpoints to Mainline DHT + relays (activate with `--iroh --pkarr`)
- **OpenTelemetry tracing** — structured JSON logs with OTEL field names, ready for Jaeger/Tempo
- **Build integrity** — source hash embedded at compile time, signed release manifests in CI
- **BUD-20 compression** — server-side zstd + xdelta3 delta encoding for LFS blobs
- **Rate limiting, CORS, TLS, graceful shutdown** — production-ready defaults

## Quick Start

```bash
cargo install blossom-server

# Default: filesystem storage + SQLite + locks enabled
blossom-server

# With iroh P2P + PKARR DHT advertisement
blossom-server --iroh --pkarr

# In-memory (no persistence, good for testing)
blossom-server --memory

# Custom bind address and base URL
blossom-server --bind 0.0.0.0:8080 --base-url https://blobs.example.com

# Full production setup
blossom-server \
  --bind 0.0.0.0:3000 \
  --base-url https://blobs.example.com \
  --require-auth \
  --admin npub1... \
  --enable-admin \
  --iroh --pkarr \
  --tls-cert cert.pem --tls-key key.pem
```

## Options

```
blossom-server [OPTIONS]

Storage:
  -d, --data-dir <PATH>          Blob storage directory [default: ./blobs]
      --memory                   Use in-memory storage (no persistence)
      --s3-endpoint <URL>        S3-compatible endpoint (overrides --data-dir)
      --s3-bucket <NAME>         S3 bucket name [default: blobs]
      --s3-region <REGION>       S3 region [default: auto]
      --s3-public-url <URL>      S3 CDN/public URL prefix

Database:
      --db-path <PATH>           SQLite database path [default: ./blossom.db]
      --db-postgres <URL>        PostgreSQL connection URL (overrides SQLite)

Network:
  -b, --bind <ADDR>              Listen address [default: 0.0.0.0:3000]
  -u, --base-url <URL>           Public base URL [default: http://localhost:3000]
      --tls-cert <FILE>          TLS certificate (PEM)
      --tls-key <FILE>           TLS private key (PEM)
      --cors-origins <ORIGINS>   CORS allowed origins (comma-separated, default: all)

Auth & Access:
      --require-auth             Require BIP-340 auth for uploads
      --whitelist <FILE>         Path to pubkey whitelist file
      --whitelist-reload-secs <N> Whitelist hot-reload interval [default: 0]
      --admin <PUBKEY>           Bootstrap admin pubkey (hex or npub, repeatable)
      --enable-admin             Enable admin endpoints at /admin/*

Locking:
      --no-locks                 Disable BUD-19 file locking (enabled by default)

P2P Transport:
      --iroh                     Enable iroh P2P transport alongside HTTP
      --iroh-key-file <PATH>     Iroh secret key file [default: ./iroh_secret.key]
      --pkarr                    Enable PKARR DHT endpoint discovery (requires --iroh)
      --pkarr-republish-secs <N> PKARR republish interval [default: 3600]

Limits:
      --max-upload-size <BYTES>  Max upload size in bytes
      --body-limit <BYTES>       Max HTTP body size [default: 268435456 (256 MB)]
      --allowed-types <TYPES>    Comma-separated MIME types (empty = all)
      --rate-limit-max <N>       Max requests per bucket [default: 60]
      --rate-limit-refill <F>    Token refill rate per second [default: 1.0]
      --no-rate-limit            Disable rate limiting

Other:
      --media                    Enable media processing on PUT /media (BUD-05)
      --webhook-urls <URLS>      Webhook URLs (comma-separated)
      --stats-flush-secs <N>     Stats flush interval [default: 60]
      --keygen                   Generate a keypair and exit
      --log-level <LEVEL>        Log level [default: info]
```

## API Endpoints

| Method | Path | Description | Protocol |
|--------|------|-------------|----------|
| `PUT` | `/upload` | Upload a blob | BUD-01 |
| `GET` | `/:sha256` | Download a blob | BUD-01 |
| `HEAD` | `/:sha256` | Check existence + size | BUD-01 |
| `DELETE` | `/:sha256` | Delete a blob (auth required) | BUD-01 |
| `GET` | `/list/:pubkey` | List blobs by uploader | BUD-02 |
| `PUT` | `/mirror` | Mirror from remote URL | BUD-04 |
| `PUT` | `/media` | Upload with processing (`--media`) | BUD-05 |
| `GET` | `/upload-requirements` | Server constraints | BUD-06 |
| `POST` | `/lfs/:repo_id/locks` | Create lock | BUD-19 |
| `GET` | `/lfs/:repo_id/locks` | List locks | BUD-19 |
| `POST` | `/lfs/:repo_id/locks/verify` | Verify locks (ours/theirs) | BUD-19 |
| `POST` | `/lfs/:repo_id/locks/:id/unlock` | Unlock | BUD-19 |
| `GET` | `/status` | Server statistics + build integrity | - |
| `GET` | `/health` | Health check (200 OK) | - |
| `GET` | `/admin/stats` | Server statistics | Admin |
| `GET` | `/admin/lfs-stats` | LFS storage efficiency metrics | Admin |
| `GET` | `/admin/users/:pubkey` | Get user record | Admin |
| `PUT` | `/admin/users/:pubkey/quota` | Set user quota | Admin |
| `PUT` | `/admin/users/:pubkey/role` | Set user role | Admin |
| `GET` | `/admin/roles` | List users by role | Admin |
| `GET` | `/admin/blobs` | Blob count and size | Admin |
| `DELETE` | `/admin/blobs/:sha256` | Admin delete blob | Admin |
| `GET` | `/admin/whitelist` | List whitelisted pubkeys | Admin |
| `PUT` | `/admin/whitelist/:pubkey` | Add to whitelist | Admin |
| `DELETE` | `/admin/whitelist/:pubkey` | Remove from whitelist | Admin |
| `GET` | `/.well-known/nostr/nip96.json` | NIP-96 server info | NIP-96 |
| `POST` | `/n96` | NIP-96 upload | NIP-96 |
| `GET` | `/n96` | NIP-96 file list | NIP-96 |
| `DELETE` | `/n96/:sha256` | NIP-96 delete | NIP-96 |

## Build Integrity

The server embeds a deterministic source hash at compile time and reports it via `GET /status`:

```json
{
  "integrity": {
    "integrity_status": "verified",
    "source_build_hash": "b52cdffc...",
    "build_target": "x86_64-unknown-linux-gnu",
    "release_signer_npub": "npub1..."
  }
}
```

- **unsigned** — built from source (normal for `cargo install`)
- **verified** — pre-built binary with signed release manifest from CI
- **mismatch** — binary or manifest has been tampered with

## Access Control

| Flags | Behavior |
|-------|----------|
| *(none)* | Open server — anyone can upload/download |
| `--require-auth` | Auth required for uploads, downloads public |
| `--require-auth --whitelist keys.txt` | Only whitelisted pubkeys upload |
| `--require-auth --admin npub1... --enable-admin` | Role-based access with admin API |

## License

MIT
