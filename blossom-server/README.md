# blossom-server

Blossom blob storage API server built on [blossom-rs](https://github.com/MonumentalSystems/blossom-rs).

## Quick Start

```bash
# Default: filesystem storage + SQLite metadata
cargo run -p blossom-server

# In-memory (no persistence, good for testing)
cargo run -p blossom-server -- --memory

# Custom bind address and base URL
cargo run -p blossom-server -- --bind 0.0.0.0:8080 --base-url https://blobs.example.com

# With iroh P2P transport + PKARR discovery
cargo run -p blossom-server -- --iroh --pkarr
# Prints: iroh P2P transport enabled — connect with: iroh://<node-id>
# Prints: PKARR discovery enabled — pk:<public-key>
```

## Options

```
blossom-server [OPTIONS]

Options:
  -b, --bind <ADDR>              Listen address [default: 0.0.0.0:3000]
  -u, --base-url <URL>           Public base URL [default: http://localhost:3000]
  -d, --data-dir <PATH>          Blob storage directory [default: ./blobs]
      --memory                   Use in-memory storage (no persistence)
      --db-path <PATH>           SQLite database path [default: ./blossom.db]
      --require-auth             Require BIP-340 auth for uploads
      --max-upload-size <BYTES>  Max upload size in bytes
      --body-limit <BYTES>       Max HTTP body size [default: 268435456 (256 MB)]
      --allowed-types <TYPES>    Comma-separated MIME types (empty = all)
      --whitelist <FILE>         Path to pubkey whitelist file
      --whitelist-reload-secs <N> Whitelist hot-reload interval [default: 0 (disabled)]
      --stats-flush-secs <N>    Stats flush interval [default: 60]
      --keygen                   Generate a keypair and exit
      --tls-cert <FILE>          TLS certificate (PEM)
      --tls-key <FILE>           TLS private key (PEM)
      --rate-limit-max <N>       Max requests per bucket [default: 60]
      --rate-limit-refill <F>    Token refill rate per second [default: 1.0]
      --no-rate-limit            Disable rate limiting
      --webhook-urls <URLS>      Webhook URLs (comma-separated)
      --cors-origins <ORIGINS>   CORS allowed origins (comma-separated, default: all)
      --enable-admin             Enable admin endpoints at /admin/*
      --media                    Enable media processing on PUT /media (BUD-05)
      --iroh                     Enable iroh P2P transport alongside HTTP
      --iroh-key-file <PATH>     Iroh secret key file [default: ./iroh_secret.key]
      --pkarr                    Enable PKARR endpoint discovery (requires --iroh)
      --pkarr-republish-secs <N> PKARR republish interval [default: 3600]
      --log-level <LEVEL>        Log level [default: info]
```

## API Endpoints

| Method | Path | Description | Protocol |
|--------|------|-------------|----------|
| `PUT` | `/upload` | Upload a blob | BUD-01 |
| `GET` | `/:sha256` | Download a blob | BUD-01 |
| `HEAD` | `/:sha256` | Check existence | BUD-01 |
| `DELETE` | `/:sha256` | Delete a blob (auth required) | BUD-01 |
| `GET` | `/list/:pubkey` | List blobs by uploader | BUD-02 |
| `PUT` | `/mirror` | Mirror from remote URL (auth required) | BUD-04 |
| `PUT` | `/media` | Upload with server-side processing (auth required, --media) | BUD-05 |
| `GET` | `/upload-requirements` | Server constraints | BUD-06 |
| `GET` | `/status` | Server statistics | - |
| `GET` | `/health` | Health check (200 OK) | - |
| `GET` | `/.well-known/nostr/nip96.json` | NIP-96 server info | NIP-96 |
| `POST` | `/n96` | NIP-96 upload (auth required) | NIP-96 |
| `GET` | `/n96` | NIP-96 file list (auth required) | NIP-96 |
| `DELETE` | `/n96/:sha256` | NIP-96 delete (auth required) | NIP-96 |
| `GET` | `/admin/stats` | Server statistics (admin auth) | Admin |
| `GET` | `/admin/users/:pubkey` | Get user record (admin auth) | Admin |
| `PUT` | `/admin/users/:pubkey/quota` | Set user quota (admin auth) | Admin |
| `GET` | `/admin/blobs` | Blob count and size (admin auth) | Admin |
| `DELETE` | `/admin/blobs/:sha256` | Admin delete blob (admin auth) | Admin |

## Features

### CORS
Enabled by default — allows all origins, methods, and headers. Suitable for browser-based Nostr clients.

### Graceful Shutdown
On Ctrl+C, the server flushes accumulated access statistics to the database before exiting.

### Stats Flush
Access statistics (egress bytes, last accessed) accumulate in memory via lock-free DashMap counters and flush to the database periodically (default: every 60 seconds) and on shutdown.

### Whitelist Hot-Reload
When `--whitelist-reload-secs` is set, the whitelist file is re-read at that interval without restarting the server.

### TLS
Optional TLS via rustls. Provide `--tls-cert` and `--tls-key` PEM files.

```bash
cargo run -p blossom-server -- --tls-cert cert.pem --tls-key key.pem
```

### Logging
Structured JSON logs to stdout with OTEL-compatible field names. Control verbosity with `--log-level` or `RUST_LOG`.

```bash
RUST_LOG=blossom_rs::server=debug cargo run -p blossom-server
```

## Access Control

Create a whitelist file with one hex pubkey per line:

```
# allowed-keys.txt
a1b2c3...  (64-char hex pubkey)
d4e5f6...
```

```bash
cargo run -p blossom-server -- \
  --require-auth \
  --whitelist allowed-keys.txt \
  --whitelist-reload-secs 30
```

## Roadmap

| Item | Status | Notes |
|------|--------|-------|
| **VitLabeler** | Not implemented | Vision Transformer inference via Candle |
| **LlmLabeler** | Not implemented | OpenAI-compatible API classification |
| **File-watch whitelist reload** | Timer-based only | Polling interval, not `inotify`/`kqueue` |
| **Server --db-postgres flag** | Not wired | PostgresDatabase works but server binary only supports SQLite |
| **Server --s3 flag** | Not wired | S3Backend works but server binary only supports filesystem |
