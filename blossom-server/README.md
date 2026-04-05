# blossom-server

Example Blossom API server showcasing all [blossom-rs](https://github.com/MonumentalSystems/blossom-rs) library features.

## Quick Start

```bash
# Default: filesystem storage + SQLite metadata in current directory
cargo run -p blossom-server

# In-memory (no persistence, good for testing)
cargo run -p blossom-server -- --memory

# Custom bind address and base URL
cargo run -p blossom-server -- --bind 0.0.0.0:8080 --base-url https://blobs.example.com
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
      --whitelist <FILE>         Path to pubkey whitelist file
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
| `GET` | `/upload-requirements` | Server constraints | BUD-06 |
| `GET` | `/status` | Server statistics | - |
| `GET` | `/.well-known/nostr/nip96.json` | NIP-96 server info | NIP-96 |
| `POST` | `/n96` | NIP-96 upload (auth required) | NIP-96 |
| `GET` | `/n96` | NIP-96 file list (auth required) | NIP-96 |
| `DELETE` | `/n96/:sha256` | NIP-96 delete (auth required) | NIP-96 |

## Logging

Structured JSON logs to stdout with OTEL-compatible field names. Control verbosity with `--log-level` or the `RUST_LOG` environment variable.

```bash
# Debug logging
cargo run -p blossom-server -- --log-level debug

# Filter by module
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
cargo run -p blossom-server -- --require-auth --whitelist allowed-keys.txt
```
