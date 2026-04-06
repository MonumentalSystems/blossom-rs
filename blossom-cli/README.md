# blossom-cli

CLI client for [Blossom](https://github.com/hzrd149/blossom) blob storage servers, built on [blossom-rs](https://github.com/MonumentalSystems/blossom-rs).

## Quick Start

```bash
# Generate a keypair
cargo run -p blossom-cli -- keygen

# Upload a file
cargo run -p blossom-cli -- -k <secret-key> upload photo.jpg

# Download a blob
cargo run -p blossom-cli -- -k <key> download <sha256> output.jpg

# Check server status
cargo run -p blossom-cli -- status
```

## Commands

```
blossom-cli <COMMAND>

Commands:
  keygen                     Generate a new BIP-340 keypair
  upload <FILE> [--content-type <MIME>]  Upload a file (auto-detects MIME type)
  media <FILE>               Upload with server-side processing (BUD-05)
  download <SHA256> [OUTPUT] Download a blob (to file or stdout)
  exists <SHA256>            Check if a blob exists (exit 0 = yes, 1 = no)
  delete <SHA256> [--yes]    Delete a blob (requires auth, prompts for confirmation)
  list <PUBKEY>              List blobs uploaded by a pubkey
  mirror <URL>               Mirror a remote blob to the server (requires auth)
  status                     Get server status
  admin <SUBCOMMAND>         Admin commands (stats, get-user, set-quota, list-blobs, delete-blob)
  resolve <PUBLIC_KEY>       Resolve a PKARR public key to blossom endpoints

Global Options:
  -s, --server <URL>     Server URL or iroh://node-id [default: http://localhost:3000]
  -k, --key <KEY>        Secret key — hex or nsec1 bech32 [env: BLOSSOM_SECRET_KEY]
  -f, --format <FORMAT>  Output format: json or text [default: text]
```

## Key Formats

The `--key` option accepts both formats:

```bash
# Hex (64 characters)
-k 7c3fb2c976bce406b095a13dae24990661b32a6d1d38c9509041ed3c34959791

# nsec1 bech32
-k nsec10slm9jtkhnjqdvy45y76ufyeqesmx2ndr5uvj5ysg8kncdy4j7gs66zq5r

# Or via environment variable
export BLOSSOM_SECRET_KEY=nsec10slm9jtkhnjqdvy45y76ufyeqesmx2ndr5uvj5ysg8kncdy4j7gs66zq5r
cargo run -p blossom-cli -- upload photo.jpg
```

The `keygen` command outputs both formats:

```
Secret key (hex):  7c3fb2c976bce406b095a13dae24990661b32a6d1d38c9509041ed3c34959791
Secret key (nsec): nsec10slm9jtkhnjqdvy45y76ufyeqesmx2ndr5uvj5ysg8kncdy4j7gs66zq5r
Public key (hex):  bea809c847e78732159417625dfe17c16dd36493919467c9b69c5e9eb3227450
```

## Examples

```bash
# Upload and capture the SHA256
SHA=$(blossom-cli -k $KEY upload document.pdf | jq -r .sha256)

# Check it exists
blossom-cli -k $KEY exists $SHA

# Mirror a blob from another server
blossom-cli -k $KEY mirror https://other-server.com/$SHA

# List all blobs by a pubkey
blossom-cli list <pubkey-hex>

# Download to stdout and pipe
blossom-cli -k $KEY download $SHA | sha256sum

# Upload via iroh P2P (no DNS/IP needed)
blossom-cli -s iroh://<node-id> -k $KEY upload photo.jpg

# Resolve a PKARR public key to endpoints
blossom-cli resolve pk:z<base32-pubkey>

# JSON output for scripting
blossom-cli -f json status
```
