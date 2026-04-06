//! blossom-cli — CLI client for Blossom blob storage servers.
//!
//! Supports upload, download, exists, delete, list, mirror, status, and keygen.
//! Keys can be provided as hex or nsec1 bech32 format.

use std::path::PathBuf;

use blossom_rs::auth::{auth_header_value, build_blossom_auth};
use blossom_rs::transport::IrohBlossomClient;
use blossom_rs::{BlossomClient, BlossomSigner, Signer};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "blossom-cli", about = "CLI client for Blossom blob storage")]
struct Args {
    /// Blossom server URL.
    #[arg(short, long, default_value = "http://localhost:3000", global = true)]
    server: String,

    /// Secret key (hex or nsec1 bech32).
    #[arg(short, long, env = "BLOSSOM_SECRET_KEY", global = true)]
    key: Option<String>,

    /// Output format: json or text.
    #[arg(short = 'f', long, default_value = "text", global = true)]
    format: OutputFormat,

    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, clap::ValueEnum)]
enum OutputFormat {
    Json,
    Text,
}

#[derive(Subcommand)]
enum Command {
    /// Upload a file.
    Upload {
        /// Path to the file to upload.
        file: PathBuf,
    },
    /// Download a blob by SHA256 hash.
    Download {
        /// SHA256 hash of the blob.
        sha256: String,
        /// Output file path (stdout if omitted).
        output: Option<PathBuf>,
    },
    /// Check if a blob exists.
    Exists {
        /// SHA256 hash of the blob.
        sha256: String,
    },
    /// Delete a blob (requires auth).
    Delete {
        /// SHA256 hash of the blob.
        sha256: String,
        /// Skip confirmation prompt.
        #[arg(short, long)]
        yes: bool,
    },
    /// List blobs uploaded by a pubkey.
    List {
        /// Hex-encoded public key.
        pubkey: String,
    },
    /// Mirror a blob from a remote URL (requires auth).
    Mirror {
        /// URL to fetch the blob from.
        url: String,
    },
    /// Get server status.
    Status,
    /// Generate a new keypair.
    Keygen,
    /// Resolve a PKARR public key to blossom endpoints.
    Resolve {
        /// PKARR public key (z-base-32, e.g., pk:z...).
        public_key: String,
    },
}

/// Decode a secret key from hex or nsec1 bech32 format.
fn decode_secret_key(input: &str) -> Result<String, String> {
    if input.starts_with("nsec1") {
        let (hrp, data) = bech32::decode(input).map_err(|e| format!("invalid nsec1: {e}"))?;
        if hrp.as_str() != "nsec" {
            return Err(format!("expected nsec hrp, got {hrp}"));
        }
        Ok(hex::encode(data))
    } else {
        // Assume hex.
        if input.len() != 64 || !input.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("invalid hex key: expected 64 hex characters".into());
        }
        Ok(input.to_string())
    }
}

/// Encode a hex secret key as nsec1 bech32.
fn encode_nsec(hex_key: &str) -> Result<String, String> {
    let bytes = hex::decode(hex_key).map_err(|e| format!("invalid hex: {e}"))?;
    let hrp = bech32::Hrp::parse("nsec").unwrap();
    Ok(bech32::encode::<bech32::Bech32>(hrp, &bytes).unwrap())
}

fn get_signer(key: &Option<String>) -> Result<Signer, String> {
    match key {
        Some(k) => {
            let hex_key = decode_secret_key(k)?;
            Signer::from_secret_hex(&hex_key)
        }
        None => Err("secret key required (--key or BLOSSOM_SECRET_KEY)".into()),
    }
}

/// Print a JSON value in the requested format.
fn print_output(format: &OutputFormat, value: &serde_json::Value) {
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string(value).unwrap()),
        OutputFormat::Text => println!("{}", serde_json::to_string_pretty(value).unwrap()),
    }
}

/// Check if the server URL is an iroh node address.
fn is_iroh_server(server: &str) -> bool {
    server.starts_with("iroh://")
}

/// Parse an iroh node ID from an `iroh://<node-id>` URL.
fn parse_iroh_addr(server: &str) -> Result<iroh::EndpointAddr, String> {
    let node_id_str = server.strip_prefix("iroh://").ok_or("not an iroh URL")?;
    let public_key: iroh::PublicKey = node_id_str
        .parse()
        .map_err(|e| format!("invalid iroh node ID: {e}"))?;
    Ok(iroh::EndpointAddr::from(public_key))
}

/// Create an IrohBlossomClient.
async fn make_iroh_client(signer: Signer) -> Result<IrohBlossomClient, String> {
    let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .bind()
        .await
        .map_err(|e| format!("iroh bind: {e}"))?;
    Ok(IrohBlossomClient::new(endpoint, signer))
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    match run(args).await {
        Ok(()) => {}
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

async fn run(args: Args) -> Result<(), String> {
    match args.command {
        Command::Keygen => {
            let signer = Signer::generate();
            let hex_secret = signer.secret_key_hex();
            let nsec = encode_nsec(&hex_secret)?;
            let pubkey = signer.public_key_hex();

            println!("Secret key (hex):  {hex_secret}");
            println!("Secret key (nsec): {nsec}");
            println!("Public key (hex):  {pubkey}");
            Ok(())
        }

        Command::Upload { file } => {
            let signer = get_signer(&args.key)?;
            let data = std::fs::read(&file).map_err(|e| format!("read {}: {e}", file.display()))?;

            let desc = if is_iroh_server(&args.server) {
                let addr = parse_iroh_addr(&args.server)?;
                let client =
                    make_iroh_client(Signer::from_secret_hex(&signer.secret_key_hex())?).await?;
                client.upload(addr, &data).await?
            } else {
                let mime = mime_from_path(&file);
                let client = BlossomClient::new(vec![args.server], signer);
                client.upload(&data, &mime).await?
            };

            print_output(&args.format, &serde_json::to_value(&desc).unwrap());
            Ok(())
        }

        Command::Download { sha256, output } => {
            let signer = get_signer(&args.key)?;

            let data = if is_iroh_server(&args.server) {
                let addr = parse_iroh_addr(&args.server)?;
                let client =
                    make_iroh_client(Signer::from_secret_hex(&signer.secret_key_hex())?).await?;
                client.download(addr, &sha256).await?
            } else {
                let client = BlossomClient::new(vec![args.server], signer);
                client.download(&sha256).await?
            };

            if let Some(path) = output {
                std::fs::write(&path, &data)
                    .map_err(|e| format!("write {}: {e}", path.display()))?;
                println!("downloaded {} bytes to {}", data.len(), path.display());
            } else {
                use std::io::Write;
                std::io::stdout()
                    .write_all(&data)
                    .map_err(|e| format!("stdout: {e}"))?;
            }
            Ok(())
        }

        Command::Exists { sha256 } => {
            let signer = get_signer(&args.key)?;

            let exists = if is_iroh_server(&args.server) {
                let addr = parse_iroh_addr(&args.server)?;
                let client =
                    make_iroh_client(Signer::from_secret_hex(&signer.secret_key_hex())?).await?;
                client.exists(addr, &sha256).await?
            } else {
                let client = BlossomClient::new(vec![args.server], signer);
                client.exists(&sha256).await?
            };

            if exists {
                println!("exists");
            } else {
                println!("not found");
                std::process::exit(1);
            }
            Ok(())
        }

        Command::Delete { sha256, yes } => {
            if !yes {
                eprint!("Delete blob {}? [y/N] ", &sha256[..12]);
                let mut input = String::new();
                std::io::stdin()
                    .read_line(&mut input)
                    .map_err(|e| format!("read stdin: {e}"))?;
                if !input.trim().eq_ignore_ascii_case("y") {
                    return Err("aborted".into());
                }
            }

            let signer = get_signer(&args.key)?;

            if is_iroh_server(&args.server) {
                let addr = parse_iroh_addr(&args.server)?;
                let client =
                    make_iroh_client(Signer::from_secret_hex(&signer.secret_key_hex())?).await?;
                if client.delete(addr, &sha256).await? {
                    println!("deleted {sha256}");
                } else {
                    return Err("delete failed: not found".into());
                }
            } else {
                let http = reqwest::Client::new();
                let auth_event = build_blossom_auth(&signer, "delete", None, None, "");
                let auth_header = auth_header_value(&auth_event);

                let url = format!("{}/{}", args.server.trim_end_matches('/'), sha256);
                let resp = http
                    .delete(&url)
                    .header("Authorization", &auth_header)
                    .send()
                    .await
                    .map_err(|e| format!("request: {e}"))?;

                if resp.status().is_success() {
                    println!("deleted {sha256}");
                } else {
                    let text = resp.text().await.unwrap_or_default();
                    return Err(format!("delete failed: {text}"));
                }
            }
            Ok(())
        }

        Command::List { pubkey } => {
            let http = reqwest::Client::new();
            let url = format!("{}/list/{}", args.server.trim_end_matches('/'), pubkey);
            let resp = http
                .get(&url)
                .send()
                .await
                .map_err(|e| format!("request: {e}"))?;

            if resp.status().is_success() {
                let body: serde_json::Value =
                    resp.json().await.map_err(|e| format!("parse: {e}"))?;
                print_output(&args.format, &body);
            } else {
                let text = resp.text().await.unwrap_or_default();
                return Err(format!("list failed: {text}"));
            }
            Ok(())
        }

        Command::Mirror { url: source_url } => {
            let signer = get_signer(&args.key)?;
            let http = reqwest::Client::new();

            let auth_event = build_blossom_auth(&signer, "upload", None, None, "");
            let auth_header = auth_header_value(&auth_event);

            let url = format!("{}/mirror", args.server.trim_end_matches('/'));
            let resp = http
                .put(&url)
                .header("Authorization", &auth_header)
                .json(&serde_json::json!({"url": source_url}))
                .send()
                .await
                .map_err(|e| format!("request: {e}"))?;

            if resp.status().is_success() {
                let body: serde_json::Value =
                    resp.json().await.map_err(|e| format!("parse: {e}"))?;
                print_output(&args.format, &body);
            } else {
                let text = resp.text().await.unwrap_or_default();
                return Err(format!("mirror failed: {text}"));
            }
            Ok(())
        }

        Command::Status => {
            let http = reqwest::Client::new();
            let url = format!("{}/status", args.server.trim_end_matches('/'));
            let resp = http
                .get(&url)
                .send()
                .await
                .map_err(|e| format!("request: {e}"))?;

            if resp.status().is_success() {
                let body: serde_json::Value =
                    resp.json().await.map_err(|e| format!("parse: {e}"))?;
                print_output(&args.format, &body);
            } else {
                let text = resp.text().await.unwrap_or_default();
                return Err(format!("status failed: {text}"));
            }
            Ok(())
        }

        Command::Resolve { public_key } => {
            use blossom_rs::transport::pkarr_discovery::resolve_blossom_endpoints;

            let pk_str = public_key.strip_prefix("pk:").unwrap_or(&public_key);
            let pk: pkarr::PublicKey = pk_str
                .parse()
                .map_err(|e| format!("invalid pkarr public key: {e}"))?;

            let (http_url, iroh_node_id) = resolve_blossom_endpoints(&pk).await?;

            let result = serde_json::json!({
                "public_key": pk.to_string(),
                "http_url": http_url,
                "iroh_node_id": iroh_node_id,
                "iroh_url": iroh_node_id.as_ref().map(|id| format!("iroh://{}", id)),
            });
            print_output(&args.format, &result);
            Ok(())
        }
    }
}

/// Guess MIME type from file extension.
fn mime_from_path(path: &std::path::Path) -> String {
    match path.extension().and_then(|e| e.to_str()) {
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("svg") => "image/svg+xml",
        Some("mp4") => "video/mp4",
        Some("webm") => "video/webm",
        Some("pdf") => "application/pdf",
        Some("json") => "application/json",
        Some("txt" | "md") => "text/plain",
        Some("html" | "htm") => "text/html",
        _ => "application/octet-stream",
    }
    .to_string()
}
