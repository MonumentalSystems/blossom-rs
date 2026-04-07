//! blossom-cli — CLI client for Blossom blob storage servers.
//!
//! Supports upload, download, exists, delete, list, mirror, status, and keygen.
//! Keys can be provided as hex or nsec1 bech32 format.

use std::path::PathBuf;

use std::sync::Arc;

use blossom_rs::auth::{auth_header_value, build_blossom_auth};
use blossom_rs::client::multi::MultiTransportClient;
use blossom_rs::traits::BlobClient;
use blossom_rs::transport::IrohBlossomClient;
use blossom_rs::{BlossomClient, BlossomSigner, Signer};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "blossom-cli",
    about = "CLI client for Blossom blob storage",
    version
)]
struct Args {
    /// Blossom server URL (HTTP).
    #[arg(short, long, default_value = "http://localhost:3000", global = true)]
    server: String,

    /// Iroh endpoint address (iroh://<node-id>). When provided alongside
    /// --server, uploads prefer iroh and downloads prefer HTTP.
    #[arg(long, global = true)]
    iroh: Option<String>,

    /// Force all operations through iroh (no HTTP fallback).
    #[arg(long, global = true)]
    iroh_only: bool,

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
        /// Override Content-Type (default: auto-detect from file extension).
        #[arg(long)]
        content_type: Option<String>,
    },
    /// Upload a file with server-side media processing (BUD-05).
    /// Returns optimized blob with blurhash, dimensions, and perceptual hash.
    Media {
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
    /// Admin commands (requires auth + admin access).
    #[command(subcommand)]
    Admin(AdminCommand),
    /// Batch upload multiple files (streaming, concurrent).
    BatchUpload {
        /// Files to upload.
        files: Vec<PathBuf>,
        /// Maximum concurrent uploads.
        #[arg(long, default_value = "8")]
        concurrency: usize,
    },
    /// Resolve a PKARR public key to blossom endpoints.
    Resolve {
        /// PKARR public key (z-base-32, e.g., pk:z...).
        public_key: String,
    },
}

#[derive(Subcommand)]
enum AdminCommand {
    /// Get server statistics.
    Stats,
    /// Get user info and quota.
    GetUser {
        /// Hex-encoded public key.
        pubkey: String,
    },
    /// Set user quota.
    SetQuota {
        /// Hex-encoded public key.
        pubkey: String,
        /// Quota in bytes (omit for unlimited).
        quota_bytes: Option<u64>,
    },
    /// List blob count and total size.
    ListBlobs,
    /// Admin delete a blob (no ownership check).
    DeleteBlob {
        /// SHA256 hash of the blob.
        sha256: String,
    },
    /// List whitelisted pubkeys.
    WhitelistList,
    /// Add a pubkey to the whitelist.
    WhitelistAdd {
        /// Hex-encoded public key to add.
        pubkey: String,
    },
    /// Remove a pubkey from the whitelist.
    WhitelistRemove {
        /// Hex-encoded public key to remove.
        pubkey: String,
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

/// Build a MultiTransportClient based on CLI args.
async fn build_client(args: &Args, signer: Signer) -> Result<MultiTransportClient, String> {
    let iroh_url = args.iroh.as_deref().or_else(|| {
        if is_iroh_server(&args.server) {
            Some(args.server.as_str())
        } else {
            None
        }
    });

    let http_server = if is_iroh_server(&args.server) {
        // If --server is iroh:// and no HTTP server, HTTP client gets a dummy URL.
        // It'll fail, and iroh will be used via fallback.
        "http://localhost:3000".to_string()
    } else {
        args.server.clone()
    };

    let http = BlossomClient::new(
        vec![http_server],
        Signer::from_secret_hex(&signer.secret_key_hex())?,
    );

    if let Some(iroh_str) = iroh_url {
        let addr = parse_iroh_addr(iroh_str)?;
        let iroh = make_iroh_client(Signer::from_secret_hex(&signer.secret_key_hex())?).await?;
        let mut client = MultiTransportClient::new(http, iroh, addr);
        if args.iroh_only {
            client = client.iroh_only();
        }
        Ok(client)
    } else {
        Ok(MultiTransportClient::http_only(http))
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

        Command::Upload {
            ref file,
            ref content_type,
        } => {
            let file = file.clone();
            let mime = content_type
                .clone()
                .unwrap_or_else(|| mime_from_path(&file));
            let signer = get_signer(&args.key)?;
            let client = build_client(&args, signer).await?;

            // Use streaming upload_file — never buffers full file in memory.
            let desc = client.upload_file(&(), &file, &mime).await?;

            print_output(&args.format, &serde_json::to_value(&desc).unwrap());
            Ok(())
        }

        Command::Download {
            ref sha256,
            ref output,
        } => {
            let signer = get_signer(&args.key)?;
            let client = build_client(&args, signer).await?;
            let data = client.download(&(), sha256).await?;

            if let Some(path) = output {
                std::fs::write(path, &data)
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

        Command::Exists { ref sha256 } => {
            let signer = get_signer(&args.key)?;
            let client = build_client(&args, signer).await?;

            if client.exists(&(), sha256).await? {
                println!("exists");
            } else {
                println!("not found");
                std::process::exit(1);
            }
            Ok(())
        }

        Command::Delete { ref sha256, yes } => {
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
            let client = build_client(&args, signer).await?;

            if client.delete(&(), sha256).await? {
                println!("deleted {sha256}");
            } else {
                return Err("delete failed: not found".into());
            }
            Ok(())
        }

        Command::List { ref pubkey } => {
            let signer = get_signer(&args.key)?;
            let client = build_client(&args, signer).await?;
            let blobs = client.list(&(), pubkey).await?;
            print_output(
                &args.format,
                &serde_json::to_value(&blobs).unwrap_or_default(),
            );
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

        Command::Media { file } => {
            let signer = get_signer(&args.key)?;
            let data = std::fs::read(&file).map_err(|e| format!("read {}: {e}", file.display()))?;
            let mime = mime_from_path(&file);

            let http = reqwest::Client::new();
            let auth = build_blossom_auth(&signer, "upload", None, None, "");
            let auth_header = auth_header_value(&auth);

            let url = format!("{}/media", args.server.trim_end_matches('/'));
            let resp = http
                .put(&url)
                .header("Authorization", &auth_header)
                .header("Content-Type", &mime)
                .body(data)
                .send()
                .await
                .map_err(|e| format!("request: {e}"))?;

            if resp.status().is_success() {
                let body: serde_json::Value =
                    resp.json().await.map_err(|e| format!("parse: {e}"))?;
                print_output(&args.format, &body);
            } else {
                let text = resp.text().await.unwrap_or_default();
                return Err(format!("media upload failed: {text}"));
            }
            Ok(())
        }

        Command::Admin(admin_cmd) => {
            let signer = get_signer(&args.key)?;
            let http = reqwest::Client::new();
            let auth = build_blossom_auth(&signer, "admin", None, None, "");
            let auth_header = auth_header_value(&auth);
            let base = args.server.trim_end_matches('/');

            match admin_cmd {
                AdminCommand::Stats => {
                    let resp = http
                        .get(format!("{}/admin/stats", base))
                        .header("Authorization", &auth_header)
                        .send()
                        .await
                        .map_err(|e| format!("request: {e}"))?;
                    if resp.status().is_success() {
                        let body: serde_json::Value =
                            resp.json().await.map_err(|e| format!("parse: {e}"))?;
                        print_output(&args.format, &body);
                    } else {
                        let text = resp.text().await.unwrap_or_default();
                        return Err(format!("admin stats failed: {text}"));
                    }
                }
                AdminCommand::GetUser { pubkey } => {
                    let resp = http
                        .get(format!("{}/admin/users/{}", base, pubkey))
                        .header("Authorization", &auth_header)
                        .send()
                        .await
                        .map_err(|e| format!("request: {e}"))?;
                    if resp.status().is_success() {
                        let body: serde_json::Value =
                            resp.json().await.map_err(|e| format!("parse: {e}"))?;
                        print_output(&args.format, &body);
                    } else {
                        let text = resp.text().await.unwrap_or_default();
                        return Err(format!("admin get-user failed: {text}"));
                    }
                }
                AdminCommand::SetQuota {
                    pubkey,
                    quota_bytes,
                } => {
                    let resp = http
                        .put(format!("{}/admin/users/{}/quota", base, pubkey))
                        .header("Authorization", &auth_header)
                        .json(&serde_json::json!({"quota_bytes": quota_bytes}))
                        .send()
                        .await
                        .map_err(|e| format!("request: {e}"))?;
                    if resp.status().is_success() {
                        let body: serde_json::Value =
                            resp.json().await.map_err(|e| format!("parse: {e}"))?;
                        print_output(&args.format, &body);
                    } else {
                        let text = resp.text().await.unwrap_or_default();
                        return Err(format!("admin set-quota failed: {text}"));
                    }
                }
                AdminCommand::ListBlobs => {
                    let resp = http
                        .get(format!("{}/admin/blobs", base))
                        .header("Authorization", &auth_header)
                        .send()
                        .await
                        .map_err(|e| format!("request: {e}"))?;
                    if resp.status().is_success() {
                        let body: serde_json::Value =
                            resp.json().await.map_err(|e| format!("parse: {e}"))?;
                        print_output(&args.format, &body);
                    } else {
                        let text = resp.text().await.unwrap_or_default();
                        return Err(format!("admin list-blobs failed: {text}"));
                    }
                }
                AdminCommand::DeleteBlob { sha256 } => {
                    let resp = http
                        .delete(format!("{}/admin/blobs/{}", base, sha256))
                        .header("Authorization", &auth_header)
                        .send()
                        .await
                        .map_err(|e| format!("request: {e}"))?;
                    if resp.status().is_success() {
                        println!("deleted {sha256}");
                    } else {
                        let text = resp.text().await.unwrap_or_default();
                        return Err(format!("admin delete failed: {text}"));
                    }
                }
                AdminCommand::WhitelistList => {
                    let resp = http
                        .get(format!("{}/admin/whitelist", base))
                        .header("Authorization", &auth_header)
                        .send()
                        .await
                        .map_err(|e| format!("request: {e}"))?;
                    if resp.status().is_success() {
                        let body: serde_json::Value =
                            resp.json().await.map_err(|e| format!("parse: {e}"))?;
                        print_output(&args.format, &body);
                    } else {
                        let text = resp.text().await.unwrap_or_default();
                        return Err(format!("whitelist list failed: {text}"));
                    }
                }
                AdminCommand::WhitelistAdd { pubkey } => {
                    let resp = http
                        .put(format!("{}/admin/whitelist/{}", base, pubkey))
                        .header("Authorization", &auth_header)
                        .send()
                        .await
                        .map_err(|e| format!("request: {e}"))?;
                    if resp.status().is_success() {
                        println!("added {pubkey} to whitelist");
                    } else {
                        let text = resp.text().await.unwrap_or_default();
                        return Err(format!("whitelist add failed: {text}"));
                    }
                }
                AdminCommand::WhitelistRemove { pubkey } => {
                    let resp = http
                        .delete(format!("{}/admin/whitelist/{}", base, pubkey))
                        .header("Authorization", &auth_header)
                        .send()
                        .await
                        .map_err(|e| format!("request: {e}"))?;
                    if resp.status().is_success() {
                        println!("removed {pubkey} from whitelist");
                    } else {
                        let text = resp.text().await.unwrap_or_default();
                        return Err(format!("whitelist remove failed: {text}"));
                    }
                }
            }
            Ok(())
        }

        Command::BatchUpload {
            ref files,
            concurrency,
        } => {
            let files = files.clone();
            let signer = get_signer(&args.key)?;
            let client = Arc::new(build_client(&args, signer).await?);

            let results =
                blossom_rs::upload_batch_concurrent(client, &(), files, concurrency).await;

            let mut success = 0;
            let mut failed = 0;
            for result in &results {
                match result {
                    Ok(desc) => {
                        println!("{} ({}B)", desc.sha256, desc.size);
                        success += 1;
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        failed += 1;
                    }
                }
            }
            println!("\n{success} uploaded, {failed} failed");
            if failed > 0 {
                std::process::exit(1);
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
