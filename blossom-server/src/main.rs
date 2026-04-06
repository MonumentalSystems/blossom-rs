//! blossom-server — Blossom blob storage API server.
//!
//! Full-featured server showcasing all blossom-rs capabilities: filesystem
//! storage, SQLite metadata, NIP-96, access control, auth enforcement,
//! structured tracing, graceful shutdown, CORS, TLS, and more.

use std::path::PathBuf;
use std::sync::Arc;

use std::sync::Arc as StdArc;

use blossom_rs::access::{normalize_pubkey, RoleBasedAccess, Whitelist};
use blossom_rs::db::MemoryDatabase;
use blossom_rs::ratelimit::{RateLimitConfig, RateLimiter};
use blossom_rs::server::admin::admin_router;
use blossom_rs::server::nip96::nip96_router;
use blossom_rs::server::SharedState;
use blossom_rs::transport::{BlossomProtocol, IrohState, BLOSSOM_ALPN};
use blossom_rs::webhooks::HttpNotifier;
use blossom_rs::{BlobServer, BlossomSigner, FilesystemBackend, MemoryBackend, Signer};
use clap::Parser;
use iroh::protocol::Router as IrohRouter;
use tower_http::cors::CorsLayer;
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Parser)]
#[command(name = "blossom-server", about = "Blossom blob storage API server")]
struct Args {
    /// Listen address.
    #[arg(short, long, default_value = "0.0.0.0:3000")]
    bind: String,

    /// Public base URL for blob URLs in responses.
    #[arg(short = 'u', long, default_value = "http://localhost:3000")]
    base_url: String,

    /// Blob storage directory (ignored with --memory).
    #[arg(short, long, default_value = "./blobs")]
    data_dir: String,

    /// Use in-memory storage instead of filesystem (no persistence).
    #[arg(long)]
    memory: bool,

    /// S3-compatible endpoint URL (e.g., https://account.r2.cloudflarestorage.com).
    /// When set, uses S3 backend instead of filesystem.
    #[arg(long)]
    s3_endpoint: Option<String>,

    /// S3 bucket name (required with --s3-endpoint).
    #[arg(long, default_value = "blobs")]
    s3_bucket: String,

    /// S3 region (use "auto" for Cloudflare R2).
    #[arg(long, default_value = "auto")]
    s3_region: String,

    /// S3 CDN/public URL prefix for blob URLs (optional).
    #[arg(long)]
    s3_public_url: Option<String>,

    /// SQLite database path for metadata (default).
    #[arg(long, default_value = "./blossom.db")]
    db_path: String,

    /// PostgreSQL connection URL (e.g., postgres://user:pass@localhost/blobs).
    /// When set, uses Postgres instead of SQLite for metadata.
    #[arg(long)]
    db_postgres: Option<String>,

    /// Require BIP-340 Nostr auth for uploads.
    #[arg(long)]
    require_auth: bool,

    /// Maximum upload size in bytes.
    #[arg(long)]
    max_upload_size: Option<u64>,

    /// Maximum HTTP body size in bytes (default: 256 MB).
    #[arg(long, default_value = "268435456")]
    body_limit: usize,

    /// Allowed MIME types for upload (comma-separated). Empty = all types.
    #[arg(long, value_delimiter = ',')]
    allowed_types: Vec<String>,

    /// Path to pubkey whitelist file (one hex pubkey per line).
    #[arg(long)]
    whitelist: Option<PathBuf>,

    /// Whitelist reload interval in seconds (0 = no reload).
    #[arg(long, default_value = "0")]
    whitelist_reload_secs: u64,

    /// Stats flush interval in seconds (0 = no periodic flush).
    #[arg(long, default_value = "60")]
    stats_flush_secs: u64,

    /// Generate a new keypair and print it, then exit.
    #[arg(long)]
    keygen: bool,

    /// TLS certificate file (PEM).
    #[arg(long)]
    tls_cert: Option<PathBuf>,

    /// TLS private key file (PEM).
    #[arg(long)]
    tls_key: Option<PathBuf>,

    /// Rate limit: max requests per bucket.
    #[arg(long, default_value = "60")]
    rate_limit_max: u64,

    /// Rate limit: token refill rate (tokens per second).
    #[arg(long, default_value = "1.0")]
    rate_limit_refill: f64,

    /// Disable rate limiting.
    #[arg(long)]
    no_rate_limit: bool,

    /// Webhook URLs (comma-separated). POST notifications on upload/delete/mirror.
    #[arg(long, value_delimiter = ',')]
    webhook_urls: Vec<String>,

    /// CORS allowed origins (comma-separated). Default: * (all).
    #[arg(long, value_delimiter = ',')]
    cors_origins: Vec<String>,

    /// Enable admin endpoints.
    #[arg(long)]
    enable_admin: bool,

    /// Bootstrap admin pubkey (hex or npub1). Persisted in the database.
    /// Can be specified multiple times.
    #[arg(long = "admin", value_delimiter = ',')]
    admin_pubkeys: Vec<String>,

    /// Enable media processing on PUT /media (BUD-05).
    #[arg(long)]
    media: bool,

    /// Enable iroh P2P transport alongside HTTP.
    #[arg(long)]
    iroh: bool,

    /// Path to iroh secret key file for stable node ID.
    /// Generated automatically if file doesn't exist.
    #[arg(long, default_value = "./iroh_secret.key")]
    iroh_key_file: PathBuf,

    /// Enable PKARR endpoint discovery (requires --iroh).
    /// Publishes _blossom and _iroh TXT records to PKARR relays.
    #[arg(long)]
    pkarr: bool,

    /// PKARR republish interval in seconds.
    #[arg(long, default_value = "3600")]
    pkarr_republish_secs: u64,

    /// Log level.
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Keygen mode — print a keypair and exit.
    if args.keygen {
        let signer = Signer::generate();
        println!("Public key (hex):  {}", signer.public_key_hex());
        println!("Secret key (hex):  {}", signer.secret_key_hex());
        return Ok(());
    }

    // Init structured tracing (JSON to stdout, OTEL-compatible field names).
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level));
    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_target(true)
                .with_span_list(true),
        )
        .init();

    // Build storage backend.
    let mut builder = if args.memory {
        info!("using in-memory storage (no persistence)");
        BlobServer::builder(MemoryBackend::new(), &args.base_url)
    } else if let Some(ref s3_endpoint) = args.s3_endpoint {
        let s3_config = blossom_rs::storage::S3Config {
            endpoint: Some(s3_endpoint.clone()),
            bucket: args.s3_bucket.clone(),
            region: args.s3_region.clone(),
            public_url: args.s3_public_url.clone(),
        };
        let backend = blossom_rs::storage::S3Backend::new(s3_config)
            .await
            .map_err(|e| format!("S3 backend: {e}"))?;
        info!(
            s3.endpoint = %s3_endpoint,
            s3.bucket = %args.s3_bucket,
            "using S3 blob storage"
        );
        BlobServer::builder(backend, &args.base_url)
    } else {
        let backend = FilesystemBackend::new(&args.data_dir)?;
        info!(data_dir = %args.data_dir, "using filesystem storage");
        BlobServer::builder(backend, &args.base_url)
    };

    // Build metadata database.
    let mut database: Box<dyn blossom_rs::db::BlobDatabase> = if args.memory {
        Box::new(MemoryDatabase::new())
    } else if let Some(ref pg_url) = args.db_postgres {
        let db = blossom_rs::db::PostgresDatabase::new(pg_url)
            .await
            .map_err(|e| format!("Postgres: {e}"))?;
        info!(db = "postgres", "using PostgreSQL metadata database");
        Box::new(db)
    } else {
        let db_url = format!("sqlite:{}?mode=rwc", args.db_path);
        let db = blossom_rs::db::SqliteDatabase::new(&db_url).await?;
        info!(db_path = %args.db_path, "using SQLite metadata database");
        Box::new(db)
    };

    // Bootstrap admin pubkeys from --admin flag.
    for admin_pk in &args.admin_pubkeys {
        let normalized = normalize_pubkey(admin_pk)
            .ok_or_else(|| format!("invalid admin pubkey: {admin_pk}"))?;
        database
            .set_role(&normalized, "admin")
            .map_err(|e| format!("set admin role: {e}"))?;
        info!(pubkey = %normalized, "bootstrapped admin role");
    }

    // Load roles from database into in-memory access control.
    let role_access = Arc::new(RoleBasedAccess::load_from_database(database.as_mut()).await);
    builder = builder.role_based_access(role_access.clone());
    builder = builder.database_boxed(database);

    if args.require_auth {
        builder = builder.require_auth();
        info!("auth required for uploads");
    }

    if let Some(max) = args.max_upload_size {
        builder = builder.max_upload_size(max);
        info!(max_bytes = max, "upload size limit set");
    }

    if !args.allowed_types.is_empty() {
        info!(types = ?args.allowed_types, "restricting upload MIME types");
        builder = builder.allowed_types(args.allowed_types);
    }

    builder = builder.body_limit(args.body_limit);

    // Rate limiter.
    if !args.no_rate_limit {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_tokens: args.rate_limit_max,
            refill_rate: args.rate_limit_refill,
        });
        builder = builder.rate_limiter(limiter);
        info!(
            max_tokens = args.rate_limit_max,
            refill_rate = args.rate_limit_refill,
            "rate limiting enabled"
        );
    }

    // Webhooks.
    if !args.webhook_urls.is_empty() {
        let notifier = HttpNotifier::new(args.webhook_urls.clone());
        builder = builder.webhook_notifier(notifier);
        info!(urls = ?args.webhook_urls, "webhook notifications enabled");
    }

    // Media processing.
    if args.media {
        builder = builder.media_processor(blossom_rs::media::ImageProcessor::new());
        info!("media processing enabled (PUT /media)");
    }

    // Whitelist setup (only if no --admin flags set role-based access).
    let whitelist: Option<Arc<Whitelist>> = if args.admin_pubkeys.is_empty() {
        if let Some(ref wl_path) = args.whitelist {
            let wl = Whitelist::from_file(wl_path)?;
            info!(path = %wl_path.display(), "loaded pubkey whitelist");
            let wl = Arc::new(wl);
            builder = builder.whitelist(wl.clone());
            Some(wl)
        } else {
            None
        }
    } else {
        None
    };

    let server = builder.build();
    let state = server.shared_state();

    // CORS — configurable origins or allow all.
    let cors = if args.cors_origins.is_empty() {
        CorsLayer::new()
            .allow_origin(tower_http::cors::Any)
            .allow_methods(tower_http::cors::Any)
            .allow_headers(tower_http::cors::Any)
    } else {
        let origins: Vec<axum::http::HeaderValue> = args
            .cors_origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();
        CorsLayer::new()
            .allow_origin(origins)
            .allow_methods(tower_http::cors::Any)
            .allow_headers(tower_http::cors::Any)
    };

    // Build router — main + NIP-96 + optional admin.
    let mut app = server.router().merge(nip96_router(state.clone()));

    if args.enable_admin {
        app = app.merge(admin_router(state.clone()));
        info!("admin endpoints enabled at /admin/*");
    }

    let app = app.layer(cors);

    // Spawn stats flush loop.
    if args.stats_flush_secs > 0 {
        let flush_state = state.clone();
        let interval = std::time::Duration::from_secs(args.stats_flush_secs);
        tokio::spawn(stats_flush_loop(flush_state, interval));
        info!(
            interval_secs = args.stats_flush_secs,
            "stats flush loop started"
        );
    }

    // Spawn whitelist hot-reload loop.
    if let (Some(wl), Some(ref wl_path)) = (whitelist, &args.whitelist) {
        if args.whitelist_reload_secs > 0 {
            let reload_path = wl_path.clone();
            let interval = std::time::Duration::from_secs(args.whitelist_reload_secs);
            tokio::spawn(whitelist_reload_loop(wl, reload_path, interval));
            info!(
                interval_secs = args.whitelist_reload_secs,
                "whitelist reload loop started"
            );
        }
    }

    // Start iroh P2P transport if enabled.
    let _iroh_router: Option<IrohRouter> = if args.iroh {
        // Load or generate secret key for stable node ID.
        let secret_key = if args.iroh_key_file.exists() {
            let bytes =
                std::fs::read(&args.iroh_key_file).map_err(|e| format!("read iroh key: {e}"))?;
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| "iroh key file must be exactly 32 bytes")?;
            iroh::SecretKey::from_bytes(&bytes)
        } else {
            let key = iroh::SecretKey::generate(&mut rand::rng());
            std::fs::write(&args.iroh_key_file, key.to_bytes())
                .map_err(|e| format!("write iroh key: {e}"))?;
            info!(path = %args.iroh_key_file.display(), "generated new iroh secret key");
            key
        };

        // Build iroh state — shares the same filesystem directory as HTTP.
        // For MemoryBackend, creates a shared instance. For FilesystemBackend,
        // both transports point at the same directory (content-addressed = shared).
        let iroh_state = StdArc::new(tokio::sync::Mutex::new(IrohState {
            backend: if args.memory {
                // For memory mode, blobs uploaded via iroh won't be visible via HTTP
                // and vice versa. Use filesystem mode for shared storage.
                warn!("--memory mode: iroh and HTTP have separate blob stores. Use filesystem for shared storage.");
                Box::new(MemoryBackend::new())
            } else {
                Box::new(
                    FilesystemBackend::new(&args.data_dir)
                        .map_err(|e| format!("iroh backend: {e}"))?,
                )
            },
            database: Box::new(MemoryDatabase::new()),
            access: if let Some(ref wl_path) = args.whitelist {
                let wl = Whitelist::from_file(wl_path)?;
                Box::new(Arc::new(wl))
            } else {
                Box::new(blossom_rs::access::OpenAccess)
            },
            base_url: args.base_url.clone(),
            max_upload_size: args.max_upload_size,
            require_auth: args.require_auth,
        }));

        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(secret_key)
            .bind()
            .await
            .map_err(|e| format!("iroh bind: {e}"))?;

        let node_id = endpoint.id();
        info!(
            iroh.node_id = %node_id,
            "iroh P2P transport enabled — connect with: iroh://{}",
            node_id,
        );

        let router = IrohRouter::builder(endpoint)
            .accept(BLOSSOM_ALPN, StdArc::new(BlossomProtocol::new(iroh_state)))
            .spawn();

        Some(router)
    } else {
        None
    };

    // Start PKARR endpoint discovery if enabled.
    if args.pkarr {
        if !args.iroh {
            warn!("--pkarr requires --iroh to be enabled; skipping PKARR");
        } else {
            // Read the iroh secret key for unified identity.
            let key_bytes: [u8; 32] = std::fs::read(&args.iroh_key_file)
                .map_err(|e| format!("read iroh key for pkarr: {e}"))?
                .try_into()
                .map_err(|_| "iroh key file must be 32 bytes")?;

            let iroh_key = iroh::SecretKey::from_bytes(&key_bytes);
            let node_id = iroh_key.public();

            use blossom_rs::transport::pkarr_discovery::{PkarrConfig, PkarrPublisher};
            let publisher = StdArc::new(PkarrPublisher::new(
                &key_bytes,
                PkarrConfig {
                    http_url: Some(args.base_url.clone()),
                    iroh_node_id: Some(node_id.to_string()),
                    republish_interval: std::time::Duration::from_secs(args.pkarr_republish_secs),
                    ttl: 3600,
                },
            ));

            info!(
                pkarr.public_key = %publisher.public_key(),
                "PKARR discovery enabled — pk:{}",
                publisher.public_key(),
            );
            publisher.spawn_republish_loop();
        }
    }

    info!(bind = %args.bind, base_url = %args.base_url, "starting blossom server");

    // Serve with graceful shutdown on Ctrl+C.
    let shutdown_state = state.clone();
    match (args.tls_cert, args.tls_key) {
        (Some(cert), Some(key)) => {
            info!("TLS enabled");
            let handle = axum_server::Handle::new();
            let shutdown_handle = handle.clone();

            tokio::spawn(async move {
                shutdown_signal(shutdown_state).await;
                shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(10)));
            });

            let tls_config =
                axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key).await?;
            let addr: std::net::SocketAddr = args.bind.parse()?;
            axum_server::bind_rustls(addr, tls_config)
                .handle(handle)
                .serve(app.into_make_service())
                .await?;
        }
        _ => {
            let listener = tokio::net::TcpListener::bind(&args.bind).await?;
            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown_signal(shutdown_state))
                .await?;
        }
    }

    info!("server shut down");
    Ok(())
}

/// Wait for Ctrl+C, then flush stats before exiting.
async fn shutdown_signal(state: SharedState) {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl+c");
    info!("shutdown signal received, flushing stats...");
    let mut s = state.lock().await;
    s.flush_stats();
    info!("stats flushed, shutting down");
}

/// Periodically flush accumulated stats to the database.
async fn stats_flush_loop(state: SharedState, interval: std::time::Duration) {
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await; // Skip immediate first tick.
    loop {
        ticker.tick().await;
        let mut s = state.lock().await;
        s.flush_stats();
        tracing::debug!("stats flushed to database");
    }
}

/// Periodically reload the whitelist from disk.
async fn whitelist_reload_loop(
    whitelist: Arc<Whitelist>,
    path: PathBuf,
    interval: std::time::Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await; // Skip immediate first tick.
    loop {
        ticker.tick().await;
        if let Err(e) = whitelist.reload(&path).await {
            warn!(error.message = %e, path = %path.display(), "failed to reload whitelist");
        }
    }
}
