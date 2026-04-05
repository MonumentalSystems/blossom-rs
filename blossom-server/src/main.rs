//! blossom-server — Blossom blob storage API server.
//!
//! Full-featured server showcasing all blossom-rs capabilities: filesystem
//! storage, SQLite metadata, NIP-96, access control, auth enforcement,
//! structured tracing, graceful shutdown, CORS, TLS, and more.

use std::path::PathBuf;
use std::sync::Arc;

use blossom_rs::access::Whitelist;
use blossom_rs::db::MemoryDatabase;
use blossom_rs::ratelimit::{RateLimitConfig, RateLimiter};
use blossom_rs::server::admin::admin_router;
use blossom_rs::server::nip96::nip96_router;
use blossom_rs::server::SharedState;
use blossom_rs::webhooks::HttpNotifier;
use blossom_rs::{BlobServer, BlossomSigner, FilesystemBackend, MemoryBackend, Signer};
use clap::Parser;
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

    /// SQLite database path for metadata (ignored with --memory).
    #[arg(long, default_value = "./blossom.db")]
    db_path: String,

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

    /// Enable admin endpoints (requires --whitelist for access control).
    #[arg(long)]
    enable_admin: bool,

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

    // Build the server with the configured backend and database.
    let mut builder = if args.memory {
        info!("using in-memory storage (no persistence)");
        BlobServer::builder(MemoryBackend::new(), &args.base_url).database(MemoryDatabase::new())
    } else {
        let backend = FilesystemBackend::new(&args.data_dir)?;
        info!(data_dir = %args.data_dir, "using filesystem storage");

        let db_url = format!("sqlite:{}?mode=rwc", args.db_path);
        let db = blossom_rs::db::SqliteDatabase::new(&db_url).await?;
        info!(db_path = %args.db_path, "using SQLite metadata database");

        BlobServer::builder(backend, &args.base_url).database(db)
    };

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

    // Whitelist setup.
    let whitelist: Option<Arc<Whitelist>> = if let Some(ref wl_path) = args.whitelist {
        let wl = Whitelist::from_file(wl_path)?;
        info!(path = %wl_path.display(), "loaded pubkey whitelist");
        let wl = Arc::new(wl);
        builder = builder.access_control(wl.clone());
        Some(wl)
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
