//! OpenTelemetry integration helpers.
//!
//! Behind the `otel` feature flag. Provides convenience functions for
//! configuring `tracing` to export spans and logs via OTLP (OpenTelemetry
//! Protocol) to backends like Jaeger, Grafana Tempo, Seq, Honeycomb, etc.
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! // Requires the `otel` feature:
//! // blossom-rs = { features = ["otel"] }
//! # #[cfg(feature = "otel")]
//! # mod example {
//! use blossom_rs::otel::init_tracing;
//!
//! #[tokio::main]
//! async fn main() {
//!     // Exports to OTEL_EXPORTER_OTLP_ENDPOINT (default: http://localhost:4317)
//!     let _guard = init_tracing("blossom-server", "info").expect("tracing init");
//!
//!     // ... start your server ...
//!     // When _guard is dropped, pending spans are flushed.
//! }
//! # }
//! ```
//!
//! ## Structured Fields
//!
//! All blossom-rs spans use a consistent naming convention compatible with
//! OTEL semantic conventions:
//!
//! | Field | Description |
//! |-------|-------------|
//! | `http.method` | HTTP method (GET, PUT, etc.) |
//! | `http.route` | Request path |
//! | `http.status_code` | Response status code |
//! | `blob.sha256` | Content-addressed blob hash |
//! | `blob.size` | Blob size in bytes |
//! | `blob.content_type` | MIME type |
//! | `auth.pubkey` | BIP-340 public key of the caller |
//! | `auth.action` | Blossom auth action (upload/delete/get) |
//! | `auth.kind` | Nostr event kind (24242) |
//! | `storage.backend` | Backend type (filesystem/s3/memory) |
//! | `server.url` | Server URL that handled the request |
//! | `error.message` | Error description |
//! | `otel.name` | Span display name |
//! | `otel.kind` | Span kind (server/client) |

#[cfg(feature = "otel")]
use opentelemetry::trace::TracerProvider as _;
#[cfg(feature = "otel")]
use opentelemetry::KeyValue;
#[cfg(feature = "otel")]
use opentelemetry_sdk::runtime::Tokio;
#[cfg(feature = "otel")]
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Guard that flushes pending spans on drop. Keep this alive for the
/// lifetime of your application.
#[cfg(feature = "otel")]
pub struct TracingGuard {
    _provider: opentelemetry_sdk::trace::TracerProvider,
}

#[cfg(feature = "otel")]
impl Drop for TracingGuard {
    fn drop(&mut self) {
        if let Err(e) = self._provider.shutdown() {
            eprintln!("otel shutdown error: {e}");
        }
    }
}

/// Initialize tracing with OTLP export.
///
/// Reads `OTEL_EXPORTER_OTLP_ENDPOINT` from the environment (default:
/// `http://localhost:4317`). Sets up a `tracing-subscriber` with both
/// a console/JSON layer and an OTLP span exporter.
///
/// Returns a [`TracingGuard`] that flushes pending spans when dropped.
#[cfg(feature = "otel")]
pub fn init_tracing(
    service_name: &str,
    default_filter: &str,
) -> Result<TracingGuard, Box<dyn std::error::Error>> {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .build()?;

    let provider = opentelemetry_sdk::trace::TracerProvider::builder()
        .with_batch_exporter(exporter, Tokio)
        .with_resource(opentelemetry_sdk::Resource::new(vec![KeyValue::new(
            "service.name",
            service_name.to_string(),
        )]))
        .build();

    let tracer = provider.tracer(service_name.to_string());
    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));

    let fmt_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_target(true)
        .with_span_list(true);

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .with(otel_layer)
        .init();

    Ok(TracingGuard {
        _provider: provider,
    })
}
