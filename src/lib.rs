//! # blossom-rs
//!
//! Full-featured [Blossom](https://github.com/hzrd149/blossom) blob storage library for Rust.
//!
//! Content-addressed blob storage over HTTP with BIP-340 Schnorr authorization
//! via Nostr kind:24242 events.
//!
//! ## Features
//!
//! - **Embeddable server**: mount a Blossom-compliant Axum router into your app
//! - **Async client**: upload/download with multi-server failover and SHA256 integrity
//! - **BIP-340 auth**: kind:24242 Nostr events for upload/download/delete authorization
//! - **Pluggable storage**: memory (testing), filesystem, S3-compatible backends
//! - **Database layer**: metadata persistence with SQLite/Postgres support
//! - **Access control**: pluggable authorization (whitelist, custom policies)
//! - **File statistics**: egress tracking with DashMap accumulator
//! - **Trait-based**: implement `BlossomSigner` for your own identity type
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use blossom_rs::{BlobServer, FilesystemBackend, Signer};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Generate a signer (or implement BlossomSigner for your own type)
//! let signer = Signer::generate();
//!
//! // Create a server with filesystem storage
//! let server = BlobServer::new(
//!     FilesystemBackend::new("/tmp/blobs")?,
//!     "http://localhost:3000",
//! );
//!
//! // Mount into your Axum app
//! let app = server.router();
//! # Ok(())
//! # }
//! ```

pub mod access;
pub mod auth;
pub mod db;
pub mod integrity;
pub mod labels;
pub mod media;
pub mod otel;
pub mod protocol;
pub mod ratelimit;
pub mod stats;
pub mod storage;
pub mod traits;
pub mod transport;
pub mod webhooks;

#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "client")]
pub mod client;

// Re-exports for convenience.
pub use access::{AccessControl, Role, RoleBasedAccess};
pub use auth::{BlossomSigner, Signer};
pub use db::{BlobDatabase, MemoryDatabase};
pub use labels::{MediaLabeler, NoopLabeler};
pub use media::{MediaProcessor, PassthroughProcessor};
pub use protocol::{BlobDescriptor, NostrEvent};
pub use storage::{BlobBackend, MemoryBackend};
pub use traits::BlobClient;

#[cfg(feature = "filesystem")]
pub use storage::FilesystemBackend;

#[cfg(feature = "s3")]
pub use storage::{S3Backend, S3Config};

#[cfg(feature = "server")]
pub use server::BlobServer;

#[cfg(feature = "client")]
pub use client::batch::{upload_batch, upload_batch_concurrent, DEFAULT_MAX_CONCURRENT};
#[cfg(feature = "client")]
pub use client::multi::{MultiTransportClient, Transport};
#[cfg(feature = "client")]
pub use client::BlossomClient;

#[cfg(feature = "db-sqlite")]
pub use db::SqliteDatabase;

#[cfg(feature = "db-postgres")]
pub use db::PostgresDatabase;
