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

pub mod auth;
pub mod protocol;
pub mod storage;

#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "client")]
pub mod client;

// Re-exports for convenience.
pub use auth::{BlossomSigner, Signer};
pub use protocol::{BlobDescriptor, NostrEvent};
pub use storage::{BlobBackend, MemoryBackend};

#[cfg(feature = "filesystem")]
pub use storage::FilesystemBackend;

#[cfg(feature = "server")]
pub use server::BlobServer;

#[cfg(feature = "client")]
pub use client::BlossomClient;
