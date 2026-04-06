//! Transport layer for Blossom blob operations.
//!
//! The wire protocol module (`wire`) defines the framing format shared
//! between all transports. The `iroh_transport` module (behind the
//! `iroh-transport` feature) provides a P2P QUIC transport using iroh.
//!
//! ## Wire Protocol
//!
//! Each QUIC stream carries one request + response using JSON-line headers
//! followed by optional binary payload:
//!
//! ```text
//! REQUEST:  {"op":"get","sha256":"...","auth":"Nostr ..."}\n
//! RESPONSE: {"status":"ok","body_len":12345}\n
//!           [binary blob bytes]
//! ```
//!
//! ## iroh Transport
//!
//! Enable the `iroh-transport` feature to use P2P QUIC connections:
//!
//! ```toml
//! blossom-rs = { version = "0.1", features = ["iroh-transport"] }
//! ```

pub mod wire;

#[cfg(feature = "iroh-transport")]
pub mod iroh_client;
#[cfg(feature = "iroh-transport")]
pub mod iroh_transport;

#[cfg(feature = "pkarr-discovery")]
pub mod pkarr_discovery;

#[cfg(feature = "iroh-transport")]
pub use iroh_client::IrohBlossomClient;
#[cfg(feature = "iroh-transport")]
pub use iroh_transport::{BlossomProtocol, IrohState, BLOSSOM_ALPN};
#[cfg(feature = "pkarr-discovery")]
pub use pkarr_discovery::{PkarrConfig, PkarrPublisher};
