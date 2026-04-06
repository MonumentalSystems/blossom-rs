//! PKARR discovery — publish and resolve Blossom endpoints via relays / Mainline DHT.
//!
//! Uses the same Ed25519 keypair as the iroh transport for unified
//! cryptographic identity. Your node is discoverable as:
//!
//! - `iroh://<node-id>` — direct P2P QUIC
//! - `pk:z<base32-pubkey>` — PKARR resolution
//! - `https://blobs.example.com` — traditional HTTP
//!
//! ## Published DNS records
//!
//! ```text
//! _blossom  TXT  "https://blobs.example.com"
//! _iroh     TXT  "<iroh-node-id>"
//! ```

use std::sync::Arc;
use std::time::Duration;

use pkarr::dns::rdata::RData;
use pkarr::{Client, Keypair, SignedPacket};
use tracing::{info, warn};

/// Configuration for PKARR discovery.
#[derive(Debug, Clone)]
pub struct PkarrConfig {
    /// HTTPS URL of the blossom server (published as `_blossom` TXT).
    pub http_url: Option<String>,
    /// Iroh node ID string (published as `_iroh` TXT).
    pub iroh_node_id: Option<String>,
    /// Republish interval. Records expire after ~2h; default 60 min.
    pub republish_interval: Duration,
    /// TTL for DNS records in seconds.
    pub ttl: u32,
}

impl Default for PkarrConfig {
    fn default() -> Self {
        Self {
            http_url: None,
            iroh_node_id: None,
            republish_interval: Duration::from_secs(3600),
            ttl: 3600,
        }
    }
}

/// PKARR publisher handle.
pub struct PkarrPublisher {
    client: Client,
    keypair: Keypair,
    config: PkarrConfig,
}

impl PkarrPublisher {
    /// Create a publisher from Ed25519 secret key bytes.
    ///
    /// These should be the same 32 bytes as your iroh secret key
    /// for unified identity.
    pub fn new(secret_key_bytes: &[u8; 32], config: PkarrConfig) -> Self {
        let keypair = Keypair::from_secret_key(secret_key_bytes);
        let client = Client::builder().build().expect("pkarr client");

        Self {
            client,
            keypair,
            config,
        }
    }

    /// Get the pkarr public key.
    pub fn public_key(&self) -> pkarr::PublicKey {
        self.keypair.public_key()
    }

    /// Build and sign a DNS packet with blossom endpoint records.
    fn build_packet(&self) -> Result<SignedPacket, String> {
        use pkarr::dns::{rdata::TXT, Name};

        let mut builder = SignedPacket::builder();

        if let Some(ref url) = self.config.http_url {
            let name = Name::new("_blossom").map_err(|e| format!("dns name: {e}"))?;
            let txt: TXT = url.as_str().try_into().map_err(|e| format!("txt: {e}"))?;
            builder = builder.txt(name, txt, self.config.ttl);
        }

        if let Some(ref node_id) = self.config.iroh_node_id {
            let name = Name::new("_iroh").map_err(|e| format!("dns name: {e}"))?;
            let txt: TXT = node_id
                .as_str()
                .try_into()
                .map_err(|e| format!("txt: {e}"))?;
            builder = builder.txt(name, txt, self.config.ttl);
        }

        builder
            .build(&self.keypair)
            .map_err(|e| format!("sign packet: {e}"))
    }

    /// Publish once.
    pub async fn publish(&self) -> Result<(), String> {
        let packet = self.build_packet()?;
        self.client
            .publish(&packet, None)
            .await
            .map_err(|e| format!("pkarr publish: {e}"))?;

        info!(
            pkarr.public_key = %self.keypair.public_key(),
            "published blossom endpoints via pkarr"
        );
        Ok(())
    }

    /// Spawn a background loop that republishes every `republish_interval`.
    pub fn spawn_republish_loop(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let interval = self.config.republish_interval;
        tokio::spawn(async move {
            if let Err(e) = self.publish().await {
                warn!(error.message = %e, "initial pkarr publish failed");
            }
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if let Err(e) = self.publish().await {
                    warn!(error.message = %e, "pkarr republish failed");
                }
            }
        })
    }
}

/// Resolve blossom endpoints for a pkarr public key.
///
/// Returns `(http_url, iroh_node_id)` if found.
pub async fn resolve_blossom_endpoints(
    public_key: &pkarr::PublicKey,
) -> Result<(Option<String>, Option<String>), String> {
    let client = Client::builder().build().expect("pkarr client");
    let packet = client
        .resolve(public_key)
        .await
        .ok_or("no pkarr record found")?;

    let mut http_url = None;
    let mut iroh_node_id = None;

    for record in packet.resource_records("_blossom") {
        if let RData::TXT(txt) = &record.rdata {
            // Convert TXT to String.
            if let Ok(s) = String::try_from(txt.clone()) {
                http_url = Some(s);
            }
        }
    }

    for record in packet.resource_records("_iroh") {
        if let RData::TXT(txt) = &record.rdata {
            if let Ok(s) = String::try_from(txt.clone()) {
                iroh_node_id = Some(s);
            }
        }
    }

    Ok((http_url, iroh_node_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_from_bytes() {
        let secret_bytes = [42u8; 32];
        let publisher = PkarrPublisher::new(
            &secret_bytes,
            PkarrConfig {
                http_url: Some("https://blobs.example.com".into()),
                iroh_node_id: Some("nodeXXX".into()),
                ..Default::default()
            },
        );

        let pk = publisher.public_key();
        assert!(!pk.to_string().is_empty());
    }

    #[test]
    fn test_build_packet() {
        let secret_bytes = [99u8; 32];
        let publisher = PkarrPublisher::new(
            &secret_bytes,
            PkarrConfig {
                http_url: Some("https://test.example.com".into()),
                iroh_node_id: Some("node123".into()),
                ttl: 1800,
                ..Default::default()
            },
        );

        let packet = publisher.build_packet().unwrap();
        let has_blossom = packet
            .resource_records("_blossom")
            .any(|r| matches!(&r.rdata, RData::TXT(_)));
        let has_iroh = packet
            .resource_records("_iroh")
            .any(|r| matches!(&r.rdata, RData::TXT(_)));
        assert!(has_blossom, "missing _blossom TXT record");
        assert!(has_iroh, "missing _iroh TXT record");
    }

    #[test]
    fn test_config_defaults() {
        let config = PkarrConfig::default();
        assert_eq!(config.republish_interval, Duration::from_secs(3600));
        assert_eq!(config.ttl, 3600);
        assert!(config.http_url.is_none());
    }

    #[test]
    fn test_unified_identity() {
        let secret_bytes = [7u8; 32];

        let iroh_key = iroh::SecretKey::from_bytes(&secret_bytes);
        let pkarr_kp = Keypair::from_secret_key(&secret_bytes);

        let iroh_pub = iroh_key.public().as_bytes().to_vec();
        let pkarr_pub = pkarr_kp.public_key().to_bytes().to_vec();
        assert_eq!(iroh_pub, pkarr_pub, "iroh and pkarr public keys must match");
    }
}
