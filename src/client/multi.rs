//! Multi-transport client with configurable preference.
//!
//! Wraps both HTTP (`BlossomClient`) and iroh (`IrohBlossomClient`)
//! clients, routing operations based on transport preference:
//!
//! - **Uploads**: prefer iroh (direct P2P, no proxy overhead)
//! - **Downloads**: prefer HTTP (CDN/Cloudflare caching)
//! - Fallback to the other transport on failure

#[cfg(feature = "iroh-transport")]
use iroh::EndpointAddr;
use tracing::{info, warn};

use super::BlossomClient;
use crate::protocol::BlobDescriptor;
use crate::traits::BlobClient;

/// Transport preference for operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Prefer HTTP (CDN-friendly).
    Http,
    /// Prefer iroh QUIC (direct P2P).
    Iroh,
}

/// Multi-transport Blossom client.
///
/// Routes operations through HTTP or iroh based on preference, with
/// automatic fallback. Default: iroh for uploads/deletes, HTTP for
/// downloads/exists/list.
pub struct MultiTransportClient {
    http: BlossomClient,
    #[cfg(feature = "iroh-transport")]
    iroh: Option<crate::transport::IrohBlossomClient>,
    #[cfg(feature = "iroh-transport")]
    iroh_addr: Option<EndpointAddr>,
    /// Transport preference for upload operations.
    pub upload_transport: Transport,
    /// Transport preference for download operations.
    pub download_transport: Transport,
}

impl MultiTransportClient {
    /// Create with HTTP only.
    pub fn http_only(http: BlossomClient) -> Self {
        Self {
            http,
            #[cfg(feature = "iroh-transport")]
            iroh: None,
            #[cfg(feature = "iroh-transport")]
            iroh_addr: None,
            upload_transport: Transport::Http,
            download_transport: Transport::Http,
        }
    }

    /// Create with both transports. Default: iroh for uploads, HTTP for downloads.
    #[cfg(feature = "iroh-transport")]
    pub fn new(
        http: BlossomClient,
        iroh: crate::transport::IrohBlossomClient,
        iroh_addr: EndpointAddr,
    ) -> Self {
        Self {
            http,
            iroh: Some(iroh),
            iroh_addr: Some(iroh_addr),
            upload_transport: Transport::Iroh,
            download_transport: Transport::Http,
        }
    }

    /// Force all operations through iroh.
    pub fn iroh_only(mut self) -> Self {
        self.upload_transport = Transport::Iroh;
        self.download_transport = Transport::Iroh;
        self
    }

    #[cfg(feature = "iroh-transport")]
    fn has_iroh(&self) -> bool {
        self.iroh.is_some() && self.iroh_addr.is_some()
    }

    #[cfg(not(feature = "iroh-transport"))]
    fn has_iroh(&self) -> bool {
        false
    }
}

impl BlobClient for MultiTransportClient {
    type Address = ();

    async fn upload(
        &self,
        _addr: &(),
        data: &[u8],
        content_type: &str,
    ) -> Result<BlobDescriptor, String> {
        #[cfg(feature = "iroh-transport")]
        if self.upload_transport == Transport::Iroh {
            if let (Some(iroh), Some(addr)) = (&self.iroh, &self.iroh_addr) {
                match iroh
                    .upload_with_type(addr.clone(), data, content_type)
                    .await
                {
                    Ok(desc) => return Ok(desc),
                    Err(e) => {
                        warn!(error.message = %e, "iroh upload failed, falling back to HTTP");
                    }
                }
            }
        }

        let result = self.http.upload(data, content_type).await;

        #[cfg(feature = "iroh-transport")]
        if result.is_err() && self.upload_transport == Transport::Http && self.has_iroh() {
            if let (Some(iroh), Some(addr)) = (&self.iroh, &self.iroh_addr) {
                info!("HTTP upload failed, trying iroh fallback");
                return iroh
                    .upload_with_type(addr.clone(), data, content_type)
                    .await;
            }
        }

        result
    }

    async fn download(&self, _addr: &(), sha256: &str) -> Result<Vec<u8>, String> {
        if self.download_transport == Transport::Http || !self.has_iroh() {
            let result = self.http.download(sha256).await;
            if result.is_ok() || !self.has_iroh() {
                return result;
            }
            warn!("HTTP download failed, trying iroh fallback");
        }

        #[cfg(feature = "iroh-transport")]
        if let (Some(iroh), Some(addr)) = (&self.iroh, &self.iroh_addr) {
            let result = iroh.download(addr.clone(), sha256).await;
            if result.is_ok() || self.download_transport == Transport::Iroh {
                return result;
            }
            warn!("iroh download failed, trying HTTP fallback");
            return self.http.download(sha256).await;
        }

        self.http.download(sha256).await
    }

    async fn exists(&self, _addr: &(), sha256: &str) -> Result<bool, String> {
        // Prefer HTTP for exists (cache-friendly HEAD request).
        self.http.exists(sha256).await
    }

    async fn delete(&self, _addr: &(), sha256: &str) -> Result<bool, String> {
        // Prefer iroh for delete (direct to origin).
        #[cfg(feature = "iroh-transport")]
        if self.has_iroh() {
            if let (Some(iroh), Some(addr)) = (&self.iroh, &self.iroh_addr) {
                match iroh.delete(addr.clone(), sha256).await {
                    Ok(v) => return Ok(v),
                    Err(e) => {
                        warn!(error.message = %e, "iroh delete failed, falling back to HTTP");
                    }
                }
            }
        }
        self.http.delete(sha256).await
    }

    async fn list(&self, _addr: &(), pubkey: &str) -> Result<Vec<BlobDescriptor>, String> {
        // Prefer HTTP for list (cacheable).
        self.http.list(pubkey).await
    }

    async fn upload_file(
        &self,
        _addr: &(),
        path: &std::path::Path,
        content_type: &str,
    ) -> Result<BlobDescriptor, String> {
        #[cfg(feature = "iroh-transport")]
        if self.upload_transport == Transport::Iroh {
            if let (Some(iroh), Some(addr)) = (&self.iroh, &self.iroh_addr) {
                match iroh.upload_file(addr.clone(), path, content_type).await {
                    Ok(desc) => return Ok(desc),
                    Err(e) => {
                        warn!(error.message = %e, "iroh upload_file failed, falling back to HTTP");
                    }
                }
            }
        }

        let result = self.http.upload_file(path, content_type).await;

        #[cfg(feature = "iroh-transport")]
        if result.is_err() && self.upload_transport == Transport::Http && self.has_iroh() {
            if let (Some(iroh), Some(addr)) = (&self.iroh, &self.iroh_addr) {
                info!("HTTP upload_file failed, trying iroh fallback");
                return iroh.upload_file(addr.clone(), path, content_type).await;
            }
        }

        result
    }
}
