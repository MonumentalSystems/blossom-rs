//! Async HTTP client for Blossom blob storage.
//!
//! Uploads/downloads content-addressed blobs with BIP-340 Schnorr
//! authorization and multi-server failover.

use crate::auth::{auth_header_value, build_blossom_auth, BlossomSigner};
use crate::protocol::{sha256_hex, BlobDescriptor};
use tracing::{info, instrument, warn};

/// Async HTTP client for Blossom blob servers.
///
/// Tries servers in order for each operation, failing over to the next
/// on error or non-success status.
pub struct BlossomClient {
    http: reqwest::Client,
    servers: Vec<String>,
    signer: Box<dyn BlossomSigner>,
}

impl BlossomClient {
    /// Create a new client with the given server URLs and signer.
    /// Create a new client with the given server URLs and signer.
    /// Default timeout: 30 seconds.
    pub fn new(servers: Vec<String>, signer: impl BlossomSigner + 'static) -> Self {
        Self::with_timeout(servers, signer, std::time::Duration::from_secs(30))
    }

    /// Create a new client with a custom timeout.
    pub fn with_timeout(
        servers: Vec<String>,
        signer: impl BlossomSigner + 'static,
        timeout: std::time::Duration,
    ) -> Self {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            http,
            servers,
            signer: Box::new(signer),
        }
    }

    /// Upload a blob to the first available server.
    ///
    /// Returns the blob descriptor with SHA256 hash. The hash is verified
    /// against the server's response to ensure integrity.
    #[instrument(name = "blossom.client.upload", skip_all, fields(
        blob.size = data.len(),
        blob.sha256,
        blob.content_type = content_type,
        server.url,
    ))]
    pub async fn upload(&self, data: &[u8], content_type: &str) -> Result<BlobDescriptor, String> {
        let our_sha256 = sha256_hex(data);
        tracing::Span::current().record("blob.sha256", our_sha256.as_str());

        let auth_event =
            build_blossom_auth(self.signer.as_ref(), "upload", Some(&our_sha256), None, "");
        let auth_header = auth_header_value(&auth_event);

        for server in &self.servers {
            let url = format!("{}/upload", server.trim_end_matches('/'));
            let result = self
                .http
                .put(&url)
                .header("Authorization", &auth_header)
                .header("Content-Type", content_type)
                .body(data.to_vec())
                .send()
                .await;

            match result {
                Ok(resp) if resp.status().is_success() => {
                    let desc: BlobDescriptor = resp
                        .json()
                        .await
                        .map_err(|e| format!("parse upload response: {e}"))?;
                    if desc.sha256 != our_sha256 {
                        return Err(format!(
                            "SHA256 mismatch: server={}, ours={}",
                            desc.sha256, our_sha256
                        ));
                    }
                    tracing::Span::current().record("server.url", server.as_str());
                    info!(
                        blob.sha256 = %desc.sha256,
                        blob.size = desc.size,
                        server.url = %server,
                        "blob uploaded"
                    );
                    return Ok(desc);
                }
                Ok(resp) => {
                    let status = resp.status();
                    let text = resp.text().await.unwrap_or_default();
                    warn!(
                        server.url = %server,
                        http.status_code = status.as_u16(),
                        error.message = %text,
                        "upload failed, trying next server"
                    );
                    continue;
                }
                Err(e) => {
                    warn!(
                        server.url = %server,
                        error.message = %e,
                        "upload request error, trying next server"
                    );
                    continue;
                }
            }
        }

        Err("all Blossom servers failed for upload".into())
    }

    /// Download a blob by SHA256 hash.
    ///
    /// Verifies content-addressed integrity after download.
    #[instrument(name = "blossom.client.download", skip_all, fields(
        blob.sha256 = %sha256,
        blob.size,
        server.url,
    ))]
    pub async fn download(&self, sha256: &str) -> Result<Vec<u8>, String> {
        let auth_event = build_blossom_auth(self.signer.as_ref(), "get", None, None, "");
        let auth_header = auth_header_value(&auth_event);

        for server in &self.servers {
            let url = format!("{}/{}", server.trim_end_matches('/'), sha256);
            let result = self
                .http
                .get(&url)
                .header("Authorization", &auth_header)
                .send()
                .await;

            match result {
                Ok(resp) if resp.status().is_success() => {
                    let data = resp
                        .bytes()
                        .await
                        .map_err(|e| format!("download body: {e}"))?
                        .to_vec();
                    let actual_hash = sha256_hex(&data);
                    if actual_hash != sha256 {
                        return Err(format!(
                            "SHA256 mismatch on download: expected={}, actual={}",
                            sha256, actual_hash
                        ));
                    }
                    tracing::Span::current().record("blob.size", data.len() as u64);
                    tracing::Span::current().record("server.url", server.as_str());
                    info!(
                        blob.sha256 = %sha256,
                        blob.size = data.len(),
                        server.url = %server,
                        "blob downloaded"
                    );
                    return Ok(data);
                }
                Ok(resp) => {
                    warn!(
                        server.url = %server,
                        http.status_code = resp.status().as_u16(),
                        "download failed, trying next server"
                    );
                    continue;
                }
                Err(e) => {
                    warn!(
                        server.url = %server,
                        error.message = %e,
                        "download request error, trying next server"
                    );
                    continue;
                }
            }
        }

        Err(format!("blob {} not found on any Blossom server", sha256))
    }

    /// Check if a blob exists on any configured server.
    #[instrument(name = "blossom.client.exists", skip_all, fields(blob.sha256 = %sha256))]
    pub async fn exists(&self, sha256: &str) -> Result<bool, String> {
        for server in &self.servers {
            let url = format!("{}/{}", server.trim_end_matches('/'), sha256);
            let result = self.http.head(&url).send().await;

            match result {
                Ok(resp) if resp.status().is_success() => return Ok(true),
                Ok(resp) if resp.status().as_u16() == 404 => continue,
                Ok(_) => continue,
                Err(e) => {
                    warn!(
                        server.url = %server,
                        error.message = %e,
                        "exists check error, trying next server"
                    );
                    continue;
                }
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Signer;

    #[test]
    fn test_client_creation() {
        let signer = Signer::generate();
        let client = BlossomClient::new(vec!["https://blossom.example.com".into()], signer);
        assert_eq!(client.servers.len(), 1);
    }
}
