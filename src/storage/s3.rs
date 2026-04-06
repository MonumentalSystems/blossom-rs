//! S3-compatible blob storage backend.
//!
//! Supports AWS S3, Cloudflare R2, MinIO, and other S3-compatible stores.
//! Behind the `s3` feature flag.

use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client as S3Client;

use super::BlobBackend;
use crate::protocol::{sha256_hex, BlobDescriptor};

/// Configuration for S3-compatible blob storage.
#[derive(Debug, Clone)]
pub struct S3Config {
    /// S3 endpoint URL (e.g., `https://s3.amazonaws.com` or MinIO/R2 endpoint).
    pub endpoint: Option<String>,
    /// S3 bucket name.
    pub bucket: String,
    /// AWS region (e.g., `us-east-1`). Use `auto` for Cloudflare R2.
    pub region: String,
    /// Optional CDN/public URL prefix. If set, blob URLs use this instead of the server base URL.
    /// Example: `https://cdn.example.com/blobs`
    pub public_url: Option<String>,
}

/// S3-compatible blob storage backend.
///
/// Stores blobs as `<sha256>.blob` objects in the configured bucket.
/// Uses the AWS SDK for S3-compatible operations.
///
/// Note: This backend implements `BlobBackend` with blocking semantics by
/// using `tokio::runtime::Handle::current().block_on()` internally, since
/// `BlobBackend` is a synchronous trait. The server wraps it in `Arc<Mutex<>>`
/// and calls from async context where a tokio runtime is always available.
pub struct S3Backend {
    client: S3Client,
    config: S3Config,
    /// Local index of known blobs (sha256 -> size). Populated on startup
    /// by listing the bucket, then maintained in-memory.
    index: std::collections::HashMap<String, u64>,
}

impl S3Backend {
    /// Create a new S3 backend. Lists the bucket to populate the local index.
    ///
    /// # Panics
    /// Panics if called outside a tokio runtime context.
    pub async fn new(config: S3Config) -> Result<Self, String> {
        let mut aws_config_builder = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(config.region.clone()));

        if let Some(ref endpoint) = config.endpoint {
            aws_config_builder = aws_config_builder.endpoint_url(endpoint);
        }

        let aws_config = aws_config_builder.load().await;
        let client = S3Client::new(&aws_config);

        let mut backend = S3Backend {
            client,
            config,
            index: std::collections::HashMap::new(),
        };

        backend.rebuild_index().await?;
        Ok(backend)
    }

    /// List all objects in the bucket and populate the index.
    async fn rebuild_index(&mut self) -> Result<(), String> {
        let mut continuation_token: Option<String> = None;

        loop {
            let mut req = self.client.list_objects_v2().bucket(&self.config.bucket);

            if let Some(ref token) = continuation_token {
                req = req.continuation_token(token);
            }

            let resp = req
                .send()
                .await
                .map_err(|e| format!("s3 list objects: {e}"))?;

            for obj in resp.contents() {
                if let Some(key) = obj.key() {
                    if let Some(hash) = key.strip_suffix(".blob") {
                        if hash.len() == 64 {
                            let size = obj.size.unwrap_or(0) as u64;
                            self.index.insert(hash.to_string(), size);
                        }
                    }
                }
            }

            if resp.is_truncated() == Some(true) {
                continuation_token = resp.next_continuation_token().map(|s| s.to_string());
            } else {
                break;
            }
        }

        tracing::info!(
            storage.backend = "s3",
            storage.bucket = %self.config.bucket,
            storage.existing_blobs = self.index.len(),
            "initialized S3 blob storage"
        );

        Ok(())
    }

    /// S3 object key for a blob.
    fn object_key(sha256: &str) -> String {
        format!("{}.blob", sha256)
    }

    /// Build the public URL for a blob.
    fn blob_url(&self, sha256: &str, base_url: &str) -> String {
        if let Some(ref cdn) = self.config.public_url {
            format!("{}/{}", cdn.trim_end_matches('/'), sha256)
        } else {
            format!("{}/{}", base_url, sha256)
        }
    }

    /// Helper to block on a future using the current tokio runtime handle.
    fn block_on<F: std::future::Future<Output = T>, T>(future: F) -> T {
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(future))
    }
}

impl BlobBackend for S3Backend {
    fn insert(&mut self, data: Vec<u8>, base_url: &str) -> BlobDescriptor {
        let hash = sha256_hex(&data);
        let size = data.len() as u64;
        let key = Self::object_key(&hash);

        let result = Self::block_on(async {
            self.client
                .put_object()
                .bucket(&self.config.bucket)
                .key(&key)
                .content_type("application/octet-stream")
                .body(ByteStream::from(data))
                .send()
                .await
        });

        if let Err(e) = result {
            tracing::warn!(
                storage.backend = "s3",
                blob.sha256 = %hash,
                error.message = %e,
                "failed to upload blob to S3"
            );
        }

        self.index.insert(hash.clone(), size);

        let url = self.blob_url(&hash, base_url);
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        BlobDescriptor {
            sha256: hash,
            size,
            content_type: Some("application/octet-stream".into()),
            url: Some(url),
            uploaded: Some(ts),
        }
    }

    fn get(&self, sha256: &str) -> Option<Vec<u8>> {
        let key = Self::object_key(sha256);

        let result = Self::block_on(async {
            self.client
                .get_object()
                .bucket(&self.config.bucket)
                .key(&key)
                .send()
                .await
        });

        match result {
            Ok(output) => {
                let bytes = Self::block_on(async { output.body.collect().await });
                match bytes {
                    Ok(b) => Some(b.into_bytes().to_vec()),
                    Err(e) => {
                        tracing::warn!(
                            storage.backend = "s3",
                            blob.sha256 = %sha256,
                            error.message = %e,
                            "failed to read S3 object body"
                        );
                        None
                    }
                }
            }
            Err(_) => None,
        }
    }

    fn exists(&self, sha256: &str) -> bool {
        if self.index.contains_key(sha256) {
            return true;
        }
        let key = Self::object_key(sha256);
        let result = Self::block_on(async {
            self.client
                .head_object()
                .bucket(&self.config.bucket)
                .key(&key)
                .send()
                .await
        });
        result.is_ok()
    }

    fn delete(&mut self, sha256: &str) -> bool {
        let existed = self.index.remove(sha256).is_some();
        let key = Self::object_key(sha256);
        let _ = Self::block_on(async {
            self.client
                .delete_object()
                .bucket(&self.config.bucket)
                .key(&key)
                .send()
                .await
        });
        existed
    }

    fn len(&self) -> usize {
        self.index.len()
    }

    fn total_bytes(&self) -> u64 {
        self.index.values().sum()
    }

    fn insert_stream(
        &mut self,
        reader: &mut dyn std::io::Read,
        _size: u64,
        base_url: &str,
    ) -> Result<BlobDescriptor, String> {
        use crate::protocol::STREAM_CHUNK_SIZE;
        use sha2::{Digest, Sha256};
        use std::io::Write;

        // Write to temp file while computing SHA256 (can't rewind dyn Read).
        let tmp_path = std::env::temp_dir().join(format!(
            "blossom_s3_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));

        let result = (|| -> Result<BlobDescriptor, String> {
            let mut file =
                std::fs::File::create(&tmp_path).map_err(|e| format!("create temp: {e}"))?;
            let mut hasher = Sha256::new();
            let mut buf = [0u8; STREAM_CHUNK_SIZE];
            let mut total = 0u64;

            loop {
                let n = reader
                    .read(&mut buf)
                    .map_err(|e| format!("read stream: {e}"))?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                file.write_all(&buf[..n])
                    .map_err(|e| format!("write temp: {e}"))?;
                total += n as u64;
            }
            file.flush().map_err(|e| format!("flush temp: {e}"))?;
            drop(file);

            let hash = hex::encode(hasher.finalize());
            let key = Self::object_key(&hash);

            // Stream from temp file to S3.
            let upload_result = Self::block_on(async {
                let body = ByteStream::from_path(&tmp_path)
                    .await
                    .map_err(|e| format!("read temp for s3: {e}"))?;
                self.client
                    .put_object()
                    .bucket(&self.config.bucket)
                    .key(&key)
                    .content_type("application/octet-stream")
                    .body(body)
                    .send()
                    .await
                    .map_err(|e| format!("s3 upload: {e}"))
            });
            upload_result?;

            self.index.insert(hash.clone(), total);

            let url = self.blob_url(&hash, base_url);
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            Ok(BlobDescriptor {
                sha256: hash,
                size: total,
                content_type: Some("application/octet-stream".into()),
                url: Some(url),
                uploaded: Some(ts),
            })
        })();

        let _ = std::fs::remove_file(&tmp_path);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_s3_config_creation() {
        let config = S3Config {
            endpoint: Some("http://localhost:9000".into()),
            bucket: "test-blobs".into(),
            region: "us-east-1".into(),
            public_url: Some("https://cdn.example.com".into()),
        };
        assert_eq!(config.bucket, "test-blobs");
        assert!(config.public_url.is_some());
    }

    #[test]
    fn test_object_key_format() {
        let key = S3Backend::object_key("abc123");
        assert_eq!(key, "abc123.blob");
    }
}
