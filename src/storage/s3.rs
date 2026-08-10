//! S3-compatible blob storage backend.
//!
//! Supports AWS S3, Cloudflare R2, MinIO, and other S3-compatible stores.
//! Behind the `s3` feature flag.

use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client as S3Client;

use super::{make_descriptor_from_hash, BlobBackend};
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

    fn valid_hash(sha256: &str) -> bool {
        sha256.len() == 64
            && sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    /// Build the public URL for a blob.
    fn blob_url(&self, sha256: &str, base_url: &str) -> String {
        if let Some(ref cdn) = self.config.public_url {
            format!("{}/{}", cdn.trim_end_matches('/'), sha256)
        } else {
            format!("{}/{}", base_url, sha256)
        }
    }

    fn descriptor(&self, sha256: &str, size: u64, base_url: &str) -> BlobDescriptor {
        let mut descriptor = make_descriptor_from_hash(sha256, size, base_url);
        descriptor.url = Some(self.blob_url(sha256, base_url));
        descriptor
    }

    /// Helper to block on a future using the current tokio runtime handle.
    fn block_on<F: std::future::Future<Output = T>, T>(future: F) -> T {
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(future))
    }
}

impl BlobBackend for S3Backend {
    fn insert(&mut self, data: Vec<u8>, base_url: &str) -> BlobDescriptor {
        let fallback = super::make_descriptor(&data, base_url);
        match self.try_insert(data, base_url) {
            Ok(descriptor) => descriptor,
            Err(error) => {
                tracing::warn!(error.message = %error, "failed to upload blob to S3");
                fallback
            }
        }
    }

    fn try_insert(&mut self, data: Vec<u8>, base_url: &str) -> Result<BlobDescriptor, String> {
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

        result.map_err(|e| format!("s3 upload: {e}"))?;

        self.index.insert(hash.clone(), size);

        Ok(self.descriptor(&hash, size, base_url))
    }

    fn insert_with_hash(
        &mut self,
        data: Vec<u8>,
        hash: &str,
        original_size: u64,
        base_url: &str,
    ) -> BlobDescriptor {
        let fallback = self.descriptor(hash, original_size, base_url);
        match self.try_insert_with_hash(data, hash, original_size, base_url) {
            Ok(descriptor) => descriptor,
            Err(error) => {
                tracing::warn!(
                    blob.sha256 = %hash,
                    error.message = %error,
                    "failed to upload blob with supplied hash to S3"
                );
                fallback
            }
        }
    }

    fn try_insert_with_hash(
        &mut self,
        data: Vec<u8>,
        hash: &str,
        original_size: u64,
        base_url: &str,
    ) -> Result<BlobDescriptor, String> {
        if !Self::valid_hash(hash) {
            return Err("invalid SHA256 storage key".into());
        }

        let key = Self::object_key(hash);
        Self::block_on(async {
            self.client
                .put_object()
                .bucket(&self.config.bucket)
                .key(&key)
                .content_type("application/octet-stream")
                .body(ByteStream::from(data))
                .send()
                .await
        })
        .map_err(|e| format!("s3 upload: {e}"))?;

        self.index.insert(hash.to_string(), original_size);
        Ok(self.descriptor(hash, original_size, base_url))
    }

    fn get(&self, sha256: &str) -> Option<Vec<u8>> {
        if !Self::valid_hash(sha256) {
            return None;
        }
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
        if !Self::valid_hash(sha256) {
            return false;
        }
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
        self.try_delete(sha256).unwrap_or(false)
    }

    fn try_delete(&mut self, sha256: &str) -> Result<bool, String> {
        if !Self::valid_hash(sha256) {
            return Err("invalid SHA256 storage key".into());
        }
        let existed = self.exists(sha256);
        let key = Self::object_key(sha256);
        Self::block_on(async {
            self.client
                .delete_object()
                .bucket(&self.config.bucket)
                .key(&key)
                .send()
                .await
        })
        .map_err(|e| format!("s3 delete: {e}"))?;

        let verification = Self::block_on(async {
            self.client
                .head_object()
                .bucket(&self.config.bucket)
                .key(&key)
                .send()
                .await
        });

        match verification {
            Ok(_) => Err("s3 delete verification failed: object still exists".into()),
            Err(error)
                if error
                    .as_service_error()
                    .is_some_and(|service_error| service_error.is_not_found()) =>
            {
                self.index.remove(sha256);
                Ok(existed)
            }
            Err(error) => Err(format!("s3 delete verification: {error}")),
        }
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

    #[cfg(feature = "server")]
    use std::collections::HashMap;
    #[cfg(feature = "server")]
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    #[cfg(feature = "server")]
    use axum::{
        body::{to_bytes, Body},
        extract::State,
        http::{Method, StatusCode, Uri},
        response::Response,
        routing::any,
        Router,
    };
    #[cfg(feature = "server")]
    use tokio::sync::Mutex;

    #[cfg(feature = "server")]
    #[derive(Clone, Default)]
    struct MockS3 {
        objects: Arc<Mutex<HashMap<String, Vec<u8>>>>,
        retain_on_delete: Arc<AtomicBool>,
    }

    #[cfg(feature = "server")]
    async fn mock_s3_request(
        State(state): State<MockS3>,
        method: Method,
        uri: Uri,
        body: Body,
    ) -> Response<Body> {
        let key = uri
            .path()
            .rsplit('/')
            .next()
            .unwrap_or_default()
            .to_string();

        match method {
            Method::PUT => match to_bytes(body, usize::MAX).await {
                Ok(bytes) => {
                    state.objects.lock().await.insert(key, bytes.to_vec());
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(Body::empty())
                        .unwrap()
                }
                Err(_) => Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::empty())
                    .unwrap(),
            },
            Method::GET => match state.objects.lock().await.get(&key).cloned() {
                Some(data) => Response::builder()
                    .status(StatusCode::OK)
                    .header("content-length", data.len())
                    .body(Body::from(data))
                    .unwrap(),
                None => Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Body::empty())
                    .unwrap(),
            },
            Method::HEAD => match state.objects.lock().await.get(&key) {
                Some(data) => Response::builder()
                    .status(StatusCode::OK)
                    .header("content-length", data.len())
                    .body(Body::empty())
                    .unwrap(),
                None => Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Body::empty())
                    .unwrap(),
            },
            Method::DELETE => {
                if !state.retain_on_delete.load(Ordering::SeqCst) {
                    state.objects.lock().await.remove(&key);
                }
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(Body::empty())
                    .unwrap()
            }
            _ => Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Body::empty())
                .unwrap(),
        }
    }

    #[cfg(feature = "server")]
    async fn mock_backend() -> (S3Backend, MockS3, tokio::task::JoinHandle<()>) {
        let state = MockS3::default();
        let app = Router::new()
            .route("/{*path}", any(mock_s3_request))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let config = S3Config {
            endpoint: Some(format!("http://{address}")),
            bucket: "test-blobs".into(),
            region: "us-east-1".into(),
            public_url: None,
        };
        let sdk_config = aws_sdk_s3::Config::builder()
            .behavior_version_latest()
            .region(aws_sdk_s3::config::Region::new(config.region.clone()))
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "test-access-key",
                "test-secret-key",
                None,
                None,
                "blossom-s3-test",
            ))
            .endpoint_url(config.endpoint.clone().unwrap())
            .force_path_style(true)
            .build();
        let backend = S3Backend {
            client: S3Client::from_conf(sdk_config),
            config,
            index: HashMap::new(),
        };

        (backend, state, server)
    }

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

    #[cfg(feature = "server")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn insert_with_hash_preserves_original_identity_and_stored_bytes() {
        let (mut backend, state, server) = mock_backend().await;
        let original = b"the original uncompressed LFS content";
        let stored = b"compressed-or-delta-bytes";
        let original_hash = sha256_hex(original);
        let stored_hash = sha256_hex(stored);

        let descriptor = backend
            .try_insert_with_hash(
                stored.to_vec(),
                &original_hash,
                original.len() as u64,
                "https://blossom.example",
            )
            .unwrap();

        assert_eq!(descriptor.sha256, original_hash);
        assert_eq!(descriptor.size, original.len() as u64);
        assert_eq!(
            descriptor.url.as_deref(),
            Some(format!("https://blossom.example/{original_hash}").as_str())
        );
        assert_eq!(
            backend.get(&original_hash).as_deref(),
            Some(stored.as_slice())
        );
        assert!(backend.get(&stored_hash).is_none());
        assert_eq!(backend.total_bytes(), original.len() as u64);
        assert_eq!(
            state
                .objects
                .lock()
                .await
                .get(&S3Backend::object_key(&original_hash))
                .map(Vec::as_slice),
            Some(stored.as_slice())
        );

        let second_original = b"another original LFS object";
        let second_stored = b"another transformed representation";
        let second_hash = sha256_hex(second_original);
        let second_descriptor = backend.insert_with_hash(
            second_stored.to_vec(),
            &second_hash,
            second_original.len() as u64,
            "https://blossom.example",
        );
        assert_eq!(second_descriptor.sha256, second_hash);
        assert_eq!(second_descriptor.size, second_original.len() as u64);
        assert_eq!(
            backend.get(&second_hash).as_deref(),
            Some(second_stored.as_slice())
        );
        assert_eq!(
            backend.total_bytes(),
            (original.len() + second_original.len()) as u64
        );

        server.abort();
    }

    #[cfg(feature = "server")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn delete_keeps_index_until_remote_absence_is_verified() {
        let (mut backend, state, server) = mock_backend().await;
        let data = b"object that must really be deleted";
        let descriptor = backend
            .try_insert(data.to_vec(), "https://blossom.example")
            .unwrap();

        state.retain_on_delete.store(true, Ordering::SeqCst);
        let error = backend.try_delete(&descriptor.sha256).unwrap_err();
        assert!(error.contains("object still exists"));
        assert!(backend.index.contains_key(&descriptor.sha256));
        assert!(backend.exists(&descriptor.sha256));

        state.retain_on_delete.store(false, Ordering::SeqCst);
        assert!(backend.try_delete(&descriptor.sha256).unwrap());
        assert!(!backend.index.contains_key(&descriptor.sha256));
        assert!(!backend.exists(&descriptor.sha256));

        server.abort();
    }
}
