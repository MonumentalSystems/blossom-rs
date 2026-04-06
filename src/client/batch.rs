//! Batch upload with concurrency control.

use std::path::PathBuf;

use tracing::{info, instrument, warn};

use crate::protocol::BlobDescriptor;
use crate::traits::BlobClient;

/// Default maximum concurrent uploads.
pub const DEFAULT_MAX_CONCURRENT: usize = 8;

/// Upload multiple files, returning results in input order.
///
/// Streams each file to the server via [`BlobClient::upload_file`].
/// Files are uploaded sequentially (true concurrent streaming requires
/// an `Arc<C>` wrapper — use [`upload_batch_shared`] for that).
///
/// Content type is auto-detected from file extension.
#[instrument(name = "blossom.batch_upload", skip_all, fields(
    batch.files = files.len(),
))]
pub async fn upload_batch<C>(
    client: &C,
    addr: &C::Address,
    files: Vec<PathBuf>,
) -> Vec<Result<BlobDescriptor, String>>
where
    C: BlobClient + Sync,
    C::Address: Clone,
{
    let mut results = Vec::with_capacity(files.len());

    for (idx, path) in files.iter().enumerate() {
        let content_type = detect_content_type(path);
        let result = client.upload_file(addr, path, &content_type).await;
        match &result {
            Ok(desc) => info!(
                batch.index = idx,
                blob.sha256 = %desc.sha256,
                file.path = %path.display(),
                "batch upload success"
            ),
            Err(e) => warn!(
                batch.index = idx,
                file.path = %path.display(),
                error.message = %e,
                "batch upload failed"
            ),
        }
        results.push(result);
    }

    results
}

/// Upload multiple files concurrently with bounded parallelism.
///
/// Requires `Arc<C>` for shared access across concurrent tasks.
/// Uses a semaphore to limit `max_concurrent` uploads in flight.
#[instrument(name = "blossom.batch_upload_concurrent", skip_all, fields(
    batch.files = files.len(),
    batch.max_concurrent = max_concurrent,
))]
pub async fn upload_batch_concurrent<C>(
    client: std::sync::Arc<C>,
    addr: &C::Address,
    files: Vec<PathBuf>,
    max_concurrent: usize,
) -> Vec<Result<BlobDescriptor, String>>
where
    C: BlobClient + Send + Sync + 'static,
    C::Address: Clone + Send + Sync + 'static,
{
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    let sem = Arc::new(Semaphore::new(max_concurrent));
    let n = files.len();
    let mut handles = Vec::with_capacity(n);

    for (idx, path) in files.into_iter().enumerate() {
        let client = client.clone();
        let addr = addr.clone();
        let sem = sem.clone();

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let content_type = detect_content_type(&path);
            let result = client.upload_file(&addr, &path, &content_type).await;
            match &result {
                Ok(desc) => info!(
                    batch.index = idx,
                    blob.sha256 = %desc.sha256,
                    file.path = %path.display(),
                    "concurrent batch upload success"
                ),
                Err(e) => warn!(
                    batch.index = idx,
                    file.path = %path.display(),
                    error.message = %e,
                    "concurrent batch upload failed"
                ),
            }
            (idx, result)
        }));
    }

    let mut results: Vec<Option<Result<BlobDescriptor, String>>> = (0..n).map(|_| None).collect();

    for handle in handles {
        if let Ok((idx, result)) = handle.await {
            results[idx] = Some(result);
        }
    }

    results
        .into_iter()
        .map(|r| r.unwrap_or_else(|| Err("task panicked".into())))
        .collect()
}

/// Detect content type from file extension.
fn detect_content_type(path: &std::path::Path) -> String {
    match path.extension().and_then(|e| e.to_str()) {
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("png") => "image/png",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("svg") => "image/svg+xml",
        Some("mp4") => "video/mp4",
        Some("webm") => "video/webm",
        Some("pdf") => "application/pdf",
        Some("json") => "application/json",
        Some("txt") => "text/plain",
        Some("html" | "htm") => "text/html",
        Some("css") => "text/css",
        Some("js") => "application/javascript",
        Some("wasm") => "application/wasm",
        Some("zip") => "application/zip",
        Some("gz" | "gzip") => "application/gzip",
        Some("tar") => "application/x-tar",
        _ => "application/octet-stream",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_content_type() {
        assert_eq!(detect_content_type("photo.jpg".as_ref()), "image/jpeg");
        assert_eq!(detect_content_type("doc.pdf".as_ref()), "application/pdf");
        assert_eq!(
            detect_content_type("data.bin".as_ref()),
            "application/octet-stream"
        );
        assert_eq!(detect_content_type("style.css".as_ref()), "text/css");
    }
}
