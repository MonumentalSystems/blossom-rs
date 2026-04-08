//! Common traits for blob operations.
//!
//! The [`BlobClient`] trait provides a unified async interface over
//! both HTTP (`BlossomClient`) and QUIC (`IrohBlossomClient`) transports.

use crate::protocol::BlobDescriptor;

/// Unified async trait for blob storage clients.
///
/// Both [`BlossomClient`](crate::client::BlossomClient) (HTTP) and
/// [`IrohBlossomClient`](crate::transport::iroh_client::IrohBlossomClient)
/// (QUIC) implement this trait, enabling transport-agnostic code.
///
/// The associated `Address` type reflects each transport's addressing
/// model: `()` for HTTP (server list is internal) and `EndpointAddr`
/// for iroh (peer address per operation).
///
/// # Example
///
/// ```rust,ignore
/// # use blossom_rs::BlobClient;
/// async fn download_blob<C: BlobClient>(
///     client: &C,
///     addr: &C::Address,
///     sha256: &str,
/// ) -> Result<Vec<u8>, String> {
///     client.download(addr, sha256).await
/// }
/// ```
pub trait BlobClient {
    /// Transport-specific address type.
    type Address: Send + Sync;

    /// Upload a blob.
    fn upload(
        &self,
        addr: &Self::Address,
        data: &[u8],
        content_type: &str,
    ) -> impl std::future::Future<Output = Result<BlobDescriptor, String>> + Send;

    /// Download a blob by SHA256 hash.
    fn download(
        &self,
        addr: &Self::Address,
        sha256: &str,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, String>> + Send;

    /// Check if a blob exists.
    fn exists(
        &self,
        addr: &Self::Address,
        sha256: &str,
    ) -> impl std::future::Future<Output = Result<bool, String>> + Send;

    /// Delete a blob by SHA256 hash (requires auth).
    fn delete(
        &self,
        addr: &Self::Address,
        sha256: &str,
    ) -> impl std::future::Future<Output = Result<bool, String>> + Send;

    /// List blobs uploaded by a pubkey.
    fn list(
        &self,
        addr: &Self::Address,
        pubkey: &str,
    ) -> impl std::future::Future<Output = Result<Vec<BlobDescriptor>, String>> + Send;

    /// Upload a file from disk without buffering the full content in memory.
    ///
    /// Two-pass approach: first pass computes SHA256 (for auth header),
    /// second pass streams the file to the server. The second read hits
    /// the OS page cache so overhead is minimal.
    fn upload_file(
        &self,
        addr: &Self::Address,
        path: &std::path::Path,
        content_type: &str,
    ) -> impl std::future::Future<Output = Result<BlobDescriptor, String>> + Send;
}
