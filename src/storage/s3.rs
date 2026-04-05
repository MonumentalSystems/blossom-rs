//! S3-compatible blob storage backend.
//!
//! Supports AWS S3, Cloudflare R2, MinIO, and other S3-compatible stores.
//! Behind the `s3` feature flag.

// TODO: Phase 2 implementation
// - S3Config struct
// - S3Backend implementing BlobBackend
// - Async upload/download via aws-sdk-s3
// - Optional CDN URL for direct downloads
