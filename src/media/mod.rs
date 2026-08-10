//! Media processing pipeline.
//!
//! Behind the `media` feature flag. Provides a [`MediaProcessor`] trait
//! for pluggable image/video processing (WebP conversion, thumbnails,
//! blurhash generation, EXIF validation, perceptual hashing).

/// Result of processing a media file.
#[derive(Debug, Clone)]
pub struct MediaResult {
    /// Processed file bytes (may be converted format).
    pub data: Vec<u8>,
    /// MIME type of the processed file.
    pub mime_type: String,
    /// Width in pixels (if image/video).
    pub width: Option<u32>,
    /// Height in pixels (if image/video).
    pub height: Option<u32>,
    /// Blurhash string for progressive loading.
    pub blurhash: Option<String>,
    /// Thumbnail bytes (small preview image).
    pub thumbnail: Option<Vec<u8>>,
    /// Perceptual hash for duplicate detection.
    pub phash: Option<u64>,
}

/// Errors from media processing.
#[derive(Debug, thiserror::Error)]
pub enum MediaError {
    #[error("unsupported media type: {0}")]
    UnsupportedType(String),
    #[error("sensitive EXIF data detected: {0}")]
    SensitiveExif(String),
    #[error("processing failed: {0}")]
    ProcessingFailed(String),
}

/// Trait for pluggable media processing.
///
/// Implementations handle image/video conversion, thumbnail generation,
/// metadata extraction, and privacy validation.
///
/// The server runs [`MediaProcessor::process`] on a blocking worker and applies
/// a request deadline. Rust cannot safely terminate an arbitrary running
/// thread, so the deadline cancels work that has not started but an invocation
/// already in progress continues to consume one of the server's bounded
/// processing slots until it returns. This fail-closed behavior prevents
/// timed-out work from growing without bound. Implementations should enforce
/// their own input, allocation, and codec limits and must not block
/// indefinitely, because stuck processors can exhaust media capacity.
pub trait MediaProcessor: Send + Sync {
    /// Process a media file. Returns the processed result with metadata.
    fn process(&self, data: &[u8], mime_type: &str) -> Result<MediaResult, MediaError>;

    /// Validate that a file doesn't contain sensitive EXIF metadata
    /// (GPS coordinates, device serial numbers, etc.).
    fn validate_exif(&self, data: &[u8]) -> Result<(), MediaError>;

    /// Compute a perceptual hash for an image (for duplicate detection).
    fn perceptual_hash(&self, data: &[u8]) -> Result<u64, MediaError>;

    /// Generate a blurhash string for an image.
    fn blurhash(&self, data: &[u8]) -> Result<String, MediaError>;

    /// Generate a thumbnail.
    fn thumbnail(
        &self,
        data: &[u8],
        max_width: u32,
        max_height: u32,
    ) -> Result<Vec<u8>, MediaError>;
}

/// No-op media processor that passes data through unchanged.
///
/// Useful as a default when media processing is not needed.
pub struct PassthroughProcessor;

impl MediaProcessor for PassthroughProcessor {
    fn process(&self, data: &[u8], mime_type: &str) -> Result<MediaResult, MediaError> {
        Ok(MediaResult {
            data: data.to_vec(),
            mime_type: mime_type.to_string(),
            width: None,
            height: None,
            blurhash: None,
            thumbnail: None,
            phash: None,
        })
    }

    fn validate_exif(&self, _data: &[u8]) -> Result<(), MediaError> {
        Ok(())
    }

    fn perceptual_hash(&self, _data: &[u8]) -> Result<u64, MediaError> {
        Err(MediaError::UnsupportedType(
            "passthrough processor does not compute phash".into(),
        ))
    }

    fn blurhash(&self, _data: &[u8]) -> Result<String, MediaError> {
        Err(MediaError::UnsupportedType(
            "passthrough processor does not compute blurhash".into(),
        ))
    }

    fn thumbnail(
        &self,
        _data: &[u8],
        _max_width: u32,
        _max_height: u32,
    ) -> Result<Vec<u8>, MediaError> {
        Err(MediaError::UnsupportedType(
            "passthrough processor does not generate thumbnails".into(),
        ))
    }
}

#[cfg(feature = "media")]
mod image_processor;

#[cfg(feature = "media")]
pub use image_processor::ImageProcessor;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passthrough_processor() {
        let proc = PassthroughProcessor;
        let data = b"fake image data";
        let result = proc.process(data, "image/png").unwrap();
        assert_eq!(result.data, data);
        assert_eq!(result.mime_type, "image/png");
        assert!(result.width.is_none());
        assert!(result.thumbnail.is_none());
    }

    #[test]
    fn test_passthrough_exif_always_ok() {
        let proc = PassthroughProcessor;
        proc.validate_exif(b"anything").unwrap();
    }

    #[test]
    fn test_passthrough_phash_unsupported() {
        let proc = PassthroughProcessor;
        assert!(proc.perceptual_hash(b"data").is_err());
    }

    #[test]
    fn test_media_result_fields() {
        let result = MediaResult {
            data: vec![1, 2, 3],
            mime_type: "image/webp".into(),
            width: Some(800),
            height: Some(600),
            blurhash: Some("LEHV6nWB2yk8pyoJadR*.7kCMdnj".into()),
            thumbnail: Some(vec![4, 5, 6]),
            phash: Some(0xDEADBEEF),
        };
        assert_eq!(result.width, Some(800));
        assert_eq!(result.height, Some(600));
        assert!(result.blurhash.is_some());
        assert!(result.phash.is_some());
    }
}
