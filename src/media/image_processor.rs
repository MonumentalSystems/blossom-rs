//! Image processing implementation using the `image` crate.
//!
//! Behind the `media` feature flag. Provides thumbnail generation,
//! blurhash computation, EXIF validation, and perceptual hashing.

use super::{MediaError, MediaProcessor, MediaResult};

const MAX_IMAGE_DIMENSION: u32 = 16_384;
const MAX_IMAGE_ALLOCATION: u64 = 256 * 1024 * 1024;

/// Image processor using the `image`, `blurhash`, and `kamadak-exif` crates.
pub struct ImageProcessor {
    /// Maximum thumbnail dimension (width or height).
    pub thumbnail_max_size: u32,
    /// Whether to reject images with GPS EXIF data.
    pub reject_gps_exif: bool,
}

impl Default for ImageProcessor {
    fn default() -> Self {
        Self {
            thumbnail_max_size: 200,
            reject_gps_exif: true,
        }
    }
}

impl ImageProcessor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with custom thumbnail size and GPS rejection policy.
    pub fn with_config(thumbnail_max_size: u32, reject_gps_exif: bool) -> Self {
        Self {
            thumbnail_max_size,
            reject_gps_exif,
        }
    }

    fn decode_limited(data: &[u8]) -> Result<image::DynamicImage, MediaError> {
        let mut reader = image::ImageReader::new(std::io::Cursor::new(data))
            .with_guessed_format()
            .map_err(|e| MediaError::ProcessingFailed(format!("detect format: {e}")))?;
        let mut limits = image::Limits::default();
        limits.max_image_width = Some(MAX_IMAGE_DIMENSION);
        limits.max_image_height = Some(MAX_IMAGE_DIMENSION);
        limits.max_alloc = Some(MAX_IMAGE_ALLOCATION);
        reader.limits(limits);
        reader
            .decode()
            .map_err(|e| MediaError::ProcessingFailed(format!("decode: {e}")))
    }

    fn perceptual_hash_image(img: &image::DynamicImage) -> u64 {
        let small = img.resize_exact(8, 8, image::imageops::FilterType::Lanczos3);
        let gray = small.to_luma8();
        let pixels: Vec<u8> = gray.pixels().map(|p| p.0[0]).collect();
        let mean = pixels.iter().map(|&p| p as f64).sum::<f64>() / pixels.len() as f64;
        pixels
            .iter()
            .enumerate()
            .fold(0u64, |mut hash, (i, pixel)| {
                if *pixel as f64 > mean {
                    hash |= 1 << (63 - i);
                }
                hash
            })
    }

    fn blurhash_image(img: &image::DynamicImage) -> Result<String, MediaError> {
        let small = img.resize(32, 32, image::imageops::FilterType::Lanczos3);
        let rgba = small.to_rgba8();
        let (w, h) = rgba.dimensions();
        blurhash::encode(4, 3, w, h, &rgba.into_raw())
            .map_err(|e| MediaError::ProcessingFailed(format!("blurhash: {e}")))
    }
}

impl MediaProcessor for ImageProcessor {
    fn process(&self, data: &[u8], mime_type: &str) -> Result<MediaResult, MediaError> {
        if !mime_type.starts_with("image/") {
            return Err(MediaError::UnsupportedType(mime_type.to_string()));
        }

        if self.reject_gps_exif {
            self.validate_exif(data)?;
        }

        // Decode image.
        let img = Self::decode_limited(data)?;

        let width = img.width();
        let height = img.height();

        // Generate thumbnail.
        let thumb = img.thumbnail(self.thumbnail_max_size, self.thumbnail_max_size);
        let mut thumb_bytes = Vec::new();
        thumb
            .write_to(
                &mut std::io::Cursor::new(&mut thumb_bytes),
                image::ImageFormat::Png,
            )
            .map_err(|e| MediaError::ProcessingFailed(format!("thumbnail: {e}")))?;

        // Compute blurhash.
        let blurhash = Self::blurhash_image(&img).ok();

        // Compute perceptual hash.
        let phash = Some(Self::perceptual_hash_image(&img));

        Ok(MediaResult {
            data: data.to_vec(),
            mime_type: mime_type.to_string(),
            width: Some(width),
            height: Some(height),
            blurhash,
            thumbnail: Some(thumb_bytes),
            phash,
        })
    }

    fn validate_exif(&self, data: &[u8]) -> Result<(), MediaError> {
        let reader = std::io::Cursor::new(data);
        let exif_reader = exif::Reader::new();
        if let Ok(exif) = exif_reader.read_from_container(&mut std::io::BufReader::new(reader)) {
            for field in exif.fields() {
                let tag_str = format!("{}", field.tag);
                if tag_str.contains("GPS") {
                    return Err(MediaError::SensitiveExif(format!(
                        "GPS data found: {}",
                        field.tag
                    )));
                }
            }
        }
        // No EXIF or no sensitive fields — OK.
        Ok(())
    }

    fn perceptual_hash(&self, data: &[u8]) -> Result<u64, MediaError> {
        let img = Self::decode_limited(data)?;
        Ok(Self::perceptual_hash_image(&img))
    }

    fn blurhash(&self, data: &[u8]) -> Result<String, MediaError> {
        let img = Self::decode_limited(data)?;
        Self::blurhash_image(&img)
    }

    fn thumbnail(
        &self,
        data: &[u8],
        max_width: u32,
        max_height: u32,
    ) -> Result<Vec<u8>, MediaError> {
        let img = Self::decode_limited(data)?;

        let thumb = img.thumbnail(max_width, max_height);
        let mut bytes = Vec::new();
        thumb
            .write_to(
                &mut std::io::Cursor::new(&mut bytes),
                image::ImageFormat::Png,
            )
            .map_err(|e| MediaError::ProcessingFailed(format!("thumbnail: {e}")))?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a simple PNG image programmatically.
    fn make_test_png(width: u32, height: u32, color: [u8; 3]) -> Vec<u8> {
        let img = image::RgbImage::from_fn(width, height, |_x, _y| image::Rgb(color));
        let mut bytes = Vec::new();
        img.write_to(
            &mut std::io::Cursor::new(&mut bytes),
            image::ImageFormat::Png,
        )
        .unwrap();
        bytes
    }

    /// Generate a gradient PNG for perceptual hash testing.
    fn make_gradient_png(width: u32, height: u32) -> Vec<u8> {
        let img = image::RgbImage::from_fn(width, height, |x, _y| {
            let v = (x * 255 / width.max(1)) as u8;
            image::Rgb([v, v, v])
        });
        let mut bytes = Vec::new();
        img.write_to(
            &mut std::io::Cursor::new(&mut bytes),
            image::ImageFormat::Png,
        )
        .unwrap();
        bytes
    }

    #[test]
    fn test_process_png() {
        let proc = ImageProcessor::new();
        let png = make_test_png(100, 80, [255, 0, 0]);

        let result = proc.process(&png, "image/png").unwrap();
        assert_eq!(result.width, Some(100));
        assert_eq!(result.height, Some(80));
        assert_eq!(result.mime_type, "image/png");
        assert!(result.thumbnail.is_some());
        assert!(result.blurhash.is_some());
        assert!(result.phash.is_some());
        // Thumbnail should be a valid PNG.
        let thumb_data = result.thumbnail.unwrap();
        let thumb = image::load_from_memory(&thumb_data).unwrap();
        assert!(thumb.width() <= 200);
        assert!(thumb.height() <= 200);
    }

    #[test]
    fn test_process_rejects_non_image() {
        let proc = ImageProcessor::new();
        let result = proc.process(b"not an image", "text/plain");
        assert!(matches!(result, Err(MediaError::UnsupportedType(_))));
    }

    #[test]
    fn test_process_rejects_corrupt_image() {
        let proc = ImageProcessor::new();
        let result = proc.process(b"not valid png data", "image/png");
        assert!(matches!(result, Err(MediaError::ProcessingFailed(_))));
    }

    #[test]
    fn test_thumbnail_respects_max_size() {
        let proc = ImageProcessor::with_config(50, false);
        let png = make_test_png(400, 300, [0, 128, 255]);

        let thumb_bytes = proc.thumbnail(&png, 50, 50).unwrap();
        // Verify the thumbnail is a valid image with correct dimensions.
        let thumb = image::load_from_memory(&thumb_bytes).unwrap();
        assert!(thumb.width() <= 50);
        assert!(thumb.height() <= 50);
    }

    #[test]
    fn test_thumbnail_preserves_aspect_ratio() {
        let proc = ImageProcessor::new();
        let png = make_test_png(200, 100, [0, 0, 0]);

        let thumb_bytes = proc.thumbnail(&png, 100, 100).unwrap();
        let thumb = image::load_from_memory(&thumb_bytes).unwrap();
        // 200x100 → 100x50 (aspect ratio preserved).
        assert_eq!(thumb.width(), 100);
        assert_eq!(thumb.height(), 50);
    }

    #[test]
    fn test_blurhash_produces_valid_string() {
        let proc = ImageProcessor::new();
        let png = make_test_png(64, 64, [100, 150, 200]);

        let hash = proc.blurhash(&png).unwrap();
        assert!(!hash.is_empty());
        // Blurhash strings are typically 20-30 chars.
        assert!(hash.len() > 5);
        assert!(hash.len() < 100);
    }

    #[test]
    fn test_blurhash_deterministic() {
        let proc = ImageProcessor::new();
        let png = make_test_png(32, 32, [50, 100, 150]);

        let hash1 = proc.blurhash(&png).unwrap();
        let hash2 = proc.blurhash(&png).unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_perceptual_hash_deterministic() {
        let proc = ImageProcessor::new();
        let png = make_test_png(100, 100, [128, 64, 32]);

        let h1 = proc.perceptual_hash(&png).unwrap();
        let h2 = proc.perceptual_hash(&png).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_perceptual_hash_similar_images() {
        let proc = ImageProcessor::new();
        // Two nearly identical images — should have similar hashes.
        let png1 = make_test_png(100, 100, [128, 64, 32]);
        let png2 = make_test_png(100, 100, [130, 66, 34]); // Slightly different color.

        let h1 = proc.perceptual_hash(&png1).unwrap();
        let h2 = proc.perceptual_hash(&png2).unwrap();

        // Hamming distance should be small for similar images.
        let hamming = (h1 ^ h2).count_ones();
        assert!(
            hamming < 10,
            "hamming distance {} too large for similar images",
            hamming
        );
    }

    #[test]
    fn test_perceptual_hash_different_images() {
        let proc = ImageProcessor::new();
        // Solid black vs gradient — should have very different hashes.
        let black = make_test_png(100, 100, [0, 0, 0]);
        let gradient = make_gradient_png(100, 100);

        let h1 = proc.perceptual_hash(&black).unwrap();
        let h2 = proc.perceptual_hash(&gradient).unwrap();

        let hamming = (h1 ^ h2).count_ones();
        assert!(
            hamming > 10,
            "hamming distance {} too small for different images",
            hamming
        );
    }

    #[test]
    fn test_perceptual_hash_scale_invariant() {
        let proc = ImageProcessor::new();
        // Same color, different sizes — phash is scale-invariant for solid colors.
        let small = make_test_png(50, 50, [200, 100, 50]);
        let large = make_test_png(500, 500, [200, 100, 50]);

        let h1 = proc.perceptual_hash(&small).unwrap();
        let h2 = proc.perceptual_hash(&large).unwrap();
        assert_eq!(
            h1, h2,
            "phash should be identical for same solid color at different sizes"
        );
    }

    #[test]
    fn test_validate_exif_no_exif_passes() {
        let proc = ImageProcessor::new();
        let png = make_test_png(10, 10, [0, 0, 0]);
        // PNGs generated by the image crate have no EXIF data.
        proc.validate_exif(&png).unwrap();
    }

    #[test]
    fn test_validate_exif_non_image_passes() {
        let proc = ImageProcessor::new();
        // Random bytes — no EXIF container found, should pass.
        proc.validate_exif(b"not an image at all").unwrap();
    }

    #[test]
    fn test_process_with_gps_rejection_disabled() {
        let proc = ImageProcessor::with_config(100, false);
        let png = make_test_png(10, 10, [0, 0, 0]);
        // Should work fine with GPS rejection off.
        let result = proc.process(&png, "image/png").unwrap();
        assert_eq!(result.width, Some(10));
    }

    #[test]
    fn test_process_full_pipeline() {
        let proc = ImageProcessor::new();
        let png = make_test_png(256, 128, [64, 128, 192]);

        let result = proc.process(&png, "image/png").unwrap();

        // Dimensions.
        assert_eq!(result.width, Some(256));
        assert_eq!(result.height, Some(128));

        // Thumbnail generated and valid.
        let thumb_data = result.thumbnail.unwrap();
        let thumb = image::load_from_memory(&thumb_data).unwrap();
        assert!(thumb.width() <= 200);
        assert!(thumb.height() <= 200);

        // Blurhash present.
        let bh = result.blurhash.unwrap();
        assert!(!bh.is_empty());

        // Phash present.
        assert!(result.phash.is_some());
    }

    #[test]
    fn test_process_small_image() {
        let proc = ImageProcessor::new();
        // Image smaller than thumbnail max — should still work.
        let png = make_test_png(5, 5, [255, 255, 255]);

        let result = proc.process(&png, "image/png").unwrap();
        assert_eq!(result.width, Some(5));
        assert_eq!(result.height, Some(5));
        assert!(result.thumbnail.is_some());
    }

    #[test]
    fn test_process_large_image() {
        let proc = ImageProcessor::with_config(100, false);
        let png = make_test_png(1000, 800, [10, 20, 30]);

        let result = proc.process(&png, "image/png").unwrap();
        assert_eq!(result.width, Some(1000));
        assert_eq!(result.height, Some(800));

        // Thumbnail should be within bounds.
        let thumb = image::load_from_memory(&result.thumbnail.unwrap()).unwrap();
        assert!(thumb.width() <= 100);
        assert!(thumb.height() <= 100);
    }

    #[test]
    fn test_jpeg_format() {
        let proc = ImageProcessor::new();
        // Generate a JPEG.
        let img = image::RgbImage::from_fn(50, 50, |_, _| image::Rgb([100, 150, 200]));
        let mut bytes = Vec::new();
        img.write_to(
            &mut std::io::Cursor::new(&mut bytes),
            image::ImageFormat::Jpeg,
        )
        .unwrap();

        let result = proc.process(&bytes, "image/jpeg").unwrap();
        assert_eq!(result.width, Some(50));
        assert_eq!(result.height, Some(50));
        assert!(result.thumbnail.is_some());
        assert!(result.blurhash.is_some());
    }
}
