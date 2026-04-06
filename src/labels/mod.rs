//! Content labeling and classification.
//!
//! Behind the `labels` feature flag. Provides a [`MediaLabeler`] trait
//! for pluggable content classification (Vision Transformer, LLM API, etc.).

use serde::{Deserialize, Serialize};

/// A content label with confidence score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentLabel {
    /// Label name (e.g., "nsfw", "violence", "safe").
    pub label: String,
    /// Confidence score (0.0 to 1.0).
    pub confidence: f32,
}

/// Result of content classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelResult {
    /// All detected labels with confidence scores.
    pub labels: Vec<ContentLabel>,
    /// Whether the content should be blocked based on policy.
    pub blocked: bool,
    /// Human-readable reason if blocked.
    pub reason: Option<String>,
}

/// Errors from content labeling.
#[derive(Debug, thiserror::Error)]
pub enum LabelError {
    #[error("unsupported content type: {0}")]
    UnsupportedType(String),
    #[error("model not loaded: {0}")]
    ModelNotLoaded(String),
    #[error("classification failed: {0}")]
    ClassificationFailed(String),
    #[error("API error: {0}")]
    ApiError(String),
}

/// Trait for pluggable content classification.
///
/// Implementations classify media content and return labels with confidence scores.
pub trait MediaLabeler: Send + Sync {
    /// Classify the content of a file.
    fn classify(&self, data: &[u8], mime_type: &str) -> Result<LabelResult, LabelError>;

    /// Check if this labeler supports the given MIME type.
    fn supports(&self, mime_type: &str) -> bool;
}

/// No-op labeler that marks everything as safe.
///
/// Useful as a default when content labeling is not needed.
pub struct NoopLabeler;

impl MediaLabeler for NoopLabeler {
    fn classify(&self, _data: &[u8], _mime_type: &str) -> Result<LabelResult, LabelError> {
        Ok(LabelResult {
            labels: vec![ContentLabel {
                label: "safe".to_string(),
                confidence: 1.0,
            }],
            blocked: false,
            reason: None,
        })
    }

    fn supports(&self, _mime_type: &str) -> bool {
        true
    }
}

/// Labeler that blocks all content. Useful for testing or as a circuit breaker.
pub struct BlockAllLabeler {
    reason: String,
}

impl BlockAllLabeler {
    pub fn new(reason: &str) -> Self {
        Self {
            reason: reason.to_string(),
        }
    }
}

impl MediaLabeler for BlockAllLabeler {
    fn classify(&self, _data: &[u8], _mime_type: &str) -> Result<LabelResult, LabelError> {
        Ok(LabelResult {
            labels: vec![ContentLabel {
                label: "blocked".to_string(),
                confidence: 1.0,
            }],
            blocked: true,
            reason: Some(self.reason.clone()),
        })
    }

    fn supports(&self, _mime_type: &str) -> bool {
        true
    }
}

// TODO: VitLabeler — local Vision Transformer inference via Candle
// Requires: candle-core, candle-nn, candle-transformers
// Should implement MediaLabeler with a pre-trained image classification model.

// TODO: LlmLabeler — remote API-based classification (OpenAI-compatible)
// Requires: reqwest, serde_json
// Should send image data to an LLM vision endpoint and parse the classification response.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noop_labeler_safe() {
        let labeler = NoopLabeler;
        let result = labeler.classify(b"test data", "image/png").unwrap();
        assert!(!result.blocked);
        assert_eq!(result.labels.len(), 1);
        assert_eq!(result.labels[0].label, "safe");
        assert_eq!(result.labels[0].confidence, 1.0);
    }

    #[test]
    fn test_noop_supports_everything() {
        let labeler = NoopLabeler;
        assert!(labeler.supports("image/png"));
        assert!(labeler.supports("video/mp4"));
        assert!(labeler.supports("application/pdf"));
    }

    #[test]
    fn test_block_all_labeler() {
        let labeler = BlockAllLabeler::new("maintenance mode");
        let result = labeler.classify(b"data", "image/jpeg").unwrap();
        assert!(result.blocked);
        assert_eq!(result.reason, Some("maintenance mode".to_string()));
    }

    #[test]
    fn test_content_label_serde() {
        let label = ContentLabel {
            label: "nsfw".to_string(),
            confidence: 0.95,
        };
        let json = serde_json::to_string(&label).unwrap();
        let parsed: ContentLabel = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.label, "nsfw");
        assert!((parsed.confidence - 0.95).abs() < f32::EPSILON);
    }

    #[test]
    fn test_label_result_serde() {
        let result = LabelResult {
            labels: vec![
                ContentLabel {
                    label: "safe".into(),
                    confidence: 0.8,
                },
                ContentLabel {
                    label: "nature".into(),
                    confidence: 0.6,
                },
            ],
            blocked: false,
            reason: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: LabelResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.labels.len(), 2);
        assert!(!parsed.blocked);
    }
}
