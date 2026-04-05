//! Webhook notification system for blob lifecycle events.
//!
//! Provides a [`WebhookNotifier`] trait and an HTTP webhook implementation
//! that fires on upload, delete, and mirror events.

use serde::{Deserialize, Serialize};

/// Blob lifecycle event types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    Upload,
    Delete,
    Mirror,
}

/// Payload sent to webhook endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookPayload {
    /// Event type that triggered the webhook.
    pub event: EventType,
    /// SHA256 hash of the blob.
    pub sha256: String,
    /// Size in bytes.
    pub size: u64,
    /// Public key of the actor (hex).
    pub pubkey: String,
    /// Unix timestamp.
    pub timestamp: u64,
    /// Additional metadata (e.g., source URL for mirrors).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Trait for webhook notification delivery.
///
/// Implementations are called after blob lifecycle events. Delivery is
/// best-effort and non-blocking — failures are logged but don't affect
/// the primary operation.
pub trait WebhookNotifier: Send + Sync {
    /// Notify about a blob event. Implementations should not block.
    fn notify(&self, payload: WebhookPayload);
}

/// No-op notifier — discards all events. Default when no webhooks configured.
pub struct NoopNotifier;

impl WebhookNotifier for NoopNotifier {
    fn notify(&self, _payload: WebhookPayload) {}
}

/// HTTP webhook notifier — sends POST requests to configured URLs.
///
/// Delivery is async and fire-and-forget. Failed deliveries are logged
/// via `tracing::warn` but never retried.
pub struct HttpNotifier {
    urls: Vec<String>,
    client: reqwest::Client,
}

impl HttpNotifier {
    /// Create a notifier that posts to the given webhook URLs.
    pub fn new(urls: Vec<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self { urls, client }
    }
}

impl WebhookNotifier for HttpNotifier {
    fn notify(&self, payload: WebhookPayload) {
        for url in &self.urls {
            let client = self.client.clone();
            let url = url.clone();
            let payload = payload.clone();
            tokio::spawn(async move {
                if let Err(e) = client.post(&url).json(&payload).send().await {
                    tracing::warn!(
                        webhook.url = %url,
                        error.message = %e,
                        "webhook delivery failed"
                    );
                }
            });
        }
    }
}

/// Helper to build a webhook payload with the current timestamp.
pub fn make_payload(
    event: EventType,
    sha256: &str,
    size: u64,
    pubkey: &str,
    metadata: Option<serde_json::Value>,
) -> WebhookPayload {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    WebhookPayload {
        event,
        sha256: sha256.to_string(),
        size,
        pubkey: pubkey.to_string(),
        timestamp,
        metadata,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_serde() {
        let payload = make_payload(EventType::Upload, &"a".repeat(64), 1024, "pubkey", None);
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"event\":\"upload\""));
        assert!(json.contains("\"size\":1024"));

        let parsed: WebhookPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.event, EventType::Upload);
    }

    #[test]
    fn test_noop_notifier() {
        let notifier = NoopNotifier;
        let payload = make_payload(EventType::Delete, &"b".repeat(64), 0, "pk", None);
        notifier.notify(payload); // Should not panic.
    }

    #[test]
    fn test_payload_with_metadata() {
        let meta = serde_json::json!({"source_url": "https://example.com/blob"});
        let payload = make_payload(EventType::Mirror, &"c".repeat(64), 512, "pk", Some(meta));
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("source_url"));
    }
}
