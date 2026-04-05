//! Token-bucket rate limiter for Blossom servers.
//!
//! Provides per-key rate limiting using a token bucket algorithm backed by
//! [`DashMap`] for lock-free concurrent access. Keys can be IP addresses,
//! public keys, or any string identifier.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;

/// Configuration for the rate limiter.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum tokens (requests) per bucket.
    pub max_tokens: u64,
    /// Token refill rate — tokens added per second.
    pub refill_rate: f64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_tokens: 60,
            refill_rate: 1.0, // 1 token/sec = 60/min
        }
    }
}

struct Bucket {
    tokens: AtomicU64,
    last_refill: AtomicU64, // unix millis
}

/// Token-bucket rate limiter.
///
/// Each unique key gets its own bucket. Tokens refill over time at the
/// configured rate. When a bucket is empty, requests are rejected.
///
/// Thread-safe and lock-free (uses `DashMap` + atomics).
pub struct RateLimiter {
    buckets: Arc<DashMap<String, Bucket>>,
    config: RateLimitConfig,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            buckets: Arc::new(DashMap::new()),
            config,
        }
    }

    /// Check if a request from `key` is allowed. Returns `true` if allowed
    /// (and consumes a token), `false` if rate limited.
    pub fn check(&self, key: &str) -> bool {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let entry = self
            .buckets
            .entry(key.to_string())
            .or_insert_with(|| Bucket {
                tokens: AtomicU64::new(self.config.max_tokens),
                last_refill: AtomicU64::new(now_ms),
            });

        let bucket = entry.value();

        // Refill tokens based on elapsed time.
        let last = bucket.last_refill.load(Ordering::Relaxed);
        let elapsed_ms = now_ms.saturating_sub(last);
        if elapsed_ms > 0 {
            let new_tokens = (elapsed_ms as f64 / 1000.0 * self.config.refill_rate) as u64;
            if new_tokens > 0 {
                bucket.last_refill.store(now_ms, Ordering::Relaxed);
                let current = bucket.tokens.load(Ordering::Relaxed);
                let refilled = current
                    .saturating_add(new_tokens)
                    .min(self.config.max_tokens);
                bucket.tokens.store(refilled, Ordering::Relaxed);
            }
        }

        // Try to consume a token.
        loop {
            let current = bucket.tokens.load(Ordering::Relaxed);
            if current == 0 {
                return false;
            }
            if bucket
                .tokens
                .compare_exchange_weak(current, current - 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }

    /// Get remaining tokens for a key (for rate limit headers).
    pub fn remaining(&self, key: &str) -> u64 {
        self.buckets
            .get(key)
            .map(|b| b.tokens.load(Ordering::Relaxed))
            .unwrap_or(self.config.max_tokens)
    }

    /// Number of tracked keys.
    pub fn tracked_keys(&self) -> usize {
        self.buckets.len()
    }

    /// Clean up stale buckets that haven't been used recently.
    pub fn cleanup(&self, max_age: Duration) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let threshold = now_ms.saturating_sub(max_age.as_millis() as u64);

        self.buckets
            .retain(|_, bucket| bucket.last_refill.load(Ordering::Relaxed) > threshold);
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(RateLimitConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_rate_limit() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_tokens: 3,
            refill_rate: 0.0, // No refill.
        });

        assert!(limiter.check("client1"));
        assert!(limiter.check("client1"));
        assert!(limiter.check("client1"));
        assert!(!limiter.check("client1")); // Exhausted.
    }

    #[test]
    fn test_separate_buckets() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_tokens: 1,
            refill_rate: 0.0,
        });

        assert!(limiter.check("client1"));
        assert!(!limiter.check("client1"));
        assert!(limiter.check("client2")); // Different bucket.
    }

    #[test]
    fn test_remaining() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_tokens: 5,
            refill_rate: 0.0,
        });

        assert_eq!(limiter.remaining("new_client"), 5);
        limiter.check("new_client");
        assert_eq!(limiter.remaining("new_client"), 4);
    }

    #[test]
    fn test_cleanup() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_tokens: 10,
            refill_rate: 0.0,
        });

        limiter.check("client1");
        limiter.check("client2");
        assert_eq!(limiter.tracked_keys(), 2);

        // Cleanup with 0 max age removes everything.
        limiter.cleanup(Duration::from_secs(0));
        assert_eq!(limiter.tracked_keys(), 0);
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let limiter = Arc::new(RateLimiter::new(RateLimitConfig {
            max_tokens: 100,
            refill_rate: 0.0,
        }));

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let lim = limiter.clone();
                thread::spawn(move || {
                    let mut allowed = 0;
                    for _ in 0..20 {
                        if lim.check("shared") {
                            allowed += 1;
                        }
                    }
                    allowed
                })
            })
            .collect();

        let total: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(total, 100); // Exactly max_tokens allowed.
    }
}
