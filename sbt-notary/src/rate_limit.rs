//! Rate limiting middleware for DoS protection
//!
//! Implements token bucket rate limiting at both per-IP and global levels.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::config::RateLimitConfig;

/// Token bucket for rate limiting
#[derive(Debug, Clone)]
struct TokenBucket {
    /// Current number of tokens
    tokens: f64,
    /// Maximum tokens (burst capacity)
    max_tokens: f64,
    /// Tokens added per second
    refill_rate: f64,
    /// Last time tokens were refilled
    last_refill: Instant,
}

impl TokenBucket {
    fn new(max_tokens: u32, refill_rate: u32) -> Self {
        Self {
            tokens: max_tokens as f64,
            max_tokens: max_tokens as f64,
            refill_rate: refill_rate as f64,
            last_refill: Instant::now(),
        }
    }

    /// Try to consume a token, returns true if successful
    fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Refill tokens based on elapsed time
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;
    }
}

/// Per-client rate limit entry
struct ClientEntry {
    bucket: TokenBucket,
    last_seen: Instant,
}

/// Rate limiter with per-IP and global limits
pub struct RateLimiter {
    config: RateLimitConfig,
    /// Per-IP rate limit buckets
    clients: Arc<RwLock<HashMap<IpAddr, ClientEntry>>>,
    /// Global rate limit bucket
    global: Arc<RwLock<TokenBucket>>,
}

impl RateLimiter {
    /// Create a new rate limiter with the given configuration
    pub fn new(config: RateLimitConfig) -> Self {
        let global = TokenBucket::new(config.global_burst, config.global_rps);

        Self {
            config,
            clients: Arc::new(RwLock::new(HashMap::new())),
            global: Arc::new(RwLock::new(global)),
        }
    }

    /// Check if a request from the given IP should be allowed
    /// Returns Ok(()) if allowed, Err with reason if rate limited
    pub async fn check_rate_limit(&self, client_ip: IpAddr) -> Result<(), RateLimitError> {
        if !self.config.enabled {
            return Ok(());
        }

        // Check global rate limit first
        {
            let mut global = self.global.write().await;
            if !global.try_consume() {
                return Err(RateLimitError::GlobalLimitExceeded);
            }
        }

        // Check per-IP rate limit
        {
            let mut clients = self.clients.write().await;
            let entry = clients.entry(client_ip).or_insert_with(|| {
                ClientEntry {
                    bucket: TokenBucket::new(self.config.per_ip_burst, self.config.per_ip_rps),
                    last_seen: Instant::now(),
                }
            });

            entry.last_seen = Instant::now();

            if !entry.bucket.try_consume() {
                return Err(RateLimitError::PerIpLimitExceeded);
            }
        }

        Ok(())
    }

    /// Check if request size is within limits
    pub fn check_request_size(&self, size: usize) -> Result<(), RateLimitError> {
        if !self.config.enabled {
            return Ok(());
        }

        if size > self.config.max_request_size {
            return Err(RateLimitError::RequestTooLarge {
                size,
                max: self.config.max_request_size,
            });
        }

        Ok(())
    }

    /// Get the maximum allowed request size
    pub fn max_request_size(&self) -> usize {
        self.config.max_request_size
    }

    /// Start background cleanup task for expired entries
    pub fn start_cleanup_task(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let cleanup_interval = Duration::from_secs(self.config.cleanup_interval_secs);
        let entry_ttl = Duration::from_secs(self.config.entry_ttl_secs);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);
            loop {
                interval.tick().await;
                self.cleanup_expired_entries(entry_ttl).await;
            }
        })
    }

    /// Remove expired client entries
    async fn cleanup_expired_entries(&self, ttl: Duration) {
        let mut clients = self.clients.write().await;
        let now = Instant::now();

        clients.retain(|_ip, entry| {
            now.duration_since(entry.last_seen) < ttl
        });
    }

    /// Get current number of tracked clients (for metrics)
    pub async fn client_count(&self) -> usize {
        self.clients.read().await.len()
    }
}

/// Rate limit error types
#[derive(Debug, Clone)]
pub enum RateLimitError {
    /// Global rate limit exceeded
    GlobalLimitExceeded,
    /// Per-IP rate limit exceeded
    PerIpLimitExceeded,
    /// Request body too large
    RequestTooLarge { size: usize, max: usize },
}

impl std::fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RateLimitError::GlobalLimitExceeded => {
                write!(f, "Server is experiencing high load, please try again later")
            }
            RateLimitError::PerIpLimitExceeded => {
                write!(f, "Too many requests from your IP address, please slow down")
            }
            RateLimitError::RequestTooLarge { size, max } => {
                write!(f, "Request too large: {} bytes exceeds maximum of {} bytes", size, max)
            }
        }
    }
}

impl std::error::Error for RateLimitError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_config() -> RateLimitConfig {
        RateLimitConfig {
            enabled: true,
            per_ip_rps: 10,
            per_ip_burst: 20,
            global_rps: 100,
            global_burst: 200,
            max_request_size: 1024,
            cleanup_interval_secs: 60,
            entry_ttl_secs: 300,
        }
    }

    #[tokio::test]
    async fn test_rate_limiter_allows_requests() {
        let limiter = RateLimiter::new(test_config());
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // First few requests should succeed
        for _ in 0..10 {
            assert!(limiter.check_rate_limit(ip).await.is_ok());
        }
    }

    #[tokio::test]
    async fn test_rate_limiter_blocks_burst() {
        let config = RateLimitConfig {
            enabled: true,
            per_ip_rps: 1,
            per_ip_burst: 5,
            global_rps: 1000,
            global_burst: 2000,
            max_request_size: 1024,
            cleanup_interval_secs: 60,
            entry_ttl_secs: 300,
        };
        let limiter = RateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // Should allow burst of 5
        for _ in 0..5 {
            assert!(limiter.check_rate_limit(ip).await.is_ok());
        }

        // 6th request should be blocked
        assert!(matches!(
            limiter.check_rate_limit(ip).await,
            Err(RateLimitError::PerIpLimitExceeded)
        ));
    }

    #[tokio::test]
    async fn test_request_size_validation() {
        let limiter = RateLimiter::new(test_config());

        // Valid size
        assert!(limiter.check_request_size(512).is_ok());

        // Too large
        assert!(matches!(
            limiter.check_request_size(2048),
            Err(RateLimitError::RequestTooLarge { .. })
        ));
    }

    #[tokio::test]
    async fn test_disabled_rate_limiter() {
        let mut config = test_config();
        config.enabled = false;
        let limiter = RateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // Should always allow when disabled
        for _ in 0..100 {
            assert!(limiter.check_rate_limit(ip).await.is_ok());
        }
    }

    #[tokio::test]
    async fn test_different_ips_have_separate_limits() {
        let config = RateLimitConfig {
            enabled: true,
            per_ip_rps: 1,
            per_ip_burst: 2,
            global_rps: 1000,
            global_burst: 2000,
            max_request_size: 1024,
            cleanup_interval_secs: 60,
            entry_ttl_secs: 300,
        };
        let limiter = RateLimiter::new(config);
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        // Each IP gets its own burst
        assert!(limiter.check_rate_limit(ip1).await.is_ok());
        assert!(limiter.check_rate_limit(ip1).await.is_ok());
        assert!(limiter.check_rate_limit(ip2).await.is_ok());
        assert!(limiter.check_rate_limit(ip2).await.is_ok());

        // Both should be blocked now
        assert!(limiter.check_rate_limit(ip1).await.is_err());
        assert!(limiter.check_rate_limit(ip2).await.is_err());
    }
}
