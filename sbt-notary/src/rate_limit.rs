//! Rate limiting middleware for DoS protection
//!
//! Implements token bucket rate limiting at both per-IP and global levels.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::warn;

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

    /// Try to consume a token, returning remaining token info if successful.
    /// Returns `Some((tokens_remaining, max_tokens, reset_secs))` or `None` if empty.
    fn try_consume_with_info(&mut self) -> Option<(f64, f64, f64)> {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            let deficit = self.max_tokens - self.tokens;
            let reset_secs = if self.refill_rate > 0.0 {
                deficit / self.refill_rate
            } else {
                0.0
            };
            Some((self.tokens, self.max_tokens, reset_secs))
        } else {
            None
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

/// Information about the current rate limit state after a successful check.
/// Used to populate `X-RateLimit-*` response headers.
#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    /// Maximum tokens (per-IP burst capacity)
    pub limit: u32,
    /// Remaining tokens in the per-IP bucket (floored to integer)
    pub remaining: u32,
    /// Seconds until the per-IP bucket is fully refilled (ceiled to integer)
    pub reset_secs: u32,
}

/// Rate limiter with per-IP and global limits
pub struct RateLimiter {
    config: RateLimitConfig,
    /// Per-IP rate limit buckets
    clients: Arc<RwLock<HashMap<IpAddr, ClientEntry>>>,
    /// Global rate limit bucket
    global: Arc<RwLock<TokenBucket>>,
    /// Total rate limit checks performed
    requests_checked: AtomicU64,
    /// Total per-IP rate limit rejections
    rejections_per_ip: AtomicU64,
    /// Total global rate limit rejections
    rejections_global: AtomicU64,
}

impl RateLimiter {
    /// Create a new rate limiter with the given configuration
    pub fn new(config: RateLimitConfig) -> Self {
        let global = TokenBucket::new(config.global_burst, config.global_rps);

        Self {
            config,
            clients: Arc::new(RwLock::new(HashMap::new())),
            global: Arc::new(RwLock::new(global)),
            requests_checked: AtomicU64::new(0),
            rejections_per_ip: AtomicU64::new(0),
            rejections_global: AtomicU64::new(0),
        }
    }

    /// Check if a request from the given IP should be allowed.
    /// Returns `RateLimitInfo` with current token state on success,
    /// or `RateLimitError` if rate limited.
    pub async fn check_rate_limit(&self, client_ip: IpAddr) -> Result<RateLimitInfo, RateLimitError> {
        if !self.config.enabled {
            return Ok(RateLimitInfo {
                limit: self.config.per_ip_burst,
                remaining: self.config.per_ip_burst,
                reset_secs: 0,
            });
        }

        self.requests_checked.fetch_add(1, Ordering::Relaxed);

        // Check global rate limit first
        {
            let mut global = self.global.write().await;
            if !global.try_consume() {
                self.rejections_global.fetch_add(1, Ordering::Relaxed);
                warn!(
                    client_ip = %client_ip,
                    limit_type = "global",
                    limit_rps = self.config.global_rps,
                    "Rate limit exceeded"
                );
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

            match entry.bucket.try_consume_with_info() {
                Some((remaining, max_tokens, reset_secs)) => {
                    Ok(RateLimitInfo {
                        limit: max_tokens as u32,
                        remaining: remaining as u32,
                        reset_secs: reset_secs.ceil() as u32,
                    })
                }
                None => {
                    self.rejections_per_ip.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        client_ip = %client_ip,
                        limit_type = "per_ip",
                        limit_rps = self.config.per_ip_rps,
                        "Rate limit exceeded"
                    );
                    Err(RateLimitError::PerIpLimitExceeded)
                }
            }
        }
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

    /// Get total number of rate limit checks performed
    pub fn requests_checked(&self) -> u64 {
        self.requests_checked.load(Ordering::Relaxed)
    }

    /// Get total per-IP rate limit rejections
    pub fn rejections_per_ip(&self) -> u64 {
        self.rejections_per_ip.load(Ordering::Relaxed)
    }

    /// Get total global rate limit rejections
    pub fn rejections_global(&self) -> u64 {
        self.rejections_global.load(Ordering::Relaxed)
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
    async fn test_rate_limit_info_values() {
        let limiter = RateLimiter::new(test_config());
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let info = limiter.check_rate_limit(ip).await.unwrap();
        assert_eq!(info.limit, 20); // per_ip_burst
        assert_eq!(info.remaining, 19); // 20 - 1 consumed
        assert!(info.reset_secs > 0); // some time until full

        // Consume more tokens and verify remaining decreases
        let info2 = limiter.check_rate_limit(ip).await.unwrap();
        assert_eq!(info2.remaining, 18);
    }

    #[tokio::test]
    async fn test_metrics_counters() {
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
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        assert_eq!(limiter.requests_checked(), 0);
        assert_eq!(limiter.rejections_per_ip(), 0);
        assert_eq!(limiter.rejections_global(), 0);

        // Two successful requests
        assert!(limiter.check_rate_limit(ip).await.is_ok());
        assert!(limiter.check_rate_limit(ip).await.is_ok());
        assert_eq!(limiter.requests_checked(), 2);
        assert_eq!(limiter.rejections_per_ip(), 0);

        // Third request should be rejected (burst = 2)
        assert!(limiter.check_rate_limit(ip).await.is_err());
        assert_eq!(limiter.requests_checked(), 3);
        assert_eq!(limiter.rejections_per_ip(), 1);
    }

    #[tokio::test]
    async fn test_disabled_returns_full_info() {
        let mut config = test_config();
        config.enabled = false;
        let limiter = RateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let info = limiter.check_rate_limit(ip).await.unwrap();
        assert_eq!(info.limit, 20); // per_ip_burst from test_config
        assert_eq!(info.remaining, 20); // full capacity when disabled
        assert_eq!(info.reset_secs, 0);

        // Should not increment counters when disabled
        assert_eq!(limiter.requests_checked(), 0);
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
