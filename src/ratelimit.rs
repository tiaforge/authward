//! Per-IP rate limiting on `/login` and `/callback` (Phase 9). Token-
//! bucket, no per-account lockout — the plan's locked-in decision, so
//! this can't be weaponized into a targeted denial-of-service against a
//! specific user's account, only throttles a given source IP.

use std::net::IpAddr;
use std::time::Instant;

use axum::http::HeaderMap;
use dashmap::DashMap;

/// Default token-bucket shape for `/login` + `/callback`: a burst of 20
/// (comfortably covers a real user retrying a botched login a few times)
/// refilling at 20/minute sustained. Exact thresholds aren't
/// operator-configurable — there's nothing here specific enough to a
/// deployment to warrant new config surface for it.
pub const LOGIN_RATE_LIMIT_CAPACITY: f64 = 20.0;
pub const LOGIN_RATE_LIMIT_REFILL_PER_SEC: f64 = 20.0 / 60.0;

pub struct RateLimiter {
    buckets: DashMap<IpAddr, Bucket>,
    capacity: f64,
    refill_per_sec: f64,
}

struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

impl RateLimiter {
    pub fn new(capacity: f64, refill_per_sec: f64) -> Self {
        Self {
            buckets: DashMap::new(),
            capacity,
            refill_per_sec,
        }
    }

    /// Consumes one token for `ip` if available. Returns `true` if the
    /// request should proceed, `false` if it should be rejected.
    pub fn check(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut bucket = self.buckets.entry(ip).or_insert_with(|| Bucket {
            tokens: self.capacity,
            last_refill: now,
        });

        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Drops buckets that have been sitting at full capacity for a while
    /// (i.e. genuinely idle, not just between bursts) — keeps the map
    /// from growing by one entry per distinct client IP for the life of
    /// the process. Called periodically alongside the other background
    /// sweeps.
    pub fn prune_idle(&self, idle_for: std::time::Duration) {
        let now = Instant::now();
        self.buckets.retain(|_, bucket| {
            bucket.tokens < self.capacity || now.duration_since(bucket.last_refill) < idle_for
        });
    }
}

/// Spawns the background loop that prunes idle rate-limit buckets —
/// keeps `login_rate_limiter`'s map from growing by one entry per
/// distinct client IP for the life of the process.
pub fn spawn_periodic_prune(
    state: crate::state::AppState,
    interval: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            state.login_rate_limiter.prune_idle(interval);
        }
    })
}

/// The client IP Caddy observed directly, from the last hop of
/// `X-Forwarded-For` — the entry Caddy itself appended, which is
/// trustworthy given the network-isolation trust boundary (this service
/// is unreachable except through Caddy). Absent or unparseable just
/// means rate limiting can't key on an IP for this request; callers
/// should fail open on that rather than block legitimate traffic outright.
pub fn client_ip(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get("x-forwarded-for")?
        .to_str()
        .ok()?
        .rsplit(',')
        .next()?
        .trim()
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_bursts_up_to_capacity_then_blocks() {
        let limiter = RateLimiter::new(3.0, 1.0);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(limiter.check(ip));
        assert!(limiter.check(ip));
        assert!(limiter.check(ip));
        assert!(
            !limiter.check(ip),
            "fourth immediate request should be rejected"
        );
    }

    #[test]
    fn different_ips_have_independent_buckets() {
        let limiter = RateLimiter::new(1.0, 1.0);
        let a: IpAddr = "127.0.0.1".parse().unwrap();
        let b: IpAddr = "127.0.0.2".parse().unwrap();
        assert!(limiter.check(a));
        assert!(!limiter.check(a));
        assert!(limiter.check(b), "a different IP must have its own budget");
    }

    #[test]
    fn client_ip_uses_the_last_forwarded_for_hop() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.5, 10.0.0.1".parse().unwrap());
        assert_eq!(client_ip(&headers), Some("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn client_ip_missing_header_is_none() {
        assert_eq!(client_ip(&HeaderMap::new()), None);
    }
}
