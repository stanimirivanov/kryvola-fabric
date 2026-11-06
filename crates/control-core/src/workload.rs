//! Bounded identity and provider leases. TLS chain/identity validation remains SPIFFE's job.

use std::time::{Duration, Instant};

pub const PROVIDER_TTL: Duration = Duration::from_secs(15);
pub const PROVIDER_REFRESH: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct Lease<T> {
    pub value: T,
    pub refreshed: Instant,
}
impl<T> Lease<T> {
    pub fn live(&self, now: Instant) -> bool {
        now.checked_duration_since(self.refreshed)
            .is_some_and(|age| age < PROVIDER_TTL)
    }
}

fn validity(not_before: i64, not_after: i64, now_ms: u64) -> bool {
    not_after
        .checked_sub(not_before)
        .is_some_and(|ttl| (1..=60).contains(&ttl))
        && u64::try_from(not_before)
            .ok()
            .and_then(|t| t.checked_mul(1000))
            .is_some_and(|t| now_ms >= t)
        && u64::try_from(not_after)
            .ok()
            .and_then(|t| t.checked_mul(1000))
            .is_some_and(|t| now_ms < t)
}

pub fn identity_expiry(der: &[u8], now_ms: u64) -> Option<u64> {
    let (rest, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let before = cert.validity().not_before.timestamp();
    let after = cert.validity().not_after.timestamp();
    if !rest.is_empty() || !validity(before, after, now_ms) {
        return None;
    }
    u64::try_from(after).ok()?.checked_mul(1000)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn provider_lease_expires_at_bound_and_failed_refresh_cannot_renew_it() {
        let now = Instant::now();
        let lease = Lease {
            value: (),
            refreshed: now,
        };
        assert!(lease.live(now + PROVIDER_TTL - Duration::from_nanos(1)));
        assert!(!lease.live(now + PROVIDER_TTL));
        assert!(!lease.live(now + PROVIDER_TTL + Duration::from_secs(10)));
    }
    #[test]
    fn identity_validity_is_bounded_and_checked_again_at_request_time() {
        assert!(validity(1, 61, 60_999));
        assert!(!validity(1, 62, 60_999));
        assert!(!validity(1, 61, 61_000));
        assert!(!validity(1, 61, 999));
        assert!(!validity(61, 1, 1_000));
    }
}
