//! Relay-native token buckets and inexpensive admission checks.

use crate::config::AbuseConfig;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BudgetKind {
    Connection,
    Event,
    Req,
    Count,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Principal {
    Ip(Vec<u8>),
    Pubkey([u8; 32]),
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

#[derive(Debug, Default)]
struct State {
    buckets: HashMap<(Principal, BudgetKind), Bucket>,
    checks: u64,
}

#[derive(Debug, Default)]
pub struct AbuseController {
    state: Mutex<State>,
}

impl AbuseController {
    pub fn admit_ip(&self, ip: &[u8], kind: BudgetKind, cfg: &AbuseConfig) -> bool {
        if !cfg.enabled || ip.is_empty() {
            return true;
        }
        let (rate, burst) = spec(kind, cfg);
        self.admit(Principal::Ip(ip.to_vec()), kind, rate, burst)
    }

    pub fn admit_pubkey(&self, pubkey: &[u8; 32], kind: BudgetKind, cfg: &AbuseConfig) -> bool {
        if !cfg.enabled {
            return true;
        }
        let (rate, burst) = match kind {
            BudgetKind::Event => (cfg.pubkey_event_rate_per_second, cfg.pubkey_event_burst),
            _ => spec(kind, cfg),
        };
        self.admit(Principal::Pubkey(*pubkey), kind, rate, burst)
    }

    fn admit(
        &self,
        principal: Principal,
        kind: BudgetKind,
        rate_per_second: u32,
        burst: u32,
    ) -> bool {
        if rate_per_second == 0 || burst == 0 {
            return true;
        }
        let now = Instant::now();
        let mut state = self.state.lock();
        state.checks = state.checks.wrapping_add(1);
        if state.checks.is_multiple_of(4096) {
            let stale_before = now.checked_sub(Duration::from_secs(600)).unwrap_or(now);
            state
                .buckets
                .retain(|_, bucket| bucket.last >= stale_before);
        }
        let bucket = state
            .buckets
            .entry((principal, kind))
            .or_insert_with(|| Bucket {
                tokens: burst as f64,
                last: now,
            });
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * rate_per_second as f64).min(burst as f64);
        bucket.last = now;
        if bucket.tokens < 1.0 {
            return false;
        }
        bucket.tokens -= 1.0;
        true
    }
}

fn spec(kind: BudgetKind, cfg: &AbuseConfig) -> (u32, u32) {
    match kind {
        BudgetKind::Connection => (cfg.connection_rate_per_second, cfg.connection_burst),
        BudgetKind::Event => (cfg.event_rate_per_second, cfg.event_burst),
        BudgetKind::Req => (cfg.req_rate_per_second, cfg.req_burst),
        BudgetKind::Count => (cfg.count_rate_per_second, cfg.count_burst),
    }
}

pub fn leading_zero_bits(bytes: &[u8]) -> u16 {
    let mut total = 0u16;
    for byte in bytes {
        if *byte == 0 {
            total += 8;
        } else {
            total += byte.leading_zeros() as u16;
            break;
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_bucket_enforces_distinct_command_budgets() {
        let mut cfg = crate::Config::default().relay.abuse;
        cfg.event_rate_per_second = 1;
        cfg.event_burst = 2;
        cfg.req_rate_per_second = 1;
        cfg.req_burst = 1;
        let limiter = AbuseController::default();
        assert!(limiter.admit_ip(&[127, 0, 0, 1], BudgetKind::Event, &cfg));
        assert!(limiter.admit_ip(&[127, 0, 0, 1], BudgetKind::Event, &cfg));
        assert!(!limiter.admit_ip(&[127, 0, 0, 1], BudgetKind::Event, &cfg));
        assert!(limiter.admit_ip(&[127, 0, 0, 1], BudgetKind::Req, &cfg));
        assert!(!limiter.admit_ip(&[127, 0, 0, 1], BudgetKind::Req, &cfg));
        cfg.pubkey_event_burst = 1;
        let pubkey = [7u8; 32];
        assert!(limiter.admit_pubkey(&pubkey, BudgetKind::Event, &cfg));
        assert!(!limiter.admit_pubkey(&pubkey, BudgetKind::Event, &cfg));
    }

    #[test]
    fn counts_leading_zero_bits() {
        assert_eq!(leading_zero_bits(&[0, 0, 0b0001_0000]), 19);
        assert_eq!(leading_zero_bits(&[0xff]), 0);
        assert_eq!(leading_zero_bits(&[]), 0);
    }
}
