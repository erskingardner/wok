//! Relay-native token buckets and inexpensive admission checks.

use crate::config::AbuseConfig;
use crate::source::TransportSource;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BudgetKind {
    Connection,
    Event,
    Req,
    Count,
    /// Messages no command budget covers: malformed messages, CLOSE and
    /// NEG-CLOSE (#49).
    Control,
}

/// Outcome of a budget check that distinguishes the first refusal of an
/// exhausted period, so the relay can explain itself once and then stay
/// quiet until the bucket refills.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Admitted,
    FirstRefusal,
    Refused,
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
    /// A refusal was already reported since the last admission.
    refusal_reported: bool,
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
    pub fn admit_source(
        &self,
        source: &TransportSource,
        kind: BudgetKind,
        cfg: &AbuseConfig,
    ) -> bool {
        self.admit_source_reporting(source, kind, cfg) == Admission::Admitted
    }

    /// [`admit_source`](Self::admit_source), reporting whether a refusal is
    /// the first since the source was last admitted.
    pub fn admit_source_reporting(
        &self,
        source: &TransportSource,
        kind: BudgetKind,
        cfg: &AbuseConfig,
    ) -> Admission {
        if !cfg.enabled {
            return Admission::Admitted;
        }
        let principal = match source {
            TransportSource::Ip(ip) => Principal::Ip(match ip {
                std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
                std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
            }),
            TransportSource::Unix => return Admission::Admitted,
        };
        let (rate, burst) = spec(kind, cfg);
        self.admit(principal, kind, rate, burst)
    }

    pub fn admit_ip(&self, ip: &[u8], kind: BudgetKind, cfg: &AbuseConfig) -> bool {
        if !cfg.enabled || ip.is_empty() {
            return true;
        }
        let (rate, burst) = spec(kind, cfg);
        self.admit(Principal::Ip(ip.to_vec()), kind, rate, burst) == Admission::Admitted
    }

    pub fn admit_pubkey(&self, pubkey: &[u8; 32], kind: BudgetKind, cfg: &AbuseConfig) -> bool {
        if !cfg.enabled {
            return true;
        }
        let (rate, burst) = match kind {
            BudgetKind::Event => (cfg.pubkey_event_rate_per_second, cfg.pubkey_event_burst),
            _ => spec(kind, cfg),
        };
        self.admit(Principal::Pubkey(*pubkey), kind, rate, burst) == Admission::Admitted
    }

    fn admit(
        &self,
        principal: Principal,
        kind: BudgetKind,
        rate_per_second: u32,
        burst: u32,
    ) -> Admission {
        if rate_per_second == 0 || burst == 0 {
            return Admission::Admitted;
        }
        let now = Instant::now();
        let mut state = self.state.lock();
        state.checks = state.checks.wrapping_add(1);
        if state.checks % 4096 == 0 {
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
                refusal_reported: false,
            });
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * rate_per_second as f64).min(burst as f64);
        bucket.last = now;
        if bucket.tokens < 1.0 {
            if bucket.refusal_reported {
                return Admission::Refused;
            }
            bucket.refusal_reported = true;
            return Admission::FirstRefusal;
        }
        bucket.tokens -= 1.0;
        bucket.refusal_reported = false;
        Admission::Admitted
    }
}

fn spec(kind: BudgetKind, cfg: &AbuseConfig) -> (u32, u32) {
    match kind {
        BudgetKind::Connection => (cfg.connection_rate_per_second, cfg.connection_burst),
        BudgetKind::Event => (cfg.event_rate_per_second, cfg.event_burst),
        BudgetKind::Req => (cfg.req_rate_per_second, cfg.req_burst),
        BudgetKind::Count => (cfg.count_rate_per_second, cfg.count_burst),
        BudgetKind::Control => (cfg.control_rate_per_second, cfg.control_burst),
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
    fn only_the_first_refusal_of_an_exhausted_period_is_reported() {
        let mut cfg = crate::Config::default().relay.abuse;
        // One token per 100ms: slow enough that back-to-back checks under a
        // loaded test run do not refill in between.
        cfg.control_rate_per_second = 10;
        cfg.control_burst = 1;
        let limiter = AbuseController::default();
        let source = TransportSource::ip_address("127.0.0.1".parse().unwrap());
        let admit = || limiter.admit_source_reporting(&source, BudgetKind::Control, &cfg);
        assert_eq!(admit(), Admission::Admitted);
        assert_eq!(admit(), Admission::FirstRefusal);
        assert_eq!(admit(), Admission::Refused);
        // After a refill the next exhausted period is reported again.
        std::thread::sleep(Duration::from_millis(120));
        assert_eq!(admit(), Admission::Admitted);
        assert_eq!(admit(), Admission::FirstRefusal);
        // Unix-socket clients are local and exempt.
        assert_eq!(
            limiter.admit_source_reporting(&TransportSource::Unix, BudgetKind::Control, &cfg),
            Admission::Admitted
        );
    }

    #[test]
    fn counts_leading_zero_bits() {
        assert_eq!(leading_zero_bits(&[0, 0, 0b0001_0000]), 19);
        assert_eq!(leading_zero_bits(&[0xff]), 0);
        assert_eq!(leading_zero_bits(&[]), 0);
    }
}
