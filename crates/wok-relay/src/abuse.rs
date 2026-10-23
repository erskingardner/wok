//! Relay-native token buckets and inexpensive admission checks.

use crate::config::AbuseConfig;
use crate::source::TransportSource;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BudgetKind {
    Connection,
    Event,
    Req,
    Count,
    /// Malformed messages, which earn an error reply and change nothing
    /// (#49).
    Invalid,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Principal {
    /// One IPv4 address.
    V4([u8; 4]),
    /// One IPv6 network: the address with every bit past
    /// `relay.abuse.ipv6_prefix_len` cleared. A host is usually given a
    /// whole /64, so keying the /128 would let it take a new budget with
    /// every address it picks from that network.
    V6([u8; 16]),
    Pubkey([u8; 32]),
}

impl Principal {
    fn address(ip: IpAddr, ipv6_prefix_len: u8) -> Self {
        match ip {
            IpAddr::V4(ip) => Self::V4(ip.octets()),
            IpAddr::V6(ip) => {
                let host_bits = 128 - u32::from(ipv6_prefix_len.min(128));
                let network = u128::MAX.checked_shl(host_bits).unwrap_or(0);
                Self::V6((u128::from(ip) & network).to_be_bytes())
            }
        }
    }
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
            TransportSource::Ip(ip) => Principal::address(*ip, cfg.ipv6_prefix_len),
            TransportSource::Unix => return Admission::Admitted,
        };
        let (rate, burst) = spec(kind, cfg);
        self.admit(principal, kind, rate, burst)
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
        BudgetKind::Invalid => (cfg.invalid_rate_per_second, cfg.invalid_burst),
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

    fn source(ip: &str) -> TransportSource {
        TransportSource::ip_address(ip.parse().unwrap())
    }

    #[test]
    fn token_bucket_enforces_distinct_command_budgets() {
        let mut cfg = crate::Config::default().relay.abuse;
        cfg.event_rate_per_second = 1;
        cfg.event_burst = 2;
        cfg.req_rate_per_second = 1;
        cfg.req_burst = 1;
        let limiter = AbuseController::default();
        let local = source("127.0.0.1");
        assert!(limiter.admit_source(&local, BudgetKind::Event, &cfg));
        assert!(limiter.admit_source(&local, BudgetKind::Event, &cfg));
        assert!(!limiter.admit_source(&local, BudgetKind::Event, &cfg));
        assert!(limiter.admit_source(&local, BudgetKind::Req, &cfg));
        assert!(!limiter.admit_source(&local, BudgetKind::Req, &cfg));
        cfg.pubkey_event_burst = 1;
        let pubkey = [7u8; 32];
        assert!(limiter.admit_pubkey(&pubkey, BudgetKind::Event, &cfg));
        assert!(!limiter.admit_pubkey(&pubkey, BudgetKind::Event, &cfg));
    }

    #[test]
    fn ipv6_sources_share_a_budget_per_configured_prefix() {
        let mut cfg = crate::Config::default().relay.abuse;
        assert_eq!(cfg.ipv6_prefix_len, 64);
        cfg.req_rate_per_second = 1;
        cfg.req_burst = 1;
        let limiter = AbuseController::default();
        let admit =
            |ip: &str, cfg: &AbuseConfig| limiter.admit_source(&source(ip), BudgetKind::Req, cfg);
        assert!(admit("2001:db8:1:2::1", &cfg));
        // Another address in the same /64 draws on the same bucket.
        assert!(!admit("2001:db8:1:2:ffff:ffff:ffff:ffff", &cfg));
        // The neighbouring /64 has its own.
        assert!(admit("2001:db8:1:3::1", &cfg));
        // IPv4 addresses are keyed one by one, and an IPv4-mapped IPv6 peer
        // is its IPv4 address.
        assert!(admit("192.0.2.1", &cfg));
        assert!(!admit("::ffff:192.0.2.1", &cfg));
        assert!(admit("192.0.2.2", &cfg));

        cfg.ipv6_prefix_len = 128;
        assert!(admit("2001:db8:5::1", &cfg));
        assert!(admit("2001:db8:5::2", &cfg));
        assert!(!admit("2001:db8:5::2", &cfg));
        cfg.ipv6_prefix_len = 48;
        assert!(admit("2001:db8:6:1::1", &cfg));
        assert!(!admit("2001:db8:6:ffff::1", &cfg));
        assert!(admit("2001:db8:7::1", &cfg));
    }

    #[test]
    fn address_principals_mask_ipv6_host_bits() {
        let ip: IpAddr = "2001:db8:aaaa:bbbb:cccc:dddd:eeee:ffff".parse().unwrap();
        let key = |prefix: u8| match Principal::address(ip, prefix) {
            Principal::V6(bytes) => std::net::Ipv6Addr::from(bytes).to_string(),
            other => panic!("{other:?}"),
        };
        assert_eq!(key(128), "2001:db8:aaaa:bbbb:cccc:dddd:eeee:ffff");
        assert_eq!(key(64), "2001:db8:aaaa:bbbb::");
        assert_eq!(key(56), "2001:db8:aaaa:bb00::");
        assert_eq!(key(1), "::");
        assert_eq!(key(0), "::");
    }

    #[test]
    fn only_the_first_refusal_of_an_exhausted_period_is_reported() {
        let mut cfg = crate::Config::default().relay.abuse;
        // One token per 100ms: slow enough that back-to-back checks under a
        // loaded test run do not refill in between.
        cfg.invalid_rate_per_second = 10;
        cfg.invalid_burst = 1;
        let limiter = AbuseController::default();
        let local = source("127.0.0.1");
        let admit = || limiter.admit_source_reporting(&local, BudgetKind::Invalid, &cfg);
        assert_eq!(admit(), Admission::Admitted);
        assert_eq!(admit(), Admission::FirstRefusal);
        assert_eq!(admit(), Admission::Refused);
        // After a refill the next exhausted period is reported again.
        std::thread::sleep(Duration::from_millis(120));
        assert_eq!(admit(), Admission::Admitted);
        assert_eq!(admit(), Admission::FirstRefusal);
        // Unix-socket clients are local and exempt.
        assert_eq!(
            limiter.admit_source_reporting(&TransportSource::Unix, BudgetKind::Invalid, &cfg),
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
