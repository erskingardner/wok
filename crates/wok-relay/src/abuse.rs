//! Relay-native token buckets and inexpensive admission checks.

use crate::config::AbuseConfig;
use crate::source::TransportSource;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
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
    /// Tokens taken and not yet refilled. Counting what was spent rather
    /// than what is left applies a changed burst at once, such as an AUTHed
    /// connection's larger one.
    spent: f64,
    last: Instant,
    /// A refusal was already reported since the last admission.
    refusal_reported: bool,
}

impl Bucket {
    fn new(now: Instant) -> Self {
        Self {
            spent: 0.0,
            last: now,
            refusal_reported: false,
        }
    }

    fn refill(&mut self, now: Instant, rate_per_second: u32) {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.spent = (self.spent - elapsed * f64::from(rate_per_second)).max(0.0);
        self.last = now;
    }

    fn has_token(&self, burst: u32) -> bool {
        self.spent + 1.0 <= f64::from(burst)
    }

    fn take(&mut self) {
        self.spent += 1.0;
        self.refusal_reported = false;
    }

    fn admit(&mut self, now: Instant, rate_per_second: u32, burst: u32) -> Admission {
        self.refill(now, rate_per_second);
        if !self.has_token(burst) {
            if self.refusal_reported {
                return Admission::Refused;
            }
            self.refusal_reported = true;
            return Admission::FirstRefusal;
        }
        self.take();
        Admission::Admitted
    }
}

/// A request that draws on its connection's own budget
/// (`relay.abuse.per_connection`) and on its address's backstop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    /// A REQ, including one that replaces a subscription, or a NEG-OPEN:
    /// each starts a scan.
    Req,
    /// A NEG-MSG round of a sync session already admitted by its NEG-OPEN.
    NegMsg,
    Count,
}

/// The budget that refused a [`Request`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The connection's own.
    Connection,
    /// The backstop every connection from its address shares.
    Address,
}

/// One connection's own budgets. The ingester that owns the connection
/// keeps them, so they take no lock and end with the connection.
#[derive(Debug, Default)]
pub struct ConnectionBudgets {
    req: Option<Bucket>,
    neg_msg: Option<Bucket>,
    count: Option<Bucket>,
}

#[derive(Debug, Default)]
struct State {
    buckets: HashMap<(Principal, BudgetKind), Bucket>,
    checks: u64,
}

/// The WebSocket connections each address holds open.
#[derive(Debug, Default)]
struct OpenConnections {
    /// By the address each connection came from.
    by_ip: HashMap<IpAddr, u32>,
    /// The same, summed by [`Principal`] under `ipv6_prefix_len`. The prefix
    /// reloads live, so this is rebuilt from `by_ip` when it changes, and the
    /// connections already open count under the new key.
    by_principal: HashMap<Principal, u32>,
    ipv6_prefix_len: u8,
}

impl OpenConnections {
    fn rekey(&mut self, ipv6_prefix_len: u8) {
        if self.ipv6_prefix_len == ipv6_prefix_len {
            return;
        }
        self.ipv6_prefix_len = ipv6_prefix_len;
        self.by_principal.clear();
        for (&ip, &count) in &self.by_ip {
            *self
                .by_principal
                .entry(Principal::address(ip, ipv6_prefix_len))
                .or_insert(0) += count;
        }
    }

    fn release(&mut self, ip: IpAddr) {
        decrement(&mut self.by_ip, &ip);
        decrement(
            &mut self.by_principal,
            &Principal::address(ip, self.ipv6_prefix_len),
        );
    }
}

/// Take one from `key`'s count, removing it at zero.
fn decrement<K: std::hash::Hash + Eq>(counts: &mut HashMap<K, u32>, key: &K) {
    if let Some(count) = counts.get_mut(key) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            counts.remove(key);
        }
    }
}

/// One connection counted against its address's
/// `relay.abuse.max_connections_per_address` until it drops.
#[derive(Debug)]
pub struct ConnectionSlot {
    held: Option<(Arc<Mutex<OpenConnections>>, IpAddr)>,
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        if let Some((open, ip)) = self.held.take() {
            open.lock().release(ip);
        }
    }
}

#[derive(Debug, Default)]
pub struct AbuseController {
    state: Mutex<State>,
    open: Arc<Mutex<OpenConnections>>,
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

    /// Count a connection from `source` until the returned slot drops, or
    /// `None`, counting nothing, when its address already holds
    /// `max_connections_per_address` of them. Connections are counted while
    /// the cap is off too, so turning it on counts those already open.
    /// Unix-socket connections carry no address and are not counted.
    pub fn hold_connection(
        &self,
        source: &TransportSource,
        cfg: &AbuseConfig,
    ) -> Option<ConnectionSlot> {
        let TransportSource::Ip(ip) = source else {
            return Some(ConnectionSlot { held: None });
        };
        let cap = if cfg.enabled {
            cfg.max_connections_per_address
        } else {
            0
        };
        let mut open = self.open.lock();
        open.rekey(cfg.ipv6_prefix_len);
        let count = open
            .by_principal
            .entry(Principal::address(*ip, cfg.ipv6_prefix_len))
            .or_insert(0);
        if cap != 0 && *count >= cap {
            return None;
        }
        *count += 1;
        *open.by_ip.entry(*ip).or_insert(0) += 1;
        Some(ConnectionSlot {
            held: Some((self.open.clone(), *ip)),
        })
    }

    /// Charge `request` to its connection's own budget, which is
    /// `authenticated_multiplier` times larger once the connection is
    /// AUTHed, and to its address's backstop, which is not. Neither is
    /// charged unless both admit, so a connection over its own budget does
    /// not spend its neighbours' share of the backstop. Unix-socket
    /// connections are local and exempt, as from every rate budget.
    pub fn admit_request(
        &self,
        budgets: &mut ConnectionBudgets,
        source: &TransportSource,
        request: Request,
        authenticated: bool,
        cfg: &AbuseConfig,
    ) -> Result<(), Refusal> {
        let TransportSource::Ip(ip) = source else {
            return Ok(());
        };
        if !cfg.enabled {
            return Ok(());
        }
        let own = &cfg.per_connection;
        let (rate, burst, slot, backstop) = match request {
            Request::Req => (
                own.req_rate_per_second,
                own.req_burst,
                &mut budgets.req,
                BudgetKind::Req,
            ),
            Request::NegMsg => (
                own.neg_msg_rate_per_second,
                own.neg_msg_burst,
                &mut budgets.neg_msg,
                BudgetKind::Req,
            ),
            Request::Count => (
                own.count_rate_per_second,
                own.count_burst,
                &mut budgets.count,
                BudgetKind::Count,
            ),
        };
        let multiplier = if authenticated {
            own.authenticated_multiplier
        } else {
            1
        };
        let (rate, burst) = (
            rate.saturating_mul(multiplier),
            burst.saturating_mul(multiplier),
        );
        let now = Instant::now();
        let bucket = (rate != 0 && burst != 0).then(|| {
            let bucket = slot.get_or_insert_with(|| Bucket::new(now));
            bucket.refill(now, rate);
            bucket
        });
        if bucket
            .as_ref()
            .is_some_and(|bucket| !bucket.has_token(burst))
        {
            return Err(Refusal::Connection);
        }
        let (backstop_rate, backstop_burst) = spec(backstop, cfg);
        let address = Principal::address(*ip, cfg.ipv6_prefix_len);
        if self.admit(address, backstop, backstop_rate, backstop_burst) != Admission::Admitted {
            return Err(Refusal::Address);
        }
        if let Some(bucket) = bucket {
            bucket.take();
        }
        Ok(())
    }

    /// Charge an event to a pubkey's budget (`pubkey_event_*`): its
    /// author's, or the AUTHed identity that published it from another key.
    pub fn admit_pubkey_event(&self, pubkey: &[u8; 32], cfg: &AbuseConfig) -> bool {
        if !cfg.enabled {
            return true;
        }
        let (rate, burst) = (cfg.pubkey_event_rate_per_second, cfg.pubkey_event_burst);
        self.admit(Principal::Pubkey(*pubkey), BudgetKind::Event, rate, burst)
            == Admission::Admitted
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
        state
            .buckets
            .entry((principal, kind))
            .or_insert_with(|| Bucket::new(now))
            .admit(now, rate_per_second, burst)
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
    fn marmot_accepts_an_add_member_burst_that_exceeds_public_capacity() {
        let public = crate::Config::default();
        let marmot = crate::Config::parse_toml(
            "preset = \"marmot\"\n[relay.auth]\nservice_url = \"wss://marmot.test\"\n",
        )
        .unwrap();
        let now = Instant::now();
        for (name, config, accepted) in [("public", public, 100), ("marmot", marmot, 251)] {
            assert!(config.relay.abuse.enabled);
            let (rate, burst) = spec(BudgetKind::Event, &config.relay.abuse);
            assert!(rate > 0 && burst > 0);
            let mut bucket = Bucket::new(now);
            // One commit plus 250 Welcomes at one instant: host speed cannot
            // refill the bucket between admission checks.
            for event in 0..251 {
                let expected = if event < accepted {
                    Admission::Admitted
                } else if event == accepted {
                    Admission::FirstRefusal
                } else {
                    Admission::Refused
                };
                assert_eq!(
                    bucket.admit(now, rate, burst),
                    expected,
                    "{name}: event {event}"
                );
            }
            // The same total spread over time is valid under both presets.
            // A sequential network publisher must not be expected to exhaust
            // the public bucket when each acknowledgement takes long enough.
            let mut bucket = Bucket::new(now);
            for event in 0..251 {
                assert_eq!(
                    bucket.admit(now + Duration::from_secs(event), rate, burst),
                    Admission::Admitted,
                    "{name}: spaced event {event}",
                );
            }
        }
    }

    #[test]
    fn an_address_holds_at_most_its_cap_of_connections() {
        let mut cfg = crate::Config::default().relay.abuse;
        cfg.max_connections_per_address = 2;
        let limiter = AbuseController::default();
        let first = limiter.hold_connection(&source("192.0.2.1"), &cfg);
        let second = limiter.hold_connection(&source("192.0.2.1"), &cfg);
        assert!(first.is_some() && second.is_some());
        assert!(limiter
            .hold_connection(&source("192.0.2.1"), &cfg)
            .is_none());
        // Another address, and the other end of the same /64, are keyed
        // like every per-address budget.
        assert!(limiter
            .hold_connection(&source("192.0.2.2"), &cfg)
            .is_some());
        let v6 = [
            limiter.hold_connection(&source("2001:db8:1:1::1"), &cfg),
            limiter.hold_connection(&source("2001:db8:1:1:ffff::2"), &cfg),
        ];
        assert!(v6.iter().all(Option::is_some));
        assert!(limiter
            .hold_connection(&source("2001:db8:1:1::3"), &cfg)
            .is_none());
        assert!(limiter
            .hold_connection(&source("2001:db8:1:2::1"), &cfg)
            .is_some());
        // A connection that ends gives its place back.
        drop(first);
        let third = limiter.hold_connection(&source("192.0.2.1"), &cfg);
        assert!(third.is_some());
        drop((second, third));
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let open = limiter.open.lock();
        assert!(!open.by_ip.contains_key(&ip));
        assert!(!open
            .by_principal
            .contains_key(&Principal::address(ip, cfg.ipv6_prefix_len)));
        drop(open);
        // Unix sockets are not counted.
        cfg.max_connections_per_address = 1;
        let unix: Vec<_> = (0..3)
            .map(|_| limiter.hold_connection(&TransportSource::Unix, &cfg))
            .collect();
        assert!(unix.iter().all(Option::is_some));
    }

    #[test]
    fn connections_are_counted_while_the_cap_is_off() {
        let mut cfg = crate::Config::default().relay.abuse;
        cfg.max_connections_per_address = 0;
        let limiter = AbuseController::default();
        let open: Vec<_> = (0..3)
            .map(|_| limiter.hold_connection(&source("192.0.2.1"), &cfg))
            .collect();
        assert!(open.iter().all(Option::is_some));
        cfg.max_connections_per_address = 3;
        cfg.enabled = false;
        assert!(limiter
            .hold_connection(&source("192.0.2.1"), &cfg)
            .is_some());
        cfg.enabled = true;
        assert!(limiter
            .hold_connection(&source("192.0.2.1"), &cfg)
            .is_none());
    }

    #[test]
    fn a_changed_ipv6_prefix_counts_the_connections_already_open() {
        let mut cfg = crate::Config::default().relay.abuse;
        cfg.max_connections_per_address = 2;
        cfg.ipv6_prefix_len = 128;
        let limiter = AbuseController::default();
        let held = [
            limiter.hold_connection(&source("2001:db8:1:1::1"), &cfg),
            limiter.hold_connection(&source("2001:db8:1:1::1"), &cfg),
        ];
        let other = limiter.hold_connection(&source("2001:db8:1:1::2"), &cfg);
        assert!(held.iter().chain([&other]).all(Option::is_some));
        // Widened to the /64, the network already holds three.
        cfg.ipv6_prefix_len = 64;
        assert!(limiter
            .hold_connection(&source("2001:db8:1:1::3"), &cfg)
            .is_none());
        // Narrowed again, each address counts its own.
        cfg.ipv6_prefix_len = 128;
        assert!(limiter
            .hold_connection(&source("2001:db8:1:1::1"), &cfg)
            .is_none());
        let third = limiter.hold_connection(&source("2001:db8:1:1::3"), &cfg);
        assert!(third.is_some());
        // Slots taken under one prefix are given back under another.
        cfg.ipv6_prefix_len = 64;
        drop((held, third));
        let fourth = limiter.hold_connection(&source("2001:db8:1:1::4"), &cfg);
        assert!(fourth.is_some());
        assert!(limiter
            .hold_connection(&source("2001:db8:1:1::5"), &cfg)
            .is_none());
        drop((other, fourth));
        let open = limiter.open.lock();
        assert!(open.by_ip.is_empty() && open.by_principal.is_empty());
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
        assert!(limiter.admit_pubkey_event(&pubkey, &cfg));
        assert!(!limiter.admit_pubkey_event(&pubkey, &cfg));
    }

    #[test]
    fn requests_draw_on_the_connection_and_its_address_backstop() {
        let mut cfg = crate::Config::default().relay.abuse;
        // One token a second: nothing refills between checks.
        cfg.req_rate_per_second = 1;
        cfg.req_burst = 3;
        cfg.per_connection.req_rate_per_second = 1;
        cfg.per_connection.req_burst = 2;
        cfg.per_connection.neg_msg_rate_per_second = 1;
        cfg.per_connection.neg_msg_burst = 1;
        let limiter = AbuseController::default();
        let local = source("192.0.2.1");
        let (mut first, mut second) = (ConnectionBudgets::default(), ConnectionBudgets::default());
        let admit = |budgets: &mut ConnectionBudgets, request, authed| {
            limiter.admit_request(budgets, &local, request, authed, &cfg)
        };
        assert_eq!(admit(&mut first, Request::Req, false), Ok(()));
        assert_eq!(admit(&mut first, Request::Req, false), Ok(()));
        // The connection's own budget refuses first, and its refusal leaves
        // the backstop's last token to the address's other connection.
        assert_eq!(
            admit(&mut first, Request::Req, false),
            Err(Refusal::Connection)
        );
        assert_eq!(admit(&mut second, Request::Req, false), Ok(()));
        assert_eq!(
            admit(&mut second, Request::Req, false),
            Err(Refusal::Address)
        );
        // NEG-MSG rounds have their own per-connection bucket but share the
        // address's REQ backstop.
        assert_eq!(
            admit(&mut second, Request::NegMsg, true),
            Err(Refusal::Address)
        );
        let other = source("198.51.100.1");
        let mut third = ConnectionBudgets::default();
        let admit = |budgets: &mut ConnectionBudgets, request, authed| {
            limiter.admit_request(budgets, &other, request, authed, &cfg)
        };
        assert_eq!(admit(&mut third, Request::NegMsg, false), Ok(()));
        assert_eq!(
            admit(&mut third, Request::NegMsg, false),
            Err(Refusal::Connection)
        );
        // AUTH multiplies the connection's bursts at once.
        assert_eq!(admit(&mut third, Request::NegMsg, true), Ok(()));
        assert_eq!(admit(&mut third, Request::Req, true), Ok(()));
        assert_eq!(
            admit(&mut third, Request::Req, true),
            Err(Refusal::Address),
            "the backstop is not multiplied"
        );
    }

    #[test]
    fn unix_connections_and_disabled_controls_skip_request_budgets() {
        let mut cfg = crate::Config::default().relay.abuse;
        cfg.per_connection.count_rate_per_second = 1;
        cfg.per_connection.count_burst = 1;
        let limiter = AbuseController::default();
        let mut budgets = ConnectionBudgets::default();
        for _ in 0..3 {
            assert_eq!(
                limiter.admit_request(
                    &mut budgets,
                    &TransportSource::Unix,
                    Request::Count,
                    false,
                    &cfg
                ),
                Ok(())
            );
        }
        let local = source("192.0.2.1");
        let mut admit = |cfg: &AbuseConfig| {
            limiter.admit_request(&mut budgets, &local, Request::Count, false, cfg)
        };
        assert_eq!(admit(&cfg), Ok(()));
        assert_eq!(admit(&cfg), Err(Refusal::Connection));
        cfg.enabled = false;
        assert_eq!(admit(&cfg), Ok(()));
        // A zero rate or burst turns the connection's bucket off.
        cfg.enabled = true;
        cfg.per_connection.count_burst = 0;
        assert_eq!(admit(&cfg), Ok(()));
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
