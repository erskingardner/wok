use parking_lot::Mutex;
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const MAX_HISTORY_POINTS: usize = 100_000;

/// Declares [`Setting`] from its variants and config keys, so the two
/// cannot drift apart.
macro_rules! settings {
    ($($(#[$doc:meta])* $variant:ident => $key:literal,)+) => {
        /// A setting that refuses requests or events, named in
        /// `wok_refusals_total{setting}` by its config key. A token bucket's
        /// refusals are labelled with its burst, how much may be sent at
        /// once, as rate and burst run out together.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum Setting {
            $($(#[$doc])* $variant,)+
        }

        impl Setting {
            /// Every setting, in the order `/metrics` lists them.
            pub const ALL: &'static [Setting] = &[$(Setting::$variant,)+];

            /// The config key, such as `relay.abuse.event_burst`.
            pub fn key(self) -> &'static str {
                match self {
                    $(Setting::$variant => $key,)+
                }
            }
        }
    };
}

settings! {
    // Connections.
    ConnectionBurst => "relay.abuse.connection_burst",
    /// WebSocket upgrades from an address that holds the most connections
    /// it may keep open.
    MaxConnectionsPerAddress => "relay.abuse.max_connections_per_address",
    // Events.
    /// Per-address EVENT and AUTH budget.
    EventBurst => "relay.abuse.event_burst",
    /// Per-author EVENT budget, charged to the AUTHed identity for events
    /// from other keys.
    PubkeyEventBurst => "relay.abuse.pubkey_event_burst",
    MaxEventSize => "events.max_event_size",
    MaxNumTags => "events.max_num_tags",
    MaxTagValSize => "events.max_tag_val_size",
    RejectOlderThan => "events.reject_older_than_secs",
    RejectNewerThan => "events.reject_newer_than_secs",
    RejectEphemeralOlderThan => "events.reject_ephemeral_older_than_secs",
    MinPowDifficulty => "relay.abuse.min_pow_difficulty",
    /// AUTH while NIP-42 is off.
    AuthEnabled => "relay.auth.enabled",
    /// AUTH before the relay URL it must name is set.
    AuthServiceUrl => "relay.auth.service_url",
    AcceptedKinds => "relay.auth.accepted_kinds",
    WritePolicy => "relay.auth.write_policy",
    /// Writes of an owner-only kind from anyone but its author, and reads of
    /// one not scoped to the reader.
    OwnerOnlyKinds => "relay.auth.owner_only_kinds",
    /// A vanish request while NIP-62 is off.
    Nip62Enabled => "relay.nip62.enabled",
    /// The write-policy plugin's rejections, shadow rejections included.
    WritePolicyPlugin => "relay.write_policy_plugin",
    MaxStoredEvents => "relay.abuse.max_stored_events",
    MaxStoredEventsPerPubkey => "relay.abuse.max_stored_events_per_pubkey",
    MinFreeDiskBytes => "database.min_free_disk_bytes",
    // Requests.
    /// A connection's REQ and NEG-OPEN budget.
    PerConnectionReqBurst => "relay.abuse.per_connection.req_burst",
    PerConnectionNegMsgBurst => "relay.abuse.per_connection.neg_msg_burst",
    PerConnectionCountBurst => "relay.abuse.per_connection.count_burst",
    /// The per-address backstop for REQ, NEG-OPEN and NEG-MSG.
    ReqBurst => "relay.abuse.req_burst",
    /// The per-address backstop for COUNT.
    CountBurst => "relay.abuse.count_burst",
    /// Malformed messages past the budget: the first gets one NOTICE, the
    /// rest no reply.
    InvalidBurst => "relay.abuse.invalid_burst",
    MaxFiltersPerReq => "relay.max_filters_per_req",
    MaxReqFilterSize => "relay.max_req_filter_size",
    /// COUNT while `max_filter_limit_count = 0` turns it off.
    MaxFilterLimitCount => "relay.max_filter_limit_count",
    /// A REQ, COUNT or NEG-OPEN with a `search` filter while NIP-50 is off.
    SearchEnabled => "relay.search_enabled",
    MaxTagsPerFilter => "relay.max_tags_per_filter",
    MaxAndEntries => "relay.max_and_entries",
    MaxKindsPerFilter => "relay.filter_validation.max_kinds_per_filter",
    AllowedKinds => "relay.filter_validation.allowed_kinds",
    RequireAuthorOrTag => "relay.filter_validation.require_author_or_tag",
    RequireScopedFilters => "relay.filter_validation.require_scoped_filters",
    MaxQueryWork => "relay.abuse.max_query_work",
    ReadPolicy => "relay.auth.read_policy",
    /// Reads of a recipient-only kind not scoped to the reader.
    RecipientOnlyKinds => "relay.auth.recipient_only_kinds",
    /// Reads of an authenticated-only kind before AUTH.
    AuthenticatedKinds => "relay.auth.authenticated_kinds",
    /// New subscriptions over the cap, and queries or sync sessions over the
    /// queue it bounds.
    MaxSubsPerConnection => "relay.max_subs_per_connection",
    MaxFilterBytesPerConnection => "relay.max_filter_bytes_per_connection",
    /// Queries while `max_concurrent_historical_queries = 0` runs none.
    MaxConcurrentHistoricalQueries => "relay.abuse.max_concurrent_historical_queries",
    NegentropyEnabled => "relay.negentropy_enabled",
    MaxSyncEvents => "relay.max_sync_events",
    SyncMemoryPerConnection => "relay.sync_memory_per_connection",
    SyncMemoryTotal => "relay.sync_memory_total",
}

impl Setting {
    /// The setting behind a [`wok_query::FilterLimit`].
    pub fn of_filter_limit(limit: wok_query::FilterLimit) -> Self {
        use wok_query::FilterLimit;
        match limit {
            FilterLimit::TagsPerFilter => Self::MaxTagsPerFilter,
            FilterLimit::AndEntries => Self::MaxAndEntries,
            FilterLimit::KindsPerFilter => Self::MaxKindsPerFilter,
            FilterLimit::AllowedKinds => Self::AllowedKinds,
            FilterLimit::AuthorOrTag => Self::RequireAuthorOrTag,
            FilterLimit::ScopedFilters => Self::RequireScopedFilters,
        }
    }

    /// The read class setting behind a read refused to a reader the filters
    /// are not scoped to.
    pub fn of_read_class(class: crate::restrict::ReadClass) -> Option<Self> {
        use crate::restrict::ReadClass;
        match class {
            ReadClass::Open => None,
            ReadClass::Authenticated => Some(Self::AuthenticatedKinds),
            ReadClass::Recipient => Some(Self::RecipientOnlyKinds),
            ReadClass::Owner => Some(Self::OwnerOnlyKinds),
        }
    }
}

/// How far back [`Refusals::recent`] reaches, and how often it keeps a mark.
pub const REFUSAL_WINDOW_SECS: u64 = 24 * 3600;
const REFUSAL_MARK_SECS: u64 = 3600;

type RefusalCounts = [u64; Setting::ALL.len()];

/// `wok_refusals_total`: what each [`Setting`] refused since start, and
/// hourly marks of those counts for the dashboard's last day.
pub struct Refusals {
    counts: [AtomicU64; Setting::ALL.len()],
    marks: Mutex<VecDeque<(u64, RefusalCounts)>>,
}

impl Default for Refusals {
    fn default() -> Self {
        Self {
            counts: std::array::from_fn(|_| AtomicU64::new(0)),
            marks: Mutex::default(),
        }
    }
}

impl Refusals {
    pub fn add(&self, setting: Setting, n: u64) {
        self.counts[setting as usize].fetch_add(n, Ordering::Relaxed);
    }

    pub fn get(&self, setting: Setting) -> u64 {
        self.counts[setting as usize].load(Ordering::Relaxed)
    }

    /// Every setting's count, in [`Setting::ALL`] order.
    pub fn counts(&self) -> impl Iterator<Item = (Setting, u64)> + '_ {
        Setting::ALL
            .iter()
            .map(|&setting| (setting, self.get(setting)))
    }

    /// Drop the marks older than [`REFUSAL_WINDOW_SECS`], and keep one of
    /// the counts at `now` if the last is an hour old. Called at least once
    /// a minute, so the oldest mark is 23 to 24 hours old once the relay has
    /// run a day.
    pub fn mark(&self, now: u64) {
        let mut marks = self.marks.lock();
        while marks
            .front()
            .is_some_and(|(at, _)| at.saturating_add(REFUSAL_WINDOW_SECS) < now)
        {
            marks.pop_front();
        }
        if marks
            .back()
            .is_some_and(|(at, _)| now < at.saturating_add(REFUSAL_MARK_SECS))
        {
            return;
        }
        marks.push_back((now, std::array::from_fn(|i| self.get(Setting::ALL[i]))));
    }

    /// What each setting refused since the oldest mark of the last day, and
    /// when that mark was kept: the last day, less up to an hour, once the
    /// relay has run that long. `None` before the first mark.
    pub fn recent(&self) -> Option<(u64, Vec<(Setting, u64)>)> {
        let marks = self.marks.lock();
        let (since, base) = marks.front()?;
        let counts = self
            .counts()
            .zip(base)
            .map(|((setting, count), base)| (setting, count.saturating_sub(*base)))
            .collect();
        Some((*since, counts))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricsSnapshot {
    pub timestamp: u64,
    pub active_connections: u64,
    pub authenticated_connections: u64,
    pub written_events_total: u64,
    pub ephemeral_events_total: u64,
    pub rejected_events_total: u64,
    pub client_messages_total: u64,
    pub relay_messages_total: u64,
    pub abuse_rejections_total: u64,
}

pub struct MetricsHistory {
    enabled: AtomicBool,
    max_points: AtomicU64,
    points: Mutex<VecDeque<MetricsSnapshot>>,
}

impl Default for MetricsHistory {
    fn default() -> Self {
        Self {
            enabled: AtomicBool::new(true),
            max_points: AtomicU64::new(5_760),
            points: Mutex::new(VecDeque::new()),
        }
    }
}

impl MetricsHistory {
    pub fn configure(&self, enabled: bool, max_points: usize) {
        let max_points = max_points.min(MAX_HISTORY_POINTS);
        self.enabled.store(enabled, Ordering::Relaxed);
        self.max_points
            .store(max_points.try_into().unwrap_or(u64::MAX), Ordering::Relaxed);
        let mut points = self.points.lock();
        while points.len() > max_points {
            points.pop_front();
        }
        if !enabled || max_points == 0 {
            points.clear();
        }
    }

    fn push(&self, snapshot: MetricsSnapshot) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        let maximum = self.max_points.load(Ordering::Relaxed) as usize;
        if maximum == 0 {
            return;
        }
        let mut points = self.points.lock();
        while points.len() >= maximum {
            points.pop_front();
        }
        points.push_back(snapshot);
    }

    pub fn snapshots(&self) -> Vec<MetricsSnapshot> {
        self.points.lock().iter().cloned().collect()
    }
}

/// Upper bounds, in microseconds, of a [`DurationHistogram`]'s buckets.
const DURATION_BOUNDS_US: [u64; 15] = [
    50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000,
    1_000_000, 2_500_000,
];
/// Upper bounds of a [`CountHistogram`]'s buckets.
const COUNT_BOUNDS: [u64; 17] = [
    1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1_024, 2_048, 4_096, 8_192, 16_384, 32_768, 65_536,
];

/// A Prometheus histogram over fixed bucket bounds. Observations are whole
/// units; `/metrics` shows them divided by `scale`.
struct Histogram {
    bounds: &'static [u64],
    scale: f64,
    /// Observations per bucket, not cumulative, then those above every bound.
    counts: Box<[AtomicU64]>,
    sum: AtomicU64,
}

impl Histogram {
    fn new(bounds: &'static [u64], scale: f64) -> Self {
        Self {
            bounds,
            scale,
            counts: (0..=bounds.len()).map(|_| AtomicU64::new(0)).collect(),
            sum: AtomicU64::new(0),
        }
    }

    fn observe(&self, value: u64) {
        let bucket = self.bounds.partition_point(|&bound| bound < value);
        self.counts[bucket].fetch_add(1, Ordering::Relaxed);
        self.sum.fetch_add(value, Ordering::Relaxed);
    }

    fn count(&self) -> u64 {
        self.counts.iter().map(|n| n.load(Ordering::Relaxed)).sum()
    }

    fn render(&self, out: &mut String, name: &str, help: &str) {
        out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} histogram\n"));
        let mut cumulative = 0;
        for (bound, count) in self.bounds.iter().zip(self.counts.iter()) {
            cumulative += count.load(Ordering::Relaxed);
            let le = *bound as f64 / self.scale;
            out.push_str(&format!("{name}_bucket{{le=\"{le}\"}} {cumulative}\n"));
        }
        cumulative += self.counts[self.bounds.len()].load(Ordering::Relaxed);
        let sum = self.sum.load(Ordering::Relaxed) as f64 / self.scale;
        out.push_str(&format!(
            "{name}_bucket{{le=\"+Inf\"}} {cumulative}\n{name}_sum {sum}\n{name}_count {cumulative}\n"
        ));
    }
}

/// Durations, observed in microseconds and shown in seconds.
pub struct DurationHistogram(Histogram);

impl Default for DurationHistogram {
    fn default() -> Self {
        Self(Histogram::new(&DURATION_BOUNDS_US, 1e6))
    }
}

impl DurationHistogram {
    pub fn observe(&self, elapsed: Duration) {
        self.0
            .observe(u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX));
    }

    pub fn count(&self) -> u64 {
        self.0.count()
    }
}

/// Counts, such as events per batch.
pub struct CountHistogram(Histogram);

impl Default for CountHistogram {
    fn default() -> Self {
        Self(Histogram::new(&COUNT_BOUNDS, 1.0))
    }
}

impl CountHistogram {
    pub fn observe(&self, n: u64) {
        self.0.observe(n);
    }

    pub fn count(&self) -> u64 {
        self.0.count()
    }

    pub fn sum(&self) -> u64 {
        self.0.sum.load(Ordering::Relaxed)
    }
}

#[derive(Default)]
pub struct Metrics {
    pub active_connections: AtomicU64,
    pub authenticated_connections: AtomicU64,
    pub written_events_total: AtomicU64,
    pub ephemeral_events_total: AtomicU64,
    /// Subscriptions whose stored matches outgrew the live buffer during
    /// their history scan and were re-read from the database.
    pub live_buffer_overflows: AtomicU64,
    /// Ephemeral matches dropped from a full live buffer.
    pub live_buffer_dropped_ephemeral: AtomicU64,
    pub dup_events_total: AtomicU64,
    pub rejected_events_total: AtomicU64,
    pub auth_challenges_sent_total: AtomicU64,
    pub auth_success_total: AtomicU64,
    pub auth_failure_total: AtomicU64,
    pub slow_client_terminations: AtomicU64,
    /// Requests whose `relay.real_ip_header` named no address where the
    /// client's should be, so the connecting address stood in for it.
    pub real_ip_header_unparsed: AtomicU64,
    pub abuse_connection_rejections: AtomicU64,
    pub abuse_event_rate_rejections: AtomicU64,
    pub abuse_req_rate_rejections: AtomicU64,
    pub abuse_count_rate_rejections: AtomicU64,
    pub abuse_invalid_rate_rejections: AtomicU64,
    pub abuse_pow_rejections: AtomicU64,
    pub abuse_query_cost_rejections: AtomicU64,
    pub abuse_query_concurrency_rejections: AtomicU64,
    pub abuse_pubkey_quota_rejections: AtomicU64,
    pub abuse_global_quota_rejections: AtomicU64,
    pub abuse_disk_reserve_rejections: AtomicU64,
    pub moderation_banned_event_rejections: AtomicU64,
    pub moderation_banned_author_rejections: AtomicU64,
    pub moderation_restricted_write_rejections: AtomicU64,
    pub moderation_kind_rejections: AtomicU64,
    /// Refusals by the setting that made them. The `abuse_*_rejections`
    /// counters above count some of the same refusals for one more release.
    pub refusals: Refusals,
    pub client_event: AtomicU64,
    pub client_req: AtomicU64,
    pub client_count: AtomicU64,
    pub client_close: AtomicU64,
    pub client_auth: AtomicU64,
    pub relay_event: AtomicU64,
    pub relay_eose: AtomicU64,
    pub relay_ok: AtomicU64,
    pub relay_notice: AtomicU64,
    pub relay_closed: AtomicU64,
    /// Where the `(tag, kind, created_at)` index stood when the writer last
    /// looked: 1 once every stored event has its entries.
    pub tag_kind_index_complete: AtomicU64,
    pub tag_kind_indexed_through: AtomicU64,
    pub tag_kind_high_water: AtomicU64,
    /// `Event__tag` entries the key-ordered build has visited, 0 when none
    /// runs, and the entries stored.
    pub tag_kind_pass_visited: AtomicU64,
    pub tag_kind_tag_entries: AtomicU64,
    /// Postings the writer's background backfill put, and the time its
    /// transactions took.
    pub tag_kind_backfill_entries_total: AtomicU64,
    pub tag_kind_backfill_micros_total: AtomicU64,
    /// Each writer batch that commits events: the messages queued when it
    /// started, the events it commits, and how long each step took.
    pub writer_queue_depth: CountHistogram,
    pub writer_commit_events: CountHistogram,
    pub writer_prepare: DurationHistogram,
    pub writer_write: DurationHistogram,
    pub writer_commit: DurationHistogram,
    pub writer_reply: DurationHistogram,
    /// Bytes the writer's event transactions sent to storage, where the OS
    /// reports it.
    pub writer_storage_bytes_total: AtomicU64,
    pub history: MetricsHistory,
}

impl Metrics {
    pub fn snapshot(&self) -> MetricsSnapshot {
        let g = |n: &AtomicU64| n.load(Ordering::Relaxed);
        MetricsSnapshot {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            active_connections: g(&self.active_connections),
            authenticated_connections: g(&self.authenticated_connections),
            written_events_total: g(&self.written_events_total),
            ephemeral_events_total: g(&self.ephemeral_events_total),
            rejected_events_total: g(&self.rejected_events_total),
            client_messages_total: g(&self.client_event)
                + g(&self.client_req)
                + g(&self.client_count)
                + g(&self.client_close)
                + g(&self.client_auth),
            relay_messages_total: g(&self.relay_event)
                + g(&self.relay_eose)
                + g(&self.relay_ok)
                + g(&self.relay_notice)
                + g(&self.relay_closed),
            abuse_rejections_total: g(&self.abuse_connection_rejections)
                + g(&self.abuse_event_rate_rejections)
                + g(&self.abuse_req_rate_rejections)
                + g(&self.abuse_count_rate_rejections)
                + g(&self.abuse_invalid_rate_rejections)
                + g(&self.abuse_pow_rejections)
                + g(&self.abuse_query_cost_rejections)
                + g(&self.abuse_query_concurrency_rejections)
                + g(&self.abuse_pubkey_quota_rejections)
                + g(&self.abuse_global_quota_rejections)
                + g(&self.abuse_disk_reserve_rejections),
        }
    }

    /// Count one refusal by `setting`.
    pub fn refused(&self, setting: Setting) {
        self.refusals.add(setting, 1);
    }

    pub fn record_history(&self) {
        self.history.push(self.snapshot());
    }

    pub fn history_json(&self) -> serde_json::Value {
        serde_json::json!({
            "current": self.snapshot(),
            "points": self.history.snapshots(),
        })
    }

    pub fn render(&self) -> String {
        let g = |n: &AtomicU64| n.load(Ordering::Relaxed);
        let mut out = format!(
            concat!(
                "# HELP wok_active_connections Current WebSocket/Unix connections\n",
                "# TYPE wok_active_connections gauge\n",
                "wok_active_connections {}\n",
                "# TYPE wok_authenticated_connections gauge\n",
                "wok_authenticated_connections {}\n",
                "# TYPE wok_written_events_total counter\n",
                "wok_written_events_total {}\n",
                "# TYPE wok_ephemeral_events_total counter\n",
                "wok_ephemeral_events_total {}\n",
                "# TYPE wok_live_buffer_overflows_total counter\n",
                "wok_live_buffer_overflows_total {}\n",
                "# TYPE wok_live_buffer_dropped_ephemeral_total counter\n",
                "wok_live_buffer_dropped_ephemeral_total {}\n",
                "# TYPE wok_dup_events_total counter\n",
                "wok_dup_events_total {}\n",
                "# TYPE wok_rejected_events_total counter\n",
                "wok_rejected_events_total {}\n",
                "# TYPE wok_auth_challenges_sent_total counter\n",
                "wok_auth_challenges_sent_total {}\n",
                "# TYPE wok_auth_success_total counter\n",
                "wok_auth_success_total {}\n",
                "# TYPE wok_auth_failure_total counter\n",
                "wok_auth_failure_total {}\n",
                "# TYPE wok_slow_client_terminations_total counter\n",
                "wok_slow_client_terminations_total {}\n",
                "# TYPE wok_real_ip_header_unparsed_total counter\n",
                "wok_real_ip_header_unparsed_total {}\n",
                "# TYPE wok_abuse_rejections_total counter\n",
                "wok_abuse_rejections_total{{reason=\"connection_rate\"}} {}\n",
                "wok_abuse_rejections_total{{reason=\"event_rate\"}} {}\n",
                "wok_abuse_rejections_total{{reason=\"req_rate\"}} {}\n",
                "wok_abuse_rejections_total{{reason=\"count_rate\"}} {}\n",
                "wok_abuse_rejections_total{{reason=\"invalid_rate\"}} {}\n",
                "wok_abuse_rejections_total{{reason=\"pow\"}} {}\n",
                "wok_abuse_rejections_total{{reason=\"query_cost\"}} {}\n",
                "wok_abuse_rejections_total{{reason=\"query_concurrency\"}} {}\n",
                "wok_abuse_rejections_total{{reason=\"pubkey_storage_quota\"}} {}\n",
                "wok_abuse_rejections_total{{reason=\"global_storage_quota\"}} {}\n",
                "wok_abuse_rejections_total{{reason=\"disk_reserve\"}} {}\n",
                "# TYPE wok_moderation_rejections_total counter\n",
                "wok_moderation_rejections_total{{reason=\"banned_event\"}} {}\n",
                "wok_moderation_rejections_total{{reason=\"banned_author\"}} {}\n",
                "wok_moderation_rejections_total{{reason=\"restricted_writes\"}} {}\n",
                "wok_moderation_rejections_total{{reason=\"kind_not_allowed\"}} {}\n",
                "# TYPE wok_client_messages_total counter\n",
                "wok_client_messages_total{{type=\"EVENT\"}} {}\n",
                "wok_client_messages_total{{type=\"REQ\"}} {}\n",
                "wok_client_messages_total{{type=\"COUNT\"}} {}\n",
                "wok_client_messages_total{{type=\"CLOSE\"}} {}\n",
                "wok_client_messages_total{{type=\"AUTH\"}} {}\n",
                "# TYPE wok_relay_messages_total counter\n",
                "wok_relay_messages_total{{type=\"EVENT\"}} {}\n",
                "wok_relay_messages_total{{type=\"EOSE\"}} {}\n",
                "wok_relay_messages_total{{type=\"OK\"}} {}\n",
                "wok_relay_messages_total{{type=\"NOTICE\"}} {}\n",
                "wok_relay_messages_total{{type=\"CLOSED\"}} {}\n",
                "# HELP wok_tag_kind_index_complete 1 once every stored event is in the (tag, kind, created_at) index\n",
                "# TYPE wok_tag_kind_index_complete gauge\n",
                "wok_tag_kind_index_complete {}\n",
                "# TYPE wok_tag_kind_index_indexed_through gauge\n",
                "wok_tag_kind_index_indexed_through {}\n",
                "# TYPE wok_tag_kind_index_high_water gauge\n",
                "wok_tag_kind_index_high_water {}\n",
                "# TYPE wok_tag_kind_index_pass_visited gauge\n",
                "wok_tag_kind_index_pass_visited {}\n",
                "# TYPE wok_tag_kind_index_tag_entries gauge\n",
                "wok_tag_kind_index_tag_entries {}\n",
                "# TYPE wok_tag_kind_backfill_entries_total counter\n",
                "wok_tag_kind_backfill_entries_total {}\n",
                "# TYPE wok_tag_kind_backfill_seconds_total counter\n",
                "wok_tag_kind_backfill_seconds_total {}\n",
            ),
            g(&self.active_connections),
            g(&self.authenticated_connections),
            g(&self.written_events_total),
            g(&self.ephemeral_events_total),
            g(&self.live_buffer_overflows),
            g(&self.live_buffer_dropped_ephemeral),
            g(&self.dup_events_total),
            g(&self.rejected_events_total),
            g(&self.auth_challenges_sent_total),
            g(&self.auth_success_total),
            g(&self.auth_failure_total),
            g(&self.slow_client_terminations),
            g(&self.real_ip_header_unparsed),
            g(&self.abuse_connection_rejections),
            g(&self.abuse_event_rate_rejections),
            g(&self.abuse_req_rate_rejections),
            g(&self.abuse_count_rate_rejections),
            g(&self.abuse_invalid_rate_rejections),
            g(&self.abuse_pow_rejections),
            g(&self.abuse_query_cost_rejections),
            g(&self.abuse_query_concurrency_rejections),
            g(&self.abuse_pubkey_quota_rejections),
            g(&self.abuse_global_quota_rejections),
            g(&self.abuse_disk_reserve_rejections),
            g(&self.moderation_banned_event_rejections),
            g(&self.moderation_banned_author_rejections),
            g(&self.moderation_restricted_write_rejections),
            g(&self.moderation_kind_rejections),
            g(&self.client_event),
            g(&self.client_req),
            g(&self.client_count),
            g(&self.client_close),
            g(&self.client_auth),
            g(&self.relay_event),
            g(&self.relay_eose),
            g(&self.relay_ok),
            g(&self.relay_notice),
            g(&self.relay_closed),
            g(&self.tag_kind_index_complete),
            g(&self.tag_kind_indexed_through),
            g(&self.tag_kind_high_water),
            g(&self.tag_kind_pass_visited),
            g(&self.tag_kind_tag_entries),
            g(&self.tag_kind_backfill_entries_total),
            g(&self.tag_kind_backfill_micros_total) as f64 / 1e6,
        );
        self.writer_queue_depth.0.render(
            &mut out,
            "wok_writer_queue_depth",
            "Messages queued for the writer when it started a batch that commits events, the first included",
        );
        self.writer_commit_events.0.render(
            &mut out,
            "wok_writer_commit_events",
            "Events in each writer commit",
        );
        self.writer_prepare.0.render(
            &mut out,
            "wok_writer_prepare_seconds",
            "From the start of a writer batch to its write transaction: management commands, maintenance and per-event checks",
        );
        self.writer_write.0.render(
            &mut out,
            "wok_writer_write_seconds",
            "Writing a batch's events and index entries, before the commit",
        );
        self.writer_commit.0.render(
            &mut out,
            "wok_writer_commit_seconds",
            "Committing a batch, flushes to storage included",
        );
        self.writer_reply.0.render(
            &mut out,
            "wok_writer_reply_seconds",
            "Sending a committed batch's OKs and handing its events to the req monitors",
        );
        out.push_str(&format!(
            concat!(
                "# HELP wok_writer_storage_bytes_total Bytes the writer's event transactions sent to storage (Linux only)\n",
                "# TYPE wok_writer_storage_bytes_total counter\n",
                "wok_writer_storage_bytes_total {}\n",
            ),
            g(&self.writer_storage_bytes_total),
        ));
        out.push_str(concat!(
            "# HELP wok_refusals_total Requests and events refused, by the config key that refused them\n",
            "# TYPE wok_refusals_total counter\n",
        ));
        for (setting, count) in self.refusals.counts() {
            out.push_str(&format!(
                "wok_refusals_total{{setting=\"{}\"}} {count}\n",
                setting.key()
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusals_are_labelled_by_real_config_keys() {
        let keys: std::collections::HashSet<String> = crate::Config::explain_toml("")
            .unwrap()
            .entries
            .into_iter()
            .map(|entry| entry.key)
            .collect();
        let metrics = Metrics::default();
        metrics.refused(Setting::MaxQueryWork);
        metrics.refusals.add(Setting::MinFreeDiskBytes, 3);
        let rendered = metrics.render();
        let mut seen = std::collections::HashSet::new();
        for &setting in Setting::ALL {
            assert!(keys.contains(setting.key()), "{}", setting.key());
            assert!(seen.insert(setting.key()), "{} twice", setting.key());
            let count = match setting {
                Setting::MaxQueryWork => 1,
                Setting::MinFreeDiskBytes => 3,
                _ => 0,
            };
            let line = format!(
                "\nwok_refusals_total{{setting=\"{}\"}} {count}\n",
                setting.key()
            );
            assert!(rendered.contains(&line), "{line}");
        }
    }

    #[test]
    fn recent_refusals_cover_the_last_day() {
        let refusals = Refusals::default();
        assert_eq!(refusals.recent(), None);
        let count = |recent: Option<(u64, Vec<(Setting, u64)>)>| {
            let (since, counts) = recent.unwrap();
            let (_, n) = counts
                .into_iter()
                .find(|(setting, _)| *setting == Setting::MaxQueryWork)
                .unwrap();
            (since, n)
        };
        let start = 1_000_000;
        refusals.add(Setting::MaxQueryWork, 5);
        refusals.mark(start);
        refusals.add(Setting::MaxQueryWork, 2);
        assert_eq!(count(refusals.recent()), (start, 2));
        // Marks are hourly.
        refusals.mark(start + 60);
        assert_eq!(refusals.marks.lock().len(), 1);
        for hour in 1..=24 {
            refusals.add(Setting::MaxQueryWork, 1);
            refusals.mark(start + hour * 3600);
        }
        // The first mark is a day old and kept; the next hour drops it.
        assert_eq!(count(refusals.recent()), (start, 26));
        refusals.mark(start + 25 * 3600);
        assert_eq!(count(refusals.recent()), (start + 3600, 23));
    }

    #[test]
    fn the_refusal_window_stays_within_the_last_day() {
        // Marked each minute, as the history thread does whatever its
        // chart interval, for 30 hours.
        let refusals = Refusals::default();
        let start = 1_000_000;
        for minute in 0..30 * 60 {
            let now = start + minute * 60;
            refusals.add(Setting::MaxQueryWork, 1);
            refusals.mark(now);
            let (since, counts) = refusals.recent().unwrap();
            let age = now - since;
            if now - start >= REFUSAL_WINDOW_SECS {
                assert!(
                    (REFUSAL_WINDOW_SECS - 3600..=REFUSAL_WINDOW_SECS).contains(&age),
                    "minute {minute}: window {age} s"
                );
            } else {
                assert_eq!(since, start);
            }
            // One refusal a minute since the mark.
            let (_, count) = counts[Setting::MaxQueryWork as usize];
            assert_eq!(count, age / 60, "minute {minute}");
        }
        // After a gap longer than the window, counting starts afresh.
        refusals.mark(start + 60 * 3600);
        assert_eq!(refusals.recent().unwrap().0, start + 60 * 3600);
    }

    #[test]
    fn histograms_render_cumulative_buckets_in_display_units() {
        let metrics = Metrics::default();
        for micros in [40, 50, 700, 3_000_000] {
            metrics.writer_commit.observe(Duration::from_micros(micros));
        }
        metrics.writer_commit_events.observe(3);
        metrics.writer_commit_events.observe(100_000);
        let rendered = metrics.render();
        for line in [
            "# TYPE wok_writer_commit_seconds histogram\n",
            "wok_writer_commit_seconds_bucket{le=\"0.00005\"} 2\n",
            "wok_writer_commit_seconds_bucket{le=\"0.0005\"} 2\n",
            "wok_writer_commit_seconds_bucket{le=\"0.001\"} 3\n",
            "wok_writer_commit_seconds_bucket{le=\"2.5\"} 3\n",
            "wok_writer_commit_seconds_bucket{le=\"+Inf\"} 4\n",
            "wok_writer_commit_seconds_sum 3.00079\n",
            "wok_writer_commit_seconds_count 4\n",
            "wok_writer_commit_events_bucket{le=\"2\"} 0\n",
            "wok_writer_commit_events_bucket{le=\"4\"} 1\n",
            "wok_writer_commit_events_bucket{le=\"65536\"} 1\n",
            "wok_writer_commit_events_bucket{le=\"+Inf\"} 2\n",
            "wok_writer_commit_events_sum 100003\n",
            "wok_writer_queue_depth_count 0\n",
            "wok_writer_storage_bytes_total 0\n",
        ] {
            assert!(rendered.contains(line), "{line}");
        }
    }

    #[test]
    fn history_is_fifo_and_hard_bounded() {
        let metrics = Metrics::default();
        metrics.history.configure(true, 2);
        metrics.active_connections.store(1, Ordering::Relaxed);
        metrics.record_history();
        metrics.active_connections.store(2, Ordering::Relaxed);
        metrics.record_history();
        metrics.active_connections.store(3, Ordering::Relaxed);
        metrics.record_history();
        let points = metrics.history.snapshots();
        assert_eq!(points.len(), 2);
        assert_eq!(points[0].active_connections, 2);
        assert_eq!(points[1].active_connections, 3);

        metrics.history.configure(false, usize::MAX);
        assert!(metrics.history.snapshots().is_empty());
        assert_eq!(
            metrics.history.max_points.load(Ordering::Relaxed),
            MAX_HISTORY_POINTS as u64
        );
    }
}
