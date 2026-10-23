//! Native TOML configuration plus the legacy strfry HOCON migration parser.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

mod edit;
mod history;
mod legacy;
mod preset;
mod provenance;

pub use edit::{write_file, Minimized};
pub use history::StaleDefault;
pub use preset::Preset;
pub use provenance::{ConfigEntry, ConfigExplanation, Origin};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The preset whose overlay this configuration was resolved over.
    #[serde(default)]
    pub preset: Preset,
    pub admin: AdminConfig,
    pub db: PathBuf,
    pub db_maxreaders: u32,
    pub db_mapsize: usize,
    pub db_no_read_ahead: bool,
    pub db_min_free_disk_bytes: u64,
    pub events: EventsConfig,
    pub observability: ObservabilityConfig,
    pub relay: RelayConfig,
    /// Warnings for the deprecated keys the file set, which loaded as their
    /// translation. Logged at startup and on reload.
    #[serde(skip)]
    pub deprecations: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct StrfryConfigTranslation {
    pub config: Config,
    pub translated_keys: Vec<String>,
    pub ignored_keys: Vec<String>,
}

const STRFRY_TRANSLATED_KEYS: &[&str] = &[
    "db",
    "dbParams.mapsize",
    "dbParams.maxreaders",
    "dbParams.noReadAhead",
    "events.ephemeralEventsLifetimeSeconds",
    "events.maxEventSize",
    "events.maxNumTags",
    "events.maxTagValSize",
    "events.rejectEphemeralEventsOlderThanSeconds",
    "events.rejectEventsNewerThanSeconds",
    "events.rejectEventsOlderThanSeconds",
    "relay.auth.enabled",
    "relay.auth.restrictReadToInvolvedPubkey",
    "relay.auth.restrictedReadKinds",
    "relay.auth.serviceUrl",
    "relay.autoPingSeconds",
    "relay.bind",
    "relay.compression.enabled",
    "relay.compression.slidingWindow",
    "relay.enableTcpKeepalive",
    "relay.filterValidation.allowedKinds",
    "relay.filterValidation.enabled",
    "relay.filterValidation.maxFiltersPerReq",
    "relay.filterValidation.maxKindsPerFilter",
    "relay.filterValidation.requireAuthorOrTag",
    "relay.info.banner",
    "relay.info.contact",
    "relay.info.description",
    "relay.info.icon",
    "relay.info.name",
    "relay.info.privacy",
    "relay.info.pubkey",
    "relay.info.self",
    "relay.info.terms",
    "relay.logging.dbScanPerf",
    "relay.logging.dumpInAll",
    "relay.logging.dumpInEvents",
    "relay.logging.dumpInReqs",
    "relay.logging.invalidEvents",
    "relay.maxFilterLimit",
    "relay.maxFilterLimitCount",
    "relay.maxTotalEventsPerReq",
    "relay.maxPendingOutboundBytes",
    "relay.maxReqFilterSize",
    "relay.maxSubsPerConnection",
    "relay.maxTagsPerFilter",
    "relay.maxWebsocketPayloadSize",
    "relay.negentropy.enabled",
    "relay.negentropy.maxSyncEvents",
    "relay.nip62.enabled",
    "relay.nofiles",
    "relay.numThreads.ingester",
    "relay.numThreads.negentropy",
    "relay.numThreads.reqMonitor",
    "relay.numThreads.reqWorker",
    "relay.port",
    "relay.queryTimesliceBudgetMicroseconds",
    "relay.realIpHeader",
    "relay.unix.authGids",
    "relay.unix.authUids",
    "relay.unix.enabled",
    "relay.unix.group",
    "relay.unix.maxFrameBytes",
    "relay.unix.maxPendingOutboundBytes",
    "relay.unix.mode",
    "relay.unix.owner",
    "relay.unix.path",
    "relay.writePolicy.plugin",
    "relay.writePolicy.timeoutSeconds",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlConfig {
    preset: Preset,
    admin: AdminConfig,
    database: DatabaseConfig,
    events: EventsConfig,
    observability: ObservabilityConfig,
    relay: RelayConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    pub enabled: bool,
    pub public_url: String,
    pub pubkeys: Vec<String>,
    pub auth_window_secs: u64,
    pub allow_config_writes: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DatabaseConfig {
    path: PathBuf,
    max_readers: u32,
    map_size: usize,
    no_read_ahead: bool,
    min_free_disk_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsConfig {
    pub max_event_size: usize,
    pub reject_newer_than_secs: u64,
    pub reject_older_than_secs: u64,
    pub reject_ephemeral_older_than_secs: u64,
    pub ephemeral_lifetime_secs: u64,
    pub ephemeral_persistence: EphemeralPersistence,
    pub max_num_tags: usize,
    pub max_tag_val_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservabilityConfig {
    pub log_format: LogFormat,
    pub log_filter: String,
    pub history_enabled: bool,
    pub history_interval_secs: u64,
    pub history_max_points: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    Pretty,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EphemeralPersistence {
    LiveOnly,
    Ttl,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    pub bind: String,
    pub port: u16,
    pub nofiles: u64,
    pub real_ip_header: String,
    pub auth: AuthConfig,
    pub info: InfoConfig,
    pub max_websocket_payload_size: usize,
    /// Maximum combined compact-JSON bytes across all filter objects in one
    /// REQ or COUNT command.
    pub max_req_filter_size: usize,
    /// Maximum combined compact-JSON filter bytes of the REQ subscriptions
    /// open on one connection, and separately of its unanswered COUNTs;
    /// zero is unlimited.
    pub max_filter_bytes_per_connection: usize,
    /// Unconditional protocol ceiling for filter objects in one REQ/COUNT.
    pub max_filters_per_req: usize,
    pub auto_ping_seconds: u64,
    pub enable_tcp_keepalive: bool,
    /// Pre-upgrade HTTP header read deadline (slowloris guard); zero
    /// disables it.
    pub handshake_timeout_secs: u64,
    /// Maximum idle gap between socket reads while a partial WebSocket frame
    /// or unfinished fragmented message is buffered (slow-trickle guard);
    /// zero disables it.
    pub frame_read_timeout_secs: u64,
    pub query_timeslice_budget_us: u64,
    pub max_filter_limit: u64,
    pub max_tags_per_filter: usize,
    #[serde(default = "default_max_and_entries")]
    pub max_and_entries: usize,
    pub max_filter_limit_count: u64,
    pub max_total_events_per_req: u64,
    pub max_subs_per_connection: usize,
    /// Per-subscription bytes of live matches held while its history is
    /// sent; zero is unbounded. See `wok_query::PendingBuffer`.
    #[serde(default = "default_max_live_buffer_bytes")]
    pub max_live_buffer_bytes: usize,
    pub max_pending_outbound_bytes: usize,
    pub write_policy_plugin: String,
    pub write_policy_timeout_secs: u64,
    pub compression_enabled: bool,
    pub compression_sliding_window: bool,
    pub dump_in_all: bool,
    pub dump_in_events: bool,
    pub dump_in_reqs: bool,
    pub db_scan_perf: bool,
    pub invalid_events: bool,
    pub ingester_threads: usize,
    pub req_worker_threads: usize,
    pub req_monitor_threads: usize,
    pub negentropy_threads: usize,
    pub negentropy_enabled: bool,
    pub max_sync_events: u64,
    pub sync_memory_per_connection: u64,
    pub sync_memory_total: u64,
    pub sync_idle_timeout_secs: u64,
    pub nip62: Nip62Config,
    pub filter_validation: FilterValidationConfig,
    pub abuse: AbuseConfig,
    pub unix: UnixConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbuseConfig {
    pub enabled: bool,
    /// The leading bits of an IPv6 address that key its per-address
    /// budgets, 1 to 128. IPv4 addresses are keyed whole.
    pub ipv6_prefix_len: u8,
    pub connection_rate_per_second: u32,
    pub connection_burst: u32,
    pub event_rate_per_second: u32,
    pub event_burst: u32,
    pub pubkey_event_rate_per_second: u32,
    pub pubkey_event_burst: u32,
    pub req_rate_per_second: u32,
    pub req_burst: u32,
    pub count_rate_per_second: u32,
    pub count_burst: u32,
    /// Malformed messages per network address.
    pub invalid_rate_per_second: u32,
    pub invalid_burst: u32,
    pub max_concurrent_historical_queries: usize,
    /// Most index entries a REQ, COUNT or NEG-OPEN may touch, estimated
    /// before its scan. Replaces `max_query_cost` (see `legacy`).
    pub max_query_work: u64,
    pub max_stored_events: u64,
    pub max_stored_events_per_pubkey: u64,
    pub min_pow_difficulty: u8,
    /// Each connection's own budgets. The address budgets above are a
    /// backstop over all of an address's connections.
    pub per_connection: PerConnectionConfig,
}

/// Budgets each connection has to itself (`[relay.abuse.per_connection]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerConnectionConfig {
    /// REQs, replacement REQs and NEG-OPENs.
    pub req_rate_per_second: u32,
    pub req_burst: u32,
    /// NEG-MSG rounds of sync sessions already admitted.
    pub neg_msg_rate_per_second: u32,
    pub neg_msg_burst: u32,
    pub count_rate_per_second: u32,
    pub count_burst: u32,
    /// An AUTHed connection's budgets are this many times larger.
    pub authenticated_multiplier: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nip62Config {
    pub enabled: bool,
    pub service_url: String,
    pub deletion_batch_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    pub enabled: bool,
    pub service_url: String,
    /// Kinds only their author and first `p`-tag recipient may read.
    pub recipient_only_kinds: Vec<u64>,
    /// Kinds only their author may read, and only their author may publish
    /// (NIP-78).
    pub owner_only_kinds: Vec<u64>,
    /// Kinds any authenticated connection may read.
    pub authenticated_kinds: Vec<u64>,
    /// Who may send REQ, COUNT and NEG-OPEN.
    pub read_policy: AccessPolicy,
    /// Who may publish events. NIP-62 vanish requests are always accepted.
    pub write_policy: AccessPolicy,
    /// Under `write_policy = "members"`, events of these kinds are also
    /// accepted when their first `p` tag is a member, so anyone can deliver
    /// gift wraps to members.
    pub inbox_kinds: Vec<u64>,
    /// The kinds the relay accepts; empty accepts every kind. NIP-86
    /// `disallowkind` can narrow it, and `allowkind` cannot widen it.
    pub accepted_kinds: Vec<u64>,
}

/// Who may read or write (`relay.auth.read_policy`, `write_policy`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessPolicy {
    /// Anyone.
    #[default]
    Open,
    /// A connection authenticated with NIP-42, as any pubkey.
    Authenticated,
    /// A member: a NIP-86 allowlisted or role-holding pubkey, or one of
    /// `admin.pubkeys`, that is not banned.
    Members,
}

impl AccessPolicy {
    /// The name the configuration uses.
    pub fn name(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Authenticated => "authenticated",
            Self::Members => "members",
        }
    }
}

impl std::fmt::Display for AccessPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InfoConfig {
    pub name: String,
    pub description: String,
    pub pubkey: String,
    pub self_pk: String,
    pub contact: String,
    pub icon: String,
    pub banner: String,
    pub privacy: String,
    pub terms: String,
}

/// Optional rules for REQ, COUNT and NEG-OPEN filters, each off at its zero
/// or empty value.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilterValidationConfig {
    pub max_kinds_per_filter: u64,
    pub allowed_kinds: String,
    pub require_author_or_tag: bool,
    /// Refuse a filter that names none of `ids`, `authors` or a tag.
    pub require_scoped_filters: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnixConfig {
    pub enabled: bool,
    pub path: PathBuf,
    pub mode: u32,
    pub owner: String,
    pub group: String,
    pub auth_uids: Vec<u32>,
    pub auth_gids: Vec<u32>,
    pub max_frame_bytes: usize,
    pub max_pending_outbound_bytes: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            preset: Preset::Public,
            admin: AdminConfig {
                enabled: false,
                public_url: String::new(),
                pubkeys: Vec::new(),
                auth_window_secs: 60,
                allow_config_writes: false,
            },
            db: PathBuf::from("./wok-db/"),
            db_maxreaders: 256,
            db_mapsize: 68_719_476_736,
            db_no_read_ahead: false,
            db_min_free_disk_bytes: 1_073_741_824,
            events: EventsConfig {
                max_event_size: wok_event::DEFAULT_MAX_EVENT_SIZE,
                reject_newer_than_secs: 900,
                reject_older_than_secs: 0,
                reject_ephemeral_older_than_secs: 60,
                ephemeral_lifetime_secs: 300,
                ephemeral_persistence: EphemeralPersistence::LiveOnly,
                max_num_tags: wok_event::DEFAULT_MAX_NUM_TAGS,
                max_tag_val_size: 1024,
            },
            observability: ObservabilityConfig {
                log_format: LogFormat::Pretty,
                log_filter: "wok=info".into(),
                history_enabled: true,
                history_interval_secs: 15,
                history_max_points: 5_760,
            },
            relay: RelayConfig {
                bind: "127.0.0.1".into(),
                port: 7777,
                nofiles: 524288,
                real_ip_header: String::new(),
                auth: AuthConfig {
                    enabled: true,
                    service_url: String::new(),
                    // Private messages and gift wraps, including NIP-59's
                    // ephemeral kind 21059, and NIP-78 app data fail closed
                    // until the operator configures the relay URL required
                    // by NIP-42.
                    recipient_only_kinds: vec![4, 1059, 21059],
                    owner_only_kinds: wok_event::APP_DATA_KINDS.to_vec(),
                    authenticated_kinds: Vec::new(),
                    read_policy: AccessPolicy::Open,
                    write_policy: AccessPolicy::Open,
                    inbox_kinds: wok_event::GIFT_WRAP_KINDS.to_vec(),
                    accepted_kinds: Vec::new(),
                },
                info: InfoConfig {
                    name: "wok default".into(),
                    description: "This is a wok instance.".into(),
                    pubkey: String::new(),
                    self_pk: String::new(),
                    contact: String::new(),
                    icon: String::new(),
                    banner: String::new(),
                    privacy: String::new(),
                    terms: String::new(),
                },
                max_websocket_payload_size: 2 * wok_event::DEFAULT_MAX_EVENT_SIZE,
                max_req_filter_size: 262_144,
                max_filter_bytes_per_connection: 2_097_152,
                max_filters_per_req: 200,
                auto_ping_seconds: 55,
                enable_tcp_keepalive: false,
                handshake_timeout_secs: 10,
                frame_read_timeout_secs: 30,
                query_timeslice_budget_us: 10000,
                max_filter_limit: 2_000,
                max_tags_per_filter: 8,
                max_and_entries: default_max_and_entries(),
                max_filter_limit_count: 1_000_000,
                max_total_events_per_req: 10_000,
                max_subs_per_connection: 200,
                max_live_buffer_bytes: default_max_live_buffer_bytes(),
                max_pending_outbound_bytes: 33_554_432,
                write_policy_plugin: String::new(),
                write_policy_timeout_secs: 10,
                compression_enabled: true,
                compression_sliding_window: true,
                dump_in_all: false,
                dump_in_events: false,
                dump_in_reqs: false,
                db_scan_perf: false,
                invalid_events: true,
                ingester_threads: 3,
                req_worker_threads: 3,
                req_monitor_threads: 3,
                negentropy_threads: 2,
                negentropy_enabled: true,
                max_sync_events: 1_000_000,
                sync_memory_per_connection: 256 * 1024 * 1024,
                sync_memory_total: 1024 * 1024 * 1024,
                sync_idle_timeout_secs: 60,
                nip62: Nip62Config {
                    enabled: true,
                    service_url: String::new(),
                    deletion_batch_size: 1_000,
                },
                filter_validation: FilterValidationConfig {
                    max_kinds_per_filter: 0,
                    allowed_kinds: String::new(),
                    require_author_or_tag: false,
                    require_scoped_filters: false,
                },
                abuse: AbuseConfig {
                    enabled: true,
                    ipv6_prefix_len: 64,
                    connection_rate_per_second: 10,
                    connection_burst: 50,
                    event_rate_per_second: 50,
                    event_burst: 100,
                    pubkey_event_rate_per_second: 25,
                    pubkey_event_burst: 50,
                    req_rate_per_second: 200,
                    req_burst: 1_000,
                    count_rate_per_second: 20,
                    count_burst: 50,
                    invalid_rate_per_second: 5,
                    invalid_burst: 20,
                    max_concurrent_historical_queries: 8,
                    max_query_work: 20_000,
                    max_stored_events: 0,
                    max_stored_events_per_pubkey: 1_000_000,
                    min_pow_difficulty: 0,
                    per_connection: PerConnectionConfig {
                        req_rate_per_second: 20,
                        // A client's startup burst of about 60 REQs fits.
                        req_burst: 100,
                        neg_msg_rate_per_second: 50,
                        neg_msg_burst: 200,
                        count_rate_per_second: 5,
                        count_burst: 20,
                        authenticated_multiplier: 4,
                    },
                },
                unix: UnixConfig {
                    enabled: false,
                    path: PathBuf::from("./wok-db/wok.sock"),
                    mode: 0o600,
                    owner: String::new(),
                    group: String::new(),
                    auth_uids: Vec::new(),
                    auth_gids: Vec::new(),
                    max_frame_bytes: 2 * wok_event::DEFAULT_MAX_EVENT_SIZE,
                    max_pending_outbound_bytes: 33_554_432,
                },
            },
            deprecations: Vec::new(),
        }
    }
}

fn default_max_and_entries() -> usize {
    wok_query::DEFAULT_MAX_AND_ENTRIES
}

fn default_max_live_buffer_bytes() -> usize {
    262_144
}

impl From<Config> for TomlConfig {
    fn from(config: Config) -> Self {
        Self {
            preset: config.preset,
            admin: config.admin,
            database: DatabaseConfig {
                path: config.db,
                max_readers: config.db_maxreaders,
                map_size: config.db_mapsize,
                no_read_ahead: config.db_no_read_ahead,
                min_free_disk_bytes: config.db_min_free_disk_bytes,
            },
            events: config.events,
            observability: config.observability,
            relay: config.relay,
        }
    }
}

impl From<TomlConfig> for Config {
    fn from(config: TomlConfig) -> Self {
        Self {
            preset: config.preset,
            admin: config.admin,
            db: config.database.path,
            db_maxreaders: config.database.max_readers,
            db_mapsize: config.database.map_size,
            db_no_read_ahead: config.database.no_read_ahead,
            db_min_free_disk_bytes: config.database.min_free_disk_bytes,
            events: config.events,
            observability: config.observability,
            relay: config.relay,
            deprecations: Vec::new(),
        }
    }
}

/// Resolves one preset's overlay text.
type OverlayFn = fn(Preset) -> &'static str;

/// The configuration layers of one TOML file before they are merged: the
/// built-in defaults, the selected preset's overlay, and the file itself.
struct Layers {
    preset: Preset,
    overlay: toml::Value,
    /// The file, with its deprecated keys translated.
    file: toml::Value,
    /// How the file's deprecated keys were translated.
    legacy: legacy::Translation,
}

impl Layers {
    fn parse(text: &str, overlay_of: OverlayFn) -> Result<Self, String> {
        let file: toml::Value = toml::from_str(text).map_err(|e| e.to_string())?;
        let preset = Preset::select(&file)?;
        let overlay =
            toml::from_str(overlay_of(preset)).map_err(|e| format!("preset {preset}: {e}"))?;
        let mut layers = Self {
            preset,
            overlay,
            file,
            legacy: legacy::Translation::default(),
        };
        layers.legacy = legacy::translate(&layers.file, &layers.preset_value()?)?;
        layers.legacy.apply(&mut layers.file);
        Ok(layers)
    }

    /// The built-in defaults with the preset's overlay: the configuration a
    /// file containing only the `preset` key would get.
    fn preset_value(&self) -> Result<toml::Value, String> {
        let mut merged = toml::Value::try_from(TomlConfig::from(Config::default()))
            .map_err(|e| e.to_string())?;
        merge_toml(&mut merged, self.overlay.clone());
        if let toml::Value::Table(table) = &mut merged {
            table.insert("preset".into(), self.preset.name().into());
        }
        Ok(merged)
    }

    /// [`Layers::preset_value`] round-tripped through its typed form, so its
    /// values are encoded exactly like [`encode`]'s.
    fn preset_encoded(&self) -> Result<toml::Value, String> {
        let preset: TomlConfig = self
            .preset_value()?
            .try_into()
            .map_err(|e: toml::de::Error| e.to_string())?;
        toml::Value::try_from(preset).map_err(|e| e.to_string())
    }

    fn resolve(&self) -> Result<Config, String> {
        let mut merged = self.preset_value()?;
        merge_toml(&mut merged, self.file.clone());
        let parsed: TomlConfig = merged
            .try_into()
            .map_err(|e: toml::de::Error| e.to_string())?;
        let mut config = validate(parsed)?;
        config.deprecations = self.legacy.warnings.clone();
        Ok(config)
    }
}

/// A resolved configuration as a TOML value, in the native file layout.
fn encode(config: &Config) -> Result<toml::Value, String> {
    toml::Value::try_from(TomlConfig::from(config.clone())).map_err(|e| e.to_string())
}

/// Check and normalize a merged configuration.
fn validate(mut parsed: TomlConfig) -> Result<Config, String> {
    validate_admin_config(&mut parsed.admin)?;
    clamp_size_class(&mut parsed);
    parsed.relay.unix.mode = mask_socket_mode(parsed.relay.unix.mode);
    if parsed.observability.history_interval_secs == 0 {
        return Err("observability.history_interval_secs must be at least 1".into());
    }
    if parsed.observability.history_max_points > crate::metrics::MAX_HISTORY_POINTS {
        return Err(format!(
            "observability.history_max_points cannot exceed {}",
            crate::metrics::MAX_HISTORY_POINTS
        ));
    }
    tracing_subscriber_filter_syntax(&parsed.observability.log_filter)?;
    if parsed.relay.abuse.per_connection.authenticated_multiplier == 0 {
        return Err(
            "relay.abuse.per_connection.authenticated_multiplier must be at least 1".into(),
        );
    }
    if let Some(kind) = parsed
        .relay
        .auth
        .accepted_kinds
        .iter()
        .find(|&&kind| kind > u64::from(u16::MAX))
    {
        return Err(format!(
            "relay.auth.accepted_kinds: kind {kind} is out of range (0 to 65535)"
        ));
    }
    if !(1..=128).contains(&parsed.relay.abuse.ipv6_prefix_len) {
        return Err(
            "relay.abuse.ipv6_prefix_len must be from 1 to 128 (128 keys each IPv6 address \
             on its own)"
                .into(),
        );
    }
    Ok(parsed.into())
}

fn merge_toml(base: &mut toml::Value, supplied: toml::Value) {
    match (base, supplied) {
        (toml::Value::Table(base), toml::Value::Table(supplied)) => {
            for (key, value) in supplied {
                if let Some(existing) = base.get_mut(&key) {
                    merge_toml(existing, value);
                } else {
                    base.insert(key, value);
                }
            }
        }
        (base, supplied) => {
            *base = supplied;
        }
    }
}

impl Config {
    /// The `created_at` window an event of `kind` must fall in.
    ///
    /// `events.reject_older_than_secs` bounds regular events only.
    /// Replaceable and addressable events, deletions and vanish requests are
    /// exempt, so profiles, lists and deletions can always be rebroadcast.
    /// AUTH uses NIP-42's fixed window instead of `[events]`, and kind 21059
    /// may be backdated as far as NIP-59 recommends.
    pub fn timestamp_policy_for_kind(&self, kind: u64) -> wok_event::TimestampPolicy {
        use wok_event::{AUTH_TIMESTAMP_WINDOW_SECS, GIFT_WRAP_BACKDATE_SECS};
        if kind == wok_event::AUTH_KIND {
            return wok_event::TimestampPolicy::from_now(
                AUTH_TIMESTAMP_WINDOW_SECS,
                AUTH_TIMESTAMP_WINDOW_SECS,
                AUTH_TIMESTAMP_WINDOW_SECS,
            );
        }
        let unbounded = wok_event::is_replaceable_kind(kind)
            || wok_event::is_param_replaceable_kind(kind)
            || kind == wok_event::DELETION_KIND
            || kind == wok_db::VANISH_KIND;
        wok_event::TimestampPolicy::from_now(
            self.events.reject_newer_than_secs,
            if unbounded {
                0
            } else {
                self.events.reject_older_than_secs
            },
            // The same allowance read visibility grants, so an accepted wrap
            // is never already expired.
            if kind == 21059 {
                GIFT_WRAP_BACKDATE_SECS
            } else {
                self.events.reject_ephemeral_older_than_secs
            },
        )
    }

    pub fn vanish_policy(&self) -> wok_db::VanishPolicy {
        wok_db::VanishPolicy {
            enabled: self.relay.nip62.enabled,
            service_url: if self.relay.nip62.service_url.is_empty() {
                self.relay.auth.service_url.clone()
            } else {
                self.relay.nip62.service_url.clone()
            },
        }
    }

    /// True when a NIP-42 AUTH can succeed: auth is enabled and the relay URL
    /// that AUTH events must name is configured. NIP-11 advertises NIP-42 under
    /// the same condition, and every AUTH challenge is gated on it.
    pub fn auth_usable(&self) -> bool {
        self.relay.auth.enabled && !self.relay.auth.service_url.is_empty()
    }

    /// NIP-11 `limitation.auth_required`: every REQ, COUNT and NEG-OPEN
    /// needs AUTH, under any `read_policy` but `open`. Particular kinds can
    /// need AUTH whatever this says, as NIP-11 allows. While AUTH cannot
    /// succeed it is not asked for, as NIP-42 is then not advertised.
    pub fn auth_required(&self) -> bool {
        self.relay.auth.read_policy != AccessPolicy::Open && self.auth_usable()
    }

    /// NIP-11 `limitation.restricted_writes`: an event must meet a condition
    /// that clients are expected to know before writing, beyond ordinary
    /// rate limits: a `write_policy` other than `open`, a list of
    /// `accepted_kinds`, or proof of work.
    pub fn restricted_writes(&self) -> bool {
        self.relay.auth.write_policy != AccessPolicy::Open
            || !self.relay.auth.accepted_kinds.is_empty()
            || (self.relay.abuse.enabled && self.relay.abuse.min_pow_difficulty > 0)
    }

    /// Whether `relay.auth.accepted_kinds` lets the relay accept events of
    /// `kind`. NIP-62 vanish requests are accepted whatever it lists while
    /// NIP-62 is on: relays that restrict what they store must still honor
    /// them. The NIP-86 kind policy may still refuse them.
    pub fn accepts_kind(&self, kind: u64) -> bool {
        let accepted = &self.relay.auth.accepted_kinds;
        accepted.is_empty()
            || accepted.contains(&kind)
            || (kind == wok_db::VANISH_KIND && self.relay.nip62.enabled)
    }

    /// The kinds [`accepts_kind`](Self::accepts_kind) admits, sorted, or
    /// `None` when it admits every kind.
    pub fn accepted_kind_list(&self) -> Option<Vec<u64>> {
        let accepted = &self.relay.auth.accepted_kinds;
        if accepted.is_empty() {
            return None;
        }
        let mut kinds = accepted.clone();
        if self.relay.nip62.enabled {
            kinds.push(wok_db::VANISH_KIND);
        }
        kinds.sort_unstable();
        kinds.dedup();
        Some(kinds)
    }

    /// Explain how `relay.real_ip_header` keys the per-address budgets of a
    /// relay listening on `listening`. A set header is trusted as each
    /// client's address. With none, a client is the address that connected,
    /// so a listener only this host or a private network can reach, as behind
    /// a reverse proxy, gives every client the proxy's address.
    pub fn real_ip_header_warning(&self, listening: &[SocketAddr]) -> Option<String> {
        let header = &self.relay.real_ip_header;
        if !header.is_empty() {
            return Some(format!(
                "relay.real_ip_header = {header:?} is trusted as each client's address by \
                 every per-address budget. Set it only when every connection comes from a \
                 proxy that overwrites the header: a client that reaches the relay directly \
                 could send a new address with each connection to escape those budgets, or \
                 send another client's address to spend that client's budgets"
            ));
        }
        let local_only = |ip: IpAddr| match ip {
            IpAddr::V4(ip) => ip.is_loopback() || ip.is_private() || ip.is_link_local(),
            IpAddr::V6(ip) => {
                ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local()
            }
        };
        if listening.is_empty() || !listening.iter().all(|addr| local_only(addr.ip())) {
            return None;
        }
        let addrs: Vec<String> = listening.iter().map(SocketAddr::to_string).collect();
        Some(format!(
            "the relay listens only on loopback or private addresses ({}) and \
             relay.real_ip_header is unset. If a reverse proxy forwards connections, every \
             client has the proxy's address and they all share one set of per-address \
             budgets (connections, EVENT and AUTH, REQ, COUNT); set relay.real_ip_header to \
             the header the proxy overwrites with the client's address",
            addrs.join(", ")
        ))
    }

    /// Who may read each kind: `relay.auth`'s read classes.
    pub fn read_restrictor(&self) -> crate::restrict::ReadRestrictor {
        let auth = &self.relay.auth;
        crate::restrict::ReadRestrictor {
            recipient_only: auth.recipient_only_kinds.clone(),
            owner_only: auth.owner_only_kinds.clone(),
            authenticated: auth.authenticated_kinds.clone(),
        }
    }

    /// Explain what is deliberately failing closed because the relay cannot
    /// complete NIP-42 authentication: restricted read kinds, and reads and
    /// writes its access policies limit to authenticated connections.
    pub fn auth_configuration_warning(&self) -> Option<String> {
        if self.auth_usable() {
            return None;
        }
        let auth = &self.relay.auth;
        let mut needs_auth = Vec::new();
        let mut kinds: Vec<u64> = self.read_restrictor().restricted_kinds().collect();
        kinds.sort_unstable();
        kinds.dedup();
        if !kinds.is_empty() {
            needs_auth.push(format!("restricted read kinds {kinds:?}"));
        }
        if auth.read_policy != AccessPolicy::Open {
            needs_auth.push(format!(
                "every read (read_policy = \"{}\")",
                auth.read_policy
            ));
        }
        match auth.write_policy {
            AccessPolicy::Open => {}
            AccessPolicy::Authenticated => {
                needs_auth.push("every write (write_policy = \"authenticated\")".into())
            }
            AccessPolicy::Members => needs_auth
                .push("writes members sign with other keys (write_policy = \"members\")".into()),
        }
        if needs_auth.is_empty() {
            return None;
        }
        let why = if !auth.enabled {
            "AUTH is off because relay.auth.enabled is false"
        } else {
            "AUTH is unavailable until relay.auth.service_url is configured"
        };
        Some(format!(
            "{why}, so these fail closed: {}",
            needs_auth.join("; ")
        ))
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, String> {
        let text = std::fs::read_to_string(path.as_ref()).map_err(|e| e.to_string())?;
        Self::parse_toml(&text)
    }

    /// Parse Wok's native TOML format. Settings resolve in three layers:
    /// built-in defaults, then the overlay of the file's `preset` (public
    /// when absent), then the file. Unknown settings and preset names are
    /// rejected.
    pub fn parse_toml(text: &str) -> Result<Self, String> {
        Layers::parse(text, Preset::overlay)?.resolve()
    }

    /// Parse a native TOML file like [`Config::parse_toml`] and report each
    /// effective value with the layer it came from.
    pub fn explain_toml(text: &str) -> Result<ConfigExplanation, String> {
        provenance::explain(text, Preset::overlay)
    }

    /// Edit a native TOML file in place so it resolves to the configuration
    /// `edit` makes of the file's own. Only keys whose value changes are
    /// touched: a key set to its preset's value is removed, and any other is
    /// set where it is or added to its table. Comments, layout and `preset`
    /// are kept. Returns the new text and its configuration, which is
    /// checked by parsing the text again.
    pub fn edit_toml(
        text: &str,
        edit: impl FnOnce(&mut Config),
    ) -> Result<(String, Config), String> {
        edit::edit(text, Preset::overlay, edit)
    }

    /// Remove the keys of a native TOML file that repeat its preset's value,
    /// keeping comments, layout and `preset`. The file resolves to the same
    /// configuration afterwards.
    pub fn minimize_toml(text: &str) -> Result<Minimized, String> {
        edit::minimize(text, Preset::overlay)
    }

    pub fn to_toml(&self) -> Result<String, String> {
        toml::to_string_pretty(&TomlConfig::from(self.clone())).map_err(|e| e.to_string())
    }

    /// Parse the legacy HOCON subset used by strfry. This exists only for the
    /// explicit `wok migrate strfry` boundary.
    pub fn parse_strfry(text: &str) -> Result<Self, String> {
        Ok(Self::translate_strfry(text)?.config)
    }

    /// Translate legacy strfry HOCON while retaining an audit trail of every
    /// supplied leaf key that was translated or deliberately ignored.
    pub fn translate_strfry(text: &str) -> Result<StrfryConfigTranslation, String> {
        let map = parse_hocon(text)?;
        let mut cfg = Config::default();
        if let Some(v) = map.get("db") {
            cfg.db = PathBuf::from(v.clone());
        }
        assign_u64(&map, "dbParams.maxreaders", |n| {
            cfg.db_maxreaders = n as u32;
            Ok(())
        })?;
        assign_u64(&map, "dbParams.mapsize", |n| {
            cfg.db_mapsize = n as usize;
            Ok(())
        })?;
        assign_bool(&map, "dbParams.noReadAhead", |b| cfg.db_no_read_ahead = b)?;
        assign_u64(&map, "events.maxEventSize", |n| {
            cfg.events.max_event_size = n as usize;
            Ok(())
        })?;
        assign_u64(&map, "events.rejectEventsNewerThanSeconds", |n| {
            cfg.events.reject_newer_than_secs = n;
            Ok(())
        })?;
        assign_u64(&map, "events.rejectEventsOlderThanSeconds", |n| {
            cfg.events.reject_older_than_secs = n;
            Ok(())
        })?;
        assign_u64(&map, "events.rejectEphemeralEventsOlderThanSeconds", |n| {
            cfg.events.reject_ephemeral_older_than_secs = n;
            Ok(())
        })?;
        assign_u64(&map, "events.ephemeralEventsLifetimeSeconds", |n| {
            cfg.events.ephemeral_lifetime_secs = n;
            Ok(())
        })?;
        assign_u64(&map, "events.maxNumTags", |n| {
            cfg.events.max_num_tags = n as usize;
            Ok(())
        })?;
        assign_u64(&map, "events.maxTagValSize", |n| {
            cfg.events.max_tag_val_size = n as usize;
            Ok(())
        })?;
        if let Some(v) = map.get("relay.bind") {
            cfg.relay.bind = v.clone();
        }
        assign_u64(&map, "relay.port", |n| {
            if n > u16::MAX as u64 {
                return Err("relay.port out of range".into());
            }
            cfg.relay.port = n as u16;
            Ok(())
        })?;
        assign_u64(&map, "relay.nofiles", |n| {
            cfg.relay.nofiles = n;
            Ok(())
        })?;
        if let Some(v) = map.get("relay.realIpHeader") {
            cfg.relay.real_ip_header = v.clone();
        }
        assign_bool(&map, "relay.auth.enabled", |b| cfg.relay.auth.enabled = b)?;
        if let Some(v) = map.get("relay.auth.serviceUrl") {
            cfg.relay.auth.service_url = v.clone();
        }
        if let Some(v) = map.get("relay.auth.restrictedReadKinds") {
            cfg.relay.auth.recipient_only_kinds = parse_kinds(v)?;
        }
        let mut involved_only = true;
        assign_bool(&map, "relay.auth.restrictReadToInvolvedPubkey", |b| {
            involved_only = b
        })?;
        let auth = &mut cfg.relay.auth;
        if !involved_only {
            // Wok has no mode that lets a REQ mixing in another kind read
            // them without AUTH: the nearest is any authenticated reader.
            let moved = std::mem::take(&mut auth.recipient_only_kinds);
            auth.authenticated_kinds = moved.clone();
            cfg.deprecations.push(format!(
                "relay.auth.restrictReadToInvolvedPubkey = false has no Wok equivalent: kinds \
                 {moved:?} become relay.auth.authenticated_kinds, which any authenticated \
                 connection may read and no other can.{}",
                legacy::owner_only_note(&moved, &auth.owner_only_kinds)
            ));
        } else {
            let note = legacy::owner_only_note(&auth.recipient_only_kinds, &auth.owner_only_kinds);
            if !note.is_empty() {
                cfg.deprecations.push(format!(
                    "relay.auth.restrictedReadKinds becomes relay.auth.recipient_only_kinds, \
                     which the author and first p-tag recipient may read.{note}"
                ));
            }
        }
        if let Some(v) = map.get("relay.info.name") {
            cfg.relay.info.name = v.clone();
        }
        if let Some(v) = map.get("relay.info.description") {
            cfg.relay.info.description = v.clone();
        }
        if let Some(v) = map.get("relay.info.pubkey") {
            cfg.relay.info.pubkey = v.clone();
        }
        if let Some(v) = map.get("relay.info.self") {
            cfg.relay.info.self_pk = v.clone();
        }
        if let Some(v) = map.get("relay.info.contact") {
            cfg.relay.info.contact = v.clone();
        }
        if let Some(v) = map.get("relay.info.icon") {
            cfg.relay.info.icon = v.clone();
        }
        if let Some(v) = map.get("relay.info.banner") {
            cfg.relay.info.banner = v.clone();
        }
        if let Some(v) = map.get("relay.info.privacy") {
            cfg.relay.info.privacy = v.clone();
        }
        if let Some(v) = map.get("relay.info.terms") {
            cfg.relay.info.terms = v.clone();
        }
        assign_u64(&map, "relay.maxWebsocketPayloadSize", |n| {
            cfg.relay.max_websocket_payload_size = n as usize;
            Ok(())
        })?;
        assign_u64(&map, "relay.maxReqFilterSize", |n| {
            // Despite its name, strfry uses this as the maximum number of
            // filter objects in the request array. Preserve that meaning only
            // at the legacy migration boundary.
            cfg.relay.max_filters_per_req = n as usize;
            Ok(())
        })?;
        assign_u64(&map, "relay.autoPingSeconds", |n| {
            cfg.relay.auto_ping_seconds = n;
            Ok(())
        })?;
        assign_bool(&map, "relay.enableTcpKeepalive", |b| {
            cfg.relay.enable_tcp_keepalive = b
        })?;
        assign_u64(&map, "relay.queryTimesliceBudgetMicroseconds", |n| {
            cfg.relay.query_timeslice_budget_us = n;
            Ok(())
        })?;
        assign_u64(&map, "relay.maxFilterLimit", |n| {
            cfg.relay.max_filter_limit = n;
            Ok(())
        })?;
        assign_u64(&map, "relay.maxTagsPerFilter", |n| {
            cfg.relay.max_tags_per_filter = n as usize;
            Ok(())
        })?;
        assign_u64(&map, "relay.maxFilterLimitCount", |n| {
            cfg.relay.max_filter_limit_count = n;
            Ok(())
        })?;
        assign_u64(&map, "relay.maxTotalEventsPerReq", |n| {
            cfg.relay.max_total_events_per_req = n;
            Ok(())
        })?;
        assign_bool(&map, "relay.nip62.enabled", |enabled| {
            cfg.relay.nip62.enabled = enabled
        })?;
        assign_u64(&map, "relay.maxSubsPerConnection", |n| {
            cfg.relay.max_subs_per_connection = n as usize;
            Ok(())
        })?;
        assign_u64(&map, "relay.maxPendingOutboundBytes", |n| {
            cfg.relay.max_pending_outbound_bytes = n as usize;
            Ok(())
        })?;
        if let Some(v) = map.get("relay.writePolicy.plugin") {
            cfg.relay.write_policy_plugin = v.clone();
        }
        assign_u64(&map, "relay.writePolicy.timeoutSeconds", |n| {
            cfg.relay.write_policy_timeout_secs = n;
            Ok(())
        })?;
        assign_bool(&map, "relay.compression.enabled", |b| {
            cfg.relay.compression_enabled = b
        })?;
        assign_bool(&map, "relay.compression.slidingWindow", |b| {
            cfg.relay.compression_sliding_window = b
        })?;
        assign_bool(&map, "relay.logging.dumpInAll", |b| {
            cfg.relay.dump_in_all = b
        })?;
        assign_bool(&map, "relay.logging.dumpInEvents", |b| {
            cfg.relay.dump_in_events = b
        })?;
        assign_bool(&map, "relay.logging.dumpInReqs", |b| {
            cfg.relay.dump_in_reqs = b
        })?;
        assign_bool(&map, "relay.logging.dbScanPerf", |b| {
            cfg.relay.db_scan_perf = b
        })?;
        assign_bool(&map, "relay.logging.invalidEvents", |b| {
            cfg.relay.invalid_events = b
        })?;
        assign_u64(&map, "relay.numThreads.ingester", |n| {
            cfg.relay.ingester_threads = n as usize;
            Ok(())
        })?;
        assign_u64(&map, "relay.numThreads.reqWorker", |n| {
            cfg.relay.req_worker_threads = n as usize;
            Ok(())
        })?;
        assign_u64(&map, "relay.numThreads.reqMonitor", |n| {
            cfg.relay.req_monitor_threads = n as usize;
            Ok(())
        })?;
        assign_u64(&map, "relay.numThreads.negentropy", |n| {
            cfg.relay.negentropy_threads = n as usize;
            Ok(())
        })?;
        assign_bool(&map, "relay.negentropy.enabled", |b| {
            cfg.relay.negentropy_enabled = b
        })?;
        assign_u64(&map, "relay.negentropy.maxSyncEvents", |n| {
            cfg.relay.max_sync_events = n;
            Ok(())
        })?;
        // strfry applies its filterValidation section only with
        // `enabled = true`, while Wok applies each rule that is set, so a
        // disabled section translates to no rules. An enabled one keeps its
        // rules, with strfry's defaults for those it leaves out, and its
        // filter-count cap folds into relay.max_filters_per_req.
        // minFiltersPerReq has no equivalent and is ignored.
        let mut validation = (
            false,
            legacy::LEGACY_MAX_FILTERS_PER_REQ,
            legacy::LEGACY_MAX_KINDS_PER_FILTER,
            String::new(),
            false,
        );
        assign_bool(&map, "relay.filterValidation.enabled", |b| validation.0 = b)?;
        assign_u64(&map, "relay.filterValidation.maxFiltersPerReq", |n| {
            validation.1 = n;
            Ok(())
        })?;
        assign_u64(&map, "relay.filterValidation.minFiltersPerReq", |_| Ok(()))?;
        assign_u64(&map, "relay.filterValidation.maxKindsPerFilter", |n| {
            validation.2 = n;
            Ok(())
        })?;
        if let Some(v) = map.get("relay.filterValidation.allowedKinds") {
            validation.3 = v.clone();
        }
        assign_bool(&map, "relay.filterValidation.requireAuthorOrTag", |b| {
            validation.4 = b
        })?;
        let (enabled, max_filters, max_kinds, allowed_kinds, require_author_or_tag) = validation;
        if enabled {
            cfg.relay.max_filters_per_req = cfg
                .relay
                .max_filters_per_req
                .min(usize::try_from(max_filters).unwrap_or(usize::MAX));
            if max_kinds == 0 {
                cfg.deprecations.push(legacy::zero_kind_cap_warning(
                    "relay.filterValidation.maxKindsPerFilter",
                ));
            }
            cfg.relay.filter_validation = FilterValidationConfig {
                max_kinds_per_filter: max_kinds,
                allowed_kinds,
                require_author_or_tag,
                require_scoped_filters: false,
            };
        }
        assign_bool(&map, "relay.unix.enabled", |b| cfg.relay.unix.enabled = b)?;
        if let Some(v) = map.get("relay.unix.path") {
            cfg.relay.unix.path = PathBuf::from(v);
        }
        if let Some(v) = map.get("relay.unix.mode") {
            cfg.relay.unix.mode = parse_mode(v)?;
        }
        if let Some(v) = map.get("relay.unix.owner") {
            cfg.relay.unix.owner = v.clone();
        }
        if let Some(v) = map.get("relay.unix.group") {
            cfg.relay.unix.group = v.clone();
        }
        assign_u64(&map, "relay.unix.maxFrameBytes", |n| {
            cfg.relay.unix.max_frame_bytes = n as usize;
            Ok(())
        })?;
        assign_u64(&map, "relay.unix.maxPendingOutboundBytes", |n| {
            cfg.relay.unix.max_pending_outbound_bytes = n as usize;
            Ok(())
        })?;
        if let Some(v) = map.get("relay.unix.authUids") {
            cfg.relay.unix.auth_uids = parse_u32s(v)?;
        }
        if let Some(v) = map.get("relay.unix.authGids") {
            cfg.relay.unix.auth_gids = parse_u32s(v)?;
        }
        let (translated_keys, ignored_keys): (Vec<_>, Vec<_>) = map
            .keys()
            .cloned()
            .partition(|key| STRFRY_TRANSLATED_KEYS.contains(&key.as_str()));
        Ok(StrfryConfigTranslation {
            config: cfg,
            translated_keys,
            ignored_keys,
        })
    }

    pub fn event_limits(&self) -> wok_event::EventLimits {
        wok_event::EventLimits {
            max_event_size: self.events.max_event_size,
            max_num_tags: self.events.max_num_tags,
            max_tag_val_size: self.events.max_tag_val_size,
        }
    }

    /// Describe changes to restart-safe security scopes (write-policy plugin,
    /// filter validation, abuse budgets, NIP-42 read restriction scope,
    /// NIP-62 vanish scope, negentropy enable switch) between this config and
    /// a reload candidate. TOML loading merges the supplied file over its
    /// preset and the factory defaults, so a valid-but-incomplete file (or a
    /// changed `preset`) silently changes omitted sections — these diffs are
    /// warn-logged on reload so the change is at least visible in the logs.
    pub fn security_scope_changes(&self, new: &Config) -> Vec<String> {
        let mut changes = Vec::new();
        // A preset only changes effective values, and each scope below
        // compares those, so this line just names the cause.
        if self.preset != new.preset {
            changes.push(format!("preset changed: {} -> {}", self.preset, new.preset));
        }
        if self.relay.write_policy_plugin != new.relay.write_policy_plugin {
            changes.push(format!(
                "relay.write_policy_plugin changed: {:?} -> {:?}{}",
                self.relay.write_policy_plugin,
                new.relay.write_policy_plugin,
                if new.relay.write_policy_plugin.is_empty() {
                    " (write-policy plugin now DISABLED)"
                } else {
                    ""
                },
            ));
        }
        if self.relay.write_policy_timeout_secs != new.relay.write_policy_timeout_secs {
            changes.push(format!(
                "relay.write_policy_timeout_secs changed: {} -> {}",
                self.relay.write_policy_timeout_secs, new.relay.write_policy_timeout_secs,
            ));
        }
        let fv = |c: &Config| {
            let f = &c.relay.filter_validation;
            (
                f.max_kinds_per_filter,
                f.allowed_kinds.clone(),
                f.require_author_or_tag,
                f.require_scoped_filters,
            )
        };
        if fv(self) != fv(new) {
            changes.push(format!(
                "relay.filter_validation changed: {:?} -> {:?}",
                self.relay.filter_validation, new.relay.filter_validation,
            ));
        }
        let ab = |c: &Config| {
            let a = &c.relay.abuse;
            (
                (
                    a.enabled,
                    a.ipv6_prefix_len,
                    a.connection_rate_per_second,
                    a.connection_burst,
                    a.event_rate_per_second,
                    a.event_burst,
                    a.pubkey_event_rate_per_second,
                    a.pubkey_event_burst,
                    a.req_rate_per_second,
                    a.req_burst,
                ),
                (
                    a.count_rate_per_second,
                    a.count_burst,
                    a.invalid_rate_per_second,
                    a.invalid_burst,
                    a.max_concurrent_historical_queries,
                    a.max_query_work,
                    a.max_stored_events,
                    a.max_stored_events_per_pubkey,
                    a.min_pow_difficulty,
                    a.per_connection.clone(),
                ),
            )
        };
        if ab(self) != ab(new) {
            changes.push(format!(
                "relay.abuse changed (enabled {} -> {}): {:?} -> {:?}",
                self.relay.abuse.enabled,
                new.relay.abuse.enabled,
                self.relay.abuse,
                new.relay.abuse,
            ));
        }
        // NIP-42 read-restriction scope: silently narrowing (or emptying) a
        // read class is fail-open, so name each kind that more readers can
        // read from now on.
        let prev = &self.relay.auth;
        let new_auth = &new.relay.auth;
        let (prev_reads, new_reads) = (self.read_restrictor(), new.read_restrictor());
        if prev.enabled != new_auth.enabled
            || prev.service_url != new_auth.service_url
            || prev_reads != new_reads
            || prev.read_policy != new_auth.read_policy
            || prev.write_policy != new_auth.write_policy
            || prev.inbox_kinds != new_auth.inbox_kinds
            || prev.accepted_kinds != new_auth.accepted_kinds
        {
            let mut widened: Vec<u64> = prev_reads
                .restricted_kinds()
                .filter(|&kind| new_reads.class(kind) < prev_reads.class(kind))
                .collect();
            widened.sort_unstable();
            widened.dedup();
            let mut note = String::new();
            if !widened.is_empty() {
                note.push_str(&format!(
                    " (read access WIDENED for kinds {widened:?}: readers the old classes refused can read them now)"
                ));
            }
            // Policies name who may read and write at all, so each change is
            // spelled out.
            for (what, old, new) in [
                ("read_policy", prev.read_policy, new_auth.read_policy),
                ("write_policy", prev.write_policy, new_auth.write_policy),
            ] {
                if old != new {
                    note.push_str(&format!(" ({what} {old} -> {new})"));
                }
            }
            changes.push(format!(
                "relay.auth changed: {:?} -> {:?}{}",
                prev, new_auth, note,
            ));
        }
        // NIP-62 vanish scope and NEG enable switch can also widen or narrow
        // who can delete/sync data.
        let prev62 = &self.relay.nip62;
        let new62 = &new.relay.nip62;
        if (prev62.enabled, prev62.service_url.clone())
            != (new62.enabled, new62.service_url.clone())
        {
            changes.push(format!("relay.nip62 changed: {:?} -> {:?}", prev62, new62,));
        }
        if self.relay.negentropy_enabled != new.relay.negentropy_enabled {
            changes.push(format!(
                "relay.negentropy_enabled changed: {} -> {}",
                self.relay.negentropy_enabled, new.relay.negentropy_enabled,
            ));
        }
        changes
    }

    /// The configuration this config's preset gives: the built-in defaults
    /// with the preset's overlay, before any file.
    pub fn preset_defaults(&self) -> Config {
        Config::parse_toml(&format!("preset = \"{}\"\n", self.preset))
            .expect("every built-in preset parses")
    }

    /// Warnings for every zero-valued guard that silently means "unlimited"
    /// (all editable live through the dashboard). Surfaced on reload so a
    /// single zero can't silently disarm a guard. A guard that the preset
    /// itself turns off, such as `relay.abuse.max_stored_events` in the
    /// public preset, is not warned about.
    pub fn zero_guard_warnings(&self) -> Vec<String> {
        let preset = self.preset_defaults();
        // Zero here, but not in the preset.
        let zeroed = |value: u64, preset: u64| value == 0 && preset != 0;
        let (a, p) = (&self.relay.abuse, &preset.relay.abuse);
        let mut warnings = Vec::new();
        if a.enabled {
            for (name, rate, burst, preset_rate, preset_burst) in [
                (
                    "connection",
                    a.connection_rate_per_second,
                    a.connection_burst,
                    p.connection_rate_per_second,
                    p.connection_burst,
                ),
                (
                    "event",
                    a.event_rate_per_second,
                    a.event_burst,
                    p.event_rate_per_second,
                    p.event_burst,
                ),
                (
                    "pubkey_event",
                    a.pubkey_event_rate_per_second,
                    a.pubkey_event_burst,
                    p.pubkey_event_rate_per_second,
                    p.pubkey_event_burst,
                ),
                (
                    "req",
                    a.req_rate_per_second,
                    a.req_burst,
                    p.req_rate_per_second,
                    p.req_burst,
                ),
                (
                    "count",
                    a.count_rate_per_second,
                    a.count_burst,
                    p.count_rate_per_second,
                    p.count_burst,
                ),
                (
                    "invalid",
                    a.invalid_rate_per_second,
                    a.invalid_burst,
                    p.invalid_rate_per_second,
                    p.invalid_burst,
                ),
                (
                    "per_connection.req",
                    a.per_connection.req_rate_per_second,
                    a.per_connection.req_burst,
                    p.per_connection.req_rate_per_second,
                    p.per_connection.req_burst,
                ),
                (
                    "per_connection.neg_msg",
                    a.per_connection.neg_msg_rate_per_second,
                    a.per_connection.neg_msg_burst,
                    p.per_connection.neg_msg_rate_per_second,
                    p.per_connection.neg_msg_burst,
                ),
                (
                    "per_connection.count",
                    a.per_connection.count_rate_per_second,
                    a.per_connection.count_burst,
                    p.per_connection.count_rate_per_second,
                    p.per_connection.count_burst,
                ),
            ] {
                if zeroed(rate.into(), preset_rate.into())
                    || zeroed(burst.into(), preset_burst.into())
                {
                    warnings.push(format!(
                        "relay.abuse {name} budget is zero — that token bucket is disabled (unlimited)"
                    ));
                }
            }
            if zeroed(a.max_query_work, p.max_query_work) {
                warnings.push("relay.abuse.max_query_work is zero — unlimited".to_string());
            }
            if zeroed(a.max_stored_events, p.max_stored_events) {
                warnings.push("relay.abuse.max_stored_events is zero — unlimited".to_string());
            }
            if zeroed(
                a.max_stored_events_per_pubkey,
                p.max_stored_events_per_pubkey,
            ) {
                warnings.push(
                    "relay.abuse.max_stored_events_per_pubkey is zero — unlimited".to_string(),
                );
            }
        }
        let r = &self.relay;
        let pr = &preset.relay;
        if zeroed(r.max_total_events_per_req, pr.max_total_events_per_req) {
            warnings.push("relay.max_total_events_per_req is zero — unlimited".to_string());
        }
        if zeroed(
            r.max_filter_bytes_per_connection as u64,
            pr.max_filter_bytes_per_connection as u64,
        ) {
            warnings.push(
                "relay.max_filter_bytes_per_connection is zero — live filter memory per connection is unlimited"
                    .to_string(),
            );
        }
        if zeroed(
            r.max_pending_outbound_bytes as u64,
            pr.max_pending_outbound_bytes as u64,
        ) {
            warnings.push(
                "relay.max_pending_outbound_bytes is zero — slow-client queue is unlimited"
                    .to_string(),
            );
        }
        if zeroed(r.handshake_timeout_secs, pr.handshake_timeout_secs) {
            warnings.push(
                "relay.handshake_timeout_secs is zero — pre-upgrade header read deadline disabled"
                    .to_string(),
            );
        }
        if zeroed(r.frame_read_timeout_secs, pr.frame_read_timeout_secs) {
            warnings.push(
                "relay.frame_read_timeout_secs is zero — partial-frame trickle guard disabled"
                    .to_string(),
            );
        }
        warnings
    }

    /// Replace this config with a freshly parsed one, keeping the values
    /// that cannot change at runtime. The frozen set matches golpe's
    /// `noReload` keys plus everything bound to a listener/socket/pool that
    /// only exists once at startup (documented as "restart required" in
    /// strfry.conf).
    pub fn apply_reload(&mut self, new: Config) {
        for change in self.security_scope_changes(&new) {
            tracing::warn!("config reload: {change}");
        }
        for warning in new.zero_guard_warnings() {
            tracing::warn!("config reload: {warning}");
        }
        for deprecation in &new.deprecations {
            tracing::warn!("config reload: {deprecation}");
        }
        let old = std::mem::replace(self, new);
        self.db = old.db;
        self.db_maxreaders = old.db_maxreaders;
        self.db_mapsize = old.db_mapsize;
        self.db_no_read_ahead = old.db_no_read_ahead;
        self.db_min_free_disk_bytes = old.db_min_free_disk_bytes;
        self.relay.bind = old.relay.bind;
        self.relay.port = old.relay.port;
        self.relay.nofiles = old.relay.nofiles;
        self.relay.max_websocket_payload_size = old.relay.max_websocket_payload_size;
        self.relay.auto_ping_seconds = old.relay.auto_ping_seconds;
        self.relay.enable_tcp_keepalive = old.relay.enable_tcp_keepalive;
        self.relay.compression_enabled = old.relay.compression_enabled;
        self.relay.compression_sliding_window = old.relay.compression_sliding_window;
        self.relay.ingester_threads = old.relay.ingester_threads;
        self.relay.req_worker_threads = old.relay.req_worker_threads;
        self.relay.req_monitor_threads = old.relay.req_monitor_threads;
        self.relay.negentropy_threads = old.relay.negentropy_threads;
        self.relay.unix = old.relay.unix;
        // Subscriber construction is process-global. Log encoding/filter
        // changes take effect after restart, while history bounds reload live.
        self.observability.log_format = old.observability.log_format;
        self.observability.log_filter = old.observability.log_filter;
    }
}

/// Ceiling for size-class settings whose values drive pre-allocation
/// (decompression buffers, websocket frame buffers). Matches the 16 MiB
/// hard cap the wok-db deletion/reindex/integrity paths already assume, so a
/// misconfigured (or dashboard-edited) value can't become an allocation
/// abort or a per-request memset amplifier.
pub const MAX_SIZE_CLASS_BYTES: usize = 16 * 1024 * 1024;

fn clamp_size_class(parsed: &mut TomlConfig) {
    let fields: [(&str, &mut usize); 3] = [
        ("events.max_event_size", &mut parsed.events.max_event_size),
        (
            "relay.max_websocket_payload_size",
            &mut parsed.relay.max_websocket_payload_size,
        ),
        (
            "relay.unix.max_frame_bytes",
            &mut parsed.relay.unix.max_frame_bytes,
        ),
    ];
    for (name, value) in fields {
        if *value > MAX_SIZE_CLASS_BYTES {
            tracing::warn!("{name} exceeds the {MAX_SIZE_CLASS_BYTES}-byte ceiling; clamping");
            *value = MAX_SIZE_CLASS_BYTES;
        }
    }
}

fn validate_admin_config(admin: &mut AdminConfig) -> Result<(), String> {
    if admin.auth_window_secs == 0 || admin.auth_window_secs > 300 {
        return Err("admin.auth_window_secs must be between 1 and 300".into());
    }
    if !admin.enabled {
        return Ok(());
    }
    let url = url::Url::parse(&admin.public_url)
        .map_err(|error| format!("admin.public_url is invalid: {error}"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err("admin.public_url must be an http(s) origin without credentials, path, query, or fragment".into());
    }
    // Bind NIP-98 to the browser-visible canonical origin: IDNs become
    // punycode and default ports/trailing slashes are removed consistently.
    admin.public_url = url.origin().ascii_serialization();
    if admin.pubkeys.is_empty() {
        return Err("admin.pubkeys must contain at least one admin when enabled".into());
    }
    for pubkey in &mut admin.pubkeys {
        let bytes = if pubkey.starts_with("npub1") {
            wok_event::decode_npub(pubkey)
                .map_err(|error| error.to_string())?
                .to_vec()
        } else {
            wok_event::from_lower_hex_exact(pubkey).map_err(|error| error.to_string())?
        };
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "admin pubkeys must be 32-byte lowercase hex or npub".to_string())?;
        *pubkey = hex::encode(bytes);
    }
    admin.pubkeys.sort();
    admin.pubkeys.dedup();
    Ok(())
}

fn tracing_subscriber_filter_syntax(filter: &str) -> Result<(), String> {
    if filter.trim().is_empty() {
        return Err("observability.log_filter cannot be empty".into());
    }
    // Keep this crate independent of tracing-subscriber. Its directive
    // grammar is intentionally simple enough to reject the common invalid
    // cases here; the CLI performs the authoritative parse at startup.
    if filter
        .split(',')
        .any(|directive| directive.trim().is_empty())
    {
        return Err("observability.log_filter contains an empty directive".into());
    }
    Ok(())
}

fn assign_u64(
    map: &BTreeMap<String, String>,
    key: &str,
    mut f: impl FnMut(u64) -> Result<(), String>,
) -> Result<(), String> {
    if let Some(v) = map.get(key) {
        let n: u64 = v
            .parse()
            .map_err(|_| format!("config key {key}: not a uint64: {v:?}"))?;
        f(n)?;
    }
    Ok(())
}

fn assign_bool(
    map: &BTreeMap<String, String>,
    key: &str,
    mut f: impl FnMut(bool),
) -> Result<(), String> {
    if let Some(v) = map.get(key) {
        match v.as_str() {
            "true" => f(true),
            "false" => f(false),
            _ => return Err(format!("config key {key}: not a bool: {v:?}")),
        }
    }
    Ok(())
}

/// `relay.unix.mode`: accepts octal (`0600`, `0o600`) or decimal (`384`).
/// Special bits (setuid/setgid/sticky) are meaningless-to-sloppy on a socket
/// node and masked off.
fn parse_mode(v: &str) -> Result<u32, String> {
    if let Some(o) = v.strip_prefix("0o").or_else(|| v.strip_prefix("0O")) {
        return u32::from_str_radix(o, 8)
            .map(mask_socket_mode)
            .map_err(|_| format!("invalid unix.mode: {v:?}"));
    }
    if v.len() > 1 && v.starts_with('0') {
        return u32::from_str_radix(&v[1..], 8)
            .map(mask_socket_mode)
            .map_err(|_| format!("invalid unix.mode: {v:?}"));
    }
    v.parse::<u32>()
        .map(mask_socket_mode)
        .map_err(|_| format!("invalid unix.mode: {v:?}"))
}

/// Mask a unix.mode value to permission bits, warning when special bits
/// (setuid/setgid/sticky) had to be dropped.
fn mask_socket_mode(mode: u32) -> u32 {
    let masked = mode & 0o777;
    if masked != mode {
        tracing::warn!("relay.unix.mode {mode:#o} has special bits; masking to {masked:#o}");
    }
    masked
}

fn parse_kinds(s: &str) -> Result<Vec<u64>, String> {
    if s.trim().is_empty() {
        return Ok(Vec::new());
    }
    s.split(',')
        .map(|p| {
            p.trim()
                .parse()
                .map_err(|_| format!("invalid kind entry: {p:?}"))
        })
        .collect()
}

fn parse_u32s(s: &str) -> Result<Vec<u32>, String> {
    if s.trim().is_empty() {
        return Ok(Vec::new());
    }
    s.split(',')
        .map(|p| {
            p.trim()
                .parse()
                .map_err(|_| format!("invalid id entry: {p:?}"))
        })
        .collect()
}

#[derive(Debug)]
enum HoconFrame {
    /// Named object (`relay {`) or an indexed array element (`0`).
    Object(String),
    /// Named array (`accept = [`). `next_index` numbers anonymous `{}` / `[]`
    /// children so `plugins.accept = [ { cmd = "x" } ]` flattens to
    /// `plugins.accept.0.cmd`.
    Array { name: String, next_index: usize },
}

impl HoconFrame {
    fn label(&self) -> &str {
        match self {
            Self::Object(name) | Self::Array { name, .. } => name,
        }
    }
}

fn hocon_prefix(stack: &[HoconFrame]) -> String {
    stack
        .iter()
        .map(HoconFrame::label)
        .filter(|name| !name.is_empty())
        .collect::<Vec<_>>()
        .join(".")
}

fn qualify_hocon(stack: &[HoconFrame], leaf: &str) -> String {
    let prefix = hocon_prefix(stack);
    if prefix.is_empty() {
        leaf.to_string()
    } else {
        format!("{prefix}.{leaf}")
    }
}

fn push_anonymous(stack: &mut Vec<HoconFrame>, frame: impl FnOnce(String) -> HoconFrame) {
    let name = match stack.last_mut() {
        Some(HoconFrame::Array { next_index, .. }) => {
            let idx = *next_index;
            *next_index += 1;
            idx.to_string()
        }
        _ => String::new(),
    };
    stack.push(frame(name));
}

fn open_hocon_block(stack: &mut Vec<HoconFrame>, stmt: &str, opener: char) -> bool {
    let Some(name) = stmt.strip_suffix(opener) else {
        return false;
    };
    let name = name.trim().trim_end_matches('=').trim();
    if opener == '{' {
        if name.is_empty() {
            push_anonymous(stack, HoconFrame::Object);
        } else {
            stack.push(HoconFrame::Object(name.to_string()));
        }
    } else if name.is_empty() {
        push_anonymous(stack, |name| HoconFrame::Array {
            name,
            next_index: 0,
        });
    } else {
        stack.push(HoconFrame::Array {
            name: name.to_string(),
            next_index: 0,
        });
    }
    true
}

fn close_hocon_frame(
    stack: &mut Vec<HoconFrame>,
    lineno: usize,
    closer: char,
    expect_array: bool,
) -> Result<(), String> {
    match stack.pop() {
        Some(HoconFrame::Array { .. }) if expect_array => Ok(()),
        Some(HoconFrame::Object(_)) if !expect_array => Ok(()),
        Some(frame) => {
            let kind = if matches!(frame, HoconFrame::Array { .. }) {
                "array"
            } else {
                "block"
            };
            let name = frame.label();
            let where_ = if name.is_empty() {
                format!("open {kind}")
            } else {
                format!("open {kind} {name}")
            };
            Err(format!(
                "line {}: unmatched '{closer}' ({where_})",
                lineno + 1
            ))
        }
        None => Err(format!("line {}: unmatched '{closer}'", lineno + 1)),
    }
}

fn take_array_index(stack: &mut [HoconFrame]) -> Option<usize> {
    match stack.last_mut() {
        Some(HoconFrame::Array { next_index, .. }) => {
            let idx = *next_index;
            *next_index += 1;
            Some(idx)
        }
        _ => None,
    }
}

fn strip_trailing_comma(mut val: String) -> String {
    if val.ends_with(',') {
        val.pop();
    }
    val
}

/// Minimal HOCON-subset tokenizer: quote-aware comment stripping (`#` and
/// `//`), inline `{`/`}`/`[`/`]` handling, anonymous object blocks in
/// arrays, and quoted string values with backslash escapes.
fn parse_hocon(text: &str) -> Result<BTreeMap<String, String>, String> {
    let mut map = BTreeMap::new();
    let mut stack: Vec<HoconFrame> = Vec::new();
    for (lineno, raw) in text.lines().enumerate() {
        for stmt in split_statements(raw) {
            let stmt = stmt.trim();
            if stmt.is_empty() || stmt == "," {
                continue;
            }
            if stmt == "}" {
                close_hocon_frame(&mut stack, lineno, '}', false)?;
                continue;
            }
            if stmt == "]" {
                close_hocon_frame(&mut stack, lineno, ']', true)?;
                continue;
            }
            if open_hocon_block(&mut stack, stmt, '{') || open_hocon_block(&mut stack, stmt, '[') {
                continue;
            }
            if let Some((k, v)) = stmt.split_once('=') {
                let key = qualify_hocon(&stack, k.trim());
                let val = unquote(&strip_trailing_comma(v.trim().to_string()))?;
                map.insert(key, val);
                continue;
            }
            if let Some(idx) = take_array_index(&mut stack) {
                let key = qualify_hocon(&stack, &idx.to_string());
                let val = unquote(&strip_trailing_comma(stmt.to_string()))?;
                map.insert(key, val);
                continue;
            }
            return Err(format!("line {}: cannot parse {stmt:?}", lineno + 1));
        }
    }
    if !stack.is_empty() {
        return Err(format!("unclosed block: {}", hocon_prefix(&stack)));
    }
    Ok(map)
}

/// Split a line into statements on `{`, `}`, `[`, and `]` (kept as their
/// own statements), honoring quoted strings and `#`/`//` comments.
fn split_statements(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_string = false;
    let mut escaped = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if in_string {
            cur.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                cur.push(c);
            }
            '#' => break,
            '/' if chars.peek() == Some(&'/') => break,
            '{' | '[' => {
                // Opener stays glued to its name: "relay {" / "accept = [".
                cur.push(c);
                if !cur.trim().is_empty() {
                    out.push(cur.trim().to_string());
                }
                cur.clear();
            }
            '}' | ']' => {
                if !cur.trim().is_empty() {
                    out.push(cur.trim().to_string());
                }
                cur.clear();
                out.push(c.to_string());
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

fn unquote(v: &str) -> Result<String, String> {
    if v.len() >= 2 && v.starts_with('"') {
        if !v.ends_with('"') {
            return Err(format!("unterminated string value: {v:?}"));
        }
        let inner = &v[1..v.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                match chars.next() {
                    Some('n') => out.push('\n'),
                    Some('t') => out.push('\t'),
                    Some('r') => out.push('\r'),
                    Some(other) => out.push(other),
                    None => return Err(format!("trailing backslash in value: {v:?}")),
                }
            } else {
                out.push(c);
            }
        }
        Ok(out)
    } else {
        Ok(v.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_class_settings_are_clamped_to_ceiling() {
        let c = Config::parse_toml(
            r#"
            [events]
            max_event_size = 4611686018427387904

            [relay]
            max_websocket_payload_size = 1073741824

            [relay.unix]
            max_frame_bytes = 33554432
            "#,
        )
        .unwrap();
        assert_eq!(c.events.max_event_size, MAX_SIZE_CLASS_BYTES);
        assert_eq!(c.relay.max_websocket_payload_size, MAX_SIZE_CLASS_BYTES);
        assert_eq!(c.relay.unix.max_frame_bytes, MAX_SIZE_CLASS_BYTES);
        // Values under the ceiling pass through untouched.
        let c = Config::parse_toml("[events]\nmax_event_size = 70000\n").unwrap();
        assert_eq!(c.events.max_event_size, 70000);
    }

    #[test]
    fn parses_nested() {
        let c = Config::parse_strfry(
            r#"
            db = "/tmp/x"
            relay {
                port = 9000
                unix {
                    enabled = true
                    path = "/tmp/wok.sock"
                }
            }
            "#,
        )
        .unwrap();
        assert_eq!(c.db, PathBuf::from("/tmp/x"));
        assert_eq!(c.relay.port, 9000);
        assert!(c.relay.unix.enabled);
    }

    #[test]
    fn comment_chars_inside_quotes_are_kept() {
        let c = Config::parse_strfry(
            r#"
            relay {
                info {
                    description = "a #b // c"
                }
            }
            "#,
        )
        .unwrap();
        assert_eq!(c.relay.info.description, "a #b // c");
    }

    #[test]
    fn inline_braces_and_comments() {
        let c = Config::parse_strfry("relay { port = 9001 } // trailing\n").unwrap();
        assert_eq!(c.relay.port, 9001);
        let c = Config::parse_strfry("relay {\n port = 9002\n} # close\n").unwrap();
        assert_eq!(c.relay.port, 9002);
    }

    #[test]
    fn strict_value_errors() {
        assert!(Config::parse_strfry("relay { port = \"abc\" }").is_err());
        assert!(Config::parse_strfry("relay { port = 70000 }").is_err());
        assert!(Config::parse_strfry("relay { auth { enabled = \"yes\" } }").is_err());
        assert!(Config::parse_strfry("relay { port = 1").is_err());
    }

    #[test]
    fn strfry_translation_reports_every_supplied_leaf_key() {
        let translation = Config::translate_strfry(
            "db = \"legacy\"\nrelay { port = 8888\n info { nips = \"1,2\" }\n mystery = true }\n",
        )
        .unwrap();
        assert_eq!(translation.config.relay.port, 8888);
        assert_eq!(translation.translated_keys, ["db", "relay.port"]);
        assert_eq!(
            translation.ignored_keys,
            ["relay.info.nips", "relay.mystery"]
        );
    }

    #[test]
    fn anonymous_objects_in_plugin_arrays_are_parsed_and_ignored() {
        let translation = Config::translate_strfry(
            r#"
            db = "/tmp/db"
            relay {
                port = 7777
                writePolicy {
                    plugin = "/bin/true"
                }
            }
            plugins {
                accept = [
                    {
                        cmd = "./whitelist.js"
                    },
                    { cmd = "./rate-limit.js" }
                ]
            }
            "#,
        )
        .unwrap();
        assert_eq!(translation.config.relay.port, 7777);
        assert_eq!(translation.config.relay.write_policy_plugin, "/bin/true");
        assert_eq!(
            translation.translated_keys,
            ["db", "relay.port", "relay.writePolicy.plugin"]
        );
        assert_eq!(
            translation.ignored_keys,
            ["plugins.accept.0.cmd", "plugins.accept.1.cmd"]
        );

        let inline = Config::translate_strfry(
            r#"plugins.accept = [ { cmd = "./whitelist.js" } ]
               relay { port = 9000 }
               "#,
        )
        .unwrap();
        assert_eq!(inline.config.relay.port, 9000);
        assert!(inline.config.relay.write_policy_plugin.is_empty());
        assert_eq!(inline.ignored_keys, ["plugins.accept.0.cmd"]);
    }

    #[test]
    fn hocon_array_delimiters_must_match() {
        assert!(
            Config::parse_strfry("plugins { accept = [ { cmd = \"x\" } }\n")
                .unwrap_err()
                .contains("unmatched '}'")
        );
        assert!(Config::parse_strfry("relay { port = 1 ]\n")
            .unwrap_err()
            .contains("unmatched ']'"));
        assert!(Config::parse_strfry("plugins { accept = [\n")
            .unwrap_err()
            .contains("unclosed block"));
    }

    #[test]
    fn unix_mode_octal_and_decimal() {
        assert_eq!(parse_mode("0600").unwrap(), 0o600);
        assert_eq!(parse_mode("0o600").unwrap(), 0o600);
        assert_eq!(parse_mode("384").unwrap(), 0o600);
        assert!(parse_mode("nope").is_err());
    }

    #[test]
    fn full_strfry_style_config() {
        let c = Config::parse_strfry(
            r#"
            db = "/tmp/db"
            dbParams {
                maxreaders = 300
                mapsize = 10995116277760
                noReadAhead = false
            }
            events {
                maxEventSize = 70000
            }
            relay {
                bind = "0.0.0.0"
                port = 7777
                nofiles = 1000
                realIpHeader = "x-real-ip"
                auth {
                    enabled = true
                    serviceUrl = "wss://relay.example.com/"
                    restrictedReadKinds = "4,1059"
                    restrictReadToInvolvedPubkey = true
                }
                info {
                    name = "test"
                    pubkey = "deadbeef"
                    self = "cafe"
                    contact = "mailto:x@example.com"
                    icon = "https://example.com/i.png"
                    banner = "https://example.com/b.png"
                    privacy = "https://example.com/p"
                    terms = "https://example.com/t"
                    nips = "[1,2]"
                }
                maxReqFilterSize = 7
                maxTotalEventsPerReq = 4321
                autoPingSeconds = 30
                enableTcpKeepalive = true
                queryTimesliceBudgetMicroseconds = 5000
                maxTagsPerFilter = 9
                maxPendingOutboundBytes = 1024
                writePolicy {
                    plugin = "/bin/true"
                    timeoutSeconds = 3
                }
                compression {
                    enabled = false
                    slidingWindow = false
                }
                logging {
                    dumpInAll = true
                    invalidEvents = false
                }
                numThreads {
                    ingester = 4
                    reqWorker = 5
                    reqMonitor = 6
                    negentropy = 7
                }
                negentropy {
                    enabled = false
                    maxSyncEvents = 42
                }
                filterValidation {
                    enabled = true
                    maxFiltersPerReq = 11
                    minFiltersPerReq = 2
                    maxKindsPerFilter = 12
                    allowedKinds = "1,6"
                    requireAuthorOrTag = true
                }
                unix {
                    enabled = true
                    path = "/tmp/w.sock"
                    mode = 0600
                    owner = "alice"
                    group = "staff"
                    maxFrameBytes = 4096
                    maxPendingOutboundBytes = 2048
                    authUids = "501,502"
                    authGids = "20"
                }
            }
            "#,
        )
        .unwrap();
        assert_eq!(c.db_maxreaders, 300);
        assert_eq!(c.events.max_event_size, 70000);
        assert_eq!(c.relay.port, 7777);
        assert_eq!(c.relay.nofiles, 1000);
        assert_eq!(c.relay.real_ip_header, "x-real-ip");
        assert_eq!(c.relay.auth.recipient_only_kinds, vec![4, 1059]);
        assert_eq!(c.relay.info.pubkey, "deadbeef");
        assert_eq!(c.relay.info.self_pk, "cafe");
        assert_eq!(c.relay.info.terms, "https://example.com/t");
        assert_eq!(c.relay.max_filters_per_req, 7);
        assert_eq!(c.relay.max_req_filter_size, 262_144);
        assert_eq!(c.relay.max_total_events_per_req, 4321);
        assert_eq!(c.relay.auto_ping_seconds, 30);
        assert!(c.relay.enable_tcp_keepalive);
        assert_eq!(c.relay.query_timeslice_budget_us, 5000);
        assert_eq!(c.relay.max_tags_per_filter, 9);
        assert_eq!(c.relay.write_policy_timeout_secs, 3);
        assert!(!c.relay.compression_enabled);
        assert!(c.relay.dump_in_all);
        assert!(!c.relay.invalid_events);
        assert_eq!(c.relay.ingester_threads, 4);
        assert_eq!(c.relay.req_worker_threads, 5);
        assert_eq!(c.relay.req_monitor_threads, 6);
        assert_eq!(c.relay.negentropy_threads, 7);
        assert!(!c.relay.negentropy_enabled);
        assert_eq!(c.relay.max_sync_events, 42);
        // The enabled filterValidation section keeps its rules; its cap of 11
        // filters is above maxReqFilterSize's 7.
        assert_eq!(c.relay.filter_validation.max_kinds_per_filter, 12);
        assert_eq!(c.relay.filter_validation.allowed_kinds, "1,6");
        assert!(c.relay.filter_validation.require_author_or_tag);
        assert_eq!(c.relay.unix.mode, 0o600);
        assert_eq!(c.relay.unix.owner, "alice");
        assert_eq!(c.relay.unix.auth_uids, vec![501, 502]);
        assert_eq!(c.relay.unix.auth_gids, vec![20]);
        assert_eq!(c.relay.unix.max_pending_outbound_bytes, 2048);
    }

    #[test]
    fn strfry_read_restrictions_become_read_classes() {
        let involved = Config::translate_strfry(
            "relay { auth { restrictedReadKinds = \"4,1059\"\n \
             restrictReadToInvolvedPubkey = true } }",
        )
        .unwrap()
        .config;
        assert_eq!(involved.relay.auth.recipient_only_kinds, [4, 1059]);
        assert!(involved.relay.auth.authenticated_kinds.is_empty());
        assert!(involved.deprecations.is_empty());
        // Without the involved-pubkey rule, any authenticated reader, and
        // never an anonymous one.
        let any = Config::translate_strfry(
            "relay { auth { restrictedReadKinds = \"4,1059\"\n \
             restrictReadToInvolvedPubkey = false } }",
        )
        .unwrap()
        .config;
        assert!(any.relay.auth.recipient_only_kinds.is_empty());
        assert_eq!(any.relay.auth.authenticated_kinds, [4, 1059]);
        assert_eq!(any.deprecations.len(), 1);
        assert!(any.deprecations[0].contains("authenticated_kinds"));
        // Neither touches NIP-78's owner-only kinds, which stay the stricter
        // class for a kind listed in both, as the warning says.
        assert_eq!(any.relay.auth.owner_only_kinds, [78, 30078]);
        assert!(!any.deprecations[0].contains("owner_only_kinds"));
        for involved in [true, false] {
            let app_data = Config::translate_strfry(&format!(
                "relay {{ auth {{ restrictedReadKinds = \"4,30078\"\n \
                 restrictReadToInvolvedPubkey = {involved} }} }}"
            ))
            .unwrap()
            .config;
            assert_eq!(app_data.deprecations.len(), 1, "{involved}");
            assert!(
                app_data.deprecations[0]
                    .contains("Kinds [30078] are also in relay.auth.owner_only_kinds"),
                "{:?}",
                app_data.deprecations
            );
            assert_eq!(
                app_data.read_restrictor().class(30078),
                crate::restrict::ReadClass::Owner
            );
        }
    }

    #[test]
    fn strfry_filter_validation_applies_only_when_enabled() {
        // strfry's stock section is disabled: no rules, whatever it pins.
        let stock = Config::translate_strfry(
            "relay { filterValidation { enabled = false\n maxFiltersPerReq = 3\n \
             minFiltersPerReq = 1\n maxKindsPerFilter = 3\n requireAuthorOrTag = true } }",
        )
        .unwrap();
        assert_eq!(stock.config.relay.max_filters_per_req, 200);
        let rules = &stock.config.relay.filter_validation;
        assert_eq!(rules.max_kinds_per_filter, 0);
        assert!(!rules.require_author_or_tag);
        assert!(stock
            .ignored_keys
            .contains(&"relay.filterValidation.minFiltersPerReq".to_string()));
        // Enabled, it keeps strfry's defaults for what it leaves out, and its
        // filter cap becomes the relay's.
        let enabled = Config::translate_strfry("relay { filterValidation { enabled = true } }")
            .unwrap()
            .config;
        assert_eq!(enabled.relay.max_filters_per_req, 3);
        assert_eq!(enabled.relay.filter_validation.max_kinds_per_filter, 3);
        assert!(enabled.deprecations.is_empty());
        // Its zero kind cap no longer refuses kind filters, with a warning.
        let zero = Config::translate_strfry(
            "relay { filterValidation { enabled = true\n maxKindsPerFilter = 0 } }",
        )
        .unwrap()
        .config;
        assert_eq!(zero.relay.filter_validation.max_kinds_per_filter, 0);
        assert_eq!(zero.deprecations.len(), 1);
        assert!(zero.deprecations[0]
            .starts_with("relay.filterValidation.maxKindsPerFilter = 0 in an enabled section"));
    }

    #[test]
    fn reload_keeps_frozen_keys() {
        let mut cfg = Config::parse_toml(
            "[relay]\nport = 7777\nmax_filter_limit = 500\n\n[observability]\nlog_format = \"pretty\"\nhistory_max_points = 10\n",
        )
        .unwrap();
        let new = Config::parse_toml(
            "[relay]\nport = 9999\nmax_filter_limit = 123\n\n[observability]\nlog_format = \"json\"\nhistory_max_points = 20\n",
        )
        .unwrap();
        cfg.apply_reload(new);
        assert_eq!(cfg.relay.port, 7777, "port is restart-required");
        assert_eq!(cfg.relay.max_filter_limit, 123, "limits reload live");
        assert_eq!(cfg.observability.log_format, LogFormat::Pretty);
        assert_eq!(cfg.observability.history_max_points, 20);
    }

    #[test]
    fn observability_history_is_hard_bounded() {
        assert!(
            Config::parse_toml("[observability]\nhistory_max_points = 100001\n")
                .unwrap_err()
                .contains("cannot exceed")
        );
        assert!(
            Config::parse_toml("[observability]\nhistory_interval_secs = 0\n")
                .unwrap_err()
                .contains("at least 1")
        );
    }

    #[test]
    fn security_scope_changes_flag_silent_reversions() {
        let full = Config::parse_toml(
            r#"
            [relay]
            write_policy_plugin = "/usr/local/bin/policy"
            max_filter_limit = 500

            [relay.filter_validation]
            enabled = true
            "#,
        )
        .unwrap();
        // Identical reload: nothing to report.
        let same = Config::parse_toml(
            r#"
            [relay]
            write_policy_plugin = "/usr/local/bin/policy"
            max_filter_limit = 500

            [relay.filter_validation]
            enabled = true
            "#,
        )
        .unwrap();
        assert!(full.security_scope_changes(&same).is_empty());
        // A valid-but-partial file reverts the plugin and filter validation
        // to defaults; the diff must surface both.
        let partial = Config::parse_toml("[relay]\nmax_filter_limit = 500\n").unwrap();
        let changes = full.security_scope_changes(&partial);
        assert!(
            changes
                .iter()
                .any(|c| c.contains("write_policy_plugin") && c.contains("DISABLED")),
            "{changes:?}"
        );
        assert!(
            changes.iter().any(|c| c.contains("filter_validation")),
            "{changes:?}"
        );
        // Zeroed abuse budgets are called out as well.
        let zeroed = Config::parse_toml("[relay.abuse]\nevent_rate_per_second = 0\n").unwrap();
        let changes = full.security_scope_changes(&zeroed);
        assert!(changes.iter().any(|c| c.contains("abuse")), "{changes:?}");
        // So is keying each IPv6 address on its own, which multiplies a
        // network's budgets.
        let per_address = Config::parse_toml("[relay.abuse]\nipv6_prefix_len = 128\n").unwrap();
        let changes = Config::default().security_scope_changes(&per_address);
        assert_eq!(changes.len(), 1, "{changes:?}");
        assert!(changes[0].contains("ipv6_prefix_len: 128"), "{changes:?}");
    }

    #[test]
    fn security_scope_changes_flags_auth_nip62_and_negentropy() {
        let base = Config::parse_toml(
            r#"
            [relay]
            negentropy_enabled = true

            [relay.auth]
            enabled = true
            recipient_only_kinds = [4]

            [relay.nip62]
            enabled = true
            "#,
        )
        .unwrap();
        // Identical reload: nothing to report.
        let same = Config::parse_toml(
            r#"
            [relay]
            negentropy_enabled = true

            [relay.auth]
            enabled = true
            recipient_only_kinds = [4]

            [relay.nip62]
            enabled = true
            "#,
        )
        .unwrap();
        assert!(base.security_scope_changes(&same).is_empty());
        // Emptying recipient_only_kinds makes kind 4 public (the access scope
        // widens), and the note must pin the exact kind.
        let widened = Config::parse_toml(
            "[relay.auth]
recipient_only_kinds = []
",
        )
        .unwrap();
        let changes = base.security_scope_changes(&widened);
        assert!(
            changes
                .iter()
                .any(|c| c.contains("relay.auth changed") && c.contains("WIDENED for kinds [4]")),
            "{changes:?}"
        );
        // Moving a kind to a class with more readers widens it too, and a
        // stricter class does not.
        let authenticated = Config::parse_toml(
            "[relay.auth]
recipient_only_kinds = []
authenticated_kinds = [4]
",
        )
        .unwrap();
        let changes = base.security_scope_changes(&authenticated);
        assert!(
            changes.iter().any(|c| c.contains("WIDENED for kinds [4]")),
            "{changes:?}"
        );
        let owner = Config::parse_toml(
            "[relay.auth]
owner_only_kinds = [4, 78, 30078]
",
        )
        .unwrap();
        let changes = base.security_scope_changes(&owner);
        assert!(
            changes
                .iter()
                .any(|c| c.contains("relay.auth changed") && !c.contains("WIDENED")),
            "{changes:?}"
        );
        // Omitting [relay.auth] merges factory defaults [4, 1059, 21059];
        // starting from a superset the defaults would drop ([4, 44, 1059]) is the
        // issue's omit-reverts-to-defaults fail-open path.
        let superset = Config::parse_toml(
            "[relay.auth]
recipient_only_kinds = [4, 44, 1059]
",
        )
        .unwrap();
        let partial = Config::parse_toml(
            "[relay]
negentropy_enabled = true
",
        )
        .unwrap();
        let changes = superset.security_scope_changes(&partial);
        assert!(
            changes
                .iter()
                .any(|c| c.contains("relay.auth changed") && c.contains("WIDENED for kinds [44]")),
            "{changes:?}"
        );
        // Toggling nip62 or negentropy flags is reported too.
        let no62 = Config::parse_toml("[relay.nip62]\nenabled = false\n").unwrap();
        let changes = base.security_scope_changes(&no62);
        assert!(
            changes.iter().any(|c| c.contains("relay.nip62 changed")),
            "{changes:?}"
        );
        let no_neg = Config::parse_toml("[relay]\nnegentropy_enabled = false\n").unwrap();
        let changes = base.security_scope_changes(&no_neg);
        assert!(
            changes
                .iter()
                .any(|c| c.contains("negentropy_enabled changed")),
            "{changes:?}"
        );
    }

    #[test]
    fn per_connection_budgets_have_their_own_table() {
        let cfg = Config::parse_toml(
            "[relay.abuse]\nreq_burst = 300\n\n\
             [relay.abuse.per_connection]\nreq_burst = 60\nauthenticated_multiplier = 2\n",
        )
        .unwrap();
        let abuse = &cfg.relay.abuse;
        assert_eq!((abuse.req_rate_per_second, abuse.req_burst), (200, 300));
        let own = &abuse.per_connection;
        assert_eq!((own.req_rate_per_second, own.req_burst), (20, 60));
        assert_eq!((own.neg_msg_rate_per_second, own.neg_msg_burst), (50, 200));
        assert_eq!((own.count_rate_per_second, own.count_burst), (5, 20));
        assert_eq!(own.authenticated_multiplier, 2);
        // 0 would make every AUTHed budget zero, which disables the bucket.
        let zero =
            Config::parse_toml("[relay.abuse.per_connection]\nauthenticated_multiplier = 0\n")
                .unwrap_err();
        assert!(zero.contains("at least 1"), "{zero}");
        let unknown =
            Config::parse_toml("[relay.abuse.per_connection]\nevent_burst = 5\n").unwrap_err();
        assert!(unknown.contains("event_burst"), "{unknown}");
    }

    #[test]
    fn ipv6_prefix_len_is_validated() {
        assert_eq!(Config::default().relay.abuse.ipv6_prefix_len, 64);
        for len in [1, 48, 128] {
            let cfg =
                Config::parse_toml(&format!("[relay.abuse]\nipv6_prefix_len = {len}\n")).unwrap();
            assert_eq!(cfg.relay.abuse.ipv6_prefix_len, len);
        }
        let zero = Config::parse_toml("[relay.abuse]\nipv6_prefix_len = 0\n").unwrap_err();
        assert!(zero.contains("from 1 to 128"), "{zero}");
        let wide = Config::parse_toml("[relay.abuse]\nipv6_prefix_len = 129\n").unwrap_err();
        assert!(wide.contains("from 1 to 128"), "{wide}");
    }

    #[test]
    fn real_ip_header_warning_names_the_budget_risk_of_each_setup() {
        let addrs = |list: &[&str]| -> Vec<SocketAddr> {
            list.iter().map(|addr| addr.parse().unwrap()).collect()
        };
        let unset = Config::default();
        // Only this host or a private network can connect: likely a proxy.
        for local in [
            &["127.0.0.1:7777"][..],
            &["127.0.0.1:7777", "[::1]:7777"],
            &["10.0.0.5:7777"],
            &["192.168.1.2:7777"],
            &["[fd00::5]:7777"],
            &["[fe80::1]:7777"],
        ] {
            let warning = unset.real_ip_header_warning(&addrs(local)).unwrap();
            assert!(
                warning.contains("relay.real_ip_header is unset"),
                "{warning}"
            );
            assert!(warning.contains(&local[0].to_string()), "{warning}");
        }
        // Clients can connect directly, so their addresses are their own.
        for direct in [
            &["0.0.0.0:7777"][..],
            &["[::]:7777"],
            &["203.0.113.9:7777"],
            &["127.0.0.1:7777", "[2001:db8::1]:7777"],
            &[],
        ] {
            assert_eq!(unset.real_ip_header_warning(&addrs(direct)), None);
        }
        let mut set = Config::default();
        set.relay.real_ip_header = "x-real-ip".into();
        for listening in [&["127.0.0.1:7777"][..], &["0.0.0.0:7777"]] {
            let warning = set.real_ip_header_warning(&addrs(listening)).unwrap();
            assert!(
                warning.starts_with("relay.real_ip_header = \"x-real-ip\" is trusted"),
                "{warning}"
            );
            assert!(
                warning.ends_with(
                    "could send a new address with each connection to escape those \
                     budgets, or send another client's address to spend that client's budgets"
                ),
                "{warning}"
            );
        }
    }

    #[test]
    fn zero_guard_warnings_cover_each_unlimited_zero() {
        // The defaults warn about nothing, though the public preset turns
        // the global storage cap off.
        assert_eq!(Config::default().relay.abuse.max_stored_events, 0);
        assert!(Config::default().zero_guard_warnings().is_empty());
        // So does a file that repeats that 0. A guard is warned about only
        // where the file zeroes one its preset keeps.
        let cfg = Config::parse_toml("[relay.abuse]\nmax_stored_events = 0\n").unwrap();
        assert!(cfg.zero_guard_warnings().is_empty());
        for field in [
            "connection_rate_per_second",
            "connection_burst",
            "event_rate_per_second",
            "event_burst",
            "pubkey_event_rate_per_second",
            "pubkey_event_burst",
            "req_rate_per_second",
            "req_burst",
            "count_rate_per_second",
            "count_burst",
            "invalid_rate_per_second",
            "invalid_burst",
            "max_query_work",
            "max_stored_events_per_pubkey",
        ] {
            let cfg = Config::parse_toml(&format!("[relay.abuse]\n{field} = 0\n")).unwrap();
            assert!(
                !cfg.zero_guard_warnings().is_empty(),
                "{field} = 0 should warn"
            );
        }
        for field in [
            "req_rate_per_second",
            "req_burst",
            "neg_msg_rate_per_second",
            "neg_msg_burst",
            "count_rate_per_second",
            "count_burst",
        ] {
            let cfg = Config::parse_toml(&format!("[relay.abuse.per_connection]\n{field} = 0\n"))
                .unwrap();
            let warnings = cfg.zero_guard_warnings();
            assert!(
                warnings.iter().any(|w| w.contains("per_connection")),
                "per_connection.{field} = 0 should warn: {warnings:?}"
            );
        }
        for field in [
            "max_total_events_per_req",
            "max_filter_bytes_per_connection",
            "max_pending_outbound_bytes",
            "handshake_timeout_secs",
            "frame_read_timeout_secs",
        ] {
            let cfg = Config::parse_toml(&format!("[relay]\n{field} = 0\n")).unwrap();
            assert!(
                !cfg.zero_guard_warnings().is_empty(),
                "{field} = 0 should warn"
            );
        }
        // With abuse protection disabled entirely, zero budgets are moot.
        let cfg = Config::parse_toml("[relay.abuse]\nenabled = false\nevent_rate_per_second = 0\n")
            .unwrap();
        assert!(cfg.zero_guard_warnings().is_empty());
    }

    #[test]
    fn unix_mode_is_masked_to_permission_bits() {
        assert_eq!(parse_mode("0o600").unwrap(), 0o600);
        assert_eq!(parse_mode("0600").unwrap(), 0o600);
        assert_eq!(parse_mode("384").unwrap(), 0o600);
        assert_eq!(parse_mode("0o1130").unwrap(), 0o130);
        assert_eq!(parse_mode("0o4755").unwrap(), 0o755);
        let c = Config::parse_toml("[relay.unix]\nmode = 0o5610\n").unwrap();
        assert_eq!(c.relay.unix.mode, 0o610);
    }

    #[test]
    fn enabled_admin_requires_a_clean_origin_and_normalizes_pubkeys() {
        let key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let cfg = Config::parse_toml(&format!(
            "[admin]\nenabled = true\npublic_url = \"https://relay.example/\"\npubkeys = [\"{key}\", \"{key}\"]\n"
        ))
        .unwrap();
        assert_eq!(cfg.admin.public_url, "https://relay.example");
        assert_eq!(cfg.admin.pubkeys, vec![key]);

        let canonical = Config::parse_toml(&format!(
            "[admin]\nenabled = true\npublic_url = \"https://bücher.example:443/\"\npubkeys = [\"{key}\"]\n"
        ))
        .unwrap();
        assert_eq!(canonical.admin.public_url, "https://xn--bcher-kva.example");

        assert!(Config::parse_toml(&format!(
            "[admin]\nenabled = true\npublic_url = \"https://relay.example/admin\"\npubkeys = [\"{key}\"]\n"
        ))
        .unwrap_err()
        .contains("origin"));
        assert!(Config::parse_toml(
            "[admin]\nenabled = true\npublic_url = \"https://relay.example\"\npubkeys = []\n"
        )
        .unwrap_err()
        .contains("at least one admin"));
    }

    #[test]
    fn read_classes_are_private_by_default_but_can_be_emptied() {
        let auth = Config::default().relay.auth;
        assert_eq!(auth.recipient_only_kinds, vec![4, 1059, 21059]);
        assert_eq!(auth.owner_only_kinds, vec![78, 30078]);
        assert!(auth.authenticated_kinds.is_empty());
        let c =
            Config::parse_toml("[relay.auth]\nrecipient_only_kinds = []\nowner_only_kinds = []\n")
                .unwrap();
        assert_eq!(
            c.read_restrictor(),
            crate::restrict::ReadRestrictor::default()
        );
        assert_eq!(c.auth_configuration_warning(), None);
    }

    #[test]
    fn timestamp_windows_follow_the_kind() {
        let mut c = Config::default();
        assert_eq!(c.events.reject_older_than_secs, 0, "no lower bound");
        c.events.reject_older_than_secs = 86_400;
        // A set bound spares replaceable, addressable, deletion and vanish
        // events.
        for kind in [0, 3, 5, 62, 10_000, 19_999, 30_000, 39_999] {
            let policy = c.timestamp_policy_for_kind(kind);
            assert_eq!(policy.reject_older_than_secs, 0, "kind {kind}");
        }
        for kind in [1, 4, 41, 1059, 9_999, 40_000] {
            let policy = c.timestamp_policy_for_kind(kind);
            assert_eq!(policy.reject_older_than_secs, 86_400, "kind {kind}");
        }
        assert_eq!(
            c.timestamp_policy_for_kind(20_001)
                .reject_ephemeral_older_than_secs,
            60
        );
        let wrap = c.timestamp_policy_for_kind(21059);
        assert_eq!(wrap.reject_ephemeral_older_than_secs, 3 * 86_400);
        assert_eq!(wrap.reject_newer_than_secs, 900);
        // The gift-wrap allowance is a constant, as read visibility assumes.
        c.events.reject_ephemeral_older_than_secs = 7 * 86_400;
        let wrap = c.timestamp_policy_for_kind(21059);
        assert_eq!(wrap.reject_ephemeral_older_than_secs, 3 * 86_400);
        // NIP-42: AUTH has its own window, whatever [events] says.
        c.events.reject_newer_than_secs = 1;
        c.events.reject_ephemeral_older_than_secs = 1;
        let auth = c.timestamp_policy_for_kind(wok_event::AUTH_KIND);
        assert_eq!(auth.reject_newer_than_secs, 600);
        assert_eq!(auth.reject_ephemeral_older_than_secs, 600);
    }

    #[test]
    fn restricted_reads_report_unusable_auth() {
        let mut c = Config::default();
        let warning = c.auth_configuration_warning().unwrap();
        assert!(warning.contains("service_url"), "{warning}");
        assert!(warning.contains("[4, 78, 1059, 21059, 30078]"), "{warning}");
        c.relay.auth.service_url = "wss://relay.example.com/".into();
        assert_eq!(c.auth_configuration_warning(), None);
        c.relay.auth.enabled = false;
        assert!(c
            .auth_configuration_warning()
            .unwrap()
            .contains("enabled is false"));
    }

    #[test]
    fn nip11_access_flags_follow_the_policies_and_proof_of_work() {
        let mut c = Config::default();
        c.relay.auth.service_url = "wss://relay.example.com".into();
        assert!(!c.auth_required() && !c.restricted_writes());
        c.relay.auth.read_policy = AccessPolicy::Authenticated;
        assert!(c.auth_required() && !c.restricted_writes());
        // Not while AUTH cannot succeed.
        c.relay.auth.enabled = false;
        assert!(!c.auth_required());
        c.relay.auth.enabled = true;
        c.relay.auth.read_policy = AccessPolicy::Open;
        c.relay.auth.write_policy = AccessPolicy::Members;
        assert!(!c.auth_required() && c.restricted_writes());
        c.relay.auth.write_policy = AccessPolicy::Open;
        c.relay.auth.accepted_kinds = vec![445];
        assert!(c.restricted_writes());
        c.relay.auth.accepted_kinds.clear();
        c.relay.abuse.min_pow_difficulty = 20;
        assert!(c.restricted_writes());
        // Proof of work is checked only with abuse controls on.
        c.relay.abuse.enabled = false;
        assert!(!c.restricted_writes());
    }

    #[test]
    fn accepted_kinds_are_a_ceiling_on_the_kinds_accepted() {
        let every = Config::default();
        assert!(every.accepts_kind(1) && every.accepts_kind(65_535));
        let narrow = Config::parse_toml("[relay.auth]\naccepted_kinds = [1059, 0, 445]\n").unwrap();
        assert!(narrow.accepts_kind(445) && !narrow.accepts_kind(1));
        // NIP-62 vanish requests, while NIP-62 is on.
        assert!(narrow.accepts_kind(62));
        assert_eq!(narrow.accepted_kind_list(), Some(vec![0, 62, 445, 1059]));
        assert_eq!(every.accepted_kind_list(), None);
        let mut no_vanish = narrow.clone();
        no_vanish.relay.nip62.enabled = false;
        assert!(!no_vanish.accepts_kind(62));
        assert_eq!(no_vanish.accepted_kind_list(), Some(vec![0, 445, 1059]));
        let error = Config::parse_toml("[relay.auth]\naccepted_kinds = [65536]\n").unwrap_err();
        assert!(error.contains("kind 65536 is out of range"), "{error}");
        // Narrowing it on reload is called out with the other access keys.
        assert_eq!(every.security_scope_changes(&narrow).len(), 1);
    }

    #[test]
    fn access_policies_report_unusable_auth_and_reloads() {
        let open =
            Config::parse_toml("[relay.auth]\nrecipient_only_kinds = []\nowner_only_kinds = []\n")
                .unwrap();
        assert_eq!(open.auth_configuration_warning(), None);
        let members = Config::parse_toml(
            "[relay.auth]\nrecipient_only_kinds = []\nowner_only_kinds = []\n\
             read_policy = \"members\"\nwrite_policy = \"authenticated\"\n",
        )
        .unwrap();
        assert_eq!(
            members.auth_configuration_warning().unwrap(),
            "AUTH is unavailable until relay.auth.service_url is configured, so these fail \
             closed: every read (read_policy = \"members\"); every write (write_policy = \
             \"authenticated\")"
        );
        assert!(Config::parse_toml("[relay.auth]\nread_policy = \"everyone\"\n").is_err());

        // A reload names each policy it changes.
        let changes = open.security_scope_changes(&members);
        assert_eq!(changes.len(), 1, "{changes:?}");
        assert!(
            changes[0]
                .ends_with(" (read_policy open -> members) (write_policy open -> authenticated)"),
            "{changes:?}"
        );
        let inbox = Config::parse_toml(
            "[relay.auth]\nrecipient_only_kinds = []\nowner_only_kinds = []\ninbox_kinds = []\n",
        )
        .unwrap();
        assert_eq!(open.security_scope_changes(&inbox).len(), 1);
    }

    #[test]
    fn native_toml_merges_defaults_and_uses_arrays() {
        let c = Config::parse_toml(
            r#"
            [database]
            path = "/tmp/wok-db"

            [relay]
            port = 9000

            [relay.auth]
            recipient_only_kinds = [4, 1059]

            [relay.unix]
            mode = 0o640
            auth_uids = [501, 502]
            "#,
        )
        .unwrap();
        assert_eq!(c.db, PathBuf::from("/tmp/wok-db"));
        assert_eq!(c.relay.port, 9000);
        assert_eq!(c.relay.auth.recipient_only_kinds, vec![4, 1059]);
        assert_eq!(c.relay.unix.mode, 0o640);
        assert_eq!(c.relay.unix.auth_uids, vec![501, 502]);
        assert_eq!(
            c.events.max_event_size,
            Config::default().events.max_event_size
        );
    }

    #[test]
    fn native_toml_rejects_unknown_keys_and_roundtrips() {
        assert!(Config::parse_toml("[relay]\nunknown_setting = true\n").is_err());
        let expected = Config::default();
        let encoded = expected.to_toml().unwrap();
        let decoded = Config::parse_toml(&encoded).unwrap();
        assert_eq!(decoded.db, expected.db);
        assert_eq!(decoded.relay.port, expected.relay.port);
        assert_eq!(decoded.relay.unix.mode, expected.relay.unix.mode);
    }

    #[test]
    fn native_toml_rejects_manual_nip_advertisement() {
        let error = Config::parse_toml("[relay.info]\nnips = [1, 2]\n").unwrap_err();
        assert!(error.contains("unknown field `nips`"), "{error}");
    }

    #[test]
    fn native_toml_selects_ephemeral_persistence_policy() {
        let default = Config::parse_toml("").unwrap();
        assert_eq!(
            default.events.ephemeral_persistence,
            EphemeralPersistence::LiveOnly
        );
        let ttl = Config::parse_toml("[events]\nephemeral_persistence = \"ttl\"\n").unwrap();
        assert_eq!(ttl.events.ephemeral_persistence, EphemeralPersistence::Ttl);
        assert!(
            Config::parse_toml("[events]\nephemeral_persistence = \"something_else\"\n").is_err()
        );
    }

    #[test]
    fn absent_preset_selects_public() {
        assert_eq!(Config::default().preset, Preset::Public);
        assert_eq!(Config::parse_toml("").unwrap().preset, Preset::Public);
        assert_eq!(
            Config::parse_toml("[relay]\nport = 9000\n").unwrap().preset,
            Preset::Public
        );
    }

    #[test]
    fn explicit_public_preset_parses_like_an_absent_one() {
        let file = r#"
            [database]
            path = "/tmp/wok-db"

            [relay]
            port = 9000

            [relay.auth]
            recipient_only_kinds = [4, 1059]

            [relay.abuse]
            event_burst = 500
            "#;
        let absent = Config::parse_toml(file).unwrap();
        let explicit = Config::parse_toml(&format!("preset = \"public\"\n{file}")).unwrap();
        assert_eq!(explicit.preset, Preset::Public);
        assert_eq!(explicit.to_toml().unwrap(), absent.to_toml().unwrap());
        assert_eq!(
            Config::parse_toml("preset = \"public\"")
                .unwrap()
                .to_toml()
                .unwrap(),
            Config::default().to_toml().unwrap()
        );
    }

    #[test]
    fn unknown_preset_is_an_error_naming_the_valid_presets() {
        let error = Config::parse_toml("preset = \"marmot\"\n").unwrap_err();
        assert_eq!(error, r#"unknown preset "marmot"; valid presets: public"#);
        let error = Config::parse_toml("preset = \"Public\"\n").unwrap_err();
        assert!(error.contains("valid presets: public"), "{error}");
        let error = Config::parse_toml("preset = 1\n").unwrap_err();
        assert!(
            error.contains("preset must be a string naming one of: public"),
            "{error}"
        );
        // Section-level keys named `preset` are still unknown fields.
        let error = Config::parse_toml("[relay]\npreset = \"public\"\n").unwrap_err();
        assert!(error.contains("unknown field `preset`"), "{error}");
    }

    #[test]
    fn preset_roundtrips_through_to_toml() {
        let parsed = Config::parse_toml("preset = \"public\"\n[relay]\nport = 9000\n").unwrap();
        let encoded = parsed.to_toml().unwrap();
        let file: toml::Value = toml::from_str(&encoded).unwrap();
        assert_eq!(
            file.get("preset").and_then(toml::Value::as_str),
            Some("public")
        );
        let decoded = Config::parse_toml(&encoded).unwrap();
        assert_eq!(decoded.preset, Preset::Public);
        assert_eq!(decoded.relay.port, 9000);
        assert_eq!(decoded.to_toml().unwrap(), encoded);
    }

    #[test]
    fn every_preset_overlay_parses_and_is_mirrored_in_docs() {
        for &preset in Preset::ALL {
            let documented = match preset {
                Preset::Public => include_str!("../../../docs/presets/public.toml"),
            };
            assert_eq!(
                preset.overlay(),
                documented,
                "docs/presets/{preset}.toml must match the shipped overlay"
            );
            let overlay: toml::Value = toml::from_str(preset.overlay()).unwrap();
            assert!(
                overlay.get("preset").is_none(),
                "the {preset} overlay must not select a preset"
            );
            let parsed = Config::parse_toml(&format!("preset = \"{preset}\"")).unwrap();
            assert_eq!(parsed.preset, preset);
            assert_eq!(preset.name().parse::<Preset>(), Ok(preset));
        }
        // The public preset is the built-in defaults.
        let public: toml::Value = toml::from_str(Preset::Public.overlay()).unwrap();
        assert_eq!(public, toml::Value::Table(Default::default()));
    }

    fn test_overlay(_: Preset) -> &'static str {
        "[relay.abuse]\nevent_burst = 300\nreq_burst = 400\n"
    }

    fn entry<'a>(explained: &'a ConfigExplanation, key: &str) -> &'a ConfigEntry {
        explained
            .entries
            .iter()
            .find(|entry| entry.key == key)
            .unwrap_or_else(|| panic!("no entry for {key}"))
    }

    #[test]
    fn explanation_reports_default_preset_and_file_origins() {
        let text = "preset = \"public\"\n\
                    \n\
                    [relay.abuse]\n\
                    event_burst = 500\n\
                    \n\
                    [relay.info]\n\
                    name = \"Example relay\"\n";
        let explained = provenance::explain(text, test_overlay).unwrap();
        assert_eq!(explained.config.relay.abuse.event_burst, 500);
        assert_eq!(explained.config.relay.abuse.req_burst, 400);

        assert_eq!(explained.entries[0].key, "preset");
        assert_eq!(
            *entry(&explained, "preset"),
            ConfigEntry {
                key: "preset".into(),
                value: "\"public\"".into(),
                origin: Origin::File { line: Some(1) },
                preset_value: None,
            }
        );
        assert_eq!(
            *entry(&explained, "relay.port"),
            ConfigEntry {
                key: "relay.port".into(),
                value: "7777".into(),
                origin: Origin::Default,
                preset_value: None,
            }
        );
        assert_eq!(
            *entry(&explained, "relay.abuse.req_burst"),
            ConfigEntry {
                key: "relay.abuse.req_burst".into(),
                value: "400".into(),
                origin: Origin::Preset(Preset::Public),
                preset_value: None,
            }
        );
        assert_eq!(
            *entry(&explained, "relay.abuse.event_burst"),
            ConfigEntry {
                key: "relay.abuse.event_burst".into(),
                value: "500".into(),
                origin: Origin::File { line: Some(4) },
                preset_value: Some("300".into()),
            }
        );
        assert_eq!(
            entry(&explained, "relay.info.name").origin,
            Origin::File { line: Some(7) }
        );
        let overrides: Vec<&str> = explained
            .entries
            .iter()
            .filter(|entry| entry.is_override())
            .map(|entry| entry.key.as_str())
            .collect();
        assert_eq!(overrides, ["relay.abuse.event_burst", "relay.info.name"]);
        let mut keys: Vec<&str> = explained.entries[1..]
            .iter()
            .map(|entry| entry.key.as_str())
            .collect();
        assert!(keys.windows(2).all(|pair| pair[0] < pair[1]));
        keys.dedup();
        assert_eq!(keys.len(), explained.entries.len() - 1);
    }

    #[test]
    fn explanation_keeps_file_origin_for_values_equal_to_the_preset() {
        let explained =
            provenance::explain("[relay.abuse]\nreq_burst = 400\n", test_overlay).unwrap();
        let req_burst = entry(&explained, "relay.abuse.req_burst");
        assert_eq!(req_burst.origin, Origin::File { line: Some(2) });
        assert!(!req_burst.is_override());
        assert_eq!(entry(&explained, "preset").origin, Origin::Default);
        assert!(explained.entries.iter().all(|entry| !entry.is_override()));
    }

    #[test]
    fn explanation_locates_dotted_inline_and_array_keys() {
        let text = r#"relay.port = 9000
admin = { enabled = false, auth_window_secs = 30 }

[relay.auth]
restricted_read_kinds = [
  4,
  1059,
]

[events]
max_event_size = 99999999999
"#;
        let explained = Config::explain_toml(text).unwrap();
        let line = |key| match entry(&explained, key).origin {
            Origin::File { line } => line,
            origin => panic!("{key} came from {origin:?}"),
        };
        assert_eq!(line("relay.port"), Some(1));
        assert_eq!(line("admin.enabled"), Some(2));
        assert_eq!(line("admin.auth_window_secs"), Some(2));
        // A deprecated key's translation is on its line.
        assert_eq!(line("relay.auth.recipient_only_kinds"), Some(5));
        assert_eq!(
            entry(&explained, "relay.auth.recipient_only_kinds").value,
            "[4, 1059]"
        );
        // Normalized values are reported as the relay uses them.
        let max_event_size = entry(&explained, "events.max_event_size");
        assert_eq!(max_event_size.value, MAX_SIZE_CLASS_BYTES.to_string());
        assert_eq!(max_event_size.preset_value.as_deref(), Some("1048576"));
        // The public preset sets nothing, so every other value is a default.
        assert_eq!(
            entry(&explained, "admin.public_url").origin,
            Origin::Default
        );
        assert!(explained
            .entries
            .iter()
            .all(|entry| !matches!(entry.origin, Origin::Preset(_))));
    }

    #[test]
    fn sample_config_parses_and_sets_only_overrides() {
        let sample = include_str!("../../../docs/wok.toml");
        let explained = Config::explain_toml(sample).unwrap();
        assert_eq!(explained.config.preset, Preset::Public);
        let repeated: Vec<&str> = explained
            .repeated_preset_values()
            .map(|entry| entry.key.as_str())
            .collect();
        assert!(
            repeated.is_empty(),
            "docs/wok.toml repeats preset values, which pins them: {repeated:?}"
        );
        assert_eq!(Config::minimize_toml(sample).unwrap().text, sample);
    }

    #[test]
    fn every_setting_is_documented_in_config_md() {
        let reference = include_str!("../../../docs/config.md");
        let mut leaves = Vec::new();
        let defaults = encode(&Config::default()).unwrap();
        provenance::flatten(&defaults, &mut Vec::new(), &mut leaves);
        let undocumented: Vec<String> = leaves
            .iter()
            .map(|(path, _)| path.join("."))
            .filter(|key| !reference.contains(&format!("| `{key}` |")))
            .collect();
        assert!(
            undocumented.is_empty(),
            "docs/config.md has no table row for {undocumented:?}"
        );
    }
}
