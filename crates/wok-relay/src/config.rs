//! Native TOML configuration plus the legacy strfry HOCON migration parser.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub admin: AdminConfig,
    pub db: PathBuf,
    pub db_maxreaders: u32,
    pub db_mapsize: usize,
    pub db_no_read_ahead: bool,
    pub db_min_free_disk_bytes: u64,
    pub events: EventsConfig,
    pub observability: ObservabilityConfig,
    pub relay: RelayConfig,
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
    "relay.filterValidation.minFiltersPerReq",
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
    pub max_filter_limit_count: u64,
    pub max_total_events_per_req: u64,
    pub max_subs_per_connection: usize,
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
    pub nip62: Nip62Config,
    pub filter_validation: FilterValidationConfig,
    pub abuse: AbuseConfig,
    pub unix: UnixConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbuseConfig {
    pub enabled: bool,
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
    pub max_concurrent_historical_queries: usize,
    pub max_query_cost: u64,
    pub max_stored_events: u64,
    pub max_stored_events_per_pubkey: u64,
    pub min_pow_difficulty: u8,
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
    pub restricted_read_kinds: Vec<u64>,
    pub restrict_read_to_involved_pubkey: bool,
    /// When true, only NIP-86 allowlisted or role-holding pubkeys (and
    /// operator admin pubkeys) may write events.
    pub restrict_writes: bool,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilterValidationConfig {
    pub enabled: bool,
    pub max_filters_per_req: u64,
    pub min_filters_per_req: u64,
    pub max_kinds_per_filter: u64,
    pub allowed_kinds: String,
    pub require_author_or_tag: bool,
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
                max_event_size: 65536,
                reject_newer_than_secs: 900,
                reject_older_than_secs: 94_608_000,
                reject_ephemeral_older_than_secs: 60,
                ephemeral_lifetime_secs: 300,
                ephemeral_persistence: EphemeralPersistence::LiveOnly,
                max_num_tags: 2000,
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
                    // Private messages and gift wraps fail closed until the
                    // operator configures the relay URL required by NIP-42.
                    restricted_read_kinds: vec![4, 1059],
                    restrict_read_to_involved_pubkey: true,
                    restrict_writes: false,
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
                max_websocket_payload_size: 131072,
                max_req_filter_size: 65_536,
                max_filters_per_req: 200,
                auto_ping_seconds: 55,
                enable_tcp_keepalive: false,
                handshake_timeout_secs: 10,
                frame_read_timeout_secs: 30,
                query_timeslice_budget_us: 10000,
                max_filter_limit: 500,
                max_tags_per_filter: 3,
                max_filter_limit_count: 1_000_000,
                max_total_events_per_req: 2_000,
                max_subs_per_connection: 200,
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
                nip62: Nip62Config {
                    enabled: true,
                    service_url: String::new(),
                    deletion_batch_size: 1_000,
                },
                filter_validation: FilterValidationConfig {
                    enabled: false,
                    max_filters_per_req: 3,
                    min_filters_per_req: 1,
                    max_kinds_per_filter: 3,
                    allowed_kinds: String::new(),
                    require_author_or_tag: false,
                },
                abuse: AbuseConfig {
                    enabled: true,
                    connection_rate_per_second: 10,
                    connection_burst: 50,
                    event_rate_per_second: 50,
                    event_burst: 100,
                    pubkey_event_rate_per_second: 25,
                    pubkey_event_burst: 50,
                    req_rate_per_second: 20,
                    req_burst: 40,
                    count_rate_per_second: 5,
                    count_burst: 10,
                    max_concurrent_historical_queries: 8,
                    max_query_cost: 1_000,
                    max_stored_events: 10_000_000,
                    max_stored_events_per_pubkey: 100_000,
                    min_pow_difficulty: 0,
                },
                unix: UnixConfig {
                    enabled: false,
                    path: PathBuf::from("./wok-db/wok.sock"),
                    mode: 0o600,
                    owner: String::new(),
                    group: String::new(),
                    auth_uids: Vec::new(),
                    auth_gids: Vec::new(),
                    max_frame_bytes: 131072,
                    max_pending_outbound_bytes: 33_554_432,
                },
            },
        }
    }
}

impl From<Config> for TomlConfig {
    fn from(config: Config) -> Self {
        Self {
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
            admin: config.admin,
            db: config.database.path,
            db_maxreaders: config.database.max_readers,
            db_mapsize: config.database.map_size,
            db_no_read_ahead: config.database.no_read_ahead,
            db_min_free_disk_bytes: config.database.min_free_disk_bytes,
            events: config.events,
            observability: config.observability,
            relay: config.relay,
        }
    }
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
    pub fn timestamp_policy_for_kind(&self, kind: u64) -> wok_event::TimestampPolicy {
        wok_event::TimestampPolicy::from_now(
            self.events.reject_newer_than_secs,
            if kind == wok_db::VANISH_KIND {
                u64::MAX
            } else {
                self.events.reject_older_than_secs
            },
            self.events.reject_ephemeral_older_than_secs,
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

    /// Explain when restricted reads are deliberately failing closed because
    /// the relay cannot complete NIP-42 authentication.
    pub fn auth_configuration_warning(&self) -> Option<String> {
        if self.relay.auth.restricted_read_kinds.is_empty() {
            return None;
        }
        if !self.relay.auth.enabled {
            return Some(format!(
                "restricted read kinds {:?} cannot be read because relay.auth.enabled is false",
                self.relay.auth.restricted_read_kinds
            ));
        }
        if self.relay.auth.service_url.is_empty() {
            return Some(format!(
                "restricted read kinds {:?} cannot be read until relay.auth.service_url is configured",
                self.relay.auth.restricted_read_kinds
            ));
        }
        None
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, String> {
        let text = std::fs::read_to_string(path.as_ref()).map_err(|e| e.to_string())?;
        Self::parse_toml(&text)
    }

    /// Parse Wok's native TOML format. Omitted settings inherit documented
    /// defaults, while unknown settings are rejected.
    pub fn parse_toml(text: &str) -> Result<Self, String> {
        let mut merged = toml::Value::try_from(TomlConfig::from(Config::default()))
            .map_err(|e| e.to_string())?;
        let supplied: toml::Value = toml::from_str(text).map_err(|e| e.to_string())?;
        merge_toml(&mut merged, supplied);
        let mut parsed: TomlConfig = merged
            .try_into()
            .map_err(|e: toml::de::Error| e.to_string())?;
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
        Ok(parsed.into())
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
            cfg.relay.auth.restricted_read_kinds = parse_kinds(v)?;
        }
        assign_bool(&map, "relay.auth.restrictReadToInvolvedPubkey", |b| {
            cfg.relay.auth.restrict_read_to_involved_pubkey = b
        })?;
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
        assign_bool(&map, "relay.filterValidation.enabled", |b| {
            cfg.relay.filter_validation.enabled = b
        })?;
        assign_u64(&map, "relay.filterValidation.maxFiltersPerReq", |n| {
            cfg.relay.filter_validation.max_filters_per_req = n;
            Ok(())
        })?;
        assign_u64(&map, "relay.filterValidation.minFiltersPerReq", |n| {
            cfg.relay.filter_validation.min_filters_per_req = n;
            Ok(())
        })?;
        assign_u64(&map, "relay.filterValidation.maxKindsPerFilter", |n| {
            cfg.relay.filter_validation.max_kinds_per_filter = n;
            Ok(())
        })?;
        if let Some(v) = map.get("relay.filterValidation.allowedKinds") {
            cfg.relay.filter_validation.allowed_kinds = v.clone();
        }
        assign_bool(&map, "relay.filterValidation.requireAuthorOrTag", |b| {
            cfg.relay.filter_validation.require_author_or_tag = b
        })?;
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
    /// a reload candidate. TOML loading merges the supplied file over factory
    /// defaults, so a valid-but-incomplete file silently reverts omitted
    /// sections — these diffs are warn-logged on reload so the reversion is
    /// at least visible in the logs.
    pub fn security_scope_changes(&self, new: &Config) -> Vec<String> {
        let mut changes = Vec::new();
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
                f.enabled,
                f.max_filters_per_req,
                f.min_filters_per_req,
                f.max_kinds_per_filter,
                f.require_author_or_tag,
            )
        };
        if fv(self) != fv(new)
            || self.relay.filter_validation.allowed_kinds
                != new.relay.filter_validation.allowed_kinds
        {
            changes.push(format!(
                "relay.filter_validation changed (enabled {} -> {}): {:?} -> {:?}",
                self.relay.filter_validation.enabled,
                new.relay.filter_validation.enabled,
                self.relay.filter_validation,
                new.relay.filter_validation,
            ));
        }
        let ab = |c: &Config| {
            let a = &c.relay.abuse;
            (
                (
                    a.enabled,
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
                    a.max_concurrent_historical_queries,
                    a.max_query_cost,
                    a.max_stored_events,
                    a.max_stored_events_per_pubkey,
                    a.min_pow_difficulty,
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
        // NIP-42 read-restriction scope: silently narrowing (or emptying)
        // restricted_read_kinds is fail-open, so call out dropped kinds
        // explicitly — those kinds are readable unauthenticated from now on.
        let prev = &self.relay.auth;
        let new_auth = &new.relay.auth;
        if prev.enabled != new_auth.enabled
            || prev.service_url != new_auth.service_url
            || prev.restricted_read_kinds != new_auth.restricted_read_kinds
            || prev.restrict_read_to_involved_pubkey != new_auth.restrict_read_to_involved_pubkey
        {
            let dropped: Vec<u64> = prev
                .restricted_read_kinds
                .iter()
                .filter(|k| !new_auth.restricted_read_kinds.contains(k))
                .copied()
                .collect();
            let note = if !dropped.is_empty() {
                format!(
                    " (restricted kinds DROPPED: {dropped:?} — previously-restricted kinds are now publicly readable)"
                )
            } else if prev.restrict_read_to_involved_pubkey
                && !new_auth.restrict_read_to_involved_pubkey
            {
                " (restrict_read_to_involved_pubkey DISABLED — the per-event filter is skipped; mixed-kind REQs can leak restricted kinds)".to_string()
            } else {
                String::new()
            };
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

    /// Warnings for every zero-valued guard that silently means "unlimited"
    /// (all editable live through the dashboard). Surfaced on reload so a
    /// single zero can't silently disarm a guard.
    pub fn zero_guard_warnings(&self) -> Vec<String> {
        let a = &self.relay.abuse;
        let mut warnings = Vec::new();
        if a.enabled {
            for (name, rate, burst) in [
                (
                    "connection",
                    a.connection_rate_per_second,
                    a.connection_burst,
                ),
                ("event", a.event_rate_per_second, a.event_burst),
                (
                    "pubkey_event",
                    a.pubkey_event_rate_per_second,
                    a.pubkey_event_burst,
                ),
                ("req", a.req_rate_per_second, a.req_burst),
                ("count", a.count_rate_per_second, a.count_burst),
            ] {
                if rate == 0 || burst == 0 {
                    warnings.push(format!(
                        "relay.abuse {name} budget is zero — that token bucket is disabled (unlimited)"
                    ));
                }
            }
            if a.max_query_cost == 0 {
                warnings.push("relay.abuse.max_query_cost is zero — unlimited".to_string());
            }
            if a.max_stored_events == 0 {
                warnings.push("relay.abuse.max_stored_events is zero — unlimited".to_string());
            }
            if a.max_stored_events_per_pubkey == 0 {
                warnings.push(
                    "relay.abuse.max_stored_events_per_pubkey is zero — unlimited".to_string(),
                );
            }
        }
        if self.relay.max_total_events_per_req == 0 {
            warnings.push("relay.max_total_events_per_req is zero — unlimited".to_string());
        }
        if self.relay.max_pending_outbound_bytes == 0 {
            warnings.push(
                "relay.max_pending_outbound_bytes is zero — slow-client queue is unlimited"
                    .to_string(),
            );
        }
        if self.relay.handshake_timeout_secs == 0 {
            warnings.push(
                "relay.handshake_timeout_secs is zero — pre-upgrade header read deadline disabled"
                    .to_string(),
            );
        }
        if self.relay.frame_read_timeout_secs == 0 {
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
        assert_eq!(c.relay.auth.restricted_read_kinds, vec![4, 1059]);
        assert_eq!(c.relay.info.pubkey, "deadbeef");
        assert_eq!(c.relay.info.self_pk, "cafe");
        assert_eq!(c.relay.info.terms, "https://example.com/t");
        assert_eq!(c.relay.max_filters_per_req, 7);
        assert_eq!(c.relay.max_req_filter_size, 65_536);
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
        assert!(c.relay.filter_validation.enabled);
        assert_eq!(c.relay.filter_validation.max_filters_per_req, 11);
        assert_eq!(c.relay.filter_validation.min_filters_per_req, 2);
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
    }

    #[test]
    fn security_scope_changes_flags_auth_nip62_and_negentropy() {
        let base = Config::parse_toml(
            r#"
            [relay]
            negentropy_enabled = true

            [relay.auth]
            enabled = true
            restricted_read_kinds = [4]

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
            restricted_read_kinds = [4]

            [relay.nip62]
            enabled = true
            "#,
        )
        .unwrap();
        assert!(base.security_scope_changes(&same).is_empty());
        // Emptying restricted_read_kinds drops kind 4 (the access scope widens),
        // and the note must pin the exact kind that is now publicly readable.
        let widened = Config::parse_toml("[relay.auth]\nrestricted_read_kinds = []\n").unwrap();
        let changes = base.security_scope_changes(&widened);
        assert!(
            changes
                .iter()
                .any(|c| c.contains("relay.auth changed") && c.contains("DROPPED: [4]")),
            "{changes:?}"
        );
        // Omitting [relay.auth] merges factory defaults [4, 1059]; starting
        // from a superset the defaults would drop ([4, 44, 1059]) is the
        // issue's omit-reverts-to-defaults fail-open path.
        let superset =
            Config::parse_toml("[relay.auth]\nrestricted_read_kinds = [4, 44, 1059]\n").unwrap();
        let partial = Config::parse_toml("[relay]\nnegentropy_enabled = true\n").unwrap();
        let changes = superset.security_scope_changes(&partial);
        assert!(
            changes
                .iter()
                .any(|c| c.contains("relay.auth changed") && c.contains("DROPPED: [44]")),
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
    fn zero_guard_warnings_cover_each_unlimited_zero() {
        // Defaults are all non-zero: no warnings.
        assert!(Config::default().zero_guard_warnings().is_empty());
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
            "max_query_cost",
            "max_stored_events",
            "max_stored_events_per_pubkey",
        ] {
            let cfg = Config::parse_toml(&format!("[relay.abuse]\n{field} = 0\n")).unwrap();
            assert!(
                !cfg.zero_guard_warnings().is_empty(),
                "{field} = 0 should warn"
            );
        }
        for field in [
            "max_total_events_per_req",
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
    fn restricted_read_kinds_are_private_by_default_but_can_be_disabled() {
        let c = Config::parse_toml("[relay.auth]\nrestricted_read_kinds = []\n").unwrap();
        assert!(c.relay.auth.restricted_read_kinds.is_empty());
        assert_eq!(
            Config::default().relay.auth.restricted_read_kinds,
            vec![4, 1059]
        );
    }

    #[test]
    fn restricted_reads_report_unusable_auth() {
        let mut c = Config::default();
        assert!(c
            .auth_configuration_warning()
            .unwrap()
            .contains("service_url"));
        c.relay.auth.service_url = "wss://relay.example.com/".into();
        assert_eq!(c.auth_configuration_warning(), None);
        c.relay.auth.enabled = false;
        assert!(c
            .auth_configuration_warning()
            .unwrap()
            .contains("enabled is false"));
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
            restricted_read_kinds = [4, 1059]

            [relay.unix]
            mode = 0o640
            auth_uids = [501, 502]
            "#,
        )
        .unwrap();
        assert_eq!(c.db, PathBuf::from("/tmp/wok-db"));
        assert_eq!(c.relay.port, 9000);
        assert_eq!(c.relay.auth.restricted_read_kinds, vec![4, 1059]);
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
    fn documented_toml_example_parses() {
        let documented = include_str!("../../../docs/wok.toml");
        Config::parse_toml(documented).unwrap();

        let documented: toml::Value = toml::from_str(documented).unwrap();
        let defaults: toml::Value = toml::from_str(&Config::default().to_toml().unwrap()).unwrap();
        assert_eq!(
            documented, defaults,
            "docs/wok.toml must list every default"
        );
    }
}
