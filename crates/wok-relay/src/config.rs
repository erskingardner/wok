//! Native TOML configuration plus the legacy strfry HOCON migration parser.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub db: PathBuf,
    pub db_maxreaders: u32,
    pub db_mapsize: usize,
    pub db_no_read_ahead: bool,
    pub events: EventsConfig,
    pub relay: RelayConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlConfig {
    database: DatabaseConfig,
    events: EventsConfig,
    relay: RelayConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DatabaseConfig {
    path: PathBuf,
    max_readers: u32,
    map_size: usize,
    no_read_ahead: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsConfig {
    pub max_event_size: usize,
    pub reject_newer_than_secs: u64,
    pub reject_older_than_secs: u64,
    pub reject_ephemeral_older_than_secs: u64,
    pub ephemeral_lifetime_secs: u64,
    pub max_num_tags: usize,
    pub max_tag_val_size: usize,
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
    pub max_req_filter_size: usize,
    pub auto_ping_seconds: u64,
    pub enable_tcp_keepalive: bool,
    pub query_timeslice_budget_us: u64,
    pub max_filter_limit: u64,
    pub max_tags_per_filter: usize,
    pub max_filter_limit_count: u64,
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
    pub filter_validation: FilterValidationConfig,
    pub unix: UnixConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    pub enabled: bool,
    pub service_url: String,
    pub restricted_read_kinds: Vec<u64>,
    pub restrict_read_to_involved_pubkey: bool,
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
    pub nips: String,
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
            db: PathBuf::from("./wok-db/"),
            db_maxreaders: 256,
            db_mapsize: 10_995_116_277_760,
            db_no_read_ahead: false,
            events: EventsConfig {
                max_event_size: 65536,
                reject_newer_than_secs: 900,
                reject_older_than_secs: 94_608_000,
                reject_ephemeral_older_than_secs: 60,
                ephemeral_lifetime_secs: 300,
                max_num_tags: 2000,
                max_tag_val_size: 1024,
            },
            relay: RelayConfig {
                bind: "127.0.0.1".into(),
                port: 7777,
                nofiles: 524288,
                real_ip_header: String::new(),
                auth: AuthConfig {
                    enabled: true,
                    service_url: String::new(),
                    // C++ strfry.conf default is "" (no restricted kinds).
                    restricted_read_kinds: Vec::new(),
                    restrict_read_to_involved_pubkey: true,
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
                    nips: String::new(),
                },
                max_websocket_payload_size: 131072,
                max_req_filter_size: 200,
                auto_ping_seconds: 55,
                enable_tcp_keepalive: false,
                query_timeslice_budget_us: 10000,
                max_filter_limit: 500,
                max_tags_per_filter: 3,
                max_filter_limit_count: 1_000_000,
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
                filter_validation: FilterValidationConfig {
                    enabled: false,
                    max_filters_per_req: 3,
                    min_filters_per_req: 1,
                    max_kinds_per_filter: 3,
                    allowed_kinds: String::new(),
                    require_author_or_tag: false,
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
            database: DatabaseConfig {
                path: config.db,
                max_readers: config.db_maxreaders,
                map_size: config.db_mapsize,
                no_read_ahead: config.db_no_read_ahead,
            },
            events: config.events,
            relay: config.relay,
        }
    }
}

impl From<TomlConfig> for Config {
    fn from(config: TomlConfig) -> Self {
        Self {
            db: config.database.path,
            db_maxreaders: config.database.max_readers,
            db_mapsize: config.database.map_size,
            db_no_read_ahead: config.database.no_read_ahead,
            events: config.events,
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
        let parsed: TomlConfig = merged
            .try_into()
            .map_err(|e: toml::de::Error| e.to_string())?;
        Ok(parsed.into())
    }

    pub fn to_toml(&self) -> Result<String, String> {
        toml::to_string_pretty(&TomlConfig::from(self.clone())).map_err(|e| e.to_string())
    }

    /// Parse the legacy HOCON subset used by strfry. This exists only for the
    /// explicit `wok migrate strfry` boundary.
    pub fn parse_strfry(text: &str) -> Result<Self, String> {
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
        if let Some(v) = map.get("relay.info.nips") {
            cfg.relay.info.nips = v.clone();
        }
        assign_u64(&map, "relay.maxWebsocketPayloadSize", |n| {
            cfg.relay.max_websocket_payload_size = n as usize;
            Ok(())
        })?;
        assign_u64(&map, "relay.maxReqFilterSize", |n| {
            cfg.relay.max_req_filter_size = n as usize;
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
        Ok(cfg)
    }

    pub fn event_limits(&self) -> wok_event::EventLimits {
        wok_event::EventLimits {
            max_event_size: self.events.max_event_size,
            max_num_tags: self.events.max_num_tags,
            max_tag_val_size: self.events.max_tag_val_size,
        }
    }

    /// Replace this config with a freshly parsed one, keeping the values
    /// that cannot change at runtime. The frozen set matches golpe's
    /// `noReload` keys plus everything bound to a listener/socket/pool that
    /// only exists once at startup (documented as "restart required" in
    /// strfry.conf).
    pub fn apply_reload(&mut self, new: Config) {
        let old = std::mem::replace(self, new);
        self.db = old.db;
        self.db_maxreaders = old.db_maxreaders;
        self.db_mapsize = old.db_mapsize;
        self.db_no_read_ahead = old.db_no_read_ahead;
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
    }
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
fn parse_mode(v: &str) -> Result<u32, String> {
    if let Some(o) = v.strip_prefix("0o").or_else(|| v.strip_prefix("0O")) {
        return u32::from_str_radix(o, 8).map_err(|_| format!("invalid unix.mode: {v:?}"));
    }
    if v.len() > 1 && v.starts_with('0') {
        return u32::from_str_radix(&v[1..], 8).map_err(|_| format!("invalid unix.mode: {v:?}"));
    }
    v.parse::<u32>()
        .map_err(|_| format!("invalid unix.mode: {v:?}"))
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

/// Minimal HOCON-subset tokenizer: quote-aware comment stripping (`#` and
/// `//`), inline `{`/`}` handling, and quoted string values with backslash
/// escapes.
fn parse_hocon(text: &str) -> Result<BTreeMap<String, String>, String> {
    let mut map = BTreeMap::new();
    let mut stack: Vec<String> = Vec::new();
    for (lineno, raw) in text.lines().enumerate() {
        for stmt in split_statements(raw) {
            let stmt = stmt.trim();
            if stmt.is_empty() {
                continue;
            }
            if stmt == "}" {
                if stack.pop().is_none() {
                    return Err(format!("line {}: unmatched '}}'", lineno + 1));
                }
                continue;
            }
            if let Some(name) = stmt.strip_suffix('{') {
                let name = name.trim().trim_end_matches('=').trim();
                if name.is_empty() {
                    return Err(format!("line {}: empty block name", lineno + 1));
                }
                stack.push(name.to_string());
                continue;
            }
            if let Some((k, v)) = stmt.split_once('=') {
                let key = if stack.is_empty() {
                    k.trim().to_string()
                } else {
                    format!("{}.{}", stack.join("."), k.trim())
                };
                let mut val = v.trim().to_string();
                if val.ends_with(',') {
                    val.pop();
                }
                let val = unquote(&val)?;
                map.insert(key, val);
                continue;
            }
            return Err(format!("line {}: cannot parse {stmt:?}", lineno + 1));
        }
    }
    if !stack.is_empty() {
        return Err(format!("unclosed block: {}", stack.join(".")));
    }
    Ok(map)
}

/// Split a line into statements on `{` and `}` (kept as their own
/// statements), honoring quoted strings and `#`/`//` comments.
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
            '{' => {
                // Block opener stays glued to its name: "relay {".
                cur.push('{');
                if !cur.trim().is_empty() {
                    out.push(cur.trim().to_string());
                }
                cur.clear();
            }
            '}' => {
                if !cur.trim().is_empty() {
                    out.push(cur.trim().to_string());
                }
                cur.clear();
                out.push("}".to_string());
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
        assert_eq!(c.relay.max_req_filter_size, 7);
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
        let mut cfg = Config::parse_toml("[relay]\nport = 7777\nmax_filter_limit = 500\n").unwrap();
        let new = Config::parse_toml("[relay]\nport = 9999\nmax_filter_limit = 123\n").unwrap();
        cfg.apply_reload(new);
        assert_eq!(cfg.relay.port, 7777, "port is restart-required");
        assert_eq!(cfg.relay.max_filter_limit, 123, "limits reload live");
    }

    #[test]
    fn empty_restricted_read_kinds() {
        let c = Config::parse_toml("[relay.auth]\nrestricted_read_kinds = []\n").unwrap();
        assert!(c.relay.auth.restricted_read_kinds.is_empty());
        // C++ default is no restricted kinds.
        assert!(Config::default()
            .relay
            .auth
            .restricted_read_kinds
            .is_empty());
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
    fn documented_toml_example_parses() {
        Config::parse_toml(include_str!("../../../docs/wok.toml")).unwrap();
    }
}
