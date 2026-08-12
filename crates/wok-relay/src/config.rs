//! strfry.conf HOCON-subset parser plus wok Unix-socket extensions.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub db: PathBuf,
    pub db_maxreaders: u32,
    pub db_mapsize: usize,
    pub db_no_read_ahead: bool,
    pub events: EventsConfig,
    pub relay: RelayConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
pub struct AuthConfig {
    pub enabled: bool,
    pub service_url: String,
    pub restricted_read_kinds: Vec<u64>,
    pub restrict_read_to_involved_pubkey: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
pub struct FilterValidationConfig {
    pub enabled: bool,
    pub max_filters_per_req: u64,
    pub min_filters_per_req: u64,
    pub max_kinds_per_filter: u64,
    pub allowed_kinds: String,
    pub require_author_or_tag: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
            db: PathBuf::from("./strfry-db/"),
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
                    restricted_read_kinds: vec![4, 1059],
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
                    path: PathBuf::from("./strfry-db/wok.sock"),
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

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, String> {
        let text = std::fs::read_to_string(path.as_ref()).map_err(|e| e.to_string())?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let map = parse_hocon(text)?;
        let mut cfg = Config::default();
        if let Some(v) = map.get("db") {
            cfg.db = PathBuf::from(v.clone());
        }
        if let Some(v) = map.get("dbParams.maxreaders") {
            cfg.db_maxreaders = v.parse().unwrap_or(cfg.db_maxreaders);
        }
        if let Some(v) = map.get("dbParams.mapsize") {
            cfg.db_mapsize = v.parse().unwrap_or(cfg.db_mapsize);
        }
        if let Some(v) = map.get("dbParams.noReadAhead") {
            cfg.db_no_read_ahead = v == "true";
        }
        assign_u64(&map, "events.maxEventSize", |n| {
            cfg.events.max_event_size = n as usize
        });
        assign_u64(&map, "events.rejectEventsNewerThanSeconds", |n| {
            cfg.events.reject_newer_than_secs = n
        });
        assign_u64(&map, "events.rejectEventsOlderThanSeconds", |n| {
            cfg.events.reject_older_than_secs = n
        });
        assign_u64(&map, "events.rejectEphemeralEventsOlderThanSeconds", |n| {
            cfg.events.reject_ephemeral_older_than_secs = n
        });
        assign_u64(&map, "events.ephemeralEventsLifetimeSeconds", |n| {
            cfg.events.ephemeral_lifetime_secs = n
        });
        assign_u64(&map, "events.maxNumTags", |n| {
            cfg.events.max_num_tags = n as usize
        });
        assign_u64(&map, "events.maxTagValSize", |n| {
            cfg.events.max_tag_val_size = n as usize
        });
        if let Some(v) = map.get("relay.bind") {
            cfg.relay.bind = v.clone();
        }
        assign_u64(&map, "relay.port", |n| cfg.relay.port = n as u16);
        if let Some(v) = map.get("relay.auth.enabled") {
            cfg.relay.auth.enabled = v == "true";
        }
        if let Some(v) = map.get("relay.auth.serviceUrl") {
            cfg.relay.auth.service_url = v.clone();
        }
        if let Some(v) = map.get("relay.auth.restrictedReadKinds") {
            cfg.relay.auth.restricted_read_kinds = parse_kinds(v);
        }
        if let Some(v) = map.get("relay.auth.restrictReadToInvolvedPubkey") {
            cfg.relay.auth.restrict_read_to_involved_pubkey = v != "false";
        }
        if let Some(v) = map.get("relay.info.name") {
            cfg.relay.info.name = v.clone();
        }
        if let Some(v) = map.get("relay.info.description") {
            cfg.relay.info.description = v.clone();
        }
        if let Some(v) = map.get("relay.info.nips") {
            cfg.relay.info.nips = v.clone();
        }
        assign_u64(&map, "relay.maxWebsocketPayloadSize", |n| {
            cfg.relay.max_websocket_payload_size = n as usize
        });
        assign_u64(&map, "relay.maxFilterLimit", |n| {
            cfg.relay.max_filter_limit = n
        });
        assign_u64(&map, "relay.maxFilterLimitCount", |n| {
            cfg.relay.max_filter_limit_count = n
        });
        assign_u64(&map, "relay.maxSubsPerConnection", |n| {
            cfg.relay.max_subs_per_connection = n as usize
        });
        assign_u64(&map, "relay.maxPendingOutboundBytes", |n| {
            cfg.relay.max_pending_outbound_bytes = n as usize
        });
        if let Some(v) = map.get("relay.writePolicy.plugin") {
            cfg.relay.write_policy_plugin = v.clone();
        }
        if let Some(v) = map.get("relay.negentropy.enabled") {
            cfg.relay.negentropy_enabled = v != "false";
        }
        if let Some(v) = map.get("relay.unix.enabled") {
            cfg.relay.unix.enabled = v == "true";
        }
        if let Some(v) = map.get("relay.unix.path") {
            cfg.relay.unix.path = PathBuf::from(v);
        }
        assign_u64(&map, "relay.unix.mode", |n| cfg.relay.unix.mode = n as u32);
        assign_u64(&map, "relay.unix.maxFrameBytes", |n| {
            cfg.relay.unix.max_frame_bytes = n as usize
        });
        if let Some(v) = map.get("relay.unix.authUids") {
            cfg.relay.unix.auth_uids = parse_u32s(v);
        }
        if let Some(v) = map.get("relay.unix.authGids") {
            cfg.relay.unix.auth_gids = parse_u32s(v);
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
}

fn assign_u64(map: &BTreeMap<String, String>, key: &str, mut f: impl FnMut(u64)) {
    if let Some(v) = map.get(key) {
        if let Ok(n) = v.parse() {
            f(n);
        }
    }
}

fn parse_kinds(s: &str) -> Vec<u64> {
    s.split(',').filter_map(|p| p.trim().parse().ok()).collect()
}

fn parse_u32s(s: &str) -> Vec<u32> {
    s.split(',').filter_map(|p| p.trim().parse().ok()).collect()
}

fn parse_hocon(text: &str) -> Result<BTreeMap<String, String>, String> {
    let mut map = BTreeMap::new();
    let mut stack: Vec<String> = Vec::new();
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line == "}" {
            stack.pop();
            continue;
        }
        if let Some(name) = line.strip_suffix('{') {
            let name = name.trim().trim_end_matches('=').trim();
            stack.push(name.to_string());
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let key = if stack.is_empty() {
                k.trim().to_string()
            } else {
                format!("{}.{}", stack.join("."), k.trim())
            };
            let mut val = v.trim().to_string();
            if val.ends_with(',') {
                val.pop();
            }
            if val.len() >= 2 && val.starts_with('"') && val.ends_with('"') {
                val = val[1..val.len() - 1].to_string();
            }
            map.insert(key, val);
        }
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested() {
        let c = Config::parse(
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
}
