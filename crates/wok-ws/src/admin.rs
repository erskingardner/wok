use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use parking_lot::Mutex;
use serde::Deserialize;
use sha2::Digest;
use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use wok_relay::{Config, EphemeralPersistence, RelayHandle};

const MAX_ADMIN_BODY: usize = 64 * 1024;
const MAX_REPLAY_IDS: usize = 4096;

#[derive(Default)]
pub struct AdminState {
    used_auth: Mutex<HashMap<[u8; 32], u64>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigPatch {
    info: Option<InfoPatch>,
    events: Option<EventsPatch>,
    limits: Option<LimitsPatch>,
    abuse: Option<AbusePatch>,
    filters: Option<FiltersPatch>,
    nip62: Option<Nip62Patch>,
    history: Option<HistoryPatch>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InfoPatch {
    name: Option<String>,
    description: Option<String>,
    pubkey: Option<String>,
    self_pk: Option<String>,
    contact: Option<String>,
    icon: Option<String>,
    banner: Option<String>,
    privacy: Option<String>,
    terms: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventsPatch {
    max_event_size: Option<usize>,
    reject_newer_than_secs: Option<u64>,
    reject_older_than_secs: Option<u64>,
    reject_ephemeral_older_than_secs: Option<u64>,
    ephemeral_lifetime_secs: Option<u64>,
    ephemeral_persistence: Option<EphemeralPersistence>,
    max_num_tags: Option<usize>,
    max_tag_val_size: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitsPatch {
    max_req_filter_size: Option<usize>,
    max_filters_per_req: Option<usize>,
    query_timeslice_budget_us: Option<u64>,
    max_filter_limit: Option<u64>,
    max_tags_per_filter: Option<usize>,
    max_filter_limit_count: Option<u64>,
    max_total_events_per_req: Option<u64>,
    max_subs_per_connection: Option<usize>,
    max_pending_outbound_bytes: Option<usize>,
    write_policy_timeout_secs: Option<u64>,
    negentropy_enabled: Option<bool>,
    max_sync_events: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AbusePatch {
    enabled: Option<bool>,
    connection_rate_per_second: Option<u32>,
    connection_burst: Option<u32>,
    event_rate_per_second: Option<u32>,
    event_burst: Option<u32>,
    pubkey_event_rate_per_second: Option<u32>,
    pubkey_event_burst: Option<u32>,
    req_rate_per_second: Option<u32>,
    req_burst: Option<u32>,
    count_rate_per_second: Option<u32>,
    count_burst: Option<u32>,
    max_concurrent_historical_queries: Option<usize>,
    max_query_cost: Option<u64>,
    max_stored_events: Option<u64>,
    max_stored_events_per_pubkey: Option<u64>,
    min_pow_difficulty: Option<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FiltersPatch {
    enabled: Option<bool>,
    max_filters_per_req: Option<u64>,
    min_filters_per_req: Option<u64>,
    max_kinds_per_filter: Option<u64>,
    allowed_kinds: Option<String>,
    require_author_or_tag: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Nip62Patch {
    enabled: Option<bool>,
    service_url: Option<String>,
    deletion_batch_size: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryPatch {
    enabled: Option<bool>,
    interval_secs: Option<u64>,
    max_points: Option<usize>,
}

pub async fn dispatch(
    req: Request<Incoming>,
    handle: Arc<RelayHandle>,
    state: Arc<AdminState>,
) -> Response<Full<Bytes>> {
    let cfg = handle.config.read().clone();
    if !cfg.admin.enabled {
        return response(StatusCode::NOT_FOUND, "text/plain", "not found");
    }
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or(&path)
        .to_string();
    if matches!(path.as_str(), "/admin" | "/admin/") && method == Method::GET {
        return admin_page(&cfg);
    }
    if !path.starts_with("/admin/api/") {
        return response(StatusCode::NOT_FOUND, "text/plain", "not found");
    }

    let authorization = req
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = match read_body(req.into_body(), MAX_ADMIN_BODY).await {
        Ok(body) => body,
        Err(error) => return response(StatusCode::PAYLOAD_TOO_LARGE, "text/plain", &error),
    };
    let absolute_url = format!("{}{}", cfg.admin.public_url, path_and_query);
    let admin_pubkey = match authorize(
        authorization.as_deref(),
        &method,
        &absolute_url,
        &body,
        &cfg,
        &state,
    ) {
        Ok(pubkey) => pubkey,
        Err(error) => return unauthorized(&error),
    };

    tracing::info!(
        admin_pubkey = %admin_pubkey,
        method = %method,
        path = %path,
        "authorized admin request"
    );
    match (method, path.as_str()) {
        (Method::GET, "/admin/api/overview") => overview(&handle),
        (Method::PUT, "/admin/api/config") => update_config(&handle, &body),
        _ => response(StatusCode::NOT_FOUND, "text/plain", "not found"),
    }
}

async fn read_body(mut body: Incoming, maximum: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| error.to_string())?;
        if let Ok(data) = frame.into_data() {
            if bytes.len().saturating_add(data.len()) > maximum {
                return Err(format!("admin request body exceeds {maximum} bytes"));
            }
            bytes.extend_from_slice(&data);
        }
    }
    Ok(bytes)
}

fn authorize(
    authorization: Option<&str>,
    method: &Method,
    absolute_url: &str,
    body: &[u8],
    cfg: &Config,
    state: &AdminState,
) -> Result<String, String> {
    let encoded = authorization
        .and_then(|value| value.strip_prefix("Nostr "))
        .ok_or_else(|| "missing Nostr authorization".to_string())?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| "invalid Nostr authorization encoding".to_string())?;
    let event: serde_json::Value = serde_json::from_slice(&decoded)
        .map_err(|_| "invalid Nostr authorization JSON".to_string())?;
    let parsed = wok_event::parse_and_verify_event(
        &event,
        &wok_event::EventLimits::default(),
        None,
        true,
        false,
    )
    .map_err(|error| format!("invalid Nostr authorization event: {error}"))?;
    let packed = parsed.packed.view();
    if packed.kind() != 27235 {
        return Err("NIP-98 authorization must be kind 27235".into());
    }
    if event.get("content").and_then(serde_json::Value::as_str) != Some("") {
        return Err("NIP-98 authorization content must be empty".into());
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if packed.created_at().abs_diff(now) > cfg.admin.auth_window_secs {
        return Err("NIP-98 authorization is outside the accepted time window".into());
    }
    if single_tag(&event, "u")? != absolute_url {
        return Err("NIP-98 u tag does not match the absolute request URL".into());
    }
    if single_tag(&event, "method")? != method.as_str() {
        return Err("NIP-98 method tag does not match the request method".into());
    }
    if !body.is_empty() {
        let payload = single_tag(&event, "payload")?;
        if payload != hex::encode(sha2::Sha256::digest(body)) {
            return Err("NIP-98 payload tag does not match the request body".into());
        }
    }
    let pubkey = hex::encode(packed.pubkey());
    if !cfg.admin.pubkeys.iter().any(|allowed| allowed == &pubkey) {
        return Err("NIP-98 signer is not an administrator".into());
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(packed.id());
    let mut used = state.used_auth.lock();
    used.retain(|_, created_at| created_at.abs_diff(now) <= cfg.admin.auth_window_secs);
    if used.contains_key(&id) {
        return Err("NIP-98 authorization event has already been used".into());
    }
    if used.len() >= MAX_REPLAY_IDS {
        return Err("NIP-98 replay cache is full".into());
    }
    used.insert(id, packed.created_at());
    Ok(pubkey)
}

fn single_tag<'a>(event: &'a serde_json::Value, name: &str) -> Result<&'a str, String> {
    let matching: Vec<_> = event
        .get("tags")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_array)
        .filter(|tag| tag.first().and_then(serde_json::Value::as_str) == Some(name))
        .collect();
    if matching.len() != 1 {
        return Err(format!(
            "NIP-98 authorization requires exactly one {name} tag"
        ));
    }
    matching[0]
        .get(1)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("NIP-98 {name} tag must contain a string value"))
}

fn overview(handle: &RelayHandle) -> Response<Full<Bytes>> {
    let cfg = handle.config.read();
    json(
        StatusCode::OK,
        serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "history": handle.metrics.history_json(),
            "can_write_config": cfg.admin.allow_config_writes && handle.config_path().is_some(),
            "config": {
                "info": {
                    "name": cfg.relay.info.name,
                    "description": cfg.relay.info.description,
                    "pubkey": cfg.relay.info.pubkey,
                    "self_pk": cfg.relay.info.self_pk,
                    "contact": cfg.relay.info.contact,
                    "icon": cfg.relay.info.icon,
                    "banner": cfg.relay.info.banner,
                    "privacy": cfg.relay.info.privacy,
                    "terms": cfg.relay.info.terms,
                },
                "events": {
                    "max_event_size": cfg.events.max_event_size,
                    "reject_newer_than_secs": cfg.events.reject_newer_than_secs,
                    "reject_older_than_secs": cfg.events.reject_older_than_secs,
                    "reject_ephemeral_older_than_secs": cfg.events.reject_ephemeral_older_than_secs,
                    "ephemeral_lifetime_secs": cfg.events.ephemeral_lifetime_secs,
                    "ephemeral_persistence": cfg.events.ephemeral_persistence,
                    "max_num_tags": cfg.events.max_num_tags,
                    "max_tag_val_size": cfg.events.max_tag_val_size,
                },
                "limits": {
                    "max_req_filter_size": cfg.relay.max_req_filter_size,
                    "max_filters_per_req": cfg.relay.max_filters_per_req,
                    "query_timeslice_budget_us": cfg.relay.query_timeslice_budget_us,
                    "max_filter_limit": cfg.relay.max_filter_limit,
                    "max_tags_per_filter": cfg.relay.max_tags_per_filter,
                    "max_filter_limit_count": cfg.relay.max_filter_limit_count,
                    "max_total_events_per_req": cfg.relay.max_total_events_per_req,
                    "max_subs_per_connection": cfg.relay.max_subs_per_connection,
                    "max_pending_outbound_bytes": cfg.relay.max_pending_outbound_bytes,
                    "write_policy_timeout_secs": cfg.relay.write_policy_timeout_secs,
                    "negentropy_enabled": cfg.relay.negentropy_enabled,
                    "max_sync_events": cfg.relay.max_sync_events,
                },
                "abuse": {
                    "enabled": cfg.relay.abuse.enabled,
                    "connection_rate_per_second": cfg.relay.abuse.connection_rate_per_second,
                    "connection_burst": cfg.relay.abuse.connection_burst,
                    "event_rate_per_second": cfg.relay.abuse.event_rate_per_second,
                    "event_burst": cfg.relay.abuse.event_burst,
                    "pubkey_event_rate_per_second": cfg.relay.abuse.pubkey_event_rate_per_second,
                    "pubkey_event_burst": cfg.relay.abuse.pubkey_event_burst,
                    "req_rate_per_second": cfg.relay.abuse.req_rate_per_second,
                    "req_burst": cfg.relay.abuse.req_burst,
                    "count_rate_per_second": cfg.relay.abuse.count_rate_per_second,
                    "count_burst": cfg.relay.abuse.count_burst,
                    "max_concurrent_historical_queries": cfg.relay.abuse.max_concurrent_historical_queries,
                    "max_query_cost": cfg.relay.abuse.max_query_cost,
                    "max_stored_events": cfg.relay.abuse.max_stored_events,
                    "max_stored_events_per_pubkey": cfg.relay.abuse.max_stored_events_per_pubkey,
                    "min_pow_difficulty": cfg.relay.abuse.min_pow_difficulty,
                },
                "filters": {
                    "enabled": cfg.relay.filter_validation.enabled,
                    "max_filters_per_req": cfg.relay.filter_validation.max_filters_per_req,
                    "min_filters_per_req": cfg.relay.filter_validation.min_filters_per_req,
                    "max_kinds_per_filter": cfg.relay.filter_validation.max_kinds_per_filter,
                    "allowed_kinds": cfg.relay.filter_validation.allowed_kinds,
                    "require_author_or_tag": cfg.relay.filter_validation.require_author_or_tag,
                },
                "nip62": {
                    "enabled": cfg.relay.nip62.enabled,
                    "service_url": cfg.relay.nip62.service_url,
                    "deletion_batch_size": cfg.relay.nip62.deletion_batch_size,
                },
                "history": {
                    "enabled": cfg.observability.history_enabled,
                    "interval_secs": cfg.observability.history_interval_secs,
                    "max_points": cfg.observability.history_max_points,
                }
            }
        }),
    )
}

fn update_config(handle: &RelayHandle, body: &[u8]) -> Response<Full<Bytes>> {
    let current = handle.config.read().clone();
    if !current.admin.allow_config_writes {
        return response(
            StatusCode::FORBIDDEN,
            "text/plain",
            "config writes are disabled",
        );
    }
    let Some(path) = handle.config_path() else {
        return response(
            StatusCode::CONFLICT,
            "text/plain",
            "relay was not started from a writable config file",
        );
    };
    let patch: ConfigPatch = match serde_json::from_slice(body) {
        Ok(patch) => patch,
        Err(error) => return response(StatusCode::BAD_REQUEST, "text/plain", &error.to_string()),
    };
    let mut next = current;
    apply_patch(&mut next, patch);
    let encoded = match next.to_toml() {
        Ok(encoded) => encoded,
        Err(error) => return response(StatusCode::BAD_REQUEST, "text/plain", &error),
    };
    let verified = match Config::parse_toml(&encoded) {
        Ok(config) => config,
        Err(error) => return response(StatusCode::BAD_REQUEST, "text/plain", &error),
    };
    if let Err(error) = atomic_write_config(&path, encoded.as_bytes()) {
        return response(StatusCode::INTERNAL_SERVER_ERROR, "text/plain", &error);
    }
    handle.config.write().apply_reload(verified);
    json(StatusCode::OK, serde_json::json!({"saved": true}))
}

fn apply_patch(config: &mut Config, patch: ConfigPatch) {
    if let Some(info) = patch.info {
        if let Some(value) = info.name {
            config.relay.info.name = value;
        }
        if let Some(value) = info.description {
            config.relay.info.description = value;
        }
        if let Some(value) = info.pubkey {
            config.relay.info.pubkey = value;
        }
        if let Some(value) = info.self_pk {
            config.relay.info.self_pk = value;
        }
        if let Some(value) = info.contact {
            config.relay.info.contact = value;
        }
        if let Some(value) = info.icon {
            config.relay.info.icon = value;
        }
        if let Some(value) = info.banner {
            config.relay.info.banner = value;
        }
        if let Some(value) = info.privacy {
            config.relay.info.privacy = value;
        }
        if let Some(value) = info.terms {
            config.relay.info.terms = value;
        }
    }
    if let Some(events) = patch.events {
        if let Some(value) = events.max_event_size {
            config.events.max_event_size = value;
        }
        if let Some(value) = events.reject_newer_than_secs {
            config.events.reject_newer_than_secs = value;
        }
        if let Some(value) = events.reject_older_than_secs {
            config.events.reject_older_than_secs = value;
        }
        if let Some(value) = events.reject_ephemeral_older_than_secs {
            config.events.reject_ephemeral_older_than_secs = value;
        }
        if let Some(value) = events.ephemeral_lifetime_secs {
            config.events.ephemeral_lifetime_secs = value;
        }
        if let Some(value) = events.ephemeral_persistence {
            config.events.ephemeral_persistence = value;
        }
        if let Some(value) = events.max_num_tags {
            config.events.max_num_tags = value;
        }
        if let Some(value) = events.max_tag_val_size {
            config.events.max_tag_val_size = value;
        }
    }
    if let Some(limits) = patch.limits {
        if let Some(value) = limits.max_req_filter_size {
            config.relay.max_req_filter_size = value;
        }
        if let Some(value) = limits.max_filters_per_req {
            config.relay.max_filters_per_req = value;
        }
        if let Some(value) = limits.query_timeslice_budget_us {
            config.relay.query_timeslice_budget_us = value;
        }
        if let Some(value) = limits.max_filter_limit {
            config.relay.max_filter_limit = value;
        }
        if let Some(value) = limits.max_tags_per_filter {
            config.relay.max_tags_per_filter = value;
        }
        if let Some(value) = limits.max_filter_limit_count {
            config.relay.max_filter_limit_count = value;
        }
        if let Some(value) = limits.max_total_events_per_req {
            config.relay.max_total_events_per_req = value;
        }
        if let Some(value) = limits.max_subs_per_connection {
            config.relay.max_subs_per_connection = value;
        }
        if let Some(value) = limits.max_pending_outbound_bytes {
            config.relay.max_pending_outbound_bytes = value;
        }
        if let Some(value) = limits.write_policy_timeout_secs {
            config.relay.write_policy_timeout_secs = value;
        }
        if let Some(value) = limits.negentropy_enabled {
            config.relay.negentropy_enabled = value;
        }
        if let Some(value) = limits.max_sync_events {
            config.relay.max_sync_events = value;
        }
    }
    if let Some(abuse) = patch.abuse {
        if let Some(value) = abuse.enabled {
            config.relay.abuse.enabled = value;
        }
        if let Some(value) = abuse.connection_rate_per_second {
            config.relay.abuse.connection_rate_per_second = value;
        }
        if let Some(value) = abuse.connection_burst {
            config.relay.abuse.connection_burst = value;
        }
        if let Some(value) = abuse.event_rate_per_second {
            config.relay.abuse.event_rate_per_second = value;
        }
        if let Some(value) = abuse.event_burst {
            config.relay.abuse.event_burst = value;
        }
        if let Some(value) = abuse.pubkey_event_rate_per_second {
            config.relay.abuse.pubkey_event_rate_per_second = value;
        }
        if let Some(value) = abuse.pubkey_event_burst {
            config.relay.abuse.pubkey_event_burst = value;
        }
        if let Some(value) = abuse.req_rate_per_second {
            config.relay.abuse.req_rate_per_second = value;
        }
        if let Some(value) = abuse.req_burst {
            config.relay.abuse.req_burst = value;
        }
        if let Some(value) = abuse.count_rate_per_second {
            config.relay.abuse.count_rate_per_second = value;
        }
        if let Some(value) = abuse.count_burst {
            config.relay.abuse.count_burst = value;
        }
        if let Some(value) = abuse.max_concurrent_historical_queries {
            config.relay.abuse.max_concurrent_historical_queries = value;
        }
        if let Some(value) = abuse.max_query_cost {
            config.relay.abuse.max_query_cost = value;
        }
        if let Some(value) = abuse.max_stored_events {
            config.relay.abuse.max_stored_events = value;
        }
        if let Some(value) = abuse.max_stored_events_per_pubkey {
            config.relay.abuse.max_stored_events_per_pubkey = value;
        }
        if let Some(value) = abuse.min_pow_difficulty {
            config.relay.abuse.min_pow_difficulty = value;
        }
    }
    if let Some(filters) = patch.filters {
        if let Some(value) = filters.enabled {
            config.relay.filter_validation.enabled = value;
        }
        if let Some(value) = filters.max_filters_per_req {
            config.relay.filter_validation.max_filters_per_req = value;
        }
        if let Some(value) = filters.min_filters_per_req {
            config.relay.filter_validation.min_filters_per_req = value;
        }
        if let Some(value) = filters.max_kinds_per_filter {
            config.relay.filter_validation.max_kinds_per_filter = value;
        }
        if let Some(value) = filters.allowed_kinds {
            config.relay.filter_validation.allowed_kinds = value;
        }
        if let Some(value) = filters.require_author_or_tag {
            config.relay.filter_validation.require_author_or_tag = value;
        }
    }
    if let Some(nip62) = patch.nip62 {
        if let Some(value) = nip62.enabled {
            config.relay.nip62.enabled = value;
        }
        if let Some(value) = nip62.service_url {
            config.relay.nip62.service_url = value;
        }
        if let Some(value) = nip62.deletion_batch_size {
            config.relay.nip62.deletion_batch_size = value;
        }
    }
    if let Some(history) = patch.history {
        if let Some(value) = history.enabled {
            config.observability.history_enabled = value;
        }
        if let Some(value) = history.interval_secs {
            config.observability.history_interval_secs = value;
        }
        if let Some(value) = history.max_points {
            config.observability.history_max_points = value;
        }
    }
}

fn atomic_write_config(path: &std::path::Path, contents: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "config path has no parent directory".to_string())?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|e| e.to_string())?;
    if let Ok(metadata) = std::fs::metadata(path) {
        temporary
            .as_file()
            .set_permissions(metadata.permissions())
            .map_err(|e| e.to_string())?;
    }
    temporary.write_all(contents).map_err(|e| e.to_string())?;
    temporary.as_file().sync_all().map_err(|e| e.to_string())?;
    temporary.persist(path).map_err(|e| e.error.to_string())?;
    if let Ok(directory) = std::fs::File::open(parent) {
        let _ = directory.sync_all();
    }
    Ok(())
}

fn unauthorized(message: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("Content-Type", "text/plain; charset=utf-8")
        .header("WWW-Authenticate", "Nostr")
        .header("Cache-Control", "no-store")
        .body(Full::new(Bytes::copy_from_slice(message.as_bytes())))
        .unwrap()
}

fn json(status: StatusCode, value: serde_json::Value) -> Response<Full<Bytes>> {
    response(status, "application/json", &value.to_string())
}

fn response(status: StatusCode, content_type: &str, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", content_type)
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .body(Full::new(Bytes::copy_from_slice(body.as_bytes())))
        .unwrap()
}

fn admin_page(cfg: &Config) -> Response<Full<Bytes>> {
    let public_url = serde_json::to_string(&cfg.admin.public_url).unwrap_or_else(|_| "\"\"".into());
    let body = ADMIN_HTML_V2.replace("__PUBLIC_URL__", &public_url);
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/html; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Frame-Options", "DENY")
        .header("X-Content-Type-Options", "nosniff")
        .header("Referrer-Policy", "no-referrer")
        .header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'",
        )
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

const ADMIN_HTML_V2: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Wok operator</title>
<style>
:root{color-scheme:dark;--bg:#090b0f;--panel:#11151c;--panel2:#151b24;--line:#28303c;--text:#f7f4ed;--muted:#99a4b5;--hot:#ff8a3d;--green:#5bd6a2;--red:#ff7373}*{box-sizing:border-box}[hidden]{display:none!important}body{margin:0;min-height:100vh;background:radial-gradient(circle at 78% -8%,#1b120f 0,transparent 32rem),var(--bg);color:var(--text);font:15px/1.45 Inter,"SF Pro Text",system-ui,-apple-system,sans-serif}button,input,select{font:inherit}button{border:0;border-radius:10px;padding:10px 14px;background:var(--hot);color:#1e0c02;font-weight:760;cursor:pointer}button.secondary{background:#1c2330;color:var(--text);border:1px solid var(--line)}button:disabled{opacity:.45;cursor:not-allowed}.mark{display:grid;place-items:center;width:46px;height:46px;border-radius:12px;background:var(--hot);color:#1b0c04;font-size:25px;font-weight:900;box-shadow:0 10px 28px #ff8a3d33}.muted{color:var(--muted)}.ok{color:var(--green)}.bad{color:var(--red)}
.login{display:grid;place-items:center;min-height:100vh;padding:24px}.login-card{width:min(470px,100%);padding:34px;background:linear-gradient(180deg,#131820,#11151c);border:1px solid var(--line);border-radius:12px;box-shadow:0 24px 70px #0006}.login-card .mark{margin-bottom:28px}.eyebrow{margin:0 0 8px;color:var(--hot);font-size:12px;font-weight:780;letter-spacing:.1em;text-transform:uppercase}.login h1{margin:0;font-size:34px;letter-spacing:-.04em}.login-copy{margin:14px 0 24px;color:var(--muted);font-size:16px;line-height:1.6}.login button{width:100%;padding:13px}.login-note{margin:18px 0 0;color:#7f8998;font-size:12px}.login-status{min-height:22px;margin-top:15px;font-size:13px}
.dashboard{max-width:1200px;margin:auto;padding:34px 24px 70px}.dashboard>header{display:flex;align-items:center;justify-content:space-between;gap:20px;margin-bottom:28px}.brand{display:flex;align-items:center;gap:14px}.brand h1{font-size:24px;margin:0}.toolbar{display:flex;gap:9px;align-items:center}.status{padding:9px 12px;border:1px solid var(--line);border-radius:8px;color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.card,.panel,.config-group{background:linear-gradient(180deg,#131820,#11151c);border:1px solid var(--line);border-radius:10px;box-shadow:0 12px 32px #0003}.card{padding:18px}.label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em}.value{font-size:29px;font-weight:780;margin-top:8px}.panels{display:grid;grid-template-columns:1.55fr 1fr;gap:16px;margin-top:16px}.panel{padding:20px}.panel h2,.config-header h2{font-size:16px;margin:0}.chart{height:245px;width:100%;margin-top:15px;background:#0b0e13;border-radius:8px;border:1px solid #1e2530}.config{margin-top:16px}.config-intro{display:flex;align-items:flex-start;justify-content:space-between;gap:20px;margin-bottom:16px}.config-intro h2{margin:0 0 4px;font-size:20px}.config-intro p{margin:0}.config-groups{display:grid;gap:12px}.config-group{overflow:hidden}.config-group summary{list-style:none;cursor:pointer;padding:18px 20px}.config-group summary::-webkit-details-marker{display:none}.config-header{display:flex;align-items:center;justify-content:space-between;gap:15px}.config-header h2:after{content:"+";display:inline-block;margin-left:9px;color:var(--hot)}details[open] .config-header h2:after{content:"−"}.config-header p{max-width:650px;margin:3px 0 0;color:var(--muted);font-size:13px}.config-fields{display:grid;grid-template-columns:1fr;gap:0;padding:0 20px 4px;border-top:1px solid var(--line)}.field{display:grid;grid-template-columns:minmax(0,1fr) minmax(220px,360px);align-items:center;gap:32px;padding:16px 0;border-bottom:1px solid #222a34}.field:last-child{border-bottom:0}.field.wide{grid-column:auto}.field>span{min-width:0}.field-title,.field-help{display:block}.field-title{font-weight:680}.field-help{margin-top:3px;color:var(--muted);font-size:12px;line-height:1.45}.field input,.field select{width:100%;height:42px;justify-self:end;background:#0a0d12;border:1px solid var(--line);border-radius:7px;padding:9px 10px;color:var(--text)}.field input:focus,.field select:focus{outline:2px solid #ff8a3d55;border-color:var(--hot)}.field.checkbox{grid-template-columns:minmax(0,1fr) minmax(220px,360px)}.field.checkbox input{width:20px;height:20px;justify-self:end;accent-color:var(--hot)}.actions{position:sticky;bottom:12px;display:flex;align-items:center;justify-content:space-between;gap:16px;margin-top:16px;padding:14px 16px;background:#11161ef2;border:1px solid var(--line);border-radius:10px;backdrop-filter:blur(12px)}
@media(max-width:820px){.grid{grid-template-columns:1fr 1fr}.panels{grid-template-columns:1fr}}@media(max-width:620px){.field:not(.checkbox){grid-template-columns:1fr;gap:10px}.field:not(.checkbox) input,.field:not(.checkbox) select{grid-column:1}.field.checkbox{grid-template-columns:minmax(0,1fr) auto;gap:20px}}@media(max-width:560px){.dashboard{padding:22px 14px}.dashboard>header,.config-intro{align-items:flex-start;flex-direction:column}.toolbar{width:100%;flex-wrap:wrap}.grid{grid-template-columns:1fr}.login-card{padding:27px}.actions{align-items:flex-start;flex-direction:column}.actions button{width:100%}}
</style>
</head>
<body>
<section id="loginView" class="login">
  <div class="login-card">
    <div class="mark">W</div>
    <p class="eyebrow">Wok operator</p>
    <h1>Sign in to administer this relay</h1>
    <p class="login-copy">Operational data and configuration are private. Use an approved Nostr key to unlock the dashboard.</p>
    <button id="login">Sign in with Nostr</button>
    <div id="loginStatus" class="login-status muted">A NIP-07 signer extension is required.</div>
    <p class="login-note">Wok requests a fresh NIP-98 signature. Your private key remains in your signer.</p>
  </div>
</section>
<main id="dashboard" class="dashboard" hidden>
  <header>
    <div class="brand"><div class="mark">W</div><div><h1>Wok operator</h1><span class="muted">Authenticated relay control surface</span></div></div>
    <div class="toolbar"><span id="status" class="status ok">Authenticated</span><button id="refresh" class="secondary">Refresh</button><button id="logout" class="secondary">Sign out</button></div>
  </header>
  <section class="grid">
    <div class="card"><div class="label">Connections</div><div id="connections" class="value">—</div></div>
    <div class="card"><div class="label">Events written</div><div id="written" class="value">—</div></div>
    <div class="card"><div class="label">Rejected</div><div id="rejected" class="value">—</div></div>
    <div class="card"><div class="label">Protocol messages</div><div id="messages" class="value">—</div></div>
  </section>
  <section class="panels">
    <div class="panel"><h2>Connections over time</h2><canvas id="chart" class="chart"></canvas><p class="muted">Bounded in-memory samples; a restart clears history.</p></div>
    <div class="panel"><h2>Runtime snapshot</h2><p class="muted">Version</p><p id="version">—</p><p class="muted">Configuration mode</p><p id="mode">—</p><p class="muted">Last refreshed</p><p id="refreshed">—</p></div>
  </section>
  <section class="config">
    <div class="config-intro"><div><h2>Relay configuration</h2><p class="muted">Live-reloadable operator settings. Restart-only infrastructure and sensitive access controls stay in wok.toml.</p></div></div>
    <div id="configGroups" class="config-groups"></div>
    <div class="actions"><span id="saveStatus" class="muted">Load configuration to begin.</span><button id="save" disabled>Save configuration</button></div>
  </section>
</main>
<script>
const PUBLIC_BASE=__PUBLIC_URL__;
const $=id=>document.getElementById(id);
const fmt=n=>new Intl.NumberFormat().format(n??0);
let data=null;
const GROUPS=[
 {key:'info',title:'Relay identity',help:'Public metadata returned by NIP-11 and shown on the landing page.',open:true,fields:[
  ['name','Name','The public display name for this relay.','text','wide'],['description','Description','A concise explanation of the relay and its purpose.','text','wide'],['pubkey','Operator pubkey','Public key advertised as the relay operator identity.','text','wide'],['self_pk','Relay pubkey','The relay own public key, advertised in the NIP-11 self field.','text','wide'],['contact','Contact','Operator contact, commonly an email address or Nostr identifier.','text','wide'],['icon','Icon URL','Square icon URL published in relay metadata.','url','wide'],['banner','Banner URL','Wide banner image URL published in relay metadata.','url','wide'],['privacy','Privacy policy URL','Link to the relay privacy policy.','url','wide'],['terms','Terms of service URL','Link to the relay terms of service.','url','wide']
 ]},
 {key:'events',title:'Event acceptance',help:'Size, timestamp, tag, and ephemeral-event policies applied before storage.',fields:[
  ['max_event_size','Maximum event bytes','Largest serialized event accepted by the relay.','number'],['max_num_tags','Maximum tags','Largest number of tags accepted on one event.','number'],['max_tag_val_size','Maximum tag value bytes','Largest individual tag value accepted.','number'],['reject_newer_than_secs','Future timestamp tolerance','Reject events this many seconds newer than the relay clock.','number'],['reject_older_than_secs','Maximum event age','Reject non-ephemeral events older than this many seconds.','number'],['reject_ephemeral_older_than_secs','Maximum ephemeral age','Reject ephemeral events older than this many seconds.','number'],['ephemeral_lifetime_secs','Ephemeral TTL','How long TTL-persisted ephemeral events remain available.','number'],['ephemeral_persistence','Ephemeral persistence','Keep ephemeral events live-only or persist them until their TTL.','select',null,[['live_only','Live only'],['ttl','TTL persistence']]]
 ]},
 {key:'limits',title:'Queries and protocol limits',help:'Bounds for subscriptions, filters, result sets, queues, plugins, and Negentropy.',fields:[
  ['max_req_filter_size','Maximum REQ filter bytes','Combined compact-JSON bytes allowed across all filter objects in one REQ or COUNT.','number'],['max_filters_per_req','Maximum filters per request','Unconditional ceiling for filter objects in one REQ or COUNT.','number'],['query_timeslice_budget_us','Query time slice (microseconds)','CPU time a query may use before yielding to other work.','number'],['max_filter_limit','REQ result ceiling','Maximum event limit accepted for a normal subscription filter.','number'],['max_filter_limit_count','COUNT result ceiling','Maximum event limit used while answering COUNT.','number'],['max_tags_per_filter','Tag constraints per filter','Maximum number of tag query keys allowed in one filter.','number'],['max_total_events_per_req','Events per REQ','Maximum total historical events emitted for one REQ.','number'],['max_subs_per_connection','Subscriptions per connection','Maximum simultaneous subscriptions on one WebSocket.','number'],['max_pending_outbound_bytes','Outbound queue bytes','Disconnect a slow client after its pending output exceeds this bound.','number'],['write_policy_timeout_secs','Write-policy timeout','Seconds to wait for the configured write-policy plugin.','number'],['negentropy_enabled','Negentropy enabled','Advertise and accept NIP-77 synchronization requests.','checkbox'],['max_sync_events','Negentropy event ceiling','Maximum events reconciled by one synchronization session.','number']
 ]},
 {key:'abuse',title:'Abuse protection',help:'Token-bucket rates, bursts, query budgets, quotas, and proof-of-work requirements.',fields:[
  ['enabled','Abuse protection enabled','Apply all configured connection, message, query, quota, and PoW guards.','checkbox'],['connection_rate_per_second','Connection rate','New connections allowed per second before burst capacity is consumed.','number'],['connection_burst','Connection burst','Maximum accumulated burst capacity for new connections.','number'],['event_rate_per_second','Connection EVENT rate','EVENT messages allowed per second on one connection.','number'],['event_burst','Connection EVENT burst','Maximum accumulated EVENT burst per connection.','number'],['pubkey_event_rate_per_second','Pubkey EVENT rate','Accepted events per second across connections for one author.','number'],['pubkey_event_burst','Pubkey EVENT burst','Maximum accumulated EVENT burst for one author.','number'],['req_rate_per_second','REQ rate','REQ messages allowed per second on one connection.','number'],['req_burst','REQ burst','Maximum accumulated REQ burst per connection.','number'],['count_rate_per_second','COUNT rate','COUNT messages allowed per second on one connection.','number'],['count_burst','COUNT burst','Maximum accumulated COUNT burst per connection.','number'],['max_concurrent_historical_queries','Concurrent historical queries','Maximum historical scans running at once per connection.','number'],['max_query_cost','Query cost ceiling','Reject filters whose estimated scan cost exceeds this value.','number'],['max_stored_events','Stored events globally','Total durable event ceiling across every author; zero means unlimited.','number'],['max_stored_events_per_pubkey','Stored events per pubkey','Per-author durable event ceiling; zero means unlimited.','number'],['min_pow_difficulty','Minimum proof of work','Required NIP-13 difficulty; zero disables the requirement.','number']
 ]},
 {key:'filters',title:'Filter validation',help:'Optional structural rules that reject overly broad or unexpected subscription filters.',fields:[
  ['enabled','Filter validation enabled','Apply the structural filter rules in this section.','checkbox'],['max_filters_per_req','Maximum filters per REQ','Largest number of filter objects accepted in one REQ.','number'],['min_filters_per_req','Minimum filters per REQ','Smallest number of filter objects required in one REQ.','number'],['max_kinds_per_filter','Kinds per filter','Largest number of event kinds allowed in one filter.','number'],['allowed_kinds','Allowed kinds','Comma-separated event kinds; empty allows every kind.','text','wide'],['require_author_or_tag','Require author or tag','Require each filter to constrain an author or a tag.','checkbox']
 ]},
 {key:'nip62',title:'NIP-62 deletion',help:'Controls Request to Vanish support and the size of durable deletion batches.',fields:[
  ['enabled','NIP-62 enabled','Advertise and process Request to Vanish events.','checkbox'],['service_url','Relay service URL','Public relay URL used to validate targeted vanish requests.','url','wide'],['deletion_batch_size','Deletion batch size','Maximum records removed in one transaction while processing a vanish request.','number']
 ]},
 {key:'history',title:'Dashboard history',help:'Bounded in-memory samples used by this dashboard; these do not affect Prometheus metrics.',fields:[
  ['enabled','History enabled','Collect in-memory samples for dashboard charts.','checkbox'],['interval_secs','Sampling interval','Seconds between in-memory metric snapshots.','number'],['max_points','Maximum points','Maximum retained snapshots; capped at 100,000.','number']
 ]}
];
function createForm(){
 const root=$('configGroups');
 for(const group of GROUPS){
  const details=document.createElement('details');details.className='config-group';details.open=!!group.open;
  const summary=document.createElement('summary');summary.innerHTML='<div class="config-header"><div><h2>'+group.title+'</h2><p>'+group.help+'</p></div></div>';details.append(summary);
  const fields=document.createElement('div');fields.className='config-fields';
  for(const f of group.fields){
   const [key,label,help,type,width,options]=f,id=group.key+'_'+key;
   const wrap=document.createElement('label');wrap.className='field '+(width||'')+(type==='checkbox'?' checkbox':'');
   const copy=document.createElement('span');copy.innerHTML='<span class="field-title">'+label+'</span><span class="field-help">'+help+'</span>';wrap.append(copy);
   let input;
   if(type==='select'){input=document.createElement('select');for(const [value,text] of options){const option=document.createElement('option');option.value=value;option.textContent=text;input.append(option)}}
   else{input=document.createElement('input');input.type=type;if(type==='number'){input.min='0';input.step='1';if(key==='min_pow_difficulty')input.max='255';if(key==='max_points')input.max='100000'}}
   input.id=id;input.className='config-input';input.dataset.group=group.key;input.dataset.key=key;wrap.append(input);fields.append(wrap);
  }
  details.append(fields);root.append(details);
 }
}
async function sha256(text){const bytes=new TextEncoder().encode(text),hash=await crypto.subtle.digest('SHA-256',bytes);return [...new Uint8Array(hash)].map(x=>x.toString(16).padStart(2,'0')).join('')}
function authNonce(){const bytes=crypto.getRandomValues(new Uint8Array(16));return [...bytes].map(x=>x.toString(16).padStart(2,'0')).join('')}
async function authFetch(path,method='GET',body=''){if(!window.nostr)throw Error('No NIP-07 signer was found in this browser');const url=PUBLIC_BASE+path,tags=[['u',url],['method',method],['nonce',authNonce()]];if(body)tags.push(['payload',await sha256(body)]);const ev=await window.nostr.signEvent({kind:27235,created_at:Math.floor(Date.now()/1000),content:'',tags});const headers={Authorization:'Nostr '+btoa(JSON.stringify(ev))};if(body)headers['Content-Type']='application/json';const res=await fetch(path,{method,body:body||undefined,headers});if(!res.ok)throw Error((await res.text())||res.statusText);return res.json()}
function setInput(input,value){if(input.type==='checkbox')input.checked=!!value;else input.value=value??''}
function getInput(input){if(input.type==='checkbox')return input.checked;if(input.type==='number'){if(!input.value)throw Error('Every numeric setting needs a value');return Number(input.value)}return input.value}
function render(d){
 data=d;const c=d.history.current||{};
 $('connections').textContent=fmt(c.active_connections);$('written').textContent=fmt(c.written_events_total);$('rejected').textContent=fmt(c.rejected_events_total);$('messages').textContent=fmt((c.client_messages_total||0)+(c.relay_messages_total||0));
 for(const input of document.querySelectorAll('.config-input'))setInput(input,d.config[input.dataset.group][input.dataset.key]);
 for(const input of document.querySelectorAll('.config-input'))input.disabled=!d.can_write_config;
 $('save').disabled=!d.can_write_config;$('saveStatus').textContent=d.can_write_config?'Changes are validated, atomically persisted, and live-reloaded.':'Configuration writes are disabled in wok.toml.';
 const chartPoints=d.history.points?.length?d.history.points:[{active_connections:c.active_connections||0},{active_connections:c.active_connections||0}];
 $('version').textContent=d.version;$('mode').textContent=d.can_write_config?'Editable':'Read only';$('refreshed').textContent=new Date().toLocaleTimeString();draw(chartPoints);
}
function yScale(maximum){const raw=Math.max(1,maximum)/4,magnitude=10**Math.floor(Math.log10(raw)),normalized=raw/magnitude;const nice=normalized<=1?1:normalized<=2?2:normalized<=5?5:10,step=Math.max(1,nice*magnitude),top=Math.max(step,Math.ceil(maximum/step)*step);return{step,top}}
function draw(points){
 const c=$('chart'),dpr=devicePixelRatio||1,r=c.getBoundingClientRect(),x=c.getContext('2d');c.width=r.width*dpr;c.height=r.height*dpr;x.scale(dpr,dpr);x.clearRect(0,0,r.width,r.height);
 const margin={top:12,right:14,bottom:27,left:50},width=Math.max(1,r.width-margin.left-margin.right),height=Math.max(1,r.height-margin.top-margin.bottom),observed=Math.max(0,...points.map(p=>p.active_connections)),scale=yScale(observed);
 x.font='12px Inter, "SF Pro Text", system-ui, sans-serif';x.textAlign='right';x.textBaseline='middle';x.lineWidth=1;
 for(let value=0;value<=scale.top;value+=scale.step){const py=margin.top+height-(value/scale.top)*height;x.fillStyle='#99a4b5';x.fillText(fmt(value),margin.left-9,py);x.strokeStyle=value===0?'#3a4351':'#28303c';x.beginPath();x.moveTo(margin.left,py);x.lineTo(margin.left+width,py);x.stroke()}
 c.setAttribute('aria-label','Connections over time. Y axis ranges from 0 to '+fmt(scale.top)+'.');
 if(!points.length)return;
 x.strokeStyle='#ff8a3d';x.lineWidth=2;x.lineJoin='round';x.lineCap='round';x.beginPath();points.forEach((p,i)=>{const px=margin.left+(points.length===1?width:width*i/(points.length-1)),py=margin.top+height-(p.active_connections/scale.top)*height;i?x.lineTo(px,py):x.moveTo(px,py)});x.stroke();
 if(points.length===1){const py=margin.top+height-(points[0].active_connections/scale.top)*height;x.fillStyle='#ff8a3d';x.beginPath();x.arc(margin.left+width,py,3,0,Math.PI*2);x.fill()}
}
async function load(first=false){try{$('status').textContent='Signing…';const next=await authFetch('/admin/api/overview');$('loginView').hidden=true;$('dashboard').hidden=false;render(next);$('status').textContent='Authenticated';$('status').className='status ok';$('loginStatus').textContent=''}catch(error){if(first){$('loginStatus').textContent=error.message;$('loginStatus').className='login-status bad'}else{$('status').textContent=error.message;$('status').className='status bad'}}}
function signOut(){data=null;$('dashboard').hidden=true;$('loginView').hidden=false;$('loginStatus').textContent='Signed out. A fresh signature is required to return.';$('loginStatus').className='login-status muted'}
function configBody(){const body={};for(const group of GROUPS){body[group.key]={};for(const input of document.querySelectorAll('[data-group="'+group.key+'"]'))body[group.key][input.dataset.key]=getInput(input)}return JSON.stringify(body)}
createForm();
$('login').onclick=()=>load(true);$('refresh').onclick=()=>load(false);$('logout').onclick=signOut;
$('save').onclick=async()=>{try{$('saveStatus').textContent='Signing and saving…';await authFetch('/admin/api/config','PUT',configBody());$('saveStatus').textContent='Saved. Refreshing…';await load(false)}catch(error){$('saveStatus').textContent=error.message;$('saveStatus').className='bad'}};
addEventListener('resize',()=>data&&draw(data.history.points||[]));
</script>
</body>
</html>"##;

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Keypair, SECP256K1};
    use serde_json::json;

    fn signed_auth_with_nonce(
        key: &Keypair,
        url: &str,
        method: &str,
        body: &[u8],
        nonce: Option<&str>,
    ) -> String {
        let (pubkey, _) = key.x_only_public_key();
        let mut tags = vec![json!(["u", url]), json!(["method", method])];
        if let Some(nonce) = nonce {
            tags.push(json!(["nonce", nonce]));
        }
        if !body.is_empty() {
            tags.push(json!(["payload", hex::encode(sha2::Sha256::digest(body))]));
        }
        let mut event = json!({
            "pubkey": hex::encode(pubkey.serialize()),
            "created_at": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            "kind": 27235,
            "tags": tags,
            "content": "",
        });
        let id = wok_event::event_id_hash(&event).unwrap();
        event["id"] = json!(hex::encode(id));
        event["sig"] = json!(hex::encode(SECP256K1.sign_schnorr(&id, key).as_ref()));
        format!(
            "Nostr {}",
            base64::engine::general_purpose::STANDARD.encode(event.to_string())
        )
    }

    fn signed_auth(key: &Keypair, url: &str, method: &str, body: &[u8]) -> String {
        signed_auth_with_nonce(key, url, method, body, None)
    }

    #[test]
    fn nip98_binds_admin_method_url_payload_and_prevents_replay() {
        let mut rng = rand::thread_rng();
        let key = Keypair::new(SECP256K1, &mut rng);
        let (pubkey, _) = key.x_only_public_key();
        let mut cfg = Config::default();
        cfg.admin.enabled = true;
        cfg.admin.public_url = "https://relay.example".into();
        cfg.admin.pubkeys = vec![hex::encode(pubkey.serialize())];
        let state = AdminState::default();
        let body = br#"{"history":{"max_points":10}}"#;
        let header = signed_auth(&key, "https://relay.example/admin/api/config", "PUT", body);
        assert!(authorize(
            Some(&header),
            &Method::PUT,
            "https://relay.example/admin/api/config",
            body,
            &cfg,
            &state
        )
        .is_ok());
        assert!(authorize(
            Some(&header),
            &Method::PUT,
            "https://relay.example/admin/api/config",
            body,
            &cfg,
            &state
        )
        .unwrap_err()
        .contains("already been used"));

        let wrong_payload = signed_auth(
            &key,
            "https://relay.example/admin/api/config",
            "PUT",
            b"different",
        );
        assert!(authorize(
            Some(&wrong_payload),
            &Method::PUT,
            "https://relay.example/admin/api/config",
            body,
            &cfg,
            &AdminState::default()
        )
        .unwrap_err()
        .contains("payload"));

        let wrong_url = signed_auth(&key, "https://relay.example/admin/api/other", "GET", b"");
        assert!(authorize(
            Some(&wrong_url),
            &Method::GET,
            "https://relay.example/admin/api/overview",
            b"",
            &cfg,
            &AdminState::default()
        )
        .unwrap_err()
        .contains("absolute request URL"));

        let other_key = Keypair::new(SECP256K1, &mut rng);
        let unauthorized = signed_auth(
            &other_key,
            "https://relay.example/admin/api/overview",
            "GET",
            b"",
        );
        assert!(authorize(
            Some(&unauthorized),
            &Method::GET,
            "https://relay.example/admin/api/overview",
            b"",
            &cfg,
            &AdminState::default()
        )
        .unwrap_err()
        .contains("not an administrator"));
    }

    #[test]
    fn nip98_rejects_duplicate_or_malformed_binding_tags() {
        let duplicate = json!({"tags": [["u", "https://relay.example"], ["u"]]});
        assert!(single_tag(&duplicate, "u")
            .unwrap_err()
            .contains("exactly one"));
        let malformed = json!({"tags": [["method"]]});
        assert!(single_tag(&malformed, "method")
            .unwrap_err()
            .contains("string value"));
    }

    #[test]
    fn nip98_nonce_makes_same_second_requests_unique() {
        let mut rng = rand::thread_rng();
        let key = Keypair::new(SECP256K1, &mut rng);
        let (pubkey, _) = key.x_only_public_key();
        let mut cfg = Config::default();
        cfg.admin.enabled = true;
        cfg.admin.public_url = "https://relay.example".into();
        cfg.admin.pubkeys = vec![hex::encode(pubkey.serialize())];
        let state = AdminState::default();
        let url = "https://relay.example/admin/api/overview";

        for nonce in ["first-request", "second-request"] {
            let header = signed_auth_with_nonce(&key, url, "GET", b"", Some(nonce));
            assert!(authorize(Some(&header), &Method::GET, url, b"", &cfg, &state,).is_ok());
        }
    }

    #[test]
    fn config_patch_is_typed_and_atomic() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wok.toml");
        std::fs::write(&path, "old").unwrap();
        atomic_write_config(&path, b"new").unwrap();
        assert_eq!(std::fs::read_to_string(path).unwrap(), "new");

        let patch: ConfigPatch = serde_json::from_value(json!({
            "info": {"contact": "ops@example.com"},
            "events": {"ephemeral_persistence": "ttl", "max_num_tags": 99},
            "limits": {"max_total_events_per_req": 123, "negentropy_enabled": false},
            "abuse": {"connection_burst": 7, "min_pow_difficulty": 8},
            "filters": {"enabled": true, "allowed_kinds": "1,7"},
            "nip62": {"deletion_batch_size": 44},
            "history": {"max_points": 10}
        }))
        .unwrap();
        let mut cfg = Config::default();
        apply_patch(&mut cfg, patch);
        assert_eq!(cfg.relay.info.contact, "ops@example.com");
        assert_eq!(cfg.events.ephemeral_persistence, EphemeralPersistence::Ttl);
        assert_eq!(cfg.events.max_num_tags, 99);
        assert_eq!(cfg.relay.max_total_events_per_req, 123);
        assert!(!cfg.relay.negentropy_enabled);
        assert_eq!(cfg.relay.abuse.connection_burst, 7);
        assert_eq!(cfg.relay.abuse.min_pow_difficulty, 8);
        assert!(cfg.relay.filter_validation.enabled);
        assert_eq!(cfg.relay.filter_validation.allowed_kinds, "1,7");
        assert_eq!(cfg.relay.nip62.deletion_batch_size, 44);
        assert_eq!(cfg.observability.history_max_points, 10);
        assert!(serde_json::from_value::<ConfigPatch>(json!({"database": {}})).is_err());
        assert!(serde_json::from_value::<ConfigPatch>(json!({
            "info": {"admin_pubkeys": []}
        }))
        .is_err());
    }

    #[test]
    fn admin_shell_starts_logged_out_and_explains_every_field() {
        assert!(ADMIN_HTML_V2.contains("Sign in to administer this relay"));
        assert!(ADMIN_HTML_V2.contains("id=\"dashboard\" class=\"dashboard\" hidden"));
        assert!(ADMIN_HTML_V2.contains("field-help"));
        assert!(ADMIN_HTML_V2.contains("grid-template-columns:1fr;gap:0"));
        assert!(ADMIN_HTML_V2.contains("minmax(220px,360px)"));
        assert!(ADMIN_HTML_V2.contains("Restart-only infrastructure"));
        assert!(ADMIN_HTML_V2.contains("fillText(fmt(value)"));
        assert!(ADMIN_HTML_V2.contains("Y axis ranges from 0"));
        assert!(ADMIN_HTML_V2.contains("chartPoints=d.history.points?.length"));
        assert!(ADMIN_HTML_V2.contains("$('dashboard').hidden=false;render(next)"));
        assert!(ADMIN_HTML_V2.contains(
            ".card,.panel,.config-group{background:linear-gradient(180deg,#131820,#11151c)"
        ));
    }
}
