use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use parking_lot::Mutex;
use serde::Deserialize;
use sha2::Digest;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use wok_relay::{Config, EphemeralPersistence, RelayHandle};

mod fields;
mod posture;

const MAX_ADMIN_BODY: usize = 64 * 1024;
pub(crate) const MAX_REPLAY_IDS: usize = 4096;

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
    per_connection: Option<PerConnectionPatch>,
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
    max_filter_bytes_per_connection: Option<usize>,
    max_filters_per_req: Option<usize>,
    query_timeslice_budget_us: Option<u64>,
    max_filter_limit: Option<u64>,
    max_tags_per_filter: Option<usize>,
    max_and_entries: Option<usize>,
    max_filter_limit_count: Option<u64>,
    max_total_events_per_req: Option<u64>,
    max_subs_per_connection: Option<usize>,
    max_pending_outbound_bytes: Option<usize>,
    write_policy_timeout_secs: Option<u64>,
    negentropy_enabled: Option<bool>,
    max_sync_events: Option<u64>,
    sync_memory_per_connection: Option<u64>,
    sync_memory_total: Option<u64>,
    sync_idle_timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AbusePatch {
    enabled: Option<bool>,
    ipv6_prefix_len: Option<u8>,
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
    invalid_rate_per_second: Option<u32>,
    invalid_burst: Option<u32>,
    max_concurrent_historical_queries: Option<usize>,
    max_query_work: Option<u64>,
    max_stored_events: Option<u64>,
    max_stored_events_per_pubkey: Option<u64>,
    min_pow_difficulty: Option<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PerConnectionPatch {
    req_rate_per_second: Option<u32>,
    req_burst: Option<u32>,
    neg_msg_rate_per_second: Option<u32>,
    neg_msg_burst: Option<u32>,
    count_rate_per_second: Option<u32>,
    count_burst: Option<u32>,
    authenticated_multiplier: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FiltersPatch {
    max_kinds_per_filter: Option<u64>,
    allowed_kinds: Option<String>,
    require_author_or_tag: Option<bool>,
    require_scoped_filters: Option<bool>,
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
    // Checked before the body is read: nothing can authorize a request whose
    // header fails here, so it is refused without waiting for its body.
    let event = match decode_authorization(authorization.as_deref()) {
        Ok(event) => event,
        Err(error) => return unauthorized(&error),
    };
    let absolute_url = format!("{}{}", cfg.admin.public_url, path_and_query);
    let verified = match verify(
        &event,
        &method,
        &cfg,
        &AuthzPolicy {
            url_ok: &|signed| signed == absolute_url,
            signer_ok: &|signer| cfg.admin.pubkeys.iter().any(|allowed| allowed == signer),
            require_payload: false,
        },
    ) {
        Ok(verified) => verified,
        Err(error) => return unauthorized(&error),
    };
    let body = match read_body(req.into_body(), MAX_ADMIN_BODY).await {
        Ok(body) => body,
        Err(error) => return response(StatusCode::PAYLOAD_TOO_LARGE, "text/plain", &error),
    };
    let (admin_pubkey, replay) = match authorize(verified, &body, &cfg, &state) {
        Ok(ok) => ok,
        Err(error) => return unauthorized(&error),
    };

    tracing::info!(
        admin_pubkey = %admin_pubkey,
        method = %method,
        path = %path,
        "authorized admin request"
    );
    let resp = match (method.clone(), path.as_str()) {
        (Method::GET, "/admin/api/overview") => overview(&handle),
        (Method::PUT, "/admin/api/config") => update_config(&handle, &body),
        _ => response(StatusCode::NOT_FOUND, "text/plain", "not found"),
    };
    // Admin handlers run synchronously and are atomic, so a non-2xx response
    // means nothing changed.
    if !resp.status().is_success() {
        replay.release();
    }
    resp
}

/// The event a request's `Authorization: Nostr <base64>` header carries,
/// decoded and parsed with Wok's strict JSON parser. Callers [`verify`] it
/// before reading the body.
pub(crate) fn decode_authorization(
    authorization: Option<&str>,
) -> Result<serde_json::Value, String> {
    let encoded = authorization
        .and_then(|value| value.strip_prefix("Nostr "))
        .ok_or_else(|| "missing Nostr authorization".to_string())?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| "invalid Nostr authorization encoding".to_string())?;
    std::str::from_utf8(&decoded)
        .ok()
        .and_then(|text| wok_event::json::parse_strict(text).ok())
        .ok_or_else(|| "invalid Nostr authorization JSON".to_string())
}

pub(crate) async fn read_body(mut body: Incoming, maximum: usize) -> Result<Vec<u8>, String> {
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

/// Policy decisions the caller makes about a NIP-98 authorization.
pub(crate) struct AuthzPolicy<'a> {
    /// Whether the signed `u` tag names the endpoint being protected.
    pub url_ok: &'a (dyn Fn(&str) -> bool + 'a),
    /// Whether the signer the event names may use the endpoint at all:
    /// listed in `admin.pubkeys` for the dashboard, holding a management
    /// level for NIP-86. Checked before the signature is verified.
    pub signer_ok: &'a (dyn Fn(&str) -> bool + 'a),
    /// Demand the `payload` tag even for an empty body (pinned NIP-86).
    pub require_payload: bool,
}

/// A NIP-98 event ID reserved in the replay cache by [`authorize`]. The ID
/// stays burned for the rest of the auth window unless the caller
/// [`release`](Self::release)s it after a failure known to have had no
/// effect, so a client can retry without re-signing. Dropping the
/// reservation keeps it burned: a cancelled request (client disconnect) may
/// already have queued its mutation on the writer (#51).
pub(crate) struct ReplayReservation<'a> {
    state: &'a AdminState,
    id: [u8; 32],
}

impl ReplayReservation<'_> {
    pub(crate) fn release(self) {
        self.state.used_auth.lock().remove(&self.id);
    }
}

impl std::fmt::Debug for ReplayReservation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplayReservation")
            .field("id", &hex::encode(self.id))
            .finish()
    }
}

/// The reply to an authorization whose signer may not use the endpoint, and
/// to one whose signature does not verify. It is one message for both, so a
/// forged event cannot ask whether a key is an admin or a manager; the
/// debug log records which.
pub(crate) const REFUSED_SIGNER: &str =
    "NIP-98 authorization is not from a key allowed here, or its signature is invalid";

/// A NIP-98 authorization whose every check that does not need the request
/// body has passed, signature included. [`authorize`] finishes it once the
/// body has arrived.
pub(crate) struct Verified<'e> {
    event: &'e serde_json::Value,
    require_payload: bool,
    pubkey: String,
    id: [u8; 32],
    created_at: u64,
}

/// Check everything a request's NIP-98 authorization states that does not
/// depend on its body. The kind, content, time window and tags come first,
/// then whether the signer may use the endpoint, then the signature. A
/// request that could never be authorized costs no verification, and
/// callers run this before reading the body, so it is refused without
/// waiting for one.
pub(crate) fn verify<'e>(
    event: &'e serde_json::Value,
    method: &Method,
    cfg: &Config,
    policy: &AuthzPolicy<'_>,
) -> Result<Verified<'e>, String> {
    if event.get("kind").and_then(serde_json::Value::as_u64) != Some(27235) {
        return Err("NIP-98 authorization must be kind 27235".into());
    }
    if event.get("content").and_then(serde_json::Value::as_str) != Some("") {
        return Err("NIP-98 authorization content must be empty".into());
    }
    let created_at = event.get("created_at").and_then(serde_json::Value::as_u64);
    if created_at
        .is_none_or(|created_at| created_at.abs_diff(unix_now()) > cfg.admin.auth_window_secs)
    {
        return Err("NIP-98 authorization is outside the accepted time window".into());
    }
    if !(policy.url_ok)(single_tag(event, "u")?) {
        return Err("NIP-98 u tag does not match the request URL".into());
    }
    if single_tag(event, "method")? != method.as_str() {
        return Err("NIP-98 method tag does not match the request method".into());
    }
    if policy.require_payload {
        single_tag(event, "payload")?;
    }
    let claimed = event.get("pubkey").and_then(serde_json::Value::as_str);
    if !claimed.is_some_and(|signer| (policy.signer_ok)(signer)) {
        tracing::debug!(signer = ?claimed, "refused NIP-98 authorization: signer not allowed");
        return Err(REFUSED_SIGNER.into());
    }
    let parsed = wok_event::parse_and_verify_event(
        event,
        &wok_event::EventLimits::default(),
        None,
        true,
        false,
    )
    .map_err(|error| {
        tracing::debug!(%error, "refused NIP-98 authorization: event does not verify");
        REFUSED_SIGNER.to_string()
    })?;
    let packed = parsed.packed.view();
    let mut id = [0u8; 32];
    id.copy_from_slice(packed.id());
    Ok(Verified {
        event,
        require_payload: policy.require_payload,
        pubkey: hex::encode(packed.pubkey()),
        id,
        created_at: packed.created_at(),
    })
}

/// Finish a [`verify`]d authorization with the request body: check the time
/// window again, check the `payload` tag against the body, then claim the
/// event in the replay cache.
pub(crate) fn authorize<'a>(
    verified: Verified<'_>,
    body: &[u8],
    cfg: &Config,
    state: &'a AdminState,
) -> Result<(String, ReplayReservation<'a>), String> {
    // The body may arrive long after `verify`: an event that expired while
    // it did is refused, or its replay entry, pruned as expired, could not
    // stop a second copy.
    let now = unix_now();
    if verified.created_at.abs_diff(now) > cfg.admin.auth_window_secs {
        return Err("NIP-98 authorization is outside the accepted time window".into());
    }
    if !body.is_empty() || verified.require_payload {
        let payload = single_tag(verified.event, "payload")?;
        if payload != hex::encode(sha2::Sha256::digest(body)) {
            return Err("NIP-98 payload tag does not match the request body".into());
        }
    }
    let mut used = state.used_auth.lock();
    used.retain(|_, created_at| created_at.abs_diff(now) <= cfg.admin.auth_window_secs);
    if used.contains_key(&verified.id) {
        return Err("NIP-98 authorization event has already been used".into());
    }
    if used.len() >= MAX_REPLAY_IDS {
        return Err("NIP-98 replay cache is full".into());
    }
    // Reserve under the same lock as the check, so two concurrent requests
    // carrying one signed event cannot both pass it.
    used.insert(verified.id, verified.created_at);
    Ok((
        verified.pubkey,
        ReplayReservation {
            state,
            id: verified.id,
        },
    ))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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
    let cfg = handle.config.read().clone();
    let file = handle.config_path().map(|path| file_state(&path));
    json(
        StatusCode::OK,
        serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "history": handle.metrics.history_json(),
            "can_write_config": cfg.admin.allow_config_writes && handle.config_path().is_some(),
            "preset": {"name": cfg.preset.name(), "summary": cfg.preset.summary()},
            "file": file,
            "posture": posture::posture(&cfg),
            "access": posture::access(&cfg),
            "sections": fields::SECTIONS,
            "config": dashboard_config(&cfg),
            "preset_config": dashboard_config(&cfg.preset_defaults()),
            "nip11": crate::nip11(&cfg)["limitation"],
            "refusals": refusals(&handle.metrics),
            "warnings": cfg.zero_guards().into_iter().map(|guard| {
                serde_json::json!({"keys": guard.keys, "warning": guard.warning})
            }).collect::<Vec<_>>(),
        }),
    )
}

/// What each setting refused over the last day, by config key, and since
/// when: `since` is null until the relay keeps its first mark.
fn refusals(metrics: &wok_relay::metrics::Metrics) -> serde_json::Value {
    let (since, counts) = match metrics.refusals.recent() {
        Some((since, counts)) => (Some(since), counts),
        None => (None, metrics.refusals.counts().collect()),
    };
    let counts: serde_json::Map<String, serde_json::Value> = counts
        .into_iter()
        .map(|(setting, count)| (setting.key().to_string(), count.into()))
        .collect();
    serde_json::json!({"since": since, "counts": counts})
}

/// What the config file on disk says: how many settings it overrides, or
/// why the relay cannot serve it, which a reload of it then refused.
fn file_state(path: &std::path::Path) -> serde_json::Value {
    let explained = std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))
        .and_then(|text| Config::explain_toml(&text));
    match explained {
        Ok(explained) => serde_json::json!({
            "path": path.display().to_string(),
            "overrides": explained.entries.iter().filter(|entry| entry.is_override()).count(),
            "problem": explained.config.serving_error().map(|error| {
                format!("{} cannot be served, so the relay kept its last configuration: {error}", path.display())
            }),
        }),
        Err(error) => serde_json::json!({
            "path": path.display().to_string(),
            "overrides": null,
            "problem": format!("{error}; the relay kept its last configuration"),
        }),
    }
}

/// The settings the dashboard shows and sends back on save, by form group.
fn dashboard_config(cfg: &Config) -> serde_json::Value {
    serde_json::json!({
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
            "max_filter_bytes_per_connection": cfg.relay.max_filter_bytes_per_connection,
            "max_filters_per_req": cfg.relay.max_filters_per_req,
            "query_timeslice_budget_us": cfg.relay.query_timeslice_budget_us,
            "max_filter_limit": cfg.relay.max_filter_limit,
            "max_tags_per_filter": cfg.relay.max_tags_per_filter,
            "max_and_entries": cfg.relay.max_and_entries,
            "max_filter_limit_count": cfg.relay.max_filter_limit_count,
            "max_total_events_per_req": cfg.relay.max_total_events_per_req,
            "max_subs_per_connection": cfg.relay.max_subs_per_connection,
            "max_pending_outbound_bytes": cfg.relay.max_pending_outbound_bytes,
            "write_policy_timeout_secs": cfg.relay.write_policy_timeout_secs,
            "negentropy_enabled": cfg.relay.negentropy_enabled,
            "max_sync_events": cfg.relay.max_sync_events,
            "sync_memory_per_connection": cfg.relay.sync_memory_per_connection,
            "sync_memory_total": cfg.relay.sync_memory_total,
            "sync_idle_timeout_secs": cfg.relay.sync_idle_timeout_secs,
        },
        "abuse": {
            "enabled": cfg.relay.abuse.enabled,
            "ipv6_prefix_len": cfg.relay.abuse.ipv6_prefix_len,
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
            "invalid_rate_per_second": cfg.relay.abuse.invalid_rate_per_second,
            "invalid_burst": cfg.relay.abuse.invalid_burst,
            "max_concurrent_historical_queries": cfg.relay.abuse.max_concurrent_historical_queries,
            "max_query_work": cfg.relay.abuse.max_query_work,
            "max_stored_events": cfg.relay.abuse.max_stored_events,
            "max_stored_events_per_pubkey": cfg.relay.abuse.max_stored_events_per_pubkey,
            "min_pow_difficulty": cfg.relay.abuse.min_pow_difficulty,
        },
        "per_connection": {
            "req_rate_per_second": cfg.relay.abuse.per_connection.req_rate_per_second,
            "req_burst": cfg.relay.abuse.per_connection.req_burst,
            "neg_msg_rate_per_second": cfg.relay.abuse.per_connection.neg_msg_rate_per_second,
            "neg_msg_burst": cfg.relay.abuse.per_connection.neg_msg_burst,
            "count_rate_per_second": cfg.relay.abuse.per_connection.count_rate_per_second,
            "count_burst": cfg.relay.abuse.per_connection.count_burst,
            "authenticated_multiplier": cfg.relay.abuse.per_connection.authenticated_multiplier,
        },
        "filters": {
            "max_kinds_per_filter": cfg.relay.filter_validation.max_kinds_per_filter,
            "allowed_kinds": cfg.relay.filter_validation.allowed_kinds,
            "require_author_or_tag": cfg.relay.filter_validation.require_author_or_tag,
            "require_scoped_filters": cfg.relay.filter_validation.require_scoped_filters,
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
        },
        // Shown but not editable: the patch has no such group. Restart
        // settings show the running value.
        "file": {
            "real_ip_header": cfg.relay.real_ip_header,
            "max_websocket_payload_size": cfg.relay.max_websocket_payload_size,
            "min_free_disk_bytes": cfg.db_min_free_disk_bytes,
            "map_size": cfg.db_mapsize,
        },
    })
}

fn update_config(handle: &RelayHandle, body: &[u8]) -> Response<Full<Bytes>> {
    match apply_config_patch(handle, body) {
        Ok(()) => json(StatusCode::OK, serde_json::json!({"saved": true})),
        Err((status, error)) => response(status, "text/plain", &error),
    }
}

/// Serializes reading, editing and replacing the config file, so concurrent
/// saves cannot drop each other's edits.
static CONFIG_WRITE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Validate, atomically persist, and live-reload a configuration patch.
/// Shared by the dashboard API and the NIP-86 relay-info methods.
pub(crate) fn apply_config_patch(
    handle: &RelayHandle,
    body: &[u8],
) -> Result<(), (StatusCode, String)> {
    if !handle.config.read().admin.allow_config_writes {
        return Err((StatusCode::FORBIDDEN, "config writes are disabled".into()));
    }
    let Some(path) = handle.config_path() else {
        return Err((
            StatusCode::CONFLICT,
            "relay was not started from a writable config file".into(),
        ));
    };
    let patch: ConfigPatch = serde_json::from_slice(body)
        .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
    let _writing = CONFIG_WRITE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let text = std::fs::read_to_string(&path).map_err(|error| {
        (
            StatusCode::CONFLICT,
            format!("cannot read {}: {error}", path.display()),
        )
    })?;
    let (edited, verified) =
        patched_file(&text, patch).map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    // The file may have been edited into a configuration the relay refuses
    // to serve, which a reload of it already refused; a save must not
    // persist or install it either.
    let unservable = |error| {
        (
            StatusCode::CONFLICT,
            format!(
                "{} cannot be served, so nothing was saved: {error}",
                path.display()
            ),
        )
    };
    if let Some(error) = verified.serving_error() {
        return Err(unservable(error));
    }
    if edited != text {
        wok_relay::config::write_file(&path, edited.as_bytes())
            .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error))?;
    }
    handle
        .config
        .write()
        .apply_reload(verified)
        .map_err(unservable)?;
    Ok(())
}

/// Apply a patch to the configuration of the file on disk and edit the file
/// in place: only keys whose value changes are touched, a key set back to its
/// preset value is removed, and comments, layout and `preset` are kept.
fn patched_file(text: &str, patch: ConfigPatch) -> Result<(String, Config), String> {
    Config::edit_toml(text, |config| apply_patch(config, patch))
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
        if let Some(value) = limits.max_filter_bytes_per_connection {
            config.relay.max_filter_bytes_per_connection = value;
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
        if let Some(value) = limits.max_and_entries {
            config.relay.max_and_entries = value;
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
        if let Some(value) = limits.sync_memory_per_connection {
            config.relay.sync_memory_per_connection = value;
        }
        if let Some(value) = limits.sync_memory_total {
            config.relay.sync_memory_total = value;
        }
        if let Some(value) = limits.sync_idle_timeout_secs {
            config.relay.sync_idle_timeout_secs = value;
        }
    }
    if let Some(abuse) = patch.abuse {
        if let Some(value) = abuse.enabled {
            config.relay.abuse.enabled = value;
        }
        if let Some(value) = abuse.ipv6_prefix_len {
            config.relay.abuse.ipv6_prefix_len = value;
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
        if let Some(value) = abuse.invalid_rate_per_second {
            config.relay.abuse.invalid_rate_per_second = value;
        }
        if let Some(value) = abuse.invalid_burst {
            config.relay.abuse.invalid_burst = value;
        }
        if let Some(value) = abuse.max_concurrent_historical_queries {
            config.relay.abuse.max_concurrent_historical_queries = value;
        }
        if let Some(value) = abuse.max_query_work {
            config.relay.abuse.max_query_work = value;
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
    if let Some(own) = patch.per_connection {
        let config = &mut config.relay.abuse.per_connection;
        if let Some(value) = own.req_rate_per_second {
            config.req_rate_per_second = value;
        }
        if let Some(value) = own.req_burst {
            config.req_burst = value;
        }
        if let Some(value) = own.neg_msg_rate_per_second {
            config.neg_msg_rate_per_second = value;
        }
        if let Some(value) = own.neg_msg_burst {
            config.neg_msg_burst = value;
        }
        if let Some(value) = own.count_rate_per_second {
            config.count_rate_per_second = value;
        }
        if let Some(value) = own.count_burst {
            config.count_burst = value;
        }
        if let Some(value) = own.authenticated_multiplier {
            config.authenticated_multiplier = value;
        }
    }
    if let Some(filters) = patch.filters {
        if let Some(value) = filters.max_kinds_per_filter {
            config.relay.filter_validation.max_kinds_per_filter = value;
        }
        if let Some(value) = filters.allowed_kinds {
            config.relay.filter_validation.allowed_kinds = value;
        }
        if let Some(value) = filters.require_author_or_tag {
            config.relay.filter_validation.require_author_or_tag = value;
        }
        if let Some(value) = filters.require_scoped_filters {
            config.relay.filter_validation.require_scoped_filters = value;
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

pub(crate) fn unauthorized(message: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("Content-Type", "text/plain; charset=utf-8")
        .header("WWW-Authenticate", "Nostr")
        .header("Cache-Control", "no-store")
        .body(Full::new(Bytes::copy_from_slice(message.as_bytes())))
        .unwrap()
}

pub(crate) fn json(status: StatusCode, value: serde_json::Value) -> Response<Full<Bytes>> {
    response(status, "application/json", &value.to_string())
}

pub(crate) fn response(
    status: StatusCode,
    content_type: &str,
    body: &str,
) -> Response<Full<Bytes>> {
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
    let body = ADMIN_HTML_V2
        .replace("__PUBLIC_URL__", &public_url)
        .replace("__WOK_MARK__", crate::WOK_MARK_SVG);
    // Pin the single inline <script> by hash instead of allowing all inline
    // scripts: a future XSS sink in the page then can't execute injected
    // script while talking to the operator's NIP-07 signer. The hash covers
    // the final substituted bytes, so config changes can't invalidate it.
    let script = body
        .split_once("<script>")
        .and_then(|(_, rest)| rest.split_once("</script>"))
        .map(|(js, _)| js)
        .unwrap_or("");
    let digest = sha2::Sha256::digest(script.as_bytes());
    let csp = format!(
        "default-src 'none'; script-src 'sha256-{}'; style-src 'unsafe-inline'; connect-src 'self'",
        base64::engine::general_purpose::STANDARD.encode(digest)
    );
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/html; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Frame-Options", "DENY")
        .header("X-Content-Type-Options", "nosniff")
        .header("Referrer-Policy", "no-referrer")
        .header("Content-Security-Policy", csp)
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
:root{color-scheme:dark;--bg:#090b0f;--panel:#11151c;--panel2:#151b24;--line:#28303c;--text:#f7f4ed;--muted:#99a4b5;--hot:#ff8a3d;--green:#5bd6a2;--red:#ff7373;--amber:#f3c15f}*{box-sizing:border-box}[hidden]{display:none!important}body{margin:0;min-height:100vh;background:radial-gradient(circle at 78% -8%,#1b120f 0,transparent 32rem),var(--bg);color:var(--text);font:15px/1.45 Inter,"SF Pro Text",system-ui,-apple-system,sans-serif}button,input,select{font:inherit}button{border:0;border-radius:10px;padding:10px 14px;background:var(--hot);color:#1e0c02;font-weight:760;cursor:pointer}button.secondary{background:#1c2330;color:var(--text);border:1px solid var(--line)}button:disabled{opacity:.45;cursor:not-allowed}a{color:var(--hot)}.mark{display:grid;place-items:center;width:46px;height:46px;background:#090b0f;color:#ff8a3d;box-shadow:0 10px 28px #0006}.mark svg{display:block;width:100%;height:100%}.muted{color:var(--muted)}.ok{color:var(--green)}.bad{color:var(--red)}
.login{display:grid;place-items:center;min-height:100vh;padding:24px}.login-card{width:min(470px,100%);padding:34px;background:linear-gradient(180deg,#131820,#11151c);border:1px solid var(--line);border-radius:12px;box-shadow:0 24px 70px #0006}.login-card .mark{margin-bottom:28px}.eyebrow{margin:0 0 8px;color:var(--hot);font-size:12px;font-weight:780;letter-spacing:.1em;text-transform:uppercase}.login h1{margin:0;font-size:34px;letter-spacing:-.04em}.login-copy{margin:14px 0 24px;color:var(--muted);font-size:16px;line-height:1.6}.login button{width:100%;padding:13px}.login-note{margin:18px 0 0;color:#7f8998;font-size:12px}.login-status{min-height:22px;margin-top:15px;font-size:13px}
.dashboard{max-width:1200px;margin:auto;padding:34px 24px 70px}.dashboard>header{display:flex;align-items:center;justify-content:space-between;gap:20px;margin-bottom:28px}.brand{display:flex;align-items:center;gap:14px}.brand h1{font-size:24px;margin:0}.toolbar{display:flex;gap:9px;align-items:center}.status{padding:9px 12px;border:1px solid var(--line);border-radius:8px;color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-top:16px}.card,.panel,.config-group,.posture{background:linear-gradient(180deg,#131820,#11151c);border:1px solid var(--line);border-radius:10px;box-shadow:0 12px 32px #0003}.card{padding:18px}.label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em}.value{font-size:29px;font-weight:780;margin-top:8px}.panels{display:grid;grid-template-columns:1.55fr 1fr;gap:16px;margin-top:16px}.panel{padding:20px}.panel h2,.config-header h2{font-size:16px;margin:0}.chart{height:245px;width:100%;margin-top:15px;background:#0b0e13;border-radius:8px;border:1px solid #1e2530}
.posture{padding:22px}.posture-head{display:flex;align-items:center;flex-wrap:wrap;gap:10px 14px}.posture-head h2{margin:0;font-size:20px}.badge{display:inline-block;padding:2px 9px;border:1px solid var(--line);border-radius:999px;font-size:12px;font-weight:700;color:var(--muted);white-space:nowrap}.badge.preset{border-color:#ff8a3d88;color:var(--hot)}.posture-summary{margin:12px 0 0;color:var(--muted)}.posture ul{margin:12px 0 0;padding-left:20px}.posture li{margin:4px 0}.warning{margin-top:14px;padding:11px 13px;border:1px solid #f3c15f66;border-radius:8px;background:#f3c15f12;color:var(--amber);font-size:13px}
.config{margin-top:16px}.config-intro{display:flex;align-items:flex-start;justify-content:space-between;gap:20px;margin-bottom:16px}.config-intro h2{margin:0 0 4px;font-size:20px}.config-intro p{margin:0}.config-groups{display:grid;gap:12px}.config-group{overflow:hidden}.config-group summary{list-style:none;cursor:pointer;padding:18px 20px}.config-group summary::-webkit-details-marker{display:none}.config-header{display:flex;align-items:center;justify-content:space-between;gap:15px}.config-header h2:after{content:"+";display:inline-block;margin-left:9px;color:var(--hot)}details[open] .config-header h2:after{content:"−"}.config-header p{max-width:650px;margin:3px 0 0;color:var(--muted);font-size:13px}.config-fields{display:grid;grid-template-columns:1fr;gap:0;padding:0 20px 4px;border-top:1px solid var(--line)}
.field{display:grid;grid-template-columns:minmax(0,1fr) minmax(220px,360px);align-items:center;gap:32px;padding:16px 0;border-bottom:1px solid #222a34}.field:last-child{border-bottom:0}.field-copy{min-width:0}.field-title,.field-help,.field-trade{display:block}.field-title{font-weight:680}.field-help{margin-top:3px;color:var(--muted);font-size:12px;line-height:1.45}.field-trade{margin-top:3px;color:#c3cad6;font-size:12px;line-height:1.45}.field-trade b{color:var(--muted);font-weight:700}.field-inputs{display:grid;gap:8px;min-width:0}.unit-input{display:flex;align-items:center;gap:8px;min-width:0}.unit-input>span{color:var(--muted);font-size:13px;white-space:nowrap}.unit-input>.bucket-label{flex:0 0 74px}.unit-input input[type=number],.unit-input input[type=text],.unit-input input[type=url],.unit-input select{flex:1 1 auto;min-width:0;height:42px;background:#0a0d12;border:1px solid var(--line);border-radius:7px;padding:9px 10px;color:var(--text)}.unit-input select.unit{flex:0 0 auto;width:auto}.unit-input input:focus,.unit-input select:focus{outline:2px solid #ff8a3d55;border-color:var(--hot)}.unit-input input[type=checkbox]{width:20px;height:20px;accent-color:var(--hot)}.off{display:flex;align-items:center;gap:6px;color:var(--muted);font-size:13px;white-space:nowrap}.read-only{font-weight:680}.field-meta{display:flex;flex-wrap:wrap;align-items:center;gap:6px 8px;margin-top:8px}.field-meta:empty{display:none}.field-meta .warning{flex-basis:100%;margin-top:2px}.badge.override{border-color:#f3c15f88;color:var(--amber)}.preset-value{color:var(--muted);font-size:12px}.refused{color:var(--hot);font-size:12px;font-weight:700}button.link{padding:0;background:none;border:0;border-radius:0;color:var(--hot);font-size:12px;font-weight:700;text-decoration:underline}.access-rows{display:grid;gap:0;padding:0 20px 8px;border-top:1px solid var(--line)}.access-row{display:grid;grid-template-columns:minmax(0,220px) minmax(0,1fr);gap:20px;padding:13px 0;border-bottom:1px solid #222a34}.access-row:last-child{border-bottom:0}.access-row>span:first-child{color:var(--muted);font-size:13px}
.actions{position:sticky;bottom:12px;display:flex;align-items:center;justify-content:space-between;gap:16px;margin-top:16px;padding:14px 16px;background:#11161ef2;border:1px solid var(--line);border-radius:10px;backdrop-filter:blur(12px)}
@media(max-width:820px){.grid{grid-template-columns:1fr 1fr}.panels{grid-template-columns:1fr}}@media(max-width:620px){.field{grid-template-columns:1fr;gap:10px}.access-row{grid-template-columns:1fr;gap:4px}}@media(max-width:560px){.dashboard{padding:22px 14px}.dashboard>header,.config-intro{align-items:flex-start;flex-direction:column}.toolbar{width:100%;flex-wrap:wrap}.grid{grid-template-columns:1fr}.login-card{padding:27px}.actions{align-items:flex-start;flex-direction:column}.actions button{width:100%}.posture{padding:18px}}
</style>
</head>
<body>
<section id="loginView" class="login">
  <div class="login-card">
    <div class="mark">__WOK_MARK__</div>
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
    <div class="brand"><div class="mark">__WOK_MARK__</div><div><h1>Wok operator</h1><span class="muted">Authenticated relay control surface</span></div></div>
    <div class="toolbar"><span id="status" class="status ok">Authenticated</span><button id="refresh" class="secondary">Refresh</button><button id="logout" class="secondary">Sign out</button></div>
  </header>
  <section class="posture" aria-labelledby="postureTitle">
    <div class="posture-head"><h2 id="postureTitle">Posture</h2><span id="presetName" class="badge preset">—</span><span id="overrides" class="badge">—</span></div>
    <p id="presetSummary" class="posture-summary"></p>
    <ul id="postureSentences"></ul>
    <p id="refusalSummary" class="posture-summary"></p>
    <div id="fileProblem" class="warning" hidden></div>
    <div id="postureWarnings"></div>
  </section>
  <section class="grid">
    <div class="card"><div class="label">Connections</div><div id="connections" class="value">—</div></div>
    <div class="card"><div class="label">Events written</div><div id="written" class="value">—</div></div>
    <div class="card"><div id="refusedLabel" class="label">Refused</div><div id="refused" class="value">—</div></div>
    <div class="card"><div class="label">Protocol messages</div><div id="messages" class="value">—</div></div>
  </section>
  <section class="panels">
    <div class="panel"><h2>Connections over time</h2><canvas id="chart" class="chart"></canvas><p class="muted">Bounded in-memory samples; a restart clears history.</p></div>
    <div class="panel"><h2>Runtime snapshot</h2><p class="muted">Version</p><p id="version">—</p><p class="muted">Configuration mode</p><p id="mode">—</p><p class="muted">Last refreshed</p><p id="refreshed">—</p></div>
  </section>
  <section class="config">
    <div class="config-intro"><div><h2>Relay configuration</h2><p class="muted">Live-reloadable operator settings, in the order an operator decides them. Access, restart-only infrastructure and other sensitive settings stay in wok.toml.</p></div></div>
    <div id="configGroups" class="config-groups"></div>
    <div class="actions"><span id="saveStatus" class="muted">Load configuration to begin.</span><button id="save" disabled>Save configuration</button></div>
  </section>
</main>
<script>
const PUBLIC_BASE=__PUBLIC_URL__;
const DOCS='https://github.com/erskingardner/wok/blob/master/docs/config.md';
const $=id=>document.getElementById(id);
const fmt=n=>new Intl.NumberFormat().format(n??0);
const UNITS={bytes:[[1073741824,'GiB'],[1048576,'MiB'],[1024,'KiB'],[1,'B']],seconds:[[31536000,'years'],[86400,'days'],[3600,'hours'],[60,'minutes'],[1,'seconds']],micros:[[1000,'ms'],[1,'µs']]};
let data=null,formBuilt=false;
function el(tag,cls,text){const e=document.createElement(tag);if(cls)e.className=cls;if(text!==undefined)e.textContent=text;return e}
function bestUnit(units,value){for(const [factor,name] of units)if(value&&value%factor===0)return [factor,name];return units[units.length-1]}
function describe(input,value){if(input.unit==='switch')return value?'On':'Off';if(input.zero_off&&value===0)return 'Off';const units=UNITS[input.unit];if(units){const [factor,name]=bestUnit(units,value);return fmt(value/factor)+' '+name}if(input.unit==='per_second')return fmt(value)+' /s';return typeof value==='number'?fmt(value):String(value||'Not set')}
function buildInput(input){
 const wrap=el('div','unit-input');wrap.dataset.group=input.group;wrap.dataset.name=input.name;
 if(input.file_only){wrap.append(el('span','read-only'));return wrap}
 const bucketLabel=input.unit==='per_second'?'Per second':input.name.endsWith('_burst')?'Burst':null;if(bucketLabel)wrap.append(el('span','bucket-label',bucketLabel));
 let field;
 if(input.unit==='switch'){field=el('input');field.type='checkbox'}
 else if(input.unit==='persistence'){field=el('select');for(const [value,text] of [['live_only','Live only'],['ttl','Keep for their lifetime']]){const option=el('option',null,text);option.value=value;field.append(option)}}
 else if(input.unit==='text'||input.unit==='url'){field=el('input');field.type=input.unit==='url'?'url':'text'}
 else{field=el('input');field.type='number';field.min='0';field.step=UNITS[input.unit]?'any':'1'}
 field.className='config-input';field.setAttribute('aria-label',input.key);wrap.append(field);
 const units=UNITS[input.unit];if(units){const select=el('select','unit');for(const [factor,name] of units){const option=el('option',null,name);option.value=factor;select.append(option)}select.setAttribute('aria-label',input.key+' unit');wrap.append(select)}
 if(input.zero_off){const label=el('label','off'),off=el('input');off.type='checkbox';off.className='off-switch';off.setAttribute('aria-label',input.key+' off');off.onchange=()=>{for(const part of wrap.querySelectorAll('.config-input,select.unit'))part.disabled=off.checked||!data.can_write_config;if(off.checked)field.value=''};label.append(off,document.createTextNode('Off'));wrap.append(label)}
 return wrap}
function setValue(input,wrap,value){
 if(input.file_only){wrap.querySelector('.read-only').textContent=describe(input,value)+' · wok.toml';return}
 const field=wrap.querySelector('.config-input'),unit=wrap.querySelector('select.unit'),off=wrap.querySelector('.off-switch');
 if(input.unit==='switch'){field.checked=!!value;return}
 if(off){off.checked=value===0}
 const units=UNITS[input.unit];
 if(units){const [factor]=bestUnit(units,value);unit.value=factor;field.value=input.zero_off&&value===0?'':value/factor;return}
 field.value=input.zero_off&&value===0?'':(value??'')}
function getValue(input,wrap){
 const field=wrap.querySelector('.config-input'),unit=wrap.querySelector('select.unit'),off=wrap.querySelector('.off-switch');
 if(input.unit==='switch')return field.checked;
 if(input.unit==='persistence'||input.unit==='text'||input.unit==='url')return field.value;
 if(off&&off.checked)return 0;
 if(field.value==='')throw Error(input.key+' needs a value');
 // A whole number of the setting's own unit, or a save could round 0.2 a
 // second down to 0, which turns a bucket off.
 const exact=Number(field.value)*(unit?Number(unit.value):1),value=Math.round(exact),base={bytes:'bytes',seconds:'seconds',micros:'microseconds',per_second:'per second'}[input.unit];
 if(!Number.isFinite(exact)||exact<0||Math.abs(exact-value)>1e-9*Math.max(1,exact))throw Error(input.key+' must be a whole number'+(base?' ('+base+')':'')+', not '+field.value+(unit?' '+unit.selectedOptions[0].textContent:''));
 return value}
// Settings the refusal counter names that have no field of their own.
const ACCESS_LABELS={'relay.auth.read_policy':'Reads','relay.auth.write_policy':'Writes','relay.auth.recipient_only_kinds':'Only to author and recipient','relay.auth.owner_only_kinds':'Only to their author','relay.auth.authenticated_kinds':'To any logged-in user','relay.auth.accepted_kinds':'Accepted kinds','relay.auth.enabled':'Login (NIP-42)','relay.auth.service_url':'Login (NIP-42)','relay.write_policy_plugin':'Write-policy plugin','relay.nip62.enabled':'Vanish requests (NIP-62)'};
function accessRows(a){
 const kinds=list=>list.length?list.map(k=>String(k.kind)+(k.name?' ('+k.name+')':'')+(k.stricter?' (governed by '+k.stricter+', which is stricter)':'')).join(', '):'None';
 return [
  ['Reads',a.read_policy+': '+a.read_policy_means,['relay.auth.read_policy']],
  ['Writes',a.write_policy+': '+a.write_policy_means,['relay.auth.write_policy']],
  ['Only to author and recipient',kinds(a.recipient_only_kinds),['relay.auth.recipient_only_kinds']],
  ['Only to their author',kinds(a.owner_only_kinds)+(a.owner_only_kinds.length?'; accepted only from a connection logged in as their author':''),['relay.auth.owner_only_kinds']],
  ['To any logged-in user',kinds(a.authenticated_kinds),['relay.auth.authenticated_kinds']],
  ['Deliverable to members',kinds(a.inbox_kinds)+(a.write_policy==='members'?'':' (used only with write_policy = members)'),[]],
  ['Accepted kinds',a.accepted_kinds?a.accepted_kinds.join(', '):'Every kind',['relay.auth.accepted_kinds']],
  ['Login (NIP-42)',a.auth_usable?'Available at '+a.service_url:a.auth_enabled?'Unavailable: relay.auth.service_url is not set':'Off: relay.auth.enabled is false',['relay.auth.enabled','relay.auth.service_url']],
  ['NIP-11','auth_required: '+a.auth_required+' · restricted_writes: '+a.restricted_writes,[]]]}
function buildAccess(root){
 const details=el('details','config-group');details.open=true;
 const summary=el('summary'),header=el('div','config-header'),copy=el('div');copy.append(el('h2',null,'Access'),el('p',null,'Who can read and write, and which kinds are private. Set in wok.toml: the dashboard shows these settings but cannot change them, so a remote save cannot lock anyone out.'));header.append(copy);summary.append(header);details.append(summary);
 const rows=el('div','access-rows');rows.id='accessRows';details.append(rows);root.append(details)}
function renderAccess(d){
 const a=d.access,rows=$('accessRows');rows.replaceChildren();
 for(const [label,text,keys] of accessRows(a)){
  const row=el('div','access-row'),value=el('span',null,text),refused=keys.reduce((n,key)=>n+(d.refusals.counts[key]||0),0);
  if(refused){value.append(document.createElement('br'),el('span','refused','Refused '+fmt(refused)+' '+windowPhrase(d.refusals.since)))}
  row.append(el('span',null,label),value);rows.append(row)}
 if(a.warning){const row=el('div','access-row'),warning=el('div','warning',a.warning);row.append(el('span',null,'Warning'),warning);rows.append(row)}
 const row=el('div','access-row'),link=el('a',null,'Read and write policies, read classes and accepted kinds');link.href=DOCS;link.rel='noreferrer';link.target='_blank';row.append(el('span',null,'Reference'),link);rows.append(row)}
function createForm(sections){
 const root=$('configGroups');buildAccess(root);
 for(const section of sections){
  const details=el('details','config-group');details.dataset.section=section.id;
  const summary=el('summary'),header=el('div','config-header'),copy=el('div');copy.append(el('h2',null,section.title),el('p',null,section.help));header.append(copy);summary.append(header);details.append(summary);
  const fields=el('div','config-fields');
  for(const f of section.fields){
   const row=el('div','field'),text=el('div','field-copy');text.append(el('span','field-title',f.label),el('span','field-help',f.help));
   for(const [label,copy] of [['If too low: ',f.too_low],['If too high: ',f.too_high]])if(copy){const line=el('span','field-trade');line.append(el('b',null,label),document.createTextNode(copy));text.append(line)}
   const meta=el('div','field-meta');meta.dataset.field=section.id+':'+section.fields.indexOf(f);text.append(meta);
   const inputs=el('div','field-inputs');for(const input of f.inputs)inputs.append(buildInput(input));
   row.append(text,inputs);fields.append(row)}
  details.append(fields);root.append(details)}
 formBuilt=true}
function wrapOf(input){return document.querySelector('.unit-input[data-group="'+input.group+'"][data-name="'+input.name+'"]')}
function syncDisabled(){for(const field of document.querySelectorAll('.config-input,.off-switch,select.unit')){const off=field.closest('.unit-input').querySelector('.off-switch');field.disabled=!data.can_write_config||(field!==off&&!!off&&off.checked)}}
function windowPhrase(since){if(since==null)return 'since the relay started';const secs=Date.now()/1000-since;if(secs>=23*3600)return 'in the last 24 h';if(secs>=3600)return 'in the last '+Math.round(secs/3600)+' h';return 'in the last '+Math.max(1,Math.round(secs/60))+' min'}
function renderMeta(d){
 for(const section of d.sections)section.fields.forEach((f,i)=>{
  const meta=document.querySelector('[data-field="'+section.id+':'+i+'"]');meta.replaceChildren();
  const preset=input=>d.preset_config[input.group][input.name],overridden=f.inputs.filter(input=>d.config[input.group][input.name]!==preset(input));
  if(overridden.length){
   meta.append(el('span','badge override','Override'),el('span','preset-value','Preset: '+overridden.map(input=>describe(input,preset(input))).join(', ')));
   if(d.can_write_config&&!f.inputs.some(input=>input.file_only)){const reset=el('button','link','Reset to preset');reset.type='button';reset.onclick=()=>{for(const input of f.inputs)setValue(input,wrapOf(input),preset(input));syncDisabled();$('saveStatus').textContent='Reset '+f.label+' to the preset; save to apply.';$('saveStatus').className='muted'};meta.append(reset)}}
  for(const input of f.inputs)for(const name of input.nip11)if(name in d.nip11)meta.append(el('span','badge','NIP-11: '+name));
  const refused=f.inputs.reduce((n,input)=>n+(d.refusals.counts[input.key]||0),0);
  if(refused)meta.append(el('span','refused','Refused '+fmt(refused)+' '+windowPhrase(d.refusals.since)));
  for(const w of d.warnings)if(w.keys.some(key=>f.inputs.some(input=>input.key===key)))meta.append(el('div','warning',w.warning));
 });
 // A guard with no field of its own is warned about on the posture card.
 const keys=new Set(d.sections.flatMap(section=>section.fields.flatMap(f=>f.inputs.map(input=>input.key))));
 $('postureWarnings').replaceChildren(...d.warnings.filter(w=>!w.keys.some(key=>keys.has(key))).map(w=>el('div','warning',w.warning)))}
function renderRefusals(d){
 const labels={...ACCESS_LABELS};for(const section of d.sections)for(const f of section.fields)for(const input of f.inputs)labels[input.key]=f.label;
 const refused=Object.entries(d.refusals.counts).filter(([,n])=>n>0).sort((a,b)=>b[1]-a[1]),total=refused.reduce((n,[,count])=>n+count,0),when=windowPhrase(d.refusals.since);
 $('refused').textContent=fmt(total);$('refusedLabel').textContent='Refused '+when;
 $('refusalSummary').textContent=total?'Refused '+fmt(total)+' requests and events '+when+', most by '+refused.slice(0,3).map(([key,n])=>(labels[key]||key)+' ('+fmt(n)+')').join(', ')+'.':'Nothing refused '+when+'.'}
function eachInput(fn){for(const section of data.sections)for(const f of section.fields)for(const input of f.inputs)fn(input,wrapOf(input))}
async function sha256(text){const bytes=new TextEncoder().encode(text),hash=await crypto.subtle.digest('SHA-256',bytes);return [...new Uint8Array(hash)].map(x=>x.toString(16).padStart(2,'0')).join('')}
function authNonce(){const bytes=crypto.getRandomValues(new Uint8Array(16));return [...bytes].map(x=>x.toString(16).padStart(2,'0')).join('')}
async function authFetch(path,method='GET',body=''){if(!window.nostr)throw Error('No NIP-07 signer was found in this browser');const url=PUBLIC_BASE+path,tags=[['u',url],['method',method],['nonce',authNonce()]];if(body)tags.push(['payload',await sha256(body)]);const ev=await window.nostr.signEvent({kind:27235,created_at:Math.floor(Date.now()/1000),content:'',tags});const headers={Authorization:'Nostr '+btoa(JSON.stringify(ev))};if(body)headers['Content-Type']='application/json';const res=await fetch(path,{method,body:body||undefined,headers});if(!res.ok)throw Error((await res.text())||res.statusText);return res.json()}
function renderPosture(d){
 $('presetName').textContent='preset: '+d.preset.name;$('presetSummary').textContent=d.preset.summary;
 $('overrides').textContent=!d.file?'no config file':d.file.overrides===null?'overrides unknown':d.file.overrides===1?'1 override':d.file.overrides+' overrides';
 if(d.file)$('overrides').title=d.file.path;
 const list=$('postureSentences');list.replaceChildren(...d.posture.map(s=>el('li',null,s)));
 const problem=d.file&&d.file.problem;$('fileProblem').hidden=!problem;$('fileProblem').textContent=problem||''}
function render(d){
 data=d;const c=d.history.current||{};
 if(!formBuilt)createForm(d.sections);
 renderPosture(d);renderAccess(d);renderRefusals(d);
 $('connections').textContent=fmt(c.active_connections);$('written').textContent=fmt(c.written_events_total);$('messages').textContent=fmt((c.client_messages_total||0)+(c.relay_messages_total||0));
 eachInput((input,wrap)=>setValue(input,wrap,d.config[input.group][input.name]));
 syncDisabled();renderMeta(d);
 $('save').disabled=!d.can_write_config;$('saveStatus').textContent=d.can_write_config?'Changes are validated, atomically persisted, and live-reloaded.':'Configuration writes are disabled in wok.toml.';$('saveStatus').className='muted';
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
function configBody(){const body={};eachInput((input,wrap)=>{if(input.file_only)return;const value=getValue(input,wrap);if(value!==data.config[input.group][input.name])(body[input.group]=body[input.group]||{})[input.name]=value});return body}
$('login').onclick=()=>load(true);$('refresh').onclick=()=>load(false);$('logout').onclick=signOut;
$('save').onclick=async()=>{try{const changes=configBody();if(!Object.keys(changes).length){$('saveStatus').textContent='No changes to save.';$('saveStatus').className='muted';return}$('saveStatus').textContent='Signing and saving…';await authFetch('/admin/api/config','PUT',JSON.stringify(changes));$('saveStatus').textContent='Saved. Refreshing…';await load(false)}catch(error){$('saveStatus').textContent='Not saved: '+error.message;$('saveStatus').className='bad'}};
addEventListener('resize',()=>data&&draw(data.history.points||[]));
</script>
</body>
</html>"##;

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Keypair, SECP256K1};
    use serde_json::json;
    use wok_relay::Preset;

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

    /// Both halves of a NIP-98 check, as dispatch runs them around reading
    /// the body.
    fn check<'a>(
        header: &str,
        method: &Method,
        body: &[u8],
        cfg: &Config,
        state: &'a AdminState,
        policy: &AuthzPolicy<'_>,
    ) -> Result<(String, ReplayReservation<'a>), String> {
        let event = decode_authorization(Some(header)).unwrap();
        authorize(verify(&event, method, cfg, policy)?, body, cfg, state)
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
        let policy = AuthzPolicy {
            url_ok: &|signed| signed == "https://relay.example/admin/api/config",
            signer_ok: &|signer| cfg.admin.pubkeys.iter().any(|allowed| allowed == signer),
            require_payload: false,
        };
        let auth = || check(&header, &Method::PUT, body, &cfg, &state, &policy);
        let (_, replay) = auth().unwrap();
        // While the first request is in flight, the same signed event cannot
        // authorize a concurrent second one (#51).
        assert!(auth().unwrap_err().contains("already been used"));
        // A request that failed without effect releases its reservation, so
        // the client can retry without re-signing.
        replay.release();
        // Success, or a cancelled request that may have taken effect, keeps
        // the ID burned for the rest of the window.
        assert!(auth().is_ok());
        assert!(auth().unwrap_err().contains("already been used"));

        let wrong_payload = signed_auth(
            &key,
            "https://relay.example/admin/api/config",
            "PUT",
            b"different",
        );
        assert!(check(
            &wrong_payload,
            &Method::PUT,
            body,
            &cfg,
            &AdminState::default(),
            &AuthzPolicy {
                url_ok: &|signed| signed == "https://relay.example/admin/api/config",
                signer_ok: &|signer| cfg.admin.pubkeys.iter().any(|allowed| allowed == signer),
                require_payload: false,
            },
        )
        .unwrap_err()
        .contains("payload"));

        let wrong_url = signed_auth(&key, "https://relay.example/admin/api/other", "GET", b"");
        assert!(check(
            &wrong_url,
            &Method::GET,
            b"",
            &cfg,
            &AdminState::default(),
            &AuthzPolicy {
                url_ok: &|signed| signed == "https://relay.example/admin/api/overview",
                signer_ok: &|signer| cfg.admin.pubkeys.iter().any(|allowed| allowed == signer),
                require_payload: false,
            },
        )
        .unwrap_err()
        .contains("u tag does not match"));

        let other_key = Keypair::new(SECP256K1, &mut rng);
        let unauthorized = signed_auth(
            &other_key,
            "https://relay.example/admin/api/overview",
            "GET",
            b"",
        );
        assert!(check(
            &unauthorized,
            &Method::GET,
            b"",
            &cfg,
            &AdminState::default(),
            &AuthzPolicy {
                url_ok: &|signed| signed == "https://relay.example/admin/api/overview",
                signer_ok: &|signer| cfg.admin.pubkeys.iter().any(|allowed| allowed == signer),
                require_payload: false,
            },
        )
        .unwrap_err()
        .contains(REFUSED_SIGNER));
    }

    /// `header` with its event's signature broken.
    fn forged(header: &str) -> String {
        let encoded = header.strip_prefix("Nostr ").unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        let mut event: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        let sig = event["sig"].as_str().unwrap().to_string();
        let flipped = if sig.starts_with('0') { "1" } else { "0" };
        event["sig"] = json!(format!("{flipped}{}", &sig[1..]));
        format!(
            "Nostr {}",
            base64::engine::general_purpose::STANDARD.encode(event.to_string())
        )
    }

    #[test]
    fn nip98_refuses_a_forged_event_alike_whoever_it_names() {
        let mut rng = rand::thread_rng();
        let admin = Keypair::new(SECP256K1, &mut rng);
        let stranger = Keypair::new(SECP256K1, &mut rng);
        let mut cfg = Config::default();
        cfg.admin.enabled = true;
        cfg.admin.public_url = "https://relay.example".into();
        cfg.admin.pubkeys = vec![hex::encode(admin.x_only_public_key().0.serialize())];
        let url = "https://relay.example/admin/api/overview";
        let policy = AuthzPolicy {
            url_ok: &|signed| signed == url,
            signer_ok: &|signer| cfg.admin.pubkeys.iter().any(|allowed| allowed == signer),
            require_payload: false,
        };
        let refusal = |header: &str| {
            check(
                header,
                &Method::GET,
                b"",
                &cfg,
                &AdminState::default(),
                &policy,
            )
            .unwrap_err()
        };
        // A stranger is refused before its signature is checked, and a
        // forged event naming the admin is refused by it, with one message,
        // so the reply cannot tell anyone which keys are admins.
        let stranger_signed = signed_auth(&stranger, url, "GET", b"");
        assert_eq!(refusal(&stranger_signed), REFUSED_SIGNER);
        assert_eq!(refusal(&forged(&stranger_signed)), REFUSED_SIGNER);
        assert_eq!(
            refusal(&forged(&signed_auth(&admin, url, "GET", b""))),
            REFUSED_SIGNER
        );
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
    fn nip98_expiring_while_the_body_arrives_is_refused() {
        let key = Keypair::new(SECP256K1, &mut rand::thread_rng());
        let mut cfg = Config::default();
        cfg.admin.enabled = true;
        cfg.admin.public_url = "https://relay.example".into();
        cfg.admin.pubkeys = vec![hex::encode(key.x_only_public_key().0.serialize())];
        cfg.admin.auth_window_secs = 1;
        let state = AdminState::default();
        let url = "https://relay.example/admin/api/config";
        let body = br#"{"history":{"max_points":10}}"#;
        let policy = AuthzPolicy {
            url_ok: &|signed| signed == url,
            signer_ok: &|signer| cfg.admin.pubkeys.iter().any(|allowed| allowed == signer),
            require_payload: false,
        };
        // Two copies of one signed request, both fresh when their headers
        // are checked, whose bodies arrive after the window has closed.
        let event = decode_authorization(Some(&signed_auth(&key, url, "PUT", body))).unwrap();
        let first = verify(&event, &Method::PUT, &cfg, &policy).unwrap();
        let second = verify(&event, &Method::PUT, &cfg, &policy).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2_200));
        for verified in [first, second] {
            assert!(authorize(verified, body, &cfg, &state)
                .unwrap_err()
                .contains("time window"));
        }
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
            assert!(check(
                &header,
                &Method::GET,
                b"",
                &cfg,
                &state,
                &AuthzPolicy {
                    url_ok: &|signed| signed == url,
                    signer_ok: &|signer| cfg.admin.pubkeys.iter().any(|allowed| allowed == signer),
                    require_payload: false,
                },
            )
            .is_ok());
        }
    }

    #[test]
    fn nip86_mode_requires_payload_tag_even_for_empty_body() {
        let mut rng = rand::thread_rng();
        let key = Keypair::new(SECP256K1, &mut rng);
        let (pubkey, _) = key.x_only_public_key();
        let mut cfg = Config::default();
        cfg.admin.enabled = true;
        cfg.admin.public_url = "https://relay.example".into();
        cfg.admin.pubkeys = vec![hex::encode(pubkey.serialize())];
        let state = AdminState::default();
        let url = "https://relay.example/";
        let policy = AuthzPolicy {
            url_ok: &|signed| signed == url,
            signer_ok: &|_| true,
            require_payload: true,
        };

        // Empty body signed without a payload tag: rejected in NIP-86 mode.
        let no_payload = signed_auth(&key, url, "POST", b"");
        let err = check(&no_payload, &Method::POST, b"", &cfg, &state, &policy).unwrap_err();
        assert!(err.contains("payload"), "{err}");

        // With the payload tag bound to SHA-256 of the empty body: accepted.
        let (pubkey, _) = key.x_only_public_key();
        let tags = vec![
            json!(["u", url]),
            json!(["method", "POST"]),
            json!(["payload", hex::encode(sha2::Sha256::digest(b""))]),
        ];
        let mut event = json!({
            "pubkey": hex::encode(pubkey.serialize()),
            "created_at": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            "kind": 27235,
            "tags": tags,
            "content": "",
        });
        let id = wok_event::event_id_hash(&event).unwrap();
        event["id"] = json!(hex::encode(id));
        event["sig"] = json!(hex::encode(SECP256K1.sign_schnorr(&id, &key).as_ref()));
        let header = format!(
            "Nostr {}",
            base64::engine::general_purpose::STANDARD.encode(event.to_string())
        );
        assert!(check(&header, &Method::POST, b"", &cfg, &state, &policy).is_ok());
    }

    #[test]
    fn config_patch_is_typed_and_atomic() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wok.toml");
        std::fs::write(&path, "old").unwrap();
        wok_relay::config::write_file(&path, b"new").unwrap();
        assert_eq!(std::fs::read_to_string(path).unwrap(), "new");

        let patch: ConfigPatch = serde_json::from_value(json!({
            "info": {"contact": "ops@example.com"},
            "events": {"ephemeral_persistence": "ttl", "max_num_tags": 99},
            "limits": {"max_total_events_per_req": 123, "negentropy_enabled": false},
            "abuse": {"connection_burst": 7, "min_pow_difficulty": 8},
            "filters": {"max_kinds_per_filter": 6, "allowed_kinds": "1,7"},
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
        assert_eq!(cfg.relay.filter_validation.max_kinds_per_filter, 6);
        assert_eq!(cfg.relay.filter_validation.allowed_kinds, "1,7");
        assert_eq!(cfg.relay.nip62.deletion_batch_size, 44);
        assert_eq!(cfg.observability.history_max_points, 10);
        assert!(serde_json::from_value::<ConfigPatch>(json!({"database": {}})).is_err());
        assert!(serde_json::from_value::<ConfigPatch>(json!({
            "info": {"admin_pubkeys": []}
        }))
        .is_err());
    }

    /// A hand-written file: comments, an inline comment, and a preset.
    const COMMENTED: &str = r#"# Example relay, behind nginx on this host.
preset = "public"

[relay]
# Loopback only: nginx terminates TLS.
bind = "127.0.0.1"
port = 7778          # 7777 is taken

[relay.info]
name = "Example relay"   # shown in NIP-11
description = "Notes and DMs."

[relay.abuse]
# Raised for the bridge that republishes in bursts.
event_burst = 500
"#;

    /// Save the way the dashboard does when the form was loaded from the
    /// file `loaded` and the file is now `disk`: like `configBody()`, send
    /// only the fields `edit` changes in the loaded form.
    fn dashboard_save_from(
        loaded: &str,
        disk: &str,
        edit: impl FnOnce(&mut serde_json::Value),
    ) -> Result<(String, Config), String> {
        let form = dashboard_config(&Config::parse_toml(loaded).unwrap());
        let mut edited = form.clone();
        edit(&mut edited);
        let mut body = json!({});
        for (group, fields) in edited.as_object().unwrap() {
            for (key, value) in fields.as_object().unwrap() {
                if form[group][key] != *value {
                    body.as_object_mut()
                        .unwrap()
                        .entry(group.clone())
                        .or_insert_with(|| json!({}))[key] = value.clone();
                }
            }
        }
        patched_file(disk, serde_json::from_value(body).unwrap())
    }

    fn dashboard_save(
        text: &str,
        edit: impl FnOnce(&mut serde_json::Value),
    ) -> Result<(String, Config), String> {
        dashboard_save_from(text, text, edit)
    }

    #[test]
    fn dashboard_save_from_a_stale_form_keeps_newer_changes() {
        // Another save raised event_burst after this form was loaded.
        let disk = COMMENTED.replace("event_burst = 500", "event_burst = 900");
        let (edited, verified) = dashboard_save_from(COMMENTED, &disk, |body| {
            body["info"]["name"] = json!("Renamed relay");
        })
        .unwrap();
        assert_eq!(
            edited,
            disk.replace(
                "name = \"Example relay\"   #",
                "name = \"Renamed relay\"   #"
            )
        );
        assert_eq!(verified.relay.abuse.event_burst, 900);
        // The page sends only the fields that differ from what it loaded.
        assert!(ADMIN_HTML_V2.contains(
            "if(value!==data.config[input.group][input.name])(body[input.group]=body[input.group]||{})"
        ));
        assert!(ADMIN_HTML_V2.contains("No changes to save."));
        // A fraction of a setting's own unit is refused, not rounded to 0.
        assert!(ADMIN_HTML_V2.contains("Math.abs(exact-value)>1e-9*Math.max(1,exact)"));
    }

    #[test]
    fn dashboard_save_changes_only_the_edited_key() {
        let (edited, verified) = dashboard_save(COMMENTED, |body| {
            body["info"]["name"] = json!("Renamed relay");
        })
        .unwrap();
        assert_eq!(
            edited,
            COMMENTED.replace(
                "name = \"Example relay\"   #",
                "name = \"Renamed relay\"   #"
            )
        );
        assert_eq!(verified.preset, Preset::Public);
        assert_eq!(verified.relay.info.name, "Renamed relay");
        assert_eq!(verified.relay.port, 7778);

        // Saving the form unchanged leaves the file as it is.
        let (unchanged, _) = dashboard_save(COMMENTED, |_| {}).unwrap();
        assert_eq!(unchanged, COMMENTED);
        // A file without `preset` does not gain one.
        let (edited, _) = dashboard_save("[relay.info]\nname = \"a\"\n", |body| {
            body["info"]["name"] = json!("b");
        })
        .unwrap();
        assert_eq!(edited, "[relay.info]\nname = \"b\"\n");
    }

    #[test]
    fn dashboard_save_writes_overrides_only() {
        // A key the file does not set is added to its table, or to a new one.
        let (edited, _) = dashboard_save(COMMENTED, |body| {
            body["abuse"]["req_burst"] = json!(80);
        })
        .unwrap();
        assert_eq!(
            edited,
            COMMENTED.replace("event_burst = 500\n", "event_burst = 500\nreq_burst = 80\n")
        );
        let (edited, _) = dashboard_save(COMMENTED, |body| {
            body["events"]["max_num_tags"] = json!(8000);
        })
        .unwrap();
        assert_eq!(
            edited,
            format!("{COMMENTED}\n[events]\nmax_num_tags = 8000\n")
        );

        // A key set back to its preset's value is removed with its comment,
        // and so is the table that leaves empty.
        let (edited, verified) = dashboard_save(COMMENTED, |body| {
            body["abuse"]["event_burst"] = json!(100);
        })
        .unwrap();
        assert_eq!(
            edited,
            COMMENTED.replace(
                "\n[relay.abuse]\n# Raised for the bridge that republishes in bursts.\nevent_burst = 500\n",
                ""
            )
        );
        assert_eq!(verified.relay.abuse.event_burst, 100);

        // Invalid values are refused before anything is written.
        let error = dashboard_save(COMMENTED, |body| {
            body["history"]["interval_secs"] = json!(0);
        })
        .unwrap_err();
        assert!(
            error.contains("history_interval_secs must be at least 1"),
            "{error}"
        );
    }

    #[test]
    fn admin_shell_starts_logged_out_and_explains_every_field() {
        assert_eq!(ADMIN_HTML_V2.matches("__WOK_MARK__").count(), 2);
        assert!(crate::WOK_MARK_SVG.contains("<path fill=\"currentColor\""));
        assert!(ADMIN_HTML_V2.contains("Sign in to administer this relay"));
        assert!(ADMIN_HTML_V2.contains("id=\"dashboard\" class=\"dashboard\" hidden"));
        assert!(ADMIN_HTML_V2.contains("field-help"));
        assert!(ADMIN_HTML_V2.contains("grid-template-columns:1fr;gap:0"));
        assert!(ADMIN_HTML_V2.contains("minmax(220px,360px)"));
        assert!(ADMIN_HTML_V2.contains("Access, restart-only infrastructure"));
        assert!(ADMIN_HTML_V2.contains("fillText(fmt(value)"));
        assert!(ADMIN_HTML_V2.contains("Y axis ranges from 0"));
        assert!(ADMIN_HTML_V2.contains("chartPoints=d.history.points?.length"));
        assert!(ADMIN_HTML_V2.contains("$('dashboard').hidden=false;render(next)"));
        assert!(ADMIN_HTML_V2.contains(
            ".card,.panel,.config-group,.posture{background:linear-gradient(180deg,#131820,#11151c)"
        ));
    }

    #[test]
    fn each_field_edits_the_config_key_it_names() {
        let defaults = dashboard_config(&Config::default());
        let mut covered = std::collections::HashSet::new();
        for field in fields::SECTIONS.iter().flat_map(|section| section.fields) {
            for input in field.inputs {
                let at = format!("{}.{} ({})", input.group, input.name, input.key);
                assert!(covered.insert((input.group, input.name)), "{at} twice");
                let value = &defaults[input.group][input.name];
                assert!(!value.is_null(), "{at} is not in the overview");
                let edit = |value: &serde_json::Value| {
                    serde_json::from_value::<ConfigPatch>(
                        json!({ input.group: { input.name: value } }),
                    )
                };
                if input.file_only {
                    assert!(edit(value).is_err(), "{at} is editable");
                    continue;
                }
                // Another valid value, as the page would send it.
                let changed = match value {
                    serde_json::Value::Bool(on) => json!(!on),
                    serde_json::Value::Number(_) => json!(7),
                    _ => match input.unit {
                        fields::Unit::Url => json!("wss://relay.test"),
                        fields::Unit::Persistence => json!("ttl"),
                        _ => json!("7"),
                    },
                };
                let (text, verified) = patched_file("", edit(&changed).unwrap()).unwrap();
                let set: Vec<_> = Config::explain_toml(&text)
                    .unwrap()
                    .entries
                    .into_iter()
                    .filter(|entry| matches!(entry.origin, wok_relay::config::Origin::File { .. }))
                    .map(|entry| entry.key)
                    .collect();
                assert_eq!(set, [input.key], "{at}");
                assert_eq!(
                    dashboard_config(&verified)[input.group][input.name],
                    changed,
                    "{at}"
                );
            }
        }
        // Every value the overview sends is on the page.
        for (group, values) in defaults.as_object().unwrap() {
            for name in values.as_object().unwrap().keys() {
                assert!(
                    covered.contains(&(group.as_str(), name.as_str())),
                    "{group}.{name} has no field"
                );
            }
        }
    }

    #[test]
    fn a_zero_that_disables_a_guard_is_shown_as_off() {
        // The relay warns about every zero that turns a guard off; each such
        // input must say Off rather than look like the strictest limit.
        for input in fields::SECTIONS
            .iter()
            .flat_map(|section| section.fields)
            .flat_map(|field| field.inputs)
            .filter(|input| !input.file_only)
        {
            if !dashboard_config(&Config::default())[input.group][input.name].is_number() {
                continue;
            }
            let patch = serde_json::from_value(json!({ input.group: { input.name: 0 } })).unwrap();
            let Ok((_, verified)) = patched_file("", patch) else {
                continue;
            };
            let guards = verified.zero_guards();
            if !guards.is_empty() {
                assert!(input.zero_off, "{} = 0 disables a guard", input.key);
                // The warning names the key, so the page shows it here.
                assert!(
                    guards
                        .iter()
                        .any(|guard| guard.keys.iter().any(|key| key == input.key)),
                    "{} = 0 warns about other keys: {guards:?}",
                    input.key
                );
            }
        }
    }

    #[test]
    fn nip11_chips_name_what_nip11_advertises() {
        // Every field NIP-11 can advertise: a lower bound set, abuse on.
        let mut cfg = Config::default();
        cfg.events.reject_older_than_secs = 3600;
        let advertised = crate::nip11(&cfg)["limitation"]
            .as_object()
            .unwrap()
            .clone();
        let mut chips: Vec<&str> = fields::SECTIONS
            .iter()
            .flat_map(|section| section.fields)
            .flat_map(|field| field.inputs)
            .flat_map(|input| input.nip11.iter().copied())
            .collect();
        chips.sort_unstable();
        // Constants and the access flags the Access panel shows have no
        // field of their own.
        let mut expected: Vec<&str> = advertised
            .keys()
            .map(String::as_str)
            .filter(|name| {
                !["max_subid_length", "auth_required", "restricted_writes"].contains(name)
            })
            .collect();
        expected.sort_unstable();
        assert_eq!(chips, expected);
        // Each chip's value is its input's.
        let values = dashboard_config(&cfg);
        for input in fields::SECTIONS
            .iter()
            .flat_map(|section| section.fields)
            .flat_map(|field| field.inputs)
        {
            for name in input.nip11 {
                assert_eq!(advertised[*name], values[input.group][input.name], "{name}");
            }
        }
        // A limit that is off is not advertised, so its chip is not shown.
        let limitation = crate::nip11(&Config::default())["limitation"].clone();
        assert!(limitation.get("created_at_lower_limit").is_none());
    }

    #[test]
    fn the_overview_counts_refusals_by_key() {
        let metrics = wok_relay::metrics::Metrics::default();
        metrics.refused(wok_relay::metrics::Setting::MaxQueryWork);
        // Before the first mark, counts are since start.
        let before = refusals(&metrics);
        assert_eq!(before["since"], serde_json::Value::Null);
        assert_eq!(before["counts"]["relay.abuse.max_query_work"], 1);
        metrics.refusals.mark(1_000);
        metrics.refused(wok_relay::metrics::Setting::MaxQueryWork);
        let after = refusals(&metrics);
        assert_eq!(after["since"], 1_000);
        assert_eq!(after["counts"]["relay.abuse.max_query_work"], 1);
        assert_eq!(after["counts"]["events.max_num_tags"], 0);
    }

    #[test]
    fn the_overview_reports_the_files_overrides_and_problems() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wok.toml");
        std::fs::write(
            &path,
            "preset = \"marmot\"\n\n[relay.abuse]\nevent_burst = 500\nreq_burst = 1000\n",
        )
        .unwrap();
        let state = file_state(&path);
        // req_burst repeats the preset, so only event_burst overrides it.
        assert_eq!(state["overrides"], 1);
        // The marmot preset needs AUTH, which this file leaves unusable.
        let problem = state["problem"].as_str().unwrap();
        assert!(problem.contains("cannot be served"), "{problem}");
        assert!(problem.contains("relay.auth.service_url"), "{problem}");

        std::fs::write(&path, "[relay]\nno_such_key = 1\n").unwrap();
        let state = file_state(&path);
        assert_eq!(state["overrides"], serde_json::Value::Null);
        assert!(state["problem"].as_str().unwrap().contains("no_such_key"));
    }

    #[test]
    fn admin_page_pins_inline_script_by_hash() {
        use base64::Engine;
        let mut cfg = Config::default();
        cfg.admin.enabled = true;
        cfg.admin.public_url = "https://relay.example".into();
        let resp = admin_page(&cfg);
        let csp = resp
            .headers()
            .get("Content-Security-Policy")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(!csp.contains("script-src 'unsafe-inline'"), "{csp}");
        let hash = csp
            .split("script-src 'sha256-")
            .nth(1)
            .and_then(|rest| rest.split('\'').next())
            .expect("script-src must carry a sha256 pin");
        // The pin must match the exact bytes of the inline script block.
        let body = ADMIN_HTML_V2
            .replace("__PUBLIC_URL__", "\"https://relay.example\"")
            .replace("__WOK_MARK__", crate::WOK_MARK_SVG);
        let script = body
            .split_once("<script>")
            .and_then(|(_, rest)| rest.split_once("</script>"))
            .map(|(js, _)| js)
            .unwrap();
        let expect = base64::engine::general_purpose::STANDARD
            .encode(sha2::Sha256::digest(script.as_bytes()));
        assert_eq!(hash, expect);
    }
}
