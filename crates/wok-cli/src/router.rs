//! `wok router` — multi-connection mesh client matching C++ `cmd_router.cpp`.
//!
//! Reads a tao-config-style router file (see strfry docs/router.md), keeps a
//! WebSocket client connection open to every configured URL, streams events
//! down (remote -> DB) and/or up (DB -> remote), hot-reloads the config on
//! change, and follows C++ reconnection and plugin semantics.

use crate::AUTH_EVENT_REFUSAL;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};
use wok_db::{Decompressor, Env, EventToWrite};
use wok_event::{parse_and_verify_event_with, EventLimits, IdPreimage, PackedEventView, AUTH_KIND};
use wok_query::NostrFilterGroup;
use wok_relay::plugin::{PluginEventSifter, PluginResult};
use wok_relay::Config;

// ---------------------------------------------------------------------------
// Router config file parsing (taocpp::config subset)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RouterConfig {
    pub connection_timeout: Duration,
    pub verbose: bool,
    pub streams: BTreeMap<String, StreamSpec>,
}

/// Parse-time ceiling for `connectionTimeout` (1 day; the default is 20s).
/// Values above this are rejected so reconnect arithmetic
/// (`timeout * 2`, `Instant + duration`) can never overflow.
const MAX_CONNECTION_TIMEOUT_SECS: u64 = 86_400;

#[derive(Debug, Clone)]
pub struct StreamSpec {
    pub dir: String,
    pub filter: Value,
    pub filter_str: String,
    pub plugin_down: String,
    pub plugin_up: String,
    pub urls: Vec<String>,
}

fn compile_router_filter(
    name: &str,
    filter: &Value,
    max_tags: usize,
    max_and_entries: usize,
) -> Result<NostrFilterGroup> {
    let filter_group = NostrFilterGroup::from_value(filter, u64::MAX, max_tags, max_and_entries)
        .map_err(|error| anyhow::anyhow!("stream {name}: bad filter: {error}"))?;
    if filter_group.requires_content() {
        bail!("stream {name}: router filters do not support content search");
    }
    Ok(filter_group)
}

fn router_event_matches(
    filter_group: &NostrFilterGroup,
    event: &Value,
    limits: &EventLimits,
) -> bool {
    wok_event::nostr_json_to_packed_event(event, limits)
        .map(|packed| filter_group.does_match(packed.view()))
        .unwrap_or(false)
}

enum Stmt {
    Open(String),
    Close,
    Assign(String, Value),
}

/// Split tao-config text into statements: `name {`, `}`, and `key = value`
/// where value may be a scalar, quoted string, `[ ... ]` array, or an
/// inline `{ ... }` JSON object (possibly multi-line). `#` and `//` comments
/// and both comma and newline separators are supported.
fn split_config(text: &str) -> Result<Vec<Stmt>> {
    let bytes = text.as_bytes();
    let mut i = 0usize;
    let mut out = Vec::new();

    fn skip_ws_comments(bytes: &[u8], i: &mut usize) {
        loop {
            while *i < bytes.len() && bytes[*i].is_ascii_whitespace() {
                *i += 1;
            }
            let is_hash_comment = *i < bytes.len() && bytes[*i] == b'#';
            let is_slash_comment =
                *i + 1 < bytes.len() && bytes[*i] == b'/' && bytes[*i + 1] == b'/';
            if is_hash_comment || is_slash_comment {
                while *i < bytes.len() && bytes[*i] != b'\n' {
                    *i += 1;
                }
            } else if *i < bytes.len() && (bytes[*i] == b',') {
                *i += 1;
            } else {
                break;
            }
        }
    }

    // Read a quoted string starting at bytes[*i] == '"'.
    fn read_string(bytes: &[u8], i: &mut usize) -> Result<String> {
        *i += 1;
        let mut s = String::new();
        while *i < bytes.len() {
            let c = bytes[*i];
            *i += 1;
            match c {
                b'"' => return Ok(s),
                b'\\' => {
                    if *i >= bytes.len() {
                        break;
                    }
                    let e = bytes[*i];
                    *i += 1;
                    match e {
                        b'n' => s.push('\n'),
                        b't' => s.push('\t'),
                        b'r' => s.push('\r'),
                        other => s.push(other as char),
                    }
                }
                _ => {
                    // Preserve UTF-8 bytes as-is.
                    let start = *i - 1;
                    let mut end = start + 1;
                    while end < bytes.len() && (bytes[end] & 0xC0) == 0x80 {
                        end += 1;
                    }
                    s.push_str(
                        std::str::from_utf8(&bytes[start..end])
                            .map_err(|_| anyhow::anyhow!("invalid UTF-8 in string"))?,
                    );
                    *i = end;
                }
            }
        }
        bail!("unterminated string")
    }

    // Read a balanced-delimiter value ([...] or {...}), string-aware.
    fn read_balanced(bytes: &[u8], i: &mut usize, open: u8, close: u8) -> Result<String> {
        let mut depth = 0usize;
        let start = *i;
        let mut in_string = false;
        let mut escaped = false;
        while *i < bytes.len() {
            let c = bytes[*i];
            if in_string {
                if escaped {
                    escaped = false;
                } else if c == b'\\' {
                    escaped = true;
                } else if c == b'"' {
                    in_string = false;
                }
                *i += 1;
                continue;
            }
            match c {
                b'"' => in_string = true,
                x if x == open => depth += 1,
                x if x == close => {
                    depth -= 1;
                    if depth == 0 {
                        *i += 1;
                        return Ok(std::str::from_utf8(&bytes[start..*i])
                            .map_err(|_| anyhow::anyhow!("invalid UTF-8"))?
                            .to_string());
                    }
                }
                _ => {}
            }
            *i += 1;
        }
        bail!("unbalanced delimiter")
    }

    while i < bytes.len() {
        skip_ws_comments(bytes, &mut i);
        if i >= bytes.len() {
            break;
        }
        let c = bytes[i];
        if c == b'}' {
            i += 1;
            out.push(Stmt::Close);
            continue;
        }
        // Read head up to '=', '{' or delimiter.
        let head_start = i;
        while i < bytes.len() && !matches!(bytes[i], b'=' | b'{' | b'\n' | b'#' | b'}') {
            i += 1;
        }
        let head = std::str::from_utf8(&bytes[head_start..i])
            .map_err(|_| anyhow::anyhow!("invalid UTF-8"))?
            .trim()
            .to_string();
        skip_ws_comments(bytes, &mut i);
        if i >= bytes.len() {
            if !head.is_empty() {
                bail!("trailing garbage: {head:?}");
            }
            break;
        }
        match bytes[i] {
            b'{' => {
                i += 1;
                if head.is_empty() {
                    bail!("block with no name");
                }
                out.push(Stmt::Open(head));
            }
            b'=' => {
                i += 1;
                skip_ws_comments(bytes, &mut i);
                if i >= bytes.len() {
                    bail!("missing value for {head:?}");
                }
                let value: Value = match bytes[i] {
                    b'"' => Value::String(read_string(bytes, &mut i)?),
                    b'[' => {
                        let raw = read_balanced(bytes, &mut i, b'[', b']')?;
                        // Entries are quoted strings separated by commas/whitespace.
                        let inner = raw[1..raw.len() - 1].trim();
                        let mut items = Vec::new();
                        let ib = inner.as_bytes();
                        let mut j = 0usize;
                        while j < ib.len() {
                            while j < ib.len() && (ib[j].is_ascii_whitespace() || ib[j] == b',') {
                                j += 1;
                            }
                            if j >= ib.len() {
                                break;
                            }
                            if ib[j] != b'"' {
                                bail!("array entries must be quoted strings");
                            }
                            items.push(Value::String(read_string(ib, &mut j)?));
                        }
                        Value::Array(items)
                    }
                    b'{' => {
                        let raw = read_balanced(bytes, &mut i, b'{', b'}')?;
                        wok_event::json::parse_strict(&raw)
                            .map_err(|e| anyhow::anyhow!("inline JSON: {e}"))?
                    }
                    _ => {
                        // Bare scalar: read to end of line/comment/comma.
                        let s_start = i;
                        while i < bytes.len() && !matches!(bytes[i], b'\n' | b'#' | b',') {
                            i += 1;
                        }
                        let tok = std::str::from_utf8(&bytes[s_start..i])
                            .map_err(|_| anyhow::anyhow!("invalid UTF-8"))?
                            .trim();
                        match tok {
                            "true" => Value::Bool(true),
                            "false" => Value::Bool(false),
                            _ => {
                                if let Ok(n) = tok.parse::<u64>() {
                                    Value::from(n)
                                } else if let Ok(f) = tok.parse::<f64>() {
                                    json!(f)
                                } else {
                                    bail!("unquoted value: {tok:?}");
                                }
                            }
                        }
                    }
                };
                out.push(Stmt::Assign(head, value));
            }
            _ => bail!("expected '=' or '{{' after {head:?}"),
        }
    }
    Ok(out)
}

pub fn parse_router_config(text: &str) -> Result<RouterConfig> {
    let stmts = split_config(text)?;
    let mut cfg = RouterConfig {
        connection_timeout: Duration::from_secs(20),
        verbose: true,
        streams: BTreeMap::new(),
    };
    let mut in_streams = false;
    let mut current_group: Option<String> = None;
    let mut group_fields: BTreeMap<String, Value> = BTreeMap::new();

    fn finish_group(
        name: &str,
        fields: &mut BTreeMap<String, Value>,
        cfg: &mut RouterConfig,
    ) -> Result<()> {
        let dir = fields
            .remove("dir")
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .with_context(|| format!("stream {name}: no dir field"))?;
        if !["up", "down", "both"].contains(&dir.as_str()) {
            bail!("stream {name}: invalid direction: {dir}");
        }
        let urls = fields
            .remove("urls")
            .and_then(|v| v.as_array().cloned())
            .with_context(|| format!("stream {name}: no urls field"))?;
        let urls: Vec<String> = urls
            .iter()
            .filter_map(|u| u.as_str().map(|s| s.to_string()))
            .collect();
        let filter = fields.remove("filter").unwrap_or_else(|| json!({}));
        if !filter.is_object() {
            bail!("stream {name}: filter must be an object");
        }
        let filter_str = wok_event::json::to_tao_string(&filter);
        Ok(())
            .map(|_| {
                cfg.streams.insert(
                    name.to_string(),
                    StreamSpec {
                        dir,
                        filter,
                        filter_str,
                        plugin_down: fields
                            .remove("pluginDown")
                            .and_then(|v| v.as_str().map(|s| s.to_string()))
                            .unwrap_or_default(),
                        plugin_up: fields
                            .remove("pluginUp")
                            .and_then(|v| v.as_str().map(|s| s.to_string()))
                            .unwrap_or_default(),
                        urls,
                    },
                );
            })
            .map(|_| ())
            .and_then(|_| {
                // Validate the filter compiles.
                compile_router_filter(name, &cfg.streams[name].filter, usize::MAX, usize::MAX)
                    .map(|_| ())
            })
    }

    for stmt in stmts {
        match stmt {
            Stmt::Open(name) => {
                if in_streams && current_group.is_none() {
                    current_group = Some(name);
                    group_fields.clear();
                } else if name == "streams" {
                    in_streams = true;
                } else {
                    bail!("unexpected block: {name}");
                }
            }
            Stmt::Close => {
                if let Some(name) = current_group.take() {
                    finish_group(&name, &mut group_fields, &mut cfg)?;
                } else if in_streams {
                    in_streams = false;
                } else {
                    bail!("unmatched '}}'");
                }
            }
            Stmt::Assign(key, value) => {
                if current_group.is_some() {
                    group_fields.insert(key, value);
                } else if in_streams {
                    bail!("field {key:?} outside any stream block");
                } else {
                    match key.as_str() {
                        "connectionTimeout" => {
                            let secs = value.as_u64().context("connectionTimeout")?;
                            // Reconnect math multiplies this by 2 and adds it
                            // to Instant::now(); keep it in a range that can't
                            // overflow Duration or Instant arithmetic.
                            if secs > MAX_CONNECTION_TIMEOUT_SECS {
                                bail!(
                                    "connectionTimeout {secs}s exceeds the {MAX_CONNECTION_TIMEOUT_SECS}s maximum"
                                );
                            }
                            cfg.connection_timeout = Duration::from_secs(secs);
                        }
                        "verbose" => {
                            cfg.verbose = value.as_bool().context("verbose")?;
                        }
                        _ => bail!("unknown top-level field: {key}"),
                    }
                }
            }
        }
    }
    if current_group.is_some() || in_streams {
        bail!("unclosed block");
    }
    Ok(cfg)
}

// ---------------------------------------------------------------------------
// Router runtime
// ---------------------------------------------------------------------------

enum ManagerMsg {
    Connected {
        group: String,
        url: String,
        id: u64,
        handle: ConnHandle,
    },
    Disconnected {
        group: String,
        url: String,
        id: u64,
    },
    /// A connection's up queue drained to `UP_QUEUE_LOW_WATER`.
    Drained,
    IncomingEvent {
        group: String,
        url: String,
        event: Value,
        /// Raw frame size; held against the shared queue budget until processed.
        approx_bytes: usize,
    },
    Log {
        group: String,
        url: String,
        text: String,
    },
}

/// Approximate cap on queued inbound event bytes between conn tasks and the
/// manager. The manager does a blocking plugin round-trip per event, so
/// without a byte bound a lagging manager lets producers queue unbounded
/// memory behind it. Producers block on the budget (TCP backpressure).
const MAX_QUEUED_EVENT_BYTES: usize = 64 * 1024 * 1024;

/// Flush the manager's write batch at this many queued bytes even if the
/// event count hasn't reached the per-flush limit.
const MAX_BATCH_BYTES: usize = 8 * 1024 * 1024;

/// Cap the text of log messages crossing the manager channel.
const MAX_LOG_CHARS: usize = 512;

/// Up-direction frames a connection queues before its stream waits for it.
const UP_QUEUE_CAPACITY: usize = 256;

/// A connection tells the manager when its up queue drains to this, so a
/// stream waiting on it resumes without waiting for the next DB change.
const UP_QUEUE_LOW_WATER: usize = UP_QUEUE_CAPACITY / 2;

/// How long a connection waits to send its Close frame on the way out.
const CLOSE_FRAME_TIMEOUT: Duration = Duration::from_secs(1);

struct Group {
    spec: StreamSpec,
    filter_group: NostrFilterGroup,
    plugin_down: PluginEventSifter,
    plugin_up: PluginEventSifter,
    /// url -> connection liveness state.
    conns: HashMap<String, ConnState>,
    /// Last levId this group's up direction has handled. Events after it are
    /// sent once every connected peer has queue room for them.
    up_cursor: u64,
}

struct ConnState {
    alive: bool,
    reconnect_after: Instant,
    /// Identifies the task spawned for this url, so a task a reload replaced
    /// can't report itself as this one.
    id: u64,
    /// Set once the task has connected. Dropping it closes the connection.
    handle: Option<ConnHandle>,
}

struct ConnHandle {
    /// Up-direction frames for the connection task to send.
    tx: mpsc::Sender<String>,
    /// Dropping this tells the task to close. It is separate from `tx` so a
    /// full queue can't hold the close back.
    _close: oneshot::Sender<()>,
}

pub async fn run_router(cfg: Config, router_path: PathBuf) -> Result<()> {
    let env = wok_db::Env::open(
        &cfg.db,
        wok_db::EnvOptions {
            max_readers: cfg.db_maxreaders,
            map_size: cfg.db_mapsize,
            no_read_ahead: cfg.db_no_read_ahead,
            ..wok_db::EnvOptions::default()
        },
    )?;
    env.ensure_initialized()?;
    let (manager_tx, mut manager_rx) = mpsc::channel::<ManagerMsg>(4096);
    let queue_budget = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_QUEUED_EVENT_BYTES));
    let mut groups: HashMap<String, Group> = HashMap::new();
    let mut router_cfg = load_router_config(&router_path)?;
    let mut head = {
        let txn = env.begin_ro()?;
        wok_db::most_recent_levid_ro(&txn).unwrap_or(0)
    };
    reconcile(&cfg, &router_cfg, &mut groups, head);
    // Some up group stopped at a peer's full queue and has events left.
    let mut up_behind = false;
    let mut next_conn_id = 0u64;

    let mut last_cfg_mtime = file_mtime(&router_path);
    let mut last_db_mtime = file_mtime(&env.path().join("data.mdb"));
    let mut batch: Vec<Value> = Vec::new();
    let mut batch_bytes = 0usize;
    let mut flush_tick = tokio::time::interval(Duration::from_secs(1));
    let mut watch_tick = tokio::time::interval(Duration::from_millis(250));
    let mut cron_tick =
        tokio::time::interval(router_cfg.connection_timeout.max(Duration::from_secs(1)));

    loop {
        tokio::select! {
            msg = manager_rx.recv() => {
                let Some(msg) = msg else { break };
                match msg {
                    ManagerMsg::Connected { group, url, id, handle } => {
                        // A task whose url a reload removed or replaced while
                        // it connected is closed by dropping its handle here.
                        if let Some(c) = conn_state(&mut groups, &group, &url, id) {
                            if router_cfg.verbose {
                                tracing::info!("{group}: Connected to {url}");
                            }
                            c.alive = true;
                            c.handle = Some(handle);
                        }
                    }
                    ManagerMsg::Disconnected { group, url, id } => {
                        tracing::info!("{group}: Disconnected from {url}");
                        if let Some(c) = conn_state(&mut groups, &group, &url, id) {
                            c.alive = false;
                            c.handle = None;
                            c.reconnect_after =
                                Instant::now() + router_cfg.connection_timeout * 2;
                        }
                    }
                    ManagerMsg::Drained => {
                        if up_behind {
                            up_behind = router_db_change(&env, &cfg, &mut groups, &mut head)?;
                        }
                    }
                    ManagerMsg::IncomingEvent { group, url, event, approx_bytes } => {
                        // Return the queue budget before doing the work.
                        queue_budget.add_permits(approx_bytes);
                        if let Some(g) = groups.get_mut(&group) {
                            if g.spec.dir != "up" {
                                let matches_filter = router_event_matches(
                                    &g.filter_group,
                                    &event,
                                    &cfg.event_limits(),
                                );
                                if !matches_filter {
                                    continue;
                                }
                                let cmd = g.spec.plugin_down.clone();
                                let ev = event.clone();
                                let res = tokio::task::block_in_place(|| {
                                    let mut msg = String::new();
                                    g.plugin_down.accept_event(&cmd, &ev, "Stream", &url, None, &mut msg)
                                });
                                if res == PluginResult::Accept {
                                    batch_bytes += approx_bytes;
                                    batch.push(event);
                                    if batch.len() >= 1000 || batch_bytes >= MAX_BATCH_BYTES {
                                        flush_router_batch(&env, &cfg, &mut batch)?;
                                        batch_bytes = 0;
                                    }
                                }
                            }
                        }
                    }
                    ManagerMsg::Log { group, url, text } => {
                        tracing::info!(
                            group = %group,
                            url = %url,
                            message = ?text,
                            "router peer message"
                        );
                    }
                }
            }
            _ = flush_tick.tick() => {
                if !batch.is_empty() {
                    flush_router_batch(&env, &cfg, &mut batch)?;
                    batch_bytes = 0;
                }
            }
            _ = watch_tick.tick() => {
                let m = file_mtime(&router_path);
                if m != last_cfg_mtime {
                    last_cfg_mtime = m;
                    match load_router_config(&router_path) {
                        Ok(new_cfg) => {
                            tracing::info!("router config reloaded");
                            reconcile(&cfg, &new_cfg, &mut groups, head);
                            router_cfg = new_cfg;
                        }
                        Err(e) => tracing::error!("router config reload failed, keeping old: {e}"),
                    }
                }
                // A stream that stopped at a full queue also retries here, in
                // case the peer it waits on disconnected instead of draining.
                let dm = file_mtime(&env.path().join("data.mdb"));
                if dm != last_db_mtime || up_behind {
                    last_db_mtime = dm;
                    up_behind = router_db_change(&env, &cfg, &mut groups, &mut head)?;
                }
            }
            _ = cron_tick.tick() => {
                // Reconnection cron: retry dead/missing connections after
                // ~2x connectionTimeout, like C++ tryConnects.
                let now = Instant::now();
                for (gname, g) in groups.iter_mut() {
                    for url in &g.spec.urls {
                        let needs = match g.conns.get(url) {
                            Some(c) => !c.alive && now >= c.reconnect_after,
                            None => true,
                        };
                        if needs {
                            next_conn_id += 1;
                            let id = next_conn_id;
                            g.conns.insert(
                                url.clone(),
                                ConnState {
                                    alive: true,
                                    reconnect_after: now + router_cfg.connection_timeout * 2,
                                    id,
                                    handle: None,
                                },
                            );
                            let dir = g.spec.dir.clone();
                            let filter = g.spec.filter.clone();
                            let gname2 = gname.clone();
                            let url2 = url.clone();
                            let tx = manager_tx.clone();
                            let timeout = router_cfg.connection_timeout;
                            let max_event_size = cfg.events.max_event_size;
                            let budget = queue_budget.clone();
                            tokio::spawn(async move {
                                run_conn(gname2, url2, id, dir, filter, tx, timeout, max_event_size, budget).await;
                            });
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// The state of `url` in `group`, if connection task `id` is still the one
/// spawned for it.
fn conn_state<'a>(
    groups: &'a mut HashMap<String, Group>,
    group: &str,
    url: &str,
    id: u64,
) -> Option<&'a mut ConnState> {
    groups
        .get_mut(group)?
        .conns
        .get_mut(url)
        .filter(|c| c.id == id)
}

fn file_mtime(p: &Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(p).ok().and_then(|m| m.modified().ok())
}

fn load_router_config(path: &Path) -> Result<RouterConfig> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read router config {}", path.display()))?;
    parse_router_config(&text).context("failed to parse router config")
}

fn flush_router_batch(env: &Env, cfg: &Config, batch: &mut Vec<Value>) -> Result<()> {
    let limits = cfg.event_limits();
    let mut evs = Vec::with_capacity(batch.len());
    for v in batch.drain(..) {
        let policy = cfg
            .timestamp_policy_for_kind(v.get("kind").and_then(Value::as_u64).unwrap_or(u64::MAX));
        // Events relayed from strfry or earlier Wok relays may carry legacy ids.
        match parse_and_verify_event_with(
            &v,
            &limits,
            Some(&policy),
            true,
            true,
            IdPreimage::Nip01OrLegacy,
        ) {
            Ok(p) if p.packed.view().kind() == AUTH_KIND => {
                tracing::warn!("router: downloaded event rejected: {AUTH_EVENT_REFUSAL}")
            }
            Ok(p) => evs.push(EventToWrite::new(p.packed.into_bytes(), p.json)),
            Err(e) => tracing::warn!("router: downloaded event rejected: {e}"),
        }
    }
    if evs.is_empty() {
        return Ok(());
    }
    let mut txn = env.begin_rw()?;
    let mut sink = wok_negentropy::DeferredSink::default();
    wok_db::write_events_with_policy(&mut txn, &mut sink, &mut evs, false, &cfg.vanish_policy())?;
    let mut cache = wok_negentropy::NegentropyFilterCache::new(cfg.relay.max_tags_per_filter);
    sink.apply(&mut cache, &mut txn)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    txn.commit()?;
    let n = evs
        .iter()
        .filter(|e| e.status == wok_db::EventWriteStatus::Written)
        .count();
    if n > 0 {
        tracing::info!("router: wrote {n} events");
    }
    Ok(())
}

/// Reconcile live groups with a (possibly new) config: drop removed
/// groups/urls, reconnect groups whose dir/filter changed, keep the rest.
/// Dropping a connection's state closes it. New and changed groups stream up
/// the events stored after `head`.
fn reconcile(
    cfg: &Config,
    router_cfg: &RouterConfig,
    groups: &mut HashMap<String, Group>,
    head: u64,
) {
    groups.retain(|name, _| router_cfg.streams.contains_key(name));
    for (name, spec) in &router_cfg.streams {
        let filter_group = match compile_router_filter(
            name,
            &spec.filter,
            cfg.relay.max_tags_per_filter,
            cfg.relay.max_and_entries,
        ) {
            Ok(fg) => fg,
            Err(e) => {
                tracing::error!("{e}; skipped");
                continue;
            }
        };
        match groups.get_mut(name) {
            Some(g) => {
                if g.spec.dir != spec.dir || g.spec.filter_str != spec.filter_str {
                    g.conns.clear();
                    g.spec.dir = spec.dir.clone();
                    g.spec.filter_str = spec.filter_str.clone();
                    g.spec.filter = spec.filter.clone();
                    g.filter_group = filter_group;
                    g.up_cursor = head;
                }
                let keep: HashSet<&String> = spec.urls.iter().collect();
                g.conns.retain(|url, _| keep.contains(url));
                g.spec.plugin_down = spec.plugin_down.clone();
                g.spec.plugin_up = spec.plugin_up.clone();
                g.spec.urls = spec.urls.clone();
            }
            None => {
                tracing::info!("New stream group [{name}]");
                groups.insert(
                    name.clone(),
                    Group {
                        spec: spec.clone(),
                        filter_group,
                        plugin_down: PluginEventSifter::new(cfg.relay.write_policy_timeout_secs),
                        plugin_up: PluginEventSifter::new(cfg.relay.write_policy_timeout_secs),
                        conns: HashMap::new(),
                        up_cursor: head,
                    },
                );
            }
        }
    }
}

/// One connection task per configured URL.
#[allow(clippy::too_many_arguments)]
async fn run_conn(
    group: String,
    url: String,
    id: u64,
    dir: String,
    filter: Value,
    tx: mpsc::Sender<ManagerMsg>,
    timeout: Duration,
    max_event_size: usize,
    budget: std::sync::Arc<tokio::sync::Semaphore>,
) {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let connect = async {
        tokio::time::timeout(
            timeout,
            tokio_tungstenite::connect_async_with_config(
                &url,
                Some(crate::mesh::mesh_ws_config(max_event_size)),
                false,
            ),
        )
        .await
        .map_err(|_| anyhow::anyhow!("timeout"))?
        .map_err(|e| anyhow::anyhow!(e.to_string()))
    };
    let remote_filter = async {
        if dir == "down" || dir == "both" {
            crate::mesh::outbound_filter_for_relay(&url, &filter).await
        } else {
            Ok(filter.clone())
        }
    };
    let (connect_result, remote_filter) = tokio::join!(connect, remote_filter);
    let (ws, _) = match connect_result {
        Ok(x) => x,
        Err(e) => {
            let _ = tx
                .send(ManagerMsg::Log {
                    group: group.clone(),
                    url: url.clone(),
                    text: format!("error connecting: {e}"),
                })
                .await;
            let _ = tx.send(ManagerMsg::Disconnected { group, url, id }).await;
            return;
        }
    };
    let remote_filter = match remote_filter {
        Ok(f) => f,
        Err(e) => {
            let _ = tx
                .send(ManagerMsg::Log {
                    group: group.clone(),
                    url: url.clone(),
                    text: format!("bad filter: {e}"),
                })
                .await;
            let _ = tx.send(ManagerMsg::Disconnected { group, url, id }).await;
            return;
        }
    };
    let (conn_tx, mut conn_rx) = mpsc::channel::<String>(UP_QUEUE_CAPACITY);
    let (close_tx, mut close_rx) = oneshot::channel::<()>();
    let _ = tx
        .send(ManagerMsg::Connected {
            group: group.clone(),
            url: url.clone(),
            id,
            handle: ConnHandle {
                tx: conn_tx,
                _close: close_tx,
            },
        })
        .await;

    // `close_rx` resolves once the manager drops the handle. A select that
    // sees it resolve ends the loop, so it is never polled again after that.
    // The loop is unbiased so neither reads nor queued sends starve the other.
    let (mut wtx, mut wrx) = ws.split();
    let mut open = true;
    if dir == "down" || dir == "both" {
        let mut f = remote_filter;
        f["limit"] = json!(0);
        let msg = json!(["REQ", "X", f]).to_string();
        open = send_frame(&mut wtx, Message::Text(msg.into()), timeout, &mut close_rx).await;
    }
    while open {
        tokio::select! {
            _ = &mut close_rx => break,
            msg = wrx.next() => {
                match msg {
                    Some(Ok(Message::Text(t))) => {
                        handle_conn_text(&tx, &group, &url, &t, max_event_size, &budget).await;
                    }
                    Some(Ok(Message::Binary(b))) => {
                        let t = String::from_utf8_lossy(&b).into_owned();
                        handle_conn_text(&tx, &group, &url, &t, max_event_size, &budget).await;
                    }
                    Some(Ok(Message::Ping(p))) => {
                        open = send_frame(&mut wtx, Message::Pong(p), timeout, &mut close_rx).await;
                    }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    _ => {}
                }
            }
            frame = conn_rx.recv() => {
                let Some(frame) = frame else { break };
                open = send_frame(&mut wtx, Message::Text(frame.into()), timeout, &mut close_rx).await;
                if open && conn_rx.len() == UP_QUEUE_LOW_WATER {
                    let _ = tx.send(ManagerMsg::Drained).await;
                }
            }
        }
    }
    let _ = tokio::time::timeout(CLOSE_FRAME_TIMEOUT, wtx.send(Message::Close(None))).await;
    let _ = tx.send(ManagerMsg::Disconnected { group, url, id }).await;
}

/// Send one frame unless the manager closes the connection first or the peer
/// takes longer than `timeout` to accept it, so a peer that stops reading
/// can't hold up its stream. False ends the connection.
async fn send_frame<S>(
    wtx: &mut S,
    frame: tokio_tungstenite::tungstenite::Message,
    timeout: Duration,
    close_rx: &mut oneshot::Receiver<()>,
) -> bool
where
    S: futures_util::Sink<tokio_tungstenite::tungstenite::Message> + Unpin,
{
    use futures_util::SinkExt;
    tokio::select! {
        biased;
        _ = &mut *close_rx => false,
        sent = tokio::time::timeout(timeout, wtx.send(frame)) => matches!(sent, Ok(Ok(()))),
    }
}

fn truncate_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

async fn handle_conn_text(
    tx: &mpsc::Sender<ManagerMsg>,
    group: &str,
    url: &str,
    t: &str,
    max_event_size: usize,
    budget: &std::sync::Arc<tokio::sync::Semaphore>,
) {
    // Reject frames that could never contain a valid event (max_event_size
    // plus the ["EVENT","sub", ...] envelope) before parsing or queueing.
    if t.len() > max_event_size.saturating_add(64) {
        tracing::warn!(url = url, "router: dropped oversize frame from relay");
        return;
    }
    let Ok(v) = serde_json::from_str::<Value>(t) else {
        return;
    };
    match v[0].as_str().unwrap_or("") {
        "EVENT" => {
            if let Some(ev) = v.get(2) {
                // Hold the frame's size against the shared queue budget so a
                // lagging manager applies backpressure instead of unbounded
                // queue growth.
                let bytes = t.len().min(MAX_QUEUED_EVENT_BYTES);
                let Ok(permit) = budget.clone().acquire_many_owned(bytes as u32).await else {
                    return;
                };
                let sent = tx
                    .send(ManagerMsg::IncomingEvent {
                        group: group.to_string(),
                        url: url.to_string(),
                        event: ev.clone(),
                        approx_bytes: bytes,
                    })
                    .await
                    .is_ok();
                if sent {
                    // The manager releases the budget once it dequeues this.
                    permit.forget();
                }
            }
        }
        "NOTICE" | "CLOSED" => {
            let _ = tx
                .send(ManagerMsg::Log {
                    group: group.to_string(),
                    url: url.to_string(),
                    text: truncate_chars(
                        &format!("{}: {v}", v[0].as_str().unwrap_or("peer")),
                        MAX_LOG_CHARS,
                    ),
                })
                .await;
        }
        "OK" if v[2].as_bool() == Some(false) => {
            let _ = tx
                .send(ManagerMsg::Log {
                    group: group.to_string(),
                    url: url.to_string(),
                    text: truncate_chars(&format!("event not written: {v}"), MAX_LOG_CHARS),
                })
                .await;
        }
        _ => {}
    }
}

/// DB changed or a peer's queue drained: stream new events to up/both groups
/// (C++ handleDBChange). Each group sends from its own cursor and stops at the
/// first event one of its connected peers has no queue room for, so a full
/// queue holds the event back instead of dropping it; a later call resumes
/// there. Returns whether any group stopped early.
fn router_db_change(
    env: &Env,
    cfg: &Config,
    groups: &mut HashMap<String, Group>,
    head: &mut u64,
) -> Result<bool> {
    let txn = env.begin_ro()?;
    *head = (*head).max(wok_db::most_recent_levid_ro(&txn)?);
    let mut decomp = Decompressor::new();
    let visibility = wok_query::visibility::ReadVisibility {
        ephemeral_lifetime_secs: Some(cfg.events.ephemeral_lifetime_secs),
        ..Default::default()
    };
    let snapshot = wok_query::visibility::ReadSnapshot::for_stored(&txn);
    let mut behind = false;
    for g in groups.values_mut() {
        if g.spec.dir == "down" {
            continue;
        }
        let peers: Vec<mpsc::Sender<String>> = g
            .conns
            .values()
            .filter_map(|c| c.handle.as_ref().map(|h| h.tx.clone()))
            .collect();
        let mut full = false;
        let mut visibility_error = None;
        wok_db::foreach_event_from(&txn, g.up_cursor.saturating_add(1), |lev, packed_bytes| {
            'event: {
                let Ok(packed) = PackedEventView::new(packed_bytes) else {
                    break 'event;
                };
                match visibility.globally_visible(&snapshot, packed) {
                    Ok(true) => {}
                    Ok(false) => break 'event,
                    Err(error) => {
                        visibility_error = Some(error);
                        return false;
                    }
                }
                if !g.filter_group.does_match(packed) {
                    break 'event;
                }
                // Reserve a slot with every connected peer before the plugin
                // sees the event. A peer whose task has exited is skipped.
                let mut permits = Vec::with_capacity(peers.len());
                for peer in &peers {
                    match peer.try_reserve() {
                        Ok(permit) => permits.push(permit),
                        Err(mpsc::error::TrySendError::Full(())) => {
                            full = true;
                            return false;
                        }
                        Err(mpsc::error::TrySendError::Closed(())) => {}
                    }
                }
                let Ok(json) =
                    wok_db::event_json_owned(&txn, &mut decomp, lev, cfg.events.max_event_size)
                else {
                    break 'event;
                };
                let Ok(ev) = serde_json::from_str::<Value>(&json) else {
                    break 'event;
                };
                let cmd = g.spec.plugin_up.clone();
                let res = tokio::task::block_in_place(|| {
                    let mut msg = String::new();
                    g.plugin_up
                        .accept_event(&cmd, &ev, "Stored", "", None, &mut msg)
                });
                if res == PluginResult::Accept {
                    let frame = format!("[\"EVENT\",{json}]");
                    for permit in permits {
                        permit.send(frame.clone());
                    }
                }
            }
            g.up_cursor = lev;
            true
        })?;
        if let Some(error) = visibility_error {
            return Err(error.into());
        }
        if full {
            behind = true;
        } else {
            g.up_cursor = g.up_cursor.max(*head);
        }
    }
    Ok(behind)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn up_spec(urls: Vec<String>) -> StreamSpec {
        StreamSpec {
            dir: "up".into(),
            filter: json!({}),
            filter_str: "{}".into(),
            plugin_down: String::new(),
            plugin_up: String::new(),
            urls,
        }
    }

    /// The handle of a connected peer whose queue holds `capacity` frames.
    fn conn_handle(capacity: usize) -> (ConnHandle, mpsc::Receiver<String>) {
        let (tx, rx) = mpsc::channel(capacity);
        let (close, _) = oneshot::channel();
        (ConnHandle { tx, _close: close }, rx)
    }

    /// An up group with one connected peer at `url`.
    fn up_group(url: &str, handle: ConnHandle) -> Group {
        Group {
            spec: up_spec(vec![url.to_string()]),
            filter_group: NostrFilterGroup::from_value(&json!({}), u64::MAX, 3, 16).unwrap(),
            plugin_down: PluginEventSifter::new(5),
            plugin_up: PluginEventSifter::new(5),
            conns: HashMap::from([(
                url.to_string(),
                ConnState {
                    alive: true,
                    reconnect_after: Instant::now(),
                    id: 1,
                    handle: Some(handle),
                },
            )]),
            up_cursor: 0,
        }
    }

    fn sent_events(rx: &mut mpsc::Receiver<String>) -> Vec<Value> {
        let mut sent = Vec::new();
        while let Ok(frame) = rx.try_recv() {
            sent.push(serde_json::from_str::<Value>(&frame).unwrap()[1].clone());
        }
        sent
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn router_outbound_skips_hidden_records_and_advances_the_cursor() {
        for (kind, ttl) in [(3, 1), (30443, 1), (20001, 1), (20001, 3600)] {
            let dir = tempfile::tempdir().unwrap();
            let events = replacement_fixture::events(kind);
            let env = replacement_fixture::seed(dir.path(), &events, 5);
            let mut cfg = Config::default();
            cfg.events.ephemeral_lifetime_secs = ttl;
            let (handle, mut rx) = conn_handle(8);
            let mut groups = HashMap::from([(
                "replacement-test".to_string(),
                up_group("ws://replacement-test.invalid", handle),
            )]);
            let mut head = 0;
            assert!(!router_db_change(&env, &cfg, &mut groups, &mut head).unwrap());
            assert!(!router_db_change(&env, &cfg, &mut groups, &mut head).unwrap());
            let sent = sent_events(&mut rx);
            assert_eq!(head, 3);
            assert_eq!(groups["replacement-test"].up_cursor, 3);
            let expected = if kind != 20001 {
                vec![events[2].clone()]
            } else if ttl == 1 {
                Vec::new()
            } else {
                events
            };
            assert_eq!(sent, expected, "kind {kind}, ttl {ttl}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn up_stream_waits_at_a_full_queue_and_sends_every_event() {
        use secp256k1::{Keypair, SECP256K1};
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), wok_db::EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let cfg = Config::default();
        let key = Keypair::new(SECP256K1, &mut rand::thread_rng());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut batch: Vec<Value> = (0..UP_QUEUE_CAPACITY * 2 + 10)
            .map(|i| {
                let mut event = json!({
                    "pubkey": hex::encode(key.x_only_public_key().0.serialize()),
                    "kind": 1,
                    "created_at": now,
                    "tags": [],
                    "content": format!("event {i}"),
                });
                let id = wok_event::event_id_hash(&event).unwrap();
                event["id"] = json!(hex::encode(id));
                event["sig"] = json!(hex::encode(SECP256K1.sign_schnorr(&id, &key).as_ref()));
                event
            })
            .collect();
        let mut stored: Vec<String> = batch
            .iter()
            .map(|e| e["id"].as_str().unwrap().to_string())
            .collect();
        flush_router_batch(&env, &cfg, &mut batch).unwrap();

        let (handle, mut rx) = conn_handle(UP_QUEUE_CAPACITY);
        let mut groups =
            HashMap::from([("full".to_string(), up_group("ws://full.invalid", handle))]);
        let mut head = 0;
        assert!(router_db_change(&env, &cfg, &mut groups, &mut head).unwrap());
        assert_eq!(rx.len(), UP_QUEUE_CAPACITY);
        let cursor = groups["full"].up_cursor;
        assert_eq!(cursor, UP_QUEUE_CAPACITY as u64);
        // While the queue stays full, the stream neither sends nor skips.
        assert!(router_db_change(&env, &cfg, &mut groups, &mut head).unwrap());
        assert_eq!(groups["full"].up_cursor, cursor);

        let mut sent = Vec::new();
        loop {
            sent.extend(sent_events(&mut rx));
            if !router_db_change(&env, &cfg, &mut groups, &mut head).unwrap() {
                break;
            }
        }
        sent.extend(sent_events(&mut rx));
        let mut sent: Vec<String> = sent
            .iter()
            .map(|e| e["id"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(sent.len(), stored.len());
        sent.sort();
        stored.sort();
        assert_eq!(sent, stored);
        assert_eq!(groups["full"].up_cursor, head);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reload_closes_a_connection_whose_up_queue_is_full() {
        // A peer that completes the handshake and then never reads.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let peer = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            std::future::pending::<()>().await;
        });
        let (manager_tx, mut manager_rx) = mpsc::channel(16);
        let budget = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_QUEUED_EVENT_BYTES));
        // A write timeout far beyond the test's wait, so only the close can
        // end the connection in time.
        let conn = tokio::spawn(run_conn(
            "g".into(),
            url.clone(),
            1,
            "up".into(),
            json!({}),
            manager_tx,
            Duration::from_secs(600),
            65536,
            budget,
        ));
        let Some(ManagerMsg::Connected { handle, .. }) = manager_rx.recv().await else {
            panic!("the connection did not report itself connected");
        };
        let frame = "x".repeat(64 * 1024);
        loop {
            match handle.tx.try_send(frame.clone()) {
                Ok(()) => tokio::task::yield_now().await,
                Err(mpsc::error::TrySendError::Full(_)) => break,
                Err(mpsc::error::TrySendError::Closed(_)) => panic!("the connection ended early"),
            }
        }

        let mut groups = HashMap::from([("g".to_string(), up_group(&url, handle))]);
        let router_cfg = RouterConfig {
            connection_timeout: Duration::from_secs(20),
            verbose: false,
            streams: BTreeMap::from([("g".to_string(), up_spec(Vec::new()))]),
        };
        reconcile(&Config::default(), &router_cfg, &mut groups, 0);
        assert!(groups["g"].conns.is_empty());
        tokio::time::timeout(Duration::from_secs(5), conn)
            .await
            .expect("the close was held back by the full queue")
            .unwrap();
        assert!(matches!(
            manager_rx.recv().await,
            Some(ManagerMsg::Disconnected { id: 1, .. })
        ));
        peer.abort();
    }

    #[tokio::test]
    async fn closed_subscription_is_reported_to_the_operator() {
        let (tx, mut rx) = mpsc::channel(1);
        let budget = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_QUEUED_EVENT_BYTES));
        handle_conn_text(
            &tx,
            "peer",
            "wss://peer.example",
            r#"["CLOSED","X","auth-required: authenticate"]"#,
            65536,
            &budget,
        )
        .await;
        let Some(ManagerMsg::Log { text, .. }) = rx.try_recv().ok() else {
            panic!("CLOSED was silently ignored")
        };
        assert!(text.contains("CLOSED") && text.contains("auth-required"));
    }

    #[test]
    fn connection_timeout_above_ceiling_is_rejected() {
        assert!(parse_router_config("connectionTimeout = 20").is_ok());
        assert!(parse_router_config("connectionTimeout = 86400").is_ok());
        assert!(parse_router_config("connectionTimeout = 86401").is_err());
        assert!(parse_router_config("connectionTimeout = 18446744073709551615").is_err());
    }

    #[test]
    fn parses_docs_example() {
        let text = r#"
            connectionTimeout = 20

            verbose = false

            streams {
                ## Stream down events from our friend relays

                friends {
                    dir = "down"
                    pluginDown = "/home/user/spam-filter.js"

                    urls = [
                        "wss://nos.lol"
                        "wss://relayable.org"
                    ]
                }

                cluster {
                    dir = "both"

                    urls = [
                        "wss://eu.example.com",
                        "wss://na.example.com",
                    ]
                }

                directory {
                    dir = "up"
                    filter = { "kinds": [0, 3] }

                    urls = [
                        "ws://internal-directory.example.com"
                    ]
                }
            }
        "#;
        let cfg = parse_router_config(text).unwrap();
        assert_eq!(cfg.connection_timeout.as_secs(), 20);
        assert!(!cfg.verbose);
        assert_eq!(cfg.streams.len(), 3);
        let friends = &cfg.streams["friends"];
        assert_eq!(friends.dir, "down");
        assert_eq!(friends.plugin_down, "/home/user/spam-filter.js");
        assert_eq!(friends.urls, vec!["wss://nos.lol", "wss://relayable.org"]);
        let directory = &cfg.streams["directory"];
        assert_eq!(directory.filter_str, r#"{"kinds":[0,3]}"#);
        assert_eq!(directory.urls, vec!["ws://internal-directory.example.com"]);
    }

    #[test]
    fn errors_on_bad_configs() {
        // no dir
        assert!(parse_router_config("streams { x { urls = [\"wss://a\"] } }").is_err());
        // no urls
        assert!(parse_router_config("streams { x { dir = \"down\" } }").is_err());
        // unclosed block
        assert!(
            parse_router_config("streams { x { dir = \"down\" urls = [\"wss://a\"] }").is_err()
        );
        // unknown top-level key
        assert!(parse_router_config("unknown = 1\nstreams {}").is_err());
        // content is unavailable in the router's packed-event matcher
        let error = parse_router_config(
            "streams { x { dir = \"up\" filter = { \"search\": \"nostr\" } urls = [\"wss://a\"] } }",
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("router filters do not support content search"));
    }

    #[test]
    fn inline_json_filter_with_nested_braces() {
        let cfg = parse_router_config(
            "streams { g { dir = \"both\" filter = { \"kinds\": [1], \"authors\": [\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"] } urls = [\"wss://x\"] } }",
        )
        .unwrap();
        let g = &cfg.streams["g"];
        assert_eq!(
            g.filter_str,
            "{\"authors\":[\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"],\"kinds\":[1]}"
        );
    }

    #[test]
    fn nip91_post_filters_fallback_results_from_older_relays() {
        let filter = compile_router_filter(
            "nip91",
            &json!({"&t":["meme", "cat"], "#t":["meme", "cat", "black"]}),
            3,
            16,
        )
        .unwrap();
        let event = |tags: Vec<Value>| {
            json!({
                "id":"11".repeat(32),
                "pubkey":"22".repeat(32),
                "created_at":1,
                "kind":1,
                "tags":tags,
                "content":"",
                "sig":"33".repeat(64)
            })
        };
        assert!(router_event_matches(
            &filter,
            &event(vec![
                json!(["t", "meme"]),
                json!(["t", "cat"]),
                json!(["t", "black"])
            ]),
            &EventLimits::default(),
        ));
        assert!(!router_event_matches(
            &filter,
            &event(vec![json!(["t", "meme"]), json!(["t", "cat"])]),
            &EventLimits::default(),
        ));
    }
}

#[cfg(test)]
#[path = "../tests/support/replacement.rs"]
mod replacement_fixture;
