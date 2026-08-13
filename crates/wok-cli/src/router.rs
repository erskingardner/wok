//! `wok router` — multi-connection mesh client matching C++ `cmd_router.cpp`.
//!
//! Reads a tao-config-style router file (see strfry docs/router.md), keeps a
//! WebSocket client connection open to every configured URL, streams events
//! down (remote -> DB) and/or up (DB -> remote), hot-reloads the config on
//! change, and follows C++ reconnection and plugin semantics.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use wok_db::{Decompressor, Env, EventToWrite};
use wok_event::{parse_and_verify_event, PackedEventView};
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

#[derive(Debug, Clone)]
pub struct StreamSpec {
    pub dir: String,
    pub filter: Value,
    pub filter_str: String,
    pub plugin_down: String,
    pub plugin_up: String,
    pub urls: Vec<String>,
}

fn compile_router_filter(name: &str, filter: &Value) -> Result<NostrFilterGroup> {
    let filter_group = NostrFilterGroup::from_value(filter, u64::MAX, 64)
        .map_err(|error| anyhow::anyhow!("stream {name}: bad filter: {error}"))?;
    if filter_group.requires_content() {
        bail!("stream {name}: router filters do not support content search");
    }
    Ok(filter_group)
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
                compile_router_filter(name, &cfg.streams[name].filter).map(|_| ())
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
                            cfg.connection_timeout =
                                Duration::from_secs(value.as_u64().context("connectionTimeout")?);
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

enum ConnMsg {
    /// Manager -> connection task: send this raw frame to the remote.
    Send(String),
    /// Manager -> connection task: close and exit.
    Close,
}

enum ManagerMsg {
    Connected {
        group: String,
        url: String,
    },
    Disconnected {
        group: String,
        url: String,
    },
    IncomingEvent {
        group: String,
        url: String,
        event: Value,
    },
    Log {
        group: String,
        url: String,
        text: String,
    },
}

struct Group {
    spec: StreamSpec,
    filter_group: NostrFilterGroup,
    plugin_down: PluginEventSifter,
    plugin_up: PluginEventSifter,
    /// url -> connection liveness state.
    conns: HashMap<String, ConnState>,
}

#[derive(Clone, Copy)]
struct ConnState {
    alive: bool,
    reconnect_after: Instant,
}

/// Live connection senders keyed by (group, url); maintained by conn tasks.
type ConnKey = (String, String);
static CONN_REGISTRY: std::sync::LazyLock<
    parking_lot::Mutex<HashMap<ConnKey, mpsc::Sender<ConnMsg>>>,
> = std::sync::LazyLock::new(|| parking_lot::Mutex::new(HashMap::new()));

fn registry_close(group: &str, url: &str) {
    if let Some(tx) = CONN_REGISTRY
        .lock()
        .get(&(group.to_string(), url.to_string()))
    {
        let _ = tx.try_send(ConnMsg::Close);
    }
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
    let mut groups: HashMap<String, Group> = HashMap::new();
    let mut router_cfg = load_router_config(&router_path)?;
    reconcile(&cfg, &router_cfg, &mut groups);
    let mut curr_event_id = {
        let txn = env.begin_ro()?;
        wok_db::most_recent_levid_ro(&txn).unwrap_or(0)
    };

    let mut last_cfg_mtime = file_mtime(&router_path);
    let mut last_db_mtime = file_mtime(&env.path().join("data.mdb"));
    let mut batch: Vec<Value> = Vec::new();
    let mut flush_tick = tokio::time::interval(Duration::from_secs(1));
    let mut watch_tick = tokio::time::interval(Duration::from_millis(250));
    let mut cron_tick =
        tokio::time::interval(router_cfg.connection_timeout.max(Duration::from_secs(1)));

    loop {
        tokio::select! {
            msg = manager_rx.recv() => {
                let Some(msg) = msg else { break };
                match msg {
                    ManagerMsg::Connected { group, url } => {
                        if router_cfg.verbose {
                            tracing::info!("{group}: Connected to {url}");
                        }
                        if let Some(g) = groups.get_mut(&group) {
                            if let Some(c) = g.conns.get_mut(&url) {
                                c.alive = true;
                            }
                        }
                    }
                    ManagerMsg::Disconnected { group, url } => {
                        tracing::info!("{group}: Disconnected from {url}");
                        if let Some(g) = groups.get_mut(&group) {
                            if let Some(c) = g.conns.get_mut(&url) {
                                c.alive = false;
                                c.reconnect_after =
                                    Instant::now() + router_cfg.connection_timeout * 2;
                            }
                        }
                    }
                    ManagerMsg::IncomingEvent { group, url, event } => {
                        if let Some(g) = groups.get_mut(&group) {
                            if g.spec.dir != "up" {
                                let cmd = g.spec.plugin_down.clone();
                                let ev = event.clone();
                                let res = tokio::task::block_in_place(|| {
                                    let mut msg = String::new();
                                    g.plugin_down.accept_event(&cmd, &ev, "Stream", &url, None, &mut msg)
                                });
                                if res == PluginResult::Accept {
                                    batch.push(event);
                                    if batch.len() >= 1000 {
                                        flush_router_batch(&env, &cfg, &mut batch)?;
                                    }
                                }
                            }
                        }
                    }
                    ManagerMsg::Log { group, url, text } => {
                        tracing::info!("{group} / {url}: {text}");
                    }
                }
            }
            _ = flush_tick.tick() => {
                if !batch.is_empty() {
                    flush_router_batch(&env, &cfg, &mut batch)?;
                }
            }
            _ = watch_tick.tick() => {
                let m = file_mtime(&router_path);
                if m != last_cfg_mtime {
                    last_cfg_mtime = m;
                    match load_router_config(&router_path) {
                        Ok(new_cfg) => {
                            tracing::info!("router config reloaded");
                            reconcile(&cfg, &new_cfg, &mut groups);
                            router_cfg = new_cfg;
                        }
                        Err(e) => tracing::error!("router config reload failed, keeping old: {e}"),
                    }
                }
                let dm = file_mtime(&env.path().join("data.mdb"));
                if dm != last_db_mtime {
                    last_db_mtime = dm;
                    router_db_change(&env, &cfg, &mut groups, &mut curr_event_id).await?;
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
                            g.conns.insert(
                                url.clone(),
                                ConnState {
                                    alive: true,
                                    reconnect_after: now + router_cfg.connection_timeout * 2,
                                },
                            );
                            let dir = g.spec.dir.clone();
                            let filter = g.spec.filter.clone();
                            let gname2 = gname.clone();
                            let url2 = url.clone();
                            let tx = manager_tx.clone();
                            let timeout = router_cfg.connection_timeout;
                            tokio::spawn(async move {
                                run_conn(gname2, url2, dir, filter, tx, timeout).await;
                            });
                        }
                    }
                }
            }
        }
    }
    Ok(())
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
        match parse_and_verify_event(&v, &limits, Some(&policy), true, true) {
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
fn reconcile(cfg: &Config, router_cfg: &RouterConfig, groups: &mut HashMap<String, Group>) {
    let removed: Vec<String> = groups
        .keys()
        .filter(|k| !router_cfg.streams.contains_key(*k))
        .cloned()
        .collect();
    for name in removed {
        if let Some(g) = groups.remove(&name) {
            for url in g.conns.keys() {
                registry_close(&name, url);
            }
        }
    }
    for (name, spec) in &router_cfg.streams {
        let filter_group = match compile_router_filter(name, &spec.filter) {
            Ok(fg) => fg,
            Err(e) => {
                tracing::error!("{e}; skipped");
                continue;
            }
        };
        match groups.get_mut(name) {
            Some(g) => {
                if g.spec.dir != spec.dir || g.spec.filter_str != spec.filter_str {
                    for url in g.conns.keys() {
                        registry_close(name, url);
                    }
                    g.conns.clear();
                    g.spec.dir = spec.dir.clone();
                    g.spec.filter_str = spec.filter_str.clone();
                    g.spec.filter = spec.filter.clone();
                    g.filter_group = filter_group;
                }
                let keep: HashSet<&String> = spec.urls.iter().collect();
                let removed: Vec<String> = g
                    .conns
                    .keys()
                    .filter(|k| !keep.contains(k))
                    .cloned()
                    .collect();
                for url in removed {
                    registry_close(name, &url);
                    g.conns.remove(&url);
                }
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
                    },
                );
            }
        }
    }
}

/// One connection task per configured URL.
async fn run_conn(
    group: String,
    url: String,
    dir: String,
    filter: Value,
    tx: mpsc::Sender<ManagerMsg>,
    timeout: Duration,
) {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let connect = async {
        tokio::time::timeout(timeout, tokio_tungstenite::connect_async(&url))
            .await
            .map_err(|_| anyhow::anyhow!("timeout"))?
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    };
    let (ws, _) = match connect.await {
        Ok(x) => x,
        Err(e) => {
            let _ = tx
                .send(ManagerMsg::Log {
                    group: group.clone(),
                    url: url.clone(),
                    text: format!("error connecting: {e}"),
                })
                .await;
            let _ = tx.send(ManagerMsg::Disconnected { group, url }).await;
            return;
        }
    };
    let (conn_tx, mut conn_rx) = mpsc::channel::<ConnMsg>(256);
    CONN_REGISTRY
        .lock()
        .insert((group.clone(), url.clone()), conn_tx);
    let _ = tx
        .send(ManagerMsg::Connected {
            group: group.clone(),
            url: url.clone(),
        })
        .await;

    let (mut wtx, mut wrx) = ws.split();
    if dir == "down" || dir == "both" {
        let mut f = filter.clone();
        f["limit"] = json!(0);
        let msg = json!(["REQ", "X", f]).to_string();
        if wtx.send(Message::Text(msg.into())).await.is_err() {
            CONN_REGISTRY.lock().remove(&(group.clone(), url.clone()));
            let _ = tx.send(ManagerMsg::Disconnected { group, url }).await;
            return;
        }
    }
    loop {
        tokio::select! {
            msg = wrx.next() => {
                match msg {
                    Some(Ok(Message::Text(t))) => {
                        handle_conn_text(&tx, &group, &url, &t).await;
                    }
                    Some(Ok(Message::Binary(b))) => {
                        let t = String::from_utf8_lossy(&b).into_owned();
                        handle_conn_text(&tx, &group, &url, &t).await;
                    }
                    Some(Ok(Message::Ping(p))) => {
                        let _ = wtx.send(Message::Pong(p)).await;
                    }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    _ => {}
                }
            }
            cmd = conn_rx.recv() => {
                match cmd {
                    Some(ConnMsg::Send(s)) => {
                        if wtx.send(Message::Text(s.into())).await.is_err() {
                            break;
                        }
                    }
                    Some(ConnMsg::Close) | None => break,
                }
            }
        }
    }
    let _ = wtx.send(Message::Close(None)).await;
    CONN_REGISTRY.lock().remove(&(group.clone(), url.clone()));
    let _ = tx.send(ManagerMsg::Disconnected { group, url }).await;
}

async fn handle_conn_text(tx: &mpsc::Sender<ManagerMsg>, group: &str, url: &str, t: &str) {
    let Ok(v) = serde_json::from_str::<Value>(t) else {
        return;
    };
    match v[0].as_str().unwrap_or("") {
        "EVENT" => {
            if let Some(ev) = v.get(2) {
                let _ = tx
                    .send(ManagerMsg::IncomingEvent {
                        group: group.to_string(),
                        url: url.to_string(),
                        event: ev.clone(),
                    })
                    .await;
            }
        }
        "NOTICE" => {
            let _ = tx
                .send(ManagerMsg::Log {
                    group: group.to_string(),
                    url: url.to_string(),
                    text: format!("NOTICE: {v}"),
                })
                .await;
        }
        "OK" if v[2].as_bool() == Some(false) => {
            let _ = tx
                .send(ManagerMsg::Log {
                    group: group.to_string(),
                    url: url.to_string(),
                    text: format!("event not written: {v}"),
                })
                .await;
        }
        _ => {}
    }
}

/// DB changed: stream new events to up/both groups (C++ handleDBChange).
async fn router_db_change(
    env: &Env,
    cfg: &Config,
    groups: &mut HashMap<String, Group>,
    curr_event_id: &mut u64,
) -> Result<()> {
    let mut sends: Vec<((String, String), String)> = Vec::new();
    {
        let txn = env.begin_ro()?;
        let mut decomp = Decompressor::new();
        let start = curr_event_id.saturating_add(1);
        let mut latest = *curr_event_id;
        wok_db::foreach_event_from(&txn, start, |lev, packed_bytes| {
            latest = lev;
            let packed = match PackedEventView::new(packed_bytes) {
                Ok(p) => p,
                Err(_) => return true,
            };
            let mut response: Option<String> = None;
            let mut ev_json: Option<Value> = None;
            for (gname, g) in groups.iter_mut() {
                if g.spec.dir == "down" {
                    continue;
                }
                if !g.filter_group.does_match(packed) {
                    continue;
                }
                if response.is_none() {
                    match wok_db::event_json_owned(
                        &txn,
                        &mut decomp,
                        lev,
                        cfg.events.max_event_size,
                    ) {
                        Ok(j) => {
                            ev_json = serde_json::from_str(&j).ok();
                            response = Some(format!("[\"EVENT\",{j}]"));
                        }
                        Err(_) => continue,
                    }
                }
                let Some(ev) = &ev_json else { continue };
                let cmd = g.spec.plugin_up.clone();
                let ev = ev.clone();
                let res = tokio::task::block_in_place(|| {
                    let mut msg = String::new();
                    g.plugin_up
                        .accept_event(&cmd, &ev, "Stored", "", None, &mut msg)
                });
                if res == PluginResult::Accept {
                    if let Some(resp) = &response {
                        for url in &g.spec.urls {
                            sends.push(((gname.clone(), url.clone()), resp.clone()));
                        }
                    }
                }
            }
            true
        })?;
        *curr_event_id = latest;
    }
    for (key, payload) in sends {
        if let Some(tx) = CONN_REGISTRY.lock().get(&key) {
            let _ = tx.try_send(ConnMsg::Send(payload));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
