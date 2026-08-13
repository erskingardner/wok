//! Relay process: ingest, writer, req, monitor, negentropy, cron.
//!
//! LMDB work stays on dedicated OS threads. Outbound messages are owned
//! `String`s sent over Tokio mpsc channels that never hold mmap borrows.

#![allow(clippy::too_many_arguments)]
#![allow(clippy::field_reassign_with_default)]

use crate::config::Config;
use crate::metrics::Metrics;
use crate::plugin::{PluginEventSifter, PluginResult};
use crate::protocol::{ClientCommand, RelayMessage};
use crate::restrict::ReadRestrictor;
use crossbeam_channel::{bounded, Receiver, Sender};
use parking_lot::Mutex;
use rand::Rng;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use wok_db::{
    event_json_owned, lookup_event_by_id_ro, most_recent_levid_ro, write_events, Decompressor, Env,
    EventToWrite, EventWriteStatus,
};
use wok_event::{
    parse_and_verify_event, to_hex, PackedEventView, TimestampPolicy, AUTH_CHALLENGE_LEN,
    AUTH_KIND, PROTECTED_TAG, REPOST_KINDS,
};
use wok_negentropy::{DeferredSink, Negentropy, NegentropyFilterCache, Vector};
use wok_query::{
    ActiveMonitors, FilterValidator, NostrFilterGroup, QueryScheduler, SubId, Subscription,
};

const AUTH_ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// One frame queued for a connection. Dropping the frame (after a send, or
/// when a dead connection's queue is drained) releases its byte accounting.
pub struct OutboundFrame {
    pub text: String,
    len: u64,
    pending: Arc<AtomicU64>,
}

impl OutboundFrame {
    pub fn into_text(mut self) -> String {
        std::mem::take(&mut self.text)
    }
}

impl Drop for OutboundFrame {
    fn drop(&mut self) {
        self.pending.fetch_sub(self.len, Ordering::Relaxed);
    }
}

/// Per-connection outbound queue with C++-style pending-byte accounting.
/// When `limit` bytes are already queued, `try_send` fails and the caller
/// terminates the slow client (`maxPendingOutboundBytes`, 0 = unlimited).
#[derive(Clone)]
pub struct Outbound {
    tx: tokio::sync::mpsc::Sender<OutboundFrame>,
    pending: Arc<AtomicU64>,
    limit: usize,
    kill: Arc<tokio::sync::Notify>,
}

impl Outbound {
    pub fn new(tx: tokio::sync::mpsc::Sender<OutboundFrame>, limit: usize) -> Self {
        Self {
            tx,
            pending: Arc::new(AtomicU64::new(0)),
            limit,
            kill: Arc::new(tokio::sync::Notify::new()),
        }
    }

    pub fn try_send(&self, msg: String) -> bool {
        let len = msg.len() as u64;
        let prev = self.pending.fetch_add(len, Ordering::Relaxed);
        if self.limit != 0 && prev.saturating_add(len) > self.limit as u64 {
            self.pending.fetch_sub(len, Ordering::Relaxed);
            return false;
        }
        // On failure the frame drops here, undoing the accounting.
        self.tx
            .try_send(OutboundFrame {
                len: msg.len() as u64,
                text: msg,
                pending: self.pending.clone(),
            })
            .is_ok()
    }

    /// Signal the owning transport to close the connection.
    pub fn kill(&self) {
        self.kill.notify_one();
    }

    /// Handle a transport can `select!` on: `killed().notified()`.
    pub fn killed(&self) -> Arc<tokio::sync::Notify> {
        self.kill.clone()
    }
}

struct ConnTable {
    map: Mutex<HashMap<u64, Outbound>>,
}

impl ConnTable {
    fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
        }
    }
    fn insert(&self, id: u64, out: Outbound) {
        self.map.lock().insert(id, out);
    }
    fn remove(&self, id: u64) {
        self.map.lock().remove(&id);
    }
    fn send(&self, id: u64, msg: RelayMessage, metrics: &Metrics) {
        bump_relay_metrics(&msg, metrics);
        let json = msg.to_json();
        let mut map = self.map.lock();
        if let Some(out) = map.get(&id) {
            if !out.try_send(json) {
                // Slow/stalled client over its pending-bytes budget: terminate
                // it like C++ RelayWebsocket does.
                metrics
                    .slow_client_terminations
                    .fetch_add(1, Ordering::Relaxed);
                let out = map.remove(&id);
                if let Some(out) = out {
                    out.kill();
                }
            }
        }
    }
    fn send_event_batch(&self, recipients: &[(u64, String)], ev_json: &str, metrics: &Metrics) {
        let mut map = self.map.lock();
        let mut killed = Vec::new();
        for (conn, sub) in recipients {
            metrics.relay_event.fetch_add(1, Ordering::Relaxed);
            let payload = format!("[\"EVENT\",\"{sub}\",{ev_json}]");
            if let Some(out) = map.get(conn) {
                if !out.try_send(payload) {
                    killed.push(*conn);
                }
            }
        }
        for conn in killed {
            metrics
                .slow_client_terminations
                .fetch_add(1, Ordering::Relaxed);
            if let Some(out) = map.remove(&conn) {
                out.kill();
            }
        }
    }
}

fn bump_relay_metrics(msg: &RelayMessage, metrics: &Metrics) {
    match msg {
        RelayMessage::Event { .. } => {
            metrics.relay_event.fetch_add(1, Ordering::Relaxed);
        }
        RelayMessage::Eose { .. } => {
            metrics.relay_eose.fetch_add(1, Ordering::Relaxed);
        }
        RelayMessage::Ok { .. } => {
            metrics.relay_ok.fetch_add(1, Ordering::Relaxed);
        }
        RelayMessage::Notice { .. } => {
            metrics.relay_notice.fetch_add(1, Ordering::Relaxed);
        }
        RelayMessage::Closed { .. } => {
            metrics.relay_closed.fetch_add(1, Ordering::Relaxed);
        }
        RelayMessage::Auth { .. } => {
            metrics
                .auth_challenges_sent_total
                .fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }
}

#[derive(Clone)]
pub struct RelayHandle {
    ingest: Vec<tokio::sync::mpsc::Sender<IngestMsg>>,
    conns: Arc<ConnTable>,
    next_id: Arc<AtomicU64>,
    pub metrics: Arc<Metrics>,
    pub config: Arc<parking_lot::RwLock<Config>>,
    shutdown: Arc<AtomicBool>,
    shutdown_notify: Arc<tokio::sync::Notify>,
}

pub enum IngestMsg {
    Client {
        conn_id: u64,
        ip: Vec<u8>,
        payload: String,
    },
    Close {
        conn_id: u64,
    },
}

enum WriterMsg {
    AddEvent {
        conn_id: u64,
        ip: Vec<u8>,
        packed: Vec<u8>,
        json: String,
        authed: Option<[u8; 32]>,
    },
    Close {
        conn_id: u64,
    },
}

enum ReqMsg {
    NewSub(Subscription),
    SetAuth { conn_id: u64, authed: [u8; 32] },
    RemoveSub { conn_id: u64, sub_id: SubId },
    Close { conn_id: u64 },
}

enum MonitorMsg {
    NewSub(Subscription),
    SetAuth { conn_id: u64, authed: [u8; 32] },
    RemoveSub { conn_id: u64, sub_id: SubId },
    Close { conn_id: u64 },
    DbChange,
}

enum NegMsg {
    Open {
        sub: Subscription,
        filter_str: String,
        payload: Vec<u8>,
    },
    Msg {
        conn_id: u64,
        sub_id: SubId,
        payload: Vec<u8>,
    },
    SetAuth {
        conn_id: u64,
        authed: [u8; 32],
    },
    CloseSub {
        conn_id: u64,
        sub_id: SubId,
    },
    Close {
        conn_id: u64,
    },
}

struct AuthSession {
    challenge: String,
    authed: Option<[u8; 32]>,
}

impl RelayHandle {
    pub fn next_conn_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// The ingester this connection is pinned to (C++ ThreadPool hashing).
    fn ingest_route(&self, conn_id: u64) -> &tokio::sync::mpsc::Sender<IngestMsg> {
        &self.ingest[conn_id as usize % self.ingest.len()]
    }

    /// Register a connection's outbound queue. Async: applies backpressure
    /// instead of blocking a Tokio worker when the ingest queue is full.
    pub async fn register(&self, conn_id: u64, out: Outbound) {
        self.conns.insert(conn_id, out);
    }

    pub async fn client_message(&self, conn_id: u64, ip: Vec<u8>, payload: String) {
        let _ = self
            .ingest_route(conn_id)
            .send(IngestMsg::Client {
                conn_id,
                ip,
                payload,
            })
            .await;
    }

    pub async fn close(&self, conn_id: u64) {
        self.conns.remove(conn_id);
        let _ = self
            .ingest_route(conn_id)
            .send(IngestMsg::Close { conn_id })
            .await;
    }

    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.shutdown_notify.notify_waiters();
    }

    /// Transports select on this to break out of a blocking accept.
    pub fn shutdown_handle(&self) -> Arc<tokio::sync::Notify> {
        self.shutdown_notify.clone()
    }

    pub fn supported_nips(&self) -> Vec<u64> {
        let cfg = self.config.read();
        supported_nips(&cfg)
    }
}

pub fn supported_nips(cfg: &Config) -> Vec<u64> {
    let mut nips = vec![1, 2, 4, 9, 11, 28, 40, 59, 70];
    if cfg.relay.auth.enabled && !cfg.relay.auth.service_url.is_empty() {
        nips.push(42);
    }
    if cfg.relay.max_filter_limit_count > 0 {
        nips.push(45);
    }
    if cfg.relay.negentropy_enabled {
        nips.push(77);
    }
    nips.sort_unstable();
    nips.dedup();
    if !cfg.relay.info.nips.is_empty() {
        if let Ok(v) = serde_json::from_str::<Vec<u64>>(&cfg.relay.info.nips) {
            return v;
        }
    }
    nips
}

pub fn start(env: Env, config: Config) -> Result<RelayHandle, String> {
    env.ensure_initialized().map_err(|e| e.to_string())?;
    let n_ingester = config.relay.ingester_threads.max(1);
    let n_req_worker = config.relay.req_worker_threads.max(1);
    let n_req_monitor = config.relay.req_monitor_threads.max(1);
    let n_negentropy = config.relay.negentropy_threads.max(1);
    let config = Arc::new(parking_lot::RwLock::new(config));
    let conns = Arc::new(ConnTable::new());
    let metrics = Arc::new(Metrics::default());
    let shutdown = Arc::new(AtomicBool::new(false));

    // One channel per worker thread. Connections are pinned to a worker by
    // conn_id % pool_size, exactly like C++ ThreadPool dispatch, so all
    // per-connection state (auth sessions, subscriptions) stays on one
    // thread and per-connection message order is preserved.
    let (ingest_txs, ingest_rxs): (Vec<_>, Vec<_>) = (0..n_ingester)
        .map(|_| tokio::sync::mpsc::channel::<IngestMsg>(4096))
        .unzip();
    let (writer_tx, writer_rx) = bounded::<WriterMsg>(4096);
    let (req_txs, req_rxs): (Vec<_>, Vec<_>) =
        (0..n_req_worker).map(|_| bounded::<ReqMsg>(4096)).unzip();
    let (mon_txs, mon_rxs): (Vec<_>, Vec<_>) = (0..n_req_monitor)
        .map(|_| bounded::<MonitorMsg>(4096))
        .unzip();
    let (neg_txs, neg_rxs): (Vec<_>, Vec<_>) =
        (0..n_negentropy).map(|_| bounded::<NegMsg>(4096)).unzip();

    let handle = RelayHandle {
        ingest: ingest_txs,
        conns: conns.clone(),
        next_id: Arc::new(AtomicU64::new(1)),
        metrics: metrics.clone(),
        config: config.clone(),
        shutdown: shutdown.clone(),
        shutdown_notify: Arc::new(tokio::sync::Notify::new()),
    };

    for (i, ingest_rx) in ingest_rxs.into_iter().enumerate() {
        let env = env.clone();
        let cfg = config.clone();
        let conns = conns.clone();
        let metrics = metrics.clone();
        let writer_tx = writer_tx.clone();
        let req_txs = req_txs.clone();
        let neg_txs = neg_txs.clone();
        thread::Builder::new()
            .name(format!("ingester-{i}"))
            .spawn(move || {
                run_ingester(
                    env, cfg, conns, metrics, ingest_rx, writer_tx, req_txs, neg_txs,
                )
            })
            .map_err(|e| e.to_string())?;
    }
    {
        let env = env.clone();
        let cfg = config.clone();
        let conns = conns.clone();
        let metrics = metrics.clone();
        let mon_txs = mon_txs.clone();
        thread::Builder::new()
            .name("writer".into())
            .spawn(move || run_writer(env, cfg, conns, metrics, writer_rx, mon_txs))
            .map_err(|e| e.to_string())?;
    }
    for (i, req_rx) in req_rxs.into_iter().enumerate() {
        let env = env.clone();
        let cfg = config.clone();
        let conns = conns.clone();
        let metrics = metrics.clone();
        let mon_txs = mon_txs.clone();
        thread::Builder::new()
            .name(format!("req-worker-{i}"))
            .spawn(move || run_req_worker(env, cfg, conns, metrics, req_rx, mon_txs))
            .map_err(|e| e.to_string())?;
    }
    for (i, mon_rx) in mon_rxs.into_iter().enumerate() {
        let env = env.clone();
        let cfg = config.clone();
        let conns = conns.clone();
        let metrics = metrics.clone();
        thread::Builder::new()
            .name(format!("req-monitor-{i}"))
            .spawn(move || run_req_monitor(env, cfg, conns, metrics, mon_rx))
            .map_err(|e| e.to_string())?;
    }
    for (i, neg_rx) in neg_rxs.into_iter().enumerate() {
        let env = env.clone();
        let cfg = config.clone();
        let conns = conns.clone();
        let metrics = metrics.clone();
        thread::Builder::new()
            .name(format!("negentropy-{i}"))
            .spawn(move || run_negentropy(env, cfg, conns, metrics, neg_rx))
            .map_err(|e| e.to_string())?;
    }
    {
        let env = env.clone();
        let cfg = config.clone();
        let shutdown = shutdown.clone();
        thread::Builder::new()
            .name("cron".into())
            .spawn(move || run_cron(env, cfg, shutdown))
            .map_err(|e| e.to_string())?;
    }

    {
        let env = env.clone();
        let shutdown = shutdown.clone();
        thread::Builder::new()
            .name("db-watch".into())
            .spawn(move || run_db_watch(env, mon_txs, shutdown))
            .map_err(|e| e.to_string())?;
    }

    let _ = writer_tx;
    Ok(handle)
}

/// Broadcast a database-change notification to every req-monitor thread.
fn broadcast_db_change(mon_txs: &[Sender<MonitorMsg>]) {
    for tx in mon_txs {
        let _ = tx.send(MonitorMsg::DbChange);
    }
}

/// Watch data.mdb for changes made by *other* processes (a co-resident C++
/// strfry, `wok import`, ...) and poke the req-monitor, mirroring C++
/// RelayReqMonitor's hoytech::file_change_monitor (100ms debounce). Polling
/// is used for portability; semantics match.
fn run_db_watch(env: Env, mon_txs: Vec<Sender<MonitorMsg>>, shutdown: Arc<AtomicBool>) {
    let path = env.path().join("data.mdb");
    let mut last: Option<(std::time::SystemTime, u64)> = None;
    while !shutdown.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(100));
        let cur = std::fs::metadata(&path)
            .ok()
            .and_then(|m| m.modified().ok().map(|t| (t, m.len())));
        if let Some(cur) = cur {
            match last {
                Some(prev) if prev == cur => {}
                _ => {
                    last = Some(cur);
                    broadcast_db_change(&mon_txs);
                }
            }
        }
    }
}

fn restrictor(cfg: &Config) -> ReadRestrictor {
    ReadRestrictor::new(
        cfg.relay.auth.restricted_read_kinds.clone(),
        cfg.relay.auth.restrict_read_to_involved_pubkey,
    )
}

fn filter_validator(cfg: &Config) -> FilterValidator {
    let mut allowed = std::collections::HashSet::new();
    for p in cfg.relay.filter_validation.allowed_kinds.split(',') {
        if let Ok(n) = p.trim().parse() {
            allowed.insert(n);
        }
    }
    FilterValidator {
        enabled: cfg.relay.filter_validation.enabled,
        min_filters_per_req: cfg.relay.filter_validation.min_filters_per_req,
        max_filters_per_req: cfg.relay.filter_validation.max_filters_per_req,
        max_kinds_per_filter: cfg.relay.filter_validation.max_kinds_per_filter,
        allowed_kinds: allowed,
        require_author_or_tag: cfg.relay.filter_validation.require_author_or_tag,
    }
}

fn gen_challenge() -> String {
    let mut rng = rand::thread_rng();
    (0..AUTH_CHALLENGE_LEN)
        .map(|_| AUTH_ALPHABET[rng.gen_range(0..AUTH_ALPHABET.len())] as char)
        .collect()
}

fn normalize_relay_url(url: &str) -> String {
    let mut s = url;
    if let Some(pos) = s.find("://") {
        s = &s[pos + 3..];
    }
    if let Some(pos) = s.find(['/', '?', '#']) {
        s = &s[..pos];
    }
    s.to_ascii_lowercase()
}

fn route_tx<T>(txs: &[Sender<T>], conn_id: u64) -> &Sender<T> {
    &txs[conn_id as usize % txs.len()]
}

#[allow(clippy::too_many_arguments)]
fn run_ingester(
    env: Env,
    cfg: Arc<parking_lot::RwLock<Config>>,
    conns: Arc<ConnTable>,
    metrics: Arc<Metrics>,
    mut rx: tokio::sync::mpsc::Receiver<IngestMsg>,
    writer_tx: Sender<WriterMsg>,
    req_txs: Vec<Sender<ReqMsg>>,
    neg_txs: Vec<Sender<NegMsg>>,
) {
    let mut auth: HashMap<u64, AuthSession> = HashMap::new();
    // blocking_recv is only used here, on a dedicated OS thread outside any
    // Tokio runtime, so no async executor is stalled.
    while let Some(msg) = rx.blocking_recv() {
        match msg {
            IngestMsg::Close { conn_id } => {
                if auth.remove(&conn_id).and_then(|a| a.authed).is_some() {
                    metrics
                        .authenticated_connections
                        .fetch_sub(1, Ordering::Relaxed);
                }
                let _ = writer_tx.send(WriterMsg::Close { conn_id });
                let _ = route_tx(&req_txs, conn_id).send(ReqMsg::Close { conn_id });
                let _ = route_tx(&neg_txs, conn_id).send(NegMsg::Close { conn_id });
            }
            IngestMsg::Client {
                conn_id,
                ip,
                payload,
            } => {
                let cfg_snap = cfg.read().clone();
                handle_client(
                    &env, &cfg_snap, &conns, &metrics, &mut auth, conn_id, ip, &payload,
                    &writer_tx, &req_txs, &neg_txs,
                );
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_client(
    env: &Env,
    cfg: &Config,
    conns: &ConnTable,
    metrics: &Metrics,
    auth: &mut HashMap<u64, AuthSession>,
    conn_id: u64,
    ip: Vec<u8>,
    payload: &str,
    writer_tx: &Sender<WriterMsg>,
    req_txs: &[Sender<ReqMsg>],
    neg_txs: &[Sender<NegMsg>],
) {
    let cmd = match ClientCommand::parse(payload) {
        Ok(c) => c,
        Err(e) => {
            conns.send(conn_id, e.into_message(), metrics);
            return;
        }
    };
    match cmd {
        ClientCommand::Newline => {}
        ClientCommand::Event(v) => {
            metrics.client_event.fetch_add(1, Ordering::Relaxed);
            ingest_event(env, cfg, conns, metrics, auth, conn_id, ip, v, writer_tx);
        }
        ClientCommand::Auth(v) => {
            metrics.client_auth.fetch_add(1, Ordering::Relaxed);
            ingest_auth(
                cfg,
                conns,
                metrics,
                auth,
                conn_id,
                v,
                route_tx(req_txs, conn_id),
                route_tx(neg_txs, conn_id),
            );
        }
        ClientCommand::Req { sub_id, filters } => {
            metrics.client_req.fetch_add(1, Ordering::Relaxed);
            ingest_req(
                cfg,
                conns,
                metrics,
                auth,
                conn_id,
                sub_id,
                filters,
                false,
                route_tx(req_txs, conn_id),
            );
        }
        ClientCommand::Count { sub_id, filters } => {
            metrics.client_count.fetch_add(1, Ordering::Relaxed);
            ingest_req(
                cfg,
                conns,
                metrics,
                auth,
                conn_id,
                sub_id,
                filters,
                true,
                route_tx(req_txs, conn_id),
            );
        }
        ClientCommand::Close { sub_id } => {
            metrics.client_close.fetch_add(1, Ordering::Relaxed);
            match SubId::new(&sub_id) {
                Ok(sid) => {
                    let _ = route_tx(req_txs, conn_id).send(ReqMsg::RemoveSub {
                        conn_id,
                        sub_id: sid,
                    });
                }
                Err(e) => {
                    conns.send(
                        conn_id,
                        RelayMessage::notice_error(format!("bad close: {e}")),
                        metrics,
                    );
                }
            }
        }
        ClientCommand::NegOpen {
            sub_id,
            filter,
            payload_hex,
        } => {
            if !cfg.relay.negentropy_enabled {
                conns.send(
                    conn_id,
                    RelayMessage::notice_error("bad msg: negentropy disabled"),
                    metrics,
                );
                return;
            }
            if let Err(e) = ingest_neg(
                cfg,
                conns,
                metrics,
                auth,
                conn_id,
                &sub_id,
                Some(filter),
                &payload_hex,
                true,
                route_tx(neg_txs, conn_id),
            ) {
                conns.send(
                    conn_id,
                    RelayMessage::notice_error(format!("negentropy error: {e}")),
                    metrics,
                );
            }
        }
        ClientCommand::NegMsg {
            sub_id,
            payload_hex,
        } => {
            if !cfg.relay.negentropy_enabled {
                conns.send(
                    conn_id,
                    RelayMessage::notice_error("bad msg: negentropy disabled"),
                    metrics,
                );
                return;
            }
            if let Err(e) = ingest_neg(
                cfg,
                conns,
                metrics,
                auth,
                conn_id,
                &sub_id,
                None,
                &payload_hex,
                false,
                route_tx(neg_txs, conn_id),
            ) {
                conns.send(
                    conn_id,
                    RelayMessage::notice_error(format!("negentropy error: {e}")),
                    metrics,
                );
            }
        }
        ClientCommand::NegClose { sub_id } => {
            if !cfg.relay.negentropy_enabled {
                conns.send(
                    conn_id,
                    RelayMessage::notice_error("bad msg: negentropy disabled"),
                    metrics,
                );
                return;
            }
            match SubId::new(&sub_id) {
                Ok(sid) => {
                    let _ = route_tx(neg_txs, conn_id).send(NegMsg::CloseSub {
                        conn_id,
                        sub_id: sid,
                    });
                }
                Err(e) => {
                    conns.send(
                        conn_id,
                        RelayMessage::notice_error(format!("negentropy error: {e}")),
                        metrics,
                    );
                }
            }
        }
    }
}

fn ingest_event(
    env: &Env,
    cfg: &Config,
    conns: &ConnTable,
    metrics: &Metrics,
    auth: &mut HashMap<u64, AuthSession>,
    conn_id: u64,
    ip: Vec<u8>,
    orig: Value,
    writer_tx: &Sender<WriterMsg>,
) {
    let policy = TimestampPolicy::from_now(
        cfg.events.reject_newer_than_secs,
        cfg.events.reject_older_than_secs,
        cfg.events.reject_ephemeral_older_than_secs,
    );
    let parsed = match parse_and_verify_event(&orig, &cfg.event_limits(), Some(&policy), true, true)
    {
        Ok(p) => p,
        Err(e) => {
            let id = orig
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_string();
            conns.send(
                conn_id,
                RelayMessage::Ok {
                    event_id: id,
                    accepted: false,
                    message: format!("invalid: {e}"),
                },
                metrics,
            );
            return;
        }
    };
    let packed = parsed.packed.view();
    let id_hex = to_hex(packed.id());

    if REPOST_KINDS.contains(&packed.kind())
        && orig
            .get("content")
            .and_then(|c| c.as_str())
            .map(|s| s.contains("[\"-\"]"))
            .unwrap_or(false)
    {
        conns.send(
            conn_id,
            RelayMessage::Ok {
                event_id: id_hex,
                accepted: false,
                message: "blocked: reposts can't embed protected events".into(),
            },
            metrics,
        );
        return;
    }

    let mut found_protected = false;
    packed.foreach_tag(|n, _| {
        if n == PROTECTED_TAG {
            found_protected = true;
            return false;
        }
        true
    });

    let mut authed = None;
    if found_protected {
        if !cfg.relay.auth.enabled || cfg.relay.auth.service_url.is_empty() {
            conns.send(
                conn_id,
                RelayMessage::Ok {
                    event_id: id_hex,
                    accepted: false,
                    message: "blocked: event marked as protected".into(),
                },
                metrics,
            );
            return;
        }
        match auth.get(&conn_id) {
            None => {
                let challenge = gen_challenge();
                auth.insert(
                    conn_id,
                    AuthSession {
                        challenge: challenge.clone(),
                        authed: None,
                    },
                );
                conns.send(conn_id, RelayMessage::Auth { challenge }, metrics);
                conns.send(
                    conn_id,
                    RelayMessage::Ok {
                        event_id: id_hex,
                        accepted: false,
                        message: "auth-required: event marked as protected".into(),
                    },
                    metrics,
                );
                return;
            }
            Some(asess) if asess.authed.is_none() => {
                conns.send(
                    conn_id,
                    RelayMessage::Ok {
                        event_id: id_hex,
                        accepted: false,
                        message: "auth-required: event marked as protected".into(),
                    },
                    metrics,
                );
                return;
            }
            Some(asess) => {
                let pk = asess.authed.unwrap();
                if pk.as_slice() != packed.pubkey() {
                    conns.send(
                        conn_id,
                        RelayMessage::Ok {
                            event_id: id_hex,
                            accepted: false,
                            message: "restricted: must be published by the author".into(),
                        },
                        metrics,
                    );
                    return;
                }
                authed = Some(pk);
            }
        }
    }

    {
        // C++ maps any failure in the event path to OK false "invalid: ...".
        let dup = (|| -> Result<bool, String> {
            let txn = env.begin_ro().map_err(|e| e.to_string())?;
            Ok(lookup_event_by_id_ro(&txn, packed.id())
                .map_err(|e| e.to_string())?
                .is_some())
        })();
        match dup {
            Ok(true) => {
                conns.send(
                    conn_id,
                    RelayMessage::Ok {
                        event_id: id_hex,
                        accepted: true,
                        message: "duplicate: have this event".into(),
                    },
                    metrics,
                );
                return;
            }
            Ok(false) => {}
            Err(e) => {
                conns.send(
                    conn_id,
                    RelayMessage::Ok {
                        event_id: id_hex,
                        accepted: false,
                        message: format!("invalid: {e}"),
                    },
                    metrics,
                );
                return;
            }
        }
    }

    let _ = writer_tx.send(WriterMsg::AddEvent {
        conn_id,
        ip,
        packed: parsed.packed.into_bytes(),
        json: parsed.json,
        authed,
    });
}

fn ingest_auth(
    cfg: &Config,
    conns: &ConnTable,
    metrics: &Metrics,
    auth: &mut HashMap<u64, AuthSession>,
    conn_id: u64,
    event_json: Value,
    req_tx: &Sender<ReqMsg>,
    neg_tx: &Sender<NegMsg>,
) {
    // C++ RelayIngester answers every AUTH failure with
    // OK <id|"?"> false "error: ...".
    let event_id = event_json
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("?")
        .to_string();
    match ingest_auth_inner(cfg, auth, conn_id, &event_json, req_tx, neg_tx) {
        Ok(packed_id) => {
            metrics.auth_success_total.fetch_add(1, Ordering::Relaxed);
            metrics
                .authenticated_connections
                .fetch_add(1, Ordering::Relaxed);
            conns.send(
                conn_id,
                RelayMessage::Ok {
                    event_id: to_hex(&packed_id),
                    accepted: true,
                    message: "successfully authenticated".into(),
                },
                metrics,
            );
        }
        Err(e) => {
            metrics.auth_failure_total.fetch_add(1, Ordering::Relaxed);
            conns.send(
                conn_id,
                RelayMessage::Ok {
                    event_id,
                    accepted: false,
                    message: format!("error: {e}"),
                },
                metrics,
            );
        }
    }
}

fn ingest_auth_inner(
    cfg: &Config,
    auth: &mut HashMap<u64, AuthSession>,
    conn_id: u64,
    event_json: &Value,
    req_tx: &Sender<ReqMsg>,
    neg_tx: &Sender<NegMsg>,
) -> Result<[u8; 32], String> {
    if cfg.relay.auth.service_url.is_empty() {
        return Err("relay needs serviceUrl to be configured before AUTH can work".into());
    }
    let policy = TimestampPolicy::from_now(
        cfg.events.reject_newer_than_secs,
        cfg.events.reject_older_than_secs,
        cfg.events.reject_ephemeral_older_than_secs,
    );
    let parsed = parse_and_verify_event(event_json, &cfg.event_limits(), Some(&policy), true, true)
        .map_err(|e| e.to_string())?;
    let packed = parsed.packed.view();
    if packed.kind() != AUTH_KIND {
        return Err("wrong event kind, expected 22242".into());
    }
    let asess = auth
        .get_mut(&conn_id)
        .ok_or("no auth status available for connection")?;
    if asess.authed.is_some() {
        return Err("already authenticated".into());
    }
    let mut found_challenge = false;
    let mut found_relay = false;
    let expected = normalize_relay_url(&cfg.relay.auth.service_url);
    if let Some(tags) = event_json.get("tags").and_then(|t| t.as_array()) {
        for tag in tags {
            let arr = match tag.as_array() {
                Some(a) if a.len() >= 2 => a,
                _ => continue,
            };
            let name = arr[0].as_str().unwrap_or("");
            let value = arr[1].as_str().unwrap_or("");
            if name == "relay" && normalize_relay_url(value) == expected {
                found_relay = true;
            } else if name == "challenge" && value == asess.challenge {
                found_challenge = true;
            }
        }
    }
    if !found_challenge {
        return Err("challenge string mismatch".into());
    }
    if !found_relay {
        return Err(format!(
            "incorrect or missing relay tag, expected: {}",
            cfg.relay.auth.service_url
        ));
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(packed.pubkey());
    asess.authed = Some(pk);
    let _ = req_tx.send(ReqMsg::SetAuth {
        conn_id,
        authed: pk,
    });
    let _ = neg_tx.send(NegMsg::SetAuth {
        conn_id,
        authed: pk,
    });
    let mut id = [0u8; 32];
    id.copy_from_slice(packed.id());
    Ok(id)
}

#[allow(clippy::too_many_arguments)]
fn ingest_req(
    cfg: &Config,
    conns: &ConnTable,
    metrics: &Metrics,
    auth: &mut HashMap<u64, AuthSession>,
    conn_id: u64,
    sub_id: String,
    filters: Vec<Value>,
    count_only: bool,
    req_tx: &Sender<ReqMsg>,
) {
    // C++ RelayIngester: errors raised before the sub id is known go out as
    // NOTICE "ERROR: bad req: ..."; everything after as CLOSED with the same
    // payload. The sub id is always known here (protocol.rs extracted it),
    // except for the "arr too small" case which C++ raises first.
    let fail_closed = |e: String| {
        conns.send(
            conn_id,
            RelayMessage::closed_error(&sub_id, format!("bad req: {e}")),
            metrics,
        );
    };
    if filters.is_empty() {
        conns.send(
            conn_id,
            RelayMessage::notice_error("bad req: arr too small"),
            metrics,
        );
        return;
    }
    if filters.len() as u64 > cfg.relay.max_req_filter_size as u64 {
        fail_closed("arr too big".into());
        return;
    }
    let max_limit = if count_only {
        let m = cfg.relay.max_filter_limit_count + 1;
        if m == 1 {
            fail_closed("COUNT disabled".into());
            return;
        }
        m
    } else {
        cfg.relay.max_filter_limit
    };
    let mut arr = vec![json!("REQ"), json!(sub_id)];
    arr.extend(filters);
    let fg = match NostrFilterGroup::from_req(&arr, max_limit, cfg.relay.max_tags_per_filter) {
        Ok(fg) => fg,
        Err(e) => {
            fail_closed(e.to_string());
            return;
        }
    };
    if let Err(e) = filter_validator(cfg).validate(&fg) {
        fail_closed(format!("filter validation failed: {e}"));
        return;
    }

    let authed = auth.get(&conn_id).and_then(|a| a.authed);
    let r = restrictor(cfg);
    let requires_auth = if count_only {
        !r.is_filter_allowed_to_count(&fg, authed.as_ref().map(|a| a.as_slice()))
    } else {
        r.is_filter_group_fully_restricted(&fg) && authed.is_none()
    };
    if requires_auth {
        if let std::collections::hash_map::Entry::Vacant(e) = auth.entry(conn_id) {
            let challenge = gen_challenge();
            e.insert(AuthSession {
                challenge: challenge.clone(),
                authed: None,
            });
            conns.send(conn_id, RelayMessage::Auth { challenge }, metrics);
        }
        conns.send(
            conn_id,
            RelayMessage::closed_error(
                &sub_id,
                "auth-required: requested filter requires authentication",
            ),
            metrics,
        );
        return;
    }
    let sid = match SubId::new(&sub_id) {
        Ok(s) => s,
        Err(e) => {
            fail_closed(e.to_string());
            return;
        }
    };
    let sub = Subscription::new(conn_id, sid, fg, count_only);
    let _ = req_tx.send(ReqMsg::NewSub(sub));
}

fn ingest_neg(
    cfg: &Config,
    conns: &ConnTable,
    metrics: &Metrics,
    auth: &mut HashMap<u64, AuthSession>,
    conn_id: u64,
    sub_id: &str,
    filter: Option<Value>,
    payload_hex: &str,
    is_open: bool,
    neg_tx: &Sender<NegMsg>,
) -> Result<(), String> {
    let payload = wok_event::from_hex(payload_hex).map_err(|e| e.to_string())?;
    if is_open {
        let Some(mut filter) = filter else {
            return Err("negentropy query missing elements".into());
        };
        if !filter.is_object() {
            return Err("negentropy filter must be an object".into());
        }
        let max_limit = cfg.relay.max_sync_events + 1;
        let fg = NostrFilterGroup::from_value(&filter, max_limit, cfg.relay.max_tags_per_filter)
            .map_err(|e| e.to_string())?;
        let r = restrictor(cfg);
        if r.is_filter_group_fully_restricted(&fg)
            && auth.get(&conn_id).and_then(|a| a.authed).is_none()
        {
            if let std::collections::hash_map::Entry::Vacant(e) = auth.entry(conn_id) {
                let challenge = gen_challenge();
                e.insert(AuthSession {
                    challenge: challenge.clone(),
                    authed: None,
                });
                conns.send(conn_id, RelayMessage::Auth { challenge }, metrics);
            }
            conns.send(
                conn_id,
                RelayMessage::NegErr {
                    sub_id: sub_id.to_string(),
                    message: "auth-required: requested filter requires authentication".into(),
                    extra: None,
                },
                metrics,
            );
            return Ok(());
        }
        if let Some(obj) = filter.as_object_mut() {
            obj.remove("since");
            obj.remove("until");
        }
        let filter_str = filter.to_string();
        let sid = SubId::new(sub_id).map_err(|e| e.to_string())?;
        let sub = Subscription::new(conn_id, sid, fg, false);
        let _ = neg_tx.send(NegMsg::Open {
            sub,
            filter_str,
            payload,
        });
    } else {
        let sid = SubId::new(sub_id).map_err(|e| e.to_string())?;
        let _ = neg_tx.send(NegMsg::Msg {
            conn_id,
            sub_id: sid,
            payload,
        });
    }
    Ok(())
}

fn run_writer(
    env: Env,
    cfg: Arc<parking_lot::RwLock<Config>>,
    conns: Arc<ConnTable>,
    metrics: Arc<Metrics>,
    rx: Receiver<WriterMsg>,
    mon_txs: Vec<Sender<MonitorMsg>>,
) {
    let mut plugin = PluginEventSifter::new(cfg.read().relay.write_policy_timeout_secs);
    while let Ok(msg) = rx.recv() {
        let mut batch = vec![msg];
        while let Ok(more) = rx.try_recv() {
            batch.push(more);
        }
        // Filter out events from connections closed within this batch, like
        // C++ RelayWriter (a per-batch set; a persistent set would leak one
        // entry per closed connection for the life of the process).
        let mut closed = std::collections::HashSet::new();
        for m in &batch {
            if let WriterMsg::Close { conn_id } = m {
                closed.insert(*conn_id);
            }
        }
        let cfg_snap = cfg.read().clone();
        let mut events: Vec<(u64, EventToWrite, Option<[u8; 32]>)> = Vec::new();
        for m in batch {
            if let WriterMsg::AddEvent {
                conn_id,
                ip,
                packed,
                json,
                authed,
            } = m
            {
                if closed.contains(&conn_id) {
                    continue;
                }
                // Unix-socket connections carry no IP; they are reported to
                // write-policy plugins as sourceType "unix" (wok extension).
                let source_type = if ip.is_empty() {
                    "unix"
                } else if ip.len() == 4 {
                    "IP4"
                } else {
                    "IP6"
                };
                let source_info = render_ip(&ip);
                let ev_json: Value = serde_json::from_str(&json).unwrap_or(json!({}));
                let mut ok_msg = String::new();
                let res = plugin.accept_event(
                    &cfg_snap.relay.write_policy_plugin,
                    &ev_json,
                    source_type,
                    &source_info,
                    authed.as_ref().map(|a| a.as_slice()),
                    &mut ok_msg,
                );
                if res == PluginResult::Accept {
                    events.push((conn_id, EventToWrite::new(packed, json), authed));
                } else {
                    let id_hex = PackedEventView::new(&packed)
                        .map(|p| to_hex(p.id()))
                        .unwrap_or_else(|_| "?".into());
                    conns.send(
                        conn_id,
                        RelayMessage::Ok {
                            event_id: id_hex,
                            accepted: res == PluginResult::ShadowReject,
                            message: ok_msg,
                        },
                        &metrics,
                    );
                }
            }
        }
        if events.is_empty() {
            continue;
        }
        let mut sink = DeferredSink::default();
        let mut evs: Vec<EventToWrite> = events.iter().map(|e| e.1.clone()).collect();
        let write_res = (|| {
            let mut txn = env.begin_rw()?;
            write_events(&mut txn, &mut sink, &mut evs, false)?;
            let mut cache = NegentropyFilterCache::new(cfg.read().relay.max_tags_per_filter);
            sink.apply(&mut cache, &mut txn)
                .map_err(|e| wok_db::DbError::msg(e.to_string()))?;
            txn.commit()?;
            Ok::<_, wok_db::DbError>(())
        })();
        if let Err(e) = write_res {
            for (conn_id, ev, _) in &events {
                let id_hex = PackedEventView::new(&ev.packed)
                    .map(|p| to_hex(p.id()))
                    .unwrap_or_else(|_| "?".into());
                conns.send(
                    *conn_id,
                    RelayMessage::Ok {
                        event_id: id_hex,
                        accepted: false,
                        message: format!("Write error: {e}"),
                    },
                    &metrics,
                );
            }
            continue;
        }
        for (i, (conn_id, _, _)) in events.iter().enumerate() {
            let packed = PackedEventView::new(&evs[i].packed).ok();
            let id_hex = packed
                .as_ref()
                .map(|p| to_hex(p.id()))
                .unwrap_or_else(|| "?".into());
            let (written, message) = match evs[i].status {
                EventWriteStatus::Written => {
                    metrics.written_events_total.fetch_add(1, Ordering::Relaxed);
                    (true, String::new())
                }
                EventWriteStatus::Duplicate => {
                    metrics.dup_events_total.fetch_add(1, Ordering::Relaxed);
                    (true, "duplicate: have this event".into())
                }
                EventWriteStatus::Replaced => {
                    metrics
                        .rejected_events_total
                        .fetch_add(1, Ordering::Relaxed);
                    (false, "replaced: have newer event".into())
                }
                EventWriteStatus::Deleted => {
                    metrics
                        .rejected_events_total
                        .fetch_add(1, Ordering::Relaxed);
                    (false, "deleted: user requested deletion".into())
                }
                EventWriteStatus::Pending => (false, "Write error: pending".into()),
            };
            conns.send(
                *conn_id,
                RelayMessage::Ok {
                    event_id: id_hex,
                    accepted: written,
                    message,
                },
                &metrics,
            );
        }
        broadcast_db_change(&mon_txs);
    }
}

fn render_ip(ip: &[u8]) -> String {
    if ip.len() == 4 {
        format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
    } else if ip.len() == 16 {
        let a: [u8; 16] = ip.try_into().unwrap_or([0; 16]);
        std::net::Ipv6Addr::from(a).to_string()
    } else {
        String::new()
    }
}

fn run_req_worker(
    env: Env,
    cfg: Arc<parking_lot::RwLock<Config>>,
    conns: Arc<ConnTable>,
    metrics: Arc<Metrics>,
    rx: Receiver<ReqMsg>,
    mon_txs: Vec<Sender<MonitorMsg>>,
) {
    let mut queries = QueryScheduler::new(cfg.read().relay.max_subs_per_connection);
    let mut authed: HashMap<u64, [u8; 32]> = HashMap::new();
    let mut decomp = Decompressor::new();
    loop {
        let msg = if queries.has_running() {
            match rx.try_recv() {
                Ok(m) => Some(m),
                Err(crossbeam_channel::TryRecvError::Empty) => None,
                Err(_) => break,
            }
        } else {
            match rx.recv() {
                Ok(m) => Some(m),
                Err(_) => break,
            }
        };
        let cfg_snap = cfg.read().clone();
        let r = restrictor(&cfg_snap);
        let txn = match env.begin_ro() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if let Some(msg) = msg {
            match msg {
                ReqMsg::NewSub(sub) => {
                    let conn = sub.conn_id;
                    if !queries.add_sub(&txn, sub).unwrap_or(false) {
                        conns.send(
                            conn,
                            RelayMessage::notice_error("too many concurrent REQs"),
                            &metrics,
                        );
                    }
                }
                ReqMsg::SetAuth {
                    conn_id,
                    authed: pk,
                } => {
                    authed.insert(conn_id, pk);
                    let _ = route_tx(&mon_txs, conn_id).send(MonitorMsg::SetAuth {
                        conn_id,
                        authed: pk,
                    });
                }
                ReqMsg::RemoveSub { conn_id, sub_id } => {
                    queries.remove_sub(conn_id, &sub_id);
                    let _ =
                        route_tx(&mon_txs, conn_id).send(MonitorMsg::RemoveSub { conn_id, sub_id });
                }
                ReqMsg::Close { conn_id } => {
                    authed.remove(&conn_id);
                    queries.close_conn(conn_id);
                    let _ = route_tx(&mon_txs, conn_id).send(MonitorMsg::Close { conn_id });
                }
            }
        }
        let mut completed: Vec<(Subscription, u64)> = Vec::new();
        let mut events: Vec<(Subscription, String)> = Vec::new();
        let _ = queries.process(
            &txn,
            cfg_snap.relay.query_timeslice_budget_us,
            |sub, lev, payload| {
                if sub.count_only {
                    return;
                }
                let pk = authed.get(&sub.conn_id).map(|a| a.as_slice());
                let packed_buf = wok_db::get_packed_ro(&txn, lev).ok().flatten();
                if let Some(buf) = packed_buf {
                    if let Ok(packed) = PackedEventView::new(&buf) {
                        if !r.should_send_to_subscriber(packed, pk) {
                            return;
                        }
                    }
                }
                if let Some(raw) = payload {
                    if let Ok(json) = decomp.decode(&txn, raw, cfg_snap.events.max_event_size) {
                        events.push((sub.clone(), json.to_string()));
                    }
                }
            },
            |sub, total| {
                completed.push((sub.clone(), total));
            },
        );
        drop(txn);
        for (sub, json) in events {
            conns.send(
                sub.conn_id,
                RelayMessage::Event {
                    sub_id: sub.sub_id.to_string(),
                    event_json: json,
                },
                &metrics,
            );
        }
        for (sub, total) in completed {
            if sub.count_only {
                let mut count = total;
                let mut limited = false;
                if count > cfg_snap.relay.max_filter_limit_count {
                    count = cfg_snap.relay.max_filter_limit_count;
                    limited = true;
                }
                conns.send(
                    sub.conn_id,
                    RelayMessage::Count {
                        sub_id: sub.sub_id.to_string(),
                        count,
                        limited,
                    },
                    &metrics,
                );
            } else {
                conns.send(
                    sub.conn_id,
                    RelayMessage::Eose {
                        sub_id: sub.sub_id.to_string(),
                    },
                    &metrics,
                );
                let _ = route_tx(&mon_txs, sub.conn_id).send(MonitorMsg::NewSub(sub));
            }
        }
    }
}

fn run_req_monitor(
    env: Env,
    cfg: Arc<parking_lot::RwLock<Config>>,
    conns: Arc<ConnTable>,
    metrics: Arc<Metrics>,
    rx: Receiver<MonitorMsg>,
) {
    let mut monitors = ActiveMonitors::new(cfg.read().relay.max_subs_per_connection);
    let mut authed: HashMap<u64, [u8; 32]> = HashMap::new();
    let mut curr_event_id = u64::MAX;
    let mut decomp = Decompressor::new();
    while let Ok(msg) = rx.recv() {
        let mut batch = vec![msg];
        while let Ok(more) = rx.try_recv() {
            batch.push(more);
        }
        let cfg_snap = cfg.read().clone();
        let r = restrictor(&cfg_snap);
        let txn = match env.begin_ro() {
            Ok(t) => t,
            Err(_) => continue,
        };
        let latest = most_recent_levid_ro(&txn).unwrap_or(0);
        if curr_event_id > latest {
            curr_event_id = latest;
        }
        for msg in batch {
            match msg {
                MonitorMsg::NewSub(mut sub) => {
                    let conn = sub.conn_id;
                    let pk = authed.get(&conn).map(|a| a.as_slice());
                    let start = sub.latest_event_id.saturating_add(1);
                    let mut catchup = Vec::new();
                    let _ = wok_db::foreach_event_from(&txn, start, |lev, packed_bytes| {
                        if let Ok(packed) = PackedEventView::new(packed_bytes) {
                            if sub.filter_group.does_match(packed)
                                && r.should_send_to_subscriber(packed, pk)
                            {
                                if let Ok(json) = event_json_owned(
                                    &txn,
                                    &mut decomp,
                                    lev,
                                    cfg_snap.events.max_event_size,
                                ) {
                                    catchup.push((sub.sub_id.to_string(), json));
                                }
                            }
                        }
                        true
                    });
                    for (sid, json) in catchup {
                        conns.send(
                            conn,
                            RelayMessage::Event {
                                sub_id: sid,
                                event_json: json,
                            },
                            &metrics,
                        );
                    }
                    sub.latest_event_id = latest;
                    if !monitors.add_sub(sub, latest) {
                        conns.send(
                            conn,
                            RelayMessage::notice_error("too many concurrent REQs"),
                            &metrics,
                        );
                    }
                }
                MonitorMsg::SetAuth {
                    conn_id,
                    authed: pk,
                } => {
                    authed.insert(conn_id, pk);
                }
                MonitorMsg::RemoveSub { conn_id, sub_id } => {
                    monitors.remove_sub(conn_id, &sub_id);
                }
                MonitorMsg::Close { conn_id } => {
                    authed.remove(&conn_id);
                    monitors.close_conn(conn_id);
                }
                MonitorMsg::DbChange => {
                    let start = curr_event_id.saturating_add(1);
                    let _ = wok_db::foreach_event_from(&txn, start, |lev, packed_bytes| {
                        if let Ok(packed) = PackedEventView::new(packed_bytes) {
                            let recips = monitors.process(lev, packed);
                            if recips.is_empty() {
                                return true;
                            }
                            if let Ok(json) = event_json_owned(
                                &txn,
                                &mut decomp,
                                lev,
                                cfg_snap.events.max_event_size,
                            ) {
                                let filtered: Vec<(u64, String)> = recips
                                    .into_iter()
                                    .filter(|recip| {
                                        let pk = authed.get(&recip.conn_id).map(|a| a.as_slice());
                                        r.should_send_to_subscriber(packed, pk)
                                    })
                                    .map(|recip| (recip.conn_id, recip.sub_id.to_string()))
                                    .collect();
                                conns.send_event_batch(&filtered, &json, &metrics);
                            }
                        }
                        true
                    });
                    curr_event_id = latest;
                }
            }
        }
    }
}

fn run_negentropy(
    env: Env,
    cfg: Arc<parking_lot::RwLock<Config>>,
    conns: Arc<ConnTable>,
    metrics: Arc<Metrics>,
    rx: Receiver<NegMsg>,
) {
    let mut views: HashMap<(u64, String), NegView> = HashMap::new();
    let mut queries = QueryScheduler::new(cfg.read().relay.max_subs_per_connection);
    queries.ensure_exists = false;
    let mut authed: HashMap<u64, [u8; 32]> = HashMap::new();
    let max_subs = cfg.read().relay.max_subs_per_connection;
    loop {
        let msg = if queries.has_running() {
            match rx.try_recv() {
                Ok(m) => Some(m),
                Err(crossbeam_channel::TryRecvError::Empty) => None,
                Err(_) => break,
            }
        } else {
            match rx.recv() {
                Ok(m) => Some(m),
                Err(_) => break,
            }
        };
        let cfg_snap = cfg.read().clone();
        let txn = match env.begin_ro() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if let Some(msg) = msg {
            match msg {
                NegMsg::Open {
                    sub,
                    filter_str,
                    payload,
                } => {
                    let conn = sub.conn_id;
                    let sid = sub.sub_id.to_string();
                    let key = (conn, sid.clone());
                    // C++ replaces any existing view with the same handle.
                    views.remove(&key);
                    let mut tree_id = None;
                    let _ = wok_db::foreach_negentropy_filter(&txn, |id, f| {
                        if f == filter_str {
                            tree_id = Some(id);
                            false
                        } else {
                            true
                        }
                    });
                    if let Some(tid) = tree_id {
                        reconcile_stateless(
                            &txn, &conns, &metrics, conn, &sid, tid, &sub, &payload,
                        );
                        // C++ keeps the stateless view even if the first
                        // reconcile failed (handleReconcile runs before
                        // addStatelessView), so insert unconditionally.
                        if count_conn_views(&views, conn) >= max_subs {
                            views.remove(&key);
                            conns.send(
                                conn,
                                RelayMessage::notice_error("too many concurrent NEG requests"),
                                &metrics,
                            );
                        } else {
                            views.insert(key, NegView::Stateless { sub, tree_id: tid });
                        }
                    } else if count_conn_views(&views, conn) >= max_subs {
                        conns.send(
                            conn,
                            RelayMessage::notice_error("too many concurrent NEG requests"),
                            &metrics,
                        );
                    } else {
                        match queries.add_sub(&txn, sub) {
                            Ok(true) => {
                                views.insert(
                                    key,
                                    NegView::Memory {
                                        initial: payload,
                                        vec: Vector::new(),
                                    },
                                );
                            }
                            _ => {
                                conns.send(
                                    conn,
                                    RelayMessage::notice_error("too many concurrent REQs"),
                                    &metrics,
                                );
                            }
                        }
                    }
                }
                NegMsg::Msg {
                    conn_id,
                    sub_id,
                    payload,
                } => {
                    let key = (conn_id, sub_id.to_string());
                    match views.get(&key) {
                        Some(NegView::Memory { vec, .. }) => {
                            if !vec.is_sealed() {
                                conns.send(
                                    conn_id,
                                    RelayMessage::notice_error(
                                        "negentropy error: got NEG-MSG before NEG-OPEN complete",
                                    ),
                                    &metrics,
                                );
                            } else {
                                match reconcile_vector(vec.clone(), &payload) {
                                    Ok(resp) => {
                                        conns.send(
                                            conn_id,
                                            RelayMessage::NegMsg {
                                                sub_id: sub_id.to_string(),
                                                payload_hex: hex::encode(resp),
                                            },
                                            &metrics,
                                        );
                                    }
                                    Err(_) => {
                                        send_neg_protocol_error(
                                            &conns,
                                            &metrics,
                                            conn_id,
                                            &sub_id.to_string(),
                                        );
                                        views.remove(&key);
                                    }
                                }
                            }
                        }
                        Some(NegView::Stateless { sub, tree_id }) => {
                            let tid = *tree_id;
                            let ok = reconcile_stateless(
                                &txn,
                                &conns,
                                &metrics,
                                conn_id,
                                &sub_id.to_string(),
                                tid,
                                sub,
                                &payload,
                            );
                            if !ok {
                                views.remove(&key);
                            }
                        }
                        None => {
                            conns.send(
                                conn_id,
                                RelayMessage::NegErr {
                                    sub_id: sub_id.to_string(),
                                    message: "closed: unknown subscription handle".into(),
                                    extra: None,
                                },
                                &metrics,
                            );
                        }
                    }
                }
                NegMsg::SetAuth {
                    conn_id,
                    authed: pk,
                } => {
                    authed.insert(conn_id, pk);
                }
                NegMsg::CloseSub { conn_id, sub_id } => {
                    queries.remove_sub(conn_id, &sub_id);
                    views.remove(&(conn_id, sub_id.to_string()));
                }
                NegMsg::Close { conn_id } => {
                    queries.close_conn(conn_id);
                    views.retain(|k, _| k.0 != conn_id);
                    authed.remove(&conn_id);
                }
            }
        }
        let r = restrictor(&cfg_snap);
        let mut lev_hits: Vec<(Subscription, u64)> = Vec::new();
        let mut done: Vec<(Subscription, u64)> = Vec::new();
        let _ = queries.process(
            &txn,
            cfg_snap.relay.query_timeslice_budget_us,
            |sub, lev, _| {
                lev_hits.push((sub.clone(), lev));
            },
            |sub, total| {
                done.push((sub.clone(), total));
            },
        );
        for (sub, lev) in lev_hits {
            if let Ok(Some(buf)) = wok_db::get_packed_ro(&txn, lev) {
                if let Ok(packed) = PackedEventView::new(&buf) {
                    let pk = authed.get(&sub.conn_id).map(|a| a.as_slice());
                    if r.should_send_to_subscriber(packed, pk) {
                        if let Some(NegView::Memory { vec, .. }) =
                            views.get_mut(&(sub.conn_id, sub.sub_id.to_string()))
                        {
                            let _ = vec.insert(packed.created_at(), packed.id());
                        }
                    }
                }
            }
        }
        for (sub, total) in done {
            let key = (sub.conn_id, sub.sub_id.to_string());
            let Some(NegView::Memory { initial, vec }) = views.get_mut(&key) else {
                continue;
            };
            // C++ counts matched levIds before the ReadRestrictor filter.
            if total > cfg_snap.relay.max_sync_events {
                conns.send(
                    sub.conn_id,
                    RelayMessage::NegErr {
                        sub_id: sub.sub_id.to_string(),
                        message: "blocked: too many query results".into(),
                        extra: Some(json!(cfg_snap.relay.max_sync_events)),
                    },
                    &metrics,
                );
                views.remove(&key);
                continue;
            }
            let _ = vec.seal();
            let initial = std::mem::take(initial);
            match reconcile_vector(vec.clone(), &initial) {
                Ok(resp) => {
                    conns.send(
                        sub.conn_id,
                        RelayMessage::NegMsg {
                            sub_id: sub.sub_id.to_string(),
                            payload_hex: hex::encode(resp),
                        },
                        &metrics,
                    );
                }
                Err(_) => {
                    send_neg_protocol_error(&conns, &metrics, sub.conn_id, &sub.sub_id.to_string());
                    views.remove(&key);
                }
            }
        }
    }
}

enum NegView {
    Memory { initial: Vec<u8>, vec: Vector },
    Stateless { sub: Subscription, tree_id: u64 },
}

fn count_conn_views(views: &HashMap<(u64, String), NegView>, conn: u64) -> usize {
    views.keys().filter(|k| k.0 == conn).count()
}

fn reconcile_vector(store: Vector, payload: &[u8]) -> Result<Vec<u8>, String> {
    let mut ne = Negentropy::new(store, 500_000).map_err(|e| e.to_string())?;
    ne.reconcile(payload).map_err(|e| e.to_string())
}

fn send_neg_protocol_error(conns: &ConnTable, metrics: &Metrics, conn: u64, sid: &str) {
    conns.send(
        conn,
        RelayMessage::NegErr {
            sub_id: sid.to_string(),
            message: "PROTOCOL-ERROR".into(),
            extra: None,
        },
        metrics,
    );
}

/// Reconcile one message against a precomputed tree ("stateless" view in
/// C++). Returns false on protocol error (caller removes the view).
#[allow(clippy::too_many_arguments)]
fn reconcile_stateless(
    txn: &wok_db::RoTxn<'_>,
    conns: &ConnTable,
    metrics: &Metrics,
    conn: u64,
    sid: &str,
    tree_id: u64,
    sub: &Subscription,
    payload: &[u8],
) -> bool {
    let resp = (|| -> Result<Vec<u8>, String> {
        let mut tree = wok_negentropy::open_ro(txn, tree_id).map_err(|e| e.to_string())?;
        let f = sub.filter_group.filters.first();
        let since = f.map(|f| f.since).unwrap_or(0);
        let until = f.map(|f| f.until).unwrap_or(u64::MAX);
        let lower = wok_negentropy::Bound::timestamp(since);
        let upper = wok_negentropy::Bound::timestamp(if until == u64::MAX {
            u64::MAX
        } else {
            until.saturating_add(1)
        });
        let sub_store = wok_negentropy::SubRange::new(&mut tree, &lower, &upper);
        let mut ne = Negentropy::new(sub_store, 500_000).map_err(|e| e.to_string())?;
        ne.reconcile(payload).map_err(|e| e.to_string())
    })();
    match resp {
        Ok(r) => {
            conns.send(
                conn,
                RelayMessage::NegMsg {
                    sub_id: sid.to_string(),
                    payload_hex: hex::encode(r),
                },
                metrics,
            );
            true
        }
        Err(_) => {
            send_neg_protocol_error(conns, metrics, conn, sid);
            false
        }
    }
}

fn run_cron(env: Env, cfg: Arc<parking_lot::RwLock<Config>>, shutdown: Arc<AtomicBool>) {
    while !shutdown.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_secs(9));
        let cfg_snap = cfg.read().clone();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let ephemeral_cutoff = now.saturating_sub(cfg_snap.events.ephemeral_lifetime_secs);
        let mut expired = Vec::new();
        if let Ok(txn) = env.begin_ro() {
            let most_recent = most_recent_levid_ro(&txn).unwrap_or(0);
            let _ = txn.foreach_full(
                txn.env().dbis().event_expiration,
                &0u64.to_ne_bytes(),
                &0u64.to_ne_bytes(),
                false,
                |k, v| {
                    if k.len() != 8 || v.len() != 8 {
                        return true;
                    }
                    let expiration = u64::from_ne_bytes(k.try_into().unwrap());
                    let lev = u64::from_ne_bytes(v.try_into().unwrap());
                    if expiration > now {
                        return false;
                    }
                    if lev == most_recent {
                        return true;
                    }
                    if expiration == 1 {
                        if let Ok(Some(buf)) = wok_db::get_packed_ro(&txn, lev) {
                            if let Ok(p) = PackedEventView::new(&buf) {
                                if p.created_at() <= ephemeral_cutoff {
                                    expired.push(lev);
                                }
                            }
                        }
                    } else {
                        expired.push(lev);
                    }
                    true
                },
            );
        }
        if expired.is_empty() {
            continue;
        }
        if let Ok(mut txn) = env.begin_rw() {
            let mut sink = DeferredSink::default();
            let _ = wok_db::delete_events(&mut txn, &mut sink, expired);
            let mut cache = NegentropyFilterCache::new(cfg.read().relay.max_tags_per_filter);
            let _ = sink.apply(&mut cache, &mut txn);
            let _ = txn.commit();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Keypair, SECP256K1};
    use wok_db::EnvOptions;

    fn sign_event(mut ev: Value) -> Value {
        let mut rng = rand::thread_rng();
        let kp = Keypair::new(SECP256K1, &mut rng);
        let (xonly, _) = kp.x_only_public_key();
        ev["pubkey"] = json!(hex::encode(xonly.serialize()));
        let id = wok_event::event_id_hash(&ev).unwrap();
        ev["id"] = json!(hex::encode(id));
        let sig = SECP256K1.sign_schnorr(&id, &kp);
        ev["sig"] = json!(hex::encode(sig.as_ref()));
        ev
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    #[tokio::test]
    async fn outbound_byte_accounting_and_kill() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<OutboundFrame>(8);
        let out = Outbound::new(tx, 100);
        let killed = out.killed();

        assert!(out.try_send("x".repeat(60)));
        assert!(out.try_send("y".repeat(30)));
        // 60 + 30 + 20 > 100: over budget, rejected.
        assert!(!out.try_send("z".repeat(20)));

        // Draining one frame releases its bytes.
        drop(rx.recv().await.unwrap());
        assert!(out.try_send("z".repeat(20)));

        // Kill notification reaches the transport.
        out.kill();
        tokio::time::timeout(Duration::from_secs(1), killed.notified())
            .await
            .expect("kill notification");

        // Limit 0 means unlimited.
        let (tx2, _rx2) = tokio::sync::mpsc::channel::<OutboundFrame>(8);
        let out2 = Outbound::new(tx2, 0);
        for _ in 0..8 {
            assert!(out2.try_send("q".repeat(1000)));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn event_write_returns_ok() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::default()).unwrap();
        env.ensure_initialized().unwrap();
        let mut cfg = Config::default();
        cfg.db = dir.path().to_path_buf();
        cfg.relay.auth.enabled = false;
        let handle = start(env, cfg).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<OutboundFrame>(32);
        let conn = handle.next_conn_id();
        handle.register(conn, Outbound::new(tx, 0)).await;
        let ev = sign_event(json!({
            "created_at": now_secs(),
            "kind": 1,
            "tags": [],
            "content": "core-ok",
        }));
        handle
            .client_message(conn, vec![127, 0, 0, 1], json!(["EVENT", ev]).to_string())
            .await;
        let mut got = None;
        for _ in 0..80 {
            match rx.try_recv() {
                Ok(frame) => {
                    got = Some(frame.into_text());
                    break;
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                Err(e) => panic!("outbound closed: {e}"),
            }
        }
        let msg = got.expect("expected outbound OK");
        assert!(msg.contains("\"OK\""), "got {msg}");
        assert!(msg.contains("true"), "got {msg}");
        handle.request_shutdown();
    }
}
