//! Relay process: ingest, writer, req, monitor, negentropy, cron.
//!
//! LMDB work stays on dedicated OS threads. Outbound messages are owned
//! `String`s sent over Tokio mpsc channels that never hold mmap borrows.

#![allow(clippy::too_many_arguments)]
#![allow(clippy::field_reassign_with_default)]

use crate::abuse::{leading_zero_bits, AbuseController, BudgetKind};
use crate::config::{Config, EphemeralPersistence};
use crate::metrics::Metrics;
use crate::plugin::{PluginEventSifter, PluginResult};
use crate::protocol::{ClientCommand, RelayMessage};
use crate::restrict::ReadRestrictor;
use crate::supported_nips;
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
    backfill_vanish_markers, is_event_vanished_ro, lookup_event_by_id_ro, most_recent_levid_ro,
    sweep_vanished_events, write_events_with_policy, Decompressor, Env, EventToWrite,
    EventWriteStatus, VANISH_KIND,
};
use wok_event::{
    parse_and_verify_event, to_hex, PackedEventView, TimestampPolicy, AUTH_CHALLENGE_LEN,
    AUTH_KIND, GIFT_WRAP_KINDS, PROTECTED_TAG, REPOST_KINDS,
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
    tx: tokio::sync::mpsc::UnboundedSender<OutboundFrame>,
    pending: Arc<AtomicU64>,
    limit: usize,
    kill: Arc<tokio::sync::Notify>,
}

impl Outbound {
    pub fn new(tx: tokio::sync::mpsc::UnboundedSender<OutboundFrame>, limit: usize) -> Self {
        Self {
            tx,
            pending: Arc::new(AtomicU64::new(0)),
            limit,
            kill: Arc::new(tokio::sync::Notify::new()),
        }
    }

    fn try_send(&self, msg: String) -> Result<(), OutboundSendError> {
        let len = msg.len() as u64;
        let prev = self.pending.fetch_add(len, Ordering::Relaxed);
        if self.limit != 0 && prev.saturating_add(len) > self.limit as u64 {
            self.pending.fetch_sub(len, Ordering::Relaxed);
            return Err(OutboundSendError::OverByteLimit);
        }
        // On failure the frame drops here, undoing the accounting.
        self.tx
            .send(OutboundFrame {
                len: msg.len() as u64,
                text: msg,
                pending: self.pending.clone(),
            })
            .map_err(|_| OutboundSendError::Closed)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutboundSendError {
    OverByteLimit,
    Closed,
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
    /// Deliver a pre-built frame, terminating the connection if it is over
    /// its pending-bytes budget (C++ slow-client termination).
    fn deliver(&self, conn_id: u64, payload: String, metrics: &Metrics) {
        let mut map = self.map.lock();
        if let Some(out) = map.get(&conn_id) {
            if let Err(error) = out.try_send(payload) {
                if error == OutboundSendError::OverByteLimit {
                    metrics
                        .slow_client_terminations
                        .fetch_add(1, Ordering::Relaxed);
                }
                if let Some(out) = map.remove(&conn_id) {
                    if error == OutboundSendError::OverByteLimit {
                        out.kill();
                    }
                }
            }
        }
    }

    fn send(&self, id: u64, msg: RelayMessage, metrics: &Metrics) {
        bump_relay_metrics(&msg, metrics);
        let json = msg.to_json();
        self.deliver(id, json, metrics);
    }

    /// Build the EVENT frame once (pre-sized) and deliver.
    fn send_event(&self, conn_id: u64, sub_id: &str, ev_json: &str, metrics: &Metrics) {
        metrics.relay_event.fetch_add(1, Ordering::Relaxed);
        let mut payload = String::with_capacity(sub_id.len() + ev_json.len() + 12);
        payload.push_str("[\"EVENT\",\"");
        payload.push_str(sub_id);
        payload.push_str("\",");
        payload.push_str(ev_json);
        payload.push(']');
        self.deliver(conn_id, payload, metrics);
    }

    fn send_event_batch(&self, recipients: &[(u64, SubId)], ev_json: &str, metrics: &Metrics) {
        for (conn, sub) in recipients {
            metrics.relay_event.fetch_add(1, Ordering::Relaxed);
            let sub = sub.as_str();
            let mut payload = String::with_capacity(sub.len() + ev_json.len() + 12);
            payload.push_str("[\"EVENT\",\"");
            payload.push_str(sub);
            payload.push_str("\",");
            payload.push_str(ev_json);
            payload.push(']');
            self.deliver(*conn, payload, metrics);
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
    abuse: Arc<AbuseController>,
    config_path: Arc<parking_lot::RwLock<Option<std::path::PathBuf>>>,
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
    NewSub {
        sub: Subscription,
        ready: Sender<()>,
    },
    SetAuth {
        conn_id: u64,
        authed: [u8; 32],
    },
    RemoveSub {
        conn_id: u64,
        sub_id: SubId,
    },
    Close {
        conn_id: u64,
    },
    DbChange,
    Ephemeral {
        packed: Vec<u8>,
        json: String,
    },
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

    /// Apply the connection-opening budget before a WebSocket upgrade.
    pub fn admit_connection(&self, ip: &[u8]) -> bool {
        let cfg = self.config.read();
        let admitted = self
            .abuse
            .admit_ip(ip, BudgetKind::Connection, &cfg.relay.abuse);
        if !admitted {
            self.metrics
                .abuse_connection_rejections
                .fetch_add(1, Ordering::Relaxed);
        }
        admitted
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

    pub fn set_config_path(&self, path: std::path::PathBuf) {
        *self.config_path.write() = Some(path);
    }

    pub fn config_path(&self) -> Option<std::path::PathBuf> {
        self.config_path.read().clone()
    }
}

pub fn start(env: Env, config: Config) -> Result<RelayHandle, String> {
    env.ensure_initialized().map_err(|e| e.to_string())?;
    let backfilled =
        backfill_vanish_markers(&env, &config.vanish_policy(), config.events.max_event_size)
            .map_err(|e| format!("NIP-62 marker backfill failed: {e}"))?;
    if backfilled > 0 {
        tracing::info!(backfilled, "materialized existing NIP-62 vanish markers");
    }
    let n_ingester = config.relay.ingester_threads.max(1);
    let n_req_worker = config.relay.req_worker_threads.max(1);
    let n_req_monitor = config.relay.req_monitor_threads.max(1);
    let n_negentropy = config.relay.negentropy_threads.max(1);
    let config = Arc::new(parking_lot::RwLock::new(config));
    let conns = Arc::new(ConnTable::new());
    let metrics = Arc::new(Metrics::default());
    {
        let cfg = config.read();
        metrics.history.configure(
            cfg.observability.history_enabled,
            cfg.observability.history_max_points,
        );
    }
    let shutdown = Arc::new(AtomicBool::new(false));
    let abuse = Arc::new(AbuseController::default());

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
        abuse: abuse.clone(),
        config_path: Arc::new(parking_lot::RwLock::new(None)),
    };

    for (i, ingest_rx) in ingest_rxs.into_iter().enumerate() {
        let env = env.clone();
        let cfg = config.clone();
        let conns = conns.clone();
        let metrics = metrics.clone();
        let writer_tx = writer_tx.clone();
        let req_txs = req_txs.clone();
        let neg_txs = neg_txs.clone();
        let abuse = abuse.clone();
        thread::Builder::new()
            .name(format!("ingester-{i}"))
            .spawn(move || {
                run_ingester(
                    env, cfg, conns, metrics, abuse, ingest_rx, writer_tx, req_txs, neg_txs,
                )
            })
            .map_err(|e| e.to_string())?;
    }
    {
        let cfg = config.clone();
        let metrics = metrics.clone();
        let shutdown = shutdown.clone();
        thread::Builder::new()
            .name("metrics-history".into())
            .spawn(move || run_metrics_history(cfg, metrics, shutdown))
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

fn run_metrics_history(
    cfg: Arc<parking_lot::RwLock<Config>>,
    metrics: Arc<Metrics>,
    shutdown: Arc<AtomicBool>,
) {
    while !shutdown.load(Ordering::Relaxed) {
        let observability = cfg.read().observability.clone();
        metrics.history.configure(
            observability.history_enabled,
            observability.history_max_points,
        );
        if observability.history_enabled && observability.history_max_points > 0 {
            metrics.record_history();
        }
        let seconds = observability.history_interval_secs.max(1);
        for _ in 0..seconds {
            if shutdown.load(Ordering::Relaxed) {
                return;
            }
            thread::sleep(Duration::from_secs(1));
        }
    }
}

/// Broadcast a database-change notification to every req-monitor thread.
fn broadcast_db_change(mon_txs: &[Sender<MonitorMsg>]) {
    for tx in mon_txs {
        let _ = tx.send(MonitorMsg::DbChange);
    }
}

fn broadcast_ephemeral(mon_txs: &[Sender<MonitorMsg>], packed: &[u8], json: &str) {
    for tx in mon_txs {
        let _ = tx.send(MonitorMsg::Ephemeral {
            packed: packed.to_vec(),
            json: json.to_string(),
        });
    }
}

/// Watch data.mdb for changes made by *other* processes (a co-resident C++
/// strfry, `wok import`, ...) and poke the req-monitor, mirroring C++
/// RelayReqMonitor's hoytech::file_change_monitor (100ms debounce). Polling
/// is used for portability; semantics match.
fn run_db_watch(env: Env, mon_txs: Vec<Sender<MonitorMsg>>, shutdown: Arc<AtomicBool>) {
    let path = env.path().join("data.mdb");
    // Reconcile once after establishing the baseline so a commit that lands
    // before this thread is first scheduled cannot be absorbed as baseline.
    let mut last = std::fs::metadata(&path)
        .ok()
        .and_then(|m| m.modified().ok().map(|t| (t, m.len())));
    let mut last_event_id = env
        .begin_ro()
        .ok()
        .and_then(|txn| most_recent_levid_ro(&txn).ok())
        .unwrap_or(0);
    broadcast_db_change(&mon_txs);
    while !shutdown.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(100));
        let cur = std::fs::metadata(&path)
            .ok()
            .and_then(|m| m.modified().ok().map(|t| (t, m.len())));
        let current_event_id = env
            .begin_ro()
            .ok()
            .and_then(|txn| most_recent_levid_ro(&txn).ok())
            .unwrap_or(last_event_id);
        let metadata_changed = cur.is_some() && cur != last;
        let events_changed = current_event_id != last_event_id;
        if metadata_changed || events_changed {
            last = cur;
            last_event_id = current_event_id;
            broadcast_db_change(&mon_txs);
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
    abuse: Arc<AbuseController>,
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
                    &env, &cfg_snap, &conns, &metrics, &abuse, &mut auth, conn_id, ip, &payload,
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
    abuse: &AbuseController,
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
            if !abuse.admit_ip(&ip, BudgetKind::Event, &cfg.relay.abuse) {
                metrics
                    .abuse_event_rate_rejections
                    .fetch_add(1, Ordering::Relaxed);
                let id = v.get("id").and_then(Value::as_str).unwrap_or("?");
                conns.send(
                    conn_id,
                    RelayMessage::Ok {
                        event_id: id.into(),
                        accepted: false,
                        message: "rate-limited: EVENT budget exhausted".into(),
                    },
                    metrics,
                );
                return;
            }
            ingest_event(
                env, cfg, conns, metrics, abuse, auth, conn_id, ip, v, writer_tx,
            );
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
            let pubkey = auth.get(&conn_id).and_then(|session| session.authed);
            if !abuse.admit_ip(&ip, BudgetKind::Req, &cfg.relay.abuse)
                || pubkey
                    .as_ref()
                    .is_some_and(|pk| !abuse.admit_pubkey(pk, BudgetKind::Req, &cfg.relay.abuse))
            {
                metrics
                    .abuse_req_rate_rejections
                    .fetch_add(1, Ordering::Relaxed);
                conns.send(
                    conn_id,
                    RelayMessage::closed_error(&sub_id, "rate-limited: REQ budget exhausted"),
                    metrics,
                );
                return;
            }
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
            let pubkey = auth.get(&conn_id).and_then(|session| session.authed);
            if !abuse.admit_ip(&ip, BudgetKind::Count, &cfg.relay.abuse)
                || pubkey
                    .as_ref()
                    .is_some_and(|pk| !abuse.admit_pubkey(pk, BudgetKind::Count, &cfg.relay.abuse))
            {
                metrics
                    .abuse_count_rate_rejections
                    .fetch_add(1, Ordering::Relaxed);
                conns.send(
                    conn_id,
                    RelayMessage::closed_error(&sub_id, "rate-limited: COUNT budget exhausted"),
                    metrics,
                );
                return;
            }
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
            let pubkey = auth.get(&conn_id).and_then(|session| session.authed);
            if !abuse.admit_ip(&ip, BudgetKind::Req, &cfg.relay.abuse)
                || pubkey
                    .as_ref()
                    .is_some_and(|pk| !abuse.admit_pubkey(pk, BudgetKind::Req, &cfg.relay.abuse))
            {
                metrics
                    .abuse_req_rate_rejections
                    .fetch_add(1, Ordering::Relaxed);
                conns.send(
                    conn_id,
                    RelayMessage::NegErr {
                        sub_id,
                        message: "rate-limited: NEG-OPEN budget exhausted".into(),
                        extra: None,
                    },
                    metrics,
                );
                return;
            }
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
    abuse: &AbuseController,
    auth: &mut HashMap<u64, AuthSession>,
    conn_id: u64,
    ip: Vec<u8>,
    orig: Value,
    writer_tx: &Sender<WriterMsg>,
) {
    let requested_kind = orig.get("kind").and_then(Value::as_u64).unwrap_or(u64::MAX);
    let policy = cfg.timestamp_policy_for_kind(requested_kind);
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
    tracing::debug!(
        conn_id,
        event_id = %id_hex,
        pubkey = %to_hex(packed.pubkey()),
        kind = packed.kind(),
        "validated inbound event"
    );
    let is_vanish_request = packed.kind() == VANISH_KIND;
    if is_vanish_request && !cfg.vanish_policy().targets_this_relay_json(&parsed.json) {
        conns.send(
            conn_id,
            RelayMessage::Ok {
                event_id: id_hex,
                accepted: false,
                message: if cfg.relay.nip62.enabled {
                    "blocked: vanish request not targeting this relay".into()
                } else {
                    "blocked: NIP-62 is disabled".into()
                },
            },
            metrics,
        );
        return;
    }

    if cfg.relay.abuse.enabled && !is_vanish_request {
        if leading_zero_bits(packed.id()) < cfg.relay.abuse.min_pow_difficulty as u16 {
            metrics.abuse_pow_rejections.fetch_add(1, Ordering::Relaxed);
            conns.send(
                conn_id,
                RelayMessage::Ok {
                    event_id: id_hex,
                    accepted: false,
                    message: format!(
                        "pow: difficulty {} required",
                        cfg.relay.abuse.min_pow_difficulty
                    ),
                },
                metrics,
            );
            return;
        }
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(packed.pubkey());
        if !abuse.admit_pubkey(&pubkey, BudgetKind::Event, &cfg.relay.abuse) {
            metrics
                .abuse_event_rate_rejections
                .fetch_add(1, Ordering::Relaxed);
            conns.send(
                conn_id,
                RelayMessage::Ok {
                    event_id: id_hex,
                    accepted: false,
                    message: "rate-limited: author EVENT budget exhausted".into(),
                },
                metrics,
            );
            return;
        }
    }

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
    if found_protected && !is_vanish_request {
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
    // NOTICE "ERROR: bad req: ..."; everything after is a NIP-01 CLOSED with
    // an `error:` machine-readable prefix. The sub id is known here,
    // except for the "arr too small" case which C++ raises first.
    let fail_closed = |e: String| {
        conns.send(
            conn_id,
            RelayMessage::closed_error(&sub_id, format!("error: bad req: {e}")),
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
    if filters.len() > cfg.relay.max_filters_per_req {
        // Preserve strfry's wire error for its legacy filter-count ceiling.
        fail_closed("arr too big".into());
        return;
    }
    let serialized_filter_bytes = filters.iter().fold(0usize, |total, filter| {
        total.saturating_add(filter.to_string().len())
    });
    if serialized_filter_bytes > cfg.relay.max_req_filter_size {
        fail_closed(format!(
            "filters exceed {} serialized bytes",
            cfg.relay.max_req_filter_size
        ));
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
    let query_cost = fg.estimated_cost(count_only);
    if cfg.relay.abuse.enabled
        && cfg.relay.abuse.max_query_cost != 0
        && query_cost > cfg.relay.abuse.max_query_cost
    {
        metrics
            .abuse_query_cost_rejections
            .fetch_add(1, Ordering::Relaxed);
        conns.send(
            conn_id,
            RelayMessage::closed_error(
                &sub_id,
                format!(
                    "rate-limited: estimated query cost {query_cost} exceeds {}",
                    cfg.relay.abuse.max_query_cost
                ),
            ),
            metrics,
        );
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
    let payload = wok_event::from_hex_strict(payload_hex).map_err(|e| e.to_string())?;
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
        let query_cost = fg.estimated_cost(false);
        if cfg.relay.abuse.enabled
            && cfg.relay.abuse.max_query_cost != 0
            && query_cost > cfg.relay.abuse.max_query_cost
        {
            metrics
                .abuse_query_cost_rejections
                .fetch_add(1, Ordering::Relaxed);
            conns.send(
                conn_id,
                RelayMessage::NegErr {
                    sub_id: sub_id.to_string(),
                    message: format!(
                        "rate-limited: estimated query cost {query_cost} exceeds {}",
                        cfg.relay.abuse.max_query_cost
                    ),
                    extra: None,
                },
                metrics,
            );
            return Ok(());
        }
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
        let vanish_policy = cfg_snap.vanish_policy();
        // A valid vanish request and an ephemeral gift wrap can arrive in the
        // same drained writer batch. Compute the batch markers up front so a
        // live-only event cannot be broadcast immediately before its request
        // is persisted later in that batch.
        let mut batch_vanish: HashMap<[u8; 32], u64> = HashMap::new();
        for m in &batch {
            let WriterMsg::AddEvent {
                conn_id,
                packed,
                json,
                ..
            } = m
            else {
                continue;
            };
            if closed.contains(conn_id) || !vanish_policy.targets_this_relay_json(json) {
                continue;
            }
            let Ok(event) = PackedEventView::new(packed) else {
                continue;
            };
            let mut pubkey = [0u8; 32];
            pubkey.copy_from_slice(event.pubkey());
            batch_vanish
                .entry(pubkey)
                .and_modify(|timestamp| *timestamp = (*timestamp).max(event.created_at()))
                .or_insert(event.created_at());
        }
        let mut events: Vec<(u64, EventToWrite)> = Vec::new();
        let mut quota_counts: HashMap<[u8; 32], u64> = HashMap::new();
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
                let mut ok_msg = String::new();
                let is_vanish_request =
                    PackedEventView::new(&packed).is_ok_and(|event| event.kind() == VANISH_KIND);
                let res = if is_vanish_request || cfg_snap.relay.write_policy_plugin.is_empty() {
                    PluginResult::Accept
                } else {
                    // Unix-socket connections carry no IP; they are reported
                    // to write-policy plugins as sourceType "unix" (wok
                    // extension). Event JSON is parsed only when a plugin will
                    // consume it; the normal empty-plugin path remains packed.
                    let source_type = if ip.is_empty() {
                        "unix"
                    } else if ip.len() == 4 {
                        "IP4"
                    } else {
                        "IP6"
                    };
                    let source_info = render_ip(&ip);
                    let ev_json: Value = serde_json::from_str(&json).unwrap_or(json!({}));
                    plugin.accept_event(
                        &cfg_snap.relay.write_policy_plugin,
                        &ev_json,
                        source_type,
                        &source_info,
                        authed.as_ref().map(|a| a.as_slice()),
                        &mut ok_msg,
                    )
                };
                if res == PluginResult::Accept {
                    if !is_vanish_request {
                        let packed_view = match PackedEventView::new(&packed) {
                            Ok(event) => event,
                            Err(error) => {
                                conns.send(
                                    conn_id,
                                    RelayMessage::Ok {
                                        event_id: "?".into(),
                                        accepted: false,
                                        message: format!("invalid: {error}"),
                                    },
                                    &metrics,
                                );
                                continue;
                            }
                        };
                        let stored_suppression = env
                            .begin_ro()
                            .and_then(|txn| is_event_vanished_ro(&txn, packed_view));
                        let suppressed = match stored_suppression {
                            Ok(value) => {
                                value || event_matches_vanish_markers(packed_view, &batch_vanish)
                            }
                            Err(error) => {
                                conns.send(
                                    conn_id,
                                    RelayMessage::Ok {
                                        event_id: to_hex(packed_view.id()),
                                        accepted: false,
                                        message: format!("Write error: {error}"),
                                    },
                                    &metrics,
                                );
                                continue;
                            }
                        };
                        if suppressed {
                            let id_hex = PackedEventView::new(&packed)
                                .map(|event| to_hex(event.id()))
                                .unwrap_or_else(|_| "?".into());
                            conns.send(
                                conn_id,
                                RelayMessage::Ok {
                                    event_id: id_hex,
                                    accepted: false,
                                    message: "blocked: author or recipient requested vanish".into(),
                                },
                                &metrics,
                            );
                            continue;
                        }
                    }
                    let is_live_only = cfg_snap.events.ephemeral_persistence
                        == EphemeralPersistence::LiveOnly
                        && PackedEventView::new(&packed)
                            .map(|event| event.expiration() == 1)
                            .unwrap_or(false);
                    if is_live_only {
                        let id_hex = PackedEventView::new(&packed)
                            .map(|event| to_hex(event.id()))
                            .unwrap_or_else(|_| "?".into());
                        broadcast_ephemeral(&mon_txs, &packed, &json);
                        metrics
                            .ephemeral_events_total
                            .fetch_add(1, Ordering::Relaxed);
                        conns.send(
                            conn_id,
                            RelayMessage::Ok {
                                event_id: id_hex,
                                accepted: true,
                                message: String::new(),
                            },
                            &metrics,
                        );
                    } else {
                        if !is_vanish_request
                            && cfg_snap.relay.abuse.enabled
                            && cfg_snap.relay.abuse.max_stored_events_per_pubkey != 0
                        {
                            let packed_view = match PackedEventView::new(&packed) {
                                Ok(packed) => packed,
                                Err(error) => {
                                    conns.send(
                                        conn_id,
                                        RelayMessage::Ok {
                                            event_id: "?".into(),
                                            accepted: false,
                                            message: format!("invalid: {error}"),
                                        },
                                        &metrics,
                                    );
                                    continue;
                                }
                            };
                            let mut pubkey = [0u8; 32];
                            pubkey.copy_from_slice(packed_view.pubkey());
                            let count = match quota_counts.entry(pubkey) {
                                std::collections::hash_map::Entry::Occupied(entry) => {
                                    *entry.into_mut()
                                }
                                std::collections::hash_map::Entry::Vacant(entry) => {
                                    match stored_event_count(&env, &pubkey) {
                                        Ok(count) => *entry.insert(count),
                                        Err(error) => {
                                            conns.send(
                                                conn_id,
                                                RelayMessage::Ok {
                                                    event_id: to_hex(packed_view.id()),
                                                    accepted: false,
                                                    message: format!("Write error: {error}"),
                                                },
                                                &metrics,
                                            );
                                            continue;
                                        }
                                    }
                                }
                            };
                            if count >= cfg_snap.relay.abuse.max_stored_events_per_pubkey {
                                metrics
                                    .abuse_pubkey_quota_rejections
                                    .fetch_add(1, Ordering::Relaxed);
                                conns.send(
                                    conn_id,
                                    RelayMessage::Ok {
                                        event_id: to_hex(packed_view.id()),
                                        accepted: false,
                                        message: "blocked: author storage quota exceeded".into(),
                                    },
                                    &metrics,
                                );
                                continue;
                            }
                            if let Some(count) = quota_counts.get_mut(&pubkey) {
                                *count = count.saturating_add(1);
                            }
                        }
                        events.push((conn_id, EventToWrite::new(packed, json)));
                    }
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
        // Move the events out instead of cloning each packed/json pair.
        let mut evs: Vec<EventToWrite> = Vec::with_capacity(events.len());
        let mut meta: Vec<u64> = Vec::with_capacity(events.len());
        for (conn_id, ev) in events.drain(..) {
            meta.push(conn_id);
            evs.push(ev);
        }
        let write_res = (|| {
            let mut txn = env.begin_rw()?;
            write_events_with_policy(&mut txn, &mut sink, &mut evs, false, &vanish_policy)?;
            let mut cache = NegentropyFilterCache::new(cfg.read().relay.max_tags_per_filter);
            sink.apply(&mut cache, &mut txn)
                .map_err(|e| wok_db::DbError::msg(e.to_string()))?;
            txn.commit()?;
            Ok::<_, wok_db::DbError>(())
        })();
        if let Err(e) = write_res {
            for (i, conn_id) in meta.iter().enumerate() {
                let id_hex = PackedEventView::new(&evs[i].packed)
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
        for (i, conn_id) in meta.iter().enumerate() {
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

fn event_matches_vanish_markers(
    packed: PackedEventView<'_>,
    markers: &HashMap<[u8; 32], u64>,
) -> bool {
    if packed.kind() != VANISH_KIND {
        let mut author = [0u8; 32];
        author.copy_from_slice(packed.pubkey());
        if markers
            .get(&author)
            .is_some_and(|timestamp| packed.created_at() <= *timestamp)
        {
            return true;
        }
    }
    if GIFT_WRAP_KINDS.contains(&packed.kind()) {
        let mut matched = false;
        packed.foreach_tag(|name, value| {
            if name == 'p' && value.len() == 32 {
                let mut recipient = [0u8; 32];
                recipient.copy_from_slice(value);
                if markers.contains_key(&recipient) {
                    matched = true;
                    return false;
                }
            }
            true
        });
        if matched {
            return true;
        }
    }
    false
}

fn stored_event_count(env: &Env, pubkey: &[u8; 32]) -> Result<u64, wok_db::DbError> {
    let txn = env.begin_ro()?;
    let start = wok_db::keys::make_key_string_u64(pubkey, 0);
    let end = wok_db::keys::make_key_string_u64(pubkey, u64::MAX);
    let mut count = 0u64;
    txn.foreach_full(
        txn.env().dbis().event_pubkey,
        &start,
        &end,
        false,
        |key, _| {
            if key.starts_with(pubkey) {
                count = count.saturating_add(1);
            }
            true
        },
    )?;
    Ok(count)
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
    let initial_cfg = cfg.read();
    let mut queries = QueryScheduler::new(
        initial_cfg.relay.abuse.max_concurrent_historical_queries,
        initial_cfg.relay.max_total_events_per_req,
    );
    drop(initial_cfg);
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
        let cfg_snap = cfg.read();
        queries.set_max_subs_per_connection(cfg_snap.relay.abuse.max_concurrent_historical_queries);
        queries.set_max_total_events_per_req(cfg_snap.relay.max_total_events_per_req);
        let r = restrictor(&cfg_snap);
        let txn = match env.begin_ro() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if let Some(msg) = msg {
            match msg {
                ReqMsg::NewSub(sub) => {
                    let conn = sub.conn_id;
                    let sub_id = sub.sub_id.to_string();
                    if !queries.add_sub(&txn, sub).unwrap_or(false) {
                        metrics
                            .abuse_query_concurrency_rejections
                            .fetch_add(1, Ordering::Relaxed);
                        conns.send(
                            conn,
                            RelayMessage::closed_error(
                                &sub_id,
                                "rate-limited: too many concurrent historical queries",
                            ),
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
        let mut completed: Vec<(Subscription, u64, Option<String>)> = Vec::new();
        // Events are framed and delivered inside the scan callback: no
        // per-event Subscription clone, no intermediate collection, and the
        // payload JSON is copied exactly once (into the frame).
        let _ = queries.process(
            &txn,
            cfg_snap.relay.query_timeslice_budget_us,
            |sub, lev, payload| {
                if sub.count_only {
                    return;
                }
                let pk = authed.get(&sub.conn_id).map(|a| a.as_slice());
                // Zero-copy packed lookup for the restriction check.
                if let Ok(Some(buf)) = txn.get_u64(txn.env().dbis().event, lev) {
                    if let Ok(packed) = PackedEventView::new(buf) {
                        if !r.should_send_to_subscriber(packed, pk) {
                            return;
                        }
                    }
                }
                if let Some(raw) = payload {
                    if let Ok(json) = decomp.decode(&txn, raw, cfg_snap.events.max_event_size) {
                        conns.send_event(sub.conn_id, sub.sub_id.as_str(), json, &metrics);
                    }
                }
            },
            |sub, total, hll| {
                completed.push((sub.clone(), total, hll));
            },
        );
        drop(txn);
        for (sub, total, hll) in completed {
            tracing::debug!(
                conn_id = sub.conn_id,
                sub_id = %sub.sub_id,
                count_only = sub.count_only,
                matched_events = total,
                hll = hll.is_some(),
                "historical query completed"
            );
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
                        hll: if limited { None } else { hll },
                    },
                    &metrics,
                );
            } else {
                let (ready_tx, ready_rx) = bounded(1);
                let installed = route_tx(&mon_txs, sub.conn_id)
                    .send(MonitorMsg::NewSub {
                        sub: sub.clone(),
                        ready: ready_tx,
                    })
                    .is_ok()
                    && ready_rx.recv_timeout(Duration::from_secs(5)).is_ok();
                if !installed {
                    conns.send(
                        sub.conn_id,
                        RelayMessage::notice_error("live subscription monitor unavailable"),
                        &metrics,
                    );
                }
                conns.send(
                    sub.conn_id,
                    RelayMessage::Eose {
                        sub_id: sub.sub_id.to_string(),
                    },
                    &metrics,
                );
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
        let cfg_snap = cfg.read();
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
                MonitorMsg::NewSub { mut sub, ready } => {
                    let conn = sub.conn_id;
                    let pk = authed.get(&conn).map(|a| a.as_slice());
                    let start = sub.latest_event_id.saturating_add(1);
                    let requires_content = sub.filter_group.requires_content();
                    let _ = wok_db::foreach_event_from(&txn, start, |lev, packed_bytes| {
                        if let Ok(packed) = PackedEventView::new(packed_bytes) {
                            if is_event_vanished_ro(&txn, packed).unwrap_or(true)
                                || !r.should_send_to_subscriber(packed, pk)
                                || (!requires_content && !sub.filter_group.does_match(packed))
                            {
                                return true;
                            }
                            if let Some(raw) = txn
                                .get_u64(txn.env().dbis().event_payload, lev)
                                .ok()
                                .flatten()
                            {
                                if let Ok(json) =
                                    decomp.decode(&txn, raw, cfg_snap.events.max_event_size)
                                {
                                    if requires_content {
                                        let search_terms =
                                            wok_db::event_search_terms(json).unwrap_or_default();
                                        if !sub.filter_group.does_match_with_search_terms(
                                            packed,
                                            Some(&search_terms),
                                        ) {
                                            return true;
                                        }
                                    }
                                    conns.send_event(conn, sub.sub_id.as_str(), json, &metrics);
                                }
                            }
                        }
                        true
                    });
                    sub.latest_event_id = latest;
                    if !monitors.add_sub(sub, latest) {
                        conns.send(
                            conn,
                            RelayMessage::notice_error("too many concurrent REQs"),
                            &metrics,
                        );
                    }
                    let _ = ready.send(());
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
                    let requires_content = monitors.requires_content();
                    let _ = wok_db::foreach_event_from(&txn, start, |lev, packed_bytes| {
                        if let Ok(packed) = PackedEventView::new(packed_bytes) {
                            if is_event_vanished_ro(&txn, packed).unwrap_or(true) {
                                return true;
                            }
                            let packed_recipients = if requires_content {
                                None
                            } else {
                                let recipients = monitors.process(lev, packed, None);
                                if recipients.is_empty() {
                                    return true;
                                }
                                Some(recipients)
                            };
                            if let Some(raw) = txn
                                .get_u64(txn.env().dbis().event_payload, lev)
                                .ok()
                                .flatten()
                            {
                                if let Ok(json) =
                                    decomp.decode(&txn, raw, cfg_snap.events.max_event_size)
                                {
                                    let recips = if let Some(recipients) = packed_recipients {
                                        recipients
                                    } else {
                                        let search_terms =
                                            wok_db::event_search_terms(json).unwrap_or_default();
                                        monitors.process(lev, packed, Some(&search_terms))
                                    };
                                    if recips.is_empty() {
                                        return true;
                                    }
                                    let filtered: Vec<(u64, SubId)> = recips
                                        .into_iter()
                                        .filter(|recip| {
                                            let pk =
                                                authed.get(&recip.conn_id).map(|a| a.as_slice());
                                            r.should_send_to_subscriber(packed, pk)
                                        })
                                        .map(|recip| (recip.conn_id, recip.sub_id))
                                        .collect();
                                    conns.send_event_batch(&filtered, json, &metrics);
                                }
                            }
                        }
                        true
                    });
                    curr_event_id = latest;
                }
                MonitorMsg::Ephemeral { packed, json } => {
                    if let Ok(packed) = PackedEventView::new(&packed) {
                        let search_terms = if monitors.requires_content() {
                            Some(wok_db::event_search_terms(&json).unwrap_or_default())
                        } else {
                            None
                        };
                        let recipients = monitors.process_ephemeral(packed, search_terms.as_ref());
                        let filtered: Vec<(u64, SubId)> = recipients
                            .into_iter()
                            .filter(|recipient| {
                                let pk = authed
                                    .get(&recipient.conn_id)
                                    .map(|authed| authed.as_slice());
                                r.should_send_to_subscriber(packed, pk)
                            })
                            .map(|recipient| (recipient.conn_id, recipient.sub_id))
                            .collect();
                        conns.send_event_batch(&filtered, &json, &metrics);
                    }
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
    let initial_cfg = cfg.read();
    let mut queries = QueryScheduler::new(
        initial_cfg.relay.abuse.max_concurrent_historical_queries,
        initial_cfg.relay.max_sync_events,
    );
    drop(initial_cfg);
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
        queries.set_max_subs_per_connection(cfg_snap.relay.abuse.max_concurrent_historical_queries);
        queries.set_max_total_events_per_req(cfg_snap.relay.max_sync_events);
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
                                metrics
                                    .abuse_query_concurrency_rejections
                                    .fetch_add(1, Ordering::Relaxed);
                                conns.send(
                                    conn,
                                    RelayMessage::NegErr {
                                        sub_id: sid,
                                        message:
                                            "rate-limited: too many concurrent historical queries"
                                                .into(),
                                        extra: None,
                                    },
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
            |sub, total, _hll| {
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
    let mut vanish_cursor = Vec::new();
    while !shutdown.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_secs(2));
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
        if let Ok(mut txn) = env.begin_rw() {
            let mut sink = DeferredSink::default();
            let expired_deleted = wok_db::delete_events(&mut txn, &mut sink, expired).unwrap_or(0);
            let vanished_deleted = sweep_vanished_events(
                &mut txn,
                &mut sink,
                cfg_snap.relay.nip62.deletion_batch_size,
                &mut vanish_cursor,
            )
            .unwrap_or(0);
            let mut cache = NegentropyFilterCache::new(cfg.read().relay.max_tags_per_filter);
            let _ = sink.apply(&mut cache, &mut txn);
            let _ = txn.commit();
            if expired_deleted > 0 || vanished_deleted > 0 {
                tracing::info!(
                    expired_deleted,
                    vanished_deleted,
                    "relay maintenance deleted events"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Keypair, SECP256K1};
    use wok_db::EnvOptions;
    use wok_event::{PackedEventBuilder, PackedEventTagBuilder};

    fn sign_event(ev: Value) -> Value {
        let mut rng = rand::thread_rng();
        let kp = Keypair::new(SECP256K1, &mut rng);
        sign_event_with_key(ev, &kp)
    }

    fn sign_event_with_key(mut ev: Value, kp: &Keypair) -> Value {
        let (xonly, _) = kp.x_only_public_key();
        ev["pubkey"] = json!(hex::encode(xonly.serialize()));
        let id = wok_event::event_id_hash(&ev).unwrap();
        ev["id"] = json!(hex::encode(id));
        let sig = SECP256K1.sign_schnorr(&id, kp);
        ev["sig"] = json!(hex::encode(sig.as_ref()));
        ev
    }

    async fn recv_outbound(rx: &mut tokio::sync::mpsc::UnboundedReceiver<OutboundFrame>) -> String {
        tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("outbound timeout")
            .expect("outbound closed")
            .into_text()
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    #[test]
    fn batch_vanish_markers_block_old_authored_events_and_all_gift_wraps() {
        let author = [1u8; 32];
        let mut markers = HashMap::new();
        markers.insert(author, 200);
        let tags = PackedEventTagBuilder::default();
        let old = PackedEventBuilder::build(&[2; 32], &author, 100, 1, 0, &tags).unwrap();
        let newer = PackedEventBuilder::build(&[3; 32], &author, 201, 1, 0, &tags).unwrap();
        let request =
            PackedEventBuilder::build(&[4; 32], &author, 200, VANISH_KIND, 0, &tags).unwrap();
        assert!(event_matches_vanish_markers(old.view(), &markers));
        assert!(!event_matches_vanish_markers(newer.view(), &markers));
        assert!(!event_matches_vanish_markers(request.view(), &markers));

        let mut gift_tags = PackedEventTagBuilder::default();
        gift_tags.add('p', &author).unwrap();
        let gift =
            PackedEventBuilder::build(&[5; 32], &[6; 32], 999, 21059, 0, &gift_tags).unwrap();
        assert!(event_matches_vanish_markers(gift.view(), &markers));
    }

    #[tokio::test]
    async fn outbound_byte_accounting_and_kill() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<OutboundFrame>();
        let out = Outbound::new(tx, 100);
        let killed = out.killed();

        assert_eq!(out.try_send("x".repeat(60)), Ok(()));
        assert_eq!(out.try_send("y".repeat(30)), Ok(()));
        // 60 + 30 + 20 > 100: over budget, rejected.
        assert_eq!(
            out.try_send("z".repeat(20)),
            Err(OutboundSendError::OverByteLimit)
        );

        // Draining one frame releases its bytes.
        drop(rx.recv().await.unwrap());
        assert_eq!(out.try_send("z".repeat(20)), Ok(()));

        // Kill notification reaches the transport.
        out.kill();
        tokio::time::timeout(Duration::from_secs(1), killed.notified())
            .await
            .expect("kill notification");

        // Limit 0 means unlimited.
        let (tx2, _rx2) = tokio::sync::mpsc::unbounded_channel::<OutboundFrame>();
        let out2 = Outbound::new(tx2, 0);
        for _ in 0..8 {
            assert_eq!(out2.try_send("q".repeat(1000)), Ok(()));
        }

        // The byte budget, not an incidental message count, bounds bursts.
        let (tx3, mut rx3) = tokio::sync::mpsc::unbounded_channel::<OutboundFrame>();
        let out3 = Outbound::new(tx3, 10_000);
        for _ in 0..500 {
            assert_eq!(out3.try_send("event".into()), Ok(()));
        }
        let mut received = 0;
        while rx3.try_recv().is_ok() {
            received += 1;
        }
        assert_eq!(received, 500);
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
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<OutboundFrame>();
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pow_policy_rejects_insufficient_event_ids() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::default()).unwrap();
        env.ensure_initialized().unwrap();
        let mut cfg = Config::default();
        cfg.db = dir.path().to_path_buf();
        cfg.relay.auth.enabled = false;
        cfg.relay.abuse.min_pow_difficulty = 255;
        let handle = start(env, cfg).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<OutboundFrame>();
        let conn = handle.next_conn_id();
        handle.register(conn, Outbound::new(tx, 0)).await;
        let event = sign_event(json!({
            "created_at": now_secs(), "kind": 1, "tags": [], "content": "no-pow"
        }));
        handle
            .client_message(
                conn,
                vec![127, 0, 0, 1],
                json!(["EVENT", event]).to_string(),
            )
            .await;
        let response = recv_outbound(&mut rx).await;
        assert!(response.contains("\"OK\"") && response.contains("false"));
        assert!(response.contains("pow: difficulty 255 required"));
        assert_eq!(
            handle.metrics.abuse_pow_rejections.load(Ordering::Relaxed),
            1
        );
        handle.request_shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn query_cost_is_rejected_before_scheduling() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::default()).unwrap();
        env.ensure_initialized().unwrap();
        let mut cfg = Config::default();
        cfg.db = dir.path().to_path_buf();
        cfg.relay.auth.enabled = false;
        cfg.relay.abuse.max_query_cost = 10;
        let handle = start(env, cfg).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<OutboundFrame>();
        let conn = handle.next_conn_id();
        handle.register(conn, Outbound::new(tx, 0)).await;
        handle
            .client_message(
                conn,
                vec![127, 0, 0, 1],
                json!(["REQ", "broad", {}]).to_string(),
            )
            .await;
        let response = recv_outbound(&mut rx).await;
        assert!(response.contains("\"CLOSED\"") && response.contains("query cost 1000"));
        assert_eq!(
            handle
                .metrics
                .abuse_query_cost_rejections
                .load(Ordering::Relaxed),
            1
        );
        handle.request_shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn default_private_read_fails_closed_until_auth_is_configured() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::default()).unwrap();
        env.ensure_initialized().unwrap();
        let mut cfg = Config::default();
        cfg.db = dir.path().to_path_buf();
        let handle = start(env, cfg).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<OutboundFrame>();
        let conn = handle.next_conn_id();
        handle.register(conn, Outbound::new(tx, 0)).await;
        handle
            .client_message(
                conn,
                vec![127, 0, 0, 1],
                json!(["REQ", "private", {"kinds":[1059]}]).to_string(),
            )
            .await;

        let challenge = recv_outbound(&mut rx).await;
        let closed = recv_outbound(&mut rx).await;
        assert!(challenge.contains("\"AUTH\""), "{challenge}");
        assert!(
            closed.contains("\"CLOSED\"") && closed.contains("auth-required"),
            "{closed}"
        );
        handle.request_shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn historical_query_concurrency_is_independent_from_live_subscription_limit() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::default()).unwrap();
        env.ensure_initialized().unwrap();
        let mut cfg = Config::default();
        cfg.db = dir.path().to_path_buf();
        cfg.relay.auth.enabled = false;
        cfg.relay.max_subs_per_connection = 200;
        cfg.relay.abuse.max_concurrent_historical_queries = 0;
        let handle = start(env, cfg).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<OutboundFrame>();
        let conn = handle.next_conn_id();
        handle.register(conn, Outbound::new(tx, 0)).await;
        handle
            .client_message(
                conn,
                vec![127, 0, 0, 1],
                json!(["REQ", "limited", {"kinds":[1]}]).to_string(),
            )
            .await;
        let response = recv_outbound(&mut rx).await;
        assert!(response.contains("\"CLOSED\"") && response.contains("concurrent historical"));
        assert_eq!(
            handle
                .metrics
                .abuse_query_concurrency_rejections
                .load(Ordering::Relaxed),
            1
        );
        handle.request_shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn author_storage_quota_is_enforced_by_the_single_writer() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::default()).unwrap();
        env.ensure_initialized().unwrap();
        let mut cfg = Config::default();
        cfg.db = dir.path().to_path_buf();
        cfg.relay.auth.enabled = false;
        cfg.relay.abuse.max_stored_events_per_pubkey = 1;
        let handle = start(env, cfg).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<OutboundFrame>();
        let conn = handle.next_conn_id();
        handle.register(conn, Outbound::new(tx, 0)).await;
        let mut rng = rand::thread_rng();
        let key = Keypair::new(SECP256K1, &mut rng);
        for content in ["first", "second"] {
            let event = sign_event_with_key(
                json!({
                    "created_at": now_secs(), "kind": 1, "tags": [], "content": content
                }),
                &key,
            );
            handle
                .client_message(
                    conn,
                    vec![127, 0, 0, 1],
                    json!(["EVENT", event]).to_string(),
                )
                .await;
            let response = recv_outbound(&mut rx).await;
            if content == "first" {
                assert!(response.contains("true"), "{response}");
            } else {
                assert!(response.contains("false") && response.contains("storage quota"));
            }
        }
        assert_eq!(
            handle
                .metrics
                .abuse_pubkey_quota_rejections
                .load(Ordering::Relaxed),
            1
        );
        handle.request_shutdown();
    }
}
