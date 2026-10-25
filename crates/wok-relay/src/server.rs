//! Relay process: ingest, writer, req, monitor, negentropy, cron.
//!
//! LMDB work stays on dedicated OS threads. Outbound messages are owned
//! `String`s sent over Tokio mpsc channels that never hold mmap borrows.

#![allow(clippy::too_many_arguments)]
#![allow(clippy::field_reassign_with_default)]

mod writer;
use writer::*;
mod sub_gate;
use sub_gate::{Current, Ns, SubGate};

use crate::abuse::{
    leading_zero_bits, AbuseController, Admission, BudgetKind, ConnectionBudgets, ConnectionSlot,
    Refusal, Request,
};
use crate::config::AccessPolicy;
use crate::config::{Config, EphemeralPersistence};
use crate::metrics::{Metrics, Setting};
use crate::moderation::{is_member, stored_is_member, ManagementCmd, WriteGrant};
use crate::plugin::{PluginEventSifter, PluginResult};
use crate::protocol::{
    has_reason_prefix, push_json_str, ClientCommand, EoseHints, ParseFailure, RelayMessage,
};
use crate::source::TransportSource;
use crate::supported_nips;
use crossbeam_channel::{bounded, unbounded, Receiver, Sender, TrySendError};
use parking_lot::Mutex;
use rand::Rng;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::Duration;
use wok_db::{
    backfill_vanish_markers, is_event_vanished_ro, load_moderation_snapshot_ro,
    lookup_event_by_id_ro, moderation_reason_ignoring_author_ro, moderation_reason_ro,
    most_recent_levid_ro, report_event, sweep_vanished_events, Decompressor, Env, EventToWrite,
    EventWriteStatus, ModerationSnapshot, SearchTermSet, MAX_MODERATION_RECORDS, MAX_REASON_BYTES,
    VANISH_KIND,
};
use wok_event::{
    parse_and_verify_event, to_hex, PackedEventView, AUTH_CHALLENGE_LEN, AUTH_KIND,
    GIFT_WRAP_KINDS, PROTECTED_TAG, REPOST_KINDS,
};
use wok_negentropy::{DeferredSink, NegentropyFilterCache};
mod negentropy;
use negentropy::run_negentropy;
use wok_query::{
    ActiveMonitors, CostedRequest, FilterValidator, HeldEvent, NostrFilterGroup, PendingBuffer,
    PendingEvent, QueryScheduler, Scheduled, SubId, Subscription,
};

const AUTH_ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const WRITER_BATCH_MAX: usize = 512;
/// How long an ingester with parked messages waits for worker capacity before
/// it looks at its own queue again.
const PARKED_RETRY_INTERVAL: Duration = Duration::from_millis(1);

/// A connection's ingress gate: `true` while its transport may hand the
/// ingester more messages. The ingester closes it while anything the
/// connection sent is parked behind a full worker queue.
type IngressGate = Arc<tokio::sync::watch::Sender<bool>>;

/// One frame queued for a connection. Dropping the frame (after a send, or
/// when a dead connection's queue is drained) releases its byte accounting.
pub struct OutboundFrame {
    pub text: String,
    len: u64,
    pending: Arc<AtomicU64>,
    /// For a subscription's EVENT or EOSE: its id's current generation, and
    /// the generation the frame belongs to.
    generation: Option<(Current, u64)>,
}

impl OutboundFrame {
    pub fn into_text(mut self) -> String {
        std::mem::take(&mut self.text)
    }

    /// True once the subscription generation this frame belongs to was
    /// replaced or closed while it waited in the queue. A transport skips it:
    /// the client no longer wants it.
    pub fn is_stale(&self) -> bool {
        self.generation
            .as_ref()
            .is_some_and(|(current, generation)| current.load(Ordering::Relaxed) != *generation)
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
    gate: IngressGate,
}

impl Outbound {
    pub fn new(tx: tokio::sync::mpsc::UnboundedSender<OutboundFrame>, limit: usize) -> Self {
        Self {
            tx,
            pending: Arc::new(AtomicU64::new(0)),
            limit,
            kill: Arc::new(tokio::sync::Notify::new()),
            gate: Arc::new(tokio::sync::watch::Sender::new(true)),
        }
    }

    fn try_send(
        &self,
        msg: String,
        generation: Option<(Current, u64)>,
    ) -> Result<(), OutboundSendError> {
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
                generation,
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

/// A connection's outbound queue and the gate in front of it.
struct ConnEntry {
    out: Outbound,
    /// Held while a frame is queued for the connection, together with the
    /// gate check that admits it.
    state: Mutex<ConnState>,
}

struct ConnState {
    subs: SubGate,
    /// The connection was removed, or terminated for a failed send: nothing
    /// more is queued for it, even by a producer that found it just before.
    gone: bool,
}

impl ConnState {
    /// Queue a frame, terminating the connection if it is over its
    /// pending-bytes budget (C++ slow-client termination).
    fn push(
        &mut self,
        out: &Outbound,
        payload: String,
        generation: Option<(Current, u64)>,
        metrics: &Metrics,
    ) {
        if let Err(error) = out.try_send(payload, generation) {
            if error == OutboundSendError::OverByteLimit {
                metrics
                    .slow_client_terminations
                    .fetch_add(1, Ordering::Relaxed);
                out.kill();
            }
            self.gone = true;
        }
    }
}

/// Connections are looked up in this many independently locked shards, so
/// producers working for different connections rarely meet on a lock.
const CONN_SHARDS: usize = 64;

type ConnShard = parking_lot::RwLock<HashMap<u64, Arc<ConnEntry>>>;

/// Every frame for a connection is queued under that connection's own lock,
/// which also guards its subscription gate (see `sub_gate`). So a subscription
/// frame is checked against its generation and queued in one step, ordered
/// against the ingester's REQ, COUNT, CLOSE and refusals, while frames for
/// other connections go ahead in parallel. A shard lock is only held to find
/// the connection, never while its own lock is taken.
struct ConnTable {
    shards: Box<[ConnShard]>,
}

impl ConnTable {
    fn new() -> Self {
        Self {
            shards: (0..CONN_SHARDS)
                .map(|_| parking_lot::RwLock::new(HashMap::new()))
                .collect(),
        }
    }

    fn shard(&self, id: u64) -> &ConnShard {
        &self.shards[id as usize % self.shards.len()]
    }

    fn entry(&self, id: u64) -> Option<Arc<ConnEntry>> {
        self.shard(id).read().get(&id).cloned()
    }

    fn insert(&self, id: u64, out: Outbound) {
        let entry = Arc::new(ConnEntry {
            out,
            state: Mutex::new(ConnState {
                subs: SubGate::default(),
                gone: false,
            }),
        });
        self.shard(id).write().insert(id, entry);
    }

    fn remove(&self, id: u64) {
        let entry = self.shard(id).write().remove(&id);
        if let Some(entry) = entry {
            entry.state.lock().gone = true;
        }
    }

    /// Run `f` under the connection's lock, unless it is gone. A connection
    /// that `f` terminated is dropped from the table afterwards.
    fn with<R>(&self, id: u64, f: impl FnOnce(&Outbound, &mut ConnState) -> R) -> Option<R> {
        let entry = self.entry(id)?;
        let mut state = entry.state.lock();
        if state.gone {
            return None;
        }
        let result = f(&entry.out, &mut state);
        let gone = state.gone;
        drop(state);
        if gone {
            self.shard(id).write().remove(&id);
        }
        Some(result)
    }

    /// Deliver a frame that belongs to no subscription (OK, NOTICE, AUTH,
    /// NEG-*), or a CLOSED for an id the relay never held.
    fn deliver(&self, conn_id: u64, payload: String, metrics: &Metrics) {
        self.with(conn_id, |out, state| {
            state.push(out, payload, None, metrics);
        });
    }

    fn send(&self, id: u64, msg: RelayMessage, metrics: &Metrics) {
        bump_relay_metrics(&msg, metrics);
        let json = msg.to_json();
        self.deliver(id, json, metrics);
    }

    /// The ingester admitted a REQ or COUNT with filters of `filter_bytes`
    /// serialized bytes: from now on only frames of `generation` pass for
    /// the id.
    fn open_sub(&self, conn_id: u64, ns: Ns, sub_id: &SubId, generation: u64, filter_bytes: usize) {
        self.with(conn_id, |_, state| {
            state.subs.open(ns, sub_id, generation, filter_bytes)
        });
    }

    /// CLOSE (no CLOSED owed). Returns the generation it closed, for the
    /// workers' cleanup.
    fn close_sub(&self, conn_id: u64, ns: Ns, sub_id: &SubId) -> Option<u64> {
        self.with(conn_id, |_, state| state.subs.close(ns, sub_id))
            .flatten()
    }

    /// Refuse a REQ or COUNT: close its id and queue the CLOSED in one step,
    /// so nothing for the id can follow it. Returns the generation it closed.
    fn refuse(
        &self,
        conn_id: u64,
        ns: Ns,
        sub_id: &str,
        reason: String,
        metrics: &Metrics,
    ) -> Option<u64> {
        let msg = RelayMessage::closed_error(sub_id, reason);
        bump_relay_metrics(&msg, metrics);
        let json = msg.to_json();
        let sub_id = SubId::new(sub_id).ok();
        self.with(conn_id, |out, state| {
            let closed = sub_id.and_then(|sub_id| state.subs.close(ns, &sub_id));
            state.push(out, json, None, metrics);
            closed
        })
        .flatten()
    }

    /// Open REQ subscriptions (pending or live) or COUNTs on a connection.
    fn open_count(&self, conn_id: u64, ns: Ns) -> usize {
        self.with(conn_id, |_, state| state.subs.len(ns))
            .unwrap_or(0)
    }

    fn is_open(&self, conn_id: u64, ns: Ns, sub_id: &SubId) -> bool {
        self.with(conn_id, |_, state| state.subs.is_open(ns, sub_id))
            .unwrap_or(false)
    }

    /// The filter bytes held by every open id in `ns` on a connection, and
    /// by `sub_id` alone.
    fn filter_bytes(&self, conn_id: u64, ns: Ns, sub_id: &SubId) -> (usize, usize) {
        self.with(conn_id, |_, state| state.subs.filter_bytes(ns, sub_id))
            .unwrap_or((0, 0))
    }

    /// Queue a frame of one generation of a subscription, if that generation
    /// is still current.
    fn push_sub(
        &self,
        conn_id: u64,
        ns: Ns,
        sub_id: &SubId,
        generation: u64,
        payload: String,
        metrics: &Metrics,
    ) -> bool {
        self.with(conn_id, |out, state| {
            let Some(current) = state.subs.admit(ns, sub_id, generation).cloned() else {
                return false;
            };
            state.push(out, payload, Some((current, generation)), metrics);
            true
        })
        .unwrap_or(false)
    }

    /// A subscription frame that the generation goes on after (EOSE).
    fn send_sub(
        &self,
        conn_id: u64,
        sub_id: &SubId,
        generation: u64,
        msg: RelayMessage,
        metrics: &Metrics,
    ) {
        let json = msg.to_json();
        if self.push_sub(conn_id, Ns::Req, sub_id, generation, json, metrics) {
            bump_relay_metrics(&msg, metrics);
        }
    }

    /// A generation's last frame (a CLOSED from a worker, a COUNT result):
    /// queued if the generation is current, which then ends.
    fn send_last(
        &self,
        conn_id: u64,
        ns: Ns,
        sub_id: &SubId,
        generation: u64,
        msg: RelayMessage,
        metrics: &Metrics,
    ) {
        let json = msg.to_json();
        self.with(conn_id, |out, state| {
            if state.subs.admit(ns, sub_id, generation).is_none() {
                return;
            }
            state.subs.close(ns, sub_id);
            bump_relay_metrics(&msg, metrics);
            state.push(out, json, None, metrics);
        });
    }

    /// Build the EVENT frame once (pre-sized) and queue it.
    fn send_event(
        &self,
        conn_id: u64,
        sub_id: &SubId,
        generation: u64,
        ev_json: &str,
        metrics: &Metrics,
    ) {
        if self.queue_event(conn_id, sub_id, generation, ev_json, metrics) {
            metrics.relay_event.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn queue_event(
        &self,
        conn_id: u64,
        sub_id: &SubId,
        generation: u64,
        ev_json: &str,
        metrics: &Metrics,
    ) -> bool {
        let sub = sub_id.as_str();
        let mut payload = String::with_capacity(sub.len() + ev_json.len() + 12);
        payload.push_str("[\"EVENT\",");
        push_json_str(&mut payload, sub);
        payload.push(',');
        payload.push_str(ev_json);
        payload.push(']');
        self.push_sub(conn_id, Ns::Req, sub_id, generation, payload, metrics)
    }

    /// One event for many subscriptions. The shared counter is bumped once,
    /// not once per frame, so monitors fanning out to many connections do
    /// not contend on it.
    fn send_event_batch(&self, recipients: &[(u64, SubId, u64)], ev_json: &str, metrics: &Metrics) {
        let queued = recipients
            .iter()
            .filter(|(conn, sub, generation)| {
                self.queue_event(*conn, sub, *generation, ev_json, metrics)
            })
            .count();
        if queued != 0 {
            metrics
                .relay_event
                .fetch_add(queued as u64, Ordering::Relaxed);
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
    /// In-memory copy of the NIP-86 moderation tables, refreshed by the
    /// writer thread after every management mutation.
    pub moderation: Arc<parking_lot::RwLock<ModerationSnapshot>>,
    shutdown: Arc<AtomicBool>,
    shutdown_notify: Arc<tokio::sync::Notify>,
    abuse: Arc<AbuseController>,
    config_path: Arc<parking_lot::RwLock<Option<std::path::PathBuf>>>,
    writer_tx: Sender<WriterMsg>,
    threads: Arc<RelayThreads>,
    /// Each connection's share of the ingest queue, in bytes: the largest
    /// message a transport accepts, as configured at start. A message larger
    /// than the share after a reload takes all of it.
    inbound_share: usize,
}

/// How long dropping the last `RelayHandle` waits for the relay threads.
const DROP_JOIN_TIMEOUT: Duration = Duration::from_secs(10);

/// The relay's OS threads, shared by every `RelayHandle` clone.
///
/// The threads, and this struct, own the only `Env` clones `start` makes.
/// LMDB closes the environment (and, on macOS, unlinks its two named POSIX
/// semaphores) only when the last clone drops, so a process that exits with
/// these threads still running leaks those semaphores until reboot. Explicit
/// `RelayHandle::shutdown_and_join`, or dropping the last handle, stops and
/// joins them first.
struct RelayThreads {
    shutdown: Arc<AtomicBool>,
    shutdown_notify: Arc<tokio::sync::Notify>,
    ingest: Vec<tokio::sync::mpsc::Sender<IngestMsg>>,
    writer_tx: Sender<WriterMsg>,
    running: Mutex<RunningThreads>,
    /// Released only once every thread is joined. A thread that read from
    /// LMDB clears its reader slot, in the environment's lock-file mapping,
    /// from a thread-local destructor after its closure returns. Were the
    /// last clone dropped by one exiting thread while another was still in
    /// that destructor, the close would unmap the slot under it (SIGSEGV).
    /// Joining waits for thread-local destructors.
    env: Mutex<Option<Env>>,
}

#[derive(Default)]
struct RunningThreads {
    ingesters: Vec<thread::JoinHandle<()>>,
    /// Every other stage; each exits on the shutdown flag, a `Stop`
    /// message, or once the ingesters and writer drop their senders.
    workers: Vec<thread::JoinHandle<()>>,
}

impl RelayThreads {
    fn stop_and_join(&self, timeout: Duration) -> Result<(), String> {
        let deadline = std::time::Instant::now() + timeout;
        // Held throughout so a concurrent caller returns only once the
        // threads are gone, not as soon as the first caller took them.
        let mut running = self.running.lock();
        self.shutdown.store(true, Ordering::Relaxed);
        self.shutdown_notify.notify_waiters();
        for h in &running.workers {
            h.thread().unpark();
        }
        for tx in &self.ingest {
            send_ingest_stop(tx, deadline);
        }
        let ingesters = join_until(std::mem::take(&mut running.ingesters), deadline);
        if ingesters.is_empty() {
            let _ = self.writer_tx.send_deadline(WriterMsg::Stop, deadline);
        }
        let workers = join_until(std::mem::take(&mut running.workers), deadline);
        running.ingesters = ingesters;
        running.workers = workers;
        if running.ingesters.is_empty() && running.workers.is_empty() {
            drop(self.env.lock().take());
            return Ok(());
        }
        let names: Vec<_> = running
            .ingesters
            .iter()
            .chain(&running.workers)
            .map(|h| h.thread().name().unwrap_or("?").to_string())
            .collect();
        Err(format!(
            "relay threads still running after {timeout:?}: {}",
            names.join(", ")
        ))
    }
}

impl RelayThreads {
    /// Stop and join the threads, waiting up to `timeout`. Threads still
    /// running then are handed to a `relay-join` thread together with the
    /// environment guard, which it releases only after joining them, so the
    /// environment is never closed while one of them is exiting. If that
    /// thread cannot start, the environment stays open.
    fn release(&mut self, timeout: Duration) {
        let Err(e) = self.stop_and_join(timeout) else {
            return;
        };
        tracing::warn!("{e}; their LMDB environment stays open until they exit");
        let running = std::mem::take(&mut *self.running.lock());
        let guard = Arc::new(Mutex::new(self.env.lock().take()));
        let held = guard.clone();
        let joiner = thread::Builder::new()
            .name("relay-join".into())
            .spawn(move || {
                for h in running.ingesters.into_iter().chain(running.workers) {
                    let _ = h.join();
                }
                drop(held.lock().take());
            });
        if joiner.is_err() {
            std::mem::forget(guard);
        }
    }
}

impl Drop for RelayThreads {
    fn drop(&mut self) {
        self.release(DROP_JOIN_TIMEOUT);
    }
}

/// Queue `Stop` without `blocking_send`, which panics inside a runtime.
fn send_ingest_stop(tx: &tokio::sync::mpsc::Sender<IngestMsg>, deadline: std::time::Instant) {
    let mut msg = IngestMsg::Stop;
    loop {
        match tx.try_send(msg) {
            Ok(()) | Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return,
            Err(tokio::sync::mpsc::error::TrySendError::Full(back)) => {
                if std::time::Instant::now() >= deadline {
                    return;
                }
                msg = back;
                thread::sleep(Duration::from_millis(1));
            }
        }
    }
}

/// Join every finished thread, polling until `deadline`; returns the rest.
fn join_until(
    mut pending: Vec<thread::JoinHandle<()>>,
    deadline: std::time::Instant,
) -> Vec<thread::JoinHandle<()>> {
    loop {
        let (done, rest): (Vec<_>, Vec<_>) = pending.into_iter().partition(|h| h.is_finished());
        for h in done {
            let name = h.thread().name().unwrap_or("?").to_string();
            if h.join().is_err() {
                tracing::error!(thread = %name, "relay thread panicked");
            }
        }
        pending = rest;
        if pending.is_empty() || std::time::Instant::now() >= deadline {
            return pending;
        }
        thread::sleep(Duration::from_millis(2));
    }
}

/// Sleep up to `total`, waking early once `shutdown` is set (the joiner
/// unparks waiting threads). Returns false on shutdown.
fn sleep_unless_shutdown(shutdown: &AtomicBool, total: Duration) -> bool {
    let deadline = std::time::Instant::now() + total;
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return false;
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            return true;
        }
        thread::park_timeout(deadline - now);
    }
}

pub enum IngestMsg {
    /// A connection registered; it precedes every `Client` message for it.
    Open {
        conn_id: u64,
        gate: Option<IngressGate>,
    },
    Client {
        conn_id: u64,
        source: TransportSource,
        payload: String,
        /// The connection's share of the ingest queue this message holds
        /// until it is handled.
        share: Option<tokio::sync::OwnedSemaphorePermit>,
    },
    Close {
        conn_id: u64,
    },
    /// Sent only by `RelayThreads::stop_and_join`: the ingester exits even
    /// though transports still hold `RelayHandle` clones (and so senders).
    Stop,
}

enum WriterMsg {
    Maintenance,
    AddEvent {
        conn_id: u64,
        source: TransportSource,
        packed: Vec<u8>,
        json: String,
        authed: Option<[u8; 32]>,
        /// What admitted the event under `relay.auth.write_policy`, which
        /// the writer checks again against committed moderation state.
        grant: WriteGrant,
    },
    Close {
        conn_id: u64,
    },
    /// NIP-86 mutation plus the reply channel for the HTTP handler. Runs on
    /// the single writer thread so the LMDB change and the snapshot refresh
    /// are ordered against event writes.
    Management(ManagementMsg),
    /// Sent only by `RelayThreads::stop_and_join`, after every ingester has
    /// exited, so all events they forwarded are already queued ahead of it.
    /// The cron thread and `RelayHandle` clones keep the channel open.
    Stop,
}

pub struct ManagementMsg {
    pub cmd: ManagementCmd,
    pub reply: tokio::sync::oneshot::Sender<Result<(), String>>,
}

enum ReqMsg {
    /// Send a REQ's history up to the snapshot fixed at admission. Its
    /// `MonitorMsg::Register` is already queued on the req monitor, so the
    /// scan's `HistoryDone` cannot reach the monitor first.
    Scan(Subscription),
    /// Answer a COUNT. COUNT ids are separate from REQ ids.
    Count(Subscription),
    SetAuth {
        conn_id: u64,
        authed: [u8; 32],
    },
    /// Stop this generation's REQ history scan or COUNT, after CLOSE, a
    /// refusal or a replacement the client no longer waits for. Cleanup only:
    /// the subscription gate already drops anything it would still send.
    Cancel {
        conn_id: u64,
        sub_id: SubId,
        generation: u64,
        count_only: bool,
    },
    Close {
        conn_id: u64,
    },
}

/// Subscription changes for a req monitor, on its control queue. The queue
/// is unbounded so a REQ's registration is queued the moment it is admitted
/// and never waits behind live traffic. Each turn the monitor takes what is in
/// its data queue, then what is in this one, and applies these first: so any
/// event sent after a registration is matched against it, however full the
/// data queue was. Every message here is paired with work the bounded req
/// worker queues pace, so the queue grows only while a monitor turn runs.
enum MonitorMsg {
    /// An admitted REQ. The monitor matches it at once but holds matches back
    /// until `HistoryDone`. It replaces any subscription with the same id.
    Register(Subscription),
    /// Stop matching this generation of the subscription, if it is the one
    /// registered: after CLOSE, a refusal, or a REQ the worker could not
    /// start. Cleanup only, like `ReqMsg::Cancel`.
    Remove {
        conn_id: u64,
        sub_id: SubId,
        generation: u64,
    },
    /// The req worker sent this generation's history, up to the snapshot
    /// `snapshot`. The monitor sends EOSE, with the history's NIP-67 `hints`,
    /// and what it held back, then delivers live.
    HistoryDone {
        conn_id: u64,
        sub_id: SubId,
        generation: u64,
        snapshot: u64,
        hints: EoseHints,
    },
    SetAuth {
        conn_id: u64,
        authed: [u8; 32],
    },
    Close {
        conn_id: u64,
    },
}

/// What a req monitor matches, on its bounded data queue.
enum MonitorData {
    /// Events were stored that the monitor may not have been handed: match
    /// everything newer than what it matched, read from LMDB.
    DbChange,
    /// Events the writer just committed, shared by every monitor.
    Stored(Arc<StoredBatch>),
    /// A live-only event, shared by every monitor.
    Ephemeral(Arc<HeldEvent>),
}

/// The events one writer commit stored, handed to the req monitors as they
/// were written, so that no monitor reads them back from LMDB.
struct StoredBatch {
    /// The commit stored local event ids `first..=last`, every one of them
    /// in `events`, in order.
    first: u64,
    last: u64,
    events: Vec<StoredEvent>,
    /// This batch's share of the writer's hand-off budget, returned when the
    /// last monitor drops it.
    bytes: usize,
    in_flight: Arc<AtomicUsize>,
}

impl Drop for StoredBatch {
    fn drop(&mut self) {
        self.in_flight.fetch_sub(self.bytes, Ordering::Relaxed);
    }
}

struct StoredEvent {
    lev_id: u64,
    packed: Vec<u8>,
    /// The stored payload, as the writer stored it.
    json: String,
    /// Tokenized once, by the first monitor with a search filter it may match.
    /// Whether the event is still stored and visible depends on each
    /// monitor's read, so every monitor checks that itself.
    search_terms: OnceLock<SearchTermSet>,
}

/// Most bytes of committed events handed to the req monitors that a monitor
/// still holds. Past it the writer sends `DbChange` instead and the monitors
/// read the commit from LMDB, so a monitor that falls behind holds no more
/// than this.
const STORED_HANDOFF_BYTES: usize = 16 << 20;

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
    /// Drop the session and send NEG-ERR from the worker, so the error is
    /// ordered after every NEG-MSG the worker already produced for it.
    Fail {
        conn_id: u64,
        sub_id: SubId,
        message: String,
    },
    Close {
        conn_id: u64,
    },
}

struct AuthSession {
    challenge: String,
    authed: Option<[u8; 32]>,
    identities: Vec<[u8; 32]>,
}

/// The most messages one connection may have waiting for the ingester.
const MAX_QUEUED_MESSAGES: u32 = 64;

/// A connection's share of the ingest queue: the bytes of its messages handed
/// to the ingester and not yet handled. A message waits for its share before
/// it is queued, so one connection never has more than the largest message
/// the relay accepts waiting for an ingester, however small the messages.
#[derive(Clone)]
struct InboundShare {
    permits: Arc<tokio::sync::Semaphore>,
    limit: u32,
}

impl InboundShare {
    fn new(limit: usize) -> Self {
        let limit = u32::try_from(limit.max(1)).unwrap_or(u32::MAX);
        Self {
            permits: Arc::new(tokio::sync::Semaphore::new(limit as usize)),
            limit,
        }
    }

    /// The share a message of `len` bytes takes: all of it, if larger, and
    /// at least `1 / MAX_QUEUED_MESSAGES` of it, so however small its
    /// messages a connection takes few of the ingest queue's slots.
    fn cost(&self, len: usize) -> u32 {
        let floor = (self.limit / MAX_QUEUED_MESSAGES).max(1);
        u32::try_from(len)
            .unwrap_or(u32::MAX)
            .clamp(floor, self.limit)
    }

    /// Wait until `len` bytes fit in the share, and hold them until the
    /// returned permit drops.
    async fn acquire(&self, len: usize) -> tokio::sync::OwnedSemaphorePermit {
        self.permits
            .clone()
            .acquire_many_owned(self.cost(len))
            .await
            .expect("an inbound share is never closed")
    }

    /// The share for `len` bytes, if it has room now.
    fn try_acquire(&self, len: usize) -> Option<tokio::sync::OwnedSemaphorePermit> {
        self.permits
            .clone()
            .try_acquire_many_owned(self.cost(len))
            .ok()
    }
}

/// Owns one relay registration and guarantees transport cleanup on every exit
/// path, including task cancellation.
pub struct ConnectionGuard {
    handle: RelayHandle,
    conn_id: u64,
    source: TransportSource,
    gate: IngressGate,
    inbound: InboundShare,
    closed: bool,
}

impl ConnectionGuard {
    pub const fn conn_id(&self) -> u64 {
        self.conn_id
    }

    pub fn source(&self) -> &TransportSource {
        &self.source
    }

    /// Hand a message to the ingester. This waits for the connection's share
    /// of the ingest queue and for room in it, never on the ingress gate: a
    /// transport checks `ingress_paused` itself, so a paused connection keeps
    /// writing, pinging and handling control frames.
    pub async fn client_message(&self, payload: String) {
        let share = self.inbound.acquire(payload.len()).await;
        self.queue(payload, share).await;
    }

    /// True while earlier messages from this connection are parked behind a
    /// full worker queue. The transport keeps reading, so Close, EOF and
    /// control frames still arrive, but `receive` holds client messages until
    /// `ingress_resumed`.
    pub fn ingress_paused(&self) -> bool {
        !*self.gate.borrow()
    }

    /// Resolves once the connection may hand over messages again. Cancel-safe.
    pub async fn ingress_resumed(&self) {
        let _ = self.gate.subscribe().wait_for(|open| *open).await;
    }

    /// Resolves once ingress is paused. Cancel-safe. A transport that stopped
    /// reading to drain an over-limit hold waits on this to start again.
    pub async fn ingress_pauses(&self) {
        let _ = self.gate.subscribe().wait_for(|open| !*open).await;
    }

    /// True while the transport should stop reading: ingress is open and
    /// messages queued behind the hold have taken it past its limit, so the
    /// `ingress_resumed` arm hands it over first. While paused the transport
    /// always reads, and the hold's limit decides what it takes.
    pub fn draining(&self, held: &HeldMessages) -> bool {
        held.over_limit() && !self.ingress_paused()
    }

    /// Pass a message read from the client to the ingester, after anything
    /// already held. While ingress is paused it is held instead. False when
    /// the hold is full: the client kept sending into a paused connection and
    /// the transport should disconnect it.
    ///
    /// While ingress is open, a message read while anything is still held,
    /// or while the connection's share of the ingest queue has no room for
    /// it, is held behind, whatever the limit: only the transport's `ready`
    /// arm hands the hold over, a batch per pass, so the transport gets back
    /// to its outbound traffic in between. The transport stops reading while
    /// `draining`, which bounds it.
    #[must_use]
    pub async fn receive(&self, held: &mut HeldMessages, text: String, wire_len: usize) -> bool {
        if self.ingress_paused() {
            return held.push(text, wire_len);
        }
        if held.is_empty() {
            if let Some(share) = self.inbound.try_acquire(text.len()) {
                match self.try_queue(text, share) {
                    Ok(()) => return true,
                    Err(text) => {
                        held.push_back(text, wire_len);
                        return true;
                    }
                }
            }
        }
        held.push_back(text, wire_len);
        true
    }

    /// Resolves once the first held message, `front` bytes long, can be
    /// handed over: ingress is open, the connection's share has room for it
    /// and its ingester's queue has a slot. Cancel-safe. Only the transport
    /// takes from its share, so that room stays until `hand_over` takes it;
    /// another connection may take the slot first, and `hand_over` then
    /// leaves the message held for the next `ready`.
    pub async fn ready(&self, front: Option<usize>) {
        self.ingress_resumed().await;
        if let Some(len) = front {
            drop(self.inbound.acquire(len).await);
            drop(self.handle.ingest_route(self.conn_id).reserve().await);
        }
    }

    /// Hand held messages to the ingester, in order, while ingress is not
    /// paused and the connection's share has room. At most `HAND_OVER_BATCH`
    /// per call, so a transport that calls this from its `select!` gets back
    /// to its outbound traffic in between.
    pub async fn hand_over(&self, held: &mut HeldMessages) {
        for _ in 0..HAND_OVER_BATCH {
            if self.ingress_paused() {
                break;
            }
            let Some(share) = held
                .front_len()
                .and_then(|len| self.inbound.try_acquire(len))
            else {
                break;
            };
            let (text, cost) = held.queue.pop_front().expect("a held message");
            if let Err(text) = self.try_queue(text, share) {
                held.queue.push_front((text, cost));
                break;
            }
            held.bytes -= cost;
        }
    }

    /// Hand over everything held while ingress is open, waiting for the
    /// share as it frees: what a closing client sent before it closed still
    /// reaches the ingester. Messages held behind a pause are left, as the
    /// close drops the parked work ahead of them.
    pub async fn hand_over_rest(&self, held: &mut HeldMessages) {
        while !self.ingress_paused() {
            let Some(len) = held.front_len() else {
                break;
            };
            let share = self.inbound.acquire(len).await;
            let (text, cost) = held.queue.pop_front().expect("a held message");
            held.bytes -= cost;
            self.queue(text, share).await;
        }
    }

    async fn queue(&self, text: String, share: tokio::sync::OwnedSemaphorePermit) {
        self.handle
            .queue_client_message(self.conn_id, self.source.clone(), text, Some(share))
            .await;
    }

    /// Queue a message if the ingester's queue has a slot now; otherwise give
    /// it back, releasing its share, for the caller to hold.
    fn try_queue(
        &self,
        text: String,
        share: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<(), String> {
        use tokio::sync::mpsc::error::TrySendError;
        let message = IngestMsg::Client {
            conn_id: self.conn_id,
            source: self.source.clone(),
            payload: text,
            share: Some(share),
        };
        match self.handle.ingest_route(self.conn_id).try_send(message) {
            // A closed queue means the relay is stopping: nothing will read it.
            Ok(()) | Err(TrySendError::Closed(_)) => Ok(()),
            Err(TrySendError::Full(IngestMsg::Client { payload, .. })) => Err(payload),
            Err(TrySendError::Full(_)) => unreachable!("a client message"),
        }
    }

    /// Cancellation covers the entire transport future, including writes and
    /// ingress backpressure. The caller then closes this guard exactly once.
    pub async fn run_until_cancelled<F: std::future::Future>(
        &self,
        killed: &tokio::sync::Notify,
        io: F,
    ) -> Option<F::Output> {
        let shutdown = self.handle.shutdown_handle();
        let shutdown_wait = shutdown.notified();
        tokio::pin!(shutdown_wait);
        shutdown_wait.as_mut().enable();
        if self.handle.is_shutdown() {
            return None;
        }
        tokio::select! {
            biased;
            _ = killed.notified() => None,
            _ = shutdown_wait => None,
            result = io => Some(result),
        }
    }

    pub async fn close(mut self) {
        self.handle.finish_connection(self.conn_id).await;
        self.closed = true;
    }
}

/// Memory charged per held message on top of its payload, so that empty or
/// tiny messages still use up the hold.
pub const HELD_MESSAGE_OVERHEAD: usize = 64;
const HAND_OVER_BATCH: usize = 64;

/// Client messages a transport has read but not yet handed to the ingester,
/// because the connection's ingress is paused or, once it resumes, because
/// they are handed over a batch at a time.
/// Each costs its wire payload length plus `HELD_MESSAGE_OVERHEAD`. Reading
/// continues while paused, so control frames and disconnects are still seen;
/// a data message that would take the hold past its limit while paused means
/// the client keeps sending into a stalled relay, and the transport ends the
/// connection.
pub struct HeldMessages {
    queue: VecDeque<(String, usize)>,
    bytes: usize,
    limit: usize,
}

impl HeldMessages {
    pub fn new(limit: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            bytes: 0,
            limit,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// The length of the first held message.
    pub fn front_len(&self) -> Option<usize> {
        self.queue.front().map(|(text, _)| text.len())
    }

    fn over_limit(&self) -> bool {
        self.bytes > self.limit
    }

    /// Hold a message whose payload was `wire_len` bytes on the wire. A single
    /// message is always held; otherwise false, and nothing is held, when the
    /// limit would be exceeded.
    #[must_use]
    pub fn push(&mut self, text: String, wire_len: usize) -> bool {
        let cost = wire_len.saturating_add(HELD_MESSAGE_OVERHEAD);
        if !self.queue.is_empty() && self.bytes.saturating_add(cost) > self.limit {
            return false;
        }
        self.push_back(text, wire_len);
        true
    }

    /// Queue a message behind what is held, regardless of the limit.
    fn push_back(&mut self, text: String, wire_len: usize) {
        let cost = wire_len.saturating_add(HELD_MESSAGE_OVERHEAD);
        self.bytes += cost;
        self.queue.push_back((text, cost));
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        let handle = self.handle.clone();
        let conn_id = self.conn_id;
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                handle.finish_connection(conn_id).await;
            });
        } else {
            handle.conns.remove(conn_id);
            handle
                .metrics
                .active_connections
                .fetch_sub(1, Ordering::Relaxed);
            let _ = handle
                .ingest_route(conn_id)
                .try_send(IngestMsg::Close { conn_id });
        }
    }
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

    pub async fn register_connection(
        &self,
        source: TransportSource,
        out: Outbound,
    ) -> ConnectionGuard {
        let conn_id = self.next_conn_id();
        let gate = out.gate.clone();
        self.conns.insert(conn_id, out);
        self.metrics
            .active_connections
            .fetch_add(1, Ordering::Relaxed);
        // Build the guard before waiting on ingress, so cancelling here still
        // runs its cleanup.
        let guard = ConnectionGuard {
            handle: self.clone(),
            conn_id,
            source,
            gate: gate.clone(),
            inbound: InboundShare::new(self.inbound_share),
            closed: false,
        };
        let gate = Some(gate);
        let _ = self
            .ingest_route(conn_id)
            .send(IngestMsg::Open { conn_id, gate })
            .await;
        guard
    }

    /// Apply the connection-opening budget before transport registration.
    pub fn admit_connection(&self, source: &TransportSource) -> bool {
        if let Some(ip) = source.ip() {
            let rendered = ip.to_string();
            if self.moderation.read().blocked_ips.contains_key(&rendered) {
                self.metrics
                    .abuse_connection_rejections
                    .fetch_add(1, Ordering::Relaxed);
                return false;
            }
        }
        let cfg = self.config.read();
        let admitted = self
            .abuse
            .admit_source(source, BudgetKind::Connection, &cfg.relay.abuse);
        if !admitted {
            self.metrics
                .abuse_connection_rejections
                .fetch_add(1, Ordering::Relaxed);
            self.metrics.refused(Setting::ConnectionBurst);
        }
        admitted
    }

    /// Count a connection against its address's
    /// `relay.abuse.max_connections_per_address` while the returned slot
    /// lives: a transport takes it before it upgrades and keeps it until the
    /// connection ends. `None` when the address already holds that many.
    pub fn hold_connection(&self, source: &TransportSource) -> Option<ConnectionSlot> {
        let slot = self
            .abuse
            .hold_connection(source, &self.config.read().relay.abuse);
        if slot.is_none() {
            self.metrics.refused(Setting::MaxConnectionsPerAddress);
        }
        slot
    }

    /// Apply a NIP-86 management mutation on the writer thread and wait for
    /// the LMDB commit plus in-memory snapshot refresh.
    pub async fn manage(&self, cmd: ManagementCmd) -> Result<(), String> {
        let (reply, rx) = tokio::sync::oneshot::channel();
        self.writer_tx
            .try_send(WriterMsg::Management(ManagementMsg { cmd, reply }))
            .map_err(|_| "relay writer queue is full".to_string())?;
        rx.await
            .map_err(|_| "relay writer shut down before replying".to_string())?
    }

    /// Close or reopen a connection's ingress gate, as parking behind a
    /// stalled worker would. For transport tests.
    #[doc(hidden)]
    pub fn set_ingress_paused(&self, conn_id: u64, paused: bool) {
        if let Some(entry) = self.conns.entry(conn_id) {
            entry.out.gate.send_replace(!paused);
        }
    }

    /// Deliver a client message. Transports go through `ConnectionGuard`,
    /// whose ingress gate keeps what they leave parked behind a full worker
    /// bounded.
    pub async fn client_message(&self, conn_id: u64, source: TransportSource, payload: String) {
        self.queue_client_message(conn_id, source, payload, None)
            .await;
    }

    async fn queue_client_message(
        &self,
        conn_id: u64,
        source: TransportSource,
        payload: String,
        share: Option<tokio::sync::OwnedSemaphorePermit>,
    ) {
        let _ = self
            .ingest_route(conn_id)
            .send(IngestMsg::Client {
                conn_id,
                source,
                payload,
                share,
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

    async fn finish_connection(&self, conn_id: u64) {
        self.close(conn_id).await;
        self.metrics
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);
    }

    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    /// Stop accepting new connections. Relay threads keep serving existing
    /// connections until `shutdown_and_join` or the last handle drops.
    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.shutdown_notify.notify_waiters();
    }

    /// Request shutdown, stop every relay thread (even while other handle
    /// clones and connections remain), and wait up to `timeout` for them to
    /// exit. On `Ok`, the relay holds no `Env` clone, so the environment
    /// closes once the caller drops its own. Blocks the calling thread (from
    /// async code, prefer `spawn_blocking`). Idempotent.
    ///
    /// Without this, a process can exit while the threads still hold the
    /// `Env`; on macOS that leaks LMDB's POSIX semaphores until reboot (see
    /// docs/production-deployment.md).
    pub fn shutdown_and_join(&self, timeout: Duration) -> Result<(), String> {
        self.threads.stop_and_join(timeout)
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
    if let Some(error) = config.serving_error() {
        return Err(error);
    }
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
    let inbound_share = config
        .relay
        .max_websocket_payload_size
        .max(config.relay.unix.max_frame_bytes);
    let config = Arc::new(parking_lot::RwLock::new(config));
    let conns = Arc::new(ConnTable::new());
    let metrics = Arc::new(Metrics::default());
    // The history thread's first wake runs here, so the first sample and
    // refusal mark are kept by the time `start` returns, however soon the
    // relay is stopped.
    let first_wake = metrics_history_wake(&config, &metrics, None);
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_notify = Arc::new(tokio::sync::Notify::new());
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
        .map(|_| unbounded::<MonitorMsg>())
        .unzip();
    let (mon_data_txs, mon_data_rxs): (Vec<_>, Vec<_>) = (0..n_req_monitor)
        .map(|_| bounded::<MonitorData>(4096))
        .unzip();
    let (neg_txs, neg_rxs): (Vec<_>, Vec<_>) =
        (0..n_negentropy).map(|_| bounded::<NegMsg>(4096)).unzip();

    let moderation = Arc::new(parking_lot::RwLock::new(
        env.begin_ro()
            .and_then(|txn| load_moderation_snapshot_ro(&txn))
            .map_err(|e| format!("NIP-86 moderation load failed: {e}"))?,
    ));

    let handle = RelayHandle {
        ingest: ingest_txs.clone(),
        conns: conns.clone(),
        next_id: Arc::new(AtomicU64::new(1)),
        metrics: metrics.clone(),
        config: config.clone(),
        moderation: moderation.clone(),
        shutdown: shutdown.clone(),
        shutdown_notify: shutdown_notify.clone(),
        abuse: abuse.clone(),
        config_path: Arc::new(parking_lot::RwLock::new(None)),
        writer_tx: writer_tx.clone(),
        inbound_share,
        threads: Arc::new(RelayThreads {
            shutdown: shutdown.clone(),
            shutdown_notify: shutdown_notify.clone(),
            ingest: ingest_txs.clone(),
            writer_tx: writer_tx.clone(),
            running: Mutex::new(RunningThreads::default()),
            env: Mutex::new(Some(env.clone())),
        }),
    };
    // Registered as each thread spawns, for `RelayThreads::stop_and_join`.
    let ingester = |h| handle.threads.running.lock().ingesters.push(h);
    let worker = |h| handle.threads.running.lock().workers.push(h);

    for (i, ingest_rx) in ingest_rxs.into_iter().enumerate() {
        let env = env.clone();
        let cfg = config.clone();
        let conns = conns.clone();
        let metrics = metrics.clone();
        let writer_tx = writer_tx.clone();
        let req_txs = req_txs.clone();
        let mon_txs = mon_txs.clone();
        let neg_txs = neg_txs.clone();
        let abuse = abuse.clone();
        let moderation = moderation.clone();
        thread::Builder::new()
            .name(format!("ingester-{i}"))
            .spawn(move || {
                run_ingester(
                    env, cfg, conns, metrics, abuse, moderation, ingest_rx, writer_tx, req_txs,
                    mon_txs, neg_txs,
                )
            })
            .map(ingester)
            .map_err(|e| e.to_string())?;
    }
    {
        let cfg = config.clone();
        let metrics = metrics.clone();
        let shutdown = shutdown.clone();
        thread::Builder::new()
            .name("metrics-history".into())
            .spawn(move || run_metrics_history(cfg, metrics, shutdown, first_wake))
            .map(worker)
            .map_err(|e| e.to_string())?;
    }
    {
        let env = env.clone();
        let cfg = config.clone();
        let conns = conns.clone();
        let metrics = metrics.clone();
        let mon_data_txs = mon_data_txs.clone();
        let moderation = moderation.clone();
        thread::Builder::new()
            .name("writer".into())
            .spawn(move || {
                run_writer(
                    env,
                    cfg,
                    conns,
                    metrics,
                    writer_rx,
                    mon_data_txs,
                    moderation,
                    TAG_KIND_STEP,
                )
            })
            .map(worker)
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
            .map(worker)
            .map_err(|e| e.to_string())?;
    }
    for (i, (mon_rx, data_rx)) in mon_rxs.into_iter().zip(mon_data_rxs).enumerate() {
        let env = env.clone();
        let cfg = config.clone();
        let conns = conns.clone();
        let metrics = metrics.clone();
        let moderation = moderation.clone();
        thread::Builder::new()
            .name(format!("req-monitor-{i}"))
            .spawn(move || run_req_monitor(env, cfg, conns, metrics, moderation, mon_rx, data_rx))
            .map(worker)
            .map_err(|e| e.to_string())?;
    }
    let sync_memory = Arc::new(negentropy::MemoryPool::default());
    for (i, neg_rx) in neg_rxs.into_iter().enumerate() {
        let sync_memory = sync_memory.clone();
        let env = env.clone();
        let cfg = config.clone();
        let conns = conns.clone();
        let metrics = metrics.clone();
        thread::Builder::new()
            .name(format!("negentropy-{i}"))
            .spawn(move || run_negentropy(env, cfg, conns, metrics, neg_rx, sync_memory))
            .map(worker)
            .map_err(|e| e.to_string())?;
    }
    {
        let shutdown = shutdown.clone();
        thread::Builder::new()
            .name("cron".into())
            .spawn(move || run_cron(writer_tx, shutdown))
            .map(worker)
            .map_err(|e| e.to_string())?;
    }

    {
        let env = env.clone();
        let shutdown = shutdown.clone();
        thread::Builder::new()
            .name("db-watch".into())
            .spawn(move || run_db_watch(env, mon_data_txs, shutdown))
            .map(worker)
            .map_err(|e| e.to_string())?;
    }

    let _ = writer_tx;
    Ok(handle)
}

/// The history thread, from the wake `start` ran for it: sleep, then wake
/// again, until the relay stops.
fn run_metrics_history(
    cfg: Arc<parking_lot::RwLock<Config>>,
    metrics: Arc<Metrics>,
    shutdown: Arc<AtomicBool>,
    (mut last_sample, mut wait): (std::time::Instant, Duration),
) {
    while sleep_unless_shutdown(&shutdown, wait) {
        (last_sample, wait) = metrics_history_wake(&cfg, &metrics, Some(last_sample));
    }
}

/// One wake of the history thread: apply the history settings, take a
/// sample if one is due, and keep a refusal mark. Returns when the last
/// sample was taken and how long to sleep.
fn metrics_history_wake(
    cfg: &parking_lot::RwLock<Config>,
    metrics: &Metrics,
    last_sample: Option<std::time::Instant>,
) -> (std::time::Instant, Duration) {
    let observability = cfg.read().observability.clone();
    metrics.history.configure(
        observability.history_enabled,
        observability.history_max_points,
    );
    let interval = Duration::from_secs(observability.history_interval_secs.max(1));
    let now = std::time::Instant::now();
    let last_sample = match last_sample {
        Some(last) if now < last + interval => last,
        _ => {
            if observability.history_enabled && observability.history_max_points > 0 {
                metrics.record_history();
            }
            now
        }
    };
    // The dashboard's refusal counts cover the last day whatever the
    // history keeps or how far apart its samples are.
    let unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    metrics.refusals.mark(unix);
    let wait = history_wait(last_sample, interval, std::time::Instant::now());
    (last_sample, wait)
}

/// The history thread wakes at least this often, so refusal marks stay
/// hourly whatever `observability.history_interval_secs` is.
const REFUSAL_MARK_TICK: Duration = Duration::from_secs(60);

/// How long the history thread sleeps: until its next sample, at most
/// [`REFUSAL_MARK_TICK`].
fn history_wait(
    last_sample: std::time::Instant,
    interval: Duration,
    now: std::time::Instant,
) -> Duration {
    (last_sample + interval)
        .saturating_duration_since(now)
        .min(REFUSAL_MARK_TICK)
}

/// Broadcast a database-change notification to every req-monitor thread.
fn broadcast_db_change(mon_txs: &[Sender<MonitorData>]) {
    for tx in mon_txs {
        let _ = tx.send(MonitorData::DbChange);
    }
}

fn broadcast_ephemeral(mon_txs: &[Sender<MonitorData>], event: HeldEvent) {
    let event = Arc::new(event);
    for tx in mon_txs {
        let _ = tx.send(MonitorData::Ephemeral(event.clone()));
    }
}

/// Hand the events a commit wrote to every req monitor, taking them out of
/// `events`. Over the hand-off budget, or for ids it cannot vouch for, it
/// sends `DbChange` instead.
fn broadcast_stored<C>(
    mon_txs: &[Sender<MonitorData>],
    in_flight: &Arc<AtomicUsize>,
    events: &mut Vec<EventToWrite<C>>,
) {
    // Ids are allocated in write order, one per written event.
    let stored: Vec<StoredEvent> = events
        .drain(..)
        .filter(|event| event.status == EventWriteStatus::Written)
        .map(|event| StoredEvent {
            lev_id: event.lev_id,
            packed: event.packed,
            json: event.json,
            search_terms: OnceLock::new(),
        })
        .collect();
    let (Some(first), Some(last)) = (stored.first(), stored.last()) else {
        return;
    };
    let (first, last) = (first.lev_id, last.lev_id);
    let bytes = stored
        .iter()
        .map(|event| event.packed.len() + event.json.len())
        .sum::<usize>();
    let contiguous = last.checked_sub(first) == Some(stored.len() as u64 - 1);
    if !contiguous || in_flight.load(Ordering::Relaxed).saturating_add(bytes) > STORED_HANDOFF_BYTES
    {
        broadcast_db_change(mon_txs);
        return;
    }
    in_flight.fetch_add(bytes, Ordering::Relaxed);
    let batch = Arc::new(StoredBatch {
        first,
        last,
        events: stored,
        bytes,
        in_flight: in_flight.clone(),
    });
    for tx in mon_txs {
        let _ = tx.send(MonitorData::Stored(batch.clone()));
    }
}

/// Watch data.mdb for changes made by compatible Wok maintenance commands
/// and poke the req-monitor. strfry must never write a Wok database. Like
/// RelayReqMonitor's hoytech::file_change_monitor (100ms debounce). Polling
/// is used for portability; semantics match.
fn run_db_watch(env: Env, mon_txs: Vec<Sender<MonitorData>>, shutdown: Arc<AtomicBool>) {
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
    while sleep_unless_shutdown(&shutdown, Duration::from_millis(100)) {
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

fn filter_validator(cfg: &Config) -> FilterValidator {
    let mut allowed = std::collections::HashSet::new();
    for p in cfg.relay.filter_validation.allowed_kinds.split(',') {
        if let Ok(n) = p.trim().parse() {
            allowed.insert(n);
        }
    }
    FilterValidator {
        max_kinds_per_filter: cfg.relay.filter_validation.max_kinds_per_filter,
        allowed_kinds: allowed,
        require_author_or_tag: cfg.relay.filter_validation.require_author_or_tag,
        require_scoped_filters: cfg.relay.filter_validation.require_scoped_filters,
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

/// One worker queue as an ingester sees it. A full queue never blocks the
/// ingester: the message is parked, and so is every later one for that worker
/// until the backlog drains, which keeps per-worker (and so per-connection)
/// order. Parked messages, protocol CLOSE and NEG-CLOSE included, are only
/// dropped when their connection closes: see `Lane::close`.
///
/// A message can carry a follow-up `F` for another worker. The follow-up is
/// released, into the caller's `released`, only once the message itself is in
/// this worker's queue.
struct Lane<T, F = ()> {
    tx: Sender<T>,
    parked: VecDeque<(T, Option<F>)>,
    /// Open connections with something already in the worker queue, and so
    /// possibly state on the worker that their `Close` must clear.
    delivered: HashSet<u64>,
}

impl<T: Routed, F> Lane<T, F> {
    fn new(tx: Sender<T>) -> Self {
        Self {
            tx,
            parked: VecDeque::new(),
            delivered: HashSet::new(),
        }
    }

    fn send_then(&mut self, msg: T, then: Option<F>, gates: &mut Gates, released: &mut Vec<F>) {
        if self.flush(gates, released) {
            let (conn_id, close) = (msg.conn_id(), msg.is_close());
            match self.tx.try_send(msg) {
                Ok(()) => {
                    if !close {
                        self.delivered.insert(conn_id);
                    }
                    released.extend(then);
                }
                Err(TrySendError::Disconnected(_)) => {}
                Err(TrySendError::Full(msg)) => self.park(msg, then, gates),
            }
        } else {
            self.park(msg, then, gates);
        }
    }

    fn park(&mut self, msg: T, then: Option<F>, gates: &mut Gates) {
        gates.park(msg.conn_id());
        self.parked.push_back((msg, then));
    }

    /// Move parked messages into the worker queue while it has room. True when
    /// nothing is left parked.
    fn flush(&mut self, gates: &mut Gates, released: &mut Vec<F>) -> bool {
        while let Some((msg, then)) = self.parked.pop_front() {
            let (conn_id, close) = (msg.conn_id(), msg.is_close());
            match self.tx.try_send(msg) {
                Ok(()) => {
                    if !close {
                        self.delivered.insert(conn_id);
                    }
                    released.extend(then);
                    gates.unpark(conn_id);
                }
                Err(TrySendError::Disconnected(_)) => gates.unpark(conn_id),
                Err(TrySendError::Full(msg)) => {
                    self.parked.push_front((msg, then));
                    return false;
                }
            }
        }
        true
    }

    /// Connection teardown. What is parked for the connection is dropped,
    /// follow-ups included, and the worker gets `close` only if it was handed
    /// something before. A closed connection therefore leaves at most one
    /// message behind, and none at all if a stalled worker never saw it,
    /// however many connections come and go while the worker is stuck.
    fn close(&mut self, conn_id: u64, close: T, gates: &mut Gates, released: &mut Vec<F>) {
        self.parked.retain(|(msg, _)| {
            let keep = msg.conn_id() != conn_id;
            if !keep {
                gates.unpark(conn_id);
            }
            keep
        });
        if self.delivered.remove(&conn_id) {
            self.send_then(close, None, gates, released);
        }
    }

    /// Hand over the backlog at shutdown, when there is nothing left to stall.
    fn flush_blocking(&mut self) {
        for (msg, _) in self.parked.drain(..) {
            let _ = self.tx.send(msg);
        }
    }
}

impl<T: Routed> Lane<T> {
    fn send(&mut self, msg: T, gates: &mut Gates) {
        self.send_then(msg, None, gates, &mut Vec::new());
    }

    fn flush_all(&mut self, gates: &mut Gates) -> bool {
        self.flush(gates, &mut Vec::new())
    }
}

/// Worker messages the ingester routes, by the connection they belong to.
trait Routed {
    fn conn_id(&self) -> u64;
    /// Connection teardown, which leaves the worker no state for it.
    fn is_close(&self) -> bool;
}

impl Routed for ReqMsg {
    fn conn_id(&self) -> u64 {
        match self {
            Self::Scan(sub) | Self::Count(sub) => sub.conn_id,
            Self::SetAuth { conn_id, .. }
            | Self::Cancel { conn_id, .. }
            | Self::Close { conn_id } => *conn_id,
        }
    }

    fn is_close(&self) -> bool {
        matches!(self, Self::Close { .. })
    }
}

impl Routed for MonitorMsg {
    fn conn_id(&self) -> u64 {
        match self {
            Self::Register(sub) => sub.conn_id,
            Self::Remove { conn_id, .. }
            | Self::HistoryDone { conn_id, .. }
            | Self::SetAuth { conn_id, .. }
            | Self::Close { conn_id } => *conn_id,
        }
    }

    fn is_close(&self) -> bool {
        matches!(self, Self::Close { .. })
    }
}

impl Routed for NegMsg {
    fn conn_id(&self) -> u64 {
        match self {
            Self::Open { sub, .. } => sub.conn_id,
            Self::Msg { conn_id, .. }
            | Self::SetAuth { conn_id, .. }
            | Self::CloseSub { conn_id, .. }
            | Self::Fail { conn_id, .. }
            | Self::Close { conn_id } => *conn_id,
        }
    }

    fn is_close(&self) -> bool {
        matches!(self, Self::Close { .. })
    }
}

impl Routed for WriterMsg {
    fn conn_id(&self) -> u64 {
        match self {
            Self::AddEvent { conn_id, .. } | Self::Close { conn_id } => *conn_id,
            // Never sent by an ingester.
            Self::Maintenance | Self::Management(_) | Self::Stop => 0,
        }
    }

    fn is_close(&self) -> bool {
        matches!(self, Self::Close { .. })
    }
}

/// Per-connection pausing. A connection with anything parked has its ingress
/// gate closed, so its transport stops handing over messages until the backlog
/// moves. What is parked is then bounded by the ingester's queue plus the one
/// message each paused connection may already have had in flight, and
/// connections that never touch the stalled worker are not paused.
#[derive(Default)]
struct Gates {
    open: HashMap<u64, IngressGate>,
    parked: HashMap<u64, usize>,
}

impl Gates {
    fn park(&mut self, conn_id: u64) {
        let parked = self.parked.entry(conn_id).or_default();
        *parked += 1;
        if *parked == 1 {
            if let Some(gate) = self.open.get(&conn_id) {
                gate.send_replace(false);
            }
        }
    }

    fn unpark(&mut self, conn_id: u64) {
        let Some(parked) = self.parked.get_mut(&conn_id) else {
            return;
        };
        *parked -= 1;
        if *parked == 0 {
            self.parked.remove(&conn_id);
            if let Some(gate) = self.open.get(&conn_id) {
                gate.send_replace(true);
            }
        }
    }
}

/// An ingester's worker queues and the gates of its connections.
struct Dispatch {
    writer: Lane<WriterMsg>,
    req: Vec<Lane<ReqMsg>>,
    /// A REQ's or CLOSE's message for the req worker follows its monitor
    /// message: a REQ's history never finishes before the monitor's control
    /// queue holds its registration, and both see a connection's REQs and
    /// CLOSEs in the same order. That queue is unbounded, so nothing parks
    /// here and the follow-up goes at once.
    mon: Vec<Lane<MonitorMsg, ReqMsg>>,
    neg: Vec<Lane<NegMsg>>,
    gates: Gates,
    /// Follow-ups whose monitor message went through, for the req lanes.
    released: Vec<ReqMsg>,
}

impl Dispatch {
    fn new(
        writer: Sender<WriterMsg>,
        req: Vec<Sender<ReqMsg>>,
        mon: Vec<Sender<MonitorMsg>>,
        neg: Vec<Sender<NegMsg>>,
    ) -> Self {
        Self {
            writer: Lane::new(writer),
            req: req.into_iter().map(Lane::new).collect(),
            mon: mon.into_iter().map(Lane::new).collect(),
            neg: neg.into_iter().map(Lane::new).collect(),
            gates: Gates::default(),
            released: Vec::new(),
        }
    }

    fn open(&mut self, conn_id: u64, gate: IngressGate) {
        self.gates.open.insert(conn_id, gate);
    }

    fn writer(&mut self, msg: WriterMsg) {
        self.writer.send(msg, &mut self.gates);
    }

    fn req(&mut self, msg: ReqMsg) {
        let n = self.req.len();
        self.req[msg.conn_id() as usize % n].send(msg, &mut self.gates);
    }

    fn monitor(&mut self, msg: MonitorMsg) {
        self.monitor_then(msg, None);
    }

    /// A REQ or CLOSE: `msg` for the req monitor, then `then` for the req
    /// worker once `msg` is queued.
    fn subscription(&mut self, msg: MonitorMsg, then: ReqMsg) {
        self.monitor_then(msg, Some(then));
    }

    fn monitor_then(&mut self, msg: MonitorMsg, then: Option<ReqMsg>) {
        let n = self.mon.len();
        self.mon[msg.conn_id() as usize % n].send_then(
            msg,
            then,
            &mut self.gates,
            &mut self.released,
        );
        self.release();
    }

    fn release(&mut self) {
        let mut released = std::mem::take(&mut self.released);
        for msg in released.drain(..) {
            self.req(msg);
        }
        self.released = released;
    }

    fn neg(&mut self, msg: NegMsg) {
        let n = self.neg.len();
        self.neg[msg.conn_id() as usize % n].send(msg, &mut self.gates);
    }

    /// Connection teardown, which no gate holds back. Whatever is still
    /// parked for the connection is dropped rather than run first: its REQs
    /// and sync messages are superseded by `Close`, and the writer already
    /// drops events from a connection that closes in the same batch.
    fn close(&mut self, conn_id: u64) {
        self.gates.open.remove(&conn_id);
        let n = self.mon.len();
        self.mon[conn_id as usize % n].close(
            conn_id,
            MonitorMsg::Close { conn_id },
            &mut self.gates,
            &mut self.released,
        );
        self.release();
        let n = self.req.len();
        self.req[conn_id as usize % n].close(
            conn_id,
            ReqMsg::Close { conn_id },
            &mut self.gates,
            &mut Vec::new(),
        );
        let n = self.neg.len();
        self.neg[conn_id as usize % n].close(
            conn_id,
            NegMsg::Close { conn_id },
            &mut self.gates,
            &mut Vec::new(),
        );
        self.writer.close(
            conn_id,
            WriterMsg::Close { conn_id },
            &mut self.gates,
            &mut Vec::new(),
        );
    }

    /// True when nothing is parked on any worker.
    fn flush(&mut self) -> bool {
        let mut done = self.writer.flush_all(&mut self.gates);
        for lane in &mut self.mon {
            done &= lane.flush(&mut self.gates, &mut self.released);
        }
        self.release();
        for lane in &mut self.req {
            done &= lane.flush_all(&mut self.gates);
        }
        for lane in &mut self.neg {
            done &= lane.flush_all(&mut self.gates);
        }
        done
    }

    /// Sleep until a worker with parked messages has room, or `timeout`.
    fn wait_for_capacity(&self, timeout: Duration) {
        let mut select = crossbeam_channel::Select::new();
        if !self.writer.parked.is_empty() {
            select.send(&self.writer.tx);
        }
        for lane in self.req.iter().filter(|lane| !lane.parked.is_empty()) {
            select.send(&lane.tx);
        }
        for lane in self.mon.iter().filter(|lane| !lane.parked.is_empty()) {
            select.send(&lane.tx);
        }
        for lane in self.neg.iter().filter(|lane| !lane.parked.is_empty()) {
            select.send(&lane.tx);
        }
        let _ = select.ready_timeout(timeout);
    }

    /// On exit, parked events still reach the writer ahead of its `Stop`.
    /// Parked queries, subscriptions and sync messages are dropped: their
    /// workers are stopping, and a stalled one must not hold up the join.
    fn flush_blocking(&mut self) {
        self.writer.flush_blocking();
    }
}

#[allow(clippy::too_many_arguments)]
fn run_ingester(
    env: Env,
    cfg: Arc<parking_lot::RwLock<Config>>,
    conns: Arc<ConnTable>,
    metrics: Arc<Metrics>,
    abuse: Arc<AbuseController>,
    moderation: Arc<parking_lot::RwLock<ModerationSnapshot>>,
    mut rx: tokio::sync::mpsc::Receiver<IngestMsg>,
    writer_tx: Sender<WriterMsg>,
    req_txs: Vec<Sender<ReqMsg>>,
    mon_txs: Vec<Sender<MonitorMsg>>,
    neg_txs: Vec<Sender<NegMsg>>,
) {
    let mut auth: HashMap<u64, AuthSession> = HashMap::new();
    let mut budgets: HashMap<u64, ConnectionBudgets> = HashMap::new();
    let mut generations = Generations::default();
    let mut dispatch = Dispatch::new(writer_tx, req_txs, mon_txs, neg_txs);
    loop {
        // blocking_recv is only used here, on a dedicated OS thread outside
        // any Tokio runtime, so no async executor is stalled. While messages
        // are parked the ingester polls instead, so it can move them on as
        // soon as their worker has room.
        let msg = if dispatch.flush() {
            match rx.blocking_recv() {
                Some(msg) => msg,
                None => break,
            }
        } else {
            match rx.try_recv() {
                Ok(msg) => msg,
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                    dispatch.wait_for_capacity(PARKED_RETRY_INTERVAL);
                    continue;
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
            }
        };
        match msg {
            IngestMsg::Stop => break,
            IngestMsg::Open { conn_id, gate } => {
                if let Some(gate) = gate {
                    dispatch.open(conn_id, gate);
                }
                // NIP-42 lets the relay challenge at any time. Challenging on
                // connect lets a client authenticate before its first REQ, so
                // a restricted live subscription (e.g. NIP-46 kind 24133) is
                // not refused and re-sent while ephemeral replies go by.
                if cfg.read().auth_usable() {
                    issue_challenge(&conns, &metrics, &mut auth, conn_id);
                }
            }
            IngestMsg::Close { conn_id } => {
                if auth.remove(&conn_id).and_then(|a| a.authed).is_some() {
                    metrics
                        .authenticated_connections
                        .fetch_sub(1, Ordering::Relaxed);
                }
                budgets.remove(&conn_id);
                dispatch.close(conn_id);
            }
            IngestMsg::Client {
                conn_id,
                source,
                payload,
                share,
            } => {
                // Keep the cheap read guard for the duration of one command.
                // Cloning Config here copied every String, PathBuf, and Vec on
                // the hottest ingress path even though reloads are rare.
                let cfg_snap = cfg.read();
                handle_client(
                    &env,
                    &cfg_snap,
                    &conns,
                    &metrics,
                    &abuse,
                    &moderation,
                    &mut auth,
                    &mut budgets,
                    &mut generations,
                    conn_id,
                    source,
                    &payload,
                    &mut dispatch,
                );
                drop(share);
            }
        }
    }
    dispatch.flush_blocking();
}

#[allow(clippy::too_many_arguments)]
fn handle_client(
    env: &Env,
    cfg: &Config,
    conns: &ConnTable,
    metrics: &Metrics,
    abuse: &AbuseController,
    moderation: &parking_lot::RwLock<ModerationSnapshot>,
    auth: &mut HashMap<u64, AuthSession>,
    budgets: &mut HashMap<u64, ConnectionBudgets>,
    generations: &mut Generations,
    conn_id: u64,
    source: TransportSource,
    payload: &str,
    dispatch: &mut Dispatch,
) {
    let cmd = match ClientCommand::parse(payload) {
        Ok(c) => c,
        Err(failure) if !admit_invalid(cfg, conns, metrics, abuse, &source, conn_id) => {
            // The reply is suppressed, but a malformed NEG request that names
            // a session still tears it down, as its NEG-ERR would have.
            if let ParseFailure::NegRequest { sub_id, .. } = failure {
                if let Ok(sub_id) = SubId::new(&sub_id) {
                    dispatch.neg(NegMsg::CloseSub { conn_id, sub_id });
                }
            }
            return;
        }
        Err(ParseFailure::NegRequest { sub_id, reason }) => {
            let reason = format!("invalid: {reason}");
            neg_err(conns, metrics, dispatch, conn_id, &sub_id, reason);
            return;
        }
        Err(e) => {
            conns.send(conn_id, e.into_message(), metrics);
            return;
        }
    };
    match cmd {
        ClientCommand::Newline => {}
        ClientCommand::Event(v) => {
            metrics.client_event.fetch_add(1, Ordering::Relaxed);
            if !abuse.admit_source(&source, BudgetKind::Event, &cfg.relay.abuse) {
                metrics
                    .abuse_event_rate_rejections
                    .fetch_add(1, Ordering::Relaxed);
                metrics.refused(Setting::EventBurst);
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
                env, cfg, conns, metrics, abuse, moderation, auth, conn_id, source, v, dispatch,
            );
        }
        ClientCommand::Auth(v) => {
            metrics.client_auth.fetch_add(1, Ordering::Relaxed);
            // AUTH costs what an EVENT costs (parse, id hash, Schnorr verify),
            // so it draws on the same per-source budget.
            if !abuse.admit_source(&source, BudgetKind::Event, &cfg.relay.abuse) {
                metrics
                    .abuse_event_rate_rejections
                    .fetch_add(1, Ordering::Relaxed);
                metrics.refused(Setting::EventBurst);
                let id = v.get("id").and_then(Value::as_str).unwrap_or("?");
                conns.send(
                    conn_id,
                    RelayMessage::Ok {
                        event_id: id.into(),
                        accepted: false,
                        message: "rate-limited: AUTH budget exhausted".into(),
                    },
                    metrics,
                );
                return;
            }
            ingest_auth(cfg, conns, metrics, auth, conn_id, v, dispatch);
        }
        ClientCommand::Req { sub_id, filters } => {
            metrics.client_req.fetch_add(1, Ordering::Relaxed);
            let request = (Request::Req, "REQ");
            let admitted = admit_request(
                cfg, metrics, abuse, budgets, auth, conn_id, &source, request,
            );
            if let Err(reason) = admitted {
                refuse_req(conns, metrics, dispatch, conn_id, Ns::Req, &sub_id, reason);
                return;
            }
            ingest_req(
                env,
                cfg,
                conns,
                metrics,
                moderation,
                auth,
                generations,
                conn_id,
                sub_id,
                filters,
                false,
                dispatch,
            );
        }
        ClientCommand::Count { sub_id, filters } => {
            metrics.client_count.fetch_add(1, Ordering::Relaxed);
            let request = (Request::Count, "COUNT");
            let admitted = admit_request(
                cfg, metrics, abuse, budgets, auth, conn_id, &source, request,
            );
            if let Err(reason) = admitted {
                refuse_req(
                    conns,
                    metrics,
                    dispatch,
                    conn_id,
                    Ns::Count,
                    &sub_id,
                    reason,
                );
                return;
            }
            ingest_req(
                env,
                cfg,
                conns,
                metrics,
                moderation,
                auth,
                generations,
                conn_id,
                sub_id,
                filters,
                true,
                dispatch,
            );
        }
        ClientCommand::Close { sub_id } => {
            metrics.client_close.fetch_add(1, Ordering::Relaxed);
            match SubId::new(&sub_id) {
                Ok(sid) => close_req(conns, dispatch, conn_id, Ns::Req, sid),
                Err(e) => {
                    if !admit_invalid(cfg, conns, metrics, abuse, &source, conn_id) {
                        return;
                    }
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
            ingest_neg_command(
                cfg,
                conns,
                metrics,
                abuse,
                moderation,
                &source,
                auth,
                budgets,
                conn_id,
                sub_id,
                Some(filter),
                payload_hex,
                dispatch,
            );
        }
        ClientCommand::NegMsg {
            sub_id,
            payload_hex,
        } => {
            ingest_neg_command(
                cfg,
                conns,
                metrics,
                abuse,
                moderation,
                &source,
                auth,
                budgets,
                conn_id,
                sub_id,
                None,
                payload_hex,
                dispatch,
            );
        }
        ClientCommand::NegClose { sub_id } => {
            if !cfg.relay.negentropy_enabled {
                if !admit_invalid(cfg, conns, metrics, abuse, &source, conn_id) {
                    return;
                }
                conns.send(
                    conn_id,
                    RelayMessage::notice_error("bad msg: negentropy disabled"),
                    metrics,
                );
                return;
            }
            match SubId::new(&sub_id) {
                Ok(sid) => {
                    dispatch.neg(NegMsg::CloseSub {
                        conn_id,
                        sub_id: sid,
                    });
                }
                Err(e) => {
                    if !admit_invalid(cfg, conns, metrics, abuse, &source, conn_id) {
                        return;
                    }
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

/// NIP-70: "Reposts of protected events MUST NOT embed the reposted event.
/// If a repost of a protected event embeds the event anyway, relays SHOULD
/// summarily reject it." True when a repost's `content` is an event object
/// with a tag named `-`, whatever the JSON's spacing or the tag's other
/// elements, or is an object the relay cannot check.
fn embeds_protected_event(content: &str) -> bool {
    // An embedded event is a JSON object; anything else needs no parse.
    if !content
        .trim_start_matches([' ', '\t', '\n', '\r'])
        .starts_with('{')
    {
        return false;
    }
    // The content is no longer than its event, which `max_event_size`
    // bounds. An object the strict parser refuses counts as protected:
    // clients' parsers accept some of what it refuses (a repeated key, deep
    // nesting, a lone surrogate, a number too large for a double), and could
    // read a protected event there. NIP-18 makes the content the reposted
    // event or empty, so no valid repost is refused.
    let Ok(Value::Object(event)) = wok_event::json::parse_strict(content) else {
        return true;
    };
    event
        .get("tags")
        .and_then(Value::as_array)
        .is_some_and(|tags| {
            tags.iter()
                .any(|tag| tag.get(0).and_then(Value::as_str) == Some("-"))
        })
}

fn ingest_event(
    env: &Env,
    cfg: &Config,
    conns: &ConnTable,
    metrics: &Metrics,
    abuse: &AbuseController,
    moderation: &parking_lot::RwLock<ModerationSnapshot>,
    auth: &mut HashMap<u64, AuthSession>,
    conn_id: u64,
    source: TransportSource,
    orig: Value,
    dispatch: &mut Dispatch,
) {
    let claimed_kind = orig.get("kind").and_then(Value::as_u64);
    if let Some(message) =
        claimed_kind.and_then(|kind| kind_refusal(cfg, metrics, moderation, kind))
    {
        let id = orig.get("id").and_then(Value::as_str).unwrap_or("?");
        conns.send(
            conn_id,
            RelayMessage::Ok {
                event_id: id.to_string(),
                accepted: false,
                message,
            },
            metrics,
        );
        return;
    }
    let requested_kind = claimed_kind.unwrap_or(u64::MAX);
    let policy = cfg.timestamp_policy_for_kind(requested_kind);
    let parsed = match parse_and_verify_event(&orig, &cfg.event_limits(), Some(&policy), true, true)
    {
        Ok(p) => p,
        Err(e) => {
            count_event_limit(metrics, requested_kind, &e);
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
    let grant = {
        let snap = moderation.read();
        let identities = auth
            .get(&conn_id)
            .map_or(&[][..], |session| session.identities.as_slice());
        let grant = WriteGrant::new(cfg, &snap, packed, identities);
        let mut id = [0u8; 32];
        id.copy_from_slice(packed.id());
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(packed.pubkey());
        // The kind gates ran before the event was verified (`kind_refusal`).
        let rejected = if snap.banned_events.contains_key(&id) {
            Some((
                &metrics.moderation_banned_event_rejections,
                None,
                "restricted: event is banned by the relay operator".to_string(),
            ))
        } else if is_vanish_request {
            // NIP-62: relays that restrict who can post MUST honor vanish
            // requests regardless of the user's status, so author bans and
            // write restrictions do not apply. Event-id bans and the kind
            // policy above still do.
            None
        } else if snap.banned_pubkeys.contains_key(&pubkey) {
            Some((
                &metrics.moderation_banned_author_rejections,
                None,
                "restricted: author is banned by the relay operator".to_string(),
            ))
        } else if !grant.admits(cfg) {
            Some((
                &metrics.moderation_restricted_write_rejections,
                Some(Setting::WritePolicy),
                grant.refusal(cfg),
            ))
        } else {
            None
        };
        if let Some((counter, setting, message)) = rejected {
            counter.fetch_add(1, Ordering::Relaxed);
            if let Some(setting) = setting {
                metrics.refused(setting);
            }
            if message.starts_with("auth-required:") {
                issue_challenge(conns, metrics, auth, conn_id);
            }
            conns.send(
                conn_id,
                RelayMessage::Ok {
                    event_id: id_hex,
                    accepted: false,
                    message,
                },
                metrics,
            );
            return;
        }
        grant
    };
    if is_vanish_request && !cfg.vanish_policy().targets_this_relay_json(&parsed.json) {
        if !cfg.relay.nip62.enabled {
            metrics.refused(Setting::Nip62Enabled);
        }
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

    if cfg.relay.abuse.enabled {
        if leading_zero_bits(packed.id()) < cfg.relay.abuse.min_pow_difficulty as u16 {
            metrics.abuse_pow_rejections.fetch_add(1, Ordering::Relaxed);
            metrics.refused(Setting::MinPowDifficulty);
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
        // An event signed by a key that is not one of the connection's AUTHed
        // identities, such as a Marmot 445 from a fresh key per event or a
        // 1059 from a random one, is charged to the connection's first
        // identity: its author's budget would be new every time (#97 F11).
        let mut author = [0u8; 32];
        author.copy_from_slice(packed.pubkey());
        let charged = auth
            .get(&conn_id)
            .filter(|session| !session.identities.contains(&author))
            .and_then(|session| session.authed)
            .unwrap_or(author);
        if !abuse.admit_pubkey_event(&charged, &cfg.relay.abuse) {
            metrics
                .abuse_event_rate_rejections
                .fetch_add(1, Ordering::Relaxed);
            metrics.refused(Setting::PubkeyEventBurst);
            let message = if charged == author {
                "rate-limited: author EVENT budget exhausted"
            } else {
                "rate-limited: EVENT budget exhausted for the authenticated pubkey"
            };
            conns.send(
                conn_id,
                RelayMessage::Ok {
                    event_id: id_hex,
                    accepted: false,
                    message: message.into(),
                },
                metrics,
            );
            return;
        }
    }

    if REPOST_KINDS.contains(&packed.kind())
        && orig
            .get("content")
            .and_then(Value::as_str)
            .is_some_and(embeds_protected_event)
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

    // NIP-70 protected events, and kinds only their author may read, such as
    // NIP-78 app data, are accepted only on a connection authenticated as
    // their author.
    let owner_only = cfg.relay.auth.owner_only_kinds.contains(&packed.kind());
    let mut authed = None;
    if (found_protected || owner_only) && !is_vanish_request {
        let refusal = if !cfg.auth_usable() {
            Some(if found_protected {
                "blocked: event marked as protected".to_string()
            } else {
                format!(
                    "restricted: kind {} needs AUTH as its author, which this relay does not offer",
                    packed.kind()
                )
            })
        } else {
            let auth_required = || {
                if found_protected {
                    "auth-required: event marked as protected".to_string()
                } else {
                    format!(
                        "auth-required: kind {} is accepted only from its author",
                        packed.kind()
                    )
                }
            };
            match auth.get(&conn_id) {
                None => {
                    issue_challenge(conns, metrics, auth, conn_id);
                    Some(auth_required())
                }
                Some(asess) if asess.authed.is_none() => Some(auth_required()),
                Some(asess) => {
                    let pk: [u8; 32] = packed.pubkey().try_into().unwrap();
                    if asess.identities.contains(&pk) {
                        authed = Some(pk);
                        None
                    } else {
                        Some("restricted: must be published by the author".to_string())
                    }
                }
            }
        };
        if let Some(message) = refusal {
            // A protected event is refused by NIP-70 whatever its kind.
            if owner_only && !found_protected {
                metrics.refused(Setting::OwnerOnlyKinds);
            }
            conns.send(
                conn_id,
                RelayMessage::Ok {
                    event_id: id_hex,
                    accepted: false,
                    message,
                },
                metrics,
            );
            return;
        }
    }

    {
        // Preserve the cheap duplicate fast path before write-policy plugins
        // and the single writer. The writer still performs the authoritative
        // lookup inside its transaction to close the concurrent-insert race.
        let dup = (|| -> Result<bool, String> {
            let txn = begin_read(env).map_err(|e| e.to_string())?;
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
            Err(error) => {
                conns.send(
                    conn_id,
                    RelayMessage::Ok {
                        event_id: id_hex,
                        accepted: false,
                        message: format!("error: {error}"),
                    },
                    metrics,
                );
                return;
            }
        }
    }

    dispatch.writer(WriterMsg::AddEvent {
        conn_id,
        source,
        packed: parsed.packed.into_bytes(),
        json: parsed.json,
        authed,
        grant,
    });
}

/// The refusal for an EVENT that its claimed kind alone decides, counted
/// where it is decided: an AUTH event, a kind `accepted_kinds` or the NIP-86
/// kind policy does not allow, or one nobody could read while AUTH is
/// unusable ([`Config::unreadable_class`]). These gates run before the event
/// is parsed and its signature verified: a kind refusal says nothing about
/// who may publish, and on a relay that accepts few kinds most junk is
/// refused without a verification. The author ban and the write policy wait
/// for the signature, so an unsigned event cannot ask whether a key is a
/// member or banned.
fn kind_refusal(
    cfg: &Config,
    metrics: &Metrics,
    moderation: &parking_lot::RwLock<ModerationSnapshot>,
    kind: u64,
) -> Option<String> {
    // NIP-42: relays MUST exclude kind 22242 from broadcast. One sent as an
    // EVENT is neither stored nor delivered to any subscription.
    if kind == AUTH_KIND {
        return Some("invalid: AUTH events must be sent with AUTH".into());
    }
    // Only `accepted_kinds` is a setting; a NIP-86 kind policy is counted by
    // the moderation counter alone.
    let setting = if !cfg.accepts_kind(kind) {
        Some(Setting::AcceptedKinds)
    } else if !moderation.read().kind_allowed(kind) {
        None
    } else {
        // A kind nobody could read is not stored, and is counted by its
        // read class.
        let class = cfg.unreadable_class(kind)?;
        if let Some(setting) = Setting::of_read_class(class) {
            metrics.refused(setting);
        }
        return Some(format!(
            "restricted: kind {kind} is read only after AUTH, which this relay does not offer"
        ));
    };
    metrics
        .moderation_kind_rejections
        .fetch_add(1, Ordering::Relaxed);
    if let Some(setting) = setting {
        metrics.refused(setting);
    }
    Some(format!(
        "restricted: kind {kind} is not allowed by this relay"
    ))
}

fn ingest_auth(
    cfg: &Config,
    conns: &ConnTable,
    metrics: &Metrics,
    auth: &mut HashMap<u64, AuthSession>,
    conn_id: u64,
    event_json: Value,
    dispatch: &mut Dispatch,
) {
    // C++ RelayIngester answers every AUTH failure with
    // OK <id|"?"> false "error: ...". Reasons that already carry a NIP-01
    // prefix keep it rather than gaining a second one.
    let event_id = event_json
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("?")
        .to_string();
    match ingest_auth_inner(cfg, metrics, auth, conn_id, &event_json, dispatch) {
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
                    message: if has_reason_prefix(&e) {
                        e
                    } else {
                        format!("error: {e}")
                    },
                },
                metrics,
            );
        }
    }
}

fn ingest_auth_inner(
    cfg: &Config,
    metrics: &Metrics,
    auth: &mut HashMap<u64, AuthSession>,
    conn_id: u64,
    event_json: &Value,
    dispatch: &mut Dispatch,
) -> Result<[u8; 32], String> {
    // Refuse AUTH under the same condition that keeps NIP-42 out of NIP-11, so
    // `enabled = false` really disables it.
    if !cfg.relay.auth.enabled {
        metrics.refused(Setting::AuthEnabled);
        return Err("blocked: AUTH is disabled on this relay".into());
    }
    if cfg.relay.auth.service_url.is_empty() {
        metrics.refused(Setting::AuthServiceUrl);
        return Err(
            "blocked: relay needs service_url to be configured before AUTH can work".into(),
        );
    }
    // Only a connection that was issued a challenge can authenticate, so
    // refuse the rest before spending a signature verification on them.
    let asess = auth
        .get_mut(&conn_id)
        .ok_or("no auth status available for connection")?;
    // The kind, this connection's challenge and the relay's URL are checked
    // as the event states them, before its signature is verified: the
    // client knows all three, so refusing on them reveals nothing, and an
    // AUTH that cannot succeed costs no verification.
    if event_json.get("kind").and_then(Value::as_u64) != Some(AUTH_KIND) {
        return Err("wrong event kind, expected 22242".into());
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
    // NIP-42's window of about ten minutes, not `[events]`: the challenge
    // already prevents replay. An AUTH event that fails validation is
    // `invalid:`, as it would be if sent as EVENT.
    let policy = cfg.timestamp_policy_for_kind(AUTH_KIND);
    let parsed = parse_and_verify_event(event_json, &cfg.event_limits(), Some(&policy), true, true)
        .map_err(|e| {
            count_event_limit(metrics, AUTH_KIND, &e);
            format!("invalid: {e}")
        })?;
    let packed = parsed.packed.view();
    let mut pk = [0u8; 32];
    pk.copy_from_slice(packed.pubkey());
    if !asess.identities.contains(&pk) {
        if asess.identities.len() >= 64 {
            return Err("restricted: too many authenticated identities".into());
        }
        asess.identities.push(pk);
    }
    // Keep admission accounting pinned to the first identity; authenticating
    // another key must not reset the connection's abuse budget.
    asess.authed.get_or_insert(pk);
    dispatch.req(ReqMsg::SetAuth {
        conn_id,
        authed: pk,
    });
    dispatch.monitor(MonitorMsg::SetAuth {
        conn_id,
        authed: pk,
    });
    dispatch.neg(NegMsg::SetAuth {
        conn_id,
        authed: pk,
    });
    let mut id = [0u8; 32];
    id.copy_from_slice(packed.id());
    Ok(id)
}

/// Generations for one ingester's REQs and COUNTs, increasing in the order
/// it handles them, and so per connection too (a connection stays on one
/// ingester). Never zero.
#[derive(Default)]
struct Generations(u64);

impl Generations {
    fn next(&mut self) -> u64 {
        self.0 += 1;
        self.0
    }
}

#[allow(clippy::too_many_arguments)]
fn ingest_req(
    env: &Env,
    cfg: &Config,
    conns: &ConnTable,
    metrics: &Metrics,
    moderation: &parking_lot::RwLock<ModerationSnapshot>,
    auth: &mut HashMap<u64, AuthSession>,
    generations: &mut Generations,
    conn_id: u64,
    sub_id: String,
    filters: Vec<Value>,
    count_only: bool,
    dispatch: &mut Dispatch,
) {
    let ns = if count_only { Ns::Count } else { Ns::Req };
    // The id comes first: every other refusal names it.
    let sid = match SubId::new(&sub_id) {
        Ok(sid) => sid,
        Err(e) => {
            let reason = format!("invalid: bad req: {e}");
            refuse_req(conns, metrics, dispatch, conn_id, ns, &sub_id, reason);
            return;
        }
    };
    if filters.is_empty() {
        // NIP-01: a refused REQ gets CLOSED. C++ RelayIngester raises
        // "arr too small" as a NOTICE, before it reads the sub id.
        let reason = "invalid: bad req: arr too small".to_string();
        refuse_req(conns, metrics, dispatch, conn_id, ns, &sub_id, reason);
        return;
    }
    let admitted = admit_req(
        cfg, conns, metrics, moderation, auth, conn_id, &sid, filters, count_only,
    );
    let (mut sub, filter_bytes) = match admitted {
        Ok(admitted) => admitted,
        Err(reason) => {
            refuse_req(conns, metrics, dispatch, conn_id, ns, &sub_id, reason);
            return;
        }
    };
    sub.generation = generations.next();
    if count_only {
        conns.open_sub(
            conn_id,
            Ns::Count,
            &sub.sub_id,
            sub.generation,
            filter_bytes,
        );
        dispatch.req(ReqMsg::Count(sub));
        return;
    }
    // The history sends what is stored now, the monitor everything stored or
    // published after. Each event is the job of exactly one of them, whatever
    // the history's limits keep out.
    let Ok(snapshot) = env.begin_ro().and_then(|txn| most_recent_levid_ro(&txn)) else {
        let reason = "error: could not read the database".to_string();
        refuse_req(conns, metrics, dispatch, conn_id, ns, &sub_id, reason);
        return;
    };
    sub.latest_event_id = snapshot;
    // NIP-67 lets EOSE say that authenticating may reveal more, but only once
    // a challenge was sent. The connection normally got one on connect; one
    // that connected while AUTH was unusable gets it now, ahead of the EOSE.
    if cfg.auth_usable() && cfg.read_restrictor().may_hide_matches(&sub.filter_group) {
        issue_challenge(conns, metrics, auth, conn_id);
        sub.auth_challenged = true;
    }
    // From here on only this generation's frames reach the client for the id.
    conns.open_sub(conn_id, Ns::Req, &sub.sub_id, sub.generation, filter_bytes);
    dispatch.subscription(MonitorMsg::Register(sub.clone()), ReqMsg::Scan(sub));
}

/// Refuse a request whose estimated index work is over
/// `relay.abuse.max_query_work`. The same request would be refused again, so
/// the reason is `blocked:`, not `rate-limited:` (#97 §8).
fn check_query_work(
    cfg: &Config,
    metrics: &Metrics,
    work: u64,
    request: &str,
) -> Result<(), String> {
    let max = cfg.relay.abuse.max_query_work;
    if !cfg.relay.abuse.enabled || max == 0 || work <= max {
        return Ok(());
    }
    metrics
        .abuse_query_cost_rejections
        .fetch_add(1, Ordering::Relaxed);
    metrics.refused(Setting::MaxQueryWork);
    Err(format!(
        "blocked: query too broad (cost {work} > {max}); split the {request} or narrow \
         authors/kinds"
    ))
}

/// Every check a REQ or COUNT passes before any worker sees it, returning
/// the subscription and its serialized filter bytes. `Err` is the CLOSED
/// reason: `invalid:` for a malformed request or one over a size limit,
/// `unsupported:` for filter elements the relay does not know, and
/// `blocked:` for an operator rule that applies to every client.
#[allow(clippy::too_many_arguments)]
fn admit_req(
    cfg: &Config,
    conns: &ConnTable,
    metrics: &Metrics,
    moderation: &parking_lot::RwLock<ModerationSnapshot>,
    auth: &mut HashMap<u64, AuthSession>,
    conn_id: u64,
    sid: &SubId,
    filters: Vec<Value>,
    count_only: bool,
) -> Result<(Subscription, usize), String> {
    // C++ RelayIngester sends `error: bad req: ...` for all of these. The
    // text after the prefix is kept.
    let bad_req = |prefix: &str, e: String| format!("{prefix}: bad req: {e}");
    let refuse = |setting, prefix: &str, e: String| {
        metrics.refused(setting);
        bad_req(prefix, e)
    };
    // A reader the policy refuses is refused before its filters are sized,
    // parsed or priced; the refusal names only the policy.
    admit_reader(cfg, conns, metrics, moderation, auth, conn_id)?;
    if filters.len() > cfg.relay.max_filters_per_req {
        // Keep strfry's wording for its legacy filter-count ceiling.
        return Err(refuse(
            Setting::MaxFiltersPerReq,
            "invalid",
            "arr too big".into(),
        ));
    }
    let serialized_filter_bytes = filters.iter().fold(0usize, |total, filter| {
        total.saturating_add(filter.to_string().len())
    });
    if serialized_filter_bytes > cfg.relay.max_req_filter_size {
        return Err(refuse(
            Setting::MaxReqFilterSize,
            "invalid",
            format!(
                "filters exceed {} serialized bytes",
                cfg.relay.max_req_filter_size
            ),
        ));
    }
    let max_limit = if count_only {
        let m = cfg.relay.max_filter_limit_count + 1;
        if m == 1 {
            return Err(refuse(
                Setting::MaxFilterLimitCount,
                "blocked",
                "COUNT disabled".into(),
            ));
        }
        m
    } else {
        cfg.relay.max_filter_limit
    };
    let mut arr = vec![json!("REQ"), json!(sid.as_str())];
    arr.extend(filters);
    let fg = NostrFilterGroup::from_req(
        &arr,
        max_limit,
        cfg.relay.max_tags_per_filter,
        cfg.relay.max_and_entries,
    )
    .map_err(|e| {
        count_filter_limit(metrics, &e);
        bad_req(e.reason_prefix(), e.to_string())
    })?;
    if let Err(e) = filter_validator(cfg).validate(&fg) {
        count_filter_limit(metrics, &e);
        return Err(bad_req("blocked", format!("filter validation failed: {e}")));
    }
    let costed = if count_only {
        CostedRequest::Count
    } else {
        CostedRequest::Req {
            max_total_events: cfg.relay.max_total_events_per_req,
        }
    };
    // The writer's gauge can trail its last backfill step; the scan itself
    // checks its own snapshot, and either plan's seeks are bounded.
    let tag_kind_index = metrics.tag_kind_index_complete.load(Ordering::Relaxed) != 0;
    let query_cost = fg.estimated_cost(costed, tag_kind_index);
    check_query_work(
        cfg,
        metrics,
        query_cost,
        if count_only { "COUNT" } else { "REQ" },
    )?;

    let authed = auth.get(&conn_id).and_then(|a| a.authed);
    let r = cfg.read_restrictor();
    let requires_auth = if count_only {
        !auth.get(&conn_id).is_some_and(|session| {
            session
                .identities
                .iter()
                .any(|pk| r.is_filter_allowed_to_count(&fg, Some(pk)))
        }) && !r.is_filter_allowed_to_count(&fg, None)
    } else {
        r.is_filter_group_fully_restricted(&fg) && authed.is_none()
    };
    if requires_auth {
        // A COUNT is refused for the filters its reader is not scoped to,
        // a REQ for all of them.
        let class = if count_only {
            let identities = auth
                .get(&conn_id)
                .map_or(&[][..], |session| session.identities.as_slice());
            r.count_refusal_class(&fg, identities)
        } else {
            r.strictest_group_class(&fg)
        };
        count_read_class(metrics, class);
        return Err(read_gate_refusal(cfg, conns, metrics, auth, conn_id).into());
    }
    // Pending and live subscriptions both count. Over a lowered cap an open
    // id can still be replaced; new ids wait until the count drops.
    if !count_only
        && !conns.is_open(conn_id, Ns::Req, sid)
        && conns.open_count(conn_id, Ns::Req) >= cfg.relay.max_subs_per_connection
    {
        metrics.refused(Setting::MaxSubsPerConnection);
        return Err("blocked: too many concurrent REQs".into());
    }
    // Live filters stay in memory until closed, and a COUNT's until it is
    // answered, which may wait for a scan slot, so each namespace's bytes are
    // budgeted per connection. Like the subscription cap, a lowered budget
    // still lets an open id be replaced by filters no larger than its own.
    let filter_budget = cfg.relay.max_filter_bytes_per_connection;
    if filter_budget != 0 {
        let ns = if count_only { Ns::Count } else { Ns::Req };
        let (held, replaced) = conns.filter_bytes(conn_id, ns, sid);
        if serialized_filter_bytes > replaced
            && held - replaced + serialized_filter_bytes > filter_budget
        {
            metrics.refused(Setting::MaxFilterBytesPerConnection);
            return Err(format!(
                "blocked: this connection's filters exceed {filter_budget} bytes"
            ));
        }
    }
    Ok((
        Subscription::new(conn_id, sid.clone(), fg, count_only),
        serialized_filter_bytes,
    ))
}

/// End the subscription or COUNT `sub_id` names, if open: its frames stop at
/// the gate at once, and its worker and monitor stop working on it.
fn close_req(conns: &ConnTable, dispatch: &mut Dispatch, conn_id: u64, ns: Ns, sub_id: SubId) {
    if let Some(generation) = conns.close_sub(conn_id, ns, &sub_id) {
        stop_sub(dispatch, conn_id, ns, sub_id, generation);
    }
}

/// Tell the workers a generation is over. Cleanup only: the gate already
/// drops whatever they still send for it.
fn stop_sub(dispatch: &mut Dispatch, conn_id: u64, ns: Ns, sub_id: SubId, generation: u64) {
    let cancel = |sub_id| ReqMsg::Cancel {
        conn_id,
        sub_id,
        generation,
        count_only: ns == Ns::Count,
    };
    match ns {
        Ns::Req => dispatch.subscription(
            MonitorMsg::Remove {
                conn_id,
                sub_id: sub_id.clone(),
                generation,
            },
            cancel(sub_id),
        ),
        Ns::Count => dispatch.req(cancel(sub_id)),
    }
}

/// Refuse a REQ or COUNT with CLOSED. NIP-01 makes a REQ replace the
/// subscription it names, so a refused one still ends one with its id: the
/// gate closes the id and queues the CLOSED in one step, so nothing for the id
/// can follow it.
fn refuse_req(
    conns: &ConnTable,
    metrics: &Metrics,
    dispatch: &mut Dispatch,
    conn_id: u64,
    ns: Ns,
    sub_id: &str,
    reason: String,
) {
    if let Some(generation) = conns.refuse(conn_id, ns, sub_id, reason, metrics) {
        if let Ok(sid) = SubId::new(sub_id) {
            stop_sub(dispatch, conn_id, ns, sid, generation);
        }
    }
}

/// Whether `relay.auth.read_policy` admits a connection authenticated as
/// `identities`. Only the `members` policy reads the moderation snapshot.
fn reader_admitted(
    cfg: &Config,
    moderation: &parking_lot::RwLock<ModerationSnapshot>,
    identities: &[[u8; 32]],
) -> bool {
    match cfg.relay.auth.read_policy {
        AccessPolicy::Open => true,
        AccessPolicy::Authenticated => !identities.is_empty(),
        AccessPolicy::Members => {
            let snap = moderation.read();
            identities.iter().any(|pk| is_member(cfg, &snap, pk))
        }
    }
}

/// [`reader_admitted`] by the committed moderation state in `txn`, for a
/// worker whose view must agree with the policy generation it read there.
fn stored_reader_admitted(
    txn: &wok_db::RoTxn<'_>,
    cfg: &Config,
    identities: &[[u8; 32]],
) -> Result<bool, wok_db::DbError> {
    match cfg.relay.auth.read_policy {
        AccessPolicy::Open => Ok(true),
        AccessPolicy::Authenticated => Ok(!identities.is_empty()),
        AccessPolicy::Members => {
            for pubkey in identities {
                if stored_is_member(txn, cfg, pubkey)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}

/// Refuse a REQ, COUNT or NEG-OPEN from a connection `relay.auth.read_policy`
/// does not admit. As at the restricted-kind gate, the refusal is
/// `auth-required:`, with a challenge, only while authenticating can help.
fn admit_reader(
    cfg: &Config,
    conns: &ConnTable,
    metrics: &Metrics,
    moderation: &parking_lot::RwLock<ModerationSnapshot>,
    auth: &mut HashMap<u64, AuthSession>,
    conn_id: u64,
) -> Result<(), String> {
    let identities = auth
        .get(&conn_id)
        .map_or(&[][..], |session| session.identities.as_slice());
    if reader_admitted(cfg, moderation, identities) {
        return Ok(());
    }
    metrics.refused(Setting::ReadPolicy);
    let refusal = read_policy_refusal(cfg, !identities.is_empty());
    if refusal.starts_with("auth-required:") {
        issue_challenge(conns, metrics, auth, conn_id);
    }
    Err(refusal)
}

/// The CLOSED reason for a read `relay.auth.read_policy` does not admit:
/// `auth-required:` while authenticating can help.
fn read_policy_refusal(cfg: &Config, authenticated: bool) -> String {
    let who = match cfg.relay.auth.read_policy {
        AccessPolicy::Members => "members",
        _ => "authenticated users",
    };
    if !cfg.auth_usable() {
        format!("restricted: this relay serves only {who}, and it does not offer AUTH")
    } else if authenticated {
        format!("restricted: this relay serves only {who}")
    } else {
        format!("auth-required: this relay serves only {who}")
    }
}

/// Count an event of `kind` refused by a limit its settings chose.
fn count_event_limit(metrics: &Metrics, kind: u64, error: &wok_event::EventError) {
    if let Some(setting) = error
        .broken_limit()
        .and_then(|limit| Config::event_limit_setting(kind, limit))
    {
        metrics.refused(setting);
    }
}

/// Count a filter refused by a limit its settings chose.
fn count_filter_limit(metrics: &Metrics, error: &wok_query::QueryError) {
    if let Some(limit) = error.broken_limit() {
        metrics.refused(Setting::of_filter_limit(limit));
    }
}

/// Count a read the restricted-kind gate refuses, by the class that
/// refused it.
fn count_read_class(metrics: &Metrics, class: crate::restrict::ReadClass) {
    if let Some(setting) = Setting::of_read_class(class) {
        metrics.refused(setting);
    }
}

/// Reason for a read refused by the restricted-kind gate. NIP-42's
/// `auth-required:` tells the client to authenticate and retry, so it (and the
/// AUTH challenge) is only sent while authenticating can change the outcome.
/// When the relay cannot complete AUTH, or the connection already authenticated
/// with keys the filter is not scoped to, the refusal is `restricted:` so the
/// client does not repeat the same AUTH.
fn read_gate_refusal(
    cfg: &Config,
    conns: &ConnTable,
    metrics: &Metrics,
    auth: &mut HashMap<u64, AuthSession>,
    conn_id: u64,
) -> &'static str {
    if !cfg.auth_usable() {
        return "restricted: requested filter requires authentication, which this relay does not offer";
    }
    if auth
        .get(&conn_id)
        .is_some_and(|session| !session.identities.is_empty())
    {
        return "restricted: requested filter is not scoped to an authenticated pubkey";
    }
    issue_challenge(conns, metrics, auth, conn_id);
    "auth-required: requested filter requires authentication"
}

/// Send the connection's NIP-42 challenge unless it already has one; a session
/// keeps a single challenge so an AUTH signed for it stays valid.
fn issue_challenge(
    conns: &ConnTable,
    metrics: &Metrics,
    auth: &mut HashMap<u64, AuthSession>,
    conn_id: u64,
) {
    if let std::collections::hash_map::Entry::Vacant(e) = auth.entry(conn_id) {
        let challenge = gen_challenge();
        e.insert(AuthSession {
            challenge: challenge.clone(),
            authed: None,
            identities: Vec::new(),
        });
        conns.send(conn_id, RelayMessage::Auth { challenge }, metrics);
    }
}

/// Charge a malformed message, which no command budget covers and which
/// earns an error reply; without this one connection could make the relay
/// answer without bound (#49). A refusal suppresses only the reply: callers
/// still apply any teardown the reply stood for. The first refusal of an
/// exhausted period gets one NOTICE; later ones are dropped silently until
/// the bucket refills.
fn admit_invalid(
    cfg: &Config,
    conns: &ConnTable,
    metrics: &Metrics,
    abuse: &AbuseController,
    source: &TransportSource,
    conn_id: u64,
) -> bool {
    let admission = abuse.admit_source_reporting(source, BudgetKind::Invalid, &cfg.relay.abuse);
    if admission == Admission::Admitted {
        return true;
    }
    metrics
        .abuse_invalid_rate_rejections
        .fetch_add(1, Ordering::Relaxed);
    metrics.refused(Setting::InvalidBurst);
    if admission == Admission::FirstRefusal {
        conns.send(
            conn_id,
            RelayMessage::Notice {
                message: "rate-limited: too many invalid messages; ignoring them until the \
                          budget refills"
                    .into(),
            },
            metrics,
        );
    }
    false
}

/// Charge a REQ, COUNT, NEG-OPEN or NEG-MSG, named by `request`, to its
/// connection's own budget and its address's backstop. `Err` is the
/// refusal reason. These budgets refill, so it is `rate-limited:`.
#[allow(clippy::too_many_arguments)]
fn admit_request(
    cfg: &Config,
    metrics: &Metrics,
    abuse: &AbuseController,
    budgets: &mut HashMap<u64, ConnectionBudgets>,
    auth: &HashMap<u64, AuthSession>,
    conn_id: u64,
    source: &TransportSource,
    (request, command): (Request, &str),
) -> Result<(), String> {
    // Any key can AUTH on an open relay, so the larger budget AUTH earns is
    // the connection's own; the address backstop still applies.
    let authenticated = auth
        .get(&conn_id)
        .is_some_and(|session| session.authed.is_some());
    let budgets = budgets.entry(conn_id).or_default();
    let refusal =
        match abuse.admit_request(budgets, source, request, authenticated, &cfg.relay.abuse) {
            Ok(()) => return Ok(()),
            Err(refusal) => refusal,
        };
    let rejections = match request {
        Request::Count => &metrics.abuse_count_rate_rejections,
        Request::Req | Request::NegMsg => &metrics.abuse_req_rate_rejections,
    };
    rejections.fetch_add(1, Ordering::Relaxed);
    metrics.refused(match (refusal, request) {
        (Refusal::Connection, Request::Req) => Setting::PerConnectionReqBurst,
        (Refusal::Connection, Request::NegMsg) => Setting::PerConnectionNegMsgBurst,
        (Refusal::Connection, Request::Count) => Setting::PerConnectionCountBurst,
        (Refusal::Address, Request::Req | Request::NegMsg) => Setting::ReqBurst,
        (Refusal::Address, Request::Count) => Setting::CountBurst,
    });
    Err(match refusal {
        Refusal::Connection => format!("rate-limited: {command} budget exhausted"),
        Refusal::Address => format!("rate-limited: {command} budget exhausted for this address"),
    })
}

/// NIP-77: a NEG-OPEN or NEG-MSG the relay cannot service is answered with
/// NEG-ERR, after which the subscription is closed. The worker that owns the
/// session sends it, after dropping the session, so no NEG-MSG for this id can
/// follow the error. An id the worker cannot hold is answered directly.
fn neg_err(
    conns: &ConnTable,
    metrics: &Metrics,
    dispatch: &mut Dispatch,
    conn_id: u64,
    sub_id: &str,
    message: String,
) {
    if let Ok(sid) = SubId::new(sub_id) {
        dispatch.neg(NegMsg::Fail {
            conn_id,
            sub_id: sid,
            message,
        });
        return;
    }
    conns.send(
        conn_id,
        RelayMessage::NegErr {
            sub_id: sub_id.to_string(),
            message,
            extra: None,
        },
        metrics,
    );
}

/// NEG-OPEN (`filter` is `Some`) or NEG-MSG. Every refusal that can name the
/// subscription is a NEG-ERR, as is a NEG-OPEN whose sub id is invalid; only
/// a NEG-MSG with an invalid sub id falls back to NOTICE.
#[allow(clippy::too_many_arguments)]
fn ingest_neg_command(
    cfg: &Config,
    conns: &ConnTable,
    metrics: &Metrics,
    abuse: &AbuseController,
    moderation: &parking_lot::RwLock<ModerationSnapshot>,
    source: &TransportSource,
    auth: &mut HashMap<u64, AuthSession>,
    budgets: &mut HashMap<u64, ConnectionBudgets>,
    conn_id: u64,
    sub_id: String,
    filter: Option<Value>,
    payload_hex: String,
    dispatch: &mut Dispatch,
) {
    // A NEG-OPEN starts a scan, so it draws on the REQ budgets. A NEG-MSG
    // continues a session its NEG-OPEN paid for, so a sync pass per group
    // does not use up the REQs a client opens next. Each round still costs a
    // worker B-tree descents, and a session could otherwise stream them
    // forever, so they have a per-connection budget of their own.
    let request = if filter.is_some() {
        (Request::Req, "NEG-OPEN")
    } else {
        (Request::NegMsg, "NEG-MSG")
    };
    let admitted = admit_request(cfg, metrics, abuse, budgets, auth, conn_id, source, request);
    if let Err(reason) = admitted {
        neg_err(conns, metrics, dispatch, conn_id, &sub_id, reason);
        return;
    }
    let sid = match SubId::new(&sub_id) {
        Ok(sid) => sid,
        // A NEG-OPEN is refused like a REQ, with a reply naming its id. No
        // session can have an invalid id, so there is none to close.
        Err(e) if filter.is_some() => {
            let reason = format!("invalid: {e}");
            neg_err(conns, metrics, dispatch, conn_id, &sub_id, reason);
            return;
        }
        Err(e) => {
            conns.send(
                conn_id,
                RelayMessage::notice_error(format!("negentropy error: {e}")),
                metrics,
            );
            return;
        }
    };
    if !cfg.relay.negentropy_enabled {
        metrics.refused(Setting::NegentropyEnabled);
        let reason = "blocked: negentropy is disabled on this relay".to_string();
        neg_err(conns, metrics, dispatch, conn_id, &sub_id, reason);
        return;
    }
    if let Err(reason) = ingest_neg(
        cfg,
        conns,
        metrics,
        moderation,
        auth,
        conn_id,
        sid,
        filter,
        &payload_hex,
        dispatch,
    ) {
        neg_err(conns, metrics, dispatch, conn_id, &sub_id, reason);
    }
}

/// Validate a NEG-OPEN / NEG-MSG and hand it to the negentropy worker. `Err`
/// carries a complete NIP-01-style reason for the caller's NEG-ERR.
#[allow(clippy::too_many_arguments)]
fn ingest_neg(
    cfg: &Config,
    conns: &ConnTable,
    metrics: &Metrics,
    moderation: &parking_lot::RwLock<ModerationSnapshot>,
    auth: &mut HashMap<u64, AuthSession>,
    conn_id: u64,
    sid: SubId,
    filter: Option<Value>,
    payload_hex: &str,
    dispatch: &mut Dispatch,
) -> Result<(), String> {
    // A NEG-OPEN the read policy refuses is refused before its payload is
    // decoded or its filter parsed. NEG-MSG continues a session its
    // NEG-OPEN was admitted for.
    if filter.is_some() {
        admit_reader(cfg, conns, metrics, moderation, auth, conn_id)?;
    }
    if payload_hex.len() > 2 * 1024 * 1024 {
        return Err("invalid: negentropy payload exceeds 1 MiB".into());
    }
    let decode = || wok_event::from_hex_strict(payload_hex).map_err(|e| format!("invalid: {e}"));
    let Some(mut filter) = filter else {
        dispatch.neg(NegMsg::Msg {
            conn_id,
            sub_id: sid,
            payload: decode()?,
        });
        return Ok(());
    };
    if !filter.is_object() {
        return Err("invalid: negentropy filter must be an object".into());
    }
    // A session keeps its filter as a REQ keeps its live filters, so it meets
    // the same size limit before it is parsed.
    if filter.to_string().len() > cfg.relay.max_req_filter_size {
        metrics.refused(Setting::MaxReqFilterSize);
        return Err(format!(
            "invalid: filters exceed {} serialized bytes",
            cfg.relay.max_req_filter_size
        ));
    }
    let max_limit = cfg.relay.max_sync_events.saturating_add(1);
    let fg = NostrFilterGroup::from_value(
        &filter,
        max_limit,
        cfg.relay.max_tags_per_filter,
        cfg.relay.max_and_entries,
    )
    .map_err(|e| {
        count_filter_limit(metrics, &e);
        format!("{}: {e}", e.reason_prefix())
    })?;
    // The rules REQ and COUNT meet, so a sync cannot list what a REQ may not.
    filter_validator(cfg).validate(&fg).map_err(|e| {
        count_filter_limit(metrics, &e);
        format!("blocked: filter validation failed: {e}")
    })?;
    let tag_kind_index = metrics.tag_kind_index_complete.load(Ordering::Relaxed) != 0;
    let query_cost = fg.estimated_cost(CostedRequest::NegOpen, tag_kind_index);
    check_query_work(cfg, metrics, query_cost, "NEG-OPEN")?;
    let r = cfg.read_restrictor();
    if r.is_filter_group_fully_restricted(&fg)
        && auth.get(&conn_id).and_then(|a| a.authed).is_none()
    {
        count_read_class(metrics, r.strictest_group_class(&fg));
        return Err(read_gate_refusal(cfg, conns, metrics, auth, conn_id).into());
    }
    // Decoded only now, once every check that needs no payload has passed.
    let payload = decode()?;
    if let Some(obj) = filter.as_object_mut() {
        obj.remove("since");
        obj.remove("until");
    }
    let filter_str = filter.to_string();
    let sub = Subscription::new(conn_id, sid, fg, false);
    dispatch.neg(NegMsg::Open {
        sub,
        filter_str,
        payload,
    });
    Ok(())
}

/// The setting behind a query the scheduler refuses: a concurrency cap of
/// zero runs none, else the connection's queue, which
/// `max_subs_per_connection` bounds, is full.
fn scheduler_refusal(cfg: &Config) -> Setting {
    if cfg.relay.abuse.max_concurrent_historical_queries == 0 {
        Setting::MaxConcurrentHistoricalQueries
    } else {
        Setting::MaxSubsPerConnection
    }
}

fn read_visibility(cfg: &Config, identities: Vec<[u8; 32]>) -> crate::restrict::ReadVisibility {
    crate::restrict::ReadVisibility {
        restrictor: cfg.read_restrictor(),
        identities,
        ephemeral_lifetime_secs: Some(cfg.events.ephemeral_lifetime_secs),
        include_auth_events: false,
    }
}

/// A read transaction for the req worker, the monitor and the ingester's
/// duplicate pre-check. Tests can make the next few fail for one database
/// (`fault::fail_reads`).
fn begin_read(env: &Env) -> Result<wok_db::RoTxn<'_>, wok_db::DbError> {
    #[cfg(test)]
    if fault::read_fails(env.path()) {
        return Err(wok_db::DbError::msg("injected read failure"));
    }
    env.begin_ro()
}

/// Read failures injected per database path, so parallel tests stay apart.
#[cfg(test)]
mod fault {
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    /// Per database: reads to let through, then reads to fail.
    static READS: Mutex<Vec<(PathBuf, usize, usize)>> = Mutex::new(Vec::new());

    /// Fail the next `count` reads from the database at `path`.
    pub(super) fn fail_reads(path: &Path, count: usize) {
        fail_reads_after(path, 0, count);
    }

    /// Let `skip` reads from the database at `path` through, then fail
    /// `count`.
    pub(super) fn fail_reads_after(path: &Path, skip: usize, count: usize) {
        let mut reads = READS.lock().unwrap();
        reads.retain(|(p, ..)| p != path);
        reads.push((path.to_path_buf(), skip, count));
    }

    pub(super) fn read_fails(path: &Path) -> bool {
        let mut reads = READS.lock().unwrap();
        let Some((_, skip, count)) = reads.iter_mut().find(|(p, ..)| p == path) else {
            return false;
        };
        if *skip != 0 {
            *skip -= 1;
            return false;
        }
        if *count == 0 {
            return false;
        }
        *count -= 1;
        true
    }
}

/// The order a req worker gives time slices in, recorded per database path
/// once a test asks for it.
#[cfg(test)]
mod trace {
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::time::Duration;

    /// The sub id of each query given a slice, and how long the slice took.
    type Log = Vec<(String, Duration)>;

    /// Per traced database.
    static LOGS: Mutex<Vec<(PathBuf, Log)>> = Mutex::new(Vec::new());

    pub(super) fn record(path: &Path) {
        let mut logs = LOGS.lock().unwrap();
        logs.retain(|(p, _)| p != path);
        logs.push((path.to_path_buf(), Vec::new()));
    }

    pub(super) fn slice(path: &Path, sub_id: Option<String>, took: Duration) {
        let mut logs = LOGS.lock().unwrap();
        if let (Some((_, log)), Some(sub_id)) = (logs.iter_mut().find(|(p, _)| p == path), sub_id) {
            log.push((sub_id, took));
        }
    }

    pub(super) fn log(path: &Path) -> Log {
        let logs = LOGS.lock().unwrap();
        logs.iter()
            .find(|(p, _)| p == path)
            .map(|(_, log)| log.clone())
            .unwrap_or_default()
    }

    /// The sub ids given slices, in order.
    pub(super) fn slices(path: &Path) -> Vec<String> {
        log(path).into_iter().map(|(sub_id, _)| sub_id).collect()
    }
}

/// Most messages a req worker takes from its queue in one pass, which bounds
/// how long its read transaction stays open.
const REQ_PASS_MAX: usize = 64;

/// How a req worker splits its time between the queries already running and
/// the new REQs and COUNTs waiting for it. The running queries get a slice
/// when nothing is waiting, or once the new queries' first slices since their
/// last slice have taken as long as that slice did. It is checked before each
/// first slice and at the end of each pass, so new queries go first, and
/// however many keep coming, each stretch of new work as long as the running
/// queries' last slice (overrun by at most one first slice) is followed by a
/// slice of theirs: about half the worker when the two take similar time.
struct RunningShare {
    /// When the running queries' last slice ended, or they started waiting.
    since: std::time::Instant,
    /// How long that slice took.
    took: Duration,
}

impl RunningShare {
    fn new(now: std::time::Instant) -> Self {
        Self {
            since: now,
            took: Duration::ZERO,
        }
    }

    fn due(&self, waiting: bool, now: std::time::Instant) -> bool {
        !waiting || now.saturating_duration_since(self.since) >= self.took
    }

    fn ran(&mut self, started: std::time::Instant, ended: std::time::Instant) {
        self.took = ended.saturating_duration_since(started);
        self.since = ended;
    }

    /// Give the running queries their slice, timing it.
    fn slice(&mut self, slice: impl FnOnce()) {
        let started = std::time::Instant::now();
        slice();
        self.ran(started, std::time::Instant::now());
    }
}

/// A req worker pass takes every message already queued (up to `REQ_PASS_MAX`)
/// and applies them in order under one read transaction. Cancels, AUTH and
/// teardown cost no query time. Each new REQ or COUNT is scheduled and given
/// its first slice at once, so a small one is answered within the pass, before
/// the messages behind it. strfry's ReqWorker drains its inbox the same way.
///
/// The running query that has waited longest gets a slice ahead of a new
/// query whenever its share is due, and at the end of the pass unless more
/// messages are waiting and it is not (see `RunningShare`).
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
        initial_cfg.relay.max_filter_limit_count.saturating_add(1),
    );
    drop(initial_cfg);
    queries.set_completeness(true);
    let mut authed: HashMap<u64, Vec<[u8; 32]>> = HashMap::new();
    let mut decomp = Decompressor::new();
    let mut pass = Vec::with_capacity(REQ_PASS_MAX);
    let worker = ReqWorker {
        conns: &conns,
        metrics: &metrics,
        mon_txs: &mon_txs,
    };
    let mut share = RunningShare::new(std::time::Instant::now());
    let mut open = true;
    while open {
        if !queries.has_running() {
            match rx.recv() {
                Ok(msg) => pass.push(msg),
                Err(_) => break,
            }
            share = RunningShare::new(std::time::Instant::now());
        }
        while pass.len() < REQ_PASS_MAX {
            match rx.try_recv() {
                Ok(msg) => pass.push(msg),
                Err(crossbeam_channel::TryRecvError::Empty) => break,
                // Answer what was taken, then stop: running queries are
                // not finished for a relay that is shutting down.
                Err(crossbeam_channel::TryRecvError::Disconnected) => {
                    open = false;
                    break;
                }
            }
        }
        {
            let cfg_snap = cfg.read();
            queries.set_max_subs_per_connection(
                cfg_snap.relay.abuse.max_concurrent_historical_queries,
            );
            // REQs and COUNTs over the concurrency cap wait their turn (#97
            // F2). Open REQs are capped at this already, so the bound is
            // reached only with COUNTs.
            queries.set_max_waiting_per_connection(cfg_snap.relay.max_subs_per_connection);
            queries.set_max_total_events_per_req(cfg_snap.relay.max_total_events_per_req);
            queries.set_count_dedup_budget(cfg_snap.relay.max_filter_limit_count.saturating_add(1));
        }
        // Opened after the messages were taken, so it sees everything up to
        // each REQ's snapshot, fixed at admission before the REQ was queued.
        // Without it a REQ or COUNT is refused rather than dropped: a
        // registered REQ would otherwise never get EOSE or CLOSED.
        let txn = begin_read(&env)
            .inspect_err(|error| tracing::warn!(%error, "req worker cannot read the database"))
            .ok();
        for msg in pass.drain(..) {
            match msg {
                ReqMsg::Scan(sub) | ReqMsg::Count(sub) => {
                    let (conn, sub_id, generation, count_only) = (
                        sub.conn_id,
                        sub.sub_id.clone(),
                        sub.generation,
                        sub.count_only,
                    );
                    let reason = match &txn {
                        Some(txn) => {
                            if queries.has_running() && share.due(true, std::time::Instant::now()) {
                                let cfg_snap = cfg.read();
                                share.slice(|| {
                                    worker.slice(&mut queries, txn, &cfg_snap, &authed, &mut decomp)
                                });
                            }
                            // With nothing running, this slice starts the share.
                            let idle = !queries.has_running();
                            match queries.add_sub(txn, sub) {
                                Ok(Scheduled::Running) => {
                                    // The new query is first in the run queue.
                                    let cfg_snap = cfg.read();
                                    let mut first = || {
                                        worker.slice(
                                            &mut queries,
                                            txn,
                                            &cfg_snap,
                                            &authed,
                                            &mut decomp,
                                        )
                                    };
                                    if idle {
                                        share.slice(first);
                                    } else {
                                        first();
                                    }
                                    None
                                }
                                // Its scan starts when one of the connection's
                                // running ones ends.
                                Ok(Scheduled::Waiting) => None,
                                Ok(Scheduled::Refused) => {
                                    metrics
                                        .abuse_query_concurrency_rejections
                                        .fetch_add(1, Ordering::Relaxed);
                                    let cfg_snap = cfg.read();
                                    metrics.refused(scheduler_refusal(&cfg_snap));
                                    Some(
                                        if cfg_snap.relay.abuse.max_concurrent_historical_queries
                                            == 0
                                        {
                                            "rate-limited: too many concurrent historical queries"
                                        } else {
                                            "rate-limited: too many historical queries waiting on \
                                             this connection"
                                        },
                                    )
                                }
                                Err(_) => Some("error: history scan could not start"),
                            }
                        }
                        None => {
                            // The query this one replaces ends with it, as
                            // `add_sub` would have ended it.
                            queries.remove_query(conn, &sub_id, count_only);
                            Some("error: history scan could not start")
                        }
                    };
                    if let Some(reason) = reason {
                        worker.refuse(conn, sub_id, generation, count_only, reason);
                    }
                }
                ReqMsg::SetAuth {
                    conn_id,
                    authed: pk,
                } => {
                    let identities = authed.entry(conn_id).or_default();
                    if !identities.contains(&pk) {
                        identities.push(pk);
                    }
                }
                ReqMsg::Cancel {
                    conn_id,
                    sub_id,
                    generation,
                    count_only,
                } => {
                    queries.remove_generation(conn_id, &sub_id, count_only, generation);
                }
                ReqMsg::Close { conn_id } => {
                    authed.remove(&conn_id);
                    queries.close_conn(conn_id);
                }
            }
        }
        if let Some(txn) = &txn {
            let waiting = !rx.is_empty();
            if open && queries.has_running() && share.due(waiting, std::time::Instant::now()) {
                let cfg_snap = cfg.read();
                share.slice(|| worker.slice(&mut queries, txn, &cfg_snap, &authed, &mut decomp));
            }
        }
    }
}

/// What a req worker delivers to.
struct ReqWorker<'a> {
    conns: &'a ConnTable,
    metrics: &'a Metrics,
    mon_txs: &'a [Sender<MonitorMsg>],
}

impl ReqWorker<'_> {
    /// A REQ or COUNT that will send no (more) history: its CLOSED goes through
    /// the gate as the generation's last frame, and a REQ's registration with
    /// the monitor is dropped.
    fn refuse(&self, conn_id: u64, sub_id: SubId, generation: u64, count_only: bool, reason: &str) {
        let ns = if count_only { Ns::Count } else { Ns::Req };
        let closed = RelayMessage::closed_error(sub_id.as_str(), reason);
        self.conns
            .send_last(conn_id, ns, &sub_id, generation, closed, self.metrics);
        if !count_only {
            let _ = route_tx(self.mon_txs, conn_id).send(MonitorMsg::Remove {
                conn_id,
                sub_id,
                generation,
            });
        }
    }

    /// Give the first query in the run queue one time slice, and answer it if
    /// that finished it.
    fn slice(
        &self,
        queries: &mut QueryScheduler,
        txn: &wok_db::RoTxn<'_>,
        cfg: &Config,
        authed: &HashMap<u64, Vec<[u8; 32]>>,
        decomp: &mut Decompressor,
    ) {
        // The ingester admitted each query by the read policy of its time.
        // One that waited behind its connection's running scans, or in this
        // worker's channel, across a reload or a member's removal is refused
        // before it reads anything more, as a running one is at its next
        // slice.
        if let Some(sub) = queries.next_query() {
            let identities = authed.get(&sub.conn_id).map_or(&[][..], Vec::as_slice);
            let admitted = stored_reader_admitted(txn, cfg, identities);
            if matches!(admitted, Ok(false)) {
                self.metrics.refused(Setting::ReadPolicy);
            }
            if !admitted.unwrap_or(false) {
                let refusal = read_policy_refusal(cfg, !identities.is_empty());
                let (conn_id, sub_id, generation, count_only) = (
                    sub.conn_id,
                    sub.sub_id.clone(),
                    sub.generation,
                    sub.count_only,
                );
                queries.remove_query(conn_id, &sub_id, count_only);
                self.refuse(conn_id, sub_id, generation, count_only, &refusal);
                return;
            }
        }
        #[cfg(test)]
        let traced = (
            queries.next_query().map(|sub| sub.sub_id.to_string()),
            std::time::Instant::now(),
        );
        let (conns, metrics) = (self.conns, self.metrics);
        let mut completed: Option<Completed> = None;
        // Events are framed and delivered inside the scan callback: no
        // per-event Subscription clone, no intermediate collection, and the
        // payload JSON is copied exactly once (into the frame).
        let scanned = queries.process_visible(
            txn,
            cfg.relay.query_timeslice_budget_us,
            |sub| read_visibility(cfg, authed.get(&sub.conn_id).cloned().unwrap_or_default()),
            |sub, _lev, payload| {
                if sub.count_only {
                    return true;
                }
                // A payload that does not decode, such as a compressed one
                // larger than a lowered `events.max_event_size`, is skipped.
                let Some(Ok(json)) =
                    payload.map(|raw| decomp.decode(txn, raw, cfg.events.max_event_size))
                else {
                    return false;
                };
                conns.send_event(sub.conn_id, &sub.sub_id, sub.generation, json, metrics);
                true
            },
            |sub, total, hll, dedup_limited, completeness| {
                completed = Some(Completed {
                    conn_id: sub.conn_id,
                    sub_id: sub.sub_id.clone(),
                    generation: sub.generation,
                    count_only: sub.count_only,
                    snapshot: sub.latest_event_id,
                    total,
                    hll,
                    dedup_limited,
                    hints: EoseHints {
                        // Authenticating, which a challenge sent before this
                        // EOSE allows, may reveal what the rule hid. Once the
                        // connection has authenticated it hides events of
                        // other pubkeys, as a refusal says `restricted:`.
                        auth: completeness.restricted
                            && sub.auth_challenged
                            && cfg.auth_usable()
                            && authed.get(&sub.conn_id).is_none_or(Vec::is_empty),
                        finish: completeness.finish,
                        more: completeness.more,
                    },
                });
            },
        );
        #[cfg(test)]
        trace::slice(txn.env().path(), traced.0, traced.1.elapsed());
        if let Err(failure) = scanned {
            tracing::warn!(
                conn_id = failure.sub.conn_id,
                sub_id = ?failure.sub.sub_id.as_str(),
                error = %failure.error,
                "historical query failed"
            );
            let sub = failure.sub;
            self.refuse(
                sub.conn_id,
                sub.sub_id,
                sub.generation,
                sub.count_only,
                "error: history scan failed",
            );
        }
        let Some(done) = completed else {
            return;
        };
        tracing::debug!(
            conn_id = done.conn_id,
            sub_id = ?done.sub_id.as_str(),
            count_only = done.count_only,
            matched_events = done.total,
            hll = done.hll.is_some(),
            "historical query completed"
        );
        if done.count_only {
            let mut count = done.total;
            let mut limited = done.dedup_limited;
            if count > cfg.relay.max_filter_limit_count {
                count = cfg.relay.max_filter_limit_count;
                limited = true;
            }
            let reply = RelayMessage::Count {
                sub_id: done.sub_id.to_string(),
                count,
                limited,
                hll: if limited { None } else { done.hll },
            };
            conns.send_last(
                done.conn_id,
                Ns::Count,
                &done.sub_id,
                done.generation,
                reply,
                metrics,
            );
        } else {
            // The monitor sends EOSE and goes live. No reply is awaited, so a
            // busy monitor never holds up other queries here.
            let _ = route_tx(self.mon_txs, done.conn_id).send(MonitorMsg::HistoryDone {
                conn_id: done.conn_id,
                sub_id: done.sub_id,
                generation: done.generation,
                snapshot: done.snapshot,
                hints: done.hints,
            });
        }
    }
}

/// A history scan the req worker finished.
struct Completed {
    conn_id: u64,
    sub_id: SubId,
    generation: u64,
    count_only: bool,
    /// Newest local event id the scan could return.
    snapshot: u64,
    total: u64,
    hll: Option<String>,
    dedup_limited: bool,
    /// NIP-67 hints for a REQ's EOSE.
    hints: EoseHints,
}

/// Matches a req monitor sends live: connection, subscription and the
/// generation the match was for.
type LiveRecipients = Vec<(u64, SubId, u64)>;

/// Route `recipients` of a stored event: live subscriptions whose connection
/// may read it are returned for delivery. Pending ones buffer its id either
/// way: the connection may AUTH before EOSE, and what the buffer holds is
/// checked against the read policy when it is sent.
fn route_stored_match(
    monitors: &mut ActiveMonitors,
    recipients: Vec<wok_query::Recipient>,
    readable: impl Fn(u64) -> bool,
    lev_id: u64,
    metrics: &Metrics,
) -> LiveRecipients {
    let mut live = Vec::new();
    for recipient in recipients {
        if recipient.pending {
            if let Some(buffer) = monitors.pending_mut(recipient.conn_id, &recipient.sub_id) {
                if buffer.push_stored(lev_id) {
                    metrics
                        .live_buffer_overflows
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
        } else if readable(recipient.conn_id) {
            live.push((recipient.conn_id, recipient.sub_id, recipient.generation));
        }
    }
    live
}

/// Send `sub` the stored events in `from..=to` it may read, as live events.
#[allow(clippy::too_many_arguments)]
fn send_stored_range(
    snapshot: &crate::restrict::ReadSnapshot<'_>,
    decomp: &mut Decompressor,
    conns: &ConnTable,
    metrics: &Metrics,
    max_event_size: usize,
    sub: &Subscription,
    visibility: &crate::restrict::ReadVisibility,
    from: u64,
    to: u64,
) {
    let txn = snapshot.txn();
    let requires_content = sub.filter_group.requires_content();
    let _ = wok_db::foreach_event_from(txn, from, |lev, packed_bytes| {
        if lev > to {
            return false;
        }
        let Ok(packed) = PackedEventView::new(packed_bytes) else {
            return true;
        };
        if !visibility.allows(snapshot, packed).unwrap_or(false)
            || (!requires_content && !sub.filter_group.does_match(packed))
        {
            return true;
        }
        let Some(raw) = txn
            .get_u64(txn.env().dbis().event_payload, lev)
            .ok()
            .flatten()
        else {
            return true;
        };
        let Ok(json) = decomp.decode(txn, raw, max_event_size) else {
            return true;
        };
        if requires_content {
            let search_terms = wok_db::event_search_terms(json).unwrap_or_default();
            if !sub
                .filter_group
                .does_match_with_search_terms(packed, Some(&search_terms))
            {
                return true;
            }
        }
        conns.send_event(sub.conn_id, &sub.sub_id, sub.generation, json, metrics);
        true
    });
}

/// Send one buffered stored event, if it still exists and is still readable.
#[allow(clippy::too_many_arguments)]
fn send_buffered_stored(
    snapshot: &crate::restrict::ReadSnapshot<'_>,
    decomp: &mut Decompressor,
    conns: &ConnTable,
    metrics: &Metrics,
    max_event_size: usize,
    conn_id: u64,
    sub_id: &SubId,
    generation: u64,
    visibility: &crate::restrict::ReadVisibility,
    lev_id: u64,
) {
    let txn = snapshot.txn();
    let dbis = txn.env().dbis();
    let Some(packed) = txn
        .get_u64(dbis.event, lev_id)
        .ok()
        .flatten()
        .and_then(|raw| PackedEventView::new(raw).ok())
    else {
        return;
    };
    if !visibility.allows(snapshot, packed).unwrap_or(false) {
        return;
    }
    let Some(raw) = txn.get_u64(dbis.event_payload, lev_id).ok().flatten() else {
        return;
    };
    if let Ok(json) = decomp.decode(txn, raw, max_event_size) {
        conns.send_event(conn_id, sub_id, generation, json, metrics);
    }
}

fn run_req_monitor(
    env: Env,
    cfg: Arc<parking_lot::RwLock<Config>>,
    conns: Arc<ConnTable>,
    metrics: Arc<Metrics>,
    moderation: Arc<parking_lot::RwLock<ModerationSnapshot>>,
    rx: Receiver<MonitorMsg>,
    data_rx: Receiver<MonitorData>,
) {
    // The ingester caps subscriptions per connection before registering them.
    let mut monitors = ActiveMonitors::new(usize::MAX);
    let mut authed: HashMap<u64, Vec<[u8; 32]>> = HashMap::new();
    // Newest local event id already matched against every subscription.
    let mut curr_event_id = u64::MAX;
    let mut decomp = Decompressor::new();
    let (mut rx, mut data_rx) = (rx, data_rx);
    let (mut control_open, mut data_open) = (true, true);
    let mut control = Vec::new();
    let mut data = Vec::new();
    let mut retry = false;
    loop {
        // After a failed read, retry shortly with what was kept.
        let retry_timer = if retry {
            crossbeam_channel::after(Duration::from_millis(10))
        } else {
            crossbeam_channel::never()
        };
        crossbeam_channel::select! {
            recv(rx) -> msg => match msg {
                Ok(msg) => control.push(msg),
                Err(_) => control_open = false,
            },
            recv(data_rx) -> msg => match msg {
                Ok(msg) => data.push(msg),
                Err(_) => data_open = false,
            },
            recv(retry_timer) -> _ => {}
        }
        // A closed queue never wakes the monitor again; it stops once both are.
        if !control_open {
            rx = crossbeam_channel::never();
        }
        if !data_open {
            data_rx = crossbeam_channel::never();
        }
        if !control_open && !data_open {
            break;
        }
        // Data first, then control. Every subscription change sent before a
        // data message taken here is then in `control`, and changes are
        // applied first: a REQ sees every event sent after its registration
        // and some sent just before, CLOSE stops delivery sooner, and EOSE
        // does not wait behind the batch's fan-out.
        data.extend(data_rx.try_iter());
        control.extend(rx.try_iter());
        if control.is_empty() && data.is_empty() {
            retry = false;
            continue;
        }
        let cfg_snap = cfg.read();
        let r = cfg_snap.read_restrictor();
        let global_visibility = read_visibility(&cfg_snap, vec![]);
        let max_event_size = cfg_snap.events.max_event_size;
        let txn = match begin_read(&env) {
            Ok(t) => t,
            Err(error) => {
                // Subscription changes are sent once, so keep them and retry
                // shortly; a lost one would leave a REQ without EOSE or
                // CLOSED. One DbChange is enough, for handed-off commits too:
                // the next scan resumes from the same cursor. Live-only events
                // are dropped.
                tracing::warn!(%error, "req monitor cannot read the database");
                let db_change = data
                    .iter()
                    .any(|m| matches!(m, MonitorData::DbChange | MonitorData::Stored(_)));
                data.clear();
                if db_change {
                    data.push(MonitorData::DbChange);
                }
                retry = true;
                continue;
            }
        };
        retry = false;
        // The clock and which policy tables can hide an event, read once for
        // the batch rather than for each event.
        let read_snapshot = crate::restrict::ReadSnapshot::for_stored(&txn);
        let latest = most_recent_levid_ro(&txn).unwrap_or(0);
        if curr_event_id > latest {
            curr_event_id = latest;
        }
        let identities = |authed: &HashMap<u64, Vec<[u8; 32]>>, conn_id: u64| {
            authed.get(&conn_id).cloned().unwrap_or_default()
        };
        // A connection the read policy no longer admits, such as a member
        // removed or an anonymous one after a reload to `authenticated`,
        // reads no more of the subscriptions it was admitted to.
        let still_admitted =
            |identities: &[[u8; 32]]| reader_admitted(&cfg_snap, &moderation, identities);
        for msg in control.drain(..) {
            match msg {
                MonitorMsg::Register(mut sub) => {
                    // Stored events after the REQ's history snapshot are the
                    // monitor's. Those it already matched are re-read when the
                    // history is done; everything it matches from here on is
                    // held until then.
                    let live_from = curr_event_id.max(sub.latest_event_id);
                    sub.latest_event_id = live_from;
                    let buffer =
                        PendingBuffer::new(live_from, cfg_snap.relay.max_live_buffer_bytes);
                    monitors.add_pending(sub, buffer);
                }
                MonitorMsg::Remove {
                    conn_id,
                    sub_id,
                    generation,
                } => {
                    // A later REQ may already have taken the id.
                    if monitors
                        .subscription(conn_id, &sub_id)
                        .is_some_and(|sub| sub.generation == generation)
                    {
                        monitors.remove_sub(conn_id, &sub_id);
                    }
                }
                MonitorMsg::HistoryDone {
                    conn_id,
                    sub_id,
                    generation,
                    snapshot,
                    hints,
                } => {
                    // Closed or replaced since: its history was for nothing.
                    if monitors.pending_generation(conn_id, &sub_id) != Some(generation) {
                        continue;
                    }
                    let buffer = monitors.pending_mut(conn_id, &sub_id).unwrap();
                    // Stored events after the history snapshot that the buffer
                    // lacks are re-read: all of them once it overflowed, else
                    // those this monitor matched before it saw the
                    // registration. The buffer holds only later ones.
                    let reread_to = if buffer.stored_overflowed() {
                        curr_event_id
                    } else {
                        buffer.live_from()
                    };
                    let delivered = snapshot.max(reread_to);
                    let buffer = monitors
                        .finish_pending(conn_id, &sub_id, generation, delivered)
                        .unwrap();
                    // NIP-01: EOSE ends stored events; what arrived while the
                    // history was sent is "newly received" and follows it.
                    // The hints are about the history, up to its snapshot.
                    let eose = RelayMessage::Eose {
                        sub_id: sub_id.to_string(),
                        hints,
                    };
                    conns.send_sub(conn_id, &sub_id, generation, eose, &metrics);
                    let identities = identities(&authed, conn_id);
                    if !still_admitted(&identities) {
                        continue;
                    }
                    let visibility = read_visibility(&cfg_snap, identities);
                    if reread_to > snapshot {
                        let sub = monitors.subscription(conn_id, &sub_id).unwrap();
                        send_stored_range(
                            &read_snapshot,
                            &mut decomp,
                            &conns,
                            &metrics,
                            max_event_size,
                            sub,
                            &visibility,
                            snapshot.saturating_add(1),
                            reread_to,
                        );
                    }
                    // Held events were matched against the policy of their
                    // time; send only what this connection may still read.
                    for event in buffer.into_events() {
                        match event {
                            PendingEvent::Stored(lev) => send_buffered_stored(
                                &read_snapshot,
                                &mut decomp,
                                &conns,
                                &metrics,
                                max_event_size,
                                conn_id,
                                &sub_id,
                                generation,
                                &visibility,
                                lev,
                            ),
                            PendingEvent::Ephemeral(event) => {
                                let readable =
                                    PackedEventView::new(&event.packed).is_ok_and(|packed| {
                                        visibility.allows(&read_snapshot, packed).unwrap_or(false)
                                    });
                                if readable {
                                    conns.send_event(
                                        conn_id,
                                        &sub_id,
                                        generation,
                                        &event.json,
                                        &metrics,
                                    );
                                }
                            }
                        }
                    }
                }
                MonitorMsg::SetAuth {
                    conn_id,
                    authed: pk,
                } => {
                    let identities = authed.entry(conn_id).or_default();
                    if !identities.contains(&pk) {
                        identities.push(pk);
                    }
                }
                MonitorMsg::Close { conn_id } => {
                    authed.remove(&conn_id);
                    monitors.close_conn(conn_id);
                }
            }
        }
        for msg in data.drain(..) {
            let batch = match msg {
                MonitorData::Ephemeral(held) => {
                    let (live, pending) = {
                        let Ok(event) = PackedEventView::new(&held.packed) else {
                            continue;
                        };
                        // Live-only events skip the database, but not the
                        // moderation policy: id/author/kind checks all apply.
                        if !global_visibility
                            .globally_visible(&read_snapshot, event)
                            .unwrap_or(false)
                        {
                            continue;
                        }
                        let search_terms = if monitors.event_requires_content(event) {
                            Some(wok_db::event_search_terms(&held.json).unwrap_or_default())
                        } else {
                            None
                        };
                        let recipients = monitors.process_ephemeral(event, search_terms.as_ref());
                        let mut live = Vec::new();
                        let mut pending = Vec::new();
                        for recipient in recipients {
                            // Held whatever the connection may read now, as
                            // stored matches are: checked when sent.
                            if recipient.pending {
                                pending.push((recipient.conn_id, recipient.sub_id));
                                continue;
                            }
                            let pk = authed
                                .get(&recipient.conn_id)
                                .map(|authed| authed.as_slice())
                                .unwrap_or(&[]);
                            if r.should_send_to_identities(event, pk) && still_admitted(pk) {
                                live.push((
                                    recipient.conn_id,
                                    recipient.sub_id,
                                    recipient.generation,
                                ));
                            }
                        }
                        (live, pending)
                    };
                    conns.send_event_batch(&live, &held.json, &metrics);
                    // One copy shared by every pending subscription it matches.
                    for (conn_id, sub_id) in pending {
                        if let Some(buffer) = monitors.pending_mut(conn_id, &sub_id) {
                            let (dropped, overflowed) = buffer.push_ephemeral(held.clone());
                            metrics
                                .live_buffer_dropped_ephemeral
                                .fetch_add(dropped, Ordering::Relaxed);
                            if overflowed {
                                metrics
                                    .live_buffer_overflows
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    continue;
                }
                MonitorData::DbChange => None,
                // Already matched, by a read of a later commit.
                MonitorData::Stored(batch) if batch.last <= curr_event_id => continue,
                // Something was stored before the batch that this monitor
                // was not handed: read it all from LMDB instead.
                MonitorData::Stored(batch) => {
                    (batch.first <= curr_event_id.saturating_add(1)).then_some(batch)
                }
            };
            let readable = |conn_id: u64, packed: PackedEventView<'_>| {
                let pk = authed.get(&conn_id).map(|a| a.as_slice()).unwrap_or(&[]);
                r.should_send_to_identities(packed, pk) && still_admitted(pk)
            };
            let Some(batch) = batch else {
                let start = curr_event_id.saturating_add(1);
                let _ = wok_db::foreach_event_from(&txn, start, |lev, packed_bytes| {
                    let Ok(packed) = PackedEventView::new(packed_bytes) else {
                        return true;
                    };
                    if !global_visibility
                        .globally_visible(&read_snapshot, packed)
                        .unwrap_or(false)
                    {
                        return true;
                    }
                    let payload = || {
                        txn.get_u64(txn.env().dbis().event_payload, lev)
                            .ok()
                            .flatten()
                    };
                    let recipients = if monitors.event_requires_content(packed) {
                        let Some(raw) = payload() else {
                            return true;
                        };
                        let Ok(json) = decomp.decode(&txn, raw, max_event_size) else {
                            return true;
                        };
                        let search_terms = wok_db::event_search_terms(json).unwrap_or_default();
                        monitors.process(lev, packed, Some(&search_terms))
                    } else {
                        monitors.process(lev, packed, None)
                    };
                    if recipients.is_empty() {
                        return true;
                    }
                    let live = route_stored_match(
                        &mut monitors,
                        recipients,
                        |conn_id| readable(conn_id, packed),
                        lev,
                        &metrics,
                    );
                    if live.is_empty() {
                        return true;
                    }
                    if let Some(raw) = payload() {
                        if let Ok(json) = decomp.decode(&txn, raw, max_event_size) {
                            conns.send_event_batch(&live, json, &metrics);
                        }
                    }
                    true
                });
                curr_event_id = latest;
                continue;
            };
            for event in batch.events.iter().filter(|e| e.lev_id > curr_event_id) {
                let Ok(packed) = PackedEventView::new(&event.packed) else {
                    continue;
                };
                // Checked in this monitor's read: since the commit, a later
                // one (or a later event of the same commit) can have deleted
                // it, and a ban, vanish request or expiry can hide it.
                let stored = txn
                    .get_u64(txn.env().dbis().event, event.lev_id)
                    .is_ok_and(|stored| stored.is_some());
                if !stored
                    || !global_visibility
                        .globally_visible(&read_snapshot, packed)
                        .unwrap_or(false)
                {
                    continue;
                }
                let recipients = if monitors.event_requires_content(packed) {
                    let search_terms = event.search_terms.get_or_init(|| {
                        wok_db::event_search_terms(&event.json).unwrap_or_default()
                    });
                    monitors.process(event.lev_id, packed, Some(search_terms))
                } else {
                    monitors.process(event.lev_id, packed, None)
                };
                if recipients.is_empty() {
                    continue;
                }
                let live = route_stored_match(
                    &mut monitors,
                    recipients,
                    |conn_id| readable(conn_id, packed),
                    event.lev_id,
                    &metrics,
                );
                conns.send_event_batch(&live, &event.json, &metrics);
            }
            curr_event_id = batch.last;
        }
    }
}

#[cfg(test)]
#[path = "review_regressions.rs"]
mod review_regressions;

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

    // The default 10 TiB map is reserved per env; tests that never grow the
    // database keep it small so parallel runs do not exhaust address space.
    fn small_map_env_options() -> EnvOptions {
        EnvOptions {
            map_size: 64 * 1024 * 1024,
            ..EnvOptions::default()
        }
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

    fn revocation(pubkey: [u8; 32], ban: bool) -> ManagementCmd {
        if ban {
            ManagementCmd::BanPubkey {
                pubkey,
                reason: "revoked".into(),
            }
        } else {
            ManagementCmd::UnallowPubkey { pubkey }
        }
    }

    #[test]
    fn same_batch_revocation_precedes_ordinary_writes_but_not_vanish() {
        // A ban or allowlist revocation committed after the ingester's
        // snapshot check still refuses an ordinary event. NIP-62 requires
        // vanish to be honored regardless of the user's status, so a vanish
        // request is still written.
        for ban in [true, false] {
            for kind in [1, VANISH_KIND] {
                same_batch_revocation_case(kind, ban);
            }
        }
    }

    fn same_batch_revocation_case(kind: u64, ban: bool) {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();

        let mut config = Config::default();
        config.db = dir.path().to_path_buf();
        config.relay.nip62.enabled = true;
        config.relay.nip62.service_url = "wss://relay.example.com".into();
        config.relay.auth.write_policy = crate::config::AccessPolicy::Members;
        let config = Arc::new(parking_lot::RwLock::new(config));
        let conns = Arc::new(ConnTable::new());
        let metrics = Arc::new(Metrics::default());
        let author = [kind as u8; 32];
        let mut txn = env.begin_rw().unwrap();
        wok_db::allow_pubkey(&mut txn, &author, "").unwrap();
        txn.commit().unwrap();
        let moderation = Arc::new(parking_lot::RwLock::new(
            env.begin_ro()
                .and_then(|txn| load_moderation_snapshot_ro(&txn))
                .unwrap(),
        ));
        let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel();
        conns.insert(1, Outbound::new(out_tx, 0));

        let id = [(kind as u8).saturating_add(1); 32];
        let tags = PackedEventTagBuilder::default();
        let packed = PackedEventBuilder::build(&id, &author, 1, kind, 0, &tags).unwrap();
        let json = json!({
            "id": to_hex(&id),
            "pubkey": to_hex(&author),
            "created_at": 1,
            "kind": kind,
            "tags": [["relay", "ALL_RELAYS"]],
            "content": "",
            "sig": "00".repeat(64),
        })
        .to_string();

        let (writer_tx, writer_rx) = bounded(4);
        writer_tx
            .send(WriterMsg::AddEvent {
                conn_id: 1,
                source: TransportSource::ip_address("127.0.0.1".parse().unwrap()),
                packed: packed.into_bytes(),
                json,
                authed: None,
                grant: WriteGrant {
                    authenticated: false,
                    member: Some(author),
                    inbox: false,
                },
            })
            .unwrap();
        let (reply, reply_rx) = tokio::sync::oneshot::channel();
        writer_tx
            .send(WriterMsg::Management(ManagementMsg {
                cmd: revocation(author, ban),
                reply,
            }))
            .unwrap();
        drop(writer_tx);

        run_writer(
            env.clone(),
            config,
            conns,
            metrics,
            writer_rx,
            Vec::new(),
            moderation,
            TAG_KIND_STEP,
        );

        assert!(reply_rx.blocking_recv().unwrap().is_ok());
        let response = out_rx.try_recv().unwrap().into_text();
        let txn = env.begin_ro().unwrap();
        if kind == VANISH_KIND {
            assert!(response.contains("true"), "{response}");
            assert_eq!(txn.entries(env.dbis().event).unwrap(), 1);
        } else {
            assert!(response.contains("false"), "{response}");
            let refusal = if ban {
                "author is banned"
            } else {
                "accepts events only from members"
            };
            assert!(response.contains(refusal), "{response}");
            assert_eq!(txn.entries(env.dbis().event).unwrap(), 0);
        }
    }

    /// A gift wrap admitted because its recipient is a member is refused
    /// when a reload drops its kind from `inbox_kinds` before the writer
    /// takes it: the grant records that it depends on that list.
    #[test]
    fn queued_inbox_writes_follow_the_writers_inbox_kinds() {
        for inbox_kinds in [vec![1059], vec![]] {
            let dir = tempfile::tempdir().unwrap();
            let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
            env.ensure_initialized().unwrap();
            let mut config = Config::default();
            config.db = dir.path().to_path_buf();
            config.relay.auth.service_url = "wss://relay.example.com".into();
            config.relay.auth.write_policy = crate::config::AccessPolicy::Members;
            config.relay.auth.inbox_kinds = inbox_kinds.clone();
            let config = Arc::new(parking_lot::RwLock::new(config));
            let conns = Arc::new(ConnTable::new());
            let (recipient, wrapper) = ([7u8; 32], [8u8; 32]);
            let mut txn = env.begin_rw().unwrap();
            wok_db::allow_pubkey(&mut txn, &recipient, "").unwrap();
            txn.commit().unwrap();
            let moderation = Arc::new(parking_lot::RwLock::new(
                env.begin_ro()
                    .and_then(|txn| load_moderation_snapshot_ro(&txn))
                    .unwrap(),
            ));
            let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel();
            conns.insert(1, Outbound::new(out_tx, 0));

            let id = [9u8; 32];
            let mut tags = PackedEventTagBuilder::default();
            tags.add('p', &recipient).unwrap();
            let packed = PackedEventBuilder::build(&id, &wrapper, 1, 1059, 0, &tags).unwrap();
            let json = json!({
                "id": to_hex(&id),
                "pubkey": to_hex(&wrapper),
                "created_at": 1,
                "kind": 1059,
                "tags": [["p", to_hex(&recipient)]],
                "content": "",
                "sig": "00".repeat(64),
            })
            .to_string();
            let (writer_tx, writer_rx) = bounded(4);
            // Granted while 1059 was an inbox kind.
            writer_tx
                .send(WriterMsg::AddEvent {
                    conn_id: 1,
                    source: TransportSource::ip_address("127.0.0.1".parse().unwrap()),
                    packed: packed.into_bytes(),
                    json,
                    authed: None,
                    grant: WriteGrant {
                        authenticated: false,
                        member: Some(recipient),
                        inbox: true,
                    },
                })
                .unwrap();
            drop(writer_tx);
            run_writer(
                env.clone(),
                config,
                conns,
                Arc::new(Metrics::default()),
                writer_rx,
                Vec::new(),
                moderation,
                TAG_KIND_STEP,
            );

            let response = out_rx.try_recv().unwrap().into_text();
            let stored = env.begin_ro().unwrap().entries(env.dbis().event).unwrap();
            if inbox_kinds.is_empty() {
                assert!(
                    response.contains("accepts events only from members"),
                    "{response}"
                );
                assert_eq!(stored, 0);
            } else {
                assert!(response.contains("true"), "{response}");
                assert_eq!(stored, 1);
            }
        }
    }

    /// An event the ingester admitted is refused when a reload has dropped
    /// its kind from `accepted_kinds` before the writer takes it, but a
    /// vanish request is still honored (NIP-62).
    #[test]
    fn the_writer_applies_its_own_accepted_kinds() {
        for (kind, stored) in [(7, false), (VANISH_KIND, true)] {
            let dir = tempfile::tempdir().unwrap();
            let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
            env.ensure_initialized().unwrap();
            let mut config = Config::default();
            config.db = dir.path().to_path_buf();
            config.relay.auth.accepted_kinds = vec![1];
            let conns = Arc::new(ConnTable::new());
            let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel();
            conns.insert(1, Outbound::new(out_tx, 0));
            let (id, author) = ([9u8; 32], [8u8; 32]);
            let tags = PackedEventTagBuilder::default();
            let packed = PackedEventBuilder::build(&id, &author, 1, kind, 0, &tags).unwrap();
            let json = json!({
                "id": to_hex(&id), "pubkey": to_hex(&author), "created_at": 1, "kind": kind,
                "tags": [["relay", "ALL_RELAYS"]], "content": "", "sig": "00".repeat(64),
            })
            .to_string();
            let (writer_tx, writer_rx) = bounded(4);
            writer_tx
                .send(WriterMsg::AddEvent {
                    conn_id: 1,
                    source: TransportSource::ip_address("127.0.0.1".parse().unwrap()),
                    packed: packed.into_bytes(),
                    json,
                    authed: None,
                    grant: Default::default(),
                })
                .unwrap();
            drop(writer_tx);
            let moderation = Arc::new(parking_lot::RwLock::new(Default::default()));
            run_writer(
                env.clone(),
                Arc::new(parking_lot::RwLock::new(config)),
                conns,
                Arc::new(Metrics::default()),
                writer_rx,
                Vec::new(),
                moderation,
                TAG_KIND_STEP,
            );
            let response = out_rx.try_recv().unwrap().into_text();
            let entries = env.begin_ro().unwrap().entries(env.dbis().event).unwrap();
            if stored {
                assert!(response.contains("true"), "kind {kind}: {response}");
                assert_eq!(entries, 1);
            } else {
                assert!(
                    response.contains("restricted: kind 7 is not allowed by this relay"),
                    "{response}"
                );
                assert_eq!(entries, 0);
            }
        }
    }

    #[test]
    fn the_writer_refuses_kinds_nobody_could_read() {
        // Queued while AUTH was usable, and taken by a writer whose
        // configuration a reload made it unusable in: the gift wrap is
        // refused, and a vanish request still honored whatever its class.
        for (kind, stored) in [(1059, false), (VANISH_KIND, true)] {
            let dir = tempfile::tempdir().unwrap();
            let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
            env.ensure_initialized().unwrap();
            let mut config = Config::default();
            config.db = dir.path().to_path_buf();
            config.relay.auth.recipient_only_kinds.push(VANISH_KIND);
            assert!(!config.auth_usable());
            let conns = Arc::new(ConnTable::new());
            let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel();
            conns.insert(1, Outbound::new(out_tx, 0));
            let (id, author) = ([9u8; 32], [8u8; 32]);
            let tags = PackedEventTagBuilder::default();
            let packed = PackedEventBuilder::build(&id, &author, 1, kind, 0, &tags).unwrap();
            let json = json!({
                "id": to_hex(&id), "pubkey": to_hex(&author), "created_at": 1, "kind": kind,
                "tags": [["relay", "ALL_RELAYS"]], "content": "", "sig": "00".repeat(64),
            })
            .to_string();
            let (writer_tx, writer_rx) = bounded(4);
            writer_tx
                .send(WriterMsg::AddEvent {
                    conn_id: 1,
                    source: TransportSource::ip_address("127.0.0.1".parse().unwrap()),
                    packed: packed.into_bytes(),
                    json,
                    authed: None,
                    grant: Default::default(),
                })
                .unwrap();
            drop(writer_tx);
            let metrics = Arc::new(Metrics::default());
            run_writer(
                env.clone(),
                Arc::new(parking_lot::RwLock::new(config)),
                conns,
                metrics.clone(),
                writer_rx,
                Vec::new(),
                Arc::new(parking_lot::RwLock::new(Default::default())),
                TAG_KIND_STEP,
            );
            let response = out_rx.try_recv().unwrap().into_text();
            let entries = env.begin_ro().unwrap().entries(env.dbis().event).unwrap();
            let refusals: u64 = metrics.refusals.counts().map(|(_, count)| count).sum();
            if stored {
                assert!(response.contains("true"), "kind {kind}: {response}");
                assert_eq!((entries, refusals), (1, 0));
            } else {
                assert!(
                    response.contains(
                        "restricted: kind 1059 is read only after AUTH, which this relay does \
                         not offer"
                    ),
                    "{response}"
                );
                assert_eq!(entries, 0);
                assert_eq!(metrics.refusals.get(Setting::RecipientOnlyKinds), 1);
            }
        }
    }

    #[test]
    fn write_policy_plugin_cannot_veto_vanish_requests() {
        // NIP-62: relays that restrict who can post MUST honor vanish requests
        // regardless of the user's status. An author who lost plugin approval
        // can still erase what they published while approved.
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), small_map_env_options()).unwrap();
        env.ensure_initialized().unwrap();
        let script = dir.path().join("reject-all.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\nwhile read line; do\n\
             id=$(echo \"$line\" | sed -n 's/.*\"id\":\"\\([^\"]*\\)\".*/\\1/p')\n\
             echo '{\"id\":\"'$id'\",\"action\":\"reject\",\"msg\":\"blocked: not registered\"}'\n\
             done\n",
        )
        .unwrap();
        let author = [7u8; 32];
        let note_id = [9u8; 32];
        let vanish_id = [8u8; 32];

        let publish = |plugin: String, id: [u8; 32], created_at: u64, kind: u64, tags: Value| {
            let mut config = Config::default();
            config.db = dir.path().to_path_buf();
            config.relay.nip62.service_url = "wss://relay.example.com".into();
            config.relay.write_policy_plugin = plugin;
            let conns = Arc::new(ConnTable::new());
            let moderation = Arc::new(parking_lot::RwLock::new(
                env.begin_ro()
                    .and_then(|txn| load_moderation_snapshot_ro(&txn))
                    .unwrap(),
            ));
            let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel();
            conns.insert(1, Outbound::new(out_tx, 0));
            let packed = PackedEventBuilder::build(
                &id,
                &author,
                created_at,
                kind,
                0,
                &PackedEventTagBuilder::default(),
            )
            .unwrap();
            let (writer_tx, writer_rx) = bounded(1);
            writer_tx
                .send(WriterMsg::AddEvent {
                    conn_id: 1,
                    source: TransportSource::ip_address("127.0.0.1".parse().unwrap()),
                    packed: packed.into_bytes(),
                    json: json!({
                        "id": to_hex(&id),
                        "pubkey": to_hex(&author),
                        "created_at": created_at,
                        "kind": kind,
                        "tags": tags,
                        "content": "",
                        "sig": "00".repeat(64),
                    })
                    .to_string(),
                    authed: None,
                    grant: Default::default(),
                })
                .unwrap();
            drop(writer_tx);
            run_writer(
                env.clone(),
                Arc::new(parking_lot::RwLock::new(config)),
                conns,
                Arc::new(Metrics::default()),
                writer_rx,
                Vec::new(),
                moderation,
                TAG_KIND_STEP,
            );
            out_rx.try_recv().unwrap().into_text()
        };

        let note = publish(String::new(), note_id, 100, 1, json!([]));
        assert!(note.contains("true"), "{note}");
        let vanish = publish(
            format!("sh {}", script.display()),
            vanish_id,
            200,
            VANISH_KIND,
            json!([["relay", "ALL_RELAYS"]]),
        );
        assert!(vanish.contains(&to_hex(&vanish_id)), "{vanish}");
        assert!(vanish.contains("true"), "{vanish}");
        // The note is suppressed immediately; physical deletion is a later sweep.
        let txn = env.begin_ro().unwrap();
        let (_, stored) = wok_db::lookup_event_by_id_ro(&txn, &note_id)
            .unwrap()
            .unwrap();
        assert!(is_event_vanished_ro(&txn, PackedEventView::new(&stored).unwrap()).unwrap());
    }

    #[test]
    fn multibyte_report_reason_is_bounded_and_reaches_queue() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
        let first_target = [9u8; 32];
        let dropped_target = [10u8; 32];
        let mut tags = PackedEventTagBuilder::default();
        tags.add('e', &first_target).unwrap();
        tags.add('e', &dropped_target).unwrap();
        let packed =
            PackedEventBuilder::build(&[1u8; 32], &[2u8; 32], 1, REPORT_KIND, 0, &tags).unwrap();
        let mut report = EventToWrite::new(
            packed.into_bytes(),
            json!({"content": "💥".repeat(200)}).to_string(),
        );
        report.status = EventWriteStatus::Written;

        let mut txn = env.begin_rw().unwrap();
        let updates = record_reports(&mut txn, &[report], 1);
        txn.commit().unwrap();
        assert_eq!(updates.len(), 1);
        let reason = updates.get(&first_target).unwrap();
        assert!(reason.len() <= MAX_REASON_BYTES);
        assert!(reason.contains('💥'));

        let txn = env.begin_ro().unwrap();
        assert_eq!(
            wok_db::list_reported_events_ro(&txn).unwrap(),
            vec![(first_target, reason.clone())]
        );
    }

    #[tokio::test]
    async fn outbound_byte_accounting_and_kill() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<OutboundFrame>();
        let out = Outbound::new(tx, 100);
        let killed = out.killed();

        assert_eq!(out.try_send("x".repeat(60), None), Ok(()));
        assert_eq!(out.try_send("y".repeat(30), None), Ok(()));
        // 60 + 30 + 20 > 100: over budget, rejected.
        assert_eq!(
            out.try_send("z".repeat(20), None),
            Err(OutboundSendError::OverByteLimit)
        );

        // Draining one frame releases its bytes.
        drop(rx.recv().await.unwrap());
        assert_eq!(out.try_send("z".repeat(20), None), Ok(()));

        // Kill notification reaches the transport.
        out.kill();
        tokio::time::timeout(Duration::from_secs(1), killed.notified())
            .await
            .expect("kill notification");

        // Limit 0 means unlimited.
        let (tx2, _rx2) = tokio::sync::mpsc::unbounded_channel::<OutboundFrame>();
        let out2 = Outbound::new(tx2, 0);
        for _ in 0..8 {
            assert_eq!(out2.try_send("q".repeat(1000), None), Ok(()));
        }

        // The byte budget, not an incidental message count, bounds bursts.
        let (tx3, mut rx3) = tokio::sync::mpsc::unbounded_channel::<OutboundFrame>();
        let out3 = Outbound::new(tx3, 10_000);
        for _ in 0..500 {
            assert_eq!(out3.try_send("event".into(), None), Ok(()));
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
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
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
            .client_message(
                conn,
                TransportSource::ip_address("127.0.0.1".parse().unwrap()),
                json!(["EVENT", ev]).to_string(),
            )
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
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
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
                TransportSource::ip_address("127.0.0.1".parse().unwrap()),
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
    async fn restricted_writes_and_bans_cannot_veto_vanish_requests() {
        // NIP-62: relays that restrict who can post MUST honor vanish requests
        // regardless of the user's status. Losing allowlist membership or
        // being banned must not stop an author erasing what they published.
        for ban in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let env = Env::open(dir.path(), small_map_env_options()).unwrap();
            env.ensure_initialized().unwrap();
            let mut cfg = Config::default();
            cfg.db = dir.path().to_path_buf();
            cfg.relay.auth.enabled = false;
            cfg.relay.auth.write_policy = crate::config::AccessPolicy::Members;
            cfg.relay.nip62.service_url = "wss://relay.example.com".into();
            let handle = start(env.clone(), cfg).unwrap();
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<OutboundFrame>();
            let conn = handle.next_conn_id();
            handle.register(conn, Outbound::new(tx, 0)).await;
            let source = || TransportSource::ip_address("127.0.0.1".parse().unwrap());
            let kp = Keypair::new(SECP256K1, &mut rand::thread_rng());
            let author = kp.x_only_public_key().0.serialize();

            handle
                .manage(ManagementCmd::AllowPubkey {
                    pubkey: author,
                    reason: String::new(),
                })
                .await
                .unwrap();
            let note = sign_event_with_key(
                json!({
                    "created_at": now_secs() - 60,
                    "kind": 1,
                    "tags": [],
                    "content": "published while allowlisted",
                }),
                &kp,
            );
            handle
                .client_message(conn, source(), json!(["EVENT", note]).to_string())
                .await;
            let response = recv_outbound(&mut rx).await;
            assert!(response.contains("true"), "{response}");

            handle.manage(revocation(author, ban)).await.unwrap();
            let vanish = sign_event_with_key(
                json!({
                    "created_at": now_secs(),
                    "kind": VANISH_KIND,
                    "tags": [["relay", "wss://relay.example.com"]],
                    "content": "",
                }),
                &kp,
            );
            handle
                .client_message(conn, source(), json!(["EVENT", vanish]).to_string())
                .await;
            let response = recv_outbound(&mut rx).await;
            assert!(
                response.contains(vanish["id"].as_str().unwrap()),
                "{response}"
            );
            assert!(response.contains("true"), "{response}");

            let note_id: [u8; 32] = hex::decode(note["id"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let txn = env.begin_ro().unwrap();
            let (_, stored) = wok_db::lookup_event_by_id_ro(&txn, &note_id)
                .unwrap()
                .unwrap();
            assert!(is_event_vanished_ro(&txn, PackedEventView::new(&stored).unwrap()).unwrap());
            drop(txn);
            handle.request_shutdown();
        }
    }

    /// Collect outbound frames until the connection stays quiet for 300ms.
    async fn drain_outbound(
        rx: &mut tokio::sync::mpsc::UnboundedReceiver<OutboundFrame>,
    ) -> Vec<String> {
        let mut frames = Vec::new();
        while let Ok(Some(frame)) =
            tokio::time::timeout(Duration::from_millis(300), rx.recv()).await
        {
            frames.push(frame.into_text());
        }
        frames
    }

    fn invalid_budget_relay(burst: u32) -> (tempfile::TempDir, RelayHandle) {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), small_map_env_options()).unwrap();
        env.ensure_initialized().unwrap();
        let mut cfg = Config::default();
        cfg.db = dir.path().to_path_buf();
        cfg.relay.auth.enabled = false;
        // One token a second: no refill can land mid-test on a loaded runner.
        cfg.relay.abuse.invalid_rate_per_second = 1;
        cfg.relay.abuse.invalid_burst = burst;
        let handle = start(env, cfg).unwrap();
        (dir, handle)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn malformed_messages_are_rate_limited_with_one_notice() {
        // Each malformed message used to earn a free NOTICE (#49). Malformed
        // CLOSEs (invalid subscription id) leave no state and share the budget.
        let (_dir, handle) = invalid_budget_relay(5);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<OutboundFrame>();
        let conn = handle.next_conn_id();
        handle.register(conn, Outbound::new(tx, 0)).await;
        let source = || TransportSource::ip_address("127.0.0.1".parse().unwrap());
        let before = handle
            .metrics
            .abuse_invalid_rate_rejections
            .load(Ordering::Relaxed);

        for i in 0..20 {
            let payload = if i % 2 == 0 {
                "[\"NOT-A-COMMAND\"]".to_string()
            } else {
                json!(["CLOSE", ""]).to_string()
            };
            handle.client_message(conn, source(), payload).await;
        }
        let frames = drain_outbound(&mut rx).await;
        let rate_limited = frames
            .iter()
            .filter(|f| f.contains("rate-limited: too many invalid messages"))
            .count();
        assert_eq!(rate_limited, 1, "{frames:?}");
        assert!(frames.len() <= 7, "{frames:?}");
        let rejected = handle
            .metrics
            .abuse_invalid_rate_rejections
            .load(Ordering::Relaxed)
            - before;
        assert!(rejected >= 13, "{rejected}");

        // Budgeted commands are unaffected.
        handle
            .client_message(
                conn,
                source(),
                json!(["REQ", "ok", {"limit": 1}]).to_string(),
            )
            .await;
        let frames = drain_outbound(&mut rx).await;
        assert!(frames.iter().any(|f| f.contains("EOSE")), "{frames:?}");
        handle.request_shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn close_is_honored_after_another_connection_exhausts_the_budget() {
        // NIP-01 CLOSE stops a subscription. A neighbour behind the same
        // address spending the malformed-message budget must not leave it
        // running.
        let (_dir, handle) = invalid_budget_relay(1);
        let source = || TransportSource::ip_address("127.0.0.1".parse().unwrap());
        let (a_tx, mut a_rx) = tokio::sync::mpsc::unbounded_channel::<OutboundFrame>();
        let a = handle.next_conn_id();
        handle.register(a, Outbound::new(a_tx, 0)).await;
        let (b_tx, mut b_rx) = tokio::sync::mpsc::unbounded_channel::<OutboundFrame>();
        let b = handle.next_conn_id();
        handle.register(b, Outbound::new(b_tx, 0)).await;

        handle
            .client_message(
                b,
                source(),
                json!(["REQ", "live", {"kinds": [1]}]).to_string(),
            )
            .await;
        assert!(recv_outbound(&mut b_rx).await.contains("EOSE"));
        for _ in 0..5 {
            handle
                .client_message(a, source(), "[\"NOT-A-COMMAND\"]".into())
                .await;
        }
        drain_outbound(&mut a_rx).await;
        handle
            .client_message(b, source(), json!(["CLOSE", "live"]).to_string())
            .await;
        // Let the CLOSE reach the subscription worker before publishing.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let event = sign_event(json!({
            "created_at": now_secs(),
            "kind": 1,
            "tags": [],
            "content": "after close",
        }));
        handle
            .client_message(a, source(), json!(["EVENT", event]).to_string())
            .await;
        assert!(recv_outbound(&mut a_rx).await.contains("true"));
        let frames = drain_outbound(&mut b_rx).await;
        assert!(
            !frames.iter().any(|f| f.contains("after close")),
            "closed subscription still delivered: {frames:?}"
        );
        handle.request_shutdown();
    }

    /// A running relay whose config the test can change live, like a reload.
    fn live_reload_relay(
        configure: impl FnOnce(&mut Config, &std::path::Path),
    ) -> (tempfile::TempDir, RelayHandle) {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), small_map_env_options()).unwrap();
        env.ensure_initialized().unwrap();
        let mut cfg = Config::default();
        cfg.db = dir.path().to_path_buf();
        cfg.relay.auth.enabled = false;
        configure(&mut cfg, dir.path());
        let handle = start(env, cfg).unwrap();
        (dir, handle)
    }

    async fn live_conn(
        handle: &RelayHandle,
    ) -> (u64, tokio::sync::mpsc::UnboundedReceiver<OutboundFrame>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<OutboundFrame>();
        let conn = handle.next_conn_id();
        handle.register(conn, Outbound::new(tx, 0)).await;
        (conn, rx)
    }

    #[test]
    fn the_history_thread_marks_refusals_whatever_its_interval() {
        let now = std::time::Instant::now();
        // A sample every two days still wakes the thread each minute.
        let two_days = Duration::from_secs(2 * 86_400);
        assert_eq!(history_wait(now, two_days, now), REFUSAL_MARK_TICK);
        // A short interval sleeps until the next sample.
        let fifteen = Duration::from_secs(15);
        assert_eq!(
            history_wait(now, fifteen, now + Duration::from_secs(10)),
            Duration::from_secs(5)
        );
        assert_eq!(
            history_wait(now, fifteen, now + fifteen * 2),
            Duration::ZERO
        );
    }

    #[test]
    fn start_returns_with_the_first_history_sample_and_refusal_mark() {
        let (_dir, handle) = live_reload_relay(|_, _| {});
        // Read without waiting for the history thread.
        assert_eq!(handle.metrics.history.snapshots().len(), 1);
        assert!(handle.metrics.refusals.recent().is_some());
        handle.shutdown_and_join(Duration::from_secs(10)).unwrap();
    }

    fn local_source() -> TransportSource {
        TransportSource::ip_address("127.0.0.1".parse().unwrap())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_reload_applies_the_write_policy_timeout() {
        // The writer captured the timeout at startup, so lowering it had no
        // effect until a restart (#54).
        let (_dir, handle) = live_reload_relay(|cfg, dir| {
            let script = dir.join("slow-accept.sh");
            std::fs::write(
                &script,
                "#!/bin/sh\nwhile read line; do\n\
                 id=$(echo \"$line\" | sed -n 's/.*\"id\":\"\\([^\"]*\\)\".*/\\1/p')\n\
                 sleep 3\n\
                 echo '{\"id\":\"'$id'\",\"action\":\"accept\"}'\n\
                 done\n",
            )
            .unwrap();
            cfg.relay.write_policy_plugin = format!("sh {}", script.display());
            cfg.relay.write_policy_timeout_secs = 30;
        });
        let (conn, mut rx) = live_conn(&handle).await;
        // Baseline under the startup 30s timeout: the slow plugin's 3s answer
        // is accepted, so the writer is running before the reload.
        let event = sign_event(json!({
            "created_at": now_secs(), "kind": 1, "tags": [], "content": "before reload",
        }));
        handle
            .client_message(conn, local_source(), json!(["EVENT", event]).to_string())
            .await;
        let response = tokio::time::timeout(Duration::from_secs(10), rx.recv())
            .await
            .unwrap()
            .unwrap()
            .into_text();
        assert!(response.contains("true"), "{response}");

        handle.config.write().relay.write_policy_timeout_secs = 1;
        let event = sign_event(json!({
            "created_at": now_secs(), "kind": 1, "tags": [], "content": "slow plugin",
        }));
        let started = std::time::Instant::now();
        handle
            .client_message(conn, local_source(), json!(["EVENT", event]).to_string())
            .await;
        let response = tokio::time::timeout(Duration::from_secs(10), rx.recv())
            .await
            .unwrap()
            .unwrap()
            .into_text();
        assert!(response.contains("false"), "{response}");
        assert!(
            started.elapsed() < Duration::from_millis(2500),
            "plugin ran {:?} past the reloaded 1s timeout",
            started.elapsed()
        );
        handle.request_shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_reload_applies_the_subscription_cap() {
        // The monitor captured max_subs_per_connection at startup (#54).
        let (_dir, handle) = live_reload_relay(|_, _| {});
        let (conn, mut rx) = live_conn(&handle).await;
        let req = |sub: &str| json!(["REQ", sub, {"kinds": [1]}]).to_string();
        // Baseline under the startup cap, so the monitor is running before
        // the reload.
        for sub in ["a", "b"] {
            handle.client_message(conn, local_source(), req(sub)).await;
            assert!(recv_outbound(&mut rx).await.contains("EOSE"));
        }
        handle.config.write().relay.max_subs_per_connection = 1;

        // Now over the lowered cap: replacing an open id still works, a new
        // id is refused.
        handle.client_message(conn, local_source(), req("a")).await;
        handle.client_message(conn, local_source(), req("c")).await;
        let frames = drain_outbound(&mut rx).await;
        assert!(
            frames
                .iter()
                .any(|f| f.contains("too many concurrent REQs")),
            "new subscription accepted over the reloaded cap: {frames:?}"
        );
        assert_eq!(
            frames.iter().filter(|f| f.contains("too many")).count(),
            1,
            "replacing an open subscription was refused: {frames:?}"
        );

        let (publisher, mut publisher_rx) = live_conn(&handle).await;
        let event = sign_event(json!({
            "created_at": now_secs(), "kind": 1, "tags": [], "content": "live after reload",
        }));
        handle
            .client_message(
                publisher,
                local_source(),
                json!(["EVENT", event]).to_string(),
            )
            .await;
        assert!(recv_outbound(&mut publisher_rx).await.contains("true"));
        let frames = drain_outbound(&mut rx).await;
        for sub in ["a", "b"] {
            assert!(
                frames
                    .iter()
                    .any(|f| f.starts_with(&format!("[\"EVENT\",\"{sub}\""))),
                "subscription {sub} stopped receiving: {frames:?}"
            );
        }
        handle.request_shutdown();
    }

    /// An outbox client's metadata fetch for a follow list of `authors`.
    fn follow_list_req(sub: &str, authors: usize) -> String {
        let authors: Vec<String> = (0..authors).map(|i| format!("{i:064x}")).collect();
        json!(["REQ", sub, {"authors": authors, "kinds": [0, 3, 10002, 10050]}]).to_string()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn default_limits_accept_a_two_thousand_author_req() {
        // Audit C5: the 64 KiB default refused follow lists of about 970
        // authors or more.
        let (_dir, handle) = live_reload_relay(|_, _| {});
        let (conn, mut rx) = live_conn(&handle).await;
        let req = follow_list_req("follows", 2_000);
        assert!(req.len() > 128 * 1024, "{} bytes", req.len());
        handle.client_message(conn, local_source(), req).await;
        let reply = recv_outbound(&mut rx).await;
        assert!(reply.starts_with(r#"["EOSE","follows""#), "{reply}");
        handle.request_shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn filter_bytes_are_budgeted_per_connection() {
        // F8: room for two follow-list subscriptions, not three.
        let budget = 2 * follow_list_req("a", 1_000).len();
        let (_dir, handle) = live_reload_relay(|cfg, _| {
            cfg.relay.max_filter_bytes_per_connection = budget;
        });
        let (conn, mut rx) = live_conn(&handle).await;
        let req = |sub: &str| follow_list_req(sub, 1_000);
        let refusal =
            format!(r#"["CLOSED","c","blocked: this connection's filters exceed {budget} bytes"]"#);
        for sub in ["a", "b"] {
            handle.client_message(conn, local_source(), req(sub)).await;
            assert!(recv_outbound(&mut rx).await.contains("EOSE"));
        }
        handle.client_message(conn, local_source(), req("c")).await;
        assert_eq!(recv_outbound(&mut rx).await, refusal);
        // Replacing an open subscription reuses its bytes, and a COUNT holds
        // nothing once answered.
        handle.client_message(conn, local_source(), req("a")).await;
        assert!(recv_outbound(&mut rx).await.contains("EOSE"));
        let count = json!(["COUNT", "n", {"kinds": [1]}]).to_string();
        handle.client_message(conn, local_source(), count).await;
        assert!(recv_outbound(&mut rx).await.starts_with(r#"["COUNT","n""#));
        // A closed subscription frees its bytes.
        let close = json!(["CLOSE", "b"]).to_string();
        handle.client_message(conn, local_source(), close).await;
        handle.client_message(conn, local_source(), req("c")).await;
        assert!(recv_outbound(&mut rx).await.contains("EOSE"));

        // Over a lowered budget an open id can still be replaced by filters no
        // larger than its own; anything that grows the total is refused.
        handle.config.write().relay.max_filter_bytes_per_connection = budget / 2;
        handle.client_message(conn, local_source(), req("a")).await;
        assert!(recv_outbound(&mut rx).await.contains("EOSE"));
        handle
            .client_message(conn, local_source(), follow_list_req("c", 1_001))
            .await;
        let frames = drain_outbound(&mut rx).await;
        assert_eq!(
            frames,
            [format!(
                r#"["CLOSED","c","blocked: this connection's filters exceed {} bytes"]"#,
                budget / 2
            )]
        );
        // Zero is unlimited.
        handle.config.write().relay.max_filter_bytes_per_connection = 0;
        for sub in ["b", "c", "d"] {
            handle.client_message(conn, local_source(), req(sub)).await;
            assert!(recv_outbound(&mut rx).await.contains("EOSE"));
        }
        handle.request_shutdown();
    }

    /// A relay with default limits over `count` stored notes by `author`
    /// of each `(kind, count)`, written straight to the database.
    fn relay_with_notes(author: &str, kinds: &[(u64, u64)]) -> (tempfile::TempDir, RelayHandle) {
        let dir = tempfile::tempdir().unwrap();
        let options = EnvOptions {
            map_size: 1 << 30,
            ..EnvOptions::default()
        };
        let env = Env::open(dir.path(), options).unwrap();
        env.ensure_initialized().unwrap();
        let mut events: Vec<EventToWrite> = kinds
            .iter()
            .flat_map(|&(kind, count)| (0..count).map(move |i| (kind, i)))
            .map(|(kind, i)| {
                let mut id = [0xCCu8; 32];
                id[..8].copy_from_slice(&kind.to_be_bytes());
                id[8..16].copy_from_slice(&i.to_be_bytes());
                let event = json!({
                    "id": hex::encode(id), "pubkey": author,
                    "created_at": 1_700_000_000 + i, "kind": kind, "tags": [],
                    "content": "note", "sig": "00".repeat(64),
                });
                let parsed = wok_event::parse_and_verify_event(
                    &event,
                    &wok_event::EventLimits::default(),
                    None,
                    false,
                    false,
                )
                .unwrap();
                EventToWrite::new(parsed.packed.into_bytes(), parsed.json)
            })
            .collect();
        let mut txn = env.begin_rw().unwrap();
        wok_db::write_events(&mut txn, &mut wok_db::NoopNegentropy, &mut events, false).unwrap();
        txn.commit().unwrap();
        let mut cfg = Config::default();
        cfg.db = dir.path().to_path_buf();
        cfg.relay.auth.enabled = false;
        let handle = start(env, cfg).unwrap();
        (dir, handle)
    }

    /// The EVENTs a REQ sends before its EOSE.
    async fn history_len(
        handle: &RelayHandle,
        conn: u64,
        rx: &mut tokio::sync::mpsc::UnboundedReceiver<OutboundFrame>,
        req: Value,
    ) -> usize {
        handle
            .client_message(conn, local_source(), req.to_string())
            .await;
        let mut events = 0;
        loop {
            let frame = recv_outbound(rx).await;
            if frame.starts_with(r#"["EVENT""#) {
                events += 1;
            } else {
                assert!(frame.starts_with(r#"["EOSE""#), "{frame}");
                return events;
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn default_limits_return_directory_batches_and_merged_reqs_whole() {
        let (_dir, handle) = relay_with_notes(
            &"11".repeat(32),
            &[(1, 2_100), (6, 500), (7, 500), (16, 500), (1111, 500)],
        );
        let (conn, mut rx) = live_conn(&handle).await;
        // MDK's directory batch: 200 authors x 6 kinds. The 500 clamp cut it.
        let batch = json!(["REQ", "dir", {"kinds": [1], "limit": 1_200}]);
        assert_eq!(history_len(&handle, conn, &mut rx, batch).await, 1_200);
        // A filter without a limit gets the same 2,000 clamp (#97 decision 9).
        let unlimited = json!(["REQ", "all", {"kinds": [1]}]);
        assert_eq!(history_len(&handle, conn, &mut rx, unlimited).await, 2_000);
        // A merged batch whose filters each fit is no longer cut at 2,000 in
        // all (audit C1).
        let merged = json!(["REQ", "merged",
            {"kinds": [1], "limit": 500}, {"kinds": [6]}, {"kinds": [7]},
            {"kinds": [16]}, {"kinds": [1111]}]);
        assert_eq!(history_len(&handle, conn, &mut rx, merged).await, 2_500);
        handle.request_shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn default_limits_let_an_author_store_past_a_hundred_thousand_events() {
        // A bot or heavy user at the 0.7 per-author quota got
        // `blocked: author storage quota exceeded` for every new event.
        let key = Keypair::new(SECP256K1, &mut rand::thread_rng());
        let author = hex::encode(key.x_only_public_key().0.serialize());
        let (_dir, handle) = relay_with_notes(&author, &[(1, 100_000)]);
        let (conn, mut rx) = live_conn(&handle).await;
        let note = sign_event_with_key(
            json!({"created_at": now_secs(), "kind": 1, "tags": [], "content": "one more"}),
            &key,
        );
        handle
            .client_message(conn, local_source(), json!(["EVENT", note]).to_string())
            .await;
        let reply = recv_outbound(&mut rx).await;
        assert!(
            reply.starts_with(r#"["OK""#) && reply.contains("true"),
            "{reply}"
        );
        handle.request_shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn default_limits_accept_long_lists_and_four_tag_letters() {
        let (_dir, handle) = live_reload_relay(|_, _| {});
        let (conn, mut rx) = live_conn(&handle).await;
        // A heavy user's follow list (audit F9): 2,000 tags used to be the cap.
        let follows: Vec<Value> = (0..4_000u32)
            .map(|i| json!(["p", format!("{i:064x}")]))
            .collect();
        let contacts = sign_event(json!({
            "created_at": now_secs(), "kind": 3, "tags": follows, "content": "",
        }));
        handle
            .client_message(conn, local_source(), json!(["EVENT", contacts]).to_string())
            .await;
        let reply = recv_outbound(&mut rx).await;
        assert!(
            reply.starts_with(r#"["OK""#) && reply.contains("true"),
            "{reply}"
        );
        // NIP-22 comments on an event of kind 1, by root and kind: four tag
        // letters, where three used to be the cap.
        let comments = json!(["REQ", "comments", {
            "kinds": [1111], "#E": ["ab".repeat(32)], "#K": ["1"],
            "#P": ["cd".repeat(32)], "#k": ["1"],
        }]);
        assert_eq!(history_len(&handle, conn, &mut rx, comments).await, 0);
        handle.request_shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_0_7_filter_validation_section_keeps_refusing_what_it_refused() {
        // `enabled = true` enforced 0.7's defaults of three filters per REQ
        // and three kinds per filter; the cap is now the relay's own.
        let legacy = Config::parse_toml("[relay.filter_validation]\nenabled = true\n").unwrap();
        let (_dir, handle) = live_reload_relay(|cfg, _| {
            cfg.relay.max_filters_per_req = legacy.relay.max_filters_per_req;
            cfg.relay.filter_validation = legacy.relay.filter_validation.clone();
        });
        let (conn, mut rx) = live_conn(&handle).await;
        let filter = json!({"kinds": [1]});
        let four_filters = json!(["REQ", "a", filter, filter, filter, filter]);
        handle
            .client_message(conn, local_source(), four_filters.to_string())
            .await;
        assert_eq!(
            recv_outbound(&mut rx).await,
            r#"["CLOSED","a","invalid: bad req: arr too big"]"#
        );
        let four_kinds = json!(["REQ", "b", {"kinds": [0, 1, 3, 7]}]);
        handle
            .client_message(conn, local_source(), four_kinds.to_string())
            .await;
        assert_eq!(
            recv_outbound(&mut rx).await,
            r#"["CLOSED","b","blocked: bad req: filter validation failed: too many kinds in filter: 4"]"#
        );
        let within = json!(["REQ", "c", filter, filter, {"kinds": [0, 3, 10002]}]);
        assert_eq!(history_len(&handle, conn, &mut rx, within).await, 0);
        handle.request_shutdown();

        // By default no rule applies: MDK's six-kind directory batch passes.
        let (_dir, handle) = live_reload_relay(|_, _| {});
        let (conn, mut rx) = live_conn(&handle).await;
        let directory = json!(["REQ", "d", {"kinds": [0, 1, 3, 10002, 10050, 30443]}]);
        assert_eq!(history_len(&handle, conn, &mut rx, directory).await, 0);
        handle.request_shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_reload_applies_the_count_dedup_budget() {
        // The REQ worker sized its COUNT dedup budget from the startup
        // max_filter_limit_count, so raising the limit live still capped a
        // multi-filter COUNT at the old value (#54).
        let (_dir, handle) = live_reload_relay(|cfg, _| cfg.relay.max_filter_limit_count = 2);
        let (conn, mut rx) = live_conn(&handle).await;
        for i in 0..5u64 {
            let event = sign_event(json!({
                "created_at": now_secs() - 10 + i, "kind": 1, "tags": [],
                "content": format!("count-{i}"),
            }));
            handle
                .client_message(conn, local_source(), json!(["EVENT", event]).to_string())
                .await;
            assert!(recv_outbound(&mut rx).await.contains("true"));
        }
        // Two filters skip the single-filter HyperLogLog path and dedup.
        let count = json!(["COUNT", "c", {"kinds": [1]}, {"kinds": [1], "limit": 100}]).to_string();
        // Baseline under the startup limit, so the REQ worker is running
        // before the reload.
        handle
            .client_message(conn, local_source(), count.clone())
            .await;
        let response = recv_outbound(&mut rx).await;
        assert!(response.contains("\"limited\":true"), "{response}");

        handle.config.write().relay.max_filter_limit_count = 10;
        handle.client_message(conn, local_source(), count).await;
        let response = recv_outbound(&mut rx).await;
        assert!(response.contains("\"count\":5"), "{response}");
        handle.request_shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn vanish_requests_pay_pow_and_author_budget() {
        let vanish = |kp: &Keypair, content: &str| {
            sign_event_with_key(
                json!({
                    "created_at": now_secs(),
                    "kind": VANISH_KIND,
                    "tags": [["relay", "ALL_RELAYS"]],
                    "content": content,
                }),
                kp,
            )
        };
        let start_relay = |configure: &dyn Fn(&mut Config)| {
            let dir = tempfile::tempdir().unwrap();
            let env = Env::open(dir.path(), small_map_env_options()).unwrap();
            env.ensure_initialized().unwrap();
            let mut cfg = Config::default();
            cfg.db = dir.path().to_path_buf();
            cfg.relay.auth.enabled = false;
            cfg.relay.nip62.service_url = "wss://relay.example.com".into();
            configure(&mut cfg);
            (dir, start(env, cfg).unwrap())
        };
        let source = || TransportSource::ip_address("127.0.0.1".parse().unwrap());
        let mut rng = rand::thread_rng();
        let kp = Keypair::new(SECP256K1, &mut rng);

        let (_dir, handle) = start_relay(&|cfg| cfg.relay.abuse.min_pow_difficulty = 255);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<OutboundFrame>();
        let conn = handle.next_conn_id();
        handle.register(conn, Outbound::new(tx, 0)).await;
        handle
            .client_message(
                conn,
                source(),
                json!(["EVENT", vanish(&kp, "no-pow")]).to_string(),
            )
            .await;
        let response = recv_outbound(&mut rx).await;
        assert!(
            response.contains("pow: difficulty 255 required"),
            "{response}"
        );
        handle.request_shutdown();

        let (_dir, handle) = start_relay(&|cfg| {
            cfg.relay.abuse.pubkey_event_rate_per_second = 1;
            cfg.relay.abuse.pubkey_event_burst = 1;
        });
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<OutboundFrame>();
        let conn = handle.next_conn_id();
        handle.register(conn, Outbound::new(tx, 0)).await;
        for content in ["first", "second"] {
            handle
                .client_message(
                    conn,
                    source(),
                    json!(["EVENT", vanish(&kp, content)]).to_string(),
                )
                .await;
        }
        let responses = [recv_outbound(&mut rx).await, recv_outbound(&mut rx).await];
        assert!(
            responses
                .iter()
                .any(|r| r.contains("rate-limited: author EVENT budget exhausted")),
            "{responses:?}"
        );
        handle.request_shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn query_cost_is_rejected_before_scheduling() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let mut cfg = Config::default();
        cfg.db = dir.path().to_path_buf();
        cfg.relay.auth.enabled = false;
        cfg.relay.abuse.max_query_work = 10;
        let handle = start(env, cfg).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<OutboundFrame>();
        let conn = handle.next_conn_id();
        handle.register(conn, Outbound::new(tx, 0)).await;
        handle
            .client_message(
                conn,
                TransportSource::ip_address("127.0.0.1".parse().unwrap()),
                json!(["REQ", "broad", {}]).to_string(),
            )
            .await;
        let response = recv_outbound(&mut rx).await;
        assert!(response.contains(
            "\"CLOSED\",\"broad\",\"blocked: query too broad (cost 2001 > 10); split the REQ"
        ));
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
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
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
                TransportSource::ip_address("127.0.0.1".parse().unwrap()),
                json!(["REQ", "private", {"kinds":[1059]}]).to_string(),
            )
            .await;

        // AUTH cannot succeed without service_url, so the refusal is final:
        // no challenge, and `restricted:` rather than `auth-required:`.
        let closed = recv_outbound(&mut rx).await;
        assert!(
            closed.starts_with(r#"["CLOSED","private","restricted: "#),
            "{closed}"
        );
        handle.request_shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn auth_without_a_challenge_is_refused_before_signature_verification() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), small_map_env_options()).unwrap();
        env.ensure_initialized().unwrap();
        let mut cfg = Config::default();
        cfg.db = dir.path().to_path_buf();
        cfg.relay.auth.service_url = "wss://auth.example".into();
        let handle = start(env, cfg).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<OutboundFrame>();
        let conn = handle.next_conn_id();
        handle.register(conn, Outbound::new(tx, 0)).await;
        let mut auth = sign_event(json!({
            "created_at": now_secs(),
            "kind": AUTH_KIND,
            "tags": [["relay", "wss://auth.example"], ["challenge", "never-issued"]],
            "content": "",
        }));
        auth["sig"] = json!("00".repeat(64));
        handle
            .client_message(
                conn,
                TransportSource::ip_address("127.0.0.1".parse().unwrap()),
                json!(["AUTH", auth]).to_string(),
            )
            .await;

        // No challenge was ever issued, so the bad signature is never checked.
        let reply = recv_outbound(&mut rx).await;
        assert!(
            reply.contains("no auth status available for connection"),
            "{reply}"
        );
        handle.request_shutdown();
    }

    #[test]
    fn an_inbound_share_admits_a_bounded_number_of_small_messages() {
        let share = InboundShare::new(64 * 1024);
        let held: Vec<_> = (0..MAX_QUEUED_MESSAGES)
            .map(|_| share.try_acquire(1).expect("room for another message"))
            .collect();
        // However small the next message, the connection has queued its most.
        assert!(share.try_acquire(1).is_none());
        drop(held);
        assert!(share.try_acquire(1).is_some());
    }

    #[tokio::test]
    async fn an_inbound_share_holds_a_connection_to_its_largest_message() {
        let share = InboundShare::new(10);
        let first = share.acquire(6).await;
        // Six of ten bytes are held: another six must wait for them.
        let waiting = share.acquire(6);
        tokio::pin!(waiting);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut waiting)
                .await
                .is_err()
        );
        drop(first);
        let second = tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .expect("released bytes admit the next message");
        drop(second);
        // A message larger than the share needs all of it, and still fits.
        let whole = tokio::time::timeout(Duration::from_secs(1), share.acquire(100))
            .await
            .expect("an oversized message takes the whole share");
        assert_eq!(share.permits.available_permits(), 0);
        drop(whole);
        assert_eq!(share.permits.available_permits(), 10);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_full_share_holds_the_message_without_blocking_the_transport() {
        let (_dir, handle, conn, mut rx) = relay_with_connection(|_| {}).await;
        let mut held = HeldMessages::new(1 << 20);
        // Everything this connection may queue is taken.
        let taken = conn.inbound.acquire(usize::MAX).await;
        let req = json!(["REQ", "held", {"kinds": [1]}]).to_string();
        let len = req.len();
        // The transport is not kept waiting: the message is held.
        let accepted = tokio::time::timeout(
            Duration::from_millis(500),
            conn.receive(&mut held, req, len),
        )
        .await
        .expect("receive returns while the share is full");
        assert!(accepted);
        assert_eq!(held.front_len(), Some(len));
        // `ready` waits for room, and resolves once it frees.
        assert!(
            tokio::time::timeout(Duration::from_millis(50), conn.ready(held.front_len()))
                .await
                .is_err()
        );
        drop(taken);
        tokio::time::timeout(Duration::from_secs(1), conn.ready(held.front_len()))
            .await
            .expect("room frees");
        conn.hand_over(&mut held).await;
        assert!(held.is_empty());
        assert!(recv_outbound(&mut rx).await.contains(r#"["EOSE","held""#));
        handle.request_shutdown();
    }

    /// A relay with `tweak` applied and one connection from 127.0.0.1,
    /// registered so that AUTH, when usable, challenges it first.
    async fn relay_with_connection(
        tweak: impl FnOnce(&mut Config),
    ) -> (
        tempfile::TempDir,
        RelayHandle,
        crate::ConnectionGuard,
        tokio::sync::mpsc::UnboundedReceiver<OutboundFrame>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), small_map_env_options()).unwrap();
        env.ensure_initialized().unwrap();
        let mut cfg = Config::default();
        cfg.db = dir.path().to_path_buf();
        tweak(&mut cfg);
        let handle = start(env, cfg).unwrap();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<OutboundFrame>();
        let conn = handle
            .register_connection(
                TransportSource::ip_address("127.0.0.1".parse().unwrap()),
                Outbound::new(tx, 0),
            )
            .await;
        (dir, handle, conn, rx)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn auth_is_refused_on_its_stated_kind_challenge_and_relay_before_verification() {
        let (_dir, handle, conn, mut rx) = relay_with_connection(|cfg| {
            cfg.relay.auth.service_url = "wss://auth.example".into();
        })
        .await;
        let challenge: Value = serde_json::from_str(&recv_outbound(&mut rx).await).unwrap();
        let challenge = challenge[1].as_str().unwrap().to_string();
        for (kind, relay, offered, refusal) in [
            (
                1,
                "wss://auth.example",
                challenge.as_str(),
                "wrong event kind",
            ),
            (
                AUTH_KIND,
                "wss://auth.example",
                "not-it",
                "challenge string mismatch",
            ),
            (
                AUTH_KIND,
                "wss://elsewhere.example",
                challenge.as_str(),
                "incorrect or missing relay tag",
            ),
        ] {
            let mut auth = sign_event(json!({
                "created_at": now_secs(),
                "kind": kind,
                "tags": [["relay", relay], ["challenge", offered]],
                "content": "",
            }));
            // A forged signature: each refusal comes before it is checked.
            auth["sig"] = json!("00".repeat(64));
            conn.client_message(json!(["AUTH", auth]).to_string()).await;
            let reply = recv_outbound(&mut rx).await;
            assert!(reply.contains(refusal), "{reply}");
        }
        handle.request_shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_reader_the_policy_refuses_is_refused_before_its_filters_are_read() {
        let (_dir, handle, conn, mut rx) = relay_with_connection(|cfg| {
            cfg.relay.auth.service_url = "wss://auth.example".into();
            cfg.relay.auth.read_policy = AccessPolicy::Members;
        })
        .await;
        let challenge = recv_outbound(&mut rx).await;
        assert!(challenge.starts_with(r#"["AUTH","#), "{challenge}");
        for message in [
            json!(["REQ", "bad-filter", {"kinds": "one"}]),
            json!(["COUNT", "bad-count", {"kinds": "one"}]),
            json!(["NEG-OPEN", "bad-payload", {"kinds": [1]}, "not hex"]),
        ] {
            conn.client_message(message.to_string()).await;
            let reply = recv_outbound(&mut rx).await;
            assert!(
                reply.contains("auth-required: this relay serves only members"),
                "{reply}"
            );
        }
        handle.request_shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_neg_open_meets_the_filter_size_limit_and_its_filter_before_its_payload() {
        let (_dir, handle, conn, mut rx) =
            relay_with_connection(|cfg| cfg.relay.max_req_filter_size = 64).await;
        let authors: Vec<String> = (0..4).map(|n| format!("{n:064x}")).collect();
        for (message, refusal) in [
            // Larger than a REQ may be, whatever its payload.
            (
                json!(["NEG-OPEN", "big", {"authors": authors}, "00"]),
                "invalid: filters exceed 64 serialized bytes",
            ),
            // A filter that does not parse is refused before the payload is
            // decoded.
            (
                json!(["NEG-OPEN", "bad", {"kinds": "one"}, "not hex"]),
                "invalid: kinds not an array",
            ),
        ] {
            conn.client_message(message.to_string()).await;
            let reply = recv_outbound(&mut rx).await;
            assert!(reply.contains(refusal), "{reply}");
        }
        assert_eq!(handle.metrics.refusals.get(Setting::MaxReqFilterSize), 1);
        // Reusing a live session's id for a filter over the limit ends that
        // session too, as NIP-77 says: its next NEG-MSG finds no session.
        let mut store = wok_negentropy::Vector::new();
        store.seal().unwrap();
        let init = hex::encode(
            wok_negentropy::Negentropy::new(store, 60_000)
                .unwrap()
                .initiate()
                .unwrap(),
        );
        conn.client_message(json!(["NEG-OPEN", "live", {"kinds": [1]}, init]).to_string())
            .await;
        assert!(recv_outbound(&mut rx)
            .await
            .starts_with(r#"["NEG-MSG","live""#));
        conn.client_message(json!(["NEG-OPEN", "live", {"authors": authors}, init]).to_string())
            .await;
        let refused = recv_outbound(&mut rx).await;
        assert!(
            refused.contains("invalid: filters exceed 64 serialized bytes"),
            "{refused}"
        );
        conn.client_message(json!(["NEG-MSG", "live", init]).to_string())
            .await;
        let reply = recv_outbound(&mut rx).await;
        assert!(
            reply.contains("closed: unknown subscription handle"),
            "{reply}"
        );
        handle.request_shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_event_its_kind_refuses_is_refused_before_verification() {
        let (_dir, handle, conn, mut rx) =
            relay_with_connection(|cfg| cfg.relay.auth.accepted_kinds = vec![0]).await;
        for (kind, refusal) in [
            (1, "restricted: kind 1 is not allowed by this relay"),
            (AUTH_KIND, "invalid: AUTH events must be sent with AUTH"),
        ] {
            let mut event = sign_event(json!({
                "created_at": now_secs(),
                "kind": kind,
                "tags": [],
                "content": "",
            }));
            event["sig"] = json!("00".repeat(64));
            conn.client_message(json!(["EVENT", event]).to_string())
                .await;
            let reply = recv_outbound(&mut rx).await;
            assert!(reply.contains(refusal), "{reply}");
        }
        // A kind the policy allows is still verified.
        let mut event = sign_event(json!({
            "created_at": now_secs(),
            "kind": 0,
            "tags": [],
            "content": "{}",
        }));
        event["sig"] = json!("00".repeat(64));
        conn.client_message(json!(["EVENT", event]).to_string())
            .await;
        let reply = recv_outbound(&mut rx).await;
        assert!(reply.contains("invalid: bad signature"), "{reply}");
        handle.request_shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_kind_nobody_could_read_is_refused_while_auth_is_unusable() {
        let (_dir, handle, conn, mut rx) =
            relay_with_connection(|cfg| cfg.relay.auth.authenticated_kinds = vec![30000]).await;
        let wrap = |kind: u64| {
            sign_event(json!({
                "created_at": now_secs(),
                "kind": kind,
                "tags": [["p", "33".repeat(32)], ["d", "x"]],
                "content": "",
            }))
        };
        // Refused by its kind, before verification.
        for kind in [4, 1059, 21059, 30000] {
            let mut event = wrap(kind);
            event["sig"] = json!("00".repeat(64));
            conn.client_message(json!(["EVENT", event]).to_string())
                .await;
            let reply = recv_outbound(&mut rx).await;
            assert!(
                reply.contains(&format!(
                    "restricted: kind {kind} is read only after AUTH, which this relay does \
                     not offer"
                )),
                "{reply}"
            );
        }
        // Once AUTH is usable, recipients can read them, so they are stored.
        handle.config.write().relay.auth.service_url = "wss://auth.example".into();
        conn.client_message(json!(["EVENT", wrap(1059)]).to_string())
            .await;
        let reply = recv_outbound(&mut rx).await;
        assert!(reply.contains(r#"true,"""#), "{reply}");
        handle.request_shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn auth_is_charged_to_the_event_budget() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), small_map_env_options()).unwrap();
        env.ensure_initialized().unwrap();
        let mut cfg = Config::default();
        cfg.db = dir.path().to_path_buf();
        cfg.relay.auth.service_url = "wss://auth.example".into();
        cfg.relay.abuse.event_rate_per_second = 1;
        cfg.relay.abuse.event_burst = 1;
        let handle = start(env, cfg).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<OutboundFrame>();
        let conn = handle.next_conn_id();
        handle.register(conn, Outbound::new(tx, 0)).await;
        for _ in 0..2 {
            handle
                .client_message(
                    conn,
                    TransportSource::ip_address("127.0.0.1".parse().unwrap()),
                    json!(["AUTH", {"id":"ab"}]).to_string(),
                )
                .await;
        }

        let first = recv_outbound(&mut rx).await;
        assert!(!first.contains("rate-limited:"), "{first}");
        let second = recv_outbound(&mut rx).await;
        assert_eq!(
            second,
            r#"["OK","ab",false,"rate-limited: AUTH budget exhausted"]"#
        );
        assert_eq!(
            handle
                .metrics
                .abuse_event_rate_rejections
                .load(Ordering::Relaxed),
            1
        );
        handle.request_shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_connection_guard_cleans_up_registration() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let mut cfg = Config::default();
        cfg.db = dir.path().to_path_buf();
        let handle = start(env, cfg).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<OutboundFrame>();
        let connection = handle
            .register_connection(TransportSource::Unix, Outbound::new(tx, 0))
            .await;
        assert_eq!(handle.metrics.active_connections.load(Ordering::Relaxed), 1);

        drop(connection);
        tokio::time::timeout(Duration::from_secs(2), async {
            while handle.metrics.active_connections.load(Ordering::Relaxed) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("connection guard cleanup");
        assert!(rx.recv().await.is_none());
        handle.request_shutdown();
    }

    /// Registration waits for ingress capacity; cancelling it there must still
    /// release the outbound entry and the connection count.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_registration_cleans_up_registration() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let mut cfg = Config::default();
        cfg.db = dir.path().to_path_buf();
        cfg.relay.ingester_threads = 1;
        let handle = start(env, cfg).unwrap();

        // Stall the ingester on the config lock, held off the runtime, then
        // fill its queue.
        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let config = handle.config.clone();
        let stall = std::thread::spawn(move || {
            let _guard = config.write();
            locked_tx.send(()).unwrap();
            let _ = release_rx.recv();
        });
        locked_rx.recv().unwrap();
        let filler = handle.next_conn_id();
        while tokio::time::timeout(
            Duration::from_millis(50),
            handle.client_message(filler, TransportSource::Unix, "[]".into()),
        )
        .await
        .is_ok()
        {}

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<OutboundFrame>();
        let registration = tokio::time::timeout(
            Duration::from_millis(50),
            handle.register_connection(TransportSource::Unix, Outbound::new(tx, 0)),
        )
        .await;
        assert!(registration.is_err(), "registration should be waiting");
        release_tx.send(()).unwrap();
        stall.join().unwrap();

        tokio::time::timeout(Duration::from_secs(5), async {
            while handle.metrics.active_connections.load(Ordering::Relaxed) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled registration cleanup");
        assert!(rx.recv().await.is_none());
        handle.request_shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn historical_query_concurrency_is_independent_from_live_subscription_limit() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
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
                TransportSource::ip_address("127.0.0.1".parse().unwrap()),
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
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
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
                    TransportSource::ip_address("127.0.0.1".parse().unwrap()),
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn global_storage_quota_aborts_the_exceeding_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let mut cfg = Config::default();
        cfg.db = dir.path().to_path_buf();
        cfg.relay.auth.enabled = false;
        cfg.relay.abuse.max_stored_events = 1;
        cfg.relay.abuse.max_stored_events_per_pubkey = 0;
        let handle = start(env.clone(), cfg).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<OutboundFrame>();
        let conn = handle.next_conn_id();
        handle.register(conn, Outbound::new(tx, 0)).await;

        for content in ["first-global", "second-global"] {
            let event = sign_event(json!({
                "created_at": now_secs(), "kind": 1, "tags": [], "content": content
            }));
            handle
                .client_message(
                    conn,
                    TransportSource::ip_address("127.0.0.1".parse().unwrap()),
                    json!(["EVENT", event]).to_string(),
                )
                .await;
            let response = recv_outbound(&mut rx).await;
            if content == "first-global" {
                assert!(response.contains("true"), "{response}");
            } else {
                assert!(response.contains("false") && response.contains("global storage quota"));
            }
        }

        let txn = env.begin_ro().unwrap();
        assert_eq!(txn.entries(env.dbis().event).unwrap(), 1);
        assert_eq!(
            handle
                .metrics
                .abuse_global_quota_rejections
                .load(Ordering::Relaxed),
            1
        );
        handle.request_shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn disk_reserve_rejects_before_opening_a_write_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let mut cfg = Config::default();
        cfg.db = dir.path().to_path_buf();
        cfg.db_min_free_disk_bytes = u64::MAX;
        cfg.relay.auth.enabled = false;
        let handle = start(env.clone(), cfg).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<OutboundFrame>();
        let conn = handle.next_conn_id();
        handle.register(conn, Outbound::new(tx, 0)).await;
        let event = sign_event(json!({
            "created_at": now_secs(), "kind": 1, "tags": [], "content": "reserve"
        }));
        handle
            .client_message(
                conn,
                TransportSource::ip_address("127.0.0.1".parse().unwrap()),
                json!(["EVENT", event]).to_string(),
            )
            .await;
        let response = recv_outbound(&mut rx).await;
        assert!(response.contains("false") && response.contains("disk reserve"));

        let txn = env.begin_ro().unwrap();
        assert_eq!(txn.entries(env.dbis().event).unwrap(), 0);
        assert_eq!(
            handle
                .metrics
                .abuse_disk_reserve_rejections
                .load(Ordering::Relaxed),
            1
        );
        handle.request_shutdown();
    }

    /// The duplicate pre-check failing to read is the relay's failure, not
    /// the event's, so the OK is `error:` (NIP-01: "for when none of that
    /// fits"), not `invalid:`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn duplicate_precheck_read_failures_are_errors() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), small_map_env_options()).unwrap();
        env.ensure_initialized().unwrap();
        let mut cfg = Config::default();
        cfg.db = dir.path().to_path_buf();
        cfg.relay.auth.enabled = false;
        let handle = start(env.clone(), cfg).unwrap();
        let (conn, mut rx) = live_conn(&handle).await;
        let event = sign_event(json!({
            "created_at": now_secs(), "kind": 1, "tags": [], "content": "precheck"
        }));
        let id = event["id"].as_str().unwrap().to_string();
        // Every read fails until the reply: the req monitor reads through
        // `begin_read` too, and could take a single injected failure first.
        fault::fail_reads(env.path(), usize::MAX);
        handle
            .client_message(conn, local_source(), json!(["EVENT", event]).to_string())
            .await;
        let reply = recv_outbound(&mut rx).await;
        fault::fail_reads(env.path(), 0);
        assert_eq!(
            reply,
            json!(["OK", id, false, "error: injected read failure"]).to_string()
        );
        handle
            .client_message(conn, local_source(), json!(["EVENT", event]).to_string())
            .await;
        assert_eq!(
            recv_outbound(&mut rx).await,
            json!(["OK", id, true, ""]).to_string()
        );
        handle.request_shutdown();
    }

    /// An ingester whose worker queues the test drains itself. Connection 1
    /// routes to `req[1]`, a two-slot queue nobody reads until the test says
    /// so: a REQ worker stuck in a long scan. Connection 2 routes to `req[0]`.
    /// Both share one req monitor, whose control queue the test reads.
    struct StalledWorker {
        ingest: tokio::sync::mpsc::Sender<IngestMsg>,
        writer: Receiver<WriterMsg>,
        req: Vec<Receiver<ReqMsg>>,
        mon: Receiver<MonitorMsg>,
        neg: Receiver<NegMsg>,
        /// Connection 2's frames.
        outbound: tokio::sync::mpsc::UnboundedReceiver<OutboundFrame>,
        _outbound_1: tokio::sync::mpsc::UnboundedReceiver<OutboundFrame>,
        conns: Arc<ConnTable>,
        gates: [IngressGate; 2],
        ingester: thread::JoinHandle<()>,
        _dir: tempfile::TempDir,
    }

    impl StalledWorker {
        fn start() -> Self {
            Self::with_capacity(2)
        }

        /// `stalled` slots in connection 1's req worker queue.
        fn with_capacity(stalled: usize) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let env = Env::open(dir.path(), small_map_env_options()).unwrap();
            env.ensure_initialized().unwrap();
            let mut config = Config::default();
            config.db = dir.path().to_path_buf();
            config.relay.auth.enabled = false;
            config.relay.abuse.enabled = false;
            let moderation = Arc::new(parking_lot::RwLock::new(
                env.begin_ro()
                    .and_then(|txn| load_moderation_snapshot_ro(&txn))
                    .unwrap(),
            ));
            let conns = Arc::new(ConnTable::new());
            let (out_tx, outbound) = tokio::sync::mpsc::unbounded_channel();
            conns.insert(2, Outbound::new(out_tx, 0));
            let (out_tx_1, _outbound_1) = tokio::sync::mpsc::unbounded_channel();
            conns.insert(1, Outbound::new(out_tx_1, 0));
            let (writer_tx, writer) = bounded(64);
            let (healthy_tx, healthy) = bounded(64);
            let (stalled_tx, stalled) = bounded(stalled);
            let (mon_tx, mon) = unbounded();
            let (neg_tx, neg) = bounded(64);
            let (ingest, ingest_rx) = tokio::sync::mpsc::channel(64);
            let ingester = thread::spawn({
                let conns = conns.clone();
                move || {
                    run_ingester(
                        env,
                        Arc::new(parking_lot::RwLock::new(config)),
                        conns,
                        Arc::new(Metrics::default()),
                        Arc::new(AbuseController::default()),
                        moderation,
                        ingest_rx,
                        writer_tx,
                        vec![healthy_tx, stalled_tx],
                        vec![mon_tx],
                        vec![neg_tx],
                    )
                }
            });
            let gates = [(); 2].map(|_| Arc::new(tokio::sync::watch::Sender::new(true)));
            for (conn_id, gate) in [1, 2].into_iter().zip(&gates) {
                ingest
                    .blocking_send(IngestMsg::Open {
                        conn_id,
                        gate: Some(gate.clone()),
                    })
                    .unwrap();
            }
            Self {
                ingest,
                writer,
                req: vec![healthy, stalled],
                mon,
                neg,
                outbound,
                _outbound_1,
                conns,
                gates,
                ingester,
                _dir: dir,
            }
        }

        fn send(&self, conn_id: u64, payload: Value) {
            self.ingest
                .blocking_send(IngestMsg::Client {
                    conn_id,
                    source: TransportSource::Unix,
                    payload: payload.to_string(),
                    share: None,
                })
                .unwrap();
        }

        fn gate_open(&self, conn_id: u64) -> bool {
            *self.gates[conn_id as usize - 1].borrow()
        }

        /// Connection 1 has six messages in flight when its worker stalls: two
        /// fill the queue and the other four park.
        fn fill(&self, last: Value) {
            for i in 0..5 {
                self.send(1, json!(["REQ", format!("s{i}"), {"kinds": [1]}]));
            }
            self.send(1, last);
        }

        /// Connection 2, on the same ingester, still gets its REQ to its own
        /// worker and an immediate reply. The ingester handles messages in
        /// order, so everything sent before this has been dispatched.
        fn assert_other_connection_progresses(&mut self, sub_id: &str) {
            self.send(2, json!(["REQ", sub_id, {"kinds": [1]}]));
            match self.req[0].recv_timeout(Duration::from_secs(2)) {
                Ok(ReqMsg::Scan(sub)) => {
                    assert_eq!((sub.conn_id, sub.sub_id.as_str()), (2, sub_id));
                }
                _ => panic!("connection 2's REQ did not reach its worker"),
            }
            self.send(2, json!(["NOT-A-COMMAND"]));
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            loop {
                if let Ok(frame) = self.outbound.try_recv() {
                    assert!(frame.into_text().contains("NOTICE"));
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "connection 2 got no reply"
                );
                thread::sleep(Duration::from_millis(1));
            }
            assert!(self.gate_open(2), "connection 2 is never paused");
        }

        fn recv_stalled(&self) -> ReqMsg {
            self.req[1]
                .recv_timeout(Duration::from_secs(2))
                .expect("stalled worker queue never refilled")
        }

        fn finish(self) {
            drop(self.ingest);
            self.ingester.join().unwrap();
        }
    }

    /// Connections that come and go behind a stalled worker leave nothing
    /// parked: their REQs are dropped with them, and as the worker never saw
    /// them it needs no Close. The backlog does not grow with churn.
    #[test]
    fn connection_churn_behind_full_worker_queue_leaves_nothing_parked() {
        let mut relay = StalledWorker::start();
        relay.fill(json!(["REQ", "last", {"kinds": [1]}]));
        // Odd ids route to the stalled worker, like connection 1.
        for conn_id in (3..203).step_by(2) {
            let gate = Arc::new(tokio::sync::watch::Sender::new(true));
            relay
                .ingest
                .blocking_send(IngestMsg::Open {
                    conn_id,
                    gate: Some(gate.clone()),
                })
                .unwrap();
            relay.send(conn_id, json!(["REQ", "churn", {"kinds": [1]}]));
            relay
                .ingest
                .blocking_send(IngestMsg::Close { conn_id })
                .unwrap();
        }
        relay.assert_other_connection_progresses("after-churn");

        for i in 0..5 {
            assert_new_sub(relay.recv_stalled(), &format!("s{i}"));
        }
        assert_new_sub(relay.recv_stalled(), "last");
        thread::sleep(Duration::from_millis(20));
        assert!(
            relay.req[1].try_recv().is_err(),
            "closed connections left work behind"
        );
        assert!(relay.writer.try_recv().is_err());
        assert!(relay.neg.try_recv().is_err());
        relay.finish();
    }

    fn assert_new_sub(msg: ReqMsg, sub_id: &str) {
        match msg {
            ReqMsg::Scan(sub) => assert_eq!((sub.conn_id, sub.sub_id.as_str()), (1, sub_id)),
            _ => panic!("expected REQ {sub_id} for connection 1"),
        }
    }

    /// A full worker queue parks messages instead of blocking the ingester,
    /// pauses only the connection that owns them, and still delivers its
    /// CLOSE, after its REQ, once the worker drains.
    #[test]
    fn full_worker_queue_does_not_stall_other_connections() {
        let mut relay = StalledWorker::start();
        relay.fill(json!(["CLOSE", "s0"]));
        relay.assert_other_connection_progresses("other");
        assert!(!relay.gate_open(1), "connection 1 is paused");

        for i in 0..5 {
            assert_new_sub(relay.recv_stalled(), &format!("s{i}"));
        }
        match relay.recv_stalled() {
            ReqMsg::Cancel {
                conn_id,
                sub_id,
                count_only: false,
                ..
            } => {
                assert_eq!((conn_id, sub_id.as_str()), (1, "s0"));
            }
            _ => panic!("expected the parked CLOSE"),
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !relay.gate_open(1) {
            assert!(
                std::time::Instant::now() < deadline,
                "connection 1 never resumed"
            );
            thread::sleep(Duration::from_millis(1));
        }
        relay.finish();
    }

    /// Disconnecting behind a full worker queue must not move the stall into
    /// connection teardown (#83 review): the Close is handled at once, drops
    /// the connection's parked work, and reaches every worker once the stalled
    /// one drains, so its subscriptions are removed.
    #[test]
    fn disconnect_behind_full_worker_queue_still_tears_down() {
        let mut relay = StalledWorker::start();
        relay.fill(json!(["REQ", "last", {"kinds": [1]}]));
        relay
            .ingest
            .blocking_send(IngestMsg::Close { conn_id: 1 })
            .unwrap();
        relay.assert_other_connection_progresses("after-close");
        // Connection 1 never reached the writer or the sync worker, so they
        // hold nothing for it to clear.
        assert!(relay.writer.try_recv().is_err());
        assert!(relay.neg.try_recv().is_err());

        assert_new_sub(relay.recv_stalled(), "s0");
        assert_new_sub(relay.recv_stalled(), "s1");
        assert!(matches!(relay.recv_stalled(), ReqMsg::Close { conn_id: 1 }));
        thread::sleep(Duration::from_millis(20));
        assert!(relay.req[1].try_recv().is_err(), "nothing runs after Close");
        relay.finish();
    }

    fn relay_env(dir: &std::path::Path) -> (Env, Config) {
        let env = Env::open(dir, EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let mut cfg = Config::default();
        cfg.db = dir.to_path_buf();
        cfg.relay.auth.enabled = false;
        (env, cfg)
    }

    /// A relay thread still running when the last handle's join times out
    /// must not end up closing the environment itself when it finally exits:
    /// the guard goes to a joiner that drops it only after joining it.
    #[test]
    fn a_timed_out_join_keeps_the_environment_open_until_threads_exit() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), small_map_env_options()).unwrap();
        env.ensure_initialized().unwrap();
        let alive = Arc::downgrade(&env.inner);
        let (release_tx, release_rx) = bounded::<()>(1);
        let outlived = Arc::new(AtomicBool::new(false));
        // A relay thread that reads, then exits only when told to: after the
        // join deadline.
        let straggler = {
            let env = env.clone();
            let (alive, outlived) = (alive.clone(), outlived.clone());
            thread::spawn(move || {
                drop(env.begin_ro().unwrap());
                release_rx.recv().unwrap();
                drop(env);
                outlived.store(alive.upgrade().is_some(), Ordering::Relaxed);
            })
        };
        // Room for both releases' `Stop`.
        let (writer_tx, _writer_rx) = bounded(2);
        let mut threads = RelayThreads {
            shutdown: Arc::new(AtomicBool::new(false)),
            shutdown_notify: Arc::new(tokio::sync::Notify::new()),
            ingest: Vec::new(),
            writer_tx,
            running: Mutex::new(RunningThreads {
                ingesters: Vec::new(),
                workers: vec![straggler],
            }),
            env: Mutex::new(Some(env)),
        };
        threads.release(Duration::from_millis(20));
        drop(threads);
        assert!(alive.upgrade().is_some());
        release_tx.send(()).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while alive.upgrade().is_some() {
            assert!(
                std::time::Instant::now() < deadline,
                "environment never closed"
            );
            thread::sleep(Duration::from_millis(1));
        }
        assert!(
            outlived.load(Ordering::Relaxed),
            "the exiting relay thread held the environment's last reference"
        );
    }

    /// Starts and stops relays from several threads at once. A relay thread
    /// that read from LMDB clears its reader slot, in the lock-file mapping,
    /// from a thread-local destructor after its closure returns. When the
    /// last relay thread to exit closed the environment, it could unmap that
    /// slot under another thread's destructor and crash the process
    /// (SIGSEGV, about once in a few thousand teardowns on Linux). A crash is
    /// the failure, so this is a stress run:
    ///
    /// `cargo test -p wok-relay --lib relay_teardown_stress -- --ignored`
    #[test]
    #[ignore = "stress run; the failure is a crash"]
    fn relay_teardown_stress() {
        let runs: Vec<_> = (0..8)
            .map(|_| {
                thread::spawn(|| {
                    for _ in 0..500 {
                        let dir = tempfile::tempdir().unwrap();
                        let env = Env::open(dir.path(), small_map_env_options()).unwrap();
                        env.ensure_initialized().unwrap();
                        let mut cfg = Config::default();
                        cfg.db = dir.path().to_path_buf();
                        cfg.relay.auth.enabled = false;
                        let handle = start(env, cfg).unwrap();
                        // The req monitors read once db-watch reports in.
                        thread::sleep(Duration::from_millis(2));
                        handle.shutdown_and_join(Duration::from_secs(10)).unwrap();
                    }
                })
            })
            .collect();
        for run in runs {
            run.join().unwrap();
        }
    }

    // An Env the relay never releases is never `mdb_env_close`d; on macOS
    // its two POSIX semaphores then outlive the process and, once
    // kern.posix.sem.max is exhausted, every Env::open fails with ENOSPC.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_and_join_releases_env_while_handles_remain() {
        let dir = tempfile::tempdir().unwrap();
        let (env, cfg) = relay_env(dir.path());
        let env_alive = Arc::downgrade(&env.inner);
        let handle = start(env, cfg).unwrap();
        // A transport's clone and an open connection outlive the join.
        let transport = handle.clone();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<OutboundFrame>();
        let conn = transport.next_conn_id();
        transport.register(conn, Outbound::new(tx, 0)).await;
        let event = sign_event(json!({
            "created_at": now_secs(), "kind": 1, "tags": [], "content": "before-join"
        }));
        transport
            .client_message(
                conn,
                TransportSource::ip_address("127.0.0.1".parse().unwrap()),
                json!(["EVENT", event]).to_string(),
            )
            .await;
        assert!(recv_outbound(&mut rx).await.contains("true"));

        let joiner = handle.clone();
        tokio::task::spawn_blocking(move || joiner.shutdown_and_join(Duration::from_secs(10)))
            .await
            .unwrap()
            .unwrap();
        assert!(handle.is_shutdown());
        {
            let running = handle.threads.running.lock();
            assert!(running.ingesters.is_empty() && running.workers.is_empty());
        }
        assert_eq!(env_alive.strong_count(), 0, "relay threads still hold Env");
        // Idempotent, and the stopped writer answers instead of hanging.
        handle.shutdown_and_join(Duration::from_secs(1)).unwrap();
        assert!(transport
            .manage(ManagementCmd::AllowKind { kind: 1 })
            .await
            .is_err());

        // The closed environment reopens with the committed event intact.
        let reopened = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
        let txn = reopened.begin_ro().unwrap();
        assert_eq!(most_recent_levid_ro(&txn).unwrap(), 1);
    }

    #[test]
    fn dropping_last_handle_joins_relay_threads() {
        let dir = tempfile::tempdir().unwrap();
        let (env, cfg) = relay_env(dir.path());
        let env_alive = Arc::downgrade(&env.inner);
        let handle = start(env, cfg).unwrap();
        let clone = handle.clone();
        drop(handle);
        assert!(
            env_alive.strong_count() > 0,
            "a live handle keeps the relay up"
        );
        // No request_shutdown: the last drop alone must stop the threads.
        drop(clone);
        assert_eq!(env_alive.strong_count(), 0, "relay threads still hold Env");
    }

    /// A REQ's registration is queued for the req monitor when the REQ is
    /// admitted, however far behind the monitor is, and its history scan only
    /// after that. So an event published after the REQ cannot reach the
    /// monitor ahead of the registration, and the scan's snapshot cannot miss
    /// events the monitor matched first. Nothing reads the monitor here.
    #[test]
    fn registrations_never_wait_for_the_monitor() {
        let relay = StalledWorker::with_capacity(64);
        for i in 0..100 {
            relay.send(1, json!(["REQ", format!("s{i}"), {"kinds": [1]}]));
        }
        relay.send(1, json!(["CLOSE", "s99"]));
        for i in 0..100 {
            assert_new_sub(relay.recv_stalled(), &format!("s{i}"));
            assert!(
                relay.mon.len() > i,
                "REQ s{i} was scanned before it was registered"
            );
        }
        assert!(matches!(
            relay.recv_stalled(),
            ReqMsg::Cancel { conn_id: 1, ref sub_id, count_only: false, .. } if sub_id.as_str() == "s99"
        ));
        let registered: Vec<String> = relay
            .mon
            .try_iter()
            .map(|msg| match msg {
                MonitorMsg::Register(sub) => sub.sub_id.to_string(),
                MonitorMsg::Remove { sub_id, .. } => format!("-{sub_id}"),
                _ => panic!("unexpected monitor message"),
            })
            .collect();
        let expected: Vec<String> = (0..100)
            .map(|i| format!("s{i}"))
            .chain(["-s99".to_string()])
            .collect();
        assert_eq!(registered, expected);
        relay.finish();
    }

    /// One req monitor thread, driven directly. Connection 1 is the subject.
    /// Connection 2 holds a live match-all subscription: its EVENT for an
    /// event shows the monitor has matched that event. Registering opens the
    /// subscription gate as the ingester would.
    struct MonitorHarness {
        env: Env,
        cfg: Arc<parking_lot::RwLock<Config>>,
        tx: Sender<MonitorMsg>,
        data: Sender<MonitorData>,
        conns: Arc<ConnTable>,
        metrics: Arc<Metrics>,
        subject: tokio::sync::mpsc::UnboundedReceiver<OutboundFrame>,
        observer: tokio::sync::mpsc::UnboundedReceiver<OutboundFrame>,
        thread: Option<thread::JoinHandle<()>>,
        _dir: tempfile::TempDir,
    }

    impl MonitorHarness {
        fn start(live_buffer_bytes: usize) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let env = Env::open(dir.path(), small_map_env_options()).unwrap();
            env.ensure_initialized().unwrap();
            let mut cfg = Config::default();
            cfg.db = dir.path().to_path_buf();
            cfg.relay.auth.enabled = false;
            cfg.relay.max_live_buffer_bytes = live_buffer_bytes;
            let conns = Arc::new(ConnTable::new());
            let (subject_tx, subject) = tokio::sync::mpsc::unbounded_channel();
            let (observer_tx, observer) = tokio::sync::mpsc::unbounded_channel();
            conns.insert(1, Outbound::new(subject_tx, 0));
            conns.insert(2, Outbound::new(observer_tx, 0));
            let metrics = Arc::new(Metrics::default());
            let (tx, rx) = unbounded();
            let (data, data_rx) = bounded(64);
            let cfg = Arc::new(parking_lot::RwLock::new(cfg));
            let thread = {
                let (env, cfg, conns, metrics) =
                    (env.clone(), cfg.clone(), conns.clone(), metrics.clone());
                let moderation = Default::default();
                thread::spawn(move || {
                    run_req_monitor(env, cfg, conns, metrics, moderation, rx, data_rx)
                })
            };
            let mut harness = Self {
                env,
                cfg,
                tx,
                data,
                conns,
                metrics,
                subject,
                observer,
                thread: Some(thread),
                _dir: dir,
            };
            let all = SubId::new("all").unwrap();
            harness.conns.open_sub(2, Ns::Req, &all, 1, 0);
            harness.send(MonitorMsg::Register(Self::sub(2, "all", json!({}), 1, 0)));
            harness.send(MonitorMsg::HistoryDone {
                conn_id: 2,
                sub_id: SubId::new("all").unwrap(),
                generation: 1,
                snapshot: 0,
                hints: EoseHints::default(),
            });
            let eose = Self::next(&mut harness.observer);
            assert_eq!(eose[0], "EOSE", "{eose}");
            harness
        }

        /// A REQ as the ingester admits it, with its history snapshot.
        fn sub(
            conn_id: u64,
            sub_id: &str,
            filter: Value,
            generation: u64,
            snapshot: u64,
        ) -> Subscription {
            let group = NostrFilterGroup::from_value(&filter, 500, 3, 16).unwrap();
            let mut sub = Subscription::new(conn_id, SubId::new(sub_id).unwrap(), group, false);
            sub.generation = generation;
            sub.latest_event_id = snapshot;
            sub
        }

        fn register(&self, generation: u64, filter: Value, snapshot: u64) {
            let x = SubId::new("x").unwrap();
            self.conns.open_sub(1, Ns::Req, &x, generation, 0);
            self.send(MonitorMsg::Register(Self::sub(
                1, "x", filter, generation, snapshot,
            )));
        }

        fn send(&self, msg: MonitorMsg) {
            self.tx.send(msg).unwrap();
        }

        fn feed(&self, msg: MonitorData) {
            self.data.send(msg).unwrap();
        }

        fn next(rx: &mut tokio::sync::mpsc::UnboundedReceiver<OutboundFrame>) -> Value {
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            loop {
                if let Ok(frame) = rx.try_recv() {
                    return serde_json::from_str(&frame.into_text()).unwrap();
                }
                assert!(std::time::Instant::now() < deadline, "no frame");
                thread::sleep(Duration::from_millis(1));
            }
        }

        fn parse(kind: u64, content: &str) -> wok_event::ParsedEvent {
            Self::parse_at(kind, content, now_secs())
        }

        fn parse_at(kind: u64, content: &str, created_at: u64) -> wok_event::ParsedEvent {
            Self::parse_tagged(kind, content, created_at, json!([]))
        }

        fn parse_tagged(
            kind: u64,
            content: &str,
            created_at: u64,
            tags: Value,
        ) -> wok_event::ParsedEvent {
            let event = sign_event(json!({
                "created_at": created_at, "kind": kind, "tags": tags, "content": content,
            }));
            wok_event::parse_and_verify_event(
                &event,
                &wok_event::EventLimits::default(),
                None,
                true,
                false,
            )
            .unwrap()
        }

        /// Wait until the observer has the event, and so the monitor matched it.
        fn observe(&mut self, id: &str) {
            let event = Self::next(&mut self.observer);
            assert_eq!(event[2]["id"], id, "{event}");
        }

        /// Store a kind-1 event without telling the monitor. Returns its
        /// local event id and event id.
        fn write(&self, content: &str) -> (u64, String) {
            self.write_event(Self::parse(1, content))
        }

        fn write_event(&self, parsed: wok_event::ParsedEvent) -> (u64, String) {
            let id = to_hex(parsed.packed.view().id());
            let mut txn = self.env.begin_rw().unwrap();
            let mut events = vec![EventToWrite::new(parsed.packed.into_bytes(), parsed.json)];
            wok_db::write_events(&mut txn, &mut wok_db::NoopNegentropy, &mut events, false)
                .unwrap();
            txn.commit().unwrap();
            let lev = most_recent_levid_ro(&self.env.begin_ro().unwrap()).unwrap();
            (lev, id)
        }

        /// Store a kind-1 event, tell the monitor and wait until it matched it.
        fn store(&mut self, content: &str) -> (u64, String) {
            let (lev, id) = self.write(content);
            self.feed(MonitorData::DbChange);
            self.observe(&id);
            (lev, id)
        }

        fn ephemeral(&mut self, content: &str) -> String {
            self.ephemeral_at(content, now_secs())
        }

        fn ephemeral_at(&mut self, content: &str, created_at: u64) -> String {
            let parsed = Self::parse_at(20_001, content, created_at);
            let id = to_hex(parsed.packed.view().id());
            self.feed(MonitorData::Ephemeral(Arc::new(HeldEvent {
                packed: parsed.packed.into_bytes(),
                json: parsed.json,
            })));
            self.observe(&id);
            id
        }

        /// The subject's frames so far, as `[type, sub id, event id]`.
        fn frames(&mut self) -> Vec<(String, String, String)> {
            let mut frames = Vec::new();
            while let Ok(frame) = self.subject.try_recv() {
                let v: Value = serde_json::from_str(&frame.into_text()).unwrap();
                let detail = match v[0].as_str().unwrap() {
                    "EVENT" => v[2]["id"].as_str().unwrap().to_string(),
                    "CLOSED" => v[2].as_str().unwrap().to_string(),
                    _ => String::new(),
                };
                frames.push((
                    v[0].as_str().unwrap().into(),
                    v[1].as_str().unwrap().into(),
                    detail,
                ));
            }
            frames
        }

        /// Send `msg` and return the subject's frames once the monitor has
        /// handled it.
        fn apply(&mut self, msg: MonitorMsg) -> Vec<(String, String, String)> {
            self.send(msg);
            self.sync();
            self.frames()
        }

        /// Wait until the monitor has handled everything sent so far: the
        /// observer sees a later sentinel event.
        fn sync(&mut self) {
            let sentinel = Self::parse(20_002, "sentinel");
            let id = to_hex(sentinel.packed.view().id());
            self.feed(MonitorData::Ephemeral(Arc::new(HeldEvent {
                packed: sentinel.packed.into_bytes(),
                json: sentinel.json,
            })));
            self.observe(&id);
        }

        fn history_done(
            &mut self,
            generation: u64,
            snapshot: u64,
        ) -> Vec<(String, String, String)> {
            self.apply(MonitorMsg::HistoryDone {
                conn_id: 1,
                sub_id: SubId::new("x").unwrap(),
                generation,
                snapshot,
                hints: EoseHints::default(),
            })
        }
    }

    impl Drop for MonitorHarness {
        fn drop(&mut self) {
            let (tx, _) = unbounded();
            drop(std::mem::replace(&mut self.tx, tx));
            let (data, _) = bounded(1);
            drop(std::mem::replace(&mut self.data, data));
            if let Some(thread) = self.thread.take() {
                thread.join().unwrap();
            }
        }
    }

    fn event_frame(id: &str) -> (String, String, String) {
        ("EVENT".into(), "x".into(), id.into())
    }

    fn eose_frame() -> (String, String, String) {
        ("EOSE".into(), "x".into(), String::new())
    }

    /// Matches that arrive while the history is sent are held, then follow
    /// EOSE in arrival order. History from a stale generation sends nothing.
    #[test]
    fn monitor_sends_held_matches_after_eose_in_arrival_order() {
        let mut h = MonitorHarness::start(0);
        let (snapshot, _) = h.store("before the REQ");
        h.register(7, json!({"kinds": [1, 20001]}), snapshot);
        let (_, stored) = h.store("after the REQ");
        let ephemeral = h.ephemeral("live only");
        let (_, later) = h.store("later");
        assert!(h.frames().is_empty(), "nothing goes out before EOSE");

        assert!(h.history_done(6, snapshot).is_empty(), "stale generation");
        assert_eq!(
            h.history_done(7, snapshot),
            [
                eose_frame(),
                event_frame(&stored),
                event_frame(&ephemeral),
                event_frame(&later)
            ]
        );
        let (_, live) = h.store("live");
        assert_eq!(h.frames(), [event_frame(&live)]);
        assert!(h.history_done(7, snapshot).is_empty(), "already live");
    }

    /// A monitor that matched commits past the history snapshot before it saw
    /// the registration re-reads them from the database.
    #[test]
    fn monitor_rereads_events_it_matched_before_the_registration() {
        let mut h = MonitorHarness::start(0);
        let (snapshot, _) = h.store("in the history");
        let (_, gap) = h.store("committed after the snapshot");
        h.register(1, json!({"kinds": [1]}), snapshot);
        let (_, held) = h.store("held");
        assert_eq!(
            h.history_done(1, snapshot),
            [eose_frame(), event_frame(&gap), event_frame(&held)]
        );
    }

    /// Stored events up to the snapshot are the history's, even when the
    /// monitor matches them only after the registration: it leaves them alone.
    #[test]
    fn monitor_leaves_events_up_to_the_snapshot_to_the_history() {
        let mut h = MonitorHarness::start(0);
        let (snapshot, history) = h.write("stored before the REQ, matched after it");
        h.register(1, json!({"kinds": [1]}), snapshot);
        h.feed(MonitorData::DbChange);
        h.observe(&history);
        let (_, live) = h.store("after the REQ");
        assert_eq!(
            h.history_done(1, snapshot),
            [eose_frame(), event_frame(&live)]
        );
    }

    /// Past the buffer bound, stored matches are re-read from the database
    /// after the history and ephemeral ones are dropped and counted.
    #[test]
    fn monitor_overflow_rereads_stored_and_drops_ephemeral() {
        let mut h = MonitorHarness::start(2 * wok_query::pending::STORED_ENTRY_BYTES);
        h.register(1, json!({"kinds": [1, 20001]}), 0);
        let ids: Vec<String> = (0..3).map(|i| h.store(&format!("stored {i}")).1).collect();
        assert_eq!(h.metrics.live_buffer_overflows.load(Ordering::Relaxed), 1);
        h.ephemeral("too big for the buffer");
        assert_eq!(
            h.metrics
                .live_buffer_dropped_ephemeral
                .load(Ordering::Relaxed),
            1
        );
        let mut expected = vec![eose_frame()];
        expected.extend(ids.iter().map(|id| event_frame(id)));
        assert_eq!(h.history_done(1, 0), expected);
    }

    /// Held events are checked against the read policy again when they are
    /// sent: one that expired or became restricted while the history was
    /// sent is dropped.
    #[test]
    fn monitor_rechecks_held_events_against_the_current_policy() {
        let mut h = MonitorHarness::start(0);
        h.register(1, json!({"kinds": [1, 20001]}), 0);
        h.ephemeral_at("expires while held", now_secs() - 10);
        let (_, stored) = h.store("stored");
        h.cfg.write().events.ephemeral_lifetime_secs = 5;
        assert_eq!(h.history_done(1, 0), [eose_frame(), event_frame(&stored)]);

        h.register(2, json!({"kinds": [1, 20001]}), 0);
        h.ephemeral("restricted while held");
        h.store("restricted while held");
        h.cfg.write().relay.auth.recipient_only_kinds = vec![1, 20001];
        assert_eq!(h.history_done(2, 0), [eose_frame()]);
    }

    /// REQs the ingester admitted under an earlier read policy, one waiting
    /// behind its connection's running scan, are refused when they reach a
    /// slice after the policy tightened, rather than scanned.
    #[test]
    fn queued_scans_are_admitted_again_when_they_run() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let mut cfg = Config::default();
        cfg.db = dir.path().to_path_buf();
        cfg.relay.auth.service_url = "wss://relay.example.com".into();
        let conns = ConnTable::new();
        let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel();
        conns.insert(1, Outbound::new(out_tx, 0));
        let metrics = Metrics::default();
        let (mon_tx, _mon_rx) = unbounded();
        let mon_txs = vec![mon_tx];
        let worker = ReqWorker {
            conns: &conns,
            metrics: &metrics,
            mon_txs: &mon_txs,
        };
        // One scan at a time per connection, so the second waits.
        let mut queries = QueryScheduler::new(1, 10_000, 1_000_001);
        queries.set_max_waiting_per_connection(8);
        let txn = env.begin_ro().unwrap();
        for (generation, id) in [(1, "running"), (2, "waiting")] {
            let sid = SubId::new(id).unwrap();
            conns.open_sub(1, Ns::Req, &sid, generation, 0);
            let group = NostrFilterGroup::from_value(&json!({"kinds": [1]}), 2_000, 8, 16).unwrap();
            let mut sub = Subscription::new(1, sid, group, false);
            sub.generation = generation;
            queries.add_sub(&txn, sub).unwrap();
        }
        assert_eq!(queries.waiting(), 1);

        cfg.relay.auth.read_policy = crate::config::AccessPolicy::Authenticated;
        let mut decomp = Decompressor::new();
        for _ in 0..2 {
            worker.slice(&mut queries, &txn, &cfg, &HashMap::new(), &mut decomp);
        }
        let mut frames = Vec::new();
        while let Ok(frame) = out_rx.try_recv() {
            frames.push(serde_json::from_str::<Value>(&frame.into_text()).unwrap());
        }
        let refusal = "auth-required: this relay serves only authenticated users";
        assert_eq!(
            frames,
            [
                json!(["CLOSED", "running", refusal]),
                json!(["CLOSED", "waiting", refusal])
            ]
        );
        // Each is the read policy's refusal.
        assert_eq!(metrics.refusals.get(Setting::ReadPolicy), 2);
        assert!(!queries.has_running());
        assert_eq!(queries.waiting(), 0);
    }

    /// A reload to an authenticated read policy stops what an anonymous
    /// connection's subscriptions deliver, held while its history was sent
    /// and live, until it authenticates.
    #[test]
    fn monitor_stops_deliveries_a_tightened_read_policy_refuses() {
        let mut h = MonitorHarness::start(0);
        // The observer stays admitted.
        h.send(MonitorMsg::SetAuth {
            conn_id: 2,
            authed: [9; 32],
        });
        h.register(1, json!({"kinds": [1, 20001]}), 0);
        h.ephemeral("held");
        h.store("held");
        h.cfg.write().relay.auth.read_policy = crate::config::AccessPolicy::Authenticated;
        assert_eq!(h.history_done(1, 0), [eose_frame()]);
        h.ephemeral("live");
        h.store("live");
        h.sync();
        assert_eq!(h.frames(), []);

        h.send(MonitorMsg::SetAuth {
            conn_id: 1,
            authed: [7; 32],
        });
        let (_, after) = h.store("after AUTH");
        h.sync();
        assert_eq!(h.frames(), [event_frame(&after)]);
    }

    /// A pending subscription holds matches its connection may not read yet,
    /// stored and live-only: the connection may AUTH before EOSE, and what
    /// was held is checked against the read policy when it is sent.
    #[test]
    fn monitor_holds_matches_until_the_connection_may_read_them() {
        let mut h = MonitorHarness::start(0);
        let pk = [7; 32];
        let p = json!([["p", hex::encode(pk)]]);
        h.register(1, json!({"#p": [hex::encode(pk)]}), 0);
        let (_, wrap) = h.write_event(MonitorHarness::parse_tagged(
            1059,
            "gift wrap",
            now_secs(),
            p.clone(),
        ));
        h.feed(MonitorData::DbChange);
        let ephemeral = MonitorHarness::parse_tagged(21059, "ephemeral wrap", now_secs(), p);
        let ephemeral_id = to_hex(ephemeral.packed.view().id());
        h.feed(MonitorData::Ephemeral(Arc::new(HeldEvent {
            packed: ephemeral.packed.into_bytes(),
            json: ephemeral.json,
        })));
        // Both are matched before the connection authenticates.
        h.sync();
        assert!(h
            .apply(MonitorMsg::SetAuth {
                conn_id: 1,
                authed: pk,
            })
            .is_empty());
        assert_eq!(
            h.history_done(1, 0),
            [eose_frame(), event_frame(&wrap), event_frame(&ephemeral_id)]
        );
    }

    /// A monitor that cannot open a read transaction keeps the subscription
    /// changes and database change it was handed, which nobody resends, and
    /// applies them once reads work again.
    #[test]
    fn monitor_keeps_subscription_changes_through_read_failures() {
        let mut h = MonitorHarness::start(0);
        let (snapshot, _) = h.store("before the REQ");
        h.register(1, json!({"kinds": [1]}), snapshot);
        let (_, held) = h.store("held");
        let event_id = |frame: Value| frame[2]["id"].as_str().unwrap().to_string();

        fault::fail_reads(h.env.path(), 3);
        h.send(MonitorMsg::HistoryDone {
            conn_id: 1,
            sub_id: SubId::new("x").unwrap(),
            generation: 1,
            snapshot,
            hints: EoseHints::default(),
        });
        let eose = MonitorHarness::next(&mut h.subject);
        assert_eq!(
            (eose[0].as_str(), eose[1].as_str()),
            (Some("EOSE"), Some("x"))
        );
        assert_eq!(event_id(MonitorHarness::next(&mut h.subject)), held);

        fault::fail_reads(h.env.path(), 3);
        let (_, live) = h.write("committed while reads fail");
        h.feed(MonitorData::DbChange);
        assert_eq!(event_id(MonitorHarness::next(&mut h.subject)), live);
    }

    /// `Remove` drops only the generation it names: cleanup of an older REQ
    /// that reaches the monitor after a newer REQ took the id leaves the newer
    /// one running.
    #[test]
    fn monitor_removes_only_the_named_generation() {
        let mut h = MonitorHarness::start(0);
        let filter = json!({"kinds": [1]});
        let remove = |generation| MonitorMsg::Remove {
            conn_id: 1,
            sub_id: SubId::new("x").unwrap(),
            generation,
        };
        h.register(1, filter.clone(), 0);
        assert_eq!(h.history_done(1, 0), [eose_frame()]);
        let (snapshot, _) = h.store("before the replacement");
        assert_eq!(h.frames().len(), 1);
        h.register(3, filter, snapshot);
        assert!(h.apply(remove(1)).is_empty());
        assert_eq!(h.history_done(3, snapshot), [eose_frame()]);
        let (_, live) = h.store("live for REQ 3");
        assert_eq!(h.frames(), [event_frame(&live)]);
        assert!(h.apply(remove(3)).is_empty());
        h.store("after removal");
        assert!(h.frames().is_empty());
    }

    /// A req worker that cannot open a read transaction refuses the REQ or
    /// COUNT it was handed instead of dropping it, so the client still gets
    /// CLOSED (and the monitor drops a REQ's registration), and keeps working.
    #[test]
    fn req_worker_refuses_what_it_cannot_start_when_reads_fail() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), small_map_env_options()).unwrap();
        env.ensure_initialized().unwrap();
        let mut cfg = Config::default();
        cfg.db = dir.path().to_path_buf();
        cfg.relay.auth.enabled = false;
        let conns = Arc::new(ConnTable::new());
        let (out_tx, mut outbound) = tokio::sync::mpsc::unbounded_channel();
        conns.insert(1, Outbound::new(out_tx, 0));
        let (req_tx, req_rx) = bounded(8);
        let (mon_tx, mon_rx) = bounded(8);
        let worker = {
            let env = env.clone();
            let cfg = Arc::new(parking_lot::RwLock::new(cfg));
            let metrics = Arc::new(Metrics::default());
            let conns = conns.clone();
            thread::spawn(move || run_req_worker(env, cfg, conns, metrics, req_rx, vec![mon_tx]))
        };
        let x = SubId::new("x").unwrap();
        let closed = |outbound: &mut tokio::sync::mpsc::UnboundedReceiver<OutboundFrame>| {
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            loop {
                if let Ok(frame) = outbound.try_recv() {
                    break frame.into_text();
                }
                assert!(std::time::Instant::now() < deadline, "no CLOSED");
                thread::sleep(Duration::from_millis(1));
            }
        };
        let sub = |generation, count_only| {
            let group = NostrFilterGroup::from_value(&json!({"kinds": [1]}), 500, 3, 16).unwrap();
            let mut sub = Subscription::new(1, SubId::new("x").unwrap(), group, count_only);
            sub.generation = generation;
            if !count_only {
                sub.latest_event_id = 0;
            }
            sub
        };
        let monitor = || mon_rx.recv_timeout(Duration::from_secs(2)).unwrap();

        fault::fail_reads(env.path(), 1);
        conns.open_sub(1, Ns::Req, &x, 7, 0);
        req_tx.send(ReqMsg::Scan(sub(7, false))).unwrap();
        assert!(matches!(
            monitor(),
            MonitorMsg::Remove { generation: 7, .. }
        ));
        let reply = closed(&mut outbound);
        assert!(reply.starts_with(r#"["CLOSED","x","error: "#), "{reply}");
        assert!(!conns.is_open(1, Ns::Req, &x));
        conns.open_sub(1, Ns::Req, &x, 8, 0);
        req_tx.send(ReqMsg::Scan(sub(8, false))).unwrap();
        assert!(matches!(
            monitor(),
            MonitorMsg::HistoryDone { generation: 8, .. }
        ));

        fault::fail_reads(env.path(), 1);
        conns.open_sub(1, Ns::Count, &x, 9, 0);
        req_tx.send(ReqMsg::Count(sub(9, true))).unwrap();
        let reply = closed(&mut outbound);
        assert!(reply.starts_with(r#"["CLOSED","x","error: "#), "{reply}");
        drop(req_tx);
        worker.join().unwrap();
    }

    /// A database with enough kind-1 history that a query reading all of it
    /// spans many time slices at `slow_scan_config`'s budget. Returns the
    /// newest local event id with it.
    fn long_history() -> (tempfile::TempDir, Env, u64) {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), small_map_env_options()).unwrap();
        env.ensure_initialized().unwrap();
        let mut events: Vec<EventToWrite> = (0..20_000u64)
            .map(|i| {
                let mut id = [0xBBu8; 32];
                id[..8].copy_from_slice(&i.to_be_bytes());
                let event = json!({
                    "id": hex::encode(id), "pubkey": "11".repeat(32),
                    "created_at": 1_700_000_000 + i, "kind": 1, "tags": [],
                    "content": "history", "sig": "00".repeat(64),
                });
                let parsed = wok_event::parse_and_verify_event(
                    &event,
                    &wok_event::EventLimits::default(),
                    None,
                    false,
                    false,
                )
                .unwrap();
                EventToWrite::new(parsed.packed.into_bytes(), parsed.json)
            })
            .collect();
        let mut txn = env.begin_rw().unwrap();
        wok_db::write_events(&mut txn, &mut wok_db::NoopNegentropy, &mut events, false).unwrap();
        txn.commit().unwrap();
        let snapshot = most_recent_levid_ro(&env.begin_ro().unwrap()).unwrap();
        (dir, env, snapshot)
    }

    /// Time slices as short as they go, so a query's slice count depends on
    /// the work it does, not on how fast the machine is.
    fn slow_scan_config(dir: &std::path::Path) -> Config {
        let mut cfg = Config::default();
        cfg.db = dir.to_path_buf();
        cfg.relay.auth.enabled = false;
        cfg.relay.query_timeslice_budget_us = 1;
        cfg.relay.max_filter_limit = 50_000;
        cfg.relay.max_total_events_per_req = 0;
        cfg
    }

    /// A REQ (or COUNT) on connection 1 as the ingester hands it over.
    fn queued_sub(
        sub_id: &str,
        filter: Value,
        generation: u64,
        count_only: bool,
        snapshot: u64,
    ) -> Subscription {
        let group = NostrFilterGroup::from_value(&filter, 50_000, 3, 16).unwrap();
        let mut sub = Subscription::new(1, SubId::new(sub_id).unwrap(), group, count_only);
        sub.generation = generation;
        if !count_only {
            sub.latest_event_id = snapshot;
        }
        sub
    }

    /// When a req worker cannot open a read for a REQ or COUNT that replaces
    /// one it is still running, the old query ends with the refusal rather
    /// than scanning on for nothing: the gate already drops what it sends.
    #[test]
    fn a_replacement_refused_on_a_failed_read_ends_the_old_query() {
        // Enough history that the first query spans many time slices.
        let (dir, env, snapshot) = long_history();
        let cfg = slow_scan_config(dir.path());
        let sub = |generation, count_only| {
            queued_sub(
                "x",
                json!({"kinds": [1], "limit": 50_000}),
                generation,
                count_only,
                snapshot,
            )
        };

        for (first, replacement) in [
            (ReqMsg::Scan(sub(1, false)), ReqMsg::Scan(sub(2, false))),
            (ReqMsg::Count(sub(1, true)), ReqMsg::Count(sub(2, true))),
        ] {
            let count = matches!(first, ReqMsg::Count(_));
            let conns = Arc::new(ConnTable::new());
            let (out_tx, mut outbound) = tokio::sync::mpsc::unbounded_channel();
            conns.insert(1, Outbound::new(out_tx, 0));
            // The ingester has opened the gate for the replacement.
            let ns = if count { Ns::Count } else { Ns::Req };
            conns.open_sub(1, ns, &SubId::new("x").unwrap(), 2, 0);
            let (req_tx, req_rx) = bounded(8);
            let (mon_tx, mon_rx) = bounded(8);
            trace::record(env.path());
            req_tx.send(first).unwrap();
            let worker = {
                let env = env.clone();
                let cfg = Arc::new(parking_lot::RwLock::new(cfg.clone()));
                let metrics = Arc::new(Metrics::default());
                thread::spawn(move || {
                    run_req_worker(env, cfg, conns, metrics, req_rx, vec![mon_tx])
                })
            };
            let recv_frame =
                |outbound: &mut tokio::sync::mpsc::UnboundedReceiver<OutboundFrame>| {
                    let deadline = std::time::Instant::now() + Duration::from_secs(2);
                    loop {
                        if let Ok(frame) = outbound.try_recv() {
                            break frame.into_text();
                        }
                        assert!(std::time::Instant::now() < deadline, "no frame");
                        thread::sleep(Duration::from_millis(1));
                    }
                };
            // Once the first query has had a slice, no read succeeds: the
            // pass that takes the replacement cannot read.
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while trace::slices(env.path()).is_empty() {
                assert!(std::time::Instant::now() < deadline, "no slice");
                thread::yield_now();
            }
            fault::fail_reads(env.path(), usize::MAX);
            req_tx.send(replacement).unwrap();
            let closed = recv_frame(&mut outbound);
            let sliced = trace::slices(env.path()).len();
            fault::fail_reads(env.path(), 0);
            assert!(closed.starts_with(r#"["CLOSED","x","error: "#), "{closed}");
            if !count {
                assert!(matches!(
                    mon_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
                    MonitorMsg::Remove { generation: 2, .. }
                ));
            }
            thread::sleep(Duration::from_millis(300));
            assert_eq!(
                trace::slices(env.path()).len(),
                sliced,
                "the replaced query kept running"
            );
            assert!(outbound.try_recv().is_err(), "a frame followed CLOSED");
            // A replaced REQ that kept scanning would report its history done.
            assert!(
                mon_rx.try_recv().is_err(),
                "the replaced query kept running"
            );
            drop(req_tx);
            worker.join().unwrap();
        }
    }

    /// A refused REQ ends the subscription it names at once: the gate closes
    /// the id and queues the CLOSED in one step, so nothing the old
    /// subscription's worker or monitor sends afterwards reaches the client,
    /// and the workers are only told to clean up. A later REQ with the id is
    /// unaffected by the old generation's late frames.
    #[test]
    fn a_refusal_ends_the_named_subscription_at_once() {
        let mut relay = StalledWorker::start();
        let metrics = Metrics::default();
        let x = SubId::new("x").unwrap();
        let next = |relay: &StalledWorker| {
            relay.req[0]
                .recv_timeout(Duration::from_secs(2))
                .expect("nothing reached the req worker")
        };
        let frame = |relay: &mut StalledWorker| {
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            loop {
                if let Ok(frame) = relay.outbound.try_recv() {
                    break frame.into_text();
                }
                assert!(std::time::Instant::now() < deadline, "no frame");
                thread::sleep(Duration::from_millis(1));
            }
        };

        relay.send(2, json!(["REQ", "x", {"kinds": [1]}]));
        let ReqMsg::Scan(first) = next(&relay) else {
            panic!("expected the scan");
        };
        relay
            .conns
            .send_event(2, &x, first.generation, "{\"a\":1}", &metrics);
        assert!(frame(&mut relay).starts_with(r#"["EVENT","x""#));

        relay.send(2, json!(["REQ", "x", {"kinds": [1], "nope": true}]));
        assert!(frame(&mut relay).starts_with(r#"["CLOSED","x","unsupported: "#));
        assert!(matches!(
            next(&relay),
            ReqMsg::Cancel { generation, count_only: false, .. } if generation == first.generation
        ));
        // The old scan and live match are too late now.
        relay
            .conns
            .send_event(2, &x, first.generation, "{\"a\":2}", &metrics);
        let eose = RelayMessage::Eose {
            sub_id: "x".into(),
            hints: EoseHints::default(),
        };
        relay
            .conns
            .send_sub(2, &x, first.generation, eose, &metrics);
        // A refusal again, with nothing open: answered as directly.
        relay.send(2, json!(["REQ", "x", {"kinds": [1], "nope": true}]));
        assert!(frame(&mut relay).starts_with(r#"["CLOSED","x","unsupported: "#));

        relay.send(2, json!(["REQ", "x", {"kinds": [1]}]));
        let ReqMsg::Scan(second) = next(&relay) else {
            panic!("expected the scan");
        };
        relay
            .conns
            .send_event(2, &x, first.generation, "{\"a\":3}", &metrics);
        relay
            .conns
            .send_event(2, &x, second.generation, "{\"b\":1}", &metrics);
        assert_eq!(frame(&mut relay), r#"["EVENT","x",{"b":1}]"#);
        assert!(relay.outbound.try_recv().is_err());
        relay.finish();
    }

    /// Start a req worker for connection 1 on `env`, recording its slices.
    fn traced_worker(
        env: &Env,
        cfg: Config,
        conns: &Arc<ConnTable>,
        req_rx: Receiver<ReqMsg>,
        mon_tx: Sender<MonitorMsg>,
    ) -> thread::JoinHandle<()> {
        trace::record(env.path());
        let (env, conns) = (env.clone(), conns.clone());
        let cfg = Arc::new(parking_lot::RwLock::new(cfg));
        let metrics = Arc::new(Metrics::default());
        thread::spawn(move || run_req_worker(env, cfg, conns, metrics, req_rx, vec![mon_tx]))
    }

    /// The sub id of the next `HistoryDone` the req worker sends.
    fn history_done_for(mon_rx: &Receiver<MonitorMsg>) -> String {
        match mon_rx.recv_timeout(Duration::from_secs(10)) {
            Ok(MonitorMsg::HistoryDone { sub_id, .. }) => sub_id.to_string(),
            Ok(_) => panic!("expected HistoryDone"),
            Err(error) => panic!("no HistoryDone: {error}"),
        }
    }

    /// A pass takes everything queued and applies it in order. Cancels, AUTH
    /// and teardown take no query time, and each new REQ or COUNT gets its
    /// first slice as the pass takes it, in queue order: small queries queued
    /// behind a long scan and 50 cancels are answered after one slice of the
    /// scan, not one per message ahead of them.
    #[test]
    fn a_pass_answers_queued_queries_without_a_slice_per_message() {
        let (dir, env, snapshot) = long_history();
        let conns = Arc::new(ConnTable::new());
        let (out_tx, mut outbound) = tokio::sync::mpsc::unbounded_channel();
        conns.insert(1, Outbound::new(out_tx, 0));
        conns.open_sub(1, Ns::Count, &SubId::new("d").unwrap(), 5, 0);
        let (req_tx, req_rx) = bounded(REQ_PASS_MAX);
        let (mon_tx, mon_rx) = unbounded();
        let all = json!({"kinds": [1], "limit": 50_000});
        let newest = json!({"kinds": [1], "limit": 1});
        let one = json!({"ids": [format!("{}{}", "00".repeat(8), "bb".repeat(24))]});
        let queue = |msg| req_tx.send(msg).unwrap();
        queue(ReqMsg::Scan(queued_sub("long", all, 1, false, snapshot)));
        for i in 0..50 {
            queue(ReqMsg::Cancel {
                conn_id: 1,
                sub_id: SubId::new(&format!("gone{i}")).unwrap(),
                generation: 100 + i,
                count_only: false,
            });
        }
        queue(ReqMsg::SetAuth {
            conn_id: 1,
            authed: [7; 32],
        });
        queue(ReqMsg::Scan(queued_sub(
            "b",
            newest.clone(),
            2,
            false,
            snapshot,
        )));
        queue(ReqMsg::Scan(queued_sub("c", newest, 3, false, snapshot)));
        queue(ReqMsg::Count(queued_sub("d", one, 5, true, snapshot)));
        let worker = traced_worker(&env, slow_scan_config(dir.path()), &conns, req_rx, mon_tx);

        assert_eq!(history_done_for(&mon_rx), "b");
        assert_eq!(history_done_for(&mon_rx), "c");
        assert_eq!(history_done_for(&mon_rx), "long");
        let slices = trace::slices(env.path());
        assert_eq!(slices[..4], ["long", "b", "c", "d"], "{slices:?}");
        assert!(slices[4..].iter().all(|s| s == "long"), "{slices:?}");
        assert!(
            slices.len() > 5,
            "the long scan fit in one slice: {slices:?}"
        );
        let count: Value = serde_json::from_str(&outbound.try_recv().unwrap().into_text()).unwrap();
        assert_eq!(count, json!(["COUNT", "d", {"count": 1}]));
        drop(req_tx);
        worker.join().unwrap();
    }

    /// New REQs are started in the order they came, and however many keep
    /// coming, small or costly, the running queries keep their share of the
    /// worker: between two of their slices, the new queries' first slices
    /// before the last one took less than the earlier of the two.
    #[test]
    fn a_stream_of_new_queries_cannot_starve_running_ones() {
        // More small queries than one slice of the scan takes, then queries
        // whose first slices each cost as much as one of its slices.
        for (arrivals, filter) in [
            (20 * REQ_PASS_MAX, json!({"kinds": [1], "limit": 1})),
            (2 * REQ_PASS_MAX, json!({"kinds": [1], "limit": 5_000})),
        ] {
            let (dir, env, snapshot) = long_history();
            let conns = Arc::new(ConnTable::new());
            let (out_tx, _outbound) = tokio::sync::mpsc::unbounded_channel();
            conns.insert(1, Outbound::new(out_tx, 0));
            let (req_tx, req_rx) = bounded(arrivals + 1);
            let (mon_tx, mon_rx) = unbounded();
            let all = json!({"kinds": [1], "limit": 50_000});
            req_tx
                .send(ReqMsg::Scan(queued_sub("long", all, 1, false, snapshot)))
                .unwrap();
            let ids: Vec<String> = (0..arrivals).map(|i| format!("s{i}")).collect();
            for (i, id) in ids.iter().enumerate() {
                let sub = queued_sub(id, filter.clone(), 2 + i as u64, false, snapshot);
                req_tx.send(ReqMsg::Scan(sub)).unwrap();
            }
            let mut cfg = slow_scan_config(dir.path());
            cfg.relay.abuse.max_concurrent_historical_queries = arrivals + 1;
            let worker = traced_worker(&env, cfg, &conns, req_rx, mon_tx);
            for _ in 0..=arrivals {
                history_done_for(&mon_rx);
            }
            drop(req_tx);
            worker.join().unwrap();

            let log = trace::log(env.path());
            let mut first_seen = HashSet::new();
            let starts: Vec<&String> = log
                .iter()
                .map(|(id, _)| id)
                .filter(|id| first_seen.insert(*id))
                .collect();
            assert_eq!(starts[0], "long");
            assert_eq!(&starts[1..], ids.iter().collect::<Vec<_>>());
            // A query runs from its first slice to its last one.
            let last: HashMap<&String, usize> = log
                .iter()
                .enumerate()
                .map(|(at, (id, _))| (id, at))
                .collect();
            let mut started = HashSet::new();
            let mut previous: Option<Duration> = None;
            let mut first_slices: Vec<Duration> = Vec::new();
            let mut running_slices = 0;
            for (at, (id, took)) in log.iter().enumerate() {
                if started.insert(id) {
                    first_slices.push(*took);
                } else {
                    running_slices += 1;
                    if let Some(previous) = previous {
                        let owed: Duration = first_slices.iter().rev().skip(1).copied().sum();
                        assert!(
                            owed.is_zero() || owed < previous,
                            "{owed:?} of new queries ran before running ones, \
                             whose last slice took {previous:?}"
                        );
                    }
                    previous = Some(*took);
                    first_slices.clear();
                }
                // Nothing left running: no share is owed until something is.
                if !started.iter().any(|id| last[*id] > at) {
                    previous = None;
                    first_slices.clear();
                }
            }
            let last_start = log
                .iter()
                .rposition(|(id, _)| *id == ids[arrivals - 1])
                .unwrap();
            assert!(
                log[..last_start]
                    .iter()
                    .filter(|(id, _)| *id == "long")
                    .count()
                    > 1,
                "the scan waited for every new query"
            );
            assert!(running_slices > 2, "{running_slices} running slices");
        }
    }

    /// Running queries get the end of a pass when nothing is waiting, or
    /// once what ran since their last slice has taken as long as that slice.
    #[test]
    fn running_queries_get_their_share_of_a_busy_worker() {
        let start = std::time::Instant::now();
        let at = |ms| start + Duration::from_millis(ms);
        let mut share = RunningShare::new(start);
        assert!(share.due(true, start), "nothing has run for them yet");
        share.ran(at(0), at(3));
        assert!(share.due(false, at(3)));
        assert!(!share.due(true, at(5)));
        assert!(share.due(true, at(6)));
        share.ran(at(6), at(16));
        assert!(!share.due(true, at(25)));
        assert!(share.due(true, at(26)));
    }

    /// Producers on several threads queue frames for the same subscription
    /// ids while the ingester opens, replaces, closes and refuses them. The
    /// gate check and the enqueue are one step under the connection's lock,
    /// as are a refusal's close and its CLOSED, so in the queue the transport
    /// reads nothing of a generation follows the point where the gate moved
    /// past it, and generations never go backwards.
    #[test]
    fn the_gate_admits_and_queues_atomically_under_concurrent_producers() {
        const IDS: usize = 3;
        const PRODUCERS: u64 = 4;
        let conns = Arc::new(ConnTable::new());
        let metrics = Arc::new(Metrics::default());
        let (out_tx, mut outbound) = tokio::sync::mpsc::unbounded_channel();
        conns.insert(1, Outbound::new(out_tx, 0));
        let sid = |id: usize| SubId::new(&format!("s{id}")).unwrap();
        // The newest generation the ingester gave each id.
        let newest: Arc<Vec<AtomicU64>> = Arc::new((0..IDS).map(|_| AtomicU64::new(0)).collect());
        let stop = Arc::new(AtomicBool::new(false));
        let producers: Vec<_> = (0..PRODUCERS)
            .map(|producer| {
                let (conns, metrics) = (conns.clone(), metrics.clone());
                let (newest, stop) = (newest.clone(), stop.clone());
                thread::spawn(move || {
                    let mut rng = rand::thread_rng();
                    let mut seq = 0u64;
                    while !stop.load(Ordering::Relaxed) {
                        let id = rng.gen_range(0..IDS);
                        // Producers lag: an older generation may still emit.
                        let generation = newest[id]
                            .load(Ordering::Relaxed)
                            .saturating_sub(rng.gen_range(0..3));
                        if generation == 0 {
                            continue;
                        }
                        seq += 1;
                        if rng.gen_ratio(1, 16) {
                            let closed = RelayMessage::closed_error(
                                sid(id).as_str(),
                                format!("last {generation}"),
                            );
                            conns.send_last(1, Ns::Req, &sid(id), generation, closed, &metrics);
                        } else {
                            let event = json!({"g": generation, "p": producer, "n": seq});
                            conns.send_event(1, &sid(id), generation, &event.to_string(), &metrics);
                        }
                    }
                })
            })
            .collect();
        let mut rng = rand::thread_rng();
        let mut next = 0u64;
        for _ in 0..20_000 {
            let id = rng.gen_range(0..IDS);
            // Everything up to the generation in a marker is over for the id.
            let over = match rng.gen_range(0..4) {
                0 | 1 => {
                    next += 1;
                    conns.open_sub(1, Ns::Req, &sid(id), next, 0);
                    newest[id].store(next, Ordering::Relaxed);
                    next - 1
                }
                2 => {
                    conns.close_sub(1, Ns::Req, &sid(id));
                    newest[id].load(Ordering::Relaxed)
                }
                _ => {
                    let over = newest[id].load(Ordering::Relaxed);
                    conns.refuse(
                        1,
                        Ns::Req,
                        sid(id).as_str(),
                        format!("refused {over}"),
                        &metrics,
                    );
                    continue;
                }
            };
            conns.deliver(
                1,
                json!(["MARK", format!("s{id}"), over]).to_string(),
                &metrics,
            );
            if rng.gen_ratio(1, 64) {
                thread::yield_now();
            }
        }
        stop.store(true, Ordering::Relaxed);
        for producer in producers {
            producer.join().unwrap();
        }

        let mut floor = [0u64; IDS];
        let mut seen = [0u64; IDS];
        let mut admitted = 0;
        while let Ok(frame) = outbound.try_recv() {
            let frame: Value = serde_json::from_str(&frame.into_text()).unwrap();
            let id: usize = frame[1].as_str().unwrap()[1..].parse().unwrap();
            let number = |text: &Value| -> u64 {
                text.as_str()
                    .unwrap()
                    .split(' ')
                    .nth(1)
                    .unwrap()
                    .parse()
                    .unwrap()
            };
            let (generation, ends) = match frame[0].as_str().unwrap() {
                "MARK" => {
                    floor[id] = floor[id].max(frame[2].as_u64().unwrap());
                    continue;
                }
                "CLOSED" if frame[2].as_str().unwrap().starts_with("refused") => {
                    floor[id] = floor[id].max(number(&frame[2]));
                    continue;
                }
                "CLOSED" => (number(&frame[2]), true),
                "EVENT" => (frame[2]["g"].as_u64().unwrap(), false),
                other => panic!("unexpected frame {other}"),
            };
            assert!(
                generation > floor[id],
                "s{id} generation {generation} queued after the gate moved past {}",
                floor[id]
            );
            assert!(generation >= seen[id], "s{id} generations went backwards");
            seen[id] = generation;
            if ends {
                floor[id] = generation;
            }
            admitted += 1;
        }
        assert!(
            admitted > 100,
            "too few producer frames got through: {admitted}"
        );
    }

    /// A commit as the writer hands it to the monitors.
    fn handed(events: Vec<(u64, &wok_event::ParsedEvent, String)>) -> MonitorData {
        MonitorData::Stored(handed_batch(events))
    }

    fn handed_batch(events: Vec<(u64, &wok_event::ParsedEvent, String)>) -> Arc<StoredBatch> {
        let (first, last) = (events[0].0, events[events.len() - 1].0);
        Arc::new(StoredBatch {
            first,
            last,
            events: events
                .into_iter()
                .map(|(lev_id, parsed, json)| StoredEvent {
                    lev_id,
                    packed: parsed.packed.clone().into_bytes(),
                    json,
                    search_terms: OnceLock::new(),
                })
                .collect(),
            bytes: 0,
            in_flight: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// `parsed`'s payload with different content, which LMDB does not hold:
    /// a monitor that sends it did not read the event back.
    fn with_content(parsed: &wok_event::ParsedEvent, content: &str) -> String {
        let mut event: Value = serde_json::from_str(&parsed.json).unwrap();
        event["content"] = json!(content);
        event.to_string()
    }

    /// The monitor matches a handed-off commit as it was handed over,
    /// without reading it back. Past a gap it reads LMDB instead, as for
    /// `DbChange`, and it sends neither an event a later one in the same
    /// commit deleted nor a commit a read already matched.
    #[test]
    fn the_monitor_matches_handed_off_commits_without_reading_them() {
        let mut h = MonitorHarness::start(1 << 20);
        h.store("a");

        let b = MonitorHarness::parse(1, "b");
        let (b_lev, b_id) = h.write_event(b.clone());
        h.feed(handed(vec![(b_lev, &b, with_content(&b, "handed b"))]));
        let event = MonitorHarness::next(&mut h.observer);
        assert_eq!(
            (&event[2]["id"], &event[2]["content"]),
            (&json!(b_id), &json!("handed b"))
        );

        // Only d is handed over: c is past the monitor's cursor, so both are
        // read from LMDB.
        let (_, c_id) = h.write("c");
        let d = MonitorHarness::parse(1, "d");
        let (d_lev, d_id) = h.write_event(d.clone());
        h.feed(handed(vec![(d_lev, &d, with_content(&d, "handed d"))]));
        h.observe(&c_id);
        let event = MonitorHarness::next(&mut h.observer);
        assert_eq!(
            (&event[2]["id"], &event[2]["content"]),
            (&json!(d_id), &json!("d"))
        );

        // f's commit deleted e.
        let e = MonitorHarness::parse(1, "e");
        let (e_lev, _) = h.write_event(e.clone());
        let mut txn = h.env.begin_rw().unwrap();
        wok_db::delete_events(&mut txn, &mut wok_db::NoopNegentropy, [e_lev]).unwrap();
        txn.commit().unwrap();
        let f = MonitorHarness::parse(1, "f");
        let (f_lev, f_id) = h.write_event(f.clone());
        h.feed(handed(vec![
            (e_lev, &e, e.json.clone()),
            (f_lev, &f, f.json.clone()),
        ]));
        h.observe(&f_id);

        h.feed(handed(vec![(b_lev, &b, b.json.clone())]));
        h.sync();
    }

    /// Every monitor checks a handed-off event against its own read. One that
    /// takes the commit after another monitor sent it, and after a later
    /// commit deleted the event, does not send it.
    #[test]
    fn each_monitor_checks_handed_off_events_against_its_own_read() {
        let mut first = MonitorHarness::start(1 << 20);
        // A second monitor on the same database, with its own match-all
        // subscription.
        let conns = Arc::new(ConnTable::new());
        let (observer_tx, mut observer) = tokio::sync::mpsc::unbounded_channel();
        conns.insert(2, Outbound::new(observer_tx, 0));
        let (tx, rx) = unbounded();
        let (data, data_rx) = bounded(64);
        let second = {
            let (env, cfg, conns) = (first.env.clone(), first.cfg.clone(), conns.clone());
            let metrics = Arc::new(Metrics::default());
            let moderation = Default::default();
            thread::spawn(move || {
                run_req_monitor(env, cfg, conns, metrics, moderation, rx, data_rx)
            })
        };
        let all = SubId::new("all").unwrap();
        conns.open_sub(2, Ns::Req, &all, 1, 0);
        tx.send(MonitorMsg::Register(MonitorHarness::sub(
            2,
            "all",
            json!({}),
            1,
            0,
        )))
        .unwrap();
        tx.send(MonitorMsg::HistoryDone {
            conn_id: 2,
            sub_id: all,
            generation: 1,
            snapshot: 0,
            hints: EoseHints::default(),
        })
        .unwrap();
        assert_eq!(MonitorHarness::next(&mut observer)[0], "EOSE");

        let event = MonitorHarness::parse(1, "deleted later");
        let (lev, id) = first.write_event(event.clone());
        let batch = handed_batch(vec![(lev, &event, event.json.clone())]);
        first.feed(MonitorData::Stored(batch.clone()));
        first.observe(&id);
        let mut txn = first.env.begin_rw().unwrap();
        wok_db::delete_events(&mut txn, &mut wok_db::NoopNegentropy, [lev]).unwrap();
        txn.commit().unwrap();
        data.send(MonitorData::Stored(batch)).unwrap();
        let sentinel = MonitorHarness::parse(20_002, "sentinel");
        let sentinel_id = to_hex(sentinel.packed.view().id());
        data.send(MonitorData::Ephemeral(Arc::new(HeldEvent {
            packed: sentinel.packed.into_bytes(),
            json: sentinel.json,
        })))
        .unwrap();
        assert_eq!(MonitorHarness::next(&mut observer)[2]["id"], sentinel_id);
        drop((tx, data));
        second.join().unwrap();
    }

    /// The writer hands the events a commit wrote to every monitor as one
    /// shared batch, whose bytes count against its budget until the last
    /// monitor drops it. Over the budget, or for ids it cannot vouch for, it
    /// sends `DbChange` instead, and nothing for a commit that wrote nothing.
    #[test]
    fn the_writer_hands_over_written_events_within_its_budget() {
        let (tx1, rx1) = unbounded();
        let (tx2, rx2) = unbounded();
        let monitors = [tx1, tx2];
        let in_flight = Arc::new(AtomicUsize::new(0));
        let event = |lev_id, status| {
            let mut event = EventToWrite::new(vec![0; 3], "{}".to_string());
            event.lev_id = lev_id;
            event.status = status;
            event
        };
        let written = EventWriteStatus::Written;
        let mut events = vec![
            event(7, written),
            event(0, EventWriteStatus::Duplicate),
            event(8, written),
        ];
        broadcast_stored(&monitors, &in_flight, &mut events);
        assert!(events.is_empty());
        let (Ok(MonitorData::Stored(a)), Ok(MonitorData::Stored(b))) =
            (rx1.try_recv(), rx2.try_recv())
        else {
            panic!("expected a handed-off commit for each monitor");
        };
        assert!(Arc::ptr_eq(&a, &b));
        let ids: Vec<u64> = a.events.iter().map(|event| event.lev_id).collect();
        assert_eq!((a.first, a.last, ids), (7, 8, vec![7, 8]));
        assert_eq!(in_flight.load(Ordering::Relaxed), 10);
        drop(a);
        assert_eq!(in_flight.load(Ordering::Relaxed), 10);
        drop(b);
        assert_eq!(in_flight.load(Ordering::Relaxed), 0);

        let db_change = |events: &mut Vec<EventToWrite>| {
            broadcast_stored(&monitors, &in_flight, events);
            [&rx1, &rx2]
                .iter()
                .all(|rx| matches!(rx.try_recv(), Ok(MonitorData::DbChange)))
        };
        in_flight.store(STORED_HANDOFF_BYTES - 4, Ordering::Relaxed);
        assert!(db_change(&mut vec![event(9, written)]));
        in_flight.store(0, Ordering::Relaxed);
        assert!(db_change(&mut vec![event(10, written), event(12, written)]));
        broadcast_stored(
            &monitors,
            &in_flight,
            &mut vec![event(0, EventWriteStatus::Duplicate)],
        );
        assert!(rx1.try_recv().is_err() && rx2.try_recv().is_err());
    }
}
