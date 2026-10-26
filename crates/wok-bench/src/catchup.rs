//! NIP-77 catch-up: `--scenario nip77_catchup`.
//!
//! A client that holds part of what a relay has catches up with NIP-77, then
//! fetches what it lacks, as an archive mirror does (#226 scenario B) and as
//! a Marmot app does for each group at start (scenario D).
//!
//! - Filters: the whole corpus in `--sync-windows` time windows, or one
//!   `{"kinds":[445],"#h":[group]}` filter with MDK's limit per Marmot group.
//! - The client holds every event the filters match except the newest
//!   `--sync-missing-pct` percent of them, or a random such share.
//! - A sync sends NEG-OPEN with the client's `(created_at, id)` pairs, answers
//!   each NEG-MSG until the client has nothing more to send, sends NEG-CLOSE,
//!   then asks for the ids it lacks in REQs of up to [`FETCH_BATCH`] ids.
//!   `--sync-concurrency` syncs run at once, `--sync-per-conn` on each
//!   connection.
//! - Oracle: the relay names exactly the events the client lacks, names none
//!   that only the client has, and returns each one unchanged. Kinds a relay
//!   may serve only after AUTH, such as gift wraps, must be served in full or
//!   withheld in full; the report lists the withheld kinds.

use anyhow::{Context, Result};
use clap::ValueEnum;
use futures_util::{SinkExt, StreamExt};
use hdrhistogram::Histogram;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use wok_negentropy::{Negentropy, Vector};

/// The client's largest message, before hex encoding. Hex doubles it, which
/// keeps a NEG-MSG under the 131,072-byte WebSocket payload limit of
/// strfry 1.1.3, Wok 0.7.0 and Wok's `public` preset. The relays answer with
/// up to 500,000 bytes.
pub const FRAME_LIMIT: u64 = 60_000;
/// MDK's NEG-OPEN limit, which group syncs send unless `--sync-limit` says
/// otherwise.
pub const GROUP_LIMIT: u64 = 16_385;
/// Ids per fetch REQ: the `maxFilterLimit` of strfry 1.1.3 and Wok 0.7.0.
pub const FETCH_BATCH: usize = 500;
/// A connection with syncs open fails after this long without a message.
const IDLE: Duration = Duration::from_secs(120);
/// Problems a report quotes; the rest are only counted.
const SAMPLES: usize = 10;
/// Header that carries each connection's simulated address.
const FORWARDED_HEADER: &str = "x-forwarded-for";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Filters {
    /// The whole corpus, in `--sync-windows` time windows.
    All,
    /// One `kinds: [445]`, `#h` filter per Marmot group in the corpus.
    Groups,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Missing {
    /// The client lacks the newest events, as after time offline.
    Newest,
    /// The client lacks a random set of events.
    Random,
}

#[derive(Clone, Debug, Serialize)]
pub struct Options {
    pub filters: Filters,
    pub windows: usize,
    pub missing: Missing,
    /// Percent of the matched events the client lacks.
    pub missing_pct: f64,
    /// Syncs in flight at once.
    pub concurrency: usize,
    /// Syncs in flight on one connection.
    pub per_conn: usize,
    /// NEG-OPEN `limit`; groups default to [`GROUP_LIMIT`].
    pub limit: Option<u64>,
    /// Connections per simulated source address; 0 sends no address.
    pub clients_per_address: usize,
    /// Fail the trial when the relay refuses a sync.
    pub expect_no_refusals: bool,
    pub seed: u64,
    pub nodelay: bool,
}

impl Options {
    fn limit(&self) -> Option<u64> {
        self.limit
            .or((self.filters == Filters::Groups).then_some(GROUP_LIMIT))
    }
}

type Id = [u8; 32];

/// One sync: its filter and what the client holds of what it matches.
#[derive(Debug)]
pub struct Job {
    pub filter: Value,
    /// `(created_at, id)` of each matched event the client holds.
    pub held: Vec<(u64, Id)>,
    /// Matched events the client lacks.
    pub missing: HashSet<Id>,
}

#[derive(Debug)]
pub struct Plan {
    pub jobs: Vec<Job>,
    /// Every event a filter matches, by id.
    pub events: HashMap<Id, Value>,
    pub held: u64,
    pub missing: u64,
}

fn event_id(event: &Value) -> Option<Id> {
    let mut id = [0u8; 32];
    hex::decode_to_slice(event["id"].as_str()?, &mut id).ok()?;
    Some(id)
}

fn kind(event: &Value) -> u64 {
    event["kind"].as_u64().unwrap_or(u64::MAX)
}

/// What a relay keeps of `events` once it has imported them: each id once,
/// no ephemeral event, the newest version of each replaceable and
/// addressable address (on a tie, the lowest id, as NIP-01 says), and no
/// event, other than a deletion, that its author deleted with a kind 5 `e`
/// tag. The rules of `crate::retained_events`, in linear time, so a
/// million-event social corpus takes seconds.
pub fn kept(events: Vec<Value>) -> Vec<Value> {
    let text = |event: &Value, field: &str| event[field].as_str().unwrap_or_default().to_owned();
    let tag_values = |event: &Value, name: &'static str| {
        event["tags"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(move |tag| tag[0] == name)
            .filter_map(|tag| tag[1].as_str().map(str::to_owned))
            .collect::<Vec<_>>()
    };
    let mut keep = vec![false; events.len()];
    let mut ids = HashSet::with_capacity(events.len());
    let mut newest: HashMap<(String, u64, String), usize> = HashMap::new();
    let mut deleted: HashSet<(String, String)> = HashSet::new();
    for (i, event) in events.iter().enumerate() {
        let k = kind(event);
        if (20_000..30_000).contains(&k) || !ids.insert(text(event, "id")) {
            continue;
        }
        let pubkey = text(event, "pubkey");
        if k == 5 {
            for target in tag_values(event, "e") {
                deleted.insert((target, pubkey.clone()));
            }
        }
        let addressable = (30_000..40_000).contains(&k);
        if !(k == 0 || k == 3 || (10_000..20_000).contains(&k) || addressable) {
            keep[i] = true;
            continue;
        }
        let d = if addressable {
            tag_values(event, "d")
                .into_iter()
                .next()
                .unwrap_or_default()
        } else {
            String::new()
        };
        let version = |e: &Value| (e["created_at"].as_u64(), std::cmp::Reverse(text(e, "id")));
        newest
            .entry((pubkey, k, d))
            .and_modify(|best| {
                if version(event) > version(&events[*best]) {
                    *best = i;
                }
            })
            .or_insert(i);
    }
    for i in newest.into_values() {
        keep[i] = true;
    }
    events
        .into_iter()
        .zip(keep)
        .filter(|(event, keep)| {
            *keep
                && (kind(event) == 5
                    || !deleted.contains(&(text(event, "id"), text(event, "pubkey"))))
        })
        .map(|(event, _)| event)
        .collect()
}

/// Splits the corpus into filters and chooses what the client lacks.
/// `events` is what the relay keeps of the corpus.
pub fn plan(events: Vec<Value>, opts: &Options) -> Result<Plan> {
    anyhow::ensure!(
        opts.missing_pct.is_finite() && (0.0..=100.0).contains(&opts.missing_pct),
        "--sync-missing-pct must be between 0 and 100"
    );
    anyhow::ensure!(
        opts.concurrency > 0 && opts.per_conn > 0 && opts.windows > 0,
        "--sync-concurrency, --sync-per-conn and --sync-windows must be at least 1"
    );
    let mut sorted = events
        .into_iter()
        .map(|event| {
            let created_at = event["created_at"].as_u64();
            match (created_at, event_id(&event)) {
                (Some(created_at), Some(id)) => Ok((created_at, id, event)),
                _ => anyhow::bail!("corpus event without a created_at or id: {event}"),
            }
        })
        .collect::<Result<Vec<_>>>()?;
    sorted.sort_unstable_by_key(|(created_at, id, _)| (*created_at, *id));
    sorted.dedup_by_key(|(_, id, _)| *id);
    anyhow::ensure!(!sorted.is_empty(), "the corpus is empty");
    let (mut filters, members) = match opts.filters {
        Filters::All => windows(&sorted, opts.windows),
        Filters::Groups => groups(&sorted)?,
    };
    if let Some(limit) = opts.limit() {
        for (filter, members) in filters.iter_mut().zip(&members) {
            // A relay keeps the newest `limit` events, and relays break ties
            // in that order differently, so no filter may pass its limit.
            anyhow::ensure!(
                members.len() as u64 <= limit,
                "{filter} matches {} events, more than its limit of {limit}; raise --sync-limit or add --sync-windows",
                members.len()
            );
            filter["limit"] = json!(limit);
        }
    }
    // Indexes into `sorted`, which is in time order.
    let mut union: Vec<usize> = members.iter().flatten().copied().collect();
    union.sort_unstable();
    union.dedup();
    let count = (opts.missing_pct * union.len() as f64 / 100.0).round() as usize;
    let lacking: HashSet<usize> = match opts.missing {
        Missing::Newest => union[union.len() - count..].iter().copied().collect(),
        Missing::Random => {
            use rand::SeedableRng;
            let mut rng = rand::rngs::StdRng::seed_from_u64(opts.seed);
            rand::seq::index::sample(&mut rng, union.len(), count)
                .into_iter()
                .map(|i| union[i])
                .collect()
        }
    };
    let jobs = filters
        .into_iter()
        .zip(members)
        .map(|(filter, members)| {
            let (lacks, holds): (Vec<usize>, Vec<usize>) =
                members.into_iter().partition(|i| lacking.contains(i));
            Job {
                filter,
                held: holds
                    .into_iter()
                    .map(|i| (sorted[i].0, sorted[i].1))
                    .collect(),
                missing: lacks.into_iter().map(|i| sorted[i].1).collect(),
            }
        })
        .collect();
    let mut sorted: Vec<Option<(u64, Id, Value)>> = sorted.into_iter().map(Some).collect();
    let events = union
        .iter()
        .filter_map(|&i| sorted[i].take().map(|(_, id, event)| (id, event)))
        .collect();
    Ok(Plan {
        jobs,
        events,
        held: (union.len() - count) as u64,
        missing: count as u64,
    })
}

/// About equal time windows over `events`, in time order, split at whole
/// seconds so that no second falls in two windows. The first window has no
/// `since` and the last no `until`, so together they cover the relay.
fn windows(events: &[(u64, Id, Value)], count: usize) -> (Vec<Value>, Vec<Vec<usize>>) {
    let n = events.len();
    let mut starts = vec![0];
    for w in 1..count {
        let second = events[w * n / count].0;
        let start = events.partition_point(|(created_at, _, _)| *created_at < second);
        if start > *starts.last().expect("first window") {
            starts.push(start);
        }
    }
    starts.push(n);
    let last = starts.len() - 2;
    starts
        .windows(2)
        .enumerate()
        .map(|(w, range)| {
            let mut filter = serde_json::Map::new();
            if w > 0 {
                filter.insert("since".into(), json!(events[range[0]].0));
            }
            if w < last {
                filter.insert("until".into(), json!(events[range[1]].0 - 1));
            }
            (Value::Object(filter), (range[0]..range[1]).collect())
        })
        .unzip()
}

/// One filter per Marmot group (a kind 445 event's `h` tag), as MDK sends
/// at start.
fn groups(events: &[(u64, Id, Value)]) -> Result<(Vec<Value>, Vec<Vec<usize>>)> {
    let mut groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (i, (_, _, event)) in events.iter().enumerate() {
        if kind(event) != 445 {
            continue;
        }
        let named: BTreeSet<&str> = event["tags"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|tag| tag[0] == "h")
            .filter_map(|tag| tag[1].as_str())
            .collect();
        for group in named {
            groups.entry(group.to_owned()).or_default().push(i);
        }
    }
    anyhow::ensure!(
        !groups.is_empty(),
        "the corpus has no kind 445 events with an h tag; pass a --corpus written with --event-mix social"
    );
    Ok(groups
        .into_iter()
        .map(|(group, members)| (json!({"kinds": [445], "#h": [group]}), members))
        .unzip())
}

/// A sync that ran to the end.
#[derive(Debug, Default)]
pub struct SessionLog {
    pub job: usize,
    /// NEG-MSGs the relay sent.
    pub rounds: u64,
    pub reconcile: Duration,
    pub fetch: Duration,
    /// JSON text sent and received: NEG-OPEN, NEG-MSG and NEG-CLOSE.
    pub neg_up: u64,
    pub neg_down: u64,
    /// JSON text sent and received: REQ and CLOSE, EVENT and EOSE.
    pub fetch_up: u64,
    pub fetch_down: u64,
    pub fetch_reqs: u64,
    /// Ids the client holds and the relay lacks.
    pub have: Vec<Id>,
    /// Ids the relay holds and the client lacks.
    pub need: Vec<Id>,
    /// Requested events the relay returned.
    pub fetched: u64,
    /// Requested events returned twice, altered or not at all, and events
    /// returned unrequested.
    pub problems: u64,
    pub problem_samples: Vec<String>,
}

#[derive(Debug, Default)]
pub struct Run {
    pub done: Vec<SessionLog>,
    /// `(job, reason)` of each sync the relay refused.
    pub refused: Vec<(usize, String)>,
    /// Refused syncs that had finished reconciling, as far as they got. The
    /// oracle checks them, but they are neither timed nor completed.
    pub fetch_refused: Vec<SessionLog>,
    /// `(job, error)` of each sync that failed or never started.
    pub failed: Vec<(usize, String)>,
    /// Protocol errors not tied to one sync.
    pub errors: Vec<String>,
    pub notices: Vec<String>,
    pub connections: usize,
    pub wall: Duration,
}

/// The simulated address of connection `conn`, as `--scenario clients`
/// assigns them.
fn address(conn: usize, per_address: usize) -> Option<IpAddr> {
    (per_address > 0).then(|| {
        let a = conn / per_address;
        IpAddr::V4(Ipv4Addr::new(
            10,
            64 | ((a >> 16) & 63) as u8,
            (a >> 8) as u8,
            a as u8,
        ))
    })
}

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Connects, retrying for five seconds while a relay the harness just
/// started comes up.
async fn connect(url: &str, address: Option<IpAddr>, nodelay: bool) -> Result<Socket> {
    let mut request = url.into_client_request()?;
    if let Some(address) = address {
        request
            .headers_mut()
            .insert(FORWARDED_HEADER, address.to_string().parse()?);
    }
    let mut tries = 0;
    loop {
        match tokio_tungstenite::connect_async_with_config(request.clone(), None, nodelay).await {
            Ok((socket, _)) => return Ok(socket),
            Err(e) if tries < 50 => {
                tries += 1;
                tracing::debug!("connect to {url}: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => return Err(e).with_context(|| format!("connect to {url}")),
        }
    }
}

/// A sync's initiator and the message it opens with.
type Initiated = (Negentropy<Vector>, Vec<u8>);

/// Syncs not yet started, in job order.
type Queue = Arc<Mutex<std::vec::IntoIter<(usize, Result<Initiated, String>)>>>;

fn initiate(job: &Job) -> Result<Initiated, wok_negentropy::NegError> {
    let mut store = Vector::new();
    for (created_at, id) in &job.held {
        store.insert(*created_at, id)?;
    }
    store.seal()?;
    let mut neg = Negentropy::new(store, FRAME_LIMIT)?;
    let initial = neg.initiate()?;
    Ok((neg, initial))
}

fn pop(queue: &Queue) -> Option<(usize, Result<Initiated, String>)> {
    queue.lock().unwrap_or_else(|e| e.into_inner()).next()
}

/// Runs every sync of `plan` against `url`. Each sync's first message is
/// built and its connection opened before the clock starts.
pub async fn run(url: &str, plan: Arc<Plan>, opts: &Options) -> Result<Run> {
    let queue: Queue = Arc::new(Mutex::new(
        plan.jobs
            .iter()
            .map(|job| initiate(job).map_err(|e| format!("negentropy initiate: {e}")))
            .enumerate()
            .collect::<Vec<_>>()
            .into_iter(),
    ));
    let concurrency = opts.concurrency.min(plan.jobs.len());
    let conns = concurrency.div_ceil(opts.per_conn);
    let mut sockets = Vec::with_capacity(conns);
    for conn in 0..conns {
        let address = address(conn, opts.clients_per_address);
        sockets.push(connect(url, address, opts.nodelay).await?);
    }
    let started = Instant::now();
    let tasks: Vec<_> = sockets
        .into_iter()
        .enumerate()
        .map(|(conn, socket)| {
            let slots = opts.per_conn.min(concurrency - conn * opts.per_conn);
            let driver = Driver {
                socket,
                plan: plan.clone(),
                queue: queue.clone(),
                live: HashMap::new(),
                run: Run::default(),
            };
            tokio::spawn(driver.drive(slots))
        })
        .collect();
    let mut run = Run {
        connections: conns,
        ..Run::default()
    };
    for task in tasks {
        let part = task.await.context("sync connection task")?;
        run.done.extend(part.done);
        run.refused.extend(part.refused);
        run.fetch_refused.extend(part.fetch_refused);
        run.failed.extend(part.failed);
        run.errors.extend(part.errors);
        run.notices.extend(part.notices);
    }
    run.wall = started.elapsed();
    // Syncs left unstarted because every connection failed.
    while let Some((job, _)) = pop(&queue) {
        run.failed
            .push((job, "not started: its connection failed".to_owned()));
    }
    Ok(run)
}

/// A sync in progress on one connection.
struct Session {
    opened: Instant,
    /// The initiator, until reconciliation ends.
    neg: Option<Negentropy<Vector>>,
    reconciled: Option<Instant>,
    have: Vec<Vec<u8>>,
    need: Vec<Vec<u8>>,
    /// Ids still to request.
    queue: Vec<Id>,
    /// Ids the open REQ asked for and the relay has not yet returned.
    batch: HashSet<Id>,
    batch_no: u64,
    returned: HashSet<Id>,
    log: SessionLog,
}

impl Session {
    fn problem(&mut self, message: String) {
        self.log.problems += 1;
        if self.log.problem_samples.len() < SAMPLES {
            self.log.problem_samples.push(message);
        }
    }

    fn into_log(self) -> SessionLog {
        let now = Instant::now();
        let reconciled = self.reconciled.unwrap_or(now);
        let mut log = self.log;
        log.reconcile = reconciled - self.opened;
        log.fetch = now - reconciled;
        log.have = self.have.iter().map(|id| to_id(id)).collect();
        log.need = self.need.iter().map(|id| to_id(id)).collect();
        log
    }
}

struct Driver {
    socket: Socket,
    plan: Arc<Plan>,
    queue: Queue,
    /// Syncs in progress, by job.
    live: HashMap<usize, Session>,
    run: Run,
}

/// Sends `frame` and returns its length.
async fn send(socket: &mut Socket, frame: Value) -> Result<u64> {
    let text = frame.to_string();
    let len = text.len() as u64;
    socket
        .send(Message::Text(text.into()))
        .await
        .context("WebSocket send")?;
    Ok(len)
}

fn neg_sid(job: usize) -> String {
    format!("neg-{job}")
}

fn parse_neg_sid(sid: &str) -> Option<usize> {
    sid.strip_prefix("neg-")?.parse().ok()
}

fn parse_ids_sid(sid: &str) -> Option<(usize, u64)> {
    let (job, batch) = sid.strip_prefix("ids-")?.split_once('-')?;
    Some((job.parse().ok()?, batch.parse().ok()?))
}

fn to_id(bytes: &[u8]) -> Id {
    bytes.try_into().unwrap_or([0; 32])
}

impl Driver {
    async fn drive(mut self, slots: usize) -> Run {
        let outcome = self.drive_inner(slots).await;
        if let Err(e) = outcome {
            let e = format!("{e:#}");
            for job in self.live.keys().copied().collect::<Vec<_>>() {
                self.live.remove(&job);
                self.run.failed.push((job, e.clone()));
            }
        }
        let _ = self.socket.close(None).await;
        self.run
    }

    async fn drive_inner(&mut self, slots: usize) -> Result<()> {
        while self.live.len() < slots && self.start_next().await? {}
        while !self.live.is_empty() {
            let message = match tokio::time::timeout(IDLE, self.socket.next()).await {
                Err(_) => anyhow::bail!(
                    "no message for {} s with {} syncs open",
                    IDLE.as_secs(),
                    self.live.len()
                ),
                Ok(None) => anyhow::bail!("relay closed the connection"),
                Ok(Some(message)) => message.context("WebSocket receive")?,
            };
            match message {
                Message::Text(text) => self.on_text(text.as_str()).await?,
                Message::Close(frame) => anyhow::bail!(
                    "relay closed the connection{}",
                    frame.map_or(String::new(), |f| format!(" ({} {})", f.code, f.reason))
                ),
                _ => {}
            }
            while self.live.len() < slots && self.start_next().await? {}
        }
        Ok(())
    }

    /// Opens the next unstarted sync, or returns false when none is left.
    async fn start_next(&mut self) -> Result<bool> {
        let Some((job, initiated)) = pop(&self.queue) else {
            return Ok(false);
        };
        let (neg, initial) = match initiated {
            Ok(initiated) => initiated,
            Err(e) => {
                self.run.failed.push((job, e));
                return Ok(true);
            }
        };
        let frame = json!([
            "NEG-OPEN",
            neg_sid(job),
            self.plan.jobs[job].filter,
            hex::encode(initial)
        ]);
        // Live before the send, so a failed send fails this sync too.
        self.live.insert(
            job,
            Session {
                opened: Instant::now(),
                neg: Some(neg),
                reconciled: None,
                have: Vec::new(),
                need: Vec::new(),
                queue: Vec::new(),
                batch: HashSet::new(),
                batch_no: 0,
                returned: HashSet::new(),
                log: SessionLog {
                    job,
                    ..SessionLog::default()
                },
            },
        );
        let neg_up = send(&mut self.socket, frame).await?;
        self.live.get_mut(&job).expect("live sync").log.neg_up = neg_up;
        Ok(true)
    }

    fn error(&mut self, message: String) {
        self.run.errors.push(message);
    }

    async fn on_text(&mut self, text: &str) -> Result<()> {
        let Ok(Value::Array(frame)) = serde_json::from_str::<Value>(text) else {
            self.error(format!("unparseable relay message: {}", clip(text)));
            return Ok(());
        };
        let len = text.len() as u64;
        let str_at = |i: usize| frame.get(i).and_then(Value::as_str);
        match (str_at(0), frame.len()) {
            (Some("NEG-MSG"), 3) => match (str_at(1), str_at(2)) {
                (Some(sid), Some(payload)) => self.on_neg_msg(sid, payload, len).await?,
                _ => self.error(format!("malformed NEG-MSG: {}", clip(text))),
            },
            // strfry adds its `maxSyncEvents` to a "too many" refusal.
            (Some("NEG-ERR"), 3..) => {
                let reason = str_at(2).unwrap_or_default();
                match str_at(1).and_then(parse_neg_sid) {
                    Some(job) if self.live.get(&job).is_some_and(|s| s.neg.is_some()) => {
                        self.live.remove(&job);
                        self.run.refused.push((job, format!("NEG-ERR {reason}")));
                    }
                    _ => self.error(format!("NEG-ERR for no open sync: {}", clip(text))),
                }
            }
            (Some("EVENT"), 3) => match str_at(1) {
                Some(sid) => self.on_event(sid, &frame[2], len),
                None => self.error(format!("malformed EVENT: {}", clip(text))),
            },
            (Some("EOSE"), 2 | 3) => match str_at(1) {
                Some(sid) => self.on_eose(sid, len).await?,
                None => self.error(format!("malformed EOSE: {}", clip(text))),
            },
            (Some("CLOSED"), 3) => {
                // A CLOSED for a REQ this client closed itself needs nothing.
                if let Some((job, batch)) = str_at(1).and_then(parse_ids_sid) {
                    if self
                        .live
                        .get(&job)
                        .is_some_and(|s| s.batch_no == batch && s.neg.is_none())
                    {
                        let reason = str_at(2).unwrap_or_default();
                        let mut session = self.live.remove(&job).expect("live sync");
                        session.log.fetch_down += len;
                        self.run.refused.push((job, format!("CLOSED {reason}")));
                        self.run.fetch_refused.push(session.into_log());
                    }
                }
            }
            (Some("NOTICE"), 2) => {
                let notice = str_at(1).unwrap_or_default().to_owned();
                self.run.notices.push(notice);
            }
            (Some("AUTH"), 2) => {}
            _ => self.error(format!("unexpected relay message: {}", clip(text))),
        }
        Ok(())
    }

    async fn on_neg_msg(&mut self, sid: &str, payload: &str, len: u64) -> Result<()> {
        let Some(job) = parse_neg_sid(sid).filter(|job| {
            self.live
                .get(job)
                .is_some_and(|session| session.neg.is_some())
        }) else {
            self.error(format!("NEG-MSG for no reconciling sync: {sid}"));
            return Ok(());
        };
        let session = self.live.get_mut(&job).expect("live sync");
        session.log.neg_down += len;
        session.log.rounds += 1;
        let reply = hex::decode(payload)
            .map_err(|e| format!("NEG-MSG is not hex: {e}"))
            .and_then(|bytes| {
                let neg = session.neg.as_mut().expect("reconciling");
                neg.reconcile_with_ids(&bytes, &mut session.have, &mut session.need)
                    .map_err(|e| format!("reconcile failed: {e}"))
            });
        match reply {
            Ok(Some(next)) => {
                let frame = json!(["NEG-MSG", sid, hex::encode(next)]);
                session.log.neg_up += send(&mut self.socket, frame).await?;
            }
            Ok(None) => {
                session.reconciled = Some(Instant::now());
                session.neg = None;
                session.log.neg_up += send(&mut self.socket, json!(["NEG-CLOSE", sid])).await?;
                session.queue = session.need.iter().map(|id| to_id(id)).collect();
                self.fetch_next(job).await?;
            }
            Err(e) => {
                self.live.remove(&job);
                self.run.failed.push((job, e));
                send(&mut self.socket, json!(["NEG-CLOSE", sid])).await?;
            }
        }
        Ok(())
    }

    /// Requests the next batch of `job`'s missing ids, or finishes the sync.
    async fn fetch_next(&mut self, job: usize) -> Result<()> {
        let session = self.live.get_mut(&job).expect("live sync");
        if session.queue.is_empty() {
            let session = self.live.remove(&job).expect("live sync");
            self.finish(session);
            return Ok(());
        }
        let take = session.queue.len().min(FETCH_BATCH);
        let ids = session.queue.split_off(session.queue.len() - take);
        let hex_ids: Vec<String> = ids.iter().map(hex::encode).collect();
        session.batch = ids.into_iter().collect();
        session.batch_no += 1;
        session.log.fetch_reqs += 1;
        let sid = format!("ids-{job}-{}", session.batch_no);
        let frame = json!(["REQ", sid, {"ids": hex_ids, "limit": take}]);
        session.log.fetch_up += send(&mut self.socket, frame).await?;
        Ok(())
    }

    fn on_event(&mut self, sid: &str, event: &Value, len: u64) {
        let Some(session) = parse_ids_sid(sid).and_then(|(job, batch)| {
            self.live
                .get_mut(&job)
                .filter(|session| session.batch_no == batch && session.neg.is_none())
        }) else {
            self.error(format!("EVENT for no open fetch: {sid}"));
            return;
        };
        session.log.fetch_down += len;
        let Some(id) = event_id(event) else {
            session.problem(format!("event without an id: {}", clip(&event.to_string())));
            return;
        };
        if !session.batch.remove(&id) {
            let problem = if session.returned.contains(&id) {
                "returned twice"
            } else {
                "returned unrequested"
            };
            session.problem(format!("{} {problem}", hex::encode(id)));
            return;
        }
        session.returned.insert(id);
        session.log.fetched += 1;
        // An id outside the corpus is counted once, as a reported extra.
        if self.plan.events.get(&id).is_some_and(|want| want != event) {
            session.problem(format!("{} returned altered", hex::encode(id)));
        }
    }

    async fn on_eose(&mut self, sid: &str, len: u64) -> Result<()> {
        let Some((job, session)) = parse_ids_sid(sid).and_then(|(job, batch)| {
            self.live
                .get_mut(&job)
                .filter(|session| session.batch_no == batch && session.neg.is_none())
                .map(|session| (job, session))
        }) else {
            self.error(format!("EOSE for no open fetch: {sid}"));
            return Ok(());
        };
        session.log.fetch_down += len;
        for id in std::mem::take(&mut session.batch) {
            session.problem(format!(
                "{} named by NEG-MSG but not returned by REQ",
                hex::encode(id)
            ));
        }
        session.log.fetch_up += send(&mut self.socket, json!(["CLOSE", sid])).await?;
        self.fetch_next(job).await
    }

    fn finish(&mut self, session: Session) {
        self.run.done.push(session.into_log());
    }
}

fn clip(text: &str) -> String {
    match text.char_indices().nth(200) {
        Some((at, _)) => format!("{}…", &text[..at]),
        None => text.to_owned(),
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Spread {
    pub p50_ms: f64,
    pub p90_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
}

impl Spread {
    fn of(durations: impl Iterator<Item = Duration>) -> Result<Self> {
        let mut hist = Histogram::<u64>::new(3)?;
        for d in durations {
            hist.record(d.as_micros().max(1) as u64)?;
        }
        let ms = |p: f64| hist.value_at_percentile(p) as f64 / 1000.0;
        Ok(Self {
            p50_ms: ms(50.0),
            p90_ms: ms(90.0),
            p99_ms: ms(99.0),
            max_ms: hist.max() as f64 / 1000.0,
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub options: Options,
    pub connections: usize,
    pub syncs: usize,
    pub completed: usize,
    pub refused: usize,
    pub failed: usize,
    /// Refused syncs by the relay's reason.
    pub refusals: BTreeMap<String, u64>,
    /// Events the filters match, the share the client holds and the share
    /// it lacks.
    pub events: u64,
    pub held: u64,
    pub missing: u64,
    /// Events the completed syncs fetched.
    pub fetched: u64,
    pub fetch_reqs: u64,
    pub rounds: u64,
    pub max_rounds: u64,
    pub neg_bytes_up: u64,
    pub neg_bytes_down: u64,
    pub fetch_bytes_up: u64,
    pub fetch_bytes_down: u64,
    /// From the first NEG-OPEN to the end of the last sync.
    pub wall_secs: f64,
    pub events_per_s: f64,
    pub syncs_per_s: f64,
    /// NEG-OPEN to the last NEG-MSG, last NEG-MSG to the last EOSE, and both.
    pub reconcile: Spread,
    pub fetch: Spread,
    pub sync: Spread,
    /// Kinds the relay withheld in full, as Wok withholds gift wraps from a
    /// reader without AUTH.
    pub withheld_kinds: Vec<u64>,
    pub notices: u64,
    pub errors: u64,
    pub error_samples: Vec<String>,
    pub mismatches: u64,
    pub mismatch_samples: Vec<String>,
}

impl Report {
    pub fn ok(&self) -> bool {
        self.errors == 0
            && self.mismatches == 0
            && self.completed + self.refused == self.syncs
            && !(self.options.expect_no_refusals && self.refused > 0)
    }

    pub fn notes(&self) -> String {
        let mut notes = format!(
            "{} of {} syncs completed, {} refused; {} events fetched in {:.3} s; latency is time per sync",
            self.completed, self.syncs, self.refused, self.fetched, self.wall_secs
        );
        if !self.withheld_kinds.is_empty() {
            notes.push_str(&format!("; withheld kinds {:?}", self.withheld_kinds));
        }
        notes.push_str("; see the NIP-77 catch-up table");
        notes
    }
}

/// Differences between what a kind's events got and what one of the two
/// allowed outcomes expects.
#[derive(Default)]
struct KindTally {
    /// Against serving every event: unnamed missing events, named held ones.
    served: u64,
    /// Against withholding every event: named missing events, held events
    /// the relay did not report lacking.
    withheld: u64,
    sample: Option<String>,
}

/// Checks a run against the plan, records each completed sync's time in
/// `hist` and summarizes. A sync refused during its fetch is checked as far
/// as it got.
pub fn report(plan: &Plan, run: &Run, opts: &Options, hist: &mut Histogram<u64>) -> Result<Report> {
    let policy = wok_relay::Config::default().read_restrictor();
    let mut mismatches = 0u64;
    let mut mismatch_samples = Vec::new();
    let mut mismatch = |n: u64, sample: String| {
        mismatches += n;
        if n > 0 && mismatch_samples.len() < SAMPLES {
            mismatch_samples.push(sample);
        }
    };
    let mut kinds: BTreeMap<u64, KindTally> = BTreeMap::new();
    for log in run.done.iter().chain(&run.fetch_refused) {
        let job = &plan.jobs[log.job];
        let filter = &job.filter;
        let need: HashSet<Id> = log.need.iter().copied().collect();
        let have: HashSet<Id> = log.have.iter().copied().collect();
        let held: HashSet<Id> = job.held.iter().map(|(_, id)| *id).collect();
        let restricted = |id: &Id| {
            plan.events
                .get(id)
                .map(kind)
                .filter(|k| policy.is_restricted_kind(*k))
        };
        // Ids the relay named that the client does not lack: wrong whether
        // a kind is served or withheld.
        for id in need.difference(&job.missing) {
            let sample = format!(
                "{filter}: named {}, {}",
                hex::encode(id),
                if held.contains(id) {
                    "which the client holds"
                } else if plan.events.contains_key(id) {
                    "which the filter does not match"
                } else {
                    "which is not in the corpus"
                }
            );
            match restricted(id) {
                Some(k) => {
                    let tally = kinds.entry(k).or_default();
                    tally.served += 1;
                    tally.withheld += 1;
                    tally.sample.get_or_insert(sample);
                }
                None => mismatch(1, sample),
            }
        }
        for id in job.missing.iter() {
            let named = need.contains(id);
            match restricted(id) {
                Some(k) => {
                    let tally = kinds.entry(k).or_default();
                    if named {
                        tally.withheld += 1;
                    } else {
                        tally.served += 1;
                    }
                }
                None if !named => mismatch(
                    1,
                    format!("{filter}: did not name missing {}", hex::encode(id)),
                ),
                None => {}
            }
        }
        for id in held.iter() {
            let lacking = have.contains(id);
            match restricted(id) {
                Some(k) => {
                    let tally = kinds.entry(k).or_default();
                    if lacking {
                        tally.served += 1;
                    } else {
                        tally.withheld += 1;
                    }
                }
                None if lacking => mismatch(1, format!("{filter}: lacks held {}", hex::encode(id))),
                None => {}
            }
        }
        let foreign = have.difference(&held).count() as u64;
        mismatch(
            foreign,
            format!("{filter}: lacks {foreign} ids the client never sent"),
        );
        mismatch(
            log.problems,
            format!("{filter}: {}", log.problem_samples.join("; ")),
        );
    }
    for log in &run.done {
        hist.record((log.reconcile + log.fetch).as_micros().max(1) as u64)?;
    }
    let mut withheld_kinds = Vec::new();
    for (k, tally) in kinds {
        if tally.withheld < tally.served {
            withheld_kinds.push(k);
        }
        let off = tally.served.min(tally.withheld);
        mismatch(
            off,
            format!(
                "kind {k} neither served nor withheld in full ({off} events off){}",
                tally.sample.map_or(String::new(), |s| format!(": {s}"))
            ),
        );
    }
    let mut refusals = BTreeMap::new();
    for (_, reason) in &run.refused {
        *refusals.entry(reason.clone()).or_insert(0) += 1;
    }
    let error_samples: Vec<String> = run
        .failed
        .iter()
        .map(|(job, e)| format!("{}: {e}", plan.jobs[*job].filter))
        .chain(run.errors.iter().cloned())
        .collect();
    let sum = |f: fn(&SessionLog) -> u64| run.done.iter().map(f).sum::<u64>();
    let fetched = sum(|log| log.fetched);
    let wall_secs = run.wall.as_secs_f64().max(f64::MIN_POSITIVE);
    Ok(Report {
        options: opts.clone(),
        connections: run.connections,
        syncs: plan.jobs.len(),
        completed: run.done.len(),
        refused: run.refused.len(),
        failed: run.failed.len(),
        refusals,
        events: plan.events.len() as u64,
        held: plan.held,
        missing: plan.missing,
        fetched,
        fetch_reqs: sum(|log| log.fetch_reqs),
        rounds: sum(|log| log.rounds),
        max_rounds: run.done.iter().map(|log| log.rounds).max().unwrap_or(0),
        neg_bytes_up: sum(|log| log.neg_up),
        neg_bytes_down: sum(|log| log.neg_down),
        fetch_bytes_up: sum(|log| log.fetch_up),
        fetch_bytes_down: sum(|log| log.fetch_down),
        wall_secs,
        events_per_s: fetched as f64 / wall_secs,
        syncs_per_s: run.done.len() as f64 / wall_secs,
        reconcile: Spread::of(run.done.iter().map(|log| log.reconcile))?,
        fetch: Spread::of(run.done.iter().map(|log| log.fetch))?,
        sync: Spread::of(run.done.iter().map(|log| log.reconcile + log.fetch))?,
        withheld_kinds,
        notices: run.notices.len() as u64,
        errors: error_samples.len() as u64,
        error_samples: error_samples.into_iter().take(SAMPLES).collect(),
        mismatches,
        mismatch_samples,
    })
}

pub fn render_markdown(report: &Report, relay: &str, repetition: u32) -> String {
    let o = &report.options;
    let filters = match o.filters {
        Filters::All if o.windows == 1 => "the whole corpus in one filter".to_owned(),
        Filters::All => format!("the whole corpus in {} time windows", report.syncs),
        Filters::Groups => format!("{} Marmot groups, one filter each", report.syncs),
    };
    let missing = match o.missing {
        Missing::Newest => "the newest",
        Missing::Random => "a random",
    };
    let mut s = format!("\n### NIP-77 catch-up: {relay}, repetition {repetition}\n\n");
    s.push_str(&format!(
        "{} syncs over {filters}, {} at once on {} connection(s), {} per connection; NEG-OPEN limit {}. The client held {} of the {} matched events and lacked {missing} {}% ({}). Completed {}, refused {}, failed {}, in {:.3} s: {:.1} events fetched and {:.1} syncs completed per second.\n\n",
        report.syncs,
        o.concurrency.min(report.syncs),
        report.connections,
        o.per_conn,
        o.limit().map_or("none".to_owned(), |l| l.to_string()),
        report.held,
        report.events,
        o.missing_pct,
        report.missing,
        report.completed,
        report.refused,
        report.failed,
        report.wall_secs,
        report.events_per_s,
        report.syncs_per_s,
    ));
    s.push_str("| phase | p50 ms | p90 ms | p99 ms | max ms |\n|---|---:|---:|---:|---:|\n");
    for (phase, spread) in [
        ("reconcile (NEG-OPEN to last NEG-MSG)", &report.reconcile),
        ("fetch (REQs for the missing ids)", &report.fetch),
        ("sync (both)", &report.sync),
    ] {
        s.push_str(&format!(
            "| {phase} | {:.2} | {:.2} | {:.2} | {:.1} |\n",
            spread.p50_ms, spread.p90_ms, spread.p99_ms, spread.max_ms
        ));
    }
    s.push_str("\n| measure | value |\n|---|---:|\n");
    let mut row = |label: &str, value: String| s.push_str(&format!("| {label} | {value} |\n"));
    row("events fetched", report.fetched.to_string());
    row("fetch REQs", report.fetch_reqs.to_string());
    row(
        "NEG-MSG rounds (total, most in one sync)",
        format!("{}, {}", report.rounds, report.max_rounds),
    );
    row(
        "NEG bytes up / down",
        format!("{} / {}", report.neg_bytes_up, report.neg_bytes_down),
    );
    row(
        "fetch bytes up / down",
        format!("{} / {}", report.fetch_bytes_up, report.fetch_bytes_down),
    );
    row("withheld kinds", format!("{:?}", report.withheld_kinds));
    row("NOTICEs", report.notices.to_string());
    row("errors", report.errors.to_string());
    row("mismatches", report.mismatches.to_string());
    for (reason, n) in &report.refusals {
        row(
            &format!("refused: {}", reason.replace('|', "\\|")),
            n.to_string(),
        );
    }
    for sample in report.error_samples.iter().chain(&report.mismatch_samples) {
        s.push_str(&format!("\n- {}", sample.replace('\n', " ")));
    }
    s.push('\n');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(created_at: u64, n: u8, kind: u64, tags: Value) -> Value {
        json!({
            "id": hex::encode([n; 32]),
            "pubkey": "00".repeat(32),
            "created_at": created_at,
            "kind": kind,
            "tags": tags,
            "content": "",
            "sig": "00".repeat(64),
        })
    }

    fn notes(times: &[u64]) -> Vec<Value> {
        times
            .iter()
            .enumerate()
            .map(|(i, t)| event(*t, i as u8 + 1, 1, json!([])))
            .collect()
    }

    fn options(filters: Filters, missing: Missing, missing_pct: f64) -> Options {
        Options {
            filters,
            windows: 1,
            missing,
            missing_pct,
            concurrency: 1,
            per_conn: 1,
            limit: None,
            clients_per_address: 1,
            expect_no_refusals: false,
            seed: 1,
            nodelay: true,
        }
    }

    fn missing_times(plan: &Plan) -> BTreeSet<u64> {
        plan.jobs
            .iter()
            .flat_map(|job| &job.missing)
            .map(|id| plan.events[id]["created_at"].as_u64().unwrap())
            .collect()
    }

    #[test]
    fn windows_split_at_whole_seconds_and_cover_the_corpus() {
        let times = [100, 101, 102, 103, 104, 104, 105, 106, 107, 108];
        let split = |windows| {
            let opts = Options {
                windows,
                ..options(Filters::All, Missing::Newest, 0.0)
            };
            let plan = plan(notes(&times), &opts).unwrap();
            let filters: Vec<Value> = plan.jobs.iter().map(|job| job.filter.clone()).collect();
            let sizes: Vec<usize> = plan.jobs.iter().map(|job| job.held.len()).collect();
            (filters, sizes)
        };
        assert_eq!(split(1), (vec![json!({})], vec![10]));
        // The middle event's second, 104, starts the second window whole.
        assert_eq!(
            split(2),
            (
                vec![json!({"until": 103}), json!({"since": 104})],
                vec![4, 6]
            )
        );
        assert_eq!(
            split(3),
            (
                vec![
                    json!({"until": 102}),
                    json!({"since": 103, "until": 104}),
                    json!({"since": 105}),
                ],
                vec![3, 3, 4]
            )
        );
        // More windows than seconds collapse to one per second.
        assert_eq!(split(40).0.len(), 9);
    }

    #[test]
    fn the_client_lacks_the_newest_or_a_seeded_random_share() {
        let times: Vec<u64> = (1..=20).collect();
        let lacking = |missing, pct, seed, windows| {
            let opts = Options {
                seed,
                windows,
                ..options(Filters::All, missing, pct)
            };
            let plan = plan(notes(&times), &opts).unwrap();
            let held: usize = plan.jobs.iter().map(|job| job.held.len()).sum();
            assert_eq!(held as u64 + plan.missing, 20);
            assert_eq!(held as u64, plan.held);
            missing_times(&plan)
        };
        assert_eq!(
            lacking(Missing::Newest, 25.0, 1, 3),
            (16..=20).collect::<BTreeSet<_>>()
        );
        assert!(lacking(Missing::Newest, 0.0, 1, 1).is_empty());
        assert_eq!(lacking(Missing::Newest, 100.0, 1, 2).len(), 20);
        let random = lacking(Missing::Random, 25.0, 7, 4);
        assert_eq!(random.len(), 5);
        assert_eq!(random, lacking(Missing::Random, 25.0, 7, 1), "same seed");
        assert_ne!(random, lacking(Missing::Random, 25.0, 8, 4), "other seed");
        assert_ne!(random, (16..=20).collect::<BTreeSet<_>>());
        let wrong = plan(
            notes(&times),
            &options(Filters::All, Missing::Newest, 101.0),
        );
        assert!(wrong.unwrap_err().to_string().contains("between 0 and 100"));
    }

    #[test]
    fn groups_get_one_filter_each_with_mdks_limit() {
        let events = vec![
            event(1, 1, 445, json!([["h", "a"]])),
            event(2, 2, 445, json!([["h", "b"]])),
            event(3, 3, 445, json!([["h", "a"]])),
            event(4, 4, 1, json!([["h", "a"]])),
            event(5, 5, 445, json!([["e", "a"]])),
            event(6, 6, 445, json!([["h", "a"]])),
        ];
        let opts = options(Filters::Groups, Missing::Newest, 50.0);
        let plan = plan(events.clone(), &opts).unwrap();
        let filters: Vec<&Value> = plan.jobs.iter().map(|job| &job.filter).collect();
        assert_eq!(
            filters,
            [
                &json!({"kinds": [445], "#h": ["a"], "limit": GROUP_LIMIT}),
                &json!({"kinds": [445], "#h": ["b"], "limit": GROUP_LIMIT}),
            ]
        );
        // Only the four group messages count; the newest two are missing.
        assert_eq!((plan.events.len(), plan.missing), (4, 2));
        assert_eq!(missing_times(&plan), BTreeSet::from([3, 6]));
        let small = Options {
            limit: Some(2),
            ..opts.clone()
        };
        let error = super::plan(events.clone(), &small).unwrap_err().to_string();
        assert!(
            error.contains("matches 3 events, more than its limit of 2"),
            "{error}"
        );
        let error = super::plan(notes(&[1, 2]), &opts).unwrap_err().to_string();
        assert!(error.contains("no kind 445 events"), "{error}");
    }

    /// Notes at odd seconds, gift wraps at even ones; the client lacks the
    /// newest half: notes 5 and 7 and wraps 6 and 8.
    fn mixed_plan() -> Plan {
        let events = (1..=8u8)
            .map(|t| event(t.into(), t, if t % 2 == 1 { 1 } else { 1059 }, json!([])))
            .collect();
        plan(events, &options(Filters::All, Missing::Newest, 50.0)).unwrap()
    }

    fn checked(plan: &Plan, need: &[u8], have: &[u8]) -> Report {
        let log = SessionLog {
            job: 0,
            need: need.iter().map(|n| [*n; 32]).collect(),
            have: have.iter().map(|n| [*n; 32]).collect(),
            ..SessionLog::default()
        };
        let run = Run {
            done: vec![log],
            connections: 1,
            wall: Duration::from_secs(1),
            ..Run::default()
        };
        let opts = options(Filters::All, Missing::Newest, 50.0);
        report(plan, &run, &opts, &mut Histogram::new(3).unwrap()).unwrap()
    }

    #[test]
    fn restricted_kinds_are_served_or_withheld_in_full() {
        let plan = mixed_plan();
        let served = checked(&plan, &[5, 6, 7, 8], &[]);
        assert_eq!(served.mismatches, 0, "{:?}", served.mismatch_samples);
        assert!(served.withheld_kinds.is_empty() && served.ok());
        // Without AUTH, Wok reports neither the missing wraps nor the held.
        let withheld = checked(&plan, &[5, 7], &[2, 4]);
        assert_eq!(withheld.mismatches, 0, "{:?}", withheld.mismatch_samples);
        assert_eq!(withheld.withheld_kinds, [1059]);
        // Serving one missing wrap and withholding the other is neither.
        let partial = checked(&plan, &[5, 6, 7], &[]);
        assert_eq!(partial.mismatches, 1, "{:?}", partial.mismatch_samples);
        assert!(!partial.ok());
        assert!(partial.mismatch_samples[0].starts_with("kind 1059 neither"));
    }

    #[test]
    fn the_oracle_counts_every_wrong_id() {
        let plan = mixed_plan();
        // Note 7 unnamed, held note 1 reported lacking, held note 3 named,
        // and an id outside the corpus named.
        let wrong = checked(&plan, &[3, 5, 6, 8, 0xee], &[1]);
        assert_eq!(wrong.mismatches, 4, "{:?}", wrong.mismatch_samples);
        let samples = wrong.mismatch_samples.join("\n");
        for expected in [
            "which the client holds",
            "which is not in the corpus",
            "did not name missing",
            "lacks held",
        ] {
            assert!(samples.contains(expected), "{expected}: {samples}");
        }
        // An id the client never sent, reported as lacking.
        assert_eq!(checked(&plan, &[5, 6, 7, 8], &[0xdd]).mismatches, 1);
    }

    /// Serves each connection to a listener on a free port with `relay`,
    /// which maps a client message to the replies, and returns its URL.
    async fn mock_relay<R>(relay: impl Fn() -> R + Send + 'static) -> String
    where
        R: FnMut(Value) -> Vec<Value> + Send + 'static,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let mut replies = relay();
                tokio::spawn(async move {
                    let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
                    while let Some(Ok(Message::Text(text))) = socket.next().await {
                        let frame = serde_json::from_str(text.as_str()).unwrap();
                        for reply in replies(frame) {
                            let _ = socket.send(Message::Text(reply.to_string().into())).await;
                        }
                    }
                });
            }
        });
        url
    }

    /// A relay that refuses every NEG-OPEN, as strfry does past
    /// `maxSyncEvents`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refusals_are_counted_and_fail_only_when_unexpected() {
        let url = mock_relay(|| {
            let mut opened = 0;
            move |frame: Value| {
                let mut reply = json!(["NEG-ERR", frame[1], "blocked: too many query results"]);
                // strfry 1.1.3 adds its limit; a relay may also send three.
                opened += 1;
                if opened % 2 == 1 {
                    reply.as_array_mut().unwrap().push(json!(1_000_000));
                }
                vec![reply]
            }
        })
        .await;
        let opts = Options {
            windows: 3,
            concurrency: 2,
            ..options(Filters::All, Missing::Newest, 50.0)
        };
        let plan = Arc::new(plan(notes(&[1, 2, 3, 4, 5, 6]), &opts).unwrap());
        let run = run(&url, plan.clone(), &opts).await.unwrap();
        let report = report(&plan, &run, &opts, &mut Histogram::new(3).unwrap()).unwrap();
        assert_eq!((report.completed, report.refused), (0, 3), "{report:#?}");
        assert_eq!(
            report.refusals,
            BTreeMap::from([("NEG-ERR blocked: too many query results".to_owned(), 3)])
        );
        assert!(report.ok());
        let strict = Report {
            options: Options {
                expect_no_refusals: true,
                ..opts
            },
            ..report
        };
        assert!(!strict.ok());
    }

    /// A relay that reconciles honestly, alters an event in the first
    /// fetch and refuses the second.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_fetch_keeps_what_it_saw() {
        let events: Vec<Value> = (0..800u16)
            .map(|i| {
                let mut event = event(i.into(), 0, 1, json!([]));
                let mut id = [0; 32];
                id[..2].copy_from_slice(&i.to_be_bytes());
                event["id"] = json!(hex::encode(id));
                event
            })
            .collect();
        let corpus: Arc<HashMap<String, Value>> = Arc::new(
            events
                .iter()
                .map(|e| (e["id"].as_str().unwrap().to_owned(), e.clone()))
                .collect(),
        );
        let url = mock_relay(move || {
            let corpus = corpus.clone();
            let mut neg = None;
            move |frame: Value| match frame[0].as_str().unwrap() {
                "NEG-OPEN" | "NEG-MSG" => {
                    let neg = neg.get_or_insert_with(|| {
                        let mut store = Vector::new();
                        for event in corpus.values() {
                            let id = hex::decode(event["id"].as_str().unwrap()).unwrap();
                            store
                                .insert(event["created_at"].as_u64().unwrap(), &id)
                                .unwrap();
                        }
                        store.seal().unwrap();
                        Negentropy::new(store, 0).unwrap()
                    });
                    let query =
                        hex::decode(frame.as_array().unwrap().last().unwrap().as_str().unwrap())
                            .unwrap();
                    vec![json!([
                        "NEG-MSG",
                        frame[1],
                        hex::encode(neg.reconcile(&query).unwrap())
                    ])]
                }
                "REQ" if frame[1].as_str().unwrap().ends_with("-1") => {
                    let mut replies: Vec<Value> = frame[2]["ids"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|id| json!(["EVENT", frame[1], corpus[id.as_str().unwrap()]]))
                        .collect();
                    replies[0][2]["content"] = json!("altered");
                    replies.push(json!(["EOSE", frame[1]]));
                    replies
                }
                "REQ" => vec![json!(["CLOSED", frame[1], "error: shutting down"])],
                _ => Vec::new(),
            }
        })
        .await;
        let opts = options(Filters::All, Missing::Newest, 100.0);
        let plan = Arc::new(plan(events, &opts).unwrap());
        let run = run(&url, plan.clone(), &opts).await.unwrap();
        assert_eq!(run.fetch_refused.len(), 1, "{run:#?}");
        let report = report(&plan, &run, &opts, &mut Histogram::new(3).unwrap()).unwrap();
        assert_eq!((report.completed, report.refused), (0, 1), "{report:#?}");
        // The altered event counts; the 300 the refused fetch never
        // returned do not.
        assert_eq!(report.mismatches, 1, "{:?}", report.mismatch_samples);
        assert!(report.mismatch_samples[0].contains("returned altered"));
        assert!(!report.ok());
    }

    /// Imports `events` into a Wok started in process, with the `{}` tree
    /// kept as the relay keeps it, and returns its URL.
    async fn start_wok(
        dir: &std::path::Path,
        events: &[Value],
    ) -> (String, wok_relay::RelayHandle) {
        let env = wok_db::Env::open(dir, wok_db::EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let mut batch: Vec<_> = events
            .iter()
            .map(|event| {
                let parsed = wok_event::parse_and_verify_event(
                    event,
                    &wok_event::EventLimits::default(),
                    None,
                    true,
                    false,
                )
                .unwrap();
                wok_db::EventToWrite::new(parsed.packed.into_bytes(), parsed.json)
            })
            .collect();
        let mut txn = env.begin_rw().unwrap();
        let mut trees = wok_negentropy::NegentropyFilterCache::default();
        wok_db::write_events(&mut txn, &mut trees, &mut batch, false).unwrap();
        txn.commit().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut cfg = wok_relay::Config {
            db: dir.to_path_buf(),
            ..Default::default()
        };
        cfg.relay.port = addr.port();
        cfg.relay.auth.enabled = false;
        cfg.relay.abuse.enabled = false;
        let handle = wok_relay::start(env, cfg).unwrap();
        let server = handle.clone();
        tokio::spawn(async move {
            let _ = wok_ws::serve_listener(server, listener).await;
        });
        (format!("ws://{addr}"), handle)
    }

    fn ids(events: &[Value]) -> BTreeSet<String> {
        events
            .iter()
            .map(|e| e["id"].as_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn a_relay_keeps_the_newest_version_and_drops_deleted_events() {
        let author = |n: u8, created_at: u64, kind: u64, tags: Value| {
            let mut e = event(created_at, n, kind, tags);
            e["pubkey"] = json!("aa".repeat(32));
            e
        };
        let events = vec![
            author(1, 10, 0, json!([])),
            author(2, 20, 0, json!([])),
            // A tie keeps the lower id.
            author(4, 5, 30_000, json!([["d", "x"]])),
            author(3, 5, 30_000, json!([["d", "x"]])),
            author(5, 5, 30_000, json!([["d", "y"]])),
            author(6, 1, 1, json!([])),
            author(7, 2, 1, json!([])),
            author(8, 3, 5, json!([["e", hex::encode([6u8; 32])]])),
            // Another author cannot delete note 7.
            event(4, 9, 5, json!([["e", hex::encode([7u8; 32])]])),
            event(6, 10, 20_001, json!([])),
            author(6, 1, 1, json!([])),
        ];
        let kept: Vec<u8> = kept(events)
            .iter()
            .map(|e| event_id(e).unwrap()[0])
            .collect();
        assert_eq!(kept, [2, 3, 5, 7, 8, 9]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn catches_up_with_wok() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("corpus.jsonl");
        crate::social::generate(
            &path,
            &crate::social::Options {
                events: 8_000,
                authors: 300,
                seed: 3,
                anchor: 1_760_000_000,
                max_follows: 300,
            },
        )
        .unwrap();
        let corpus = crate::read_event_values(&path).unwrap();
        let db = tempfile::tempdir().unwrap();
        let (url, handle) = start_wok(db.path(), &corpus).await;
        let kept = kept(corpus.clone());
        assert_eq!(
            ids(&kept),
            ids(&crate::retained_events(&corpus)),
            "the linear oracle keeps what retained_events keeps"
        );
        let cases = [
            Options {
                windows: 1,
                ..options(Filters::All, Missing::Newest, 10.0)
            },
            Options {
                windows: 5,
                concurrency: 4,
                per_conn: 2,
                ..options(Filters::All, Missing::Random, 30.0)
            },
            Options {
                concurrency: 16,
                per_conn: 8,
                ..options(Filters::Groups, Missing::Random, 50.0)
            },
        ];
        for opts in cases {
            let plan = Arc::new(plan(kept.clone(), &opts).unwrap());
            let wraps_missing = plan
                .jobs
                .iter()
                .flat_map(|job| &job.missing)
                .filter(|id| kind(&plan.events[*id]) == 1059)
                .count() as u64;
            let run = run(&url, plan.clone(), &opts).await.unwrap();
            let mut hist = Histogram::new(3).unwrap();
            let report = report(&plan, &run, &opts, &mut hist).unwrap();
            assert!(report.ok(), "{opts:?}: {report:#?}");
            assert_eq!(report.completed, plan.jobs.len());
            assert_eq!(hist.len(), plan.jobs.len() as u64);
            assert!(report.rounds >= report.completed as u64);
            assert!(report.neg_bytes_up > 0 && report.neg_bytes_down > 0);
            if opts.filters == Filters::All {
                // Wok serves gift wraps only to their recipients after AUTH.
                assert!(wraps_missing > 0, "the corpus has missing gift wraps");
                assert_eq!(report.withheld_kinds, [1059]);
                assert_eq!(report.fetched, plan.missing - wraps_missing);
            } else {
                assert!(report.syncs > 10 && report.withheld_kinds.is_empty());
                assert_eq!(report.fetched, plan.missing);
            }
            assert!(report.fetched > 0 && report.fetch_bytes_down > 0);
            let md = render_markdown(&report, "wok", 1);
            assert!(md.contains("| sync (both) |"), "{md}");
        }
        handle.request_shutdown();
    }
}
