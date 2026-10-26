//! Fixed-rate publication: `--scenario ws_publish_rate`.
//!
//! `ws_publish_scaled` sends a connection's next event only after the last
//! one's OK, so a relay that slows down slows the sender too and its backlog
//! never shows. Here event `seq` is due `seq / rate` seconds after the start,
//! on connection `seq % conns`, and goes out then whether or not earlier
//! events have been answered. Latency counts from when an event was due, so
//! time it waited behind a slow relay counts as well.
//!
//! Every event's send time and reply go to an outcome log, one JSON line per
//! event in due order. [`reconcile`] compares that log with the relay's
//! export and puts each event in one outcome: acknowledged and stored;
//! acknowledged but missing, a lost write; refused, by the reason's prefix;
//! or unanswered, then stored or not. An event never sent because its
//! connection failed counts as unanswered.

use anyhow::{Context, Result};
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use hdrhistogram::Histogram;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::Message;

use crate::{connect_retry, read_ack, ClientConnection, EventFactory, EventMix};

/// Share of the intended rate the sends must reach for a run to count.
pub(crate) const RATE_HELD: f64 = 0.99;
/// Acknowledged but missing events a reconciliation lists by id.
const LISTED: usize = 20;
/// How long a connection keeps reading once every event it sent is answered,
/// so a repeated or malformed OK queued behind the last one still counts.
const TAIL: Duration = Duration::from_millis(500);

#[derive(Clone, Debug)]
pub struct Options {
    /// Events per second over all connections.
    pub rate: f64,
    pub secs: f64,
    pub conns: usize,
    /// How long to wait for replies after the last send.
    pub drain: Duration,
    pub seed: u64,
    pub base_timestamp: u64,
    pub mix: EventMix,
}

impl Options {
    /// Events the run sends.
    pub fn events(&self) -> Result<u64> {
        anyhow::ensure!(
            self.rate.is_finite() && self.rate > 0.0 && self.secs.is_finite() && self.secs > 0.0,
            "--send-rate and --send-secs must be positive"
        );
        anyhow::ensure!(self.conns > 0, "fixed-rate publication needs a connection");
        // A relay keeps every event of these mixes, so every acknowledged
        // one must be in its export.
        anyhow::ensure!(
            matches!(self.mix, EventMix::Kind1 | EventMix::Realistic),
            "--scenario ws_publish_rate needs --event-mix kind1 or realistic"
        );
        let events = (self.rate * self.secs).ceil();
        anyhow::ensure!(
            events <= f64::from(u32::MAX),
            "--send-rate times --send-secs is too many events"
        );
        Ok(events as u64)
    }

    fn due(&self, seq: u64) -> Duration {
        Duration::from_secs_f64(seq as f64 / self.rate)
    }
}

/// One connection's events, signed and serialized before the clock starts.
pub struct Lane {
    warmup: Value,
    events: Vec<Planned>,
}

struct Planned {
    seq: u64,
    id: [u8; 32],
    kind: u16,
    frame: String,
}

/// Sign every event up front, on every core, so signing costs the run
/// nothing. Connection `c` sends `seq` `c`, `c + conns`, and so on.
pub fn plan(opts: &Options) -> Result<Vec<Lane>> {
    let total = opts.events()?;
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    let per_thread = opts.conns.div_ceil(threads);
    Ok(std::thread::scope(|scope| {
        let workers: Vec<_> = (0..opts.conns)
            .step_by(per_thread)
            .map(|first| {
                scope.spawn(move || {
                    (first..(first + per_thread).min(opts.conns))
                        .map(|conn| lane(opts, total, conn))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        workers
            .into_iter()
            .flat_map(|worker| worker.join().expect("event signing panicked"))
            .collect()
    }))
}

fn lane(opts: &Options, total: u64, conn: usize) -> Lane {
    let conns = opts.conns as u64;
    let conn = conn as u64;
    let count = total / conns + u64::from(conn < total % conns);
    // Each connection signs with its own keys.
    let mut factory = EventFactory::new(splitmix(splitmix(opts.seed).wrapping_add(conn)));
    let warmup = factory.event(0, count + 1, opts.base_timestamp, opts.mix);
    let events = (1..=count)
        .map(|i| {
            let event = factory.event(i, count + 1, opts.base_timestamp, opts.mix);
            Planned {
                seq: (i - 1) * conns + conn,
                id: parse_id(event["id"].as_str().unwrap_or_default())
                    .expect("generated events carry a hex id"),
                kind: event["kind"]
                    .as_u64()
                    .and_then(|kind| u16::try_from(kind).ok())
                    .unwrap_or(u16::MAX),
                frame: json!(["EVENT", event]).to_string(),
            }
        })
        .collect();
    Lane { warmup, events }
}

/// SplitMix64's finalizer: nearby inputs give unrelated seeds.
fn splitmix(seed: u64) -> u64 {
    let mut z = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn parse_id(hex_id: &str) -> Option<[u8; 32]> {
    let mut id = [0u8; 32];
    hex::decode_to_slice(hex_id, &mut id).ok()?;
    Some(id)
}

/// What happened to one event. Times are microseconds from the start.
#[derive(Debug)]
pub struct Record {
    seq: u64,
    conn: usize,
    id: [u8; 32],
    kind: u16,
    due_us: u64,
    sent_us: Option<u64>,
    reply: Option<Reply>,
}

#[derive(Debug)]
struct Reply {
    accepted: bool,
    message: String,
    at_us: u64,
}

/// A whole run, in due order.
pub struct Run {
    records: Vec<Record>,
    /// Why connections failed, one entry per failed connection.
    errors: Vec<String>,
    /// OK frames that were malformed, named no event of their connection's,
    /// or repeated an earlier OK.
    misrouted: u64,
    notices: u64,
    /// When each connection stopped reading, by connection.
    ended_us: Vec<u64>,
}

/// Connect and warm up every lane, then send on schedule until the last
/// event is sent and answered, or `drain` passes after it.
pub async fn run(url: &str, lanes: Vec<Lane>, opts: &Options) -> Result<Run> {
    let mut sockets = Vec::with_capacity(lanes.len());
    for lane in &lanes {
        let mut socket = connect_retry(url).await?;
        socket
            .send(Message::Text(
                json!(["EVENT", lane.warmup]).to_string().into(),
            ))
            .await?;
        anyhow::ensure!(
            read_ack(&mut socket, &lane.warmup).await?,
            "warm-up publication refused"
        );
        let ClientConnection::WebSocket(socket) = socket else {
            anyhow::bail!("--scenario ws_publish_rate publishes over WebSocket only");
        };
        sockets.push(*socket);
    }
    // Give every task a moment to start before the first event is due.
    let start = Instant::now() + Duration::from_millis(100);
    let opts = Arc::new(opts.clone());
    let tasks: Vec<_> = sockets
        .into_iter()
        .zip(lanes)
        .enumerate()
        .map(|(conn, (socket, lane))| {
            let (sink, stream) = socket.split();
            tokio::spawn(drive(sink, stream, lane.events, conn, start, opts.clone()))
        })
        .collect();
    let mut run = Run {
        records: Vec::new(),
        errors: Vec::new(),
        misrouted: 0,
        notices: 0,
        ended_us: Vec::new(),
    };
    for task in tasks {
        let log = task.await.context("publisher task panicked")?;
        run.records.extend(log.records);
        run.errors.extend(log.error);
        run.misrouted += log.misrouted;
        run.notices += log.notices;
        run.ended_us.push(log.ended_us);
    }
    run.records.sort_unstable_by_key(|record| record.seq);
    Ok(run)
}

struct LaneLog {
    records: Vec<Record>,
    error: Option<String>,
    misrouted: u64,
    notices: u64,
    ended_us: u64,
}

fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

fn since(start: Instant) -> u64 {
    micros(Instant::now().saturating_duration_since(start))
}

fn failure(conn: usize, start: Instant, why: &str) -> String {
    format!(
        "connection {conn} at {:.1} s: {why}",
        since(start) as f64 / 1e6
    )
}

async fn until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

/// One connection: a sender that keeps the schedule and a reader that takes
/// the replies, on the two halves of the socket. A send still pending once
/// the schedule and the drain are over is abandoned, so a relay that stops
/// reading cannot hold the run open.
async fn drive<S, R>(
    mut sink: S,
    mut stream: R,
    events: Vec<Planned>,
    conn: usize,
    start: Instant,
    opts: Arc<Options>,
) -> LaneLog
where
    S: Sink<Message> + Unpin,
    S::Error: std::fmt::Display,
    R: Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let stalled = start + Duration::from_secs_f64(opts.secs) + opts.drain;
    let index: HashMap<[u8; 32], usize> = events
        .iter()
        .enumerate()
        .map(|(k, event)| (event.id, k))
        .collect();
    let mut frames = Vec::with_capacity(events.len());
    let records: Vec<Record> = events
        .into_iter()
        .map(|event| {
            frames.push(event.frame);
            Record {
                seq: event.seq,
                conn,
                id: event.id,
                kind: event.kind,
                due_us: micros(opts.due(event.seq)),
                sent_us: None,
                reply: None,
            }
        })
        .collect();
    let mut sent = vec![None; records.len()];
    let mut replies: Vec<Option<Reply>> = records.iter().map(|_| None).collect();
    // When sending stopped, and how many events went out.
    let (done_tx, mut done_rx) = watch::channel(None::<(Instant, usize)>);

    let send = async {
        let mut error = None;
        let mut count = 0;
        for (k, frame) in frames.into_iter().enumerate() {
            let due = start + Duration::from_micros(records[k].due_us);
            if due > Instant::now() {
                tokio::time::sleep_until(due).await;
            }
            match tokio::time::timeout_at(stalled, sink.send(Message::Text(frame.into()))).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    error = Some(failure(conn, start, &format!("send failed: {e}")));
                    break;
                }
                Err(_) => {
                    error = Some(failure(
                        conn,
                        start,
                        "send stalled: the relay stopped reading",
                    ));
                    break;
                }
            }
            sent[k] = Some(since(start));
            count += 1;
        }
        let _ = done_tx.send(Some((Instant::now(), count)));
        error
    };

    let receive = async {
        let mut error = None;
        let (mut misrouted, mut notices, mut answered) = (0u64, 0u64, 0usize);
        let mut finished: Option<(Instant, usize)> = None;
        // When every sent event had its answer.
        let mut settled: Option<Instant> = None;
        loop {
            if settled.is_none() && finished.is_some_and(|(_, count)| answered >= count) {
                settled = Some(Instant::now());
            }
            let deadline = finished.map(|(at, _)| {
                let drained = at + opts.drain;
                settled.map_or(drained, |settled| drained.min(settled + TAIL))
            });
            tokio::select! {
                _ = done_rx.changed(), if finished.is_none() => {
                    finished = *done_rx.borrow_and_update();
                }
                () = until(deadline) => break,
                message = stream.next() => {
                    // Once every sent event is answered, a close loses nothing.
                    let text = match message {
                        Some(Ok(Message::Text(text))) => text,
                        Some(Ok(Message::Close(frame))) => {
                            let why = frame.map_or_else(String::new, |frame| {
                                format!(" ({} {})", u16::from(frame.code), frame.reason)
                            });
                            if settled.is_none() {
                                error = Some(failure(conn, start, &format!("relay closed the connection{why}")));
                            }
                            break;
                        }
                        Some(Ok(_)) => continue,
                        Some(Err(e)) => {
                            if settled.is_none() {
                                error = Some(failure(conn, start, &e.to_string()));
                            }
                            break;
                        }
                        None => {
                            if settled.is_none() {
                                error = Some(failure(conn, start, "relay closed the connection"));
                            }
                            break;
                        }
                    };
                    let Ok(frame) = serde_json::from_str::<Value>(text.as_str()) else {
                        misrouted += 1;
                        continue;
                    };
                    match frame[0].as_str() {
                        Some("OK") => {
                            let at_us = since(start);
                            let receipt = frame
                                .as_array()
                                .filter(|parts| parts.len() == 4)
                                .and_then(|_| {
                                    let k = *index.get(&parse_id(frame[1].as_str()?)?)?;
                                    Some((k, frame[2].as_bool()?, frame[3].as_str()?))
                                });
                            match receipt {
                                Some((k, accepted, message)) if replies[k].is_none() => {
                                    replies[k] = Some(Reply {
                                        accepted,
                                        message: message.to_owned(),
                                        at_us,
                                    });
                                    answered += 1;
                                }
                                _ => misrouted += 1,
                            }
                        }
                        Some("NOTICE") => notices += 1,
                        // AUTH challenges and anything else a relay may send.
                        _ => {}
                    }
                }
            }
        }
        (error, misrouted, notices, since(start))
    };

    let (send_error, (receive_error, misrouted, notices, ended_us)) = tokio::join!(send, receive);
    let _ = tokio::time::timeout(Duration::from_secs(1), sink.close()).await;
    let records = records
        .into_iter()
        .zip(sent)
        .zip(replies)
        .map(|((record, sent_us), reply)| Record {
            sent_us,
            reply,
            ..record
        })
        .collect();
    LaneLog {
        records,
        // A send fails because the relay closed the connection, which the
        // reader saw first.
        error: receive_error.or(send_error),
        misrouted,
        notices,
        ended_us,
    }
}

/// The machine-readable prefix of an OK message, such as `rate-limited`.
fn prefix(message: &str) -> String {
    match message.split_once(':') {
        Some((prefix, _))
            if (1..=32).contains(&prefix.len())
                && prefix.bytes().all(|b| b.is_ascii_lowercase() || b == b'-') =>
        {
            prefix.to_owned()
        }
        _ => "(none)".to_owned(),
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub intended_rate: f64,
    /// Events sent per second over the offered window: the schedule, or to
    /// the last send if that was later.
    pub achieved_rate: f64,
    /// Events accepted per second over the offered window, or to the last
    /// accepting OK if that was later: what the relay took in, backlog
    /// included.
    pub accepted_rate: f64,
    pub secs: f64,
    pub connections: usize,
    pub events: u64,
    pub sent: u64,
    /// Events not sent because their connection had failed.
    pub unsent: u64,
    pub accepted: u64,
    /// Accepted with a `duplicate:` message: the relay already had them.
    pub duplicates: u64,
    /// Refusals by message prefix.
    pub refused: BTreeMap<String, u64>,
    /// Sent but unanswered when the drain ended.
    pub no_reply: u64,
    pub misrouted: u64,
    pub notices: u64,
    pub connection_errors: Vec<String>,
    /// From when an event was due to its accepting OK. A sent event never
    /// answered counts until its connection stopped reading, a lower bound;
    /// refusals are left out.
    pub ok_p50_ms: f64,
    pub ok_p99_ms: f64,
    pub ok_max_ms: f64,
    /// From when an event was due to when its send completed.
    pub send_lag_p99_ms: f64,
    pub send_lag_max_ms: f64,
    pub log: String,
    /// Set once the log is compared with the relay's export.
    pub reconciliation: Option<Reconciliation>,
}

impl Report {
    pub fn rate_held(&self) -> bool {
        self.achieved_rate >= RATE_HELD * self.intended_rate
    }

    pub fn errors(&self) -> u64 {
        self.connection_errors.len() as u64
    }

    pub fn mismatches(&self) -> u64 {
        self.misrouted
            + self
                .reconciliation
                .as_ref()
                .map_or(0, Reconciliation::mismatches)
    }

    pub fn ok(&self) -> bool {
        self.errors() == 0 && self.mismatches() == 0 && self.rate_held()
    }

    pub fn notes(&self) -> String {
        let refused: u64 = self.refused.values().sum();
        let storage = match &self.reconciliation {
            None => "not reconciled (remote target; see --reconcile)",
            Some(reconciliation) if reconciliation.ok() => "reconciled",
            Some(_) => "MISMATCH",
        };
        format!(
            "{} events at {}/s over {} connection(s): sent {} at {:.1}/s{}, accepted {}, refused {refused}, no reply {}; storage {storage}; see the fixed-rate table",
            self.events,
            self.intended_rate,
            self.connections,
            self.sent,
            self.achieved_rate,
            if self.rate_held() { "" } else { " (rate NOT held)" },
            self.accepted,
            self.no_reply,
        )
    }
}

/// Summarize a run. Accepting OKs' latencies, in microseconds from when
/// each event was due, go into `hist`, with every sent event never answered
/// at the time its connection stopped reading.
pub fn report(run: &Run, opts: &Options, log: &Path, hist: &mut Histogram<u64>) -> Result<Report> {
    let mut lag = Histogram::<u64>::new(3)?;
    let mut report = Report {
        intended_rate: opts.rate,
        achieved_rate: 0.0,
        accepted_rate: 0.0,
        secs: opts.secs,
        connections: opts.conns,
        events: run.records.len() as u64,
        sent: 0,
        unsent: 0,
        accepted: 0,
        duplicates: 0,
        refused: BTreeMap::new(),
        no_reply: 0,
        misrouted: run.misrouted,
        notices: run.notices,
        connection_errors: run.errors.clone(),
        ok_p50_ms: 0.0,
        ok_p99_ms: 0.0,
        ok_max_ms: 0.0,
        send_lag_p99_ms: 0.0,
        send_lag_max_ms: 0.0,
        log: log.display().to_string(),
        reconciliation: None,
    };
    let (mut last_sent, mut last_accepted) = (0, 0);
    for record in &run.records {
        match record.sent_us {
            Some(sent) => {
                report.sent += 1;
                last_sent = last_sent.max(sent);
                lag.record(sent.saturating_sub(record.due_us).max(1))?;
            }
            None => report.unsent += 1,
        }
        match &record.reply {
            Some(reply) if reply.accepted => {
                report.accepted += 1;
                last_accepted = last_accepted.max(reply.at_us);
                report.duplicates += u64::from(prefix(&reply.message) == "duplicate");
                hist.record(reply.at_us.saturating_sub(record.due_us).max(1))?;
            }
            Some(reply) => *report.refused.entry(prefix(&reply.message)).or_default() += 1,
            None if record.sent_us.is_some() => {
                report.no_reply += 1;
                let ended = run.ended_us.get(record.conn).copied().unwrap_or_default();
                hist.record(ended.saturating_sub(record.due_us).max(1))?;
            }
            None => {}
        }
    }
    // The last send closes an interval of 1 / rate.
    let window = (report.events as f64 / opts.rate).max(last_sent as f64 / 1e6 + 1.0 / opts.rate);
    report.achieved_rate = report.sent as f64 / window;
    report.accepted_rate = report.accepted as f64 / window.max(last_accepted as f64 / 1e6);
    if report.sent > 0 {
        report.send_lag_p99_ms = lag.value_at_percentile(99.0) as f64 / 1000.0;
        report.send_lag_max_ms = lag.max() as f64 / 1000.0;
    }
    if !hist.is_empty() {
        report.ok_p50_ms = hist.value_at_percentile(50.0) as f64 / 1000.0;
        report.ok_p99_ms = hist.value_at_percentile(99.0) as f64 / 1000.0;
        report.ok_max_ms = hist.max() as f64 / 1000.0;
    }
    Ok(report)
}

/// One outcome log line.
#[derive(Debug, Serialize, Deserialize)]
struct LogLine {
    seq: u64,
    conn: usize,
    id: String,
    kind: u16,
    due_us: u64,
    sent_us: Option<u64>,
    reply_us: Option<u64>,
    ok: Option<bool>,
    message: Option<String>,
}

/// Write the outcome log, one JSON line per event in due order.
pub fn write_log(path: &Path, run: &Run) -> Result<()> {
    let file = std::fs::File::create(path).with_context(|| format!("create {}", path.display()))?;
    let mut out = std::io::BufWriter::new(file);
    for record in &run.records {
        let line = LogLine {
            seq: record.seq,
            conn: record.conn,
            id: hex::encode(record.id),
            kind: record.kind,
            due_us: record.due_us,
            sent_us: record.sent_us,
            reply_us: record.reply.as_ref().map(|reply| reply.at_us),
            ok: record.reply.as_ref().map(|reply| reply.accepted),
            message: record.reply.as_ref().map(|reply| reply.message.clone()),
        };
        serde_json::to_writer(&mut out, &line)?;
        out.write_all(b"\n")?;
    }
    out.flush()?;
    Ok(())
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Reconciliation {
    pub events: u64,
    pub acked_stored: u64,
    /// Acknowledged but not in the export: lost writes.
    pub acked_missing: u64,
    /// Refusals by message prefix.
    pub refused: BTreeMap<String, u64>,
    /// Refused but in the export anyway.
    pub refused_stored: u64,
    /// Unanswered, sent or not, but stored.
    pub no_reply_stored: u64,
    /// Unanswered and not stored: a client would have to send them again.
    pub no_reply_missing: u64,
    /// The first acknowledged but missing events, in due order.
    pub missing_ids: Vec<String>,
}

impl Reconciliation {
    pub fn mismatches(&self) -> u64 {
        self.acked_missing + self.refused_stored
    }

    pub fn ok(&self) -> bool {
        self.mismatches() == 0
    }

    pub fn summary(&self) -> String {
        format!(
            "{} events: {} acknowledged and stored, {} acknowledged but missing, {} refused ({} of them stored), {} unanswered but stored, {} unanswered and missing",
            self.events,
            self.acked_stored,
            self.acked_missing,
            self.refused.values().sum::<u64>(),
            self.refused_stored,
            self.no_reply_stored,
            self.no_reply_missing,
        )
    }
}

#[derive(Deserialize)]
struct Exported {
    id: String,
}

/// Put every event of an outcome log in one outcome, by whether the relay's
/// export (one event per line, as `wok export` and `strfry export` write)
/// holds it.
pub fn reconcile(log: impl BufRead, export: impl BufRead) -> Result<Reconciliation> {
    let mut out = Reconciliation::default();
    // Per event: id, reply, stored.
    let mut events: Vec<([u8; 32], Option<bool>, bool)> = Vec::new();
    let mut index = HashMap::new();
    for (n, line) in log.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: LogLine = serde_json::from_str(&line)
            .with_context(|| format!("outcome log line {} is not an outcome", n + 1))?;
        let id = parse_id(&entry.id)
            .with_context(|| format!("outcome log line {} has a bad id", n + 1))?;
        anyhow::ensure!(
            index.insert(id, events.len()).is_none(),
            "the outcome log repeats event {}",
            entry.id
        );
        if entry.ok == Some(false) {
            *out.refused
                .entry(prefix(entry.message.as_deref().unwrap_or_default()))
                .or_default() += 1;
        }
        events.push((id, entry.ok, false));
    }
    for (n, line) in export.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let event: Exported = serde_json::from_str(&line)
            .with_context(|| format!("export line {} is not an event", n + 1))?;
        if let Some(&k) = parse_id(&event.id).and_then(|id| index.get(&id)) {
            events[k].2 = true;
        }
    }
    for (id, ok, stored) in events {
        out.events += 1;
        match (ok, stored) {
            (Some(true), true) => out.acked_stored += 1,
            (Some(true), false) => {
                out.acked_missing += 1;
                if out.missing_ids.len() < LISTED {
                    out.missing_ids.push(hex::encode(id));
                }
            }
            (Some(false), stored) => out.refused_stored += u64::from(stored),
            (None, true) => out.no_reply_stored += 1,
            (None, false) => out.no_reply_missing += 1,
        }
    }
    Ok(out)
}

/// [`reconcile`] files; an export of `-` is standard input.
pub fn reconcile_files(log: &Path, export: &Path) -> Result<Reconciliation> {
    let open = |path: &Path| {
        std::fs::File::open(path)
            .map(std::io::BufReader::new)
            .with_context(|| format!("open {}", path.display()))
    };
    if export == Path::new("-") {
        reconcile(open(log)?, std::io::stdin().lock())
    } else {
        reconcile(open(log)?, open(export)?)
    }
}

pub fn render_markdown(report: &Report, relay: &str, repetition: u32) -> String {
    let mut s = format!("\n### Fixed-rate publication: {relay}, repetition {repetition}\n\n");
    s.push_str(&format!(
        "{} events due at {}/s for {} s over {} connection(s). Sent {} at {:.1}/s ({}); send lag p99 {:.2} ms, max {:.1} ms. Accepted {} at {:.1}/s over the schedule, or to the last accepting OK if later. Latency from when an event was due to its accepting OK, an unanswered event counting until the drain ended: p50 {:.2} ms, p99 {:.2} ms, max {:.1} ms. Outcome log: `{}`.\n\n",
        report.events,
        report.intended_rate,
        report.secs,
        report.connections,
        report.sent,
        report.achieved_rate,
        if report.rate_held() { "rate held" } else { "rate NOT held" },
        report.send_lag_p99_ms,
        report.send_lag_max_ms,
        report.accepted,
        report.accepted_rate,
        report.ok_p50_ms,
        report.ok_p99_ms,
        report.ok_max_ms,
        report.log,
    ));
    s.push_str("| outcome | events |\n|---|---:|\n");
    let mut row = |label: &str, n: u64| s.push_str(&format!("| {label} | {n} |\n"));
    let refused = report
        .reconciliation
        .as_ref()
        .map_or(&report.refused, |reconciliation| &reconciliation.refused);
    match &report.reconciliation {
        Some(reconciliation) => {
            row("acknowledged, stored", reconciliation.acked_stored);
            row("acknowledged, MISSING", reconciliation.acked_missing);
            for (prefix, n) in refused {
                row(&format!("refused: {prefix}"), *n);
            }
            row("refused, but stored", reconciliation.refused_stored);
            row("no reply, stored", reconciliation.no_reply_stored);
            row("no reply, not stored", reconciliation.no_reply_missing);
        }
        None => {
            row("accepted (storage not reconciled)", report.accepted);
            for (prefix, n) in refused {
                row(&format!("refused: {prefix}"), *n);
            }
            row("no reply", report.no_reply);
            row("never sent", report.unsent);
        }
    }
    if report.duplicates > 0 {
        row("accepted as duplicates", report.duplicates);
    }
    if report.misrouted > 0 {
        row("malformed, misrouted or repeated OKs", report.misrouted);
    }
    for error in &report.connection_errors {
        s.push_str(&format!("\nConnection failed: {error}\n"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(rate: f64, secs: f64, conns: usize) -> Options {
        Options {
            rate,
            secs,
            conns,
            drain: Duration::from_secs(1),
            seed: 5,
            base_timestamp: 1_800_000_000,
            mix: EventMix::Realistic,
        }
    }

    #[test]
    fn options_refuse_what_a_relay_does_not_keep_whole() {
        assert_eq!(options(250.0, 2.0, 4).events().unwrap(), 500);
        assert_eq!(options(0.5, 3.0, 4).events().unwrap(), 2);
        for bad in [
            options(0.0, 1.0, 1),
            options(f64::NAN, 1.0, 1),
            options(10.0, 0.0, 1),
            options(10.0, 1.0, 0),
            Options {
                mix: EventMix::Lifecycle,
                ..options(10.0, 1.0, 1)
            },
        ] {
            assert!(bad.events().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_plan_deals_events_to_connections_in_due_order() {
        let opts = options(10.0, 1.0, 3);
        let lanes = plan(&opts).unwrap();
        let seqs: Vec<Vec<u64>> = lanes
            .iter()
            .map(|lane| lane.events.iter().map(|event| event.seq).collect())
            .collect();
        assert_eq!(seqs, [vec![0, 3, 6, 9], vec![1, 4, 7], vec![2, 5, 8]]);
        let ids: std::collections::HashSet<_> = lanes
            .iter()
            .flat_map(|lane| lane.events.iter().map(|event| event.id))
            .chain(
                lanes
                    .iter()
                    .map(|lane| parse_id(lane.warmup["id"].as_str().unwrap()).unwrap()),
            )
            .collect();
        assert_eq!(ids.len(), 13, "every event and warm-up is distinct");
        let again: Vec<[u8; 32]> = plan(&opts).unwrap()[1]
            .events
            .iter()
            .map(|event| event.id)
            .collect();
        let first: Vec<[u8; 32]> = lanes[1].events.iter().map(|event| event.id).collect();
        assert_eq!(again, first, "the plan is reproducible");
        let other: Vec<[u8; 32]> = plan(&Options { seed: 6, ..opts }).unwrap()[1]
            .events
            .iter()
            .map(|event| event.id)
            .collect();
        assert_ne!(other, first, "another seed signs other events");
    }

    fn line(seq: u64, ok: Option<bool>, message: &str) -> String {
        let id = hex::encode([seq as u8 + 1; 32]);
        serde_json::to_string(&LogLine {
            seq,
            conn: 0,
            id,
            kind: 1,
            due_us: seq * 1000,
            sent_us: Some(seq * 1000 + 5),
            reply_us: ok.map(|_| seq * 1000 + 900),
            ok,
            message: ok.map(|_| message.to_owned()),
        })
        .unwrap()
    }

    #[test]
    fn reconciliation_puts_every_event_in_one_outcome() {
        let log = [
            line(0, Some(true), ""),
            line(1, Some(true), "duplicate: have it"),
            line(2, Some(true), ""),
            line(3, Some(false), "rate-limited: slow down"),
            line(4, Some(false), "rate-limited: slow down"),
            line(5, Some(false), "Too fast"),
            line(6, None, ""),
            line(7, None, ""),
        ]
        .join("\n");
        // Stored: 0, 1, 4 (refused!), 6, and an event of someone else's.
        let export = [0u8, 1, 4, 6, 200]
            .iter()
            .map(|seq| json!({"id": hex::encode([seq + 1; 32]), "kind": 1}).to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let out = reconcile(log.as_bytes(), export.as_bytes()).unwrap();
        assert_eq!(out.events, 8);
        assert_eq!((out.acked_stored, out.acked_missing), (2, 1));
        assert_eq!(out.missing_ids, [hex::encode([3u8; 32])]);
        assert_eq!(
            out.refused,
            BTreeMap::from([("(none)".to_owned(), 1), ("rate-limited".to_owned(), 2)])
        );
        assert_eq!(out.refused_stored, 1);
        assert_eq!((out.no_reply_stored, out.no_reply_missing), (1, 1));
        assert_eq!(out.mismatches(), 2);
        assert!(!out.ok());

        let repeated = [line(0, None, ""), line(0, Some(true), "")].join("\n");
        assert!(reconcile(repeated.as_bytes(), &b""[..]).is_err());
        assert!(reconcile(line(0, None, "").as_bytes(), &b"not json"[..]).is_err());
    }

    /// A relay that answers a quarter of each connection's events at once, a
    /// quarter with a refusal, a quarter never, and a quarter 300 ms late.
    /// It stores what it accepts, and what it leaves unanswered on its first
    /// connection.
    async fn scripted_relay(listener: tokio::net::TcpListener, conns: usize) -> Vec<String> {
        let mut tasks = Vec::new();
        for conn in 0..conns {
            let (stream, _) = listener.accept().await.unwrap();
            let socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            tasks.push(tokio::spawn(async move {
                let (mut sink, mut stream) = socket.split();
                let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
                let writer = tokio::spawn(async move {
                    while let Some(text) = rx.recv().await {
                        if sink.send(Message::Text(text.into())).await.is_err() {
                            break;
                        }
                    }
                });
                let mut stored = Vec::new();
                let mut n = 0usize;
                while let Some(Ok(message)) = stream.next().await {
                    let Message::Text(text) = message else {
                        continue;
                    };
                    let frame: Value = serde_json::from_str(text.as_str()).unwrap();
                    let event = frame[1].clone();
                    let id = event["id"].as_str().unwrap().to_owned();
                    let ok = |accepted: bool, message: &str| {
                        json!(["OK", id, accepted, message]).to_string()
                    };
                    // The first event is the warm-up.
                    let class = if n == 0 { 0 } else { (n - 1) % 4 };
                    n += 1;
                    match class {
                        0 => {
                            tx.send(ok(true, "")).unwrap();
                            stored.push(event.to_string());
                        }
                        1 => tx.send(ok(false, "rate-limited: slow down")).unwrap(),
                        2 if conn == 0 => stored.push(event.to_string()),
                        2 => {}
                        _ => {
                            let tx = tx.clone();
                            let reply = ok(true, "");
                            tokio::spawn(async move {
                                tokio::time::sleep(Duration::from_millis(300)).await;
                                let _ = tx.send(reply);
                            });
                            stored.push(event.to_string());
                        }
                    }
                }
                drop(tx);
                let _ = writer.await;
                stored
            }));
        }
        let mut stored = Vec::new();
        for task in tasks {
            stored.extend(task.await.unwrap());
        }
        stored
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_publisher_keeps_its_schedule_while_replies_lag() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let relay = tokio::spawn(scripted_relay(listener, 2));
        let opts = options(400.0, 1.0, 2);
        let lanes = plan(&opts).unwrap();
        let run = run(&url, lanes, &opts).await.unwrap();
        let stored = relay.await.unwrap();

        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("outcomes.jsonl");
        write_log(&log, &run).unwrap();
        let mut hist = Histogram::new(3).unwrap();
        let report = report(&run, &opts, &log, &mut hist).unwrap();
        assert!(report.connection_errors.is_empty(), "{report:#?}");
        assert_eq!((report.events, report.sent, report.unsent), (400, 400, 0));
        assert_eq!((report.accepted, report.no_reply), (200, 100));
        assert_eq!(
            report.refused,
            BTreeMap::from([("rate-limited".to_owned(), 100)])
        );
        assert_eq!((report.misrouted, report.duplicates), (0, 0));
        // Waiting for each OK would have added 300 ms every fourth event.
        assert!(report.send_lag_max_ms < 200.0, "{report:#?}");
        assert!(report.achieved_rate > 0.9 * opts.rate, "{report:#?}");
        assert!(report.ok_max_ms >= 300.0, "{report:#?}");
        // The relay's last OK came 300 ms after the last send.
        assert!(
            report.accepted_rate < 0.9 * 200.0 / opts.secs,
            "{report:#?}"
        );

        let export = stored.join("\n");
        let reconciliation = reconcile(
            std::io::BufReader::new(std::fs::File::open(&log).unwrap()),
            export.as_bytes(),
        )
        .unwrap();
        assert_eq!(reconciliation.events, 400);
        assert_eq!(
            (reconciliation.acked_stored, reconciliation.acked_missing),
            (200, 0)
        );
        assert_eq!(reconciliation.refused_stored, 0);
        assert_eq!(
            (
                reconciliation.no_reply_stored,
                reconciliation.no_reply_missing
            ),
            (50, 50)
        );
        let lines = std::fs::read_to_string(&log).unwrap();
        let seqs: Vec<u64> = lines
            .lines()
            .map(|line| serde_json::from_str::<LogLine>(line).unwrap().seq)
            .collect();
        assert_eq!(
            seqs,
            (0..400).collect::<Vec<_>>(),
            "the log is in due order"
        );
    }

    #[tokio::test]
    async fn a_relay_that_stops_reading_cannot_hold_the_run_open() {
        let opts = Options {
            drain: Duration::from_millis(200),
            ..options(50.0, 0.2, 1)
        };
        let events = plan(&opts).unwrap().remove(0).events;
        // Full socket buffers: no send completes and nothing arrives.
        let sink = futures_util::sink::unfold((), |(), _: Message| {
            std::future::pending::<Result<(), std::io::Error>>()
        });
        let stream = futures_util::stream::pending();
        let begun = std::time::Instant::now();
        let log = drive(
            Box::pin(sink),
            stream,
            events,
            0,
            Instant::now(),
            Arc::new(opts),
        )
        .await;
        assert!(begun.elapsed() < Duration::from_secs(3), "the run hung");
        let error = log.error.unwrap();
        assert!(
            error.ends_with("send stalled: the relay stopped reading"),
            "{error}"
        );
        assert_eq!(log.records.len(), 10);
        assert!(log.records.iter().all(|record| record.sent_us.is_none()));
    }

    #[test]
    fn accepted_throughput_counts_the_whole_offered_window() {
        let opts = options(100.0, 1.0, 1);
        let run_with = |reply: &dyn Fn(u64, u64) -> Reply| Run {
            records: (0..100)
                .map(|seq| {
                    let due_us = seq * 10_000;
                    Record {
                        seq,
                        conn: 0,
                        id: [seq as u8; 32],
                        kind: 1,
                        due_us,
                        sent_us: Some(due_us + 50),
                        reply: Some(reply(seq, due_us)),
                    }
                })
                .collect(),
            errors: Vec::new(),
            misrouted: 0,
            notices: 0,
            ended_us: vec![3_000_000],
        };
        let summarize = |run: &Run| {
            report(
                run,
                &opts,
                Path::new("unused"),
                &mut Histogram::new(3).unwrap(),
            )
            .unwrap()
        };
        // Ten accepted in a burst, then refusals.
        let burst = summarize(&run_with(&|seq, due_us| Reply {
            accepted: seq < 10,
            message: if seq < 10 {
                ""
            } else {
                "rate-limited: slow down"
            }
            .to_owned(),
            at_us: due_us + 1_000,
        }));
        assert!((burst.accepted_rate - 10.0).abs() < 0.1, "{burst:#?}");
        assert!((burst.achieved_rate - 100.0).abs() < 0.1, "{burst:#?}");
        // All accepted, each a second late: the backlog counts.
        let late = summarize(&run_with(&|_, due_us| Reply {
            accepted: true,
            message: String::new(),
            at_us: due_us + 1_000_000,
        }));
        assert!((late.accepted_rate - 100.0 / 1.99).abs() < 0.1, "{late:#?}");
    }

    #[test]
    fn unanswered_events_count_in_the_latency_until_the_drain_ended() {
        let opts = options(100.0, 1.0, 1);
        let run = Run {
            records: (0..100)
                .map(|seq| {
                    let due_us = seq * 10_000;
                    Record {
                        seq,
                        conn: 0,
                        id: [seq as u8; 32],
                        kind: 1,
                        due_us,
                        sent_us: Some(due_us + 50),
                        // The last two are never answered.
                        reply: (seq < 98).then(|| Reply {
                            accepted: true,
                            message: String::new(),
                            at_us: due_us + 10_000,
                        }),
                    }
                })
                .collect(),
            errors: Vec::new(),
            misrouted: 0,
            notices: 0,
            ended_us: vec![2_000_000],
        };
        let mut hist = Histogram::new(3).unwrap();
        let report = report(&run, &opts, Path::new("unused"), &mut hist).unwrap();
        assert_eq!((report.accepted, report.no_reply), (98, 2));
        assert!((report.ok_p50_ms - 10.0).abs() < 0.1, "{report:#?}");
        // 2 s less the last due time, 0.99 s.
        assert!((report.ok_p99_ms - 1010.0).abs() < 2.0, "{report:#?}");
        assert!(report.ok_max_ms >= 1020.0, "{report:#?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_repeated_final_ok_is_still_caught() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        // OK the warm-up and twenty events, the last one twice.
        let relay = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            let mut n = 0;
            while let Some(Ok(message)) = socket.next().await {
                let Message::Text(text) = message else {
                    continue;
                };
                let frame: Value = serde_json::from_str(text.as_str()).unwrap();
                let ok = json!(["OK", frame[1]["id"], true, ""]).to_string();
                for _ in 0..if n == 20 { 2 } else { 1 } {
                    socket.send(Message::Text(ok.clone().into())).await.unwrap();
                }
                n += 1;
            }
        });
        let opts = options(100.0, 0.2, 1);
        let run = run(&url, plan(&opts).unwrap(), &opts).await.unwrap();
        relay.await.unwrap();
        let mut hist = Histogram::new(3).unwrap();
        let report = report(&run, &opts, Path::new("unused"), &mut hist).unwrap();
        assert_eq!((report.accepted, report.misrouted), (20, 1), "{report:#?}");
        assert!(report.connection_errors.is_empty(), "{report:#?}");
        assert!(!report.ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_dropped_connection_fails_the_run_and_leaves_the_rest_unsent() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        // Answer the warm-up and ten events, then close.
        let relay = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            for _ in 0..11 {
                let Some(Ok(Message::Text(text))) = socket.next().await else {
                    panic!("publisher went away");
                };
                let frame: Value = serde_json::from_str(text.as_str()).unwrap();
                let ok = json!(["OK", frame[1]["id"], true, ""]).to_string();
                socket.send(Message::Text(ok.into())).await.unwrap();
            }
            use tokio_tungstenite::tungstenite::protocol::{frame::coding::CloseCode, CloseFrame};
            let frame = CloseFrame {
                code: CloseCode::Again,
                reason: "overloaded".into(),
            };
            socket.close(Some(frame)).await.unwrap();
        });
        let opts = options(200.0, 1.0, 1);
        let begun = std::time::Instant::now();
        let run = run(&url, plan(&opts).unwrap(), &opts).await.unwrap();
        relay.await.unwrap();
        assert!(begun.elapsed() < Duration::from_secs(4), "the run hung");
        let mut hist = Histogram::new(3).unwrap();
        let report = report(&run, &opts, Path::new("unused"), &mut hist).unwrap();
        assert_eq!(report.errors(), 1, "{report:#?}");
        assert_eq!(report.accepted, 10);
        assert_eq!(report.sent + report.unsent, 200);
        assert!(report.unsent > 0, "{report:#?}");
        assert!(
            report.connection_errors[0].ends_with("relay closed the connection (1013 overloaded)"),
            "{report:#?}"
        );
        assert!(!report.ok());
    }
}
