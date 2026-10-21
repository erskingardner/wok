//! `--scenario ws_transport`: what WebSocket connections cost the relay.
//!
//! Every phase runs twice against a fresh relay process, once with clients
//! that offer permessage-deflate and once with clients that do not:
//!
//! - **memory**: RSS per connection after opening `--connections` sockets
//!   (cold), after each fetched a small history (warm), and optionally after
//!   `--transport-idle-secs` of silence (idle) and for a second wave of as
//!   many warmed connections opened beside the idle ones;
//! - **burst**: `--bursts` sequential history bursts of `--burst-events`
//!   events on one connection: time to EOSE, bytes on the wire, relay CPU and,
//!   on Linux, relay write syscalls per burst;
//! - **fanout**: `--fanout-subscribers` live subscribers receive
//!   `--fanout-events` publications: relay CPU per delivered event;
//! - **churn**: `--churn-connections` connect, fetch, close cycles (mobile
//!   reconnects): cycles per second and relay CPU per cycle.
//!
//! A **codec** phase first compresses the corpus in process, as EVENT frames
//! grouped by kind and as EOSE frames, at each deflate level: CPU per message
//! and compressed size, with context takeover and from a fresh compressor.
//!
//! The relay is measured from outside (`/proc` on Linux, `ps` elsewhere), so
//! the numbers include everything a connection costs, not only the codec.

use crate::clients::ws_handshake;
use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::io::BufRead;
use std::net::SocketAddr;
use std::path::Path;
use std::process::Child;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wok_ws::frame::{
    DeflateCtx, InflateCtx, MessageKind, Role, WsEncoder, WsEvent, WsParser, OP_CLOSE, OP_PONG,
};

const MAX_MESSAGE: usize = 32 << 20;
/// Connections opened or warmed at once.
const BATCH: usize = 64;
/// Concurrent clients in the churn phase.
const CHURN_WORKERS: usize = 16;
/// Events in each warm and churn fetch.
const SMALL_FETCH: u64 = 10;
/// Frames per codec group, and the levels swept.
const CODEC_FRAMES: usize = 2_000;
const CODEC_LEVELS: [u32; 6] = [1, 2, 3, 4, 5, 6];

#[derive(Clone, Debug, Serialize)]
pub struct TransportOptions {
    pub connections: usize,
    pub idle_secs: u64,
    pub burst_events: u64,
    pub bursts: usize,
    pub fanout_subscribers: usize,
    pub fanout_events: u64,
    pub churn_connections: usize,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct TransportReport {
    pub options: Option<TransportOptions>,
    /// Kind-1 events in the imported corpus (the burst filter).
    pub kind1_events: u64,
    pub modes: Vec<ModeReport>,
    /// Whether relay write syscalls could be read (Linux `/proc/<pid>/io`).
    pub syscalls_measured: bool,
    pub codec: Vec<CodecRow>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CodecRow {
    pub frames: String,
    pub count: usize,
    pub avg_bytes: usize,
    pub level: u32,
    pub ns_per_frame: f64,
    /// Compressed / original with context takeover (a burst or live stream).
    pub ratio: f64,
    /// Compressed / original from a fresh compressor (a connection's first
    /// message, or its first after the compressor was released).
    pub fresh_ratio: f64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ModeReport {
    pub offer_deflate: bool,
    /// Connections that negotiated deflate, of those opened in this mode.
    pub negotiated: usize,
    pub opened: usize,
    pub base_rss_kb: u64,
    pub cold_kb_per_conn: f64,
    pub warm_kb_per_conn: f64,
    pub idle_kb_per_conn: Option<f64>,
    /// RSS a second wave of warmed connections adds per connection while the
    /// first wave stays idle.
    pub second_wave_kb_per_conn: Option<f64>,
    pub burst_events: u64,
    pub burst_first_p50_ms: f64,
    pub burst_p50_ms: f64,
    pub burst_p99_ms: f64,
    pub burst_wire_bytes: f64,
    pub burst_cpu_ms: f64,
    pub burst_write_syscalls: Option<f64>,
    pub fanout_deliveries: u64,
    pub fanout_secs: f64,
    pub fanout_cpu_us_per_delivery: f64,
    pub fanout_wire_bytes_per_delivery: f64,
    pub churn_cycles: u64,
    pub churn_per_s: f64,
    pub churn_cpu_us_per_cycle: f64,
    pub errors: Vec<String>,
}

impl TransportReport {
    pub fn ok(&self) -> bool {
        self.modes.len() == 2 && self.modes.iter().all(|mode| mode.errors.is_empty())
    }

    pub fn errors(&self) -> u64 {
        self.modes.iter().map(|mode| mode.errors.len() as u64).sum()
    }
}

pub struct RunInput<'a> {
    pub bin: &'a Path,
    pub dbdir: &'a Path,
    pub corpus: &'a Path,
    /// Kind-1 events in the corpus, and its newest `created_at`. Fetches stop
    /// there, so both modes fetch the same events whatever fan-out stored.
    pub kind1_events: u64,
    pub newest: u64,
    /// Fan-out notes for both modes, all newer than the corpus.
    pub fanout: Vec<Value>,
    pub opts: TransportOptions,
}

/// Import the corpus once, then run every phase per mode on a fresh relay.
pub fn run(rt: &tokio::runtime::Runtime, input: RunInput<'_>) -> Result<TransportReport> {
    anyhow::ensure!(
        crate::import_with(input.bin, input.dbdir, input.corpus, false),
        "import of {} failed",
        input.corpus.display()
    );
    let mut report = TransportReport {
        options: Some(input.opts.clone()),
        kind1_events: input.kind1_events,
        codec: codec_sweep(input.corpus)?,
        ..TransportReport::default()
    };
    for (round, offer_deflate) in [false, true].into_iter().enumerate() {
        let port = crate::free_port();
        let mut child = crate::spawn_relay(input.bin, input.dbdir, port)?;
        let url = format!("ws://127.0.0.1:{port}");
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let mode = wait_listening(&mut child, addr).and_then(|()| {
            // Each round publishes its own fan-out events: the relay already
            // stores the previous round's.
            let n = input.opts.fanout_events as usize;
            let fanout = &input.fanout
                [(round * n).min(input.fanout.len())..((round + 1) * n).min(input.fanout.len())];
            rt.block_on(run_mode(
                child.id(),
                addr,
                offer_deflate,
                &input.opts,
                (input.kind1_events, input.newest),
                fanout,
            ))
        });
        crate::stop_relay(&mut child, &url);
        let mode = mode?;
        report.syscalls_measured = mode.burst_write_syscalls.is_some();
        report.modes.push(mode);
    }
    Ok(report)
}

/// Compress EVENT frames of the corpus (by kind and all together) and EOSE
/// frames with wok-ws's deflater at each level.
fn codec_sweep(corpus: &Path) -> Result<Vec<CodecRow>> {
    let mut groups: Vec<(String, Vec<String>)> = ["kind 0", "kind 1", "kind 7", "all"]
        .into_iter()
        .map(|name| (name.to_owned(), Vec::new()))
        .collect();
    for line in std::io::BufReader::new(std::fs::File::open(corpus)?).lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let kind = serde_json::from_str::<Value>(line)?["kind"].as_u64();
        let frame = format!("[\"EVENT\",\"sub-{:04}\",{line}]", groups[3].1.len() % 10);
        let group = match kind {
            Some(0) => Some(0),
            Some(1) => Some(1),
            Some(7) => Some(2),
            _ => None,
        };
        for index in group.into_iter().chain([3]) {
            if groups[index].1.len() < CODEC_FRAMES {
                groups[index].1.push(frame.clone());
            }
        }
    }
    // Clients name subscriptions with short random strings.
    let mut x = 0x2545_f491_4f6c_dd1du64;
    let eose = (0..CODEC_FRAMES)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            format!("[\"EOSE\",\"{:016x}\"]", x)
        })
        .collect();
    groups.push(("EOSE".to_owned(), eose));
    let mut rows = Vec::new();
    for (name, frames) in groups.iter().filter(|(_, frames)| !frames.is_empty()) {
        let original: usize = frames.iter().map(String::len).sum();
        for level in CODEC_LEVELS {
            let mut best = f64::MAX;
            let mut compressed = 0;
            for _ in 0..3 {
                let mut deflater = DeflateCtx::with_level(true, level);
                let started = Instant::now();
                compressed = 0;
                for frame in frames {
                    compressed += deflater.compress(frame.as_bytes())?.len();
                }
                best = best.min(started.elapsed().as_nanos() as f64 / frames.len() as f64);
            }
            let fresh = frames.iter().take(200).try_fold(0, |sum, frame| {
                DeflateCtx::with_level(true, level)
                    .compress(frame.as_bytes())
                    .map(|out| sum + out.len())
            })?;
            let fresh_original: usize = frames.iter().take(200).map(String::len).sum();
            rows.push(CodecRow {
                frames: name.clone(),
                count: frames.len(),
                avg_bytes: original / frames.len(),
                level,
                ns_per_frame: best,
                ratio: compressed as f64 / original as f64,
                fresh_ratio: fresh as f64 / fresh_original as f64,
            });
        }
    }
    Ok(rows)
}

fn wait_listening(child: &mut Child, addr: SocketAddr) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            anyhow::bail!("relay exited during startup ({status})");
        }
        if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
            return Ok(());
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "relay did not listen within 30 s"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

async fn run_mode(
    pid: u32,
    addr: SocketAddr,
    deflate: bool,
    opts: &TransportOptions,
    (kind1_events, newest): (u64, u64),
    fanout: &[Value],
) -> Result<ModeReport> {
    let mut report = ModeReport {
        offer_deflate: deflate,
        ..ModeReport::default()
    };
    let small = json!({"kinds": [1], "until": newest, "limit": SMALL_FETCH});
    let expect_small = SMALL_FETCH.min(kind1_events) as usize;
    // Warm the relay (threads, LMDB pages, allocator) before the baseline.
    {
        let mut conn = Conn::open(addr, deflate).await?;
        for i in 0..3 {
            conn.fetch(&format!("warm-{i}"), &small).await?;
        }
        conn.close().await;
    }
    settle().await;

    // Memory: cold, warm, idle, and a second wave beside the idle first.
    let base = ProcSample::read(pid)?;
    report.base_rss_kb = base.rss_kb;
    let conns = open_all(addr, deflate, opts.connections, &mut report.errors).await?;
    report.opened = conns.len();
    report.negotiated = conns.iter().filter(|conn| conn.deflate).count();
    if deflate && report.negotiated != report.opened {
        report.errors.push(format!(
            "{} of {} connections negotiated deflate",
            report.negotiated, report.opened
        ));
    }
    let per_conn = |sample: &ProcSample, from: u64, n: usize| {
        (sample.rss_kb as f64 - from as f64) / n.max(1) as f64
    };
    settle().await;
    report.cold_kb_per_conn = per_conn(&ProcSample::read(pid)?, base.rss_kb, report.opened);
    let mut warmed = warm_all(conns, &small, expect_small, &mut report.errors).await?;
    settle().await;
    report.warm_kb_per_conn = per_conn(&ProcSample::read(pid)?, base.rss_kb, report.opened);
    if opts.idle_secs > 0 {
        let until = tokio::time::Instant::now() + Duration::from_secs(opts.idle_secs);
        let mut holders = tokio::task::JoinSet::new();
        for mut conn in warmed.drain(..) {
            holders.spawn(async move {
                // Answer pings; nothing else should arrive while idle.
                let got = tokio::time::timeout_at(until, conn.next_text()).await;
                (conn, got)
            });
        }
        while let Some(joined) = holders.join_next().await {
            let (conn, got) = joined?;
            if let Ok(got) = got {
                let what = got.map(|m| String::from_utf8_lossy(&m).into_owned());
                report.errors.push(format!("idle connection got {what:?}"));
            }
            warmed.push(conn);
        }
        let idle = ProcSample::read(pid)?;
        report.idle_kb_per_conn = Some(per_conn(&idle, base.rss_kb, report.opened));
        // What new active connections add while the first wave stays idle:
        // memory an idle connection gave back is reused here even when the
        // allocator kept it from the OS (and so from the idle sample).
        let wave = open_all(addr, deflate, opts.connections, &mut report.errors).await?;
        let wave = warm_all(wave, &small, expect_small, &mut report.errors).await?;
        settle().await;
        report.second_wave_kb_per_conn =
            Some(per_conn(&ProcSample::read(pid)?, idle.rss_kb, wave.len()));
        for conn in wave {
            conn.close().await;
        }
    }
    for conn in warmed {
        conn.close().await;
    }
    settle().await;

    // Bursts on one connection.
    let burst = json!({"kinds": [1], "until": newest, "limit": opts.burst_events});
    let expect_burst = opts.burst_events.min(kind1_events) as usize;
    report.burst_events = expect_burst as u64;
    let mut conn = Conn::open(addr, deflate).await?;
    for i in 0..3 {
        conn.fetch(&format!("bw{i}"), &burst).await?;
    }
    let mut times = Vec::with_capacity(opts.bursts);
    let mut firsts = Vec::with_capacity(opts.bursts);
    let wire_before = conn.wire_in;
    let before = ProcSample::read(pid)?;
    for i in 0..opts.bursts {
        let started = Instant::now();
        let got = conn.fetch(&format!("b{i}"), &burst).await?;
        times.push(started.elapsed().as_secs_f64() * 1000.0);
        if let Some(first) = conn.first_event {
            firsts.push((first - started).as_secs_f64() * 1000.0);
        }
        if got != expect_burst {
            report
                .errors
                .push(format!("burst returned {got} of {expect_burst} events"));
        }
    }
    let after = ProcSample::read(pid)?;
    let bursts = opts.bursts.max(1) as f64;
    report.burst_wire_bytes = (conn.wire_in - wire_before) as f64 / bursts;
    report.burst_cpu_ms = (after.cpu_ms - before.cpu_ms) / bursts;
    report.burst_write_syscalls = after
        .write_syscalls
        .zip(before.write_syscalls)
        .map(|(a, b)| a.saturating_sub(b) as f64 / bursts);
    times.sort_by(f64::total_cmp);
    firsts.sort_by(f64::total_cmp);
    report.burst_first_p50_ms = percentile(&firsts, 0.50);
    report.burst_p50_ms = percentile(&times, 0.50);
    report.burst_p99_ms = percentile(&times, 0.99);
    conn.close().await;

    fanout_phase(pid, addr, deflate, opts, fanout, &mut report).await?;
    churn_phase(pid, addr, deflate, opts, &small, expect_small, &mut report).await?;
    Ok(report)
}

/// Open `n` connections, a batch at a time; stops at the first failure.
async fn open_all(
    addr: SocketAddr,
    deflate: bool,
    n: usize,
    errors: &mut Vec<String>,
) -> Result<Vec<Conn>> {
    let mut conns = Vec::with_capacity(n);
    while conns.len() < n {
        let mut batch = tokio::task::JoinSet::new();
        for _ in 0..BATCH.min(n - conns.len()) {
            batch.spawn(Conn::open(addr, deflate));
        }
        let mut failed = false;
        while let Some(joined) = batch.join_next().await {
            match joined? {
                Ok(conn) => conns.push(conn),
                Err(e) => {
                    errors.push(format!("open: {e}"));
                    failed = true;
                }
            }
        }
        if failed {
            break;
        }
    }
    Ok(conns)
}

/// Have every connection fetch `filter` (REQ, EOSE, CLOSE), a batch at a time.
async fn warm_all(
    conns: Vec<Conn>,
    filter: &Value,
    expect: usize,
    errors: &mut Vec<String>,
) -> Result<Vec<Conn>> {
    let mut warmed = Vec::with_capacity(conns.len());
    let mut pending = conns.into_iter();
    loop {
        let mut batch = tokio::task::JoinSet::new();
        for (i, mut conn) in pending.by_ref().take(BATCH).enumerate() {
            let filter = filter.clone();
            batch.spawn(async move {
                let got = conn.fetch(&format!("w{i}"), &filter).await;
                (conn, got)
            });
        }
        if batch.is_empty() {
            return Ok(warmed);
        }
        while let Some(joined) = batch.join_next().await {
            let (conn, got) = joined?;
            match got {
                Ok(n) if n == expect => {}
                Ok(n) => errors.push(format!("warm fetch returned {n} of {expect} events")),
                Err(e) => errors.push(format!("warm fetch: {e}")),
            }
            warmed.push(conn);
        }
    }
}

async fn fanout_phase(
    pid: u32,
    addr: SocketAddr,
    deflate: bool,
    opts: &TransportOptions,
    events: &[Value],
    report: &mut ModeReport,
) -> Result<()> {
    if opts.fanout_subscribers == 0 || events.is_empty() {
        return Ok(());
    }
    let live = json!({"kinds": [1], "limit": 0});
    let mut subscribers = Vec::with_capacity(opts.fanout_subscribers);
    for _ in 0..opts.fanout_subscribers {
        let mut conn = Conn::open(addr, deflate).await?;
        conn.subscribe("live", &live).await?;
        subscribers.push(conn);
    }
    let expected = events.len();
    let ids: Vec<String> = events
        .iter()
        .map(|event| event["id"].as_str().unwrap_or_default().to_owned())
        .collect();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let mut readers = tokio::task::JoinSet::new();
    for mut conn in subscribers {
        readers.spawn(async move {
            let before = conn.wire_in;
            let mut got = 0usize;
            while got < expected {
                match tokio::time::timeout_at(deadline, conn.next_text()).await {
                    Ok(Ok(msg)) if msg.starts_with(b"[\"EVENT\",\"live\",") => got += 1,
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => return Err(e),
                    Err(_) => break,
                }
            }
            let wire = conn.wire_in - before;
            conn.close().await;
            Ok((got, wire))
        });
    }
    // The publisher never negotiates deflate, so only subscribers differ.
    let mut publisher = Conn::open(addr, false).await?;
    let started = Instant::now();
    let before = ProcSample::read(pid)?;
    for (event, id) in events.iter().zip(&ids) {
        publisher.send(&json!(["EVENT", event]).to_string()).await?;
        let ok = loop {
            let msg = publisher.next_text().await?;
            let value: Value = serde_json::from_slice(&msg).unwrap_or(Value::Null);
            if value[0] == "OK" && value[1] == id.as_str() {
                break value[2] == true;
            }
        };
        if !ok {
            report
                .errors
                .push(format!("fan-out publication {id} refused"));
        }
    }
    let mut deliveries = 0u64;
    let mut wire = 0u64;
    while let Some(joined) = readers.join_next().await {
        match joined? {
            Ok((got, bytes)) => {
                deliveries += got as u64;
                wire += bytes;
                if got != expected {
                    report
                        .errors
                        .push(format!("subscriber received {got} of {expected} events"));
                }
            }
            Err(e) => report.errors.push(format!("subscriber: {e}")),
        }
    }
    let elapsed = started.elapsed();
    let after = ProcSample::read(pid)?;
    publisher.close().await;
    report.fanout_deliveries = deliveries;
    report.fanout_secs = elapsed.as_secs_f64();
    report.fanout_cpu_us_per_delivery =
        (after.cpu_ms - before.cpu_ms) * 1000.0 / deliveries.max(1) as f64;
    report.fanout_wire_bytes_per_delivery = wire as f64 / deliveries.max(1) as f64;
    Ok(())
}

async fn churn_phase(
    pid: u32,
    addr: SocketAddr,
    deflate: bool,
    opts: &TransportOptions,
    filter: &Value,
    expect: usize,
    report: &mut ModeReport,
) -> Result<()> {
    if opts.churn_connections == 0 {
        return Ok(());
    }
    let next = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let total = opts.churn_connections;
    let started = Instant::now();
    let before = ProcSample::read(pid)?;
    let mut workers = tokio::task::JoinSet::new();
    for _ in 0..CHURN_WORKERS {
        let next = next.clone();
        let filter = filter.clone();
        workers.spawn(async move {
            let mut errors = Vec::new();
            let mut cycles = 0u64;
            while next.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < total {
                let cycle = async {
                    let mut conn = Conn::open(addr, deflate).await?;
                    let got = conn.fetch("c", &filter).await?;
                    conn.close().await;
                    anyhow::ensure!(got == expect, "churn fetch returned {got} of {expect}");
                    Ok(())
                };
                match cycle.await {
                    Ok(()) => cycles += 1,
                    Err(e) => errors.push(format!("churn: {e}")),
                }
            }
            (cycles, errors)
        });
    }
    let mut cycles = 0;
    while let Some(joined) = workers.join_next().await {
        let (n, errors) = joined?;
        cycles += n;
        report.errors.extend(errors.into_iter().take(3));
    }
    let elapsed = started.elapsed().as_secs_f64();
    let after = ProcSample::read(pid)?;
    report.churn_cycles = cycles;
    report.churn_per_s = cycles as f64 / elapsed.max(f64::EPSILON);
    report.churn_cpu_us_per_cycle = (after.cpu_ms - before.cpu_ms) * 1000.0 / cycles.max(1) as f64;
    Ok(())
}

fn percentile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = ((sorted.len() as f64 * q).ceil() as usize).clamp(1, sorted.len());
    sorted[rank - 1]
}

/// Let the relay finish handling what the clients just did before sampling.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(750)).await;
}

/// A client connection driven directly with wok-ws's codec in client mode.
struct Conn {
    stream: tokio::net::TcpStream,
    parser: WsParser,
    encoder: WsEncoder,
    deflate: bool,
    pending: VecDeque<WsEvent>,
    buf: Vec<u8>,
    /// Raw bytes read from the socket after the handshake.
    wire_in: u64,
    /// When the last subscription's first EVENT arrived.
    first_event: Option<Instant>,
}

impl Conn {
    async fn open(addr: SocketAddr, offer_deflate: bool) -> Result<Self> {
        let (stream, rest, deflate) = ws_handshake(addr, None, offer_deflate, true)
            .await
            .map_err(|e| anyhow::anyhow!("handshake: {e}"))?;
        let mut parser = WsParser::with_role(
            MAX_MESSAGE,
            deflate.then(|| InflateCtx::new(true)),
            Role::Client,
        );
        let encoder = WsEncoder::with_role(deflate.then(|| DeflateCtx::new(true)), Role::Client);
        let pending = parser.feed(&rest)?.into();
        Ok(Self {
            stream,
            parser,
            encoder,
            deflate,
            pending,
            buf: vec![0; 16 * 1024],
            wire_in: rest.len() as u64,
            first_event: None,
        })
    }

    async fn send(&mut self, text: &str) -> Result<()> {
        let frame = self
            .encoder
            .encode_message(MessageKind::Text, text.as_bytes())?;
        self.stream.write_all(&frame).await?;
        Ok(())
    }

    /// The next text message, answering pings on the way.
    async fn next_text(&mut self) -> Result<Vec<u8>> {
        loop {
            while let Some(event) = self.pending.pop_front() {
                match event {
                    WsEvent::Message(_, body) => return Ok(body),
                    WsEvent::Ping(payload) => {
                        let pong = self.encoder.encode_control(OP_PONG, &payload);
                        self.stream.write_all(&pong).await?;
                    }
                    WsEvent::Pong(_) => {}
                    WsEvent::Close(_) => anyhow::bail!("relay sent a close frame"),
                }
            }
            let n = self.stream.read(&mut self.buf).await?;
            anyhow::ensure!(n > 0, "relay closed the connection");
            self.wire_in += n as u64;
            let events = self.parser.feed(&self.buf[..n])?;
            self.pending.extend(events);
        }
    }

    /// REQ, then count this subscription's EVENTs until its EOSE.
    async fn subscribe(&mut self, sid: &str, filter: &Value) -> Result<usize> {
        self.send(&json!(["REQ", sid, filter]).to_string()).await?;
        let event_prefix = format!("[\"EVENT\",\"{sid}\",");
        let eose = format!("[\"EOSE\",\"{sid}\"]");
        let mut events = 0;
        self.first_event = None;
        loop {
            let msg = self.next_text().await?;
            if msg.starts_with(event_prefix.as_bytes()) {
                self.first_event.get_or_insert_with(Instant::now);
                events += 1;
            } else if msg == eose.as_bytes() {
                return Ok(events);
            } else if msg.starts_with(b"[\"CLOSED\"") || msg.starts_with(b"[\"NOTICE\"") {
                anyhow::bail!("{}", String::from_utf8_lossy(&msg));
            }
        }
    }

    /// REQ → EOSE → CLOSE.
    async fn fetch(&mut self, sid: &str, filter: &Value) -> Result<usize> {
        let events = self.subscribe(sid, filter).await?;
        self.send(&json!(["CLOSE", sid]).to_string()).await?;
        Ok(events)
    }

    async fn close(mut self) {
        let frame = self.encoder.encode_control(OP_CLOSE, &[]);
        let _ = self.stream.write_all(&frame).await;
        let _ = self.stream.shutdown().await;
    }
}

/// Relay process counters read from outside the process.
struct ProcSample {
    rss_kb: u64,
    cpu_ms: f64,
    write_syscalls: Option<u64>,
}

impl ProcSample {
    #[cfg(target_os = "linux")]
    fn read(pid: u32) -> Result<Self> {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
        let rss_kb = status
            .lines()
            .find_map(|line| line.strip_prefix("VmRSS:"))
            .and_then(|v| v.split_whitespace().next()?.parse().ok())
            .context("VmRSS missing")?;
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
        // Fields after the parenthesised command: utime and stime are the
        // 12th and 13th, in clock ticks (USER_HZ, 100 on Linux).
        let fields: Vec<&str> = stat
            .rsplit_once(')')
            .context("malformed stat")?
            .1
            .split_whitespace()
            .collect();
        let ticks: u64 = fields[11].parse::<u64>()? + fields[12].parse::<u64>()?;
        let write_syscalls = std::fs::read_to_string(format!("/proc/{pid}/io"))
            .ok()
            .and_then(|io| {
                io.lines()
                    .find_map(|line| line.strip_prefix("syscw:"))
                    .and_then(|v| v.trim().parse().ok())
            });
        Ok(Self {
            rss_kb,
            cpu_ms: ticks as f64 * 10.0,
            write_syscalls,
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn read(pid: u32) -> Result<Self> {
        let out = std::process::Command::new("ps")
            .args(["-o", "rss=,time=", "-p", &pid.to_string()])
            .output()?;
        let text = String::from_utf8_lossy(&out.stdout);
        let mut fields = text.split_whitespace();
        let rss_kb = fields.next().context("ps rss")?.parse()?;
        // [[hh:]mm:]ss.cc
        let cpu_secs = fields
            .next()
            .context("ps time")?
            .split(':')
            .try_fold(0.0, |acc, part| part.parse::<f64>().map(|v| acc * 60.0 + v))?;
        Ok(Self {
            rss_kb,
            cpu_ms: cpu_secs * 1000.0,
            write_syscalls: None,
        })
    }
}

pub fn render_markdown(report: &TransportReport, relay: &str, repetition: u32) -> String {
    let Some(opts) = &report.options else {
        return String::new();
    };
    let mut s = format!(
        "\n## ws_transport: {relay} r{repetition}\n\n{} connections (idle {} s), {} bursts of {} events ({} kind-1 events stored), {} fan-out subscribers × {} events, {} churn cycles. KB/conn is relay RSS growth over the baseline divided by open connections.\n\n",
        opts.connections,
        opts.idle_secs,
        opts.bursts,
        opts.burst_events,
        report.kind1_events,
        opts.fanout_subscribers,
        opts.fanout_events,
        opts.churn_connections,
    );
    s.push_str("| deflate | negotiated | KB/conn cold | KB/conn warm | KB/conn idle | KB/conn 2nd wave | burst first EVENT p50 ms | burst EOSE p50 ms | burst EOSE p99 ms | burst wire KB | burst CPU ms | burst write syscalls | fan-out CPU µs/delivery | fan-out wire B/delivery | churn cycles/s | churn CPU µs/cycle | errors |\n|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|\n");
    for mode in &report.modes {
        s.push_str(&format!(
            "| {} | {}/{} | {:.1} | {:.1} | {} | {} | {:.2} | {:.2} | {:.2} | {:.1} | {:.2} | {} | {:.1} | {:.0} | {:.0} | {:.0} | {} |\n",
            if mode.offer_deflate { "offered" } else { "off" },
            mode.negotiated,
            mode.opened,
            mode.cold_kb_per_conn,
            mode.warm_kb_per_conn,
            mode.idle_kb_per_conn
                .map_or_else(|| "—".into(), |v| format!("{v:.1}")),
            mode.second_wave_kb_per_conn
                .map_or_else(|| "—".into(), |v| format!("{v:.1}")),
            mode.burst_first_p50_ms,
            mode.burst_p50_ms,
            mode.burst_p99_ms,
            mode.burst_wire_bytes / 1024.0,
            mode.burst_cpu_ms,
            mode.burst_write_syscalls
                .map_or_else(|| "—".into(), |v| format!("{v:.0}")),
            mode.fanout_cpu_us_per_delivery,
            mode.fanout_wire_bytes_per_delivery,
            mode.churn_per_s,
            mode.churn_cpu_us_per_cycle,
            if mode.errors.is_empty() {
                "0".into()
            } else {
                format!("{}: {}", mode.errors.len(), mode.errors[0])
            },
        ));
    }
    if !report.codec.is_empty() {
        s.push_str("\nCodec (in process, wok-ws deflater). Ratio is compressed / original bytes; takeover is a burst or live stream on one connection, fresh is a connection's first message.\n\n| frames | count | avg bytes | level | µs/frame | ratio (takeover) | ratio (fresh) |\n|---|---:|---:|---:|---:|---:|---:|\n");
        for row in &report.codec {
            s.push_str(&format!(
                "| {} | {} | {} | {} | {:.2} | {:.3} | {:.3} |\n",
                row.frames,
                row.count,
                row.avg_bytes,
                row.level,
                row.ns_per_frame / 1000.0,
                row.ratio,
                row.fresh_ratio,
            ));
        }
    }
    s
}
