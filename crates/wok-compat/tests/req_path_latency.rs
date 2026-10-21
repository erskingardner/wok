//! REQ path latency for client traffic shapes: a REQ sent right after CLOSEs,
//! bursts of small REQs on many connections, and live fan-out to many
//! connections.
//!
//! Not regression tests: run them by hand, in release mode, to compare
//! builds. They use only the public relay API, so the same file runs against
//! older revisions.
//!
//! ```text
//! cargo test --release -p wok-compat --test req_path_latency -- --ignored --nocapture --test-threads 1
//! ```
//!
//! Each test prints one line per measurement: the sample count and
//! p50/p90/p99/max in milliseconds. "Heavy" lines run while every req worker
//! is busy with NIP-50 searches that match the whole corpus: `HEAVY` such
//! connections per worker each send one search after another.
//!
//! Knobs (environment), with defaults:
//! - `close_then_req` and `req_bursts`: `CORPUS` (200000) stored kind-1
//!   events, each containing the searched word; `HEAVY` (2).
//! - `close_then_req`: `ROUNDS` (100) times, open `CLOSE_SUBS` (50) live
//!   subscriptions, CLOSE them all, then send one `{"kinds":[1],"limit":5}`
//!   and time it to EOSE.
//! - `req_bursts`: `CONNS` (100) connections each send `BURST` (30, then
//!   60) small REQs at once, `ROUNDS` (5) times; each sample runs from its
//!   connection's first REQ to that REQ's EOSE.
//! - `fanout_many_connections`: `CONNS` (2000) connections with `SUBS` (5)
//!   live subscriptions each that every published event matches; `RATE`
//!   (200) events a second for `SECS` (10) seconds, over 10000 stored
//!   events. Prints publish-to-receipt per delivered frame, and REQ to EOSE
//!   for sequential probes alongside.
#![allow(clippy::field_reassign_with_default)]

use hdrhistogram::Histogram;
use secp256k1::{Keypair, SECP256K1};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use wok_compat::sign_event_with_key;
use wok_relay::{Config, ConnectionGuard, Outbound, OutboundFrame, RelayHandle, TransportSource};

type Rx = tokio::sync::mpsc::UnboundedReceiver<OutboundFrame>;

const SEARCHED: &str = "common";

fn knob(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A relay over `corpus` stored kind-1 events, written straight to LMDB.
/// Abuse controls and AUTH are off; every other limit is the default.
fn relay(corpus: usize) -> (tempfile::TempDir, RelayHandle) {
    let dir = tempfile::tempdir().unwrap();
    let env = wok_db::Env::open(
        dir.path(),
        wok_db::EnvOptions {
            map_size: 8 << 30,
            ..wok_db::EnvOptions::default()
        },
    )
    .unwrap();
    env.ensure_initialized().unwrap();
    let base = now() - corpus as u64;
    for chunk in (0..corpus).collect::<Vec<_>>().chunks(10_000) {
        let mut events: Vec<wok_db::EventToWrite> = chunk
            .iter()
            .map(|&i| {
                let mut id = [0xCCu8; 32];
                id[..8].copy_from_slice(&(i as u64).to_be_bytes());
                let event = json!({
                    "id": hex::encode(id),
                    "pubkey": format!("{:064x}", i % 500),
                    "created_at": base + i as u64,
                    "kind": 1,
                    "tags": [],
                    "content": format!("a {SEARCHED} note, number {i}, about topic {}", i % 97),
                    "sig": "00".repeat(64),
                });
                let parsed = wok_event::parse_and_verify_event(
                    &event,
                    &wok_event::EventLimits::default(),
                    None,
                    false,
                    false,
                )
                .unwrap();
                wok_db::EventToWrite::new(parsed.packed.into_bytes(), parsed.json)
            })
            .collect();
        let mut txn = env.begin_rw().unwrap();
        wok_db::write_events(&mut txn, &mut wok_db::NoopNegentropy, &mut events, false).unwrap();
        txn.commit().unwrap();
    }
    let mut cfg = Config::default();
    cfg.db = dir.path().to_path_buf();
    cfg.relay.auth.enabled = false;
    cfg.relay.abuse.enabled = false;
    (dir, wok_relay::start(env, cfg).unwrap())
}

async fn connect(handle: &RelayHandle) -> (ConnectionGuard, Rx) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let conn = handle
        .register_connection(TransportSource::Unix, Outbound::new(tx, 0))
        .await;
    (conn, rx)
}

async fn send(conn: &ConnectionGuard, msg: Value) {
    conn.client_message(msg.to_string()).await;
}

/// Wait for EOSE or CLOSED for `sub_id`, skipping everything else.
async fn eose(rx: &mut Rx, sub_id: &str) -> Value {
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(120), rx.recv())
            .await
            .expect("no EOSE within 120 s")
            .expect("connection closed");
        let text = frame.into_text();
        if text.starts_with("[\"EVENT\"") {
            continue;
        }
        let value: Value = serde_json::from_str(&text).unwrap();
        if value[1] == sub_id && (value[0] == "EOSE" || value[0] == "CLOSED") {
            return value;
        }
    }
}

fn percentiles(label: &str, mut samples: Vec<Duration>) {
    if samples.is_empty() {
        println!("{label:<36} n=0");
        return;
    }
    samples.sort();
    let at = |p: f64| {
        let i = ((samples.len() as f64 - 1.0) * p).round() as usize;
        samples[i].as_secs_f64() * 1e3
    };
    println!(
        "{label:<36} n={:<6} p50={:>8.2} ms  p90={:>8.2} ms  p99={:>8.2} ms  max={:>8.2} ms",
        samples.len(),
        at(0.5),
        at(0.9),
        at(0.99),
        at(1.0),
    );
}

/// Searches matching the whole corpus, one after another on `per_worker`
/// connections per req worker, until stopped.
struct Heavy {
    stop: Arc<AtomicBool>,
    /// Each task's searches: when each was sent and how long it took.
    tasks: Vec<tokio::task::JoinHandle<Vec<(Instant, Duration)>>>,
    started: Instant,
}

impl Heavy {
    async fn start(handle: &RelayHandle, per_worker: usize) -> Self {
        let workers = Config::default().relay.req_worker_threads;
        let stop = Arc::new(AtomicBool::new(false));
        let mut tasks = Vec::new();
        // Connection ids are consecutive, and a connection's req worker is
        // its id modulo the worker count: these cover every worker.
        for c in 0..workers * per_worker {
            let (conn, mut rx) = connect(handle).await;
            let stop = stop.clone();
            tasks.push(tokio::spawn(async move {
                let mut searches = Vec::new();
                while !stop.load(Ordering::Relaxed) {
                    let sub_id = format!("heavy{c}-{}", searches.len());
                    let sent = Instant::now();
                    send(
                        &conn,
                        json!(["REQ", sub_id, {"search": SEARCHED, "limit": 500}]),
                    )
                    .await;
                    let reply = eose(&mut rx, &sub_id).await;
                    assert_eq!(reply[0], "EOSE", "{reply}");
                    searches.push((sent, sent.elapsed()));
                    send(&conn, json!(["CLOSE", sub_id])).await;
                }
                searches
            }));
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        Self {
            stop,
            tasks,
            started: Instant::now(),
        }
    }

    /// Report the searches sent while the probes ran.
    async fn stop(self) {
        let secs = self.started.elapsed().as_secs_f64();
        self.stop.store(true, Ordering::Relaxed);
        let mut took = Vec::new();
        for task in self.tasks {
            took.extend(
                task.await
                    .unwrap()
                    .into_iter()
                    .filter(|(sent, _)| *sent >= self.started)
                    .map(|(_, took)| took),
            );
        }
        println!(
            "{:<36} {} sent in {secs:.1} s ({:.1}/s)",
            "  heavy searches",
            took.len(),
            took.len() as f64 / secs
        );
        percentiles("  heavy search, REQ to EOSE", took);
    }
}

async fn close_then_req_probe(handle: &RelayHandle, rounds: usize, subs: usize) -> Vec<Duration> {
    let (conn, mut rx) = connect(handle).await;
    let mut samples = Vec::new();
    for round in 0..rounds {
        for s in 0..subs {
            send(
                &conn,
                json!(["REQ", format!("live{s}"), {"kinds": [1], "limit": 0}]),
            )
            .await;
        }
        for s in 0..subs {
            eose(&mut rx, &format!("live{s}")).await;
        }
        for s in 0..subs {
            send(&conn, json!(["CLOSE", format!("live{s}")])).await;
        }
        let sub_id = format!("probe{round}");
        let start = Instant::now();
        send(&conn, json!(["REQ", sub_id, {"kinds": [1], "limit": 5}])).await;
        let reply = eose(&mut rx, &sub_id).await;
        assert_eq!(reply[0], "EOSE", "{reply}");
        samples.push(start.elapsed());
        send(&conn, json!(["CLOSE", sub_id])).await;
    }
    samples
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "benchmark; run by hand in release mode"]
async fn close_then_req() {
    let corpus = knob("CORPUS", 200_000);
    let heavy = knob("HEAVY", 2);
    let rounds = knob("ROUNDS", 100);
    let subs = knob("CLOSE_SUBS", 50);
    let (_dir, handle) = relay(corpus);
    println!(
        "close_then_req: {corpus} events; {rounds} rounds of {subs} CLOSEs then one REQ; \
         {heavy} search connections per req worker"
    );
    let samples = close_then_req_probe(&handle, rounds, subs).await;
    percentiles("close+REQ, idle", samples);
    let load = Heavy::start(&handle, heavy).await;
    let samples = close_then_req_probe(&handle, rounds, subs).await;
    percentiles("close+REQ, heavy", samples);
    load.stop().await;
    handle.request_shutdown();
}

/// Every connection sends `burst` small REQs at once, `rounds` times.
async fn bursts(handle: &RelayHandle, conns: usize, burst: usize, rounds: usize) -> Vec<Duration> {
    let barrier = Arc::new(tokio::sync::Barrier::new(conns));
    let mut tasks = Vec::new();
    for c in 0..conns {
        let (conn, mut rx) = connect(handle).await;
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            let mut samples = Vec::new();
            for round in 0..rounds {
                barrier.wait().await;
                let ids: Vec<String> = (0..burst).map(|i| format!("b{c}-{round}-{i}")).collect();
                let start = Instant::now();
                for sub_id in &ids {
                    send(&conn, json!(["REQ", sub_id, {"kinds": [1], "limit": 5}])).await;
                }
                let mut pending: std::collections::HashSet<&str> =
                    ids.iter().map(String::as_str).collect();
                while !pending.is_empty() {
                    let frame = tokio::time::timeout(Duration::from_secs(120), rx.recv())
                        .await
                        .expect("burst stalled")
                        .expect("connection closed");
                    let text = frame.into_text();
                    if text.starts_with("[\"EVENT\"") {
                        continue;
                    }
                    let value: Value = serde_json::from_str(&text).unwrap();
                    if let Some(sub_id) = value[1].as_str() {
                        if pending.remove(sub_id) {
                            assert_eq!(value[0], "EOSE", "{value}");
                            samples.push(start.elapsed());
                        }
                    }
                }
                for sub_id in &ids {
                    send(&conn, json!(["CLOSE", sub_id])).await;
                }
            }
            samples
        }));
    }
    let mut samples = Vec::new();
    for task in tasks {
        samples.extend(task.await.unwrap());
    }
    samples
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "benchmark; run by hand in release mode"]
async fn req_bursts() {
    let corpus = knob("CORPUS", 200_000);
    let heavy = knob("HEAVY", 2);
    let conns = knob("CONNS", 100);
    let rounds = knob("ROUNDS", 5);
    let sizes = match std::env::var("BURST") {
        Ok(burst) => vec![burst.parse().unwrap()],
        Err(_) => vec![30, 60],
    };
    let (_dir, handle) = relay(corpus);
    println!(
        "req_bursts: {corpus} events; {conns} connections, {rounds} rounds; \
         {heavy} search connections per req worker"
    );
    for &burst in &sizes {
        let samples = bursts(&handle, conns, burst, rounds).await;
        percentiles(&format!("burst of {burst}, idle"), samples);
    }
    let load = Heavy::start(&handle, heavy).await;
    for &burst in &sizes {
        let samples = bursts(&handle, conns, burst, rounds).await;
        percentiles(&format!("burst of {burst}, heavy"), samples);
    }
    load.stop().await;
    handle.request_shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "benchmark; run by hand in release mode"]
async fn fanout_many_connections() {
    let conns = knob("CONNS", 2000);
    let subs = knob("SUBS", 5);
    let rate = knob("RATE", 200);
    let secs = knob("SECS", 10);
    let (_dir, handle) = relay(10_000);
    println!(
        "fanout_many_connections: {conns} connections x {subs} live subscriptions, \
         {rate} events/s for {secs} s"
    );
    let epoch = Instant::now();
    let delivered = Arc::new(std::sync::Mutex::new(Histogram::<u64>::new(3).unwrap()));
    let mut subscribers = Vec::new();
    for c in 0..conns {
        let (conn, mut rx) = connect(&handle).await;
        for s in 0..subs {
            let sub_id = format!("f{c}-{s}");
            send(&conn, json!(["REQ", sub_id, {"kinds": [1], "limit": 0}])).await;
            eose(&mut rx, &sub_id).await;
        }
        let delivered = delivered.clone();
        subscribers.push((
            conn,
            tokio::spawn(async move {
                let mut histogram = Histogram::<u64>::new(3).unwrap();
                while let Some(frame) = rx.recv().await {
                    let text = frame.into_text();
                    let Some(at) = text.find("\"content\":\"t") else {
                        continue;
                    };
                    let digits: String = text[at + 12..]
                        .chars()
                        .take_while(char::is_ascii_digit)
                        .collect();
                    let sent = Duration::from_micros(digits.parse().unwrap());
                    let latency = epoch.elapsed().saturating_sub(sent);
                    histogram.record(latency.as_micros() as u64).unwrap();
                }
                delivered.lock().unwrap().add(&histogram).unwrap();
            }),
        ));
    }

    let key = Keypair::new(SECP256K1, &mut rand::thread_rng());
    let (publisher, mut publisher_rx) = connect(&handle).await;
    let total = rate * secs;
    // Each event carries the time it was sent, so it is signed as it is sent.
    let tick = Duration::from_millis(10);
    let per_tick = (rate / 100).max(1);
    let mut next = Instant::now();
    let mut sent = 0;
    let probing = {
        let handle = handle.clone();
        tokio::spawn(async move {
            let (conn, mut rx) = connect(&handle).await;
            let mut samples = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(secs as u64);
            let mut i = 0;
            while Instant::now() < deadline {
                let sub_id = format!("p{i}");
                i += 1;
                let start = Instant::now();
                send(&conn, json!(["REQ", sub_id, {"kinds": [1], "limit": 5}])).await;
                let reply = eose(&mut rx, &sub_id).await;
                assert_eq!(reply[0], "EOSE", "{reply}");
                samples.push(start.elapsed());
                send(&conn, json!(["CLOSE", sub_id])).await;
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            samples
        })
    };
    while sent < total {
        for _ in 0..per_tick {
            let at = epoch.elapsed().as_micros();
            let event = sign_event_with_key(
                json!({"created_at": now(), "kind": 1, "tags": [], "content": format!("t{at}")}),
                &key,
            );
            publisher
                .client_message(json!(["EVENT", event]).to_string())
                .await;
            sent += 1;
        }
        while publisher_rx.try_recv().is_ok() {}
        next += tick;
        tokio::time::sleep_until(next.into()).await;
    }
    let probes = probing.await.unwrap();
    // Let the last deliveries arrive, then close every subscriber, which
    // ends its task.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let mut tasks = Vec::new();
    for (conn, task) in subscribers {
        conn.close().await;
        tasks.push(task);
    }
    for task in tasks {
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("a subscriber did not finish")
            .unwrap();
    }
    handle.request_shutdown();
    let histogram = std::mem::replace(&mut *delivered.lock().unwrap(), Histogram::new(3).unwrap());
    let ms = |q: f64| histogram.value_at_quantile(q) as f64 / 1e3;
    println!(
        "{:<36} n={:<9} p50={:>8.2} ms  p90={:>8.2} ms  p99={:>8.2} ms  max={:>8.2} ms",
        "publish to receipt",
        histogram.len(),
        ms(0.5),
        ms(0.9),
        ms(0.99),
        histogram.max() as f64 / 1e3,
    );
    println!(
        "{:<36} {} of {} frames",
        "  delivered",
        histogram.len(),
        total * conns * subs
    );
    percentiles("REQ to EOSE during fan-out", probes);
}
