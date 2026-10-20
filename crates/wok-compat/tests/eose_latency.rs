//! Time from REQ to EOSE while the req monitors are busy fanning out.
//!
//! Not a regression test: run it by hand, in release mode, to compare
//! builds. It uses only the public relay API, so the same file runs against
//! older revisions.
//!
//! ```text
//! cargo test --release -p wok-compat --test eose_latency -- --ignored --nocapture
//! ```
//!
//! Knobs (environment): `FANOUT_CONNS` (default 50) connections each holding
//! `FANOUT_SUBS` (20) live `{"kinds":[1]}` subscriptions; a publisher storing
//! `PUBLISH_RATE` (1000) kind-1 events a second; `PROBES` (200) sequential
//! fetch-and-close REQs and `BURSTS` (10) bursts of `BURST` (30) REQs sent at
//! once on one connection, each a small `{"kinds":[1],"limit":5}`.
#![allow(clippy::field_reassign_with_default)]

use secp256k1::{Keypair, SECP256K1};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use wok_compat::sign_event_with_key;
use wok_relay::{Config, ConnectionGuard, Outbound, OutboundFrame, RelayHandle, TransportSource};

type Rx = tokio::sync::mpsc::UnboundedReceiver<OutboundFrame>;

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

/// Wait for EOSE (or CLOSED) for `sub_id`, skipping everything else.
async fn eose(rx: &mut Rx, sub_id: &str) -> Value {
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(60), rx.recv())
            .await
            .expect("no EOSE within 60 s")
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
    samples.sort();
    let at = |p: f64| {
        let i = ((samples.len() as f64 - 1.0) * p).round() as usize;
        samples[i].as_secs_f64() * 1e3
    };
    println!(
        "{label:<28} n={:<5} p50={:>8.2} ms  p90={:>8.2} ms  p99={:>8.2} ms  max={:>8.2} ms",
        samples.len(),
        at(0.5),
        at(0.9),
        at(0.99),
        at(1.0),
    );
}

async fn probe(handle: &RelayHandle, probes: usize, bursts: usize, burst: usize, label: &str) {
    let (conn, mut rx) = connect(handle).await;
    let mut sequential = Vec::new();
    for i in 0..probes {
        let sub_id = format!("p{i}");
        let start = Instant::now();
        send(&conn, json!(["REQ", sub_id, {"kinds": [1], "limit": 5}])).await;
        let reply = eose(&mut rx, &sub_id).await;
        assert_eq!(reply[0], "EOSE", "{reply}");
        sequential.push(start.elapsed());
        send(&conn, json!(["CLOSE", sub_id])).await;
    }
    percentiles(&format!("{label}: sequential"), sequential);

    let mut burst_samples = Vec::new();
    for b in 0..bursts {
        let start = Instant::now();
        let ids: Vec<String> = (0..burst).map(|i| format!("b{b}-{i}")).collect();
        for sub_id in &ids {
            send(&conn, json!(["REQ", sub_id, {"kinds": [1], "limit": 5}])).await;
        }
        let mut pending: std::collections::HashSet<String> = ids.iter().cloned().collect();
        while !pending.is_empty() {
            let frame = tokio::time::timeout(Duration::from_secs(60), rx.recv())
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
                    burst_samples.push(start.elapsed());
                }
            }
        }
        for sub_id in &ids {
            send(&conn, json!(["CLOSE", sub_id])).await;
        }
    }
    percentiles(&format!("{label}: burst of {burst}"), burst_samples);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "benchmark; run by hand in release mode"]
async fn eose_latency_under_monitor_fanout() {
    let fanout_conns = knob("FANOUT_CONNS", 50);
    let fanout_subs = knob("FANOUT_SUBS", 20);
    let rate = knob("PUBLISH_RATE", 1000);
    let probes = knob("PROBES", 200);
    let bursts = knob("BURSTS", 10);
    let burst = knob("BURST", 30);

    let (dir, env) = wok_compat::temp_db();
    let mut cfg = Config::default();
    cfg.db = dir.path().to_path_buf();
    cfg.relay.auth.enabled = false;
    cfg.relay.abuse.enabled = false;
    // Room for the burst's scans; the default (8) would refuse part of it.
    cfg.relay.abuse.max_concurrent_historical_queries = burst.max(8);
    let handle = wok_relay::start(env, cfg).unwrap();

    // Some history for the probes to read.
    let (publisher, mut publisher_rx) = connect(&handle).await;
    let key = Keypair::new(SECP256K1, &mut rand::thread_rng());
    for i in 0..100 {
        let event = sign_event_with_key(
            json!({"created_at": now(), "kind": 1, "tags": [], "content": format!("seed {i}")}),
            &key,
        );
        send(&publisher, json!(["EVENT", event])).await;
        publisher_rx.recv().await.unwrap();
    }

    println!(
        "fan-out: {fanout_conns} connections x {fanout_subs} subscriptions, \
         {rate} stored events/s; probes: {probes} sequential, {bursts} bursts of {burst}"
    );
    probe(&handle, probes, bursts, burst, "idle").await;

    // Live subscribers, drained so their queues stay small.
    let mut subscribers = Vec::new();
    for c in 0..fanout_conns {
        let (conn, mut rx) = connect(&handle).await;
        for s in 0..fanout_subs {
            let sub_id = format!("f{c}-{s}");
            send(&conn, json!(["REQ", sub_id, {"kinds": [1], "limit": 0}])).await;
            eose(&mut rx, &sub_id).await;
        }
        subscribers.push(conn);
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
    }

    // Pre-signed so signing does not compete with the relay; enough for five
    // minutes of load.
    let events: Vec<String> = (0..rate * 300)
        .map(|i| {
            let key = Keypair::new(SECP256K1, &mut rand::thread_rng());
            let event = sign_event_with_key(
                json!({"created_at": now(), "kind": 1, "tags": [], "content": format!("load {i}")}),
                &key,
            );
            json!(["EVENT", event]).to_string()
        })
        .collect();
    let stop = Arc::new(AtomicBool::new(false));
    let publishing = {
        let stop = stop.clone();
        tokio::spawn(async move {
            let tick = Duration::from_millis(10);
            let per_tick = (rate / 100).max(1);
            let mut next = Instant::now();
            let mut events = events.into_iter();
            while !stop.load(Ordering::Relaxed) {
                for _ in 0..per_tick {
                    let Some(event) = events.next() else {
                        panic!("load ran out before the probes finished");
                    };
                    publisher.client_message(event).await;
                }
                while publisher_rx.try_recv().is_ok() {}
                next += tick;
                tokio::time::sleep_until(next.into()).await;
            }
        })
    };
    tokio::time::sleep(Duration::from_secs(2)).await;
    probe(&handle, probes, bursts, burst, "fan-out").await;
    stop.store(true, Ordering::Relaxed);
    publishing.await.unwrap();
    drop(subscribers);
    handle.request_shutdown();
}
