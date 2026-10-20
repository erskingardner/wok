//! REQ lifecycle: a subscription is live before its history is scanned.
//!
//! Each REQ is registered with the live monitor before the req worker takes
//! its history snapshot. Matches that arrive meanwhile are held and follow
//! EOSE, stored ones deduplicated against the history. These tests publish
//! from the subscribing connection right after its REQ, so every event is
//! causally after the REQ and must be delivered, however long the history
//! scan takes.
#![allow(clippy::field_reassign_with_default)]

use secp256k1::{Keypair, SECP256K1};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use wok_compat::sign_event_with_key;
use wok_db::{Env, EventToWrite};
use wok_relay::{Config, ConnectionGuard, Outbound, OutboundFrame, RelayHandle, TransportSource};

type Rx = tokio::sync::mpsc::UnboundedReceiver<OutboundFrame>;

/// Stored history big enough that sending it overlaps the publishing below.
const HISTORY: usize = 20_000;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// `HISTORY` old kind-1 events tagged `t=hist`, written straight to the
/// database. Their signatures are not checked on the way in or out.
fn seed_history(env: &Env) {
    let base = now() - 10_000_000;
    let mut events: Vec<_> = (0..HISTORY as u64)
        .map(|i| {
            let mut id = [0xAAu8; 32];
            id[..8].copy_from_slice(&i.to_be_bytes());
            let event = json!({
                "id": hex::encode(id),
                "pubkey": "11".repeat(32),
                "created_at": base + i,
                "kind": 1,
                "tags": [["t", "hist"]],
                "content": format!("history {i}"),
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
            EventToWrite::new(parsed.packed.into_bytes(), parsed.json)
        })
        .collect();
    let mut txn = env.begin_rw().unwrap();
    wok_db::write_events(&mut txn, &mut wok_db::NoopNegentropy, &mut events, false).unwrap();
    txn.commit().unwrap();
}

struct Relay {
    handle: RelayHandle,
    _dir: tempfile::TempDir,
}

impl Relay {
    fn new(history: bool, configure: impl FnOnce(&mut Config)) -> Self {
        let (dir, env) = wok_compat::temp_db();
        if history {
            seed_history(&env);
        }
        let mut cfg = Config::default();
        cfg.db = dir.path().to_path_buf();
        cfg.relay.auth.enabled = false;
        cfg.relay.abuse.enabled = false;
        cfg.relay.max_filter_limit = HISTORY as u64 + 1_000;
        cfg.relay.max_total_events_per_req = 0;
        configure(&mut cfg);
        Self {
            handle: wok_relay::start(env, cfg).unwrap(),
            _dir: dir,
        }
    }

    async fn client(&self) -> Client {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let conn = self
            .handle
            .register_connection(TransportSource::Unix, Outbound::new(tx, 0))
            .await;
        Client {
            conn,
            rx,
            frames: Vec::new(),
            events: HashMap::new(),
            replies: HashMap::new(),
            accepted: 0,
        }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.handle.request_shutdown();
    }
}

struct Client {
    conn: ConnectionGuard,
    rx: Rx,
    /// Every frame received, in order.
    frames: Vec<Value>,
    /// EVENT deliveries by subscription id, then event id.
    events: HashMap<String, HashMap<String, usize>>,
    /// Other frames, by type and subscription id.
    replies: HashMap<(String, String), usize>,
    accepted: usize,
}

impl Client {
    async fn send(&self, msg: Value) {
        self.conn.client_message(msg.to_string()).await;
    }

    /// Sign and publish; returns the event id.
    async fn publish(&self, kind: u64, tag: &str, content: &str) -> String {
        let key = Keypair::new(SECP256K1, &mut rand::thread_rng());
        let event = sign_event_with_key(
            json!({
                "created_at": now(), "kind": kind, "tags": [["t", tag]], "content": content,
            }),
            &key,
        );
        let id = event["id"].as_str().unwrap().to_string();
        self.send(json!(["EVENT", event])).await;
        id
    }

    fn record(&mut self, frame: Value) {
        let kind = frame[0].as_str().unwrap_or_default().to_string();
        match kind.as_str() {
            "EVENT" => {
                *self
                    .events
                    .entry(frame[1].as_str().unwrap().into())
                    .or_default()
                    .entry(frame[2]["id"].as_str().unwrap().into())
                    .or_default() += 1;
            }
            "OK" => self.accepted += usize::from(frame[2] == true),
            _ => {
                let sub_id = frame[1].as_str().unwrap_or_default().to_string();
                *self.replies.entry((kind, sub_id)).or_default() += 1;
            }
        }
        self.frames.push(frame);
    }

    /// How many `kind` frames (EOSE, CLOSED, COUNT) `sub_id` got.
    fn replies(&self, kind: &str, sub_id: &str) -> usize {
        self.replies
            .get(&(kind.to_string(), sub_id.to_string()))
            .copied()
            .unwrap_or(0)
    }

    fn has(&self, kind: &str, sub_id: &str) -> bool {
        self.replies(kind, sub_id) != 0
    }

    fn delivered(&self, sub_id: &str) -> HashMap<String, usize> {
        self.events.get(sub_id).cloned().unwrap_or_default()
    }

    fn got(&self, sub_id: &str, id: &str) -> bool {
        self.events
            .get(sub_id)
            .is_some_and(|events| events.contains_key(id))
    }

    fn got_all(&self, sub_id: &str, ids: &[String]) -> bool {
        ids.iter().all(|id| self.got(sub_id, id))
    }

    /// Receive until `done` holds.
    async fn recv_until(&mut self, done: impl Fn(&Self) -> bool) {
        while !done(self) {
            let frame = tokio::time::timeout(Duration::from_secs(20), self.rx.recv())
                .await
                .expect("relay went quiet")
                .expect("connection closed");
            self.record(serde_json::from_str(&frame.into_text()).unwrap());
        }
    }

    /// Receive whatever else arrives within `quiet`.
    async fn settle(&mut self, quiet: Duration) {
        while let Ok(Some(frame)) = tokio::time::timeout(quiet, self.rx.recv()).await {
            self.record(serde_json::from_str(&frame.into_text()).unwrap());
        }
    }

    fn clear(&mut self) {
        self.frames.clear();
        self.events.clear();
        self.replies.clear();
        self.accepted = 0;
    }

    /// Index of the first frame matching `pred`.
    fn position(&self, pred: impl Fn(&Value) -> bool) -> usize {
        self.frames.iter().position(pred).expect("frame not found")
    }
}

fn is(frame: &Value, kind: &str, sub_id: &str) -> bool {
    frame[0] == kind && frame[1] == sub_id
}

fn history_and(live: Value) -> Value {
    json!(["REQ", "x", {"kinds": [1], "#t": ["hist"], "limit": HISTORY + 1_000}, live])
}

async fn ephemeral_burst_after_req(history: bool) {
    let relay = Relay::new(history, |_| {});
    let mut client = relay.client().await;
    client
        .send(history_and(json!({"kinds": [20001], "#t": ["live"]})))
        .await;
    let mut ids = Vec::new();
    for i in 0..60 {
        ids.push(client.publish(20001, "live", &format!("live {i}")).await);
    }
    client
        .recv_until(|c| c.has("EOSE", "x") && c.accepted == ids.len())
        .await;
    client.recv_until(|c| c.got_all("x", &ids)).await;
    let seen = client.delivered("x");
    for id in &ids {
        assert_eq!(seen[id], 1, "ephemeral {id} delivered more than once");
    }
    let history_events = seen.len() - ids.len();
    assert_eq!(history_events, if history { HISTORY } else { 0 });
    // Everything the history sent precedes EOSE; the ephemeral events were
    // published after the REQ, so they are real-time and follow it.
    let eose = client.position(|f| is(f, "EOSE", "x"));
    for id in &ids {
        let at =
            client.position(|f| is(f, "EVENT", "x") && f[2]["id"].as_str() == Some(id.as_str()));
        assert!(at > eose, "ephemeral event {id} came before EOSE");
    }
}

/// Ephemeral events published from the moment of the REQ all arrive, even
/// while a long history is still being sent (strfry, and Wok before this
/// change, installed the live filter only after the history).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ephemeral_events_after_req_are_all_delivered() {
    ephemeral_burst_after_req(false).await;
    ephemeral_burst_after_req(true).await;
}

/// The NIP-46 shape across two connections: a client subscribes for replies,
/// then publishes a request; the signer answers each request with a burst.
/// Every reply follows the REQ causally, so none may be lost while the
/// client's history is still being sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replies_to_a_request_sent_after_req_are_all_delivered() {
    let relay = Relay::new(true, |_| {});
    let mut signer = relay.client().await;
    signer
        .send(json!(["REQ", "requests", {"kinds": [20001], "#t": ["request"]}]))
        .await;
    signer.recv_until(|c| c.has("EOSE", "requests")).await;

    let mut client = relay.client().await;
    client
        .send(history_and(json!({"kinds": [20001], "#t": ["reply"]})))
        .await;
    client.publish(20001, "request", "please sign").await;

    signer
        .recv_until(|c| !c.delivered("requests").is_empty())
        .await;
    let mut replies = Vec::new();
    for i in 0..30 {
        replies.push(signer.publish(20001, "reply", &format!("reply {i}")).await);
    }
    client
        .recv_until(|c| c.has("EOSE", "x") && c.got_all("x", &replies))
        .await;
    assert_eq!(client.delivered("x").len(), HISTORY + replies.len());
}

/// A stored event committed while the history is being sent reaches the
/// client exactly once: from the history if the snapshot includes it, else
/// after EOSE from the held matches.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stored_events_committed_during_history_arrive_exactly_once() {
    let relay = Relay::new(true, |cfg| {
        // Yield often so the scan spans many passes.
        cfg.relay.query_timeslice_budget_us = 100;
    });
    let mut client = relay.client().await;
    client
        .send(json!(["REQ", "x", {"kinds": [1], "#t": ["hist"], "limit": HISTORY + 1_000}]))
        .await;
    let mut ids = Vec::new();
    for i in 0..20 {
        ids.push(client.publish(1, "hist", &format!("new {i}")).await);
    }
    client
        .recv_until(|c| c.has("EOSE", "x") && c.accepted == ids.len())
        .await;
    client.recv_until(|c| c.got_all("x", &ids)).await;
    client.settle(Duration::from_millis(300)).await;
    let seen = client.delivered("x");
    assert_eq!(seen.len(), HISTORY + ids.len());
    assert!(
        seen.values().all(|n| *n == 1),
        "an event was delivered twice"
    );
}

/// History covers what was stored when the REQ arrived; everything stored
/// after reaches the client live, even if its `limit` keeps the history empty
/// and the req worker starts the scan late, behind another long one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_limit_zero_req_gets_every_event_stored_after_it() {
    let relay = Relay::new(true, |cfg| cfg.relay.req_worker_threads = 1);
    let busy = relay.client().await;
    busy.send(json!(["REQ", "busy", {"kinds": [1], "#t": ["hist"], "limit": HISTORY + 1_000}]))
        .await;
    let mut client = relay.client().await;
    client
        .send(json!(["REQ", "x", {"kinds": [1], "#t": ["fresh"], "limit": 0}]))
        .await;
    let mut ids = Vec::new();
    for i in 0..20 {
        ids.push(client.publish(1, "fresh", &format!("fresh {i}")).await);
    }
    client
        .recv_until(|c| c.has("EOSE", "x") && c.accepted == ids.len() && c.got_all("x", &ids))
        .await;
    client.settle(Duration::from_millis(300)).await;
    let seen = client.delivered("x");
    assert_eq!(seen.len(), ids.len());
    assert!(seen.values().all(|n| *n == 1));
}

/// Once a REQ replaces a subscription, the old filter delivers nothing more,
/// and nothing published for the new one is lost during the swap.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replacing_a_subscription_stops_the_old_filter_at_once() {
    let relay = Relay::new(true, |_| {});
    let mut client = relay.client().await;
    client
        .send(json!(["REQ", "x", {"kinds": [1, 20001], "#t": ["old"]}]))
        .await;
    client.recv_until(|c| c.has("EOSE", "x")).await;
    let old = client.publish(20001, "old", "before the swap").await;
    client.recv_until(|c| c.got("x", &old)).await;

    client
        .send(history_and(json!({"kinds": [1, 20001], "#t": ["new"]})))
        .await;
    let mut new = Vec::new();
    for i in 0..20 {
        client
            .publish(20001, "old", &format!("old ephemeral {i}"))
            .await;
        client.publish(1, "old", &format!("old stored {i}")).await;
        new.push(
            client
                .publish(20001, "new", &format!("new ephemeral {i}"))
                .await,
        );
        new.push(client.publish(1, "new", &format!("new stored {i}")).await);
    }
    client
        .recv_until(|c| c.accepted == 1 + 4 * 20 && c.has("EOSE", "x") && c.got_all("x", &new))
        .await;
    client.settle(Duration::from_millis(300)).await;
    let seen = client.delivered("x");
    let old_after_swap = client
        .frames
        .iter()
        .filter(|f| is(f, "EVENT", "x") && f[2]["tags"][0][1] == "old")
        .count();
    assert_eq!(old_after_swap, 1, "only the pre-swap old event may arrive");
    assert_eq!(seen.len(), 1 + HISTORY + new.len());
    assert!(seen.values().all(|n| *n == 1));
}

/// A refused REQ still replaces the subscription it names (NIP-01): the old
/// one stops, whether it was live or still sending history, and nothing for
/// the id follows the CLOSED.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_replacement_closes_the_old_subscription() {
    let relay = Relay::new(true, |_| {});
    let mut client = relay.client().await;
    let bad = json!(["REQ", "x", {"kinds": [1], "nope": true}]);
    client
        .send(json!(["REQ", "sentinel", {"kinds": [20001]}]))
        .await;

    // A live subscription.
    client.send(json!(["REQ", "x", {"kinds": [20001]}])).await;
    client
        .recv_until(|c| c.has("EOSE", "x") && c.has("EOSE", "sentinel"))
        .await;
    client.send(bad.clone()).await;
    client.recv_until(|c| c.has("CLOSED", "x")).await;
    let probe = client.publish(20001, "probe", "after the refusal").await;
    client.recv_until(|c| c.got("sentinel", &probe)).await;
    client.settle(Duration::from_millis(200)).await;
    let closed = client.position(|f| is(f, "CLOSED", "x"));
    assert!(
        !client.frames[closed..]
            .iter()
            .any(|f| f[1] == "x" && f[0] != "CLOSED"),
        "{:?}",
        &client.frames[closed..]
    );

    // One still sending its history, refused twice in a row: the second
    // refusal must wait for the teardown the first one started.
    client.clear();
    client
        .send(history_and(json!({"kinds": [20001], "#t": ["live"]})))
        .await;
    client.send(bad.clone()).await;
    client.send(bad).await;
    client.recv_until(|c| c.replies("CLOSED", "x") == 2).await;
    let probe = client.publish(20001, "live", "after the refusal").await;
    client.recv_until(|c| c.got("sentinel", &probe)).await;
    client.settle(Duration::from_millis(500)).await;
    let closed = client.position(|f| is(f, "CLOSED", "x"));
    assert!(
        !client.frames[closed + 1..]
            .iter()
            .any(|f| f[1] == "x" && f[0] != "CLOSED"),
        "the old subscription outlived its refused replacement"
    );
    assert!(!client.has("EOSE", "x"));
}

/// The subscription cap is checked when the REQ arrives: the REQ over it
/// gets CLOSED and never an EOSE, an open id can still be replaced, and
/// closing one makes room.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_req_over_the_subscription_cap_is_closed_without_eose() {
    let relay = Relay::new(false, |cfg| cfg.relay.max_subs_per_connection = 200);
    let mut client = relay.client().await;
    for i in 0..200 {
        let sub_id = format!("s{i}");
        client
            .send(json!(["REQ", sub_id, {"kinds": [20001]}]))
            .await;
        client.recv_until(|c| c.has("EOSE", &sub_id)).await;
    }
    client
        .send(json!(["REQ", "s200", {"kinds": [20001]}]))
        .await;
    client.recv_until(|c| c.has("CLOSED", "s200")).await;
    let closed = client.frames.last().unwrap();
    assert_eq!(closed[2], "blocked: too many concurrent REQs");

    // Replacing an open id at the cap is allowed.
    client.send(json!(["REQ", "s0", {"kinds": [20001]}])).await;
    client.recv_until(|c| c.replies("EOSE", "s0") == 2).await;
    let probe = client.publish(20001, "probe", "after the cap").await;
    client
        .recv_until(|c| (0..200).all(|i| c.got(&format!("s{i}"), &probe)))
        .await;
    client.settle(Duration::from_millis(200)).await;
    assert!(!client
        .frames
        .iter()
        .any(|f| f[1] == "s200" && f[0] != "CLOSED"));

    client.send(json!(["CLOSE", "s1"])).await;
    client
        .send(json!(["REQ", "s200", {"kinds": [20001]}]))
        .await;
    client.recv_until(|c| c.has("EOSE", "s200")).await;
}

/// With a tiny live buffer, stored matches are re-read from the database and
/// still arrive exactly once; ephemeral ones are either delivered or counted
/// as dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn overflowing_the_live_buffer_loses_no_stored_event() {
    let relay = Relay::new(true, |cfg| {
        cfg.relay.max_live_buffer_bytes = 1;
        cfg.relay.query_timeslice_budget_us = 100;
    });
    let mut client = relay.client().await;
    client
        .send(history_and(json!({"kinds": [20001], "#t": ["live"]})))
        .await;
    let mut stored = Vec::new();
    let mut ephemeral = Vec::new();
    for i in 0..10 {
        stored.push(client.publish(1, "hist", &format!("stored {i}")).await);
        ephemeral.push(
            client
                .publish(20001, "live", &format!("ephemeral {i}"))
                .await,
        );
    }
    client
        .recv_until(|c| c.has("EOSE", "x") && c.accepted == 20 && c.got_all("x", &stored))
        .await;
    client.settle(Duration::from_millis(300)).await;
    let seen = client.delivered("x");
    assert!(seen.values().all(|n| *n == 1));
    let ephemeral_delivered = ephemeral.iter().filter(|id| seen.contains_key(*id)).count() as u64;
    let dropped = relay
        .handle
        .metrics
        .live_buffer_dropped_ephemeral
        .load(Ordering::Relaxed);
    assert_eq!(ephemeral_delivered + dropped, ephemeral.len() as u64);
    assert_eq!(seen.len() as u64, HISTORY as u64 + 10 + ephemeral_delivered);
}

/// COUNT and REQ ids are separate: a COUNT reusing an in-flight REQ's id
/// leaves the REQ running to its EOSE.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn count_does_not_cancel_a_req_with_the_same_id() {
    let relay = Relay::new(true, |_| {});
    let mut client = relay.client().await;
    client
        .send(json!(["REQ", "x", {"kinds": [1], "#t": ["hist"], "limit": HISTORY + 1_000}]))
        .await;
    client.send(json!(["COUNT", "x", {"kinds": [1]}])).await;
    client
        .recv_until(|c| c.has("EOSE", "x") && c.has("COUNT", "x"))
        .await;
    assert_eq!(client.delivered("x").len(), HISTORY);
    let count = client.frames.iter().find(|f| is(f, "COUNT", "x")).unwrap();
    assert_eq!(count[2]["count"], HISTORY);
}
