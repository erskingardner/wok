//! `[relay.filter_validation]` on every read that names filters: REQ, COUNT
//! and NEG-OPEN alike, including `require_scoped_filters`, which refuses
//! enumeration such as `{"kinds":[445]}` and keeps the filters Marmot
//! clients send (tracking issue #97 §3.7, F13).

use serde_json::{json, Value};
use std::time::Duration;
use wok_relay::{Config, ConnectionGuard, Outbound, OutboundFrame, RelayHandle, TransportSource};

const GROUP: &str = "8c3f1aa20a9b5fd8e4f5c7bb86e2b9e5d3a1c7d10f6a2e4b5c8d9e0f1a2b3c4d";

struct Relay {
    handle: RelayHandle,
    _dir: tempfile::TempDir,
}

impl Relay {
    fn new(configure: impl FnOnce(&mut Config)) -> Self {
        let (dir, env) = wok_compat::temp_db();
        let mut cfg = Config {
            db: dir.path().to_path_buf(),
            ..Default::default()
        };
        configure(&mut cfg);
        Self {
            handle: wok_relay::start(env, cfg).unwrap(),
            _dir: dir,
        }
    }

    async fn connect(&self) -> Client {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let guard = self
            .handle
            .register_connection(TransportSource::Unix, Outbound::new(tx, 0))
            .await;
        Client { guard, rx }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.handle.request_shutdown();
    }
}

struct Client {
    guard: ConnectionGuard,
    rx: tokio::sync::mpsc::UnboundedReceiver<OutboundFrame>,
}

impl Client {
    /// Send `msg` and return the first frame for its id (`msg[1]`) that is
    /// not one of the events it sends, which are collected in `events`.
    async fn request(&mut self, msg: Value, events: &mut Vec<Value>) -> Value {
        self.guard.client_message(msg.to_string()).await;
        self.reply(&msg[1], events).await
    }

    /// Publish `event` and return its OK.
    async fn publish(&mut self, event: &Value) -> Value {
        self.guard
            .client_message(json!(["EVENT", event]).to_string())
            .await;
        self.reply(&event["id"], &mut Vec::new()).await
    }

    async fn reply(&mut self, id: &Value, events: &mut Vec<Value>) -> Value {
        let msg = json!([null, id]);
        loop {
            let frame = tokio::time::timeout(Duration::from_secs(5), self.rx.recv())
                .await
                .expect("a frame from the relay")
                .unwrap();
            let reply: Value = serde_json::from_str(&frame.into_text()).unwrap();
            if reply[1] != msg[1] {
                continue;
            }
            if reply[0] == "EVENT" {
                events.push(reply[2].clone());
                continue;
            }
            return reply;
        }
    }
}

/// An empty client's first negentropy message.
fn neg_init() -> String {
    let mut store = wok_negentropy::Vector::new();
    store.seal().unwrap();
    let mut client = wok_negentropy::Negentropy::new(store, 60_000).unwrap();
    hex::encode(client.initiate().unwrap())
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scoped_filters_refuse_enumeration_on_every_read() {
    let relay = Relay::new(|cfg| cfg.relay.filter_validation.require_scoped_filters = true);
    let mut client = relay.connect().await;
    let message = wok_compat::sign_event(json!({
        "created_at": now(),
        "kind": 445,
        "tags": [["h", GROUP]],
        "content": "mls ciphertext",
    }));
    let ok = client.publish(&message).await;
    assert_eq!(ok[2], true, "{ok}");

    let unscoped = json!({"kinds": [445]});
    let refusal = "filter validation failed: filter must name ids, authors or a tag";
    for (msg, reply) in [
        (
            json!(["REQ", "dump", unscoped]),
            json!(["CLOSED", "dump", format!("blocked: bad req: {refusal}")]),
        ),
        (
            json!(["COUNT", "dump", unscoped]),
            json!(["CLOSED", "dump", format!("blocked: bad req: {refusal}")]),
        ),
        (
            json!(["NEG-OPEN", "dump", unscoped, neg_init()]),
            json!(["NEG-ERR", "dump", format!("blocked: {refusal}")]),
        ),
    ] {
        let mut events = Vec::new();
        assert_eq!(
            client.request(msg.clone(), &mut events).await,
            reply,
            "{msg}"
        );
        assert!(events.is_empty(), "{msg}");
    }

    // The group's own filter is served.
    let group = json!({"kinds": [445], "#h": [GROUP]});
    let mut events = Vec::new();
    let eose = client
        .request(json!(["REQ", "group", group]), &mut events)
        .await;
    assert_eq!(eose[0], "EOSE", "{eose}");
    assert_eq!(events, [message]);
    let count = client
        .request(json!(["COUNT", "count", group]), &mut Vec::new())
        .await;
    assert_eq!(
        (&count[0], &count[2]["count"]),
        (&json!("COUNT"), &json!(1))
    );
    let sync = client
        .request(
            json!(["NEG-OPEN", "sync", group, neg_init()]),
            &mut Vec::new(),
        )
        .await;
    assert_eq!(sync[0], "NEG-MSG", "{sync}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn neg_open_meets_every_filter_rule() {
    let relay = Relay::new(|cfg| {
        let rules = &mut cfg.relay.filter_validation;
        rules.allowed_kinds = "445,1059".into();
        rules.max_kinds_per_filter = 1;
    });
    let mut client = relay.connect().await;
    for (filter, reason) in [
        (json!({"kinds": [1]}), "kind not allowed: 1"),
        (json!({"kinds": [445, 1059]}), "too many kinds in filter: 2"),
    ] {
        let reply = client
            .request(
                json!(["NEG-OPEN", "sync", filter, neg_init()]),
                &mut Vec::new(),
            )
            .await;
        assert_eq!(
            reply,
            json!([
                "NEG-ERR",
                "sync",
                format!("blocked: filter validation failed: {reason}")
            ])
        );
    }
    let reply = client
        .request(
            json!(["NEG-OPEN", "sync", {"kinds": [445]}, neg_init()]),
            &mut Vec::new(),
        )
        .await;
    assert_eq!(reply[0], "NEG-MSG", "{reply}");
}
