//! The `marmot` preset (tracking issue #97 §4.2) serving the traffic MDK
//! sends: anonymous group messages and Welcomes, AUTHed inbox reads,
//! anonymous directory reads, and NIP-77 per group, while enumeration and
//! other kinds are refused.

use secp256k1::{Keypair, SECP256K1};
use serde_json::{json, Value};
use std::time::Duration;
use wok_relay::{Config, ConnectionGuard, Outbound, OutboundFrame, RelayHandle, TransportSource};

const AUTH_RELAY: &str = "wss://marmot.test";
const GROUP: &str = "8c3f1aa20a9b5fd8e4f5c7bb86e2b9e5d3a1c7d10f6a2e4b5c8d9e0f1a2b3c4d";

fn marmot_config(extra: &str) -> Config {
    Config::parse_toml(&format!(
        "preset = \"marmot\"\n[relay.auth]\nservice_url = \"{AUTH_RELAY}\"\n{extra}"
    ))
    .unwrap()
}

struct Relay {
    handle: RelayHandle,
    _dir: tempfile::TempDir,
}

impl Relay {
    fn start(mut config: Config) -> Self {
        let (dir, env) = wok_compat::temp_db();
        config.db = dir.path().to_path_buf();
        Self {
            handle: wok_relay::start(env, config).unwrap(),
            _dir: dir,
        }
    }

    async fn connect(&self, source: TransportSource) -> Client {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let guard = self
            .handle
            .register_connection(source, Outbound::new(tx, 0))
            .await;
        Client {
            guard,
            rx,
            challenge: None,
        }
    }

    /// A connection from its own network address, so the per-address
    /// budgets apply to it as to one client.
    async fn client(&self, ip: &str) -> Client {
        self.connect(TransportSource::ip_address(ip.parse().unwrap()))
            .await
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
    challenge: Option<String>,
}

impl Client {
    async fn send(&self, msg: Value) {
        self.guard.client_message(msg.to_string()).await;
    }

    async fn recv(&mut self) -> Value {
        let frame = tokio::time::timeout(Duration::from_secs(10), self.rx.recv())
            .await
            .expect("a frame from the relay")
            .unwrap();
        let msg: Value = serde_json::from_str(&frame.into_text()).unwrap();
        if msg[0] == "AUTH" {
            self.challenge = msg[1].as_str().map(str::to_string);
        }
        msg
    }

    /// The next frame for `id` that is one of `types`; the events a REQ
    /// sends before it are collected in `events`.
    async fn reply(&mut self, id: &str, types: &[&str], events: &mut Vec<Value>) -> Value {
        loop {
            let msg = self.recv().await;
            if msg[1] != id {
                continue;
            }
            if msg[0] == "EVENT" {
                events.push(msg[2].clone());
            } else if types.iter().any(|t| msg[0] == *t) {
                return msg;
            }
        }
    }

    async fn auth(&mut self, key: &Keypair) {
        while self.challenge.is_none() {
            self.recv().await;
        }
        let event = wok_compat::sign_event_with_key(
            json!({
                "created_at": now(),
                "kind": 22242,
                "tags": [["relay", AUTH_RELAY], ["challenge", self.challenge]],
                "content": "",
            }),
            key,
        );
        let id = event["id"].as_str().unwrap().to_string();
        self.send(json!(["AUTH", event])).await;
        let ok = self.reply(&id, &["OK"], &mut Vec::new()).await;
        assert_eq!(ok[2], true, "{ok}");
    }

    /// Publish `event`, and return the OK's reason when it was refused.
    async fn refusal(&mut self, event: &Value) -> Option<String> {
        self.send(json!(["EVENT", event])).await;
        let ok = self
            .reply(event["id"].as_str().unwrap(), &["OK"], &mut Vec::new())
            .await;
        (ok[2] == false).then(|| ok[3].as_str().unwrap().to_string())
    }

    /// The stored events a REQ of `filter` returns, or why it was refused.
    async fn history(&mut self, filter: Value) -> Result<Vec<Value>, String> {
        self.send(json!(["REQ", "history", filter])).await;
        let mut events = Vec::new();
        let end = self
            .reply("history", &["EOSE", "CLOSED"], &mut events)
            .await;
        if end[0] == "CLOSED" {
            return Err(end[2].as_str().unwrap().to_string());
        }
        self.send(json!(["CLOSE", "history"])).await;
        Ok(events)
    }

    /// Open a sync of `filter` and return its first reply.
    async fn neg_open(&mut self, filter: Value) -> Value {
        let mut store = wok_negentropy::Vector::new();
        store.seal().unwrap();
        let mut client = wok_negentropy::Negentropy::new(store, 60_000).unwrap();
        let init = hex::encode(client.initiate().unwrap());
        self.send(json!(["NEG-OPEN", "sync", filter, init])).await;
        self.reply("sync", &["NEG-MSG", "NEG-ERR"], &mut Vec::new())
            .await
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn key() -> Keypair {
    Keypair::new(SECP256K1, &mut rand::thread_rng())
}

fn hex_of(key: &Keypair) -> String {
    hex::encode(key.x_only_public_key().0.serialize())
}

fn signed(key: &Keypair, kind: u64, tags: Value, content: &str) -> Value {
    wok_compat::sign_event_with_key(
        json!({"created_at": now(), "kind": kind, "tags": tags, "content": content}),
        key,
    )
}

/// A Welcome for `recipient` in a gift wrap, signed by a random key.
fn gift_wrap(recipient: &Keypair, content: &str) -> Value {
    signed(&key(), 1059, json!([["p", hex_of(recipient)]]), content)
}

#[test]
fn the_marmot_preset_refuses_to_start_without_auth() {
    let (_dir, env) = wok_compat::temp_db();
    let config = Config::parse_toml("preset = \"marmot\"\n").unwrap();
    let error = wok_relay::start(env, config).err().unwrap();
    assert!(error.contains("relay.auth.service_url"), "{error}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_marmot_preset_serves_mdk_traffic() {
    let config = marmot_config("");
    assert!(config.restricted_writes() && !config.auth_required());
    let relay = Relay::start(config);
    let (account, inviter) = (key(), key());

    // The account's directory events and KeyPackage, from its own key.
    let mut publisher = relay.client("203.0.113.1").await;
    let directory = [
        signed(&account, 0, json!([]), "{\"name\":\"alice\"}"),
        signed(&account, 10002, json!([["r", "wss://marmot.test"]]), ""),
        signed(&account, 10050, json!([["relay", "wss://marmot.test"]]), ""),
        signed(
            &account,
            30443,
            json!([["d", "ab".repeat(32)]]),
            "keypackage",
        ),
    ];
    for event in &directory {
        assert_eq!(publisher.refusal(event).await, None, "{event}");
    }
    // An anonymous 445 from a fresh key, and a Welcome larger than the public
    // preset's 1 MiB events.
    let message = signed(&key(), 445, json!([["h", GROUP]]), "mls ciphertext");
    assert_eq!(publisher.refusal(&message).await, None);
    let welcome = gift_wrap(&account, &"w".repeat(2 * 1024 * 1024));
    assert_eq!(publisher.refusal(&welcome).await, None);
    // Kinds outside the Marmot set are refused.
    let note = signed(&inviter, 1, json!([]), "hello");
    assert_eq!(
        publisher.refusal(&note).await.as_deref(),
        Some("restricted: kind 1 is not allowed by this relay")
    );

    // Anonymous directory and group reads.
    let mut reader = relay.client("203.0.113.2").await;
    let batch = json!({
        "authors": [hex_of(&account)],
        "kinds": [0, 3, 10000, 10002, 10050, 30443],
        "limit": 1200,
    });
    let mut found = reader.history(batch).await.unwrap();
    found.sort_by_key(|event| event["kind"].as_u64());
    assert_eq!(found, directory);
    let group = json!({"kinds": [445], "#h": [GROUP]});
    assert_eq!(
        reader.history(group.clone()).await.unwrap(),
        std::slice::from_ref(&message)
    );

    // The inbox only after AUTH as the recipient.
    let inbox = json!({"kinds": [1059], "#p": [hex_of(&account)]});
    let refused = reader.history(inbox.clone()).await.unwrap_err();
    assert!(refused.starts_with("auth-required:"), "{refused}");
    let mut receiver = relay.client("203.0.113.3").await;
    receiver.auth(&account).await;
    assert_eq!(receiver.history(inbox).await.unwrap(), [welcome]);

    // Enumeration is refused; MDK's filters name their scope.
    let refused = reader.history(json!({"kinds": [445]})).await.unwrap_err();
    assert_eq!(
        refused,
        "blocked: bad req: filter validation failed: filter must name ids, authors or a tag"
    );

    // MDK never sends COUNT, so the preset turns it off.
    reader
        .send(json!(["COUNT", "count", {"kinds": [445], "#h": [GROUP]}]))
        .await;
    let refused = reader
        .reply("count", &["COUNT", "CLOSED"], &mut Vec::new())
        .await;
    assert_eq!(
        refused,
        json!(["CLOSED", "count", "blocked: bad req: COUNT disabled"])
    );

    // NIP-77 per group, and not over every group.
    assert_eq!(reader.neg_open(group).await[0], "NEG-MSG");
    let refused = reader.neg_open(json!({"kinds": [445]})).await;
    assert_eq!(
        refused[2],
        "blocked: filter validation failed: filter must name ids, authors or a tag"
    );
}

/// An inviter's commit and 250 Welcomes fit one address's Marmot EVENT burst
/// without needing refill. The public-versus-Marmot capacity comparison uses
/// a fixed clock in wok-relay's abuse unit tests.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_marmot_preset_fits_an_add_member_burst_from_one_address() {
    let relay = Relay::start(marmot_config(""));
    let mut inviter = relay.client("198.51.100.7").await;
    let commit = signed(&key(), 445, json!([["h", GROUP]]), "add commit");
    assert_eq!(inviter.refusal(&commit).await, None);
    for _ in 0..250 {
        let welcome = gift_wrap(&key(), "welcome");
        assert_eq!(inviter.refusal(&welcome).await, None, "{welcome}");
    }
}
