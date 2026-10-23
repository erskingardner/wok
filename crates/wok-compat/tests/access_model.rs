//! The access model (tracking issue #97 §3.6): who may read each kind, by
//! its read class, and how the access keys of earlier releases translate.

use secp256k1::{Keypair, SECP256K1};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::time::Duration;
use wok_relay::{Config, ConnectionGuard, Outbound, OutboundFrame, RelayHandle, TransportSource};

const AUTH_RELAY: &str = "wss://access.test";

struct Relay {
    handle: RelayHandle,
    config: Config,
    _dir: tempfile::TempDir,
}

impl Relay {
    /// A relay configured by `auth`, the body of a `[relay.auth]` table.
    fn with_auth(auth: &str) -> Self {
        let (dir, env) = wok_compat::temp_db();
        let mut config = Config::parse_toml(&format!(
            "[relay.auth]\nservice_url = \"{AUTH_RELAY}\"\n{auth}\n"
        ))
        .unwrap();
        config.db = dir.path().to_path_buf();
        Self {
            handle: wok_relay::start(env, config.clone()).unwrap(),
            config,
            _dir: dir,
        }
    }

    async fn connect(&self) -> Client {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let guard = self
            .handle
            .register_connection(TransportSource::Unix, Outbound::new(tx, 0))
            .await;
        Client {
            guard,
            rx,
            challenge: None,
        }
    }

    /// A connection authenticated as `key`, or an anonymous one.
    async fn reader(&self, key: Option<&Keypair>) -> Client {
        let mut client = self.connect().await;
        if let Some(key) = key {
            client.auth(key).await;
        }
        client
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
    /// The NIP-42 challenge, once the relay has sent it.
    challenge: Option<String>,
}

impl Client {
    async fn send(&self, msg: Value) {
        self.guard.client_message(msg.to_string()).await;
    }

    async fn recv(&mut self) -> Value {
        let frame = tokio::time::timeout(Duration::from_secs(5), self.rx.recv())
            .await
            .expect("a frame from the relay")
            .unwrap();
        let msg: Value = serde_json::from_str(&frame.into_text()).unwrap();
        if msg[0] == "AUTH" {
            self.challenge = msg[1].as_str().map(str::to_string);
        }
        msg
    }

    /// The next frame for `id` that is one of `types`.
    async fn reply(&mut self, id: &str, types: &[&str]) -> Value {
        loop {
            let msg = self.recv().await;
            if msg[1] == id && types.iter().any(|t| msg[0] == *t) {
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
        let ok = self.reply(&id, &["OK"]).await;
        assert_eq!(ok[2], true, "{ok}");
    }

    /// Send an EVENT and return its OK.
    async fn publish(&mut self, event: &Value) -> Value {
        self.send(json!(["EVENT", event])).await;
        self.reply(event["id"].as_str().unwrap(), &["OK"]).await
    }

    /// The stored events a REQ of `filters` returns, or the reason it was
    /// refused.
    async fn history(&mut self, filters: Value) -> Result<Vec<Value>, String> {
        let mut req = vec![json!("REQ"), json!("history")];
        req.extend(filters.as_array().unwrap().iter().cloned());
        self.send(Value::Array(req)).await;
        let mut events = Vec::new();
        loop {
            let msg = self.recv().await;
            match (msg[0].as_str(), msg[1].as_str()) {
                (Some("EVENT"), Some("history")) => events.push(msg[2].clone()),
                (Some("EOSE"), Some("history")) => break,
                (Some("CLOSED"), Some("history")) => {
                    return Err(msg[2].as_str().unwrap().to_string())
                }
                _ => {}
            }
        }
        self.send(json!(["CLOSE", "history"])).await;
        Ok(events)
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

fn hex(key: &Keypair) -> String {
    hex::encode(key.x_only_public_key().0.serialize())
}

/// An event of `kind` by `author`, addressed to `recipient` with a `p` tag.
fn event(author: &Keypair, kind: u64, recipient: &Keypair) -> Value {
    wok_compat::sign_event_with_key(
        json!({
            "created_at": now(),
            "kind": kind,
            "tags": [["p", hex(recipient)]],
            "content": format!("kind {kind}"),
        }),
        author,
    )
}

/// The kinds each of four readers is served by a REQ for kinds 1 and 7:
/// an anonymous connection, the author, the recipient and a stranger.
async fn kinds_read(relay: &Relay, author: &Keypair, recipient: &Keypair) -> Vec<BTreeSet<u64>> {
    let mut publisher = relay.connect().await;
    for kind in [1, 7] {
        let ok = publisher.publish(&event(author, kind, recipient)).await;
        assert_eq!(ok[2], true, "{ok}");
    }
    let mut read = Vec::new();
    for reader in [None, Some(author), Some(recipient), Some(&key())] {
        let events = relay
            .reader(reader)
            .await
            .history(json!([{"kinds": [1]}, {"kinds": [7]}]))
            .await
            .unwrap();
        read.push(events.iter().map(|e| e["kind"].as_u64().unwrap()).collect());
    }
    read
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn old_read_keys_translate_to_the_same_readers() {
    let open_and = |kinds: &[u64]| -> BTreeSet<u64> { kinds.iter().copied().collect() };
    let (open, both) = (open_and(&[1]), open_and(&[1, 7]));
    for (old, new, readers) in [
        // Recipient-only: the author and the first `p` tag.
        (
            "restricted_read_kinds = [7]",
            "recipient_only_kinds = [7]",
            [&open, &both, &both, &open],
        ),
        (
            "restricted_read_kinds = [7]\nrestrict_read_to_involved_pubkey = true",
            "recipient_only_kinds = [7]",
            [&open, &both, &both, &open],
        ),
        // Without the involved-pubkey rule, any authenticated connection, and
        // no longer an anonymous one that mixes in kind 1.
        (
            "restricted_read_kinds = [7]\nrestrict_read_to_involved_pubkey = false",
            "recipient_only_kinds = []\nauthenticated_kinds = [7]",
            [&open, &both, &both, &both],
        ),
    ] {
        let (author, recipient) = (key(), key());
        let translated = Relay::with_auth(old);
        assert!(
            !translated.config.deprecations.is_empty(),
            "{old}: no deprecation warning"
        );
        let current = Relay::with_auth(new);
        assert!(current.config.deprecations.is_empty(), "{new}");
        assert_eq!(
            translated.config.read_restrictor(),
            current.config.read_restrictor()
        );
        let expected: Vec<BTreeSet<u64>> = readers.into_iter().cloned().collect();
        assert_eq!(
            kinds_read(&translated, &author, &recipient).await,
            expected,
            "{old}"
        );
        assert_eq!(
            kinds_read(&current, &author, &recipient).await,
            expected,
            "{new}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_kinds_need_auth_as_anyone() {
    let relay = Relay::with_auth("authenticated_kinds = [7]");
    let (author, recipient) = (key(), key());
    let mut publisher = relay.connect().await;
    let shared = event(&author, 7, &recipient);
    assert_eq!(publisher.publish(&shared).await[2], true);

    let mut anonymous = relay.reader(None).await;
    let refused = anonymous
        .history(json!([{"kinds": [7]}]))
        .await
        .unwrap_err();
    assert!(refused.starts_with("auth-required:"), "{refused}");
    let mut stranger = relay.reader(Some(&key())).await;
    assert_eq!(
        stranger.history(json!([{"kinds": [7]}])).await.unwrap(),
        [shared]
    );
}
