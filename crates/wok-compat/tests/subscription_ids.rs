//! NIP-01: "<subscription_id> is an arbitrary, non-empty string of max length
//! 64 chars". Ids with any character work end to end, over WebSocket and
//! Unix: every frame that names one (EVENT for history and live delivery,
//! EOSE, COUNT, CLOSED) is valid JSON carrying the id unchanged. The length
//! is counted in characters, and subscriptions are keyed by the exact id.
#![allow(clippy::field_reassign_with_default)]

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio_tungstenite::tungstenite::Message;
use wok_compat::sign_event;
use wok_relay::{Config, RelayHandle};

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A client on either transport. Every frame it receives must parse as
/// JSON.
enum Wire {
    Ws(Box<WsStream>),
    Unix(tokio::net::UnixStream),
}

impl Wire {
    async fn send(&mut self, msg: Value) {
        let text = msg.to_string();
        match self {
            Wire::Ws(ws) => ws.send(Message::Text(text.into())).await.unwrap(),
            Wire::Unix(stream) => wok_unix::write_frame(stream, text.as_bytes())
                .await
                .unwrap(),
        }
    }

    async fn next_frame(&mut self, wait: Duration) -> Option<Value> {
        let text = match self {
            Wire::Ws(ws) => loop {
                let msg = tokio::time::timeout(wait, ws.next()).await.ok()??.unwrap();
                if msg.is_text() {
                    break msg.to_text().unwrap().to_string();
                }
            },
            Wire::Unix(stream) => {
                let body = tokio::time::timeout(wait, wok_unix::read_frame(stream, 1 << 20))
                    .await
                    .ok()?
                    .unwrap();
                String::from_utf8(body).unwrap()
            }
        };
        Some(
            serde_json::from_str(&text)
                .unwrap_or_else(|error| panic!("frame is not JSON ({error}): {text:?}")),
        )
    }

    /// Frames up to and including the first that `done` accepts.
    async fn recv_until(&mut self, done: impl Fn(&Value) -> bool) -> Vec<Value> {
        let mut frames = Vec::new();
        loop {
            let frame = self
                .next_frame(Duration::from_secs(3))
                .await
                .unwrap_or_else(|| panic!("timed out; got {frames:?}"));
            let hit = done(&frame);
            frames.push(frame);
            if hit {
                return frames;
            }
        }
    }

    /// Frames that arrive within `wait`.
    async fn settle(&mut self, wait: Duration) -> Vec<Value> {
        let mut frames = Vec::new();
        while let Some(frame) = self.next_frame(wait).await {
            frames.push(frame);
        }
        frames
    }

    /// Publish an event tagged `t`, returning its id once the relay has
    /// stored it. Frames that arrive before the OK are returned too.
    async fn publish(&mut self, tag: &str) -> (String, Vec<Value>) {
        let event = sign_event(json!({
            "created_at": now(), "kind": 1, "tags": [["t", tag]], "content": tag,
        }));
        let id = event["id"].as_str().unwrap().to_string();
        self.send(json!(["EVENT", event])).await;
        let frames = self.recv_until(|f| f[0] == "OK" && f[1] == id).await;
        assert_eq!(frames.last().unwrap()[2], true, "{frames:?}");
        (id, frames)
    }
}

fn is(frame: &Value, kind: &str, sub_id: &str) -> bool {
    frame[0] == kind && frame[1] == sub_id
}

fn delivers(frame: &Value, sub_id: &str, event_id: &str) -> bool {
    is(frame, "EVENT", sub_id) && frame[2]["id"] == event_id
}

struct Relay {
    handle: RelayHandle,
    ws_addr: std::net::SocketAddr,
    unix_path: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

impl Relay {
    async fn start() -> Self {
        let (dir, env) = wok_compat::temp_db();
        let unix_path = dir.path().join("wok.sock");
        let mut cfg = Config::default();
        cfg.db = dir.path().to_path_buf();
        cfg.relay.auth.enabled = false;
        // Many REQs and COUNTs from one address, faster than its budget.
        cfg.relay.abuse.enabled = false;
        cfg.relay.unix.enabled = true;
        cfg.relay.unix.path = unix_path.clone();
        let handle = wok_relay::start(env, cfg.clone()).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ws_addr = listener.local_addr().unwrap();
        let h = handle.clone();
        tokio::spawn(async move {
            let _ = wok_ws::serve_listener(h, listener).await;
        });
        let h = handle.clone();
        tokio::spawn(async move {
            let _ = wok_unix::serve(h, cfg).await;
        });
        wait_for(&unix_path).await;
        Self {
            handle,
            ws_addr,
            unix_path,
            _dir: dir,
        }
    }

    async fn clients(&self) -> [(&'static str, Wire); 2] {
        let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{}/", self.ws_addr))
            .await
            .unwrap();
        let unix = wok_unix::connect(&self.unix_path).await.unwrap();
        [
            ("websocket", Wire::Ws(Box::new(ws))),
            ("unix", Wire::Unix(unix)),
        ]
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.handle.request_shutdown();
    }
}

async fn wait_for(path: &Path) {
    for _ in 0..200 {
        if path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("{} never appeared", path.display());
}

fn valid_ids() -> Vec<String> {
    let mut ids: Vec<String> = [
        "é",
        "a\"b",
        "a\\b",
        "😀",
        "tab\there",
        "line\nbreak",
        "nul\0",
        "del\u{7f}",
        "</script>",
    ]
    .map(String::from)
    .into();
    // 64 characters, of one, two and four bytes each.
    ids.extend(["x", "é", "😀"].map(|c| c.repeat(64)));
    ids
}

/// History, EOSE, live delivery, COUNT, refusal and CLOSE for ids that the
/// relay used to refuse as having an invalid character, or as too long when
/// counted in bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn any_string_of_up_to_64_characters_is_a_subscription_id() {
    let relay = Relay::start().await;
    for (transport, mut wire) in relay.clients().await {
        for (i, sid) in valid_ids().iter().enumerate() {
            let sid = sid.as_str();
            let case = |what: &str| format!("{transport}-{i}-{what}");
            let (stored, _) = wire.publish(&case("stored")).await;

            let filter = json!({"kinds": [1], "#t": [case("stored"), case("live"), case("after")]});
            wire.send(json!(["REQ", sid, filter])).await;
            let frames = wire.recv_until(|f| is(f, "EOSE", sid)).await;
            assert!(
                frames.iter().any(|f| delivers(f, sid, &stored)),
                "{transport} {sid:?}: no history EVENT in {frames:?}"
            );

            let (live, mut frames) = wire.publish(&case("live")).await;
            if !frames.iter().any(|f| delivers(f, sid, &live)) {
                frames.extend(wire.recv_until(|f| delivers(f, sid, &live)).await);
            }

            wire.send(json!(["COUNT", sid, {"kinds": [1], "#t": [case("stored")]}]))
                .await;
            let frames = wire.recv_until(|f| is(f, "COUNT", sid)).await;
            assert_eq!(frames.last().unwrap()[2]["count"], 1, "{transport} {sid:?}");

            // A refusal names the id, and ends the subscription with it.
            wire.send(json!(["REQ", sid, {"kinds": [1], "nope": 1}]))
                .await;
            let frames = wire.recv_until(|f| is(f, "CLOSED", sid)).await;
            assert_eq!(
                frames.last().unwrap()[2],
                "unsupported: bad req: unrecognised filter item: nope"
            );
            let (after, mut late) = wire.publish(&case("after")).await;
            late.extend(wire.settle(Duration::from_millis(100)).await);
            assert!(
                !late.iter().any(|f| delivers(f, sid, &after)),
                "{transport} {sid:?}: delivered after CLOSED: {late:?}"
            );

            // CLOSE finds the id too.
            wire.send(json!(["REQ", sid, filter])).await;
            wire.recv_until(|f| is(f, "EOSE", sid)).await;
            wire.send(json!(["CLOSE", sid])).await;
            let (closed, mut late) = wire.publish(&case("after")).await;
            late.extend(wire.settle(Duration::from_millis(100)).await);
            assert!(
                !late.iter().any(|f| delivers(f, sid, &closed)),
                "{transport} {sid:?}: delivered after CLOSE: {late:?}"
            );
        }
    }
}

/// 65 characters is one too many, whatever their width, and the refusal
/// still names the id.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ids_over_64_characters_are_refused() {
    let relay = Relay::start().await;
    for (transport, mut wire) in relay.clients().await {
        for sid in ["x", "é", "😀"].map(|c| c.repeat(65)) {
            for cmd in ["REQ", "COUNT"] {
                wire.send(json!([cmd, sid, {"kinds": [1]}])).await;
                assert_eq!(
                    wire.next_frame(Duration::from_secs(3)).await.unwrap(),
                    json!([
                        "CLOSED",
                        sid,
                        "invalid: bad req: invalid subscription id length"
                    ]),
                    "{transport} {cmd}"
                );
            }
        }
    }
}

/// The relay keys subscriptions by the exact id: "é" as one code point and
/// as `e` plus a combining accent are two subscriptions, as are ids that
/// differ only by a backslash, and closing one leaves the other.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subscriptions_are_keyed_by_the_exact_id() {
    let relay = Relay::start().await;
    for (transport, mut wire) in relay.clients().await {
        for (kept, closed) in [("e\u{301}", "\u{e9}"), ("a\\\"b", "a\"b")] {
            let tag = format!("{transport}-{closed}");
            for sid in [kept, closed] {
                wire.send(json!(["REQ", sid, {"kinds": [1], "#t": [tag]}]))
                    .await;
                wire.recv_until(|f| is(f, "EOSE", sid)).await;
            }
            wire.send(json!(["CLOSE", closed])).await;
            let (event, mut frames) = wire.publish(&tag).await;
            if !frames.iter().any(|f| delivers(f, kept, &event)) {
                frames.extend(wire.recv_until(|f| delivers(f, kept, &event)).await);
            }
            frames.extend(wire.settle(Duration::from_millis(100)).await);
            assert!(
                !frames.iter().any(|f| delivers(f, closed, &event)),
                "{transport} {closed:?} outlived its CLOSE: {frames:?}"
            );
            wire.send(json!(["CLOSE", kept])).await;
        }
    }
}
