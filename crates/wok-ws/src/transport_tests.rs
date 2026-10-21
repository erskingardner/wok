//! Per-connection transport costs: idle release of permessage-deflate state.

#![allow(clippy::field_reassign_with_default)]
use super::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

fn relay(dir: &std::path::Path) -> Arc<RelayHandle> {
    let env = wok_db::Env::open(dir, wok_db::EnvOptions::for_tests()).unwrap();
    let mut cfg = Config::default();
    cfg.db = dir.to_path_buf();
    cfg.relay.auth.enabled = false;
    cfg.relay.auto_ping_seconds = 0;
    Arc::new(wok_relay::start(env, cfg).unwrap())
}

/// A client's half of a WebSocket that sees each server frame's wire size.
struct Client {
    io: DuplexStream,
    encoder: WsEncoder,
    parser: WsParser,
}

impl Client {
    fn new(io: DuplexStream, deflate: bool) -> Self {
        Self {
            io,
            encoder: WsEncoder::with_role(
                deflate.then(|| DeflateCtx::new(true)),
                frame::Role::Client,
            ),
            parser: WsParser::with_role(
                1 << 20,
                deflate.then(|| InflateCtx::new(true)),
                frame::Role::Client,
            ),
        }
    }

    async fn send(&mut self, msg: serde_json::Value) {
        let frame = self
            .encoder
            .encode_message(MessageKind::Text, msg.to_string().as_bytes())
            .unwrap();
        self.io.write_all(&frame).await.unwrap();
    }

    /// The next server frame: its payload size on the wire and its text.
    async fn frame(&mut self) -> (usize, String) {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut head = [0u8; 2];
            self.io.read_exact(&mut head).await.unwrap();
            let mut wire = head.to_vec();
            let len = match head[1] & 0x7f {
                126 => {
                    let mut ext = [0u8; 2];
                    self.io.read_exact(&mut ext).await.unwrap();
                    wire.extend_from_slice(&ext);
                    u16::from_be_bytes(ext) as usize
                }
                127 => panic!("unexpectedly large frame"),
                len => len as usize,
            };
            let mut payload = vec![0u8; len];
            self.io.read_exact(&mut payload).await.unwrap();
            wire.extend_from_slice(&payload);
            match self.parser.feed(&wire).unwrap().pop() {
                Some(WsEvent::Message(_, text)) => (len, String::from_utf8(text).unwrap()),
                other => panic!("expected a message, got {other:?}"),
            }
        })
        .await
        .expect("no frame from the relay")
    }

    /// REQ then CLOSE; returns the EOSE frame's payload size on the wire.
    async fn fetch(&mut self, sid: &str) -> usize {
        self.send(serde_json::json!(["REQ", sid, {"kinds": [1], "limit": 1}]))
            .await;
        let (len, text) = self.frame().await;
        assert_eq!(text, format!("[\"EOSE\",\"{sid}\"]"));
        self.send(serde_json::json!(["CLOSE", sid])).await;
        len
    }
}

/// A quiet connection drops its compressor and inflater, and both directions
/// keep context takeover across the gap: the client, which kept its own
/// window, decodes the fresh compressor's output, and the relay decodes the
/// client's back-references into messages sent before it went quiet.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_deflate_state_is_released_without_breaking_takeover() {
    let dir = tempfile::tempdir().unwrap();
    let handle = relay(dir.path());
    let (io, stream) = tokio::io::duplex(1 << 16);
    let check = Duration::from_millis(100);
    let task = tokio::spawn(handle_ws(
        stream,
        handle.clone(),
        "127.0.0.1:9000".parse().unwrap(),
        1 << 20,
        Some(Deflate {
            server_takeover: true,
            client_takeover: true,
        }),
        check,
    ));
    let mut client = Client::new(io, true);

    let fresh = client.fetch("q").await;
    let with_history = client.fetch("q").await;
    assert!(
        with_history < fresh,
        "the repeat EOSE should refer back: {with_history} vs {fresh}"
    );
    // Two whole checks without traffic release everything.
    tokio::time::sleep(check * 3).await;
    // The REQ is a back-reference into the client's earlier REQs; the EOSE
    // comes from a fresh compressor.
    assert_eq!(client.fetch("q").await, fresh);
    assert_eq!(client.fetch("q").await, with_history);

    drop(client);
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    handle.request_shutdown();
}

/// compression.slidingWindow = false governs only the relay's compressor. A
/// client that was not asked for client_no_context_takeover may still refer
/// back into its earlier messages, so the inflater must keep their history.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inflater_follows_the_client_takeover_not_the_sliding_window() {
    let dir = tempfile::tempdir().unwrap();
    let handle = relay(dir.path());
    let (io, stream) = tokio::io::duplex(1 << 16);
    let task = tokio::spawn(handle_ws(
        stream,
        handle.clone(),
        "127.0.0.1:9000".parse().unwrap(),
        1 << 20,
        Some(Deflate {
            server_takeover: false,
            client_takeover: true,
        }),
        DEFLATE_IDLE_CHECK,
    ));
    // The relay's compressor resets per message, so the client inflater may
    // keep context or not; the client's compressor keeps it.
    let mut client = Client::new(io, true);
    let first = client.fetch("q").await;
    assert_eq!(client.fetch("q").await, first, "no relay-side takeover");
    assert_eq!(client.fetch("q").await, first);
    drop(client);
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    handle.request_shutdown();
}
