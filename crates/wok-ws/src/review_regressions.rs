#![allow(clippy::field_reassign_with_default)]
use super::*;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn review_kill_interrupts_blocked_websocket_write() {
    let dir = tempfile::tempdir().unwrap();
    let env = wok_db::Env::open(dir.path(), wok_db::EnvOptions::for_tests()).unwrap();
    let mut cfg = Config::default();
    cfg.relay.max_pending_outbound_bytes = 128;
    cfg.relay.auto_ping_seconds = 1;
    let handle = Arc::new(wok_relay::start(env, cfg).unwrap());
    // A one-byte write capacity forces the first NOTICE to block because
    // the peer deliberately never reads. Input and output are independent.
    let (mut peer, stream) = tokio::io::duplex(1);
    let mut task = tokio::spawn(handle_ws(
        stream,
        handle.clone(),
        "127.0.0.1:9000".parse().unwrap(),
        1024,
        None,
        DEFLATE_IDLE_CHECK,
    ));
    let mut encoder = WsEncoder::with_role(None, frame::Role::Client);
    peer.write_all(&encoder.encode_message(MessageKind::Text, b"x").unwrap())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    for _ in 0..30 {
        handle
            .client_message(1, TransportSource::Unix, "x".into())
            .await;
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while handle
            .metrics
            .slow_client_terminations
            .load(Ordering::Relaxed)
            == 0
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let terminated = tokio::time::timeout(Duration::from_millis(500), &mut task)
        .await
        .is_ok();
    if !terminated {
        task.abort();
        let _ = task.await;
    }
    handle.request_shutdown();
    drop(peer);
    assert!(
        terminated,
        "kill was signalled and counted, but blocked write kept the connection task alive"
    );
}

/// A client's half of a WebSocket over an in-memory stream.
struct Peer {
    io: tokio::io::DuplexStream,
    encoder: WsEncoder,
    parser: WsParser,
    events: std::collections::VecDeque<WsEvent>,
}

impl Peer {
    async fn send(&mut self, msg: serde_json::Value) {
        self.send_raw(msg.to_string().as_bytes()).await;
    }

    async fn send_raw(&mut self, text: &[u8]) {
        let frame = self
            .encoder
            .encode_message(MessageKind::Text, text)
            .unwrap();
        self.io.write_all(&frame).await.unwrap();
    }

    async fn control(&mut self, opcode: u8, payload: &[u8]) {
        let frame = self.encoder.encode_control(opcode, payload);
        self.io.write_all(&frame).await.unwrap();
    }

    async fn next(&mut self) -> WsEvent {
        use tokio::io::AsyncReadExt;
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(event) = self.events.pop_front() {
                    return event;
                }
                let mut buf = [0u8; 4096];
                let n = self.io.read(&mut buf).await.unwrap();
                assert!(n > 0, "relay closed the stream");
                self.events.extend(self.parser.feed(&buf[..n]).unwrap());
            }
        })
        .await
        .expect("no frame from the relay")
    }

    async fn next_text(&mut self) -> String {
        match self.next().await {
            WsEvent::Message(_, text) => String::from_utf8(text).unwrap(),
            _ => panic!("expected a message"),
        }
    }
}

fn signed_note() -> serde_json::Value {
    use secp256k1::{Keypair, SECP256K1};
    let kp = Keypair::new(SECP256K1, &mut rand::thread_rng());
    let mut event = serde_json::json!({
        "pubkey": hex::encode(kp.x_only_public_key().0.serialize()),
        "created_at": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        "kind": 1,
        "tags": [],
        "content": "while paused",
    });
    let id = wok_event::event_id_hash(&event).unwrap();
    event["id"] = hex::encode(id).into();
    event["sig"] = hex::encode(SECP256K1.sign_schnorr(&id, &kp).as_ref()).into();
    event
}

/// The largest message, and so the hold, in the paused-ingress tests.
const HOLD: usize = 4096;

/// A relay with one WebSocket client whose subscription "live" is open.
async fn paused_ingress_relay() -> (
    tempfile::TempDir,
    Arc<RelayHandle>,
    Peer,
    tokio::task::JoinHandle<()>,
) {
    paused_ingress_relay_with(HOLD, 1 << 16).await
}

/// `paused_ingress_relay` with a given largest message (and so hold) and
/// in-memory stream buffer size in each direction.
async fn paused_ingress_relay_with(
    max_message: usize,
    pipe: usize,
) -> (
    tempfile::TempDir,
    Arc<RelayHandle>,
    Peer,
    tokio::task::JoinHandle<()>,
) {
    let dir = tempfile::tempdir().unwrap();
    let env = wok_db::Env::open(dir.path(), wok_db::EnvOptions::for_tests()).unwrap();
    let mut cfg = Config::default();
    cfg.db = dir.path().to_path_buf();
    cfg.relay.auth.enabled = false;
    cfg.relay.auto_ping_seconds = 0;
    let handle = Arc::new(wok_relay::start(env, cfg).unwrap());
    let (io, stream) = tokio::io::duplex(pipe);
    let task = tokio::spawn(handle_ws(
        stream,
        handle.clone(),
        "127.0.0.1:9000".parse().unwrap(),
        max_message,
        None,
        DEFLATE_IDLE_CHECK,
    ));
    let mut peer = Peer {
        io,
        encoder: WsEncoder::with_role(None, frame::Role::Client),
        parser: WsParser::with_role(1 << 20, None, frame::Role::Client),
        events: Default::default(),
    };
    peer.send(serde_json::json!(["REQ", "live", {"kinds": [1]}]))
        .await;
    assert!(peer.next_text().await.contains("EOSE"));
    (dir, handle, peer, task)
}

async fn assert_connection_ends(handle: &RelayHandle, task: tokio::task::JoinHandle<()>) {
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("connection did not close")
        .unwrap();
    assert_eq!(handle.metrics.active_connections.load(Ordering::Relaxed), 0);
}

/// While ingress is paused (earlier work parked behind a busy worker), the
/// WebSocket keeps delivering outbound frames and answering control frames,
/// holds client messages until ingress resumes, and a client Close still
/// tears the connection down, even with the hold full.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn paused_ingress_keeps_websocket_output_and_control() {
    let (_dir, handle, mut peer, task) = paused_ingress_relay().await;
    let conn_id = 1;
    let reqs = || handle.metrics.client_req.load(Ordering::Relaxed);
    assert_eq!(reqs(), 1);

    handle.set_ingress_paused(conn_id, true);
    peer.send(serde_json::json!(["REQ", "held", {"limit": 0}]))
        .await;
    // Outbound still flows: another connection's event reaches the live sub.
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let publisher = handle.next_conn_id();
    handle.register(publisher, Outbound::new(tx, 0)).await;
    handle
        .client_message(
            publisher,
            TransportSource::Unix,
            serde_json::json!(["EVENT", signed_note()]).to_string(),
        )
        .await;
    let event = peer.next_text().await;
    assert!(event.starts_with("[\"EVENT\",\"live\""), "got {event}");
    // Control frames are still answered.
    peer.control(frame::OP_PING, b"still-there").await;
    assert!(matches!(peer.next().await, WsEvent::Pong(p) if p == b"still-there"));
    assert_eq!(reqs(), 1, "the held REQ reached the relay while paused");

    handle.set_ingress_paused(conn_id, false);
    assert!(peer.next_text().await.contains("\"EOSE\",\"held\""));
    assert_eq!(reqs(), 2);

    // Paused again with the hold filled to its limit, a Close still ends
    // the connection; the held messages go with it.
    handle.set_ingress_paused(conn_id, true);
    for _ in 0..HOLD / wok_relay::HELD_MESSAGE_OVERHEAD {
        peer.send_raw(b"").await;
    }
    peer.control(frame::OP_CLOSE, &[]).await;
    assert!(matches!(peer.next().await, WsEvent::Close(_)));
    assert_connection_ends(&handle, task).await;
    assert_eq!(reqs(), 2);
    handle.request_shutdown();
}

/// One maximum-size message, which with its overhead alone exceeds the hold,
/// is still held while paused without stopping reads: later control frames
/// and a Close are handled before ingress resumes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn paused_ingress_keeps_reading_after_a_maximum_size_message() {
    let (_dir, handle, mut peer, task) = paused_ingress_relay().await;
    handle.set_ingress_paused(1, true);
    peer.send_raw(&[b' '; HOLD]).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    peer.control(frame::OP_PING, b"after-max").await;
    assert!(matches!(peer.next().await, WsEvent::Pong(p) if p == b"after-max"));
    peer.control(frame::OP_CLOSE, &[]).await;
    assert!(matches!(peer.next().await, WsEvent::Close(_)));
    assert_connection_ends(&handle, task).await;
    handle.request_shutdown();
}

/// A client that keeps sending into a paused connection is closed once its
/// hold is full, even empty messages counting, instead of buffering without
/// bound until the worker recovers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn paused_ingress_closes_a_websocket_that_overflows_its_hold() {
    let (_dir, handle, mut peer, task) = paused_ingress_relay().await;
    handle.set_ingress_paused(1, true);
    for _ in 0..=HOLD / wok_relay::HELD_MESSAGE_OVERHEAD {
        peer.send_raw(b"").await;
    }
    assert_connection_ends(&handle, task).await;
    handle.request_shutdown();
}

/// Messages read just as ingress resumes, even a burst of them in one read,
/// queue behind a large hold rather than handing it over, so outbound frames
/// and Pongs are written between batches. The ingester is stalled so that
/// handing over the whole hold, more than the shared ingest queue takes,
/// would block the connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resumed_ingress_hands_over_a_large_hold_in_batches() {
    const HELD: usize = 6000;
    // Enough data frames in one read to walk the hold a batch per frame.
    const BURST: usize = 600;
    const PIPE: usize = 1 << 16;
    let (_dir, handle, mut peer, task) = paused_ingress_relay_with(1 << 20, PIPE).await;
    let conn_id = 1;
    handle.set_ingress_paused(conn_id, true);
    for _ in 0..HELD {
        peer.send(serde_json::json!(["CLOSE", "x"])).await;
    }
    peer.control(frame::OP_PING, b"held").await;
    assert!(matches!(peer.next().await, WsEvent::Pong(p) if p == b"held"));

    // Block the connection on writing Pongs the peer does not read, so the
    // next message is read only after ingress has resumed.
    for _ in 0..PIPE / 127 + 24 {
        peer.control(frame::OP_PING, &[b'p'; 125]).await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Queue an event for the live subscription behind those Pongs.
    let (observer_tx, mut observer) = tokio::sync::mpsc::unbounded_channel();
    let observer_id = handle.next_conn_id();
    handle
        .register(observer_id, Outbound::new(observer_tx, 0))
        .await;
    handle
        .client_message(
            observer_id,
            TransportSource::Unix,
            serde_json::json!(["REQ", "observer", {"kinds": [1]}]).to_string(),
        )
        .await;
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let publisher = handle.next_conn_id();
    handle.register(publisher, Outbound::new(tx, 0)).await;
    handle
        .client_message(
            publisher,
            TransportSource::Unix,
            serde_json::json!(["EVENT", signed_note()]).to_string(),
        )
        .await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(frame) = observer.recv().await {
            if frame.text.starts_with("[\"EVENT\",\"observer\"") {
                return;
            }
        }
    })
    .await
    .expect("the event was not published");
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Stall the ingester on the config lock, held off the runtime.
    let (locked_tx, locked_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let config = handle.config.clone();
    let stall = std::thread::spawn(move || {
        let _guard = config.write();
        locked_tx.send(()).unwrap();
        let _ = release_rx.recv();
    });
    locked_rx.recv().unwrap();

    let mut trigger = Vec::new();
    for _ in 0..BURST {
        trigger.extend(
            peer.encoder
                .encode_message(MessageKind::Text, br#"["CLOSE","x"]"#)
                .unwrap(),
        );
    }
    trigger.extend(
        peer.encoder
            .encode_message(
                MessageKind::Text,
                serde_json::json!(["REQ", "after", {"limit": 0}])
                    .to_string()
                    .as_bytes(),
            )
            .unwrap(),
    );
    trigger.extend(peer.encoder.encode_control(frame::OP_PING, b"after"));
    peer.io.write_all(&trigger).await.unwrap();
    handle.set_ingress_paused(conn_id, false);

    let (mut ponged, mut delivered) = (false, false);
    while !(ponged && delivered) {
        match peer.next().await {
            WsEvent::Pong(p) => ponged |= p == b"after",
            WsEvent::Message(_, text) => {
                let text = String::from_utf8(text).unwrap();
                assert!(text.starts_with("[\"EVENT\",\"live\""), "got {text}");
                delivered = true;
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    let closes = || handle.metrics.client_close.load(Ordering::Relaxed);
    assert!(closes() < HELD as u64);

    // Released, the rest of the hold goes through ahead of the new message.
    release_tx.send(()).unwrap();
    stall.join().unwrap();
    assert!(peer.next_text().await.contains("\"EOSE\",\"after\""));
    assert_eq!(closes(), (HELD + BURST) as u64);
    assert!(!task.is_finished(), "a resumed connection was disconnected");
    peer.control(frame::OP_CLOSE, &[]).await;
    assert!(matches!(peer.next().await, WsEvent::Close(_)));
    assert_connection_ends(&handle, task).await;
    handle.request_shutdown();
}
