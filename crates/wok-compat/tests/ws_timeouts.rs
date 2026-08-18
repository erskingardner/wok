//! WebSocket connection-lifecycle timeouts (slowloris / slow-trickle
//! defenses): pre-upgrade HTTP header read deadline, idle-gap deadline while
//! a partial frame is buffered, and ping/pong liveness.

use futures_util::SinkExt;
use serde_json::json;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use wok_compat::sign_event;
use wok_db::{Env, EnvOptions};
use wok_relay::Config;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[allow(clippy::field_reassign_with_default)]
fn test_cfg(dir: &std::path::Path) -> Config {
    let mut cfg = Config::default();
    cfg.db = dir.to_path_buf();
    cfg.relay.bind = "127.0.0.1".into();
    cfg.relay.port = 0;
    cfg.relay.unix.enabled = false;
    cfg.relay.auth.enabled = false;
    cfg
}

async fn start(dir: &std::path::Path, cfg: Config) -> std::net::SocketAddr {
    let env = Env::open(dir, EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let handle = wok_relay::start(env, cfg).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = wok_ws::serve_listener(handle, listener).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    addr
}

/// Read until the peer closes (or errors) and assert it happens within
/// `within`. Any bytes the peer sends first (e.g. a 408) are consumed.
async fn expect_closed(stream: &mut TcpStream, within: Duration, what: &str) {
    let start = Instant::now();
    let mut buf = [0u8; 512];
    loop {
        match tokio::time::timeout(within, stream.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return,
            Ok(Ok(_)) => {
                assert!(
                    start.elapsed() < within,
                    "{what}: connection still open after {within:?}"
                );
            }
            Err(_) => panic!("{what}: connection still open after {within:?}"),
        }
    }
}

/// Complete a plain RFC 6455 handshake over a raw socket.
async fn ws_handshake(stream: &mut TcpStream) {
    stream
        .write_all(
            b"GET / HTTP/1.1\r\nHost: relay.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        )
        .await
        .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut byte))
            .await
            .expect("handshake response")
            .expect("handshake read");
        assert!(n == 1, "connection closed during handshake");
        head.push(byte[0]);
    }
    let head = String::from_utf8(head).unwrap();
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
}

/// Read one server frame (never masked). Returns (opcode, payload).
async fn read_server_frame(stream: &mut TcpStream, within: Duration) -> (u8, Vec<u8>) {
    let mut header = [0u8; 2];
    tokio::time::timeout(within, stream.read_exact(&mut header))
        .await
        .expect("frame header deadline")
        .expect("frame header");
    let opcode = header[0] & 0x0F;
    let mut len = (header[1] & 0x7F) as usize;
    assert_eq!(header[1] & 0x80, 0, "server frames must not be masked");
    if len == 126 {
        let mut ext = [0u8; 2];
        stream.read_exact(&mut ext).await.unwrap();
        len = u16::from_be_bytes(ext) as usize;
    }
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await.unwrap();
    (opcode, payload)
}

/// Build one masked client frame (FIN set).
fn masked_client_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x80 | opcode];
    let mask = [1u8, 2, 3, 4];
    if payload.len() < 126 {
        out.push(0x80 | payload.len() as u8);
    } else {
        out.push(0x80 | 126);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(&mask);
    for (i, b) in payload.iter().enumerate() {
        out.push(b ^ mask[i % 4]);
    }
    out
}

/// A masked client frame with no payload (used for pong).
fn masked_empty_frame(opcode: u8) -> Vec<u8> {
    masked_client_frame(opcode, &[])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_http_headers_are_closed_by_handshake_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = test_cfg(dir.path());
    cfg.relay.handshake_timeout_secs = 1;
    let addr = start(dir.path(), cfg).await;

    let mut stream = TcpStream::connect(addr).await.unwrap();
    // Partial request line, then silence: a classic slowloris park.
    stream.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();

    expect_closed(
        &mut stream,
        Duration::from_secs(10),
        "pre-upgrade slowloris",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trickled_partial_frame_is_closed_by_frame_read_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = test_cfg(dir.path());
    cfg.relay.frame_read_timeout_secs = 1;
    cfg.relay.auto_ping_seconds = 0; // isolate from ping liveness
    let addr = start(dir.path(), cfg).await;

    let mut stream = TcpStream::connect(addr).await.unwrap();
    ws_handshake(&mut stream).await;

    // Masked text frame declaring a 1000-byte payload, then a single byte.
    let mut frame = vec![0x81u8, 0x80 | 126];
    frame.extend_from_slice(&1000u16.to_be_bytes());
    frame.extend_from_slice(&[1, 2, 3, 4]); // mask key
    frame.push(b'x' ^ 1); // one masked payload byte, then silence
    stream.write_all(&frame).await.unwrap();

    expect_closed(
        &mut stream,
        Duration::from_secs(10),
        "slow-trickle partial frame",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_mid_fragmented_message_is_closed_by_frame_read_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = test_cfg(dir.path());
    cfg.relay.frame_read_timeout_secs = 1;
    cfg.relay.auto_ping_seconds = 0; // isolate from ping liveness
    let addr = start(dir.path(), cfg).await;

    let mut stream = TcpStream::connect(addr).await.unwrap();
    ws_handshake(&mut stream).await;

    // A complete, non-final text frame: the parser now holds an unfinished
    // fragmented message with an empty read buffer, then silence.
    let mut frame = vec![0x01u8, 0x80 | 5]; // FIN=0, opcode text, masked len 5
    frame.extend_from_slice(&[1, 2, 3, 4]); // mask key
    for (i, b) in b"hello".iter().enumerate() {
        frame.push(b ^ [1u8, 2, 3, 4][i % 4]);
    }
    stream.write_all(&frame).await.unwrap();

    expect_closed(&mut stream, Duration::from_secs(10), "mid-fragment idle").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn outbound_traffic_does_not_reset_partial_frame_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = test_cfg(dir.path());
    cfg.relay.frame_read_timeout_secs = 1;
    cfg.relay.auto_ping_seconds = 0; // isolate from ping liveness
    let addr = start(dir.path(), cfg).await;

    // Subscriber that leaves a partial frame pending, then goes silent.
    let mut silent = TcpStream::connect(addr).await.unwrap();
    ws_handshake(&mut silent).await;
    silent
        .write_all(&masked_client_frame(0x1, br#"["REQ","s",{}]"#))
        .await
        .unwrap();
    let mut frame = vec![0x81u8, 0x80 | 126]; // masked text, 16-bit length
    frame.extend_from_slice(&1000u16.to_be_bytes());
    frame.extend_from_slice(&[1, 2, 3, 4]); // mask key
    frame.push(b'x' ^ 1); // one masked payload byte, then silence
    silent.write_all(&frame).await.unwrap();

    // A publisher keeps outbound EVENT traffic flowing to that subscription
    // for far longer than the frame timeout. Every delivered EVENT cancels
    // and recreates the read branch of the connection's select loop; the
    // partial-frame deadline must survive that, not restart.
    let url = format!("ws://{addr}/");
    let (mut ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("publisher connect");
    let publisher = tokio::spawn(async move {
        for i in 0..30 {
            let ev = sign_event(json!({
                "created_at": now_secs(),
                "kind": 1,
                "tags": [],
                "content": format!("flood-{i}"),
            }));
            if ws
                .send(Message::Text(json!(["EVENT", ev]).to_string().into()))
                .await
                .is_err()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    });

    expect_closed(
        &mut silent,
        Duration::from_secs(4),
        "partial frame during outbound traffic",
    )
    .await;
    publisher.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unanswered_ping_closes_connection_but_pong_keeps_it_alive() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = test_cfg(dir.path());
    cfg.relay.auto_ping_seconds = 1;
    let addr = start(dir.path(), cfg).await;

    let mut stream = TcpStream::connect(addr).await.unwrap();
    ws_handshake(&mut stream).await;

    // First auto-ping arrives; answering it must keep the connection open.
    let (opcode, _) = read_server_frame(&mut stream, Duration::from_secs(5)).await;
    assert_eq!(opcode, 0x9, "expected ping");
    stream.write_all(&masked_empty_frame(0xA)).await.unwrap();

    // A second ping proves the pong satisfied the liveness check.
    let (opcode, _) = read_server_frame(&mut stream, Duration::from_secs(5)).await;
    assert_eq!(opcode, 0x9, "expected second ping after pong");

    // Stop answering: the next ping interval must close the connection.
    expect_closed(&mut stream, Duration::from_secs(10), "pong liveness").await;
}
