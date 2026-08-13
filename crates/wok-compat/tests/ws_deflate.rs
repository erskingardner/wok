//! permessage-deflate e2e: handshake negotiation + compressed frames both
//! directions, driven over a raw socket with wok-ws's codec in client mode.

use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;
use wok_compat::sign_event;
use wok_db::{Env, EnvOptions};
use wok_relay::Config;
use wok_ws::frame::{
    read_events, DeflateCtx, InflateCtx, MessageKind, Role, WsEncoder, WsEvent, WsParser,
};

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
    cfg.relay.compression_enabled = true;
    cfg
}

async fn start(dir: &std::path::Path) -> (wok_relay::RelayHandle, std::net::SocketAddr) {
    let env = Env::open(dir, EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let cfg = test_cfg(dir);
    let handle = wok_relay::start(env, cfg).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let h = handle.clone();
    tokio::spawn(async move {
        let _ = wok_ws::serve_listener(h, listener).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    (handle, addr)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn permessage_deflate_negotiated_and_roundtrips() {
    let dir = tempfile::tempdir().unwrap();
    let (handle, addr) = start(dir.path()).await;

    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n";
    sock.write_all(req.as_bytes()).await.unwrap();
    let mut hdr = Vec::new();
    let mut byte = [0u8; 1];
    while !hdr.ends_with(b"\r\n\r\n") {
        sock.read_exact(&mut byte).await.unwrap();
        hdr.push(byte[0]);
        assert!(hdr.len() < 4096);
    }
    let hdr = String::from_utf8_lossy(&hdr);
    assert!(hdr.contains("101"), "handshake failed: {hdr}");
    assert!(
        hdr.to_ascii_lowercase()
            .contains("sec-websocket-extensions: permessage-deflate"),
        "extension not negotiated: {hdr}"
    );

    let mut parser = WsParser::with_role(1 << 20, Some(InflateCtx::new(true)), Role::Client);
    let mut encoder = WsEncoder::with_role(Some(DeflateCtx::new(true)), Role::Client);

    // Send a compressed EVENT.
    let ev = sign_event(json!({
        "created_at": now_secs(),
        "kind": 1,
        "tags": [],
        "content": "deflate-e2e deflate-e2e deflate-e2e deflate-e2e",
    }));
    let payload = json!(["EVENT", ev]).to_string();
    let wire = encoder
        .encode_message(MessageKind::Text, payload.as_bytes())
        .unwrap();
    sock.write_all(&wire).await.unwrap();

    // The OK should come back compressed (RSV1) and inflate to accepted=true.
    let events = read_events(&mut sock, &mut parser).await.unwrap();
    let mut got_ok = false;
    for ev in events {
        if let WsEvent::Message(MessageKind::Text, body) = ev {
            let text = String::from_utf8(body).unwrap();
            if text.contains("\"OK\"") {
                assert!(text.contains("true"), "got {text}");
                got_ok = true;
            }
        }
    }
    assert!(got_ok);
    handle.request_shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_extension_offer_still_plain() {
    let dir = tempfile::tempdir().unwrap();
    let (handle, addr) = start(dir.path()).await;
    // tungstenite client (no deflate): confirms the plain path still works.
    let url = format!("ws://{addr}/");
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let ev = sign_event(json!({
        "created_at": now_secs(),
        "kind": 1,
        "tags": [],
        "content": "plain-e2e",
    }));
    ws.send(Message::Text(json!(["EVENT", ev]).to_string().into()))
        .await
        .unwrap();
    for _ in 0..20 {
        match tokio::time::timeout(Duration::from_secs(2), ws.next()).await {
            Ok(Some(Ok(m))) => {
                let t = m.to_text().unwrap_or("").to_string();
                if t.contains("\"OK\"") {
                    assert!(t.contains("true"));
                    handle.request_shutdown();
                    return;
                }
            }
            _ => break,
        }
    }
    panic!("no OK received");
}
