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
    let env = Env::open(dir, EnvOptions::for_tests()).unwrap();
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

/// Upgrade a raw socket, sending each of `offers` as its own
/// `Sec-WebSocket-Extensions` line, and return it with the
/// `Sec-WebSocket-Extensions` the relay answered, if any.
async fn upgrade(
    addr: std::net::SocketAddr,
    offers: &[&str],
) -> (tokio::net::TcpStream, Option<String>) {
    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut req = String::from("GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n");
    for offer in offers {
        req.push_str(&format!("Sec-WebSocket-Extensions: {offer}\r\n"));
    }
    req.push_str("\r\n");
    sock.write_all(req.as_bytes()).await.unwrap();
    let mut hdr = Vec::new();
    let mut byte = [0u8; 1];
    while !hdr.ends_with(b"\r\n\r\n") {
        sock.read_exact(&mut byte).await.unwrap();
        hdr.push(byte[0]);
        assert!(hdr.len() < 4096);
    }
    let hdr = String::from_utf8_lossy(&hdr);
    assert!(hdr.starts_with("HTTP/1.1 101"), "handshake failed: {hdr}");
    let extensions = hdr.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("sec-websocket-extensions")
            .then(|| value.trim().to_string())
    });
    (sock, extensions)
}

/// Read until `want` text messages have arrived.
async fn read_texts(
    sock: &mut tokio::net::TcpStream,
    parser: &mut WsParser,
    want: usize,
) -> Vec<String> {
    let mut texts = Vec::new();
    while texts.len() < want {
        let events = tokio::time::timeout(Duration::from_secs(5), read_events(sock, parser))
            .await
            .expect("relay went quiet")
            .expect("message did not decode");
        for ev in events {
            if let WsEvent::Message(MessageKind::Text, body) = ev {
                texts.push(String::from_utf8(body).unwrap());
            }
        }
    }
    texts
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn permessage_deflate_negotiated_and_roundtrips() {
    let dir = tempfile::tempdir().unwrap();
    let (handle, addr) = start(dir.path()).await;

    let (mut sock, extensions) = upgrade(addr, &["permessage-deflate"]).await;
    assert_eq!(extensions.as_deref(), Some("permessage-deflate"));

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

/// RFC 7692 §7: the relay accepts the first offer it can honour, echoing
/// the context-takeover parameters, and declines the rest.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deflate_offers_are_accepted_only_as_offered() {
    let dir = tempfile::tempdir().unwrap();
    let (handle, addr) = start(dir.path()).await;
    let cases: &[(&[&str], Option<&str>)] = &[
        (
            &["permessage-deflate; server_no_context_takeover"],
            Some("permessage-deflate; server_no_context_takeover"),
        ),
        (
            &["permessage-deflate; client_no_context_takeover"],
            Some("permessage-deflate; client_no_context_takeover"),
        ),
        (
            &["permessage-deflate; client_max_window_bits"],
            Some("permessage-deflate"),
        ),
        (
            &["permessage-deflate; server_max_window_bits=15"],
            Some("permessage-deflate; server_max_window_bits=15"),
        ),
        // A smaller server window can't be honoured, nor can parameters
        // that are unknown, repeated or invalid.
        (&["permessage-deflate; server_max_window_bits=10"], None),
        (&["permessage-deflate; mystery"], None),
        (
            &["permessage-deflate; server_no_context_takeover; server_no_context_takeover"],
            None,
        ),
        (&["permessage-deflate; client_max_window_bits=16"], None),
        // A fallback, in the same line or the next, is considered in turn.
        (
            &["permessage-deflate; server_max_window_bits=10; client_max_window_bits, permessage-deflate; client_max_window_bits"],
            Some("permessage-deflate"),
        ),
        (
            &[
                "permessage-deflate; server_max_window_bits=9",
                "permessage-deflate; server_no_context_takeover",
            ],
            Some("permessage-deflate; server_no_context_takeover"),
        ),
    ];
    for (offers, want) in cases {
        let (_sock, extensions) = upgrade(addr, offers).await;
        assert_eq!(extensions.as_deref(), *want, "offers {offers:?}");
    }
    handle.request_shutdown();
}

/// A client that offered server_no_context_takeover may inflate each message
/// on its own: none refers back into an earlier one, however alike they are.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_no_context_takeover_messages_inflate_alone() {
    let dir = tempfile::tempdir().unwrap();
    let (handle, addr) = start(dir.path()).await;
    let (mut sock, extensions) =
        upgrade(addr, &["permessage-deflate; server_no_context_takeover"]).await;
    assert_eq!(
        extensions.as_deref(),
        Some("permessage-deflate; server_no_context_takeover")
    );
    // A fresh inflater for every message, as such a client may use.
    let mut parser = WsParser::with_role(1 << 20, Some(InflateCtx::new(false)), Role::Client);
    let mut encoder = WsEncoder::with_role(Some(DeflateCtx::new(true)), Role::Client);

    let ev = sign_event(json!({
        "created_at": now_secs(),
        "kind": 1,
        "tags": [],
        "content": "no-context-takeover no-context-takeover no-context-takeover",
    }));
    let send = |encoder: &mut WsEncoder, msg: serde_json::Value| {
        encoder
            .encode_message(MessageKind::Text, msg.to_string().as_bytes())
            .unwrap()
    };
    let wire = send(&mut encoder, json!(["EVENT", ev]));
    sock.write_all(&wire).await.unwrap();
    let ok = read_texts(&mut sock, &mut parser, 1).await;
    assert!(ok[0].contains("\"OK\"") && ok[0].contains("true"), "{ok:?}");

    // The same event, then EOSE, four times over: with context takeover
    // each copy would refer back into the one before.
    let rounds = 4;
    for round in 0..rounds {
        let req = json!(["REQ", format!("sub{round}"), {"ids": [ev["id"]]}]);
        let wire = send(&mut encoder, req);
        sock.write_all(&wire).await.unwrap();
    }
    let texts = read_texts(&mut sock, &mut parser, rounds * 2).await;
    let events = texts
        .iter()
        .filter(|t| t.starts_with("[\"EVENT\"") && t.contains(ev["id"].as_str().unwrap()))
        .count();
    assert_eq!(events, rounds, "{texts:?}");
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
