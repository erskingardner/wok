//! Non-ASCII event id interop. The NIP-01 id preimage is UTF-8 JSON with all
//! non-escaped characters included verbatim, so an em-dash in `content` is
//! hashed as raw UTF-8 bytes. These tests pin wok's id check against ids
//! computed independently of wok's own serializer (plain serde_json like
//! nostr client libraries, plus a Python json/hashlib vector), at the
//! validation layer and end-to-end over every transport.

use futures_util::{SinkExt, StreamExt};
use secp256k1::{Keypair, SECP256K1};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;
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

fn nip01_id_independent(ev: &Value) -> [u8; 32] {
    let preimage = serde_json::to_string(&json!([
        0,
        ev["pubkey"],
        ev["created_at"],
        ev["kind"],
        ev["tags"],
        ev["content"],
    ]))
    .unwrap();
    let mut h = Sha256::new();
    h.update(preimage.as_bytes());
    h.finalize().into()
}

fn sign_independent(content: &str) -> Value {
    let mut rng = rand::thread_rng();
    let kp = Keypair::new(SECP256K1, &mut rng);
    let (xonly, _) = kp.x_only_public_key();
    let mut ev = json!({
        "pubkey": hex::encode(xonly.serialize()),
        "created_at": now_secs(),
        "kind": 1,
        "tags": [],
        "content": content,
    });
    let id = nip01_id_independent(&ev);
    ev["id"] = json!(hex::encode(id));
    let sig = SECP256K1.sign_schnorr(&id, &kp);
    ev["sig"] = json!(hex::encode(sig.as_ref()));
    ev
}

#[test]
fn wok_id_matches_python_raw_utf8_vector() {
    // Vector computed with python3 json.dumps(ensure_ascii=False) + hashlib.sha256.
    let ev = json!({
        "pubkey": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "created_at": 1700000000u64,
        "kind": 1,
        "tags": [],
        "content": "hello — world",
    });
    let id = wok_event::event_id_hash(&ev).unwrap();
    assert_eq!(
        hex::encode(id),
        "f8353245af01472e1a9b6685fc0850d8468c815e93b3b04841192bdaa07c12b4"
    );
}

#[test]
fn em_dash_event_passes_id_check_at_validation_layer() {
    let ev = sign_independent("hello — world");
    // What the client put on the wire (serde_json: raw UTF-8, no escaping).
    let wire = serde_json::to_string(&json!(["EVENT", ev])).unwrap();
    assert!(wire.contains('—'));
    let cmd = wok_relay::protocol::ClientCommand::parse(&wire).unwrap();
    let wok_relay::protocol::ClientCommand::Event(ev) = cmd else {
        panic!()
    };
    let parsed = wok_event::parse_and_verify_event(
        &ev,
        &wok_event::EventLimits::default(),
        None,
        true,
        false,
    );
    assert!(parsed.is_ok(), "em-dash event rejected: {parsed:?}");
}

#[test]
fn escaped_em_dash_wire_form_passes_id_check() {
    let ev = sign_independent("hello — world");
    // A client that escapes non-ASCII on the wire (\u2014) but hashes raw
    // UTF-8 per NIP-01.
    let wire = serde_json::to_string(&json!(["EVENT", ev]))
        .unwrap()
        .replace('—', "\\u2014");
    assert!(!wire.contains('—'));
    let cmd = wok_relay::protocol::ClientCommand::parse(&wire).unwrap();
    let wok_relay::protocol::ClientCommand::Event(ev) = cmd else {
        panic!()
    };
    let parsed = wok_event::parse_and_verify_event(
        &ev,
        &wok_event::EventLimits::default(),
        None,
        true,
        false,
    );
    assert!(parsed.is_ok(), "escaped em-dash event rejected: {parsed:?}");
}

#[allow(clippy::field_reassign_with_default)]
fn test_cfg(dir: &std::path::Path, deflate: bool, unix: bool) -> Config {
    let mut cfg = Config::default();
    cfg.db = dir.to_path_buf();
    cfg.relay.bind = "127.0.0.1".into();
    cfg.relay.port = 0;
    cfg.relay.auth.enabled = false;
    cfg.relay.compression_enabled = deflate;
    cfg.relay.unix.enabled = unix;
    if unix {
        cfg.relay.unix.path = dir.join("wok.sock");
    }
    cfg
}

async fn start_ws(
    dir: &std::path::Path,
    deflate: bool,
) -> (wok_relay::RelayHandle, std::net::SocketAddr) {
    let env = Env::open(dir, EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let cfg = test_cfg(dir, deflate, false);
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
async fn em_dash_event_accepted_over_plain_ws() {
    let dir = tempfile::tempdir().unwrap();
    let (handle, addr) = start_ws(dir.path(), false).await;
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/"))
        .await
        .unwrap();
    let ev = sign_independent("hello — world");
    let id = ev["id"].as_str().unwrap().to_string();
    ws.send(Message::Text(json!(["EVENT", ev]).to_string().into()))
        .await
        .unwrap();
    let mut verdict = None;
    for _ in 0..20 {
        match tokio::time::timeout(Duration::from_secs(2), ws.next()).await {
            Ok(Some(Ok(m))) => {
                let t = m.to_text().unwrap_or("").to_string();
                if t.contains("\"OK\"") {
                    verdict = Some(t);
                    break;
                }
            }
            _ => break,
        }
    }
    let verdict = verdict.expect("no OK received");
    assert!(
        verdict.contains("true"),
        "em-dash event rejected over plain ws: {verdict} (id {id})"
    );
    handle.request_shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn em_dash_event_accepted_over_deflate_ws() {
    let dir = tempfile::tempdir().unwrap();
    let (handle, addr) = start_ws(dir.path(), true).await;

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

    let mut parser = WsParser::with_role(1 << 20, Some(InflateCtx::new(true)), Role::Client);
    let mut encoder = WsEncoder::with_role(Some(DeflateCtx::new(true)), Role::Client);

    let ev = sign_independent("hello — world — deflate");
    let payload = json!(["EVENT", ev]).to_string();
    let wire = encoder
        .encode_message(MessageKind::Text, payload.as_bytes())
        .unwrap();
    sock.write_all(&wire).await.unwrap();

    let events = read_events(&mut sock, &mut parser).await.unwrap();
    let mut verdict = None;
    for ev in events {
        if let WsEvent::Message(MessageKind::Text, body) = ev {
            let text = String::from_utf8(body).unwrap();
            if text.contains("\"OK\"") {
                verdict = Some(text);
            }
        }
    }
    let verdict = verdict.expect("no OK received");
    assert!(
        verdict.contains("true"),
        "em-dash event rejected over deflate ws: {verdict}"
    );
    handle.request_shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn em_dash_event_accepted_over_unix_socket() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let cfg = test_cfg(dir.path(), false, true);
    let sock_path = cfg.relay.unix.path.clone();
    let handle = wok_relay::start(env, cfg.clone()).unwrap();
    let h = handle.clone();
    tokio::spawn(async move {
        let _ = wok_unix::serve(h, cfg).await;
    });
    for _ in 0..50 {
        if sock_path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let mut s = wok_unix::connect(&sock_path).await.unwrap();
    let ev = sign_independent("hello — world — unix");
    let payload = json!(["EVENT", ev]).to_string();
    wok_unix::write_frame(&mut s, payload.as_bytes())
        .await
        .unwrap();
    let body = wok_unix::read_frame(&mut s, 1 << 20).await.unwrap();
    let text = String::from_utf8(body).unwrap();
    assert!(
        text.contains("\"OK\"") && text.contains("true"),
        "em-dash event rejected over unix socket: {text}"
    );
    handle.request_shutdown();
}
