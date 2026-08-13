//! End-to-end WebSocket and Unix interoperability.

use futures_util::{SinkExt, Stream, StreamExt};
use serde_json::json;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
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
    cfg.events.reject_older_than_secs = u64::MAX / 4;
    cfg
}

async fn recv_until<S>(ws: &mut S, pred: impl Fn(&str) -> bool) -> Vec<String>
where
    S: Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let mut out = Vec::new();
    for _ in 0..20 {
        match tokio::time::timeout(Duration::from_secs(2), ws.next()).await {
            Ok(Some(Ok(msg))) => {
                let t = msg.to_text().unwrap_or("").to_string();
                let hit = pred(&t);
                out.push(t);
                if hit {
                    break;
                }
            }
            _ => break,
        }
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_publish_and_subscribe() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let cfg = test_cfg(dir.path());
    let handle = wok_relay::start(env, cfg).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let h = handle.clone();
    tokio::spawn(async move {
        let _ = wok_ws::serve_listener(h, listener).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let url = format!("ws://{addr}/");
    let (mut ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("connect");
    let ev = sign_event(json!({
        "created_at": now_secs(),
        "kind": 1,
        "tags": [],
        "content": "e2e-ws",
    }));
    ws.send(Message::Text(json!(["EVENT", ev]).to_string().into()))
        .await
        .unwrap();
    let msgs = recv_until(&mut ws, |t| t.contains("\"OK\"")).await;
    assert!(
        msgs.iter()
            .any(|t| t.contains("\"OK\"") && t.contains("true")),
        "expected OK, got {msgs:?}"
    );

    ws.send(Message::Text(
        json!(["REQ", "s1", {"kinds":[1], "limit": 10}])
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let msgs = recv_until(&mut ws, |t| t.contains("EOSE")).await;
    assert!(
        msgs.iter().any(|t| t.contains("e2e-ws")),
        "expected historical EVENT, got {msgs:?}"
    );
    assert!(
        msgs.iter().any(|t| t.contains("EOSE")),
        "expected EOSE, got {msgs:?}"
    );

    ws.send(Message::Text(
        json!(["COUNT", "c1", {"kinds":[1]}]).to_string().into(),
    ))
    .await
    .unwrap();
    let msgs = recv_until(&mut ws, |t| t.contains("COUNT")).await;
    assert!(
        msgs.iter().any(|t| t.contains("COUNT")),
        "expected COUNT, got {msgs:?}"
    );

    handle.request_shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unix_publish_and_subscribe() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let sock = dir.path().join("wok.sock");
    let mut cfg = test_cfg(dir.path());
    cfg.relay.unix.enabled = true;
    cfg.relay.unix.path = sock.clone();
    let handle = wok_relay::start(env, cfg.clone()).unwrap();
    let h = handle.clone();
    let cfg2 = cfg.clone();
    tokio::spawn(async move {
        let _ = wok_unix::serve(h, cfg2).await;
    });
    tokio::time::sleep(Duration::from_millis(80)).await;

    let mut stream = wok_unix::connect(&sock).await.expect("unix connect");
    let ev = sign_event(json!({
        "created_at": now_secs(),
        "kind": 1,
        "tags": [],
        "content": "e2e-unix",
    }));
    wok_unix::write_frame(&mut stream, json!(["EVENT", ev]).to_string().as_bytes())
        .await
        .unwrap();
    let mut got_ok = false;
    let mut seen = Vec::new();
    for _ in 0..10 {
        let frame = tokio::time::timeout(
            Duration::from_secs(2),
            wok_unix::read_frame(&mut stream, 1_000_000),
        )
        .await;
        if let Ok(Ok(body)) = frame {
            let t = String::from_utf8_lossy(&body).into_owned();
            seen.push(t.clone());
            if t.contains("\"OK\"") && t.contains("true") {
                got_ok = true;
                break;
            }
        }
    }
    assert!(got_ok, "expected OK on unix, got {seen:?}");

    wok_unix::write_frame(
        &mut stream,
        json!(["REQ", "u1", {"kinds":[1]}]).to_string().as_bytes(),
    )
    .await
    .unwrap();
    let mut got_event = false;
    let mut got_eose = false;
    for _ in 0..20 {
        let frame = tokio::time::timeout(
            Duration::from_secs(2),
            wok_unix::read_frame(&mut stream, 1_000_000),
        )
        .await;
        if let Ok(Ok(body)) = frame {
            let t = String::from_utf8_lossy(&body);
            if t.contains("e2e-unix") {
                got_event = true;
            }
            if t.contains("EOSE") {
                got_eose = true;
                break;
            }
        }
    }
    assert!(
        got_event && got_eose,
        "unix REQ should return event and EOSE"
    );
    handle.request_shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_publish_unix_subscribe() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let sock = dir.path().join("wok.sock");
    let mut cfg = test_cfg(dir.path());
    cfg.relay.unix.enabled = true;
    cfg.relay.unix.path = sock.clone();
    let handle = wok_relay::start(env, cfg.clone()).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let h1 = handle.clone();
    tokio::spawn(async move {
        let _ = wok_ws::serve_listener(h1, listener).await;
    });
    let h2 = handle.clone();
    let cfg2 = cfg.clone();
    tokio::spawn(async move {
        let _ = wok_unix::serve(h2, cfg2).await;
    });
    tokio::time::sleep(Duration::from_millis(80)).await;

    let mut unix = wok_unix::connect(&sock).await.expect("unix");
    wok_unix::write_frame(
        &mut unix,
        json!(["REQ", "live", {"kinds":[1]}]).to_string().as_bytes(),
    )
    .await
    .unwrap();
    // Drain EOSE
    let _ = tokio::time::timeout(
        Duration::from_secs(2),
        wok_unix::read_frame(&mut unix, 1_000_000),
    )
    .await;

    let url = format!("ws://{addr}/");
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let ev = sign_event(json!({
        "created_at": now_secs(),
        "kind": 1,
        "tags": [],
        "content": "cross-ws-to-unix",
    }));
    ws.send(Message::Text(json!(["EVENT", ev]).to_string().into()))
        .await
        .unwrap();
    let _ = recv_until(&mut ws, |t| t.contains("\"OK\"")).await;

    let mut got = false;
    for _ in 0..20 {
        let frame = tokio::time::timeout(
            Duration::from_secs(2),
            wok_unix::read_frame(&mut unix, 1_000_000),
        )
        .await;
        if let Ok(Ok(body)) = frame {
            if String::from_utf8_lossy(&body).contains("cross-ws-to-unix") {
                got = true;
                break;
            }
        }
    }
    assert!(got, "unix subscriber should receive WS-published event");
    handle.request_shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unix_publish_ws_subscribe() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let sock = dir.path().join("wok.sock");
    let mut cfg = test_cfg(dir.path());
    cfg.relay.unix.enabled = true;
    cfg.relay.unix.path = sock.clone();
    let handle = wok_relay::start(env, cfg.clone()).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let h1 = handle.clone();
    tokio::spawn(async move {
        let _ = wok_ws::serve_listener(h1, listener).await;
    });
    let h2 = handle.clone();
    let cfg2 = cfg.clone();
    tokio::spawn(async move {
        let _ = wok_unix::serve(h2, cfg2).await;
    });
    tokio::time::sleep(Duration::from_millis(80)).await;

    let url = format!("ws://{addr}/");
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    ws.send(Message::Text(
        json!(["REQ", "live", {"kinds":[1]}]).to_string().into(),
    ))
    .await
    .unwrap();
    let _ = recv_until(&mut ws, |t| t.contains("EOSE")).await;

    let mut unix = wok_unix::connect(&sock).await.unwrap();
    let ev = sign_event(json!({
        "created_at": now_secs(),
        "kind": 1,
        "tags": [],
        "content": "cross-unix-to-ws",
    }));
    wok_unix::write_frame(&mut unix, json!(["EVENT", ev]).to_string().as_bytes())
        .await
        .unwrap();

    let msgs = recv_until(&mut ws, |t| t.contains("cross-unix-to-ws")).await;
    assert!(
        msgs.iter().any(|t| t.contains("cross-unix-to-ws")),
        "WS subscriber should receive unix-published event, got {msgs:?}"
    );
    handle.request_shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip11_http_document() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let mut cfg = test_cfg(dir.path());
    cfg.relay.info.pubkey =
        "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6".into();
    cfg.relay.info.terms = "https://example.com/tos".into();
    let handle = wok_relay::start(env, cfg).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let h = handle.clone();
    tokio::spawn(async move {
        let _ = wok_ws::serve_listener(h, listener).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let client = reqwest_get_nip11(addr).await;
    assert!(client["supported_nips"]
        .as_array()
        .unwrap()
        .iter()
        .any(|n| n == 1));
    assert_eq!(client["software"], "git+https://github.com/jeff/wok.git");
    // npub is converted to hex like C++.
    assert_eq!(
        client["pubkey"],
        "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"
    );
    assert_eq!(client["terms_of_service"], "https://example.com/tos");
    handle.request_shutdown();
}

async fn reqwest_get_nip11(addr: std::net::SocketAddr) -> serde_json::Value {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nAccept: application/nostr+json\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf);
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("{}");
    serde_json::from_str(body.trim()).unwrap_or(json!({}))
}
