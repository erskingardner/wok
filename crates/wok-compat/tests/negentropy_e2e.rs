//! NIP-77 negentropy e2e: tree-backed (stateless) and memory views must
//! survive past the first NEG-MSG, like C++ RelayNegentropy views.

use futures_util::{SinkExt, Stream, StreamExt};
use serde_json::json;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio_tungstenite::tungstenite::Message;
use wok_compat::sign_event;
use wok_db::{write_events, Env, EnvOptions, EventToWrite, NoopNegentropy};
use wok_event::{parse_and_verify_event, EventLimits, PackedEventView};
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

async fn ws_connect(
    addr: std::net::SocketAddr,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let url = format!("ws://{addr}/");
    let (ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    ws
}

async fn recv_matching(
    ws: &mut (impl Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin),
    want: &str,
) -> Vec<String> {
    let mut out = Vec::new();
    for _ in 0..20 {
        match tokio::time::timeout(Duration::from_secs(2), ws.next()).await {
            Ok(Some(Ok(msg))) => {
                let t = msg.to_text().unwrap_or("").to_string();
                let hit = t.contains(want);
                out.push(t);
                if hit {
                    return out;
                }
            }
            _ => break,
        }
    }
    out
}

async fn start_server(dir: &std::path::Path) -> (wok_relay::RelayHandle, std::net::SocketAddr) {
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

fn write_and_build_default_tree(dir: &std::path::Path) {
    let env = Env::open(dir, EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let mut evs = Vec::new();
    for i in 0..3u64 {
        let ev = sign_event(json!({
            "created_at": now_secs() - 100 + i,
            "kind": 1,
            "tags": [],
            "content": format!("neg-{i}"),
        }));
        let parsed =
            parse_and_verify_event(&ev, &EventLimits::default(), None, true, false).unwrap();
        evs.push(EventToWrite::new(parsed.packed.into_bytes(), parsed.json));
    }
    let mut txn = env.begin_rw().unwrap();
    write_events(&mut txn, &mut NoopNegentropy, &mut evs, false).unwrap();
    // The default "{}" filter is tree id 1 (created by ensure_initialized).
    {
        let mut tree = wok_negentropy::open_rw(&mut txn, 1).unwrap();
        for ev in &evs {
            let packed = PackedEventView::new(&ev.packed).unwrap();
            tree.insert(packed.created_at(), packed.id()).unwrap();
        }
        tree.backend.flush().unwrap();
    }
    txn.commit().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stateless_tree_view_survives_multiple_rounds() {
    let dir = tempfile::tempdir().unwrap();
    write_and_build_default_tree(dir.path());
    let (handle, addr) = start_server(dir.path()).await;
    let mut ws = ws_connect(addr).await;

    let mut client_store = wok_negentropy::Vector::new();
    client_store.seal().unwrap();
    let mut client = wok_negentropy::Negentropy::new(client_store, 60_000).unwrap();
    let init = client.initiate().unwrap();

    let open = json!(["NEG-OPEN", "s", {}, hex::encode(&init)]);
    ws.send(Message::Text(open.to_string().into()))
        .await
        .unwrap();
    let msgs = recv_matching(&mut ws, "\"NEG-MSG\"").await;
    assert!(
        msgs.iter().any(|t| t.contains("\"NEG-MSG\"")),
        "expected NEG-MSG reply to NEG-OPEN, got {msgs:?}"
    );

    // A second message on the same handle must still be answered (the C++
    // StatelessView persists); previously this failed with
    // "closed: unknown subscription handle".
    let again = json!(["NEG-MSG", "s", hex::encode(&init)]);
    ws.send(Message::Text(again.to_string().into()))
        .await
        .unwrap();
    let msgs = recv_matching(&mut ws, "\"NEG-").await;
    assert!(
        msgs.iter().any(|t| t.contains("\"NEG-MSG\"")),
        "expected NEG-MSG on round 2, got {msgs:?}"
    );

    // After NEG-CLOSE the handle is gone.
    ws.send(Message::Text(r#"["NEG-CLOSE","s"]"#.into()))
        .await
        .unwrap();
    ws.send(Message::Text(again.to_string().into()))
        .await
        .unwrap();
    let msgs = recv_matching(&mut ws, "\"NEG-ERR\"").await;
    assert!(
        msgs.iter()
            .any(|t| t.contains("closed: unknown subscription handle")),
        "expected NEG-ERR after close, got {msgs:?}"
    );

    handle.request_shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn memory_view_survives_multiple_rounds() {
    let dir = tempfile::tempdir().unwrap();
    write_and_build_default_tree(dir.path());
    let (handle, addr) = start_server(dir.path()).await;
    let mut ws = ws_connect(addr).await;

    let mut client_store = wok_negentropy::Vector::new();
    client_store.seal().unwrap();
    let mut client = wok_negentropy::Negentropy::new(client_store, 60_000).unwrap();
    let init = client.initiate().unwrap();

    // No tree matches this filter, so the relay builds a memory view.
    let open = json!(["NEG-OPEN", "m", {"kinds":[1]}, hex::encode(&init)]);
    ws.send(Message::Text(open.to_string().into()))
        .await
        .unwrap();
    let msgs = recv_matching(&mut ws, "\"NEG-MSG\"").await;
    assert!(
        msgs.iter().any(|t| t.contains("\"NEG-MSG\"")),
        "expected NEG-MSG reply to NEG-OPEN, got {msgs:?}"
    );

    let again = json!(["NEG-MSG", "m", hex::encode(&init)]);
    ws.send(Message::Text(again.to_string().into()))
        .await
        .unwrap();
    let msgs = recv_matching(&mut ws, "\"NEG-").await;
    assert!(
        msgs.iter().any(|t| t.contains("\"NEG-MSG\"")),
        "expected NEG-MSG on round 2, got {msgs:?}"
    );

    handle.request_shutdown();
}
