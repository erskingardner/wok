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
    start_server_with(dir, |_| {}).await
}

async fn start_server_with(
    dir: &std::path::Path,
    configure: impl FnOnce(&mut Config),
) -> (wok_relay::RelayHandle, std::net::SocketAddr) {
    let env = Env::open(dir, EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let mut cfg = test_cfg(dir);
    configure(&mut cfg);
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
    let env = Env::open(dir, EnvOptions::for_tests()).unwrap();
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

/// A NEG-MSG that does not reconcile closes its session with one NEG-ERR,
/// the same from a tree-backed view as from a memory view.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_neg_msg_that_does_not_reconcile_gets_one_neg_err_from_either_view() {
    let dir = tempfile::tempdir().unwrap();
    write_and_build_default_tree(dir.path());
    let (handle, addr) = start_server(dir.path()).await;
    let mut ws = ws_connect(addr).await;

    let mut client_store = wok_negentropy::Vector::new();
    client_store.seal().unwrap();
    let mut client = wok_negentropy::Negentropy::new(client_store, 60_000).unwrap();
    let init = hex::encode(client.initiate().unwrap());

    // "{}" is answered from its tree; no tree matches kind 1, so that view
    // is built in memory.
    for (sub_id, filter) in [("s", json!({})), ("m", json!({"kinds": [1]}))] {
        let open = json!(["NEG-OPEN", sub_id, filter, init]);
        ws.send(Message::Text(open.to_string().into()))
            .await
            .unwrap();
        let msgs = recv_matching(&mut ws, "\"NEG-MSG\"").await;
        assert!(msgs.iter().any(|t| t.contains("\"NEG-MSG\"")), "{msgs:?}");

        // "00" has no protocol version byte. The reply to a handle never
        // opened marks the end of the replies to it.
        for msg in [
            json!(["NEG-MSG", sub_id, "00"]),
            json!(["NEG-MSG", "never", init]),
        ] {
            ws.send(Message::Text(msg.to_string().into()))
                .await
                .unwrap();
        }
        let msgs = recv_matching(&mut ws, "\"never\"").await;
        assert_eq!(
            msgs,
            [
                json!(["NEG-ERR", sub_id, "error: invalid reconciliation message"]).to_string(),
                json!(["NEG-ERR", "never", "closed: unknown subscription handle"]).to_string(),
            ]
        );
    }
    handle.request_shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_malformed_neg_msg_still_closes_its_session() {
    // A malformed NEG-MSG that names a session tears it down with NEG-ERR.
    // When the malformed-message budget suppresses that reply, the session
    // must still close (#49).
    let dir = tempfile::tempdir().unwrap();
    write_and_build_default_tree(dir.path());
    let (handle, addr) = start_server_with(dir.path(), |cfg| {
        // One token a second: no refill can land mid-test.
        cfg.relay.abuse.invalid_rate_per_second = 1;
        cfg.relay.abuse.invalid_burst = 1;
    })
    .await;
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
    assert!(msgs.iter().any(|t| t.contains("\"NEG-MSG\"")), "{msgs:?}");

    // Spend the budget: the first malformed message is answered, the second
    // earns the one rate-limited NOTICE.
    for _ in 0..2 {
        ws.send(Message::Text("[\"NOT-A-COMMAND\"]".into()))
            .await
            .unwrap();
    }
    let msgs = recv_matching(&mut ws, "rate-limited").await;
    assert!(msgs.iter().any(|t| t.contains("rate-limited")), "{msgs:?}");

    ws.send(Message::Text(r#"["NEG-MSG","s",123]"#.into()))
        .await
        .unwrap();
    let again = json!(["NEG-MSG", "s", hex::encode(&init)]);
    ws.send(Message::Text(again.to_string().into()))
        .await
        .unwrap();
    let msgs = recv_matching(&mut ws, "\"NEG-ERR\"").await;
    assert!(
        msgs.iter()
            .any(|t| t.contains("closed: unknown subscription handle")),
        "session survived a refused malformed NEG-MSG: {msgs:?}"
    );
    handle.request_shutdown();
}

/// The writer keeps the negentropy trees current while NIP-77 is off, so
/// turning it back on, which reloads live, answers at once from a tree that
/// holds every event stored meanwhile. A tree that skipped them would need a
/// reindex with the relay stopped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trees_stay_current_while_nip77_is_off() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
    let mut cfg = test_cfg(dir.path());
    cfg.relay.negentropy_enabled = false;
    let handle = wok_relay::start(env.clone(), cfg).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(wok_ws::serve_listener(handle.clone(), listener));
    let mut ws = ws_connect(addr).await;

    for i in 0..3u64 {
        let event = sign_event(json!({
            "created_at": now_secs() - 100 + i,
            "kind": 1,
            "tags": [],
            "content": format!("stored while NIP-77 is off {i}"),
        }));
        ws.send(Message::Text(json!(["EVENT", event]).to_string().into()))
            .await
            .unwrap();
        let id = event["id"].as_str().unwrap();
        let msgs = recv_matching(&mut ws, id).await;
        assert!(
            msgs.iter()
                .any(|t| t.contains(&format!(r#""OK","{id}",true"#))),
            "{msgs:?}"
        );
    }

    let mut client_store = wok_negentropy::Vector::new();
    client_store.seal().unwrap();
    let mut client = wok_negentropy::Negentropy::new(client_store, 60_000).unwrap();
    let init = hex::encode(client.initiate().unwrap());
    let open = json!(["NEG-OPEN", "s", {}, init]).to_string();
    ws.send(Message::Text(open.clone().into())).await.unwrap();
    let msgs = recv_matching(&mut ws, "\"NEG-ERR\"").await;
    assert!(
        msgs.iter().any(|t| t.contains("negentropy is disabled")),
        "{msgs:?}"
    );
    {
        let txn = env.begin_ro().unwrap();
        assert_eq!(wok_negentropy::verify_tree(&txn, 1, "{}").unwrap(), 3);
    }

    handle.config.write().relay.negentropy_enabled = true;
    ws.send(Message::Text(open.into())).await.unwrap();
    let msgs = recv_matching(&mut ws, "\"NEG-").await;
    let reply: serde_json::Value = serde_json::from_str(msgs.last().unwrap()).unwrap();
    assert_eq!(reply[0], "NEG-MSG", "{msgs:?}");
    let (mut have, mut need) = (Vec::new(), Vec::new());
    client
        .reconcile_with_ids(
            &hex::decode(reply[2].as_str().unwrap()).unwrap(),
            &mut have,
            &mut need,
        )
        .unwrap();
    assert_eq!((have.len(), need.len()), (0, 3));

    handle.request_shutdown();
}
