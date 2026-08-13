//! The req-monitor must pick up writes made by *other* processes (or other
//! Env handles) via the data.mdb file watcher, like C++ RelayReqMonitor's
//! file_change_monitor.

use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio_tungstenite::tungstenite::Message;
use wok_compat::sign_event;
use wok_db::{write_events, Env, EnvOptions, EventToWrite, NoopNegentropy};
use wok_event::{parse_and_verify_event, EventLimits};
use wok_relay::Config;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[allow(clippy::field_reassign_with_default)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn external_writer_triggers_live_delivery() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let mut cfg = Config::default();
    cfg.db = dir.path().to_path_buf();
    cfg.relay.bind = "127.0.0.1".into();
    cfg.relay.port = 0;
    cfg.relay.unix.enabled = false;
    cfg.relay.auth.enabled = false;
    let handle = wok_relay::start(env, cfg).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let h = handle.clone();
    tokio::spawn(async move {
        let _ = wok_ws::serve_listener(h, listener).await;
    });
    tokio::time::sleep(Duration::from_millis(80)).await;

    let url = format!("ws://{addr}/");
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    ws.send(Message::Text(
        json!(["REQ", "live", {"kinds":[1]}]).to_string().into(),
    ))
    .await
    .unwrap();
    // Wait for EOSE before the external write.
    for _ in 0..20 {
        match tokio::time::timeout(Duration::from_secs(2), ws.next()).await {
            Ok(Some(Ok(m))) if m.to_text().unwrap_or("").contains("EOSE") => break,
            Ok(Some(Ok(_))) => continue,
            _ => panic!("no EOSE"),
        }
    }

    // Write directly through a second Env handle, bypassing the relay's
    // writer thread entirely (this is what a co-resident C++ strfry or
    // `wok import` does).
    let env2 = Env::open(
        dir.path(),
        EnvOptions {
            create_dir: false,
            ..EnvOptions::default()
        },
    )
    .unwrap();
    let ev = sign_event(json!({
        "created_at": now_secs(),
        "kind": 1,
        "tags": [],
        "content": "external-write",
    }));
    let parsed = parse_and_verify_event(&ev, &EventLimits::default(), None, true, false).unwrap();
    let mut evs = vec![EventToWrite::new(parsed.packed.into_bytes(), parsed.json)];
    {
        let mut txn = env2.begin_rw().unwrap();
        write_events(&mut txn, &mut NoopNegentropy, &mut evs, false).unwrap();
        txn.commit().unwrap();
    }

    let mut got = false;
    for _ in 0..40 {
        match tokio::time::timeout(Duration::from_millis(500), ws.next()).await {
            Ok(Some(Ok(m))) => {
                if m.to_text().unwrap_or("").contains("external-write") {
                    got = true;
                    break;
                }
            }
            _ => continue,
        }
    }
    assert!(
        got,
        "live subscription should receive externally-written event"
    );
    handle.request_shutdown();
}
