#![allow(clippy::field_reassign_with_default)]
use super::*;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn review_kill_interrupts_blocked_websocket_write() {
    let dir = tempfile::tempdir().unwrap();
    let env = wok_db::Env::open(dir.path(), wok_db::EnvOptions::default()).unwrap();
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
        false,
        false,
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
