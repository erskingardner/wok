//! End-to-end WebSocket and Unix interoperability.

use base64::Engine;
use futures_util::{SinkExt, Stream, StreamExt};
use secp256k1::{Keypair, SECP256K1};
use serde_json::json;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio_tungstenite::tungstenite::Message;
use wok_compat::{sign_event, sign_event_with_key};
use wok_db::{Env, EnvOptions};
use wok_query::{HyperLogLog, NostrFilter};
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
async fn nip62_vanish_is_immediate_and_blocks_rebroadcast() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let cfg = test_cfg(dir.path());
    let handle = wok_relay::start(env, cfg).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let relay = handle.clone();
    tokio::spawn(async move {
        let _ = wok_ws::serve_listener(relay, listener).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/"))
        .await
        .unwrap();
    let author = {
        let mut rng = rand::thread_rng();
        Keypair::new(SECP256K1, &mut rng)
    };
    let now = now_secs();
    let old = sign_event_with_key(
        json!({
            "created_at": now - 60, "kind": 1, "tags": [], "content": "must-vanish"
        }),
        &author,
    );
    ws.send(Message::Text(json!(["EVENT", old]).to_string().into()))
        .await
        .unwrap();
    let accepted = recv_until(&mut ws, |text| text.contains("\"OK\"")).await;
    assert!(accepted.iter().any(|text| text.contains("true")));

    let invalid = sign_event_with_key(
        json!({
            "created_at": now - 20, "kind": 62, "tags": [], "content": ""
        }),
        &author,
    );
    ws.send(Message::Text(json!(["EVENT", invalid]).to_string().into()))
        .await
        .unwrap();
    let rejected = recv_until(&mut ws, |text| text.contains("\"OK\"")).await;
    assert!(rejected
        .iter()
        .any(|text| text.contains("false") && text.contains("not targeting")));

    let vanish = sign_event_with_key(
        json!({
            "created_at": now - 10,
            "kind": 62,
            "tags": [["relay", "ALL_RELAYS"], ["-"]],
            "content": ""
        }),
        &author,
    );
    ws.send(Message::Text(json!(["EVENT", vanish]).to_string().into()))
        .await
        .unwrap();
    let accepted = recv_until(&mut ws, |text| text.contains("\"OK\"")).await;
    assert!(accepted.iter().any(|text| text.contains("true")));

    ws.send(Message::Text(
        json!(["REQ", "after-vanish", {"kinds":[1]}])
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let history = recv_until(&mut ws, |text| text.contains("EOSE")).await;
    assert!(history.iter().any(|text| text.contains("EOSE")));
    assert!(history.iter().all(|text| !text.contains("must-vanish")));

    ws.send(Message::Text(
        json!(["COUNT", "after-vanish-count", {"kinds":[1]}])
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let count = recv_until(&mut ws, |text| text.contains("\"COUNT\"")).await;
    assert!(
        count.iter().any(|text| text.contains("\"count\":0")),
        "{count:?}"
    );

    let rebroadcast = sign_event_with_key(
        json!({
            "created_at": now - 30,
            "kind": 1,
            "tags": [["x", "new-id"]],
            "content": "must-stay-gone"
        }),
        &author,
    );
    ws.send(Message::Text(
        json!(["EVENT", rebroadcast]).to_string().into(),
    ))
    .await
    .unwrap();
    let rejected = recv_until(&mut ws, |text| text.contains("\"OK\"")).await;
    assert!(rejected
        .iter()
        .any(|text| text.contains("false") && text.contains("requested vanish")));

    ws.send(Message::Text(
        json!(["REQ", "request-record", {"kinds":[62]}])
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let request = recv_until(&mut ws, |text| text.contains("EOSE")).await;
    assert!(request
        .iter()
        .any(|text| text.contains("ALL_RELAYS") && text.contains("\"EVENT\"")));

    handle.request_shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip45_count_returns_mergeable_hll_for_canonical_tag_query() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let cfg = test_cfg(dir.path());
    let handle = wok_relay::start(env, cfg).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let relay = handle.clone();
    tokio::spawn(async move {
        let _ = wok_ws::serve_listener(relay, listener).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/"))
        .await
        .unwrap();
    let keys: Vec<Keypair> = {
        let mut rng = rand::thread_rng();
        (0..4).map(|_| Keypair::new(SECP256K1, &mut rng)).collect()
    };
    let target = sign_event(json!({
        "created_at": now_secs() - 20,
        "kind": 1,
        "tags": [],
        "content": "hll-target",
    }));
    let target_id = target["id"].as_str().unwrap().to_string();
    ws.send(Message::Text(json!(["EVENT", target]).to_string().into()))
        .await
        .unwrap();
    let _ = recv_until(&mut ws, |text| text.contains("\"OK\"")).await;

    for (index, key) in keys.iter().enumerate() {
        let reaction = sign_event_with_key(
            json!({
                "created_at": now_secs() - 10 + index as u64,
                "kind": 7,
                "tags": [["e", target_id]],
                "content": "+",
            }),
            key,
        );
        ws.send(Message::Text(json!(["EVENT", reaction]).to_string().into()))
            .await
            .unwrap();
        let accepted = recv_until(&mut ws, |text| text.contains("\"OK\"")).await;
        assert!(accepted.iter().any(|text| text.contains("true")));
    }
    let repeated_author = sign_event_with_key(
        json!({
            "created_at": now_secs(),
            "kind": 7,
            "tags": [["e", target_id]],
            "content": "second reaction from one author",
        }),
        &keys[0],
    );
    ws.send(Message::Text(
        json!(["EVENT", repeated_author]).to_string().into(),
    ))
    .await
    .unwrap();
    let accepted = recv_until(&mut ws, |text| text.contains("\"OK\"")).await;
    assert!(accepted.iter().any(|text| text.contains("true")));

    let count_filter = json!({"#e":[target_id], "kinds":[7]});
    ws.send(Message::Text(
        json!(["COUNT", "hll", count_filter]).to_string().into(),
    ))
    .await
    .unwrap();
    let response = recv_until(&mut ws, |text| text.contains("\"COUNT\"")).await;
    let body = response
        .iter()
        .find_map(|text| {
            serde_json::from_str::<serde_json::Value>(text)
                .ok()
                .filter(|value| value[0] == "COUNT")
                .map(|value| value[2].clone())
        })
        .expect("COUNT body");
    assert_eq!(body["count"], 5);
    let actual = body["hll"].as_str().expect("HLL response");
    assert_eq!(actual.len(), 512);

    let parsed_filter = NostrFilter::parse(&count_filter, 500, 3).unwrap();
    let mut expected = HyperLogLog::for_filter(&parsed_filter).unwrap();
    for key in &keys {
        let (pubkey, _) = key.x_only_public_key();
        expected.add_pubkey(&pubkey.serialize());
    }
    assert_eq!(actual, expected.encode_hex());

    let empty_target = "00".repeat(32);
    ws.send(Message::Text(
        json!(["COUNT", "empty-hll", {"#e":[empty_target], "kinds":[7]}])
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let empty = recv_until(&mut ws, |text| text.contains("empty-hll")).await;
    assert!(empty
        .iter()
        .any(|text| text.contains(&format!("\"hll\":\"{}\"", "00".repeat(256)))));

    ws.send(Message::Text(
        json!(["COUNT", "ambiguous-hll", {
            "#e":[target_id], "#p":["11".repeat(32)], "kinds":[7]
        }])
        .to_string()
        .into(),
    ))
    .await
    .unwrap();
    let ambiguous = recv_until(&mut ws, |text| text.contains("ambiguous-hll")).await;
    assert!(ambiguous
        .iter()
        .filter(|text| text.contains("\"COUNT\""))
        .all(|text| !text.contains("\"hll\"")));

    handle.request_shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip50_ranked_historical_and_live_search() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let cfg = test_cfg(dir.path());
    let handle = wok_relay::start(env, cfg).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let relay = handle.clone();
    tokio::spawn(async move {
        let _ = wok_ws::serve_listener(relay, listener).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/"))
        .await
        .unwrap();
    let now = now_secs();
    for event in [
        sign_event(json!({
            "created_at": now.saturating_sub(20),
            "kind": 1,
            "tags": [],
            "content": "exact nostr search phrase",
        })),
        sign_event(json!({
            "created_at": now.saturating_sub(10),
            "kind": 1,
            "tags": [],
            "content": "search across the newest nostr event",
        })),
        sign_event(json!({
            "created_at": now,
            "kind": 0,
            "tags": [],
            "content": "nostr search profile must be filtered",
        })),
    ] {
        ws.send(Message::Text(json!(["EVENT", event]).to_string().into()))
            .await
            .unwrap();
        let replies = recv_until(&mut ws, |text| text.contains("\"OK\"")).await;
        assert!(replies.iter().any(|text| text.contains("true")));
    }

    ws.send(Message::Text(
        json!(["REQ", "nip50-history", {"search":"nostr search", "kinds":[1], "limit":1}])
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let history = recv_until(&mut ws, |text| text.contains("EOSE")).await;
    let events: Vec<_> = history
        .iter()
        .filter(|text| text.contains("\"EVENT\""))
        .collect();
    assert_eq!(events.len(), 1, "expected post-ranking limit: {history:?}");
    assert!(
        events[0].contains("exact nostr search phrase"),
        "{history:?}"
    );

    ws.send(Message::Text(
        json!(["REQ", "nip50-live", {"search":"live needle", "kinds":[1]}])
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let initial = recv_until(&mut ws, |text| text.contains("EOSE")).await;
    assert!(initial.iter().any(|text| text.contains("EOSE")));

    let unrelated = sign_event(json!({
        "created_at": now + 1,
        "kind": 1,
        "tags": [],
        "content": "live haystack only",
    }));
    ws.send(Message::Text(
        json!(["EVENT", unrelated]).to_string().into(),
    ))
    .await
    .unwrap();
    let unrelated_replies = recv_until(&mut ws, |text| text.contains("\"OK\"")).await;
    assert!(unrelated_replies
        .iter()
        .all(|text| !text.contains("live haystack only")));

    let matching = sign_event(json!({
        "created_at": now + 2,
        "kind": 1,
        "tags": [],
        "content": "a LIVE needle arrived",
    }));
    ws.send(Message::Text(json!(["EVENT", matching]).to_string().into()))
        .await
        .unwrap();
    let live = recv_until(&mut ws, |text| text.contains("a LIVE needle arrived")).await;
    assert!(
        live.iter()
            .any(|text| text.contains("a LIVE needle arrived")),
        "expected matching live event: {live:?}"
    );

    handle.request_shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ephemeral_events_are_live_only_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let probe = env.clone();
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
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    ws.send(Message::Text(
        json!(["REQ", "live-ephemeral", {"kinds":[21000]}])
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let initial = recv_until(&mut ws, |text| text.contains("EOSE")).await;
    assert!(initial.iter().any(|text| text.contains("EOSE")));

    let event = sign_event(json!({
        "created_at": now_secs(),
        "kind": 21000,
        "tags": [],
        "content": "live-but-not-stored",
    }));
    ws.send(Message::Text(json!(["EVENT", event]).to_string().into()))
        .await
        .unwrap();
    let mut got_ok = false;
    let mut got_event = false;
    let mut messages = Vec::new();
    for _ in 0..20 {
        if let Ok(Some(Ok(message))) = tokio::time::timeout(Duration::from_secs(2), ws.next()).await
        {
            let text = message.to_text().unwrap_or("").to_string();
            got_ok |= text.contains("\"OK\"") && text.contains("true");
            got_event |= text.contains("live-but-not-stored");
            messages.push(text);
            if got_ok && got_event {
                break;
            }
        }
    }
    assert!(got_ok && got_event, "got {messages:?}");

    let (mut historical, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    historical
        .send(Message::Text(
            json!(["REQ", "history", {"kinds":[21000]}])
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    let history = recv_until(&mut historical, |text| text.contains("EOSE")).await;
    assert!(history.iter().any(|text| text.contains("EOSE")));
    assert!(!history
        .iter()
        .any(|text| text.contains("live-but-not-stored")));

    let integrity = wok_db::check_integrity(&probe.begin_ro().unwrap()).unwrap();
    assert_eq!(integrity.events, 0);
    assert_eq!(integrity.payloads, 0);
    assert_eq!(
        handle
            .metrics
            .ephemeral_events_total
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        handle.metrics.written_events_total.load(Ordering::Relaxed),
        0
    );
    handle.request_shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ttl_compatibility_mode_persists_ephemeral_events() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let probe = env.clone();
    let mut cfg = test_cfg(dir.path());
    cfg.events.ephemeral_persistence = wok_relay::EphemeralPersistence::Ttl;
    let handle = wok_relay::start(env, cfg).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let h = handle.clone();
    tokio::spawn(async move {
        let _ = wok_ws::serve_listener(h, listener).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/"))
        .await
        .unwrap();
    let event = sign_event(json!({
        "created_at": now_secs(),
        "kind": 21000,
        "tags": [],
        "content": "ttl-compatibility",
    }));
    ws.send(Message::Text(json!(["EVENT", event]).to_string().into()))
        .await
        .unwrap();
    let accepted = recv_until(&mut ws, |text| text.contains("\"OK\"")).await;
    assert!(accepted
        .iter()
        .any(|text| text.contains("\"OK\"") && text.contains("true")));

    ws.send(Message::Text(
        json!(["REQ", "ttl-history", {"kinds":[21000]}])
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let history = recv_until(&mut ws, |text| text.contains("EOSE")).await;
    assert!(history
        .iter()
        .any(|text| text.contains("ttl-compatibility")));
    let integrity = wok_db::check_integrity(&probe.begin_ro().unwrap()).unwrap();
    assert_eq!(integrity.events, 1);
    assert_eq!(
        handle
            .metrics
            .ephemeral_events_total
            .load(Ordering::Relaxed),
        0
    );
    assert_eq!(
        handle.metrics.written_events_total.load(Ordering::Relaxed),
        1
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
    cfg.relay.abuse.min_pow_difficulty = 20;
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
    assert_eq!(
        client["supported_nips"],
        json!([1, 9, 11, 13, 40, 45, 50, 62, 70, 77])
    );
    assert_eq!(client["limitation"]["max_event_tags"], 2000);
    assert_eq!(client["limitation"]["created_at_lower_limit"], u64::MAX / 4);
    assert_eq!(client["limitation"]["created_at_upper_limit"], 900);
    assert_eq!(client["limitation"]["default_limit"], 500);
    assert_eq!(client["limitation"]["max_total_events_per_req"], 2000);
    assert_eq!(client["limitation"]["min_pow_difficulty"], 20);
    assert_eq!(client["limitation"]["max_query_cost"], 1000);
    assert_eq!(
        client["software"],
        "git+https://github.com/erskingardner/wok.git"
    );
    // npub is converted to hex like C++.
    assert_eq!(
        client["pubkey"],
        "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"
    );
    assert_eq!(client["terms_of_service"], "https://example.com/tos");
    handle.request_shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip98_admin_http_route_authenticates_and_rejects_replay() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let key = Keypair::new(SECP256K1, &mut rand::thread_rng());
    let (pubkey, _) = key.x_only_public_key();
    let mut cfg = test_cfg(dir.path());
    cfg.admin.enabled = true;
    cfg.admin.public_url = format!("http://{addr}");
    cfg.admin.pubkeys = vec![hex::encode(pubkey.serialize())];
    let handle = wok_relay::start(env, cfg).unwrap();
    let h = handle.clone();
    tokio::spawn(async move {
        let _ = wok_ws::serve_listener(h, listener).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let shell = raw_http(
        addr,
        "GET /admin HTTP/1.1\r\nHost: ignored.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(shell.starts_with("HTTP/1.1 200"));
    assert!(shell.contains("Wok operator"));

    let unauthorized = raw_http(
        addr,
        "GET /admin/api/overview HTTP/1.1\r\nHost: ignored.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(unauthorized.starts_with("HTTP/1.1 401"));

    let absolute_url = format!("http://{addr}/admin/api/overview");
    let event = sign_event_with_key(
        json!({
            "created_at": now_secs(),
            "kind": 27235,
            "tags": [["u", absolute_url], ["method", "GET"]],
            "content": "",
        }),
        &key,
    );
    let authorization = base64::engine::general_purpose::STANDARD.encode(event.to_string());
    let request = format!(
        "GET /admin/api/overview HTTP/1.1\r\nHost: attacker-controlled.example\r\nAuthorization: Nostr {authorization}\r\nConnection: close\r\n\r\n"
    );
    let overview = raw_http(addr, &request).await;
    assert!(overview.starts_with("HTTP/1.1 200"), "{overview}");
    assert!(overview.contains("\"history\""));
    assert!(overview.contains("\"can_write_config\":false"));

    let replay = raw_http(addr, &request).await;
    assert!(replay.starts_with("HTTP/1.1 401"), "{replay}");
    assert!(replay.contains("already been used"));
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

async fn raw_http(addr: std::net::SocketAddr, request: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    String::from_utf8(response).unwrap()
}
