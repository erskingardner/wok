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
    cfg
}

fn test_env(dir: &std::path::Path) -> Env {
    Env::open(
        dir,
        EnvOptions {
            map_size: 64 * 1024 * 1024,
            ..EnvOptions::default()
        },
    )
    .unwrap()
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
    let env = test_env(dir.path());
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
    // NIP-67: the one stored match was sent.
    assert_eq!(
        msgs.last().map(String::as_str),
        Some(r#"["EOSE","s1",["finish"]]"#),
        "{msgs:?}"
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
async fn events_survive_their_publisher_disconnecting_immediately() {
    // Bots, CLI tools and backgrounded mobile apps publish and hang up
    // without waiting for OK. A validated EVENT must be stored anyway; the
    // writer used to drop events whose connection closed in the same batch.
    let dir = tempfile::tempdir().unwrap();
    let env = test_env(dir.path());
    env.ensure_initialized().unwrap();
    let handle = wok_relay::start(env, test_cfg(dir.path())).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let h = handle.clone();
    tokio::spawn(async move {
        let _ = wok_ws::serve_listener(h, listener).await;
    });
    let url = format!("ws://{addr}/");

    let mut publishers = Vec::new();
    for _ in 0..8 {
        publishers.push(tokio_tungstenite::connect_async(&url).await.unwrap().0);
    }
    let mut ids = Vec::new();
    for (index, mut ws) in publishers.into_iter().enumerate() {
        let event = sign_event(json!({
            "created_at": now_secs(),
            "kind": 1,
            "tags": [],
            "content": format!("publish and hang up {index}"),
        }));
        ids.push(event["id"].as_str().unwrap().to_owned());
        ws.send(Message::Text(json!(["EVENT", event]).to_string().into()))
            .await
            .unwrap();
        ws.close(None).await.unwrap();
    }
    ids.sort();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let stored = loop {
        let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
        ws.send(Message::Text(
            json!(["REQ", "check", {"ids": ids}]).to_string().into(),
        ))
        .await
        .unwrap();
        let mut stored: Vec<String> = recv_until(&mut ws, |t| t.contains("EOSE"))
            .await
            .iter()
            .filter_map(|t| {
                let frame: serde_json::Value = serde_json::from_str(t).ok()?;
                (frame[0] == "EVENT").then(|| frame[2]["id"].as_str().unwrap().to_owned())
            })
            .collect();
        stored.sort();
        if stored == ids || tokio::time::Instant::now() > deadline {
            break stored;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(stored, ids, "every validated EVENT must be stored");
    handle.request_shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_accepts_events_beyond_the_legacy_nip44_ceiling() {
    let dir = tempfile::tempdir().unwrap();
    let env = test_env(dir.path());
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
    let large_content = "x".repeat(256 * 1024);
    for (kind, tags) in [
        (445, Vec::new()),
        (1059, vec![json!(["p", "11".repeat(32)])]),
    ] {
        let event = sign_event(json!({
            "created_at": now_secs(),
            "kind": kind,
            "tags": tags,
            "content": large_content,
        }));
        let frame = json!(["EVENT", event]).to_string();
        assert!(frame.len() > 131_072);
        ws.send(Message::Text(frame.into())).await.unwrap();
        let replies = recv_until(&mut ws, |text| text.contains("\"OK\"")).await;
        assert!(
            replies
                .iter()
                .any(|text| text.contains("\"OK\"") && text.contains("true")),
            "kind {kind} was not accepted: {replies:?}"
        );
    }

    handle.request_shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip91_historical_live_and_count_share_and_semantics() {
    let dir = tempfile::tempdir().unwrap();
    let env = test_env(dir.path());
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
    for (content, tags) in [
        ("nip91-black", vec!["meme", "cat", "black"]),
        ("nip91-white", vec!["meme", "cat", "white"]),
        ("nip91-missing-or", vec!["meme", "cat"]),
        ("nip91-missing-and", vec!["meme", "black"]),
    ] {
        let event = sign_event(json!({
            "created_at":now,
            "kind":1,
            "tags":tags.into_iter().map(|value| json!(["t", value])).collect::<Vec<_>>(),
            "content":content,
        }));
        ws.send(Message::Text(json!(["EVENT", event]).to_string().into()))
            .await
            .unwrap();
        let replies = recv_until(&mut ws, |text| text.contains("\"OK\"")).await;
        assert!(replies.iter().any(|text| text.contains("true")));
    }

    let filter = json!({
        "kinds":[1],
        "&t":["meme", "cat"],
        "#t":["meme", "cat", "black", "white"]
    });
    ws.send(Message::Text(
        json!(["REQ", "nip91-live", filter.clone()])
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let history = recv_until(&mut ws, |text| text.contains("EOSE")).await;
    assert!(history.iter().any(|text| text.contains("nip91-black")));
    assert!(history.iter().any(|text| text.contains("nip91-white")));
    assert!(history
        .iter()
        .all(|text| !text.contains("nip91-missing-or") && !text.contains("nip91-missing-and")));

    ws.send(Message::Text(
        json!(["COUNT", "nip91-count", filter]).to_string().into(),
    ))
    .await
    .unwrap();
    let count = recv_until(&mut ws, |text| text.contains("COUNT")).await;
    assert!(
        count.iter().any(|text| text.contains("\"count\":2")),
        "expected exact NIP-91 count: {count:?}"
    );
    assert!(count.iter().all(|text| !text.contains("\"hll\"")));

    let live = sign_event(json!({
        "created_at":now + 1,
        "kind":1,
        "tags":[["t","meme"],["t","cat"],["t","black"]],
        "content":"nip91-live-match",
    }));
    ws.send(Message::Text(json!(["EVENT", live]).to_string().into()))
        .await
        .unwrap();
    let live_replies = recv_until(&mut ws, |text| text.contains("nip91-live-match")).await;
    assert!(live_replies
        .iter()
        .any(|text| text.contains("nip91-live-match")));

    handle.request_shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip62_vanish_is_immediate_and_blocks_rebroadcast() {
    let dir = tempfile::tempdir().unwrap();
    let env = test_env(dir.path());
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
    let env = test_env(dir.path());
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

    let parsed_filter = NostrFilter::parse(&count_filter, 500, 3, 16).unwrap();
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
    let env = test_env(dir.path());
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
    let env = test_env(dir.path());
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
    let env = test_env(dir.path());
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
    let env = test_env(dir.path());
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
                // NIP-67: the one stored match was sent.
                assert_eq!(t, r#"["EOSE","u1",["finish"]]"#);
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
    let env = test_env(dir.path());
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
    let env = test_env(dir.path());
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
    let env = test_env(dir.path());
    env.ensure_initialized().unwrap();
    let mut cfg = test_cfg(dir.path());
    cfg.relay.info.pubkey =
        "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6".into();
    cfg.relay.info.terms = "https://example.com/tos".into();
    cfg.relay.abuse.min_pow_difficulty = 20;
    cfg.events.reject_older_than_secs = 86_400;
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
        json!([1, 9, 11, 13, 40, 45, 50, 62, 67, 70, 77, 91])
    );
    assert_eq!(client["limitation"]["max_event_tags"], 5000);
    assert_eq!(client["limitation"]["max_message_length"], 2_097_152);
    assert_eq!(client["limitation"]["created_at_lower_limit"], 86_400);
    assert_eq!(client["limitation"]["created_at_upper_limit"], 900);
    assert_eq!(client["limitation"]["max_limit"], 2000);
    assert_eq!(client["limitation"]["default_limit"], 2000);
    assert_eq!(client["limitation"]["max_total_events_per_req"], 10_000);
    assert_eq!(client["limitation"]["min_pow_difficulty"], 20);
    assert_eq!(client["limitation"]["max_query_work"], 20_000);
    assert_eq!(client["limitation"]["max_tags_per_filter"], 8);
    assert_eq!(client["limitation"]["max_and_entries"], 16);
    // NIP-11: `software` MUST be a URL to the project's homepage.
    assert_eq!(client["software"], "https://github.com/erskingardner/wok");
    // npub is converted to hex like C++.
    assert_eq!(
        client["pubkey"],
        "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"
    );
    assert_eq!(client["terms_of_service"], "https://example.com/tos");
    handle.request_shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_is_served_on_a_single_endpoint() {
    let dir = tempfile::tempdir().unwrap();
    let env = test_env(dir.path());
    env.ensure_initialized().unwrap();
    let handle = wok_relay::start(env, test_cfg(dir.path())).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let h = handle.clone();
    tokio::spawn(async move {
        let _ = wok_ws::serve_listener(h, listener).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // NIP-01: path segments do not change the relay, so only the root
    // accepts connections and serves the relay documents.
    for path in ["/foo", "/foo/bar", "//", "/admin/x"] {
        match tokio_tungstenite::connect_async(format!("ws://{addr}{path}")).await {
            Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
                assert_eq!(response.status(), 404, "{path}")
            }
            other => panic!("{path} must not upgrade: {:?}", other.map(|_| ())),
        }
        let nip11 = raw_http(
            addr,
            &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/nostr+json\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert!(nip11.starts_with("HTTP/1.1 404"), "{path}: {nip11}");
        let page = raw_http(
            addr,
            &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert!(page.starts_with("HTTP/1.1 404"), "{path}: {page}");
    }

    for url in [format!("ws://{addr}"), format!("ws://{addr}/?client=x")] {
        let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
        ws.send(Message::Text(
            json!(["REQ", "root", {"limit": 0}]).to_string().into(),
        ))
        .await
        .unwrap();
        let msgs = recv_until(&mut ws, |t| t.contains("EOSE")).await;
        assert!(msgs.iter().any(|t| t.contains("EOSE")), "{url}: {msgs:?}");
    }
    let nip11 = raw_http(
        addr,
        "GET /?client=x HTTP/1.1\r\nHost: localhost\r\nAccept: application/nostr+json\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(nip11.starts_with("HTTP/1.1 200"), "{nip11}");
    assert!(nip11.contains("\"supported_nips\""), "{nip11}");
    let metrics = raw_http(
        addr,
        "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(metrics.starts_with("HTTP/1.1 200"), "{metrics}");
    handle.request_shutdown();
}

fn assert_cors(response: &str) {
    let headers = response
        .split("\r\n\r\n")
        .next()
        .unwrap()
        .to_ascii_lowercase();
    for header in [
        "access-control-allow-origin: *",
        "access-control-allow-headers: content-type, authorization, accept",
        "access-control-allow-methods: get, post, options",
    ] {
        assert!(headers.contains(header), "missing {header:?}: {response}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip11_omits_created_at_lower_limit_without_a_bound() {
    let dir = tempfile::tempdir().unwrap();
    let env = test_env(dir.path());
    env.ensure_initialized().unwrap();
    let cfg = test_cfg(dir.path());
    assert_eq!(cfg.events.reject_older_than_secs, 0);
    let handle = wok_relay::start(env, cfg).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let h = handle.clone();
    tokio::spawn(async move {
        let _ = wok_ws::serve_listener(h, listener).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let limitation = &reqwest_get_nip11(addr).await["limitation"];
    assert_eq!(
        limitation.get("created_at_lower_limit"),
        None,
        "{limitation}"
    );
    assert_eq!(limitation["created_at_upper_limit"], 900);
    handle.request_shutdown();
}

/// The query-work ceiling is advertised only while it refuses something:
/// with abuse controls on and a nonzero value.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip11_advertises_max_query_work_only_while_it_applies() {
    let dir = tempfile::tempdir().unwrap();
    let env = test_env(dir.path());
    env.ensure_initialized().unwrap();
    let handle = wok_relay::start(env, test_cfg(dir.path())).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let h = handle.clone();
    tokio::spawn(async move {
        let _ = wok_ws::serve_listener(h, listener).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let advertised = |limitation: &serde_json::Value| limitation.get("max_query_work").cloned();
    let limitation = &reqwest_get_nip11(addr).await["limitation"];
    assert_eq!(advertised(limitation), Some(json!(20_000)), "{limitation}");
    handle.config.write().relay.abuse.max_query_work = 0;
    let limitation = &reqwest_get_nip11(addr).await["limitation"];
    assert_eq!(advertised(limitation), None, "{limitation}");
    {
        let mut cfg = handle.config.write();
        cfg.relay.abuse.max_query_work = 20_000;
        cfg.relay.abuse.enabled = false;
    }
    let limitation = &reqwest_get_nip11(addr).await["limitation"];
    assert_eq!(advertised(limitation), None, "{limitation}");
    handle.request_shutdown();
}

/// NIP-11 says what a client must do before it may read or write:
/// `auth_required` follows the read policy, and `restricted_writes` the
/// write policy and proof of work, as each is enforced.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip11_advertises_access_requirements_as_enforced() {
    let dir = tempfile::tempdir().unwrap();
    let env = test_env(dir.path());
    env.ensure_initialized().unwrap();
    let mut cfg = test_cfg(dir.path());
    cfg.relay.auth.enabled = true;
    cfg.relay.auth.service_url = "wss://relay.example.com".into();
    let handle = wok_relay::start(env, cfg).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let h = handle.clone();
    tokio::spawn(async move {
        let _ = wok_ws::serve_listener(h, listener).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let flags = |limitation: &serde_json::Value| {
        (
            limitation["auth_required"].clone(),
            limitation["restricted_writes"].clone(),
        )
    };
    let limitation = &reqwest_get_nip11(addr).await["limitation"];
    assert_eq!(limitation["max_subid_length"], 64, "{limitation}");
    assert_eq!(flags(limitation), (json!(false), json!(false)));

    handle.config.write().relay.auth.read_policy = wok_relay::AccessPolicy::Members;
    let limitation = &reqwest_get_nip11(addr).await["limitation"];
    assert_eq!(flags(limitation), (json!(true), json!(false)));
    // While AUTH cannot succeed, clients are not told to try it: reads are
    // refused with `restricted:` instead, and NIP-42 is not advertised.
    handle.config.write().relay.auth.service_url.clear();
    let nip11 = reqwest_get_nip11(addr).await;
    assert_eq!(flags(&nip11["limitation"]), (json!(false), json!(false)));
    assert!(!nip11["supported_nips"]
        .as_array()
        .unwrap()
        .contains(&json!(42)));
    handle.config.write().relay.auth.service_url = "wss://relay.example.com".into();
    {
        let mut cfg = handle.config.write();
        cfg.relay.auth.read_policy = wok_relay::AccessPolicy::Open;
        cfg.relay.auth.write_policy = wok_relay::AccessPolicy::Authenticated;
    }
    let limitation = &reqwest_get_nip11(addr).await["limitation"];
    assert_eq!(flags(limitation), (json!(false), json!(true)));
    {
        let mut cfg = handle.config.write();
        cfg.relay.auth.write_policy = wok_relay::AccessPolicy::Open;
        cfg.relay.abuse.min_pow_difficulty = 20;
    }
    let limitation = &reqwest_get_nip11(addr).await["limitation"];
    assert_eq!(flags(limitation), (json!(false), json!(true)));
    // Proof of work is not checked with abuse controls off, nor advertised.
    handle.config.write().relay.abuse.enabled = false;
    let limitation = &reqwest_get_nip11(addr).await["limitation"];
    assert_eq!(flags(limitation), (json!(false), json!(false)));
    assert_eq!(limitation["min_pow_difficulty"], 0);
    handle.request_shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip11_and_nip86_accept_cors_requests() {
    let dir = tempfile::tempdir().unwrap();
    let env = test_env(dir.path());
    env.ensure_initialized().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let admin_key = Keypair::new(SECP256K1, &mut rand::thread_rng());
    let mut cfg = test_cfg(dir.path());
    cfg.admin.enabled = true;
    cfg.admin.public_url = format!("http://{addr}");
    cfg.admin.pubkeys = vec![hex::encode(admin_key.x_only_public_key().0.serialize())];
    let handle = wok_relay::start(env, cfg).unwrap();
    let h = handle.clone();
    tokio::spawn(async move {
        let _ = wok_ws::serve_listener(h, listener).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // NIP-11: relays MUST accept CORS requests. A browser NIP-86 tool sends
    // this preflight before its POST.
    let preflight = raw_http(
        addr,
        &format!("OPTIONS / HTTP/1.1\r\nHost: {addr}\r\nOrigin: https://manager.example\r\nAccess-Control-Request-Method: POST\r\nAccess-Control-Request-Headers: authorization, content-type\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert!(preflight.starts_with("HTTP/1.1 204"), "{preflight}");
    assert!(!preflight.contains("<html"), "{preflight}");
    assert_cors(&preflight);

    // Accept is a media-range list, not one exact string.
    let nip11 = raw_http(
        addr,
        "GET / HTTP/1.1\r\nHost: localhost\r\nAccept: application/nostr+json, application/json;q=0.9\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(nip11.starts_with("HTTP/1.1 200"), "{nip11}");
    assert!(nip11.contains("\"supported_nips\""), "{nip11}");
    assert_cors(&nip11);
    assert!(
        nip11.to_ascii_lowercase().contains("vary: accept"),
        "{nip11}"
    );
    let page = raw_http(
        addr,
        "GET / HTTP/1.1\r\nHost: localhost\r\nAccept: text/html,*/*;q=0.8\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(page.contains("<html"), "{page}");
    assert_cors(&page);
    assert!(page.to_ascii_lowercase().contains("vary: accept"), "{page}");

    // NIP-86 replies carry the headers too, refusals included.
    let body = json!({"method": "supportedmethods", "params": []}).to_string();
    let unauthorized = raw_http(
        addr,
        &format!(
            "POST / HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/nostr+json+rpc\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
    .await;
    assert!(unauthorized.starts_with("HTTP/1.1 401"), "{unauthorized}");
    assert_cors(&unauthorized);
    let authorized = raw_http(addr, &nip86_request(addr, &admin_key, &body)).await;
    assert!(authorized.starts_with("HTTP/1.1 200"), "{authorized}");
    assert!(authorized.contains("banpubkey"), "{authorized}");
    assert_cors(&authorized);
    handle.request_shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip98_admin_http_route_authenticates_and_rejects_replay() {
    let dir = tempfile::tempdir().unwrap();
    let env = test_env(dir.path());
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

/// POST a NIP-86 management RPC signed with `key`. The `u` tag deliberately
/// uses the ws:// form to exercise the relay's URL normalization.
async fn nip86_rpc(
    addr: std::net::SocketAddr,
    key: &Keypair,
    method: &str,
    params: serde_json::Value,
) -> (String, serde_json::Value) {
    use sha2::Digest;
    let body = json!({"method": method, "params": params}).to_string();
    let payload = hex::encode(sha2::Sha256::digest(body.as_bytes()));
    let nonce = hex::encode(rand::random::<[u8; 16]>());
    let event = sign_event_with_key(
        json!({
            "created_at": now_secs(),
            "kind": 27235,
            "tags": [
                ["u", format!("ws://{addr}")],
                ["method", "POST"],
                ["payload", payload],
                ["nonce", nonce],
            ],
            "content": "",
        }),
        key,
    );
    let authorization = base64::engine::general_purpose::STANDARD.encode(event.to_string());
    let request = format!(
        "POST / HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Nostr {authorization}\r\nContent-Type: application/nostr+json+rpc\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let raw = raw_http(addr, &request).await;
    let status = raw.lines().next().unwrap_or("").to_string();
    let parsed: serde_json::Value =
        serde_json::from_str(raw.split("\r\n\r\n").nth(1).unwrap_or("{}").trim())
            .unwrap_or(json!({}));
    (status, parsed)
}

async fn ws_publish<S>(ws: &mut S, event: serde_json::Value) -> Vec<String>
where
    S: Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
        + futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error>
        + Unpin,
{
    ws.send(Message::Text(json!(["EVENT", event]).to_string().into()))
        .await
        .unwrap();
    recv_until(ws, |t| t.contains("\"OK\"")).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip86_management_api_e2e() {
    let dir = tempfile::tempdir().unwrap();
    // Small map: the suite default reserves 10TB of virtual space per relay
    // and concurrent relays can exceed the host's VM budget.
    let env = Env::open(
        dir.path(),
        EnvOptions {
            map_size: 64 * 1024 * 1024,
            ..EnvOptions::default()
        },
    )
    .unwrap();
    env.ensure_initialized().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let admin_key = Keypair::new(SECP256K1, &mut rand::thread_rng());
    let (admin_pubkey, _) = admin_key.x_only_public_key();
    let alice_key = Keypair::new(SECP256K1, &mut rand::thread_rng());
    let (alice_pubkey, _) = alice_key.x_only_public_key();
    let alice_hex = hex::encode(alice_pubkey.serialize());
    let mod_key = Keypair::new(SECP256K1, &mut rand::thread_rng());
    let (mod_pubkey, _) = mod_key.x_only_public_key();
    let mod_hex = hex::encode(mod_pubkey.serialize());

    let mut cfg = test_cfg(dir.path());
    cfg.admin.enabled = true;
    cfg.admin.public_url = format!("http://{addr}");
    cfg.admin.pubkeys = vec![hex::encode(admin_pubkey.serialize())];
    let handle = wok_relay::start(env, cfg).unwrap();
    let h = handle.clone();
    tokio::spawn(async move {
        let _ = wok_ws::serve_listener(h, listener).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // NIP-11 advertises the management API only when the admin surface is on.
    let nip11 = reqwest_get_nip11(addr).await;
    assert!(
        nip11["supported_nips"]
            .as_array()
            .unwrap()
            .contains(&json!(86)),
        "NIP-11 should advertise 86, got {nip11}"
    );

    // Unauthenticated and non-manager requests are rejected with 401.
    let body = json!({"method": "supportedmethods", "params": []}).to_string();
    let unauth = raw_http(
        addr,
        &format!(
            "POST / HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/nostr+json+rpc\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        ),
    )
    .await;
    assert!(unauth.starts_with("HTTP/1.1 401"), "{unauth}");
    let (status, _) = nip86_rpc(addr, &alice_key, "supportedmethods", json!([])).await;
    assert!(status.starts_with("HTTP/1.1 401"), "{status}");

    let (status, result) = nip86_rpc(addr, &admin_key, "supportedmethods", json!([])).await;
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    assert!(
        result["result"]
            .as_array()
            .unwrap()
            .contains(&json!("banpubkey")),
        "{result}"
    );

    // Alice publishes; her event is served historically and counted.
    let url = format!("ws://{addr}/");
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let ev1 = sign_event_with_key(
        json!({"created_at": now_secs(), "kind": 1, "tags": [], "content": "nip86-e2e-one"}),
        &alice_key,
    );
    let ev1_id = ev1["id"].as_str().unwrap().to_string();
    let msgs = ws_publish(&mut ws, ev1.clone()).await;
    assert!(msgs.iter().any(|t| t.contains("true")), "{msgs:?}");
    ws.send(Message::Text(
        json!(["REQ", "s1", {"authors": [alice_hex], "limit": 10}])
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let msgs = recv_until(&mut ws, |t| t.contains("EOSE")).await;
    assert!(msgs.iter().any(|t| t.contains("nip86-e2e-one")), "{msgs:?}");

    // Ban alice: writes rejected, stored events suppressed from REQ and COUNT.
    let (_, result) = nip86_rpc(addr, &admin_key, "banpubkey", json!([alice_hex, "spam"])).await;
    assert_eq!(result["result"], json!(true), "{result}");
    let (_, result) = nip86_rpc(addr, &admin_key, "listbannedpubkeys", json!([])).await;
    assert!(
        result["result"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["pubkey"] == json!(alice_hex) && entry["reason"] == json!("spam")),
        "{result}"
    );
    let ev2 = sign_event_with_key(
        json!({"created_at": now_secs(), "kind": 1, "tags": [], "content": "nip86-e2e-two"}),
        &alice_key,
    );
    let msgs = ws_publish(&mut ws, ev2).await;
    assert!(
        msgs.iter()
            .any(|t| t.contains("false") && t.contains("restricted")),
        "{msgs:?}"
    );
    ws.send(Message::Text(
        json!(["REQ", "s2", {"authors": [alice_hex], "limit": 10}])
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let msgs = recv_until(&mut ws, |t| t.contains("EOSE")).await;
    assert!(
        !msgs.iter().any(|t| t.contains("nip86-e2e-one")),
        "banned author's stored events must be suppressed, got {msgs:?}"
    );
    ws.send(Message::Text(
        json!(["COUNT", "c1", {"kinds": [1]}]).to_string().into(),
    ))
    .await
    .unwrap();
    let msgs = recv_until(&mut ws, |t| t.contains("COUNT")).await;
    assert!(
        msgs.iter().any(|t| t.contains("\"count\":0")),
        "banned author's events must not be counted, got {msgs:?}"
    );

    // Unban restores visibility: bans suppress, they do not delete.
    let (_, result) = nip86_rpc(addr, &admin_key, "unbanpubkey", json!([alice_hex])).await;
    assert_eq!(result["result"], json!(true), "{result}");
    ws.send(Message::Text(
        json!(["REQ", "s3", {"authors": [alice_hex], "limit": 10}])
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let msgs = recv_until(&mut ws, |t| t.contains("EOSE")).await;
    assert!(
        msgs.iter().any(|t| t.contains("nip86-e2e-one")),
        "unban must restore suppressed events, got {msgs:?}"
    );

    // Event-level ban and allowevent.
    let (_, result) = nip86_rpc(addr, &admin_key, "banevent", json!([ev1_id, "illegal"])).await;
    assert_eq!(result["result"], json!(true), "{result}");
    ws.send(Message::Text(
        json!(["REQ", "s4", {"ids": [ev1_id]}]).to_string().into(),
    ))
    .await
    .unwrap();
    let msgs = recv_until(&mut ws, |t| t.contains("EOSE")).await;
    assert!(
        !msgs.iter().any(|t| t.contains("nip86-e2e-one")),
        "banned event must be suppressed, got {msgs:?}"
    );
    let (_, result) = nip86_rpc(addr, &admin_key, "unbanevent", json!([ev1_id])).await;
    assert_eq!(result["result"], json!(true), "{result}");
    let (_, result) = nip86_rpc(addr, &admin_key, "listbannedevents", json!([])).await;
    assert_eq!(result["result"], json!([]), "{result}");
    let (_, result) = nip86_rpc(addr, &admin_key, "listallowedevents", json!([])).await;
    assert_eq!(
        result["result"],
        json!([]),
        "unbanevent must not allow the event: {result}"
    );
    ws.send(Message::Text(
        json!(["REQ", "s5", {"ids": [ev1_id]}]).to_string().into(),
    ))
    .await
    .unwrap();
    let msgs = recv_until(&mut ws, |t| t.contains("EOSE")).await;
    assert!(
        msgs.iter().any(|t| t.contains("nip86-e2e-one")),
        "unbanevent must restore the event, got {msgs:?}"
    );

    // allowevent and banevent move the event between the two lists.
    let (_, result) = nip86_rpc(addr, &admin_key, "banevent", json!([ev1_id, "illegal"])).await;
    assert_eq!(result["result"], json!(true), "{result}");
    let (_, result) = nip86_rpc(addr, &admin_key, "allowevent", json!([ev1_id, "fine"])).await;
    assert_eq!(result["result"], json!(true), "{result}");
    let (_, result) = nip86_rpc(addr, &admin_key, "listbannedevents", json!([])).await;
    assert_eq!(result["result"], json!([]), "{result}");
    let (_, result) = nip86_rpc(addr, &admin_key, "listallowedevents", json!([])).await;
    assert_eq!(
        result["result"],
        json!([{"id": ev1_id, "reason": "fine"}]),
        "{result}"
    );
    let (_, result) = nip86_rpc(addr, &admin_key, "unallowevent", json!([ev1_id])).await;
    assert_eq!(result["result"], json!(true), "{result}");
    let (_, result) = nip86_rpc(addr, &admin_key, "listallowedevents", json!([])).await;
    assert_eq!(result["result"], json!([]), "{result}");
    let (_, result) = nip86_rpc(addr, &admin_key, "listbannedevents", json!([])).await;
    assert_eq!(
        result["result"],
        json!([]),
        "unallowevent must not ban the event: {result}"
    );

    // A NIP-56 report feeds the moderation queue; banevent dequeues it.
    let report = sign_event_with_key(
        json!({
            "created_at": now_secs(),
            "kind": 1984,
            "tags": [["e", ev1_id]],
            "content": "spam report",
        }),
        &alice_key,
    );
    let msgs = ws_publish(&mut ws, report).await;
    assert!(msgs.iter().any(|t| t.contains("true")), "{msgs:?}");
    let (_, result) = nip86_rpc(addr, &admin_key, "listeventsneedingmoderation", json!([])).await;
    assert!(
        result["result"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["id"] == json!(ev1_id)
                && entry["reason"].as_str().unwrap().contains("spam report")),
        "{result}"
    );
    let (_, result) = nip86_rpc(addr, &admin_key, "banevent", json!([ev1_id])).await;
    assert_eq!(result["result"], json!(true), "{result}");
    let (_, result) = nip86_rpc(addr, &admin_key, "listeventsneedingmoderation", json!([])).await;
    assert!(
        !result["result"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["id"] == json!(ev1_id)),
        "banevent must clear the moderation queue entry, got {result}"
    );
    let (_, result) = nip86_rpc(addr, &admin_key, "allowevent", json!([ev1_id])).await;
    assert_eq!(result["result"], json!(true), "{result}");

    // Roles: moderators ban but cannot change relay configuration.
    let (_, result) = nip86_rpc(
        addr,
        &admin_key,
        "createrole",
        json!(["vip", "VIP", "valued posters", "#ffcc00", 10]),
    )
    .await;
    assert_eq!(result["result"], json!(true), "{result}");
    let (_, result) = nip86_rpc(addr, &admin_key, "assignrole", json!([alice_hex, "vip"])).await;
    assert_eq!(result["result"], json!(true), "{result}");
    let (_, result) = nip86_rpc(
        addr,
        &admin_key,
        "assignrole",
        json!([mod_hex, "moderator"]),
    )
    .await;
    assert_eq!(result["result"], json!(true), "{result}");
    let (_, result) = nip86_rpc(addr, &mod_key, "supportedmethods", json!([])).await;
    let methods = result["result"].as_array().unwrap();
    assert!(methods.contains(&json!("banpubkey")), "{result}");
    assert!(
        !methods.contains(&json!("changerelayname")),
        "moderators are offered only what they may call: {result}"
    );
    let (_, result) = nip86_rpc(addr, &mod_key, "banpubkey", json!([alice_hex])).await;
    assert_eq!(
        result["result"],
        json!(true),
        "moderator must ban: {result}"
    );
    let (_, result) = nip86_rpc(addr, &mod_key, "changerelayname", json!(["x"])).await;
    assert!(
        result["error"].as_str().unwrap_or("").contains("admin"),
        "moderator must not change relay config: {result}"
    );
    let (_, result) = nip86_rpc(addr, &mod_key, "unbanpubkey", json!([alice_hex])).await;
    assert_eq!(result["result"], json!(true), "{result}");
    let (_, result) = nip86_rpc(addr, &admin_key, "deleterole", json!(["vip"])).await;
    assert_eq!(result["result"], json!(true), "{result}");

    // Config-backed methods fail cleanly without a writable config file.
    let (_, result) = nip86_rpc(addr, &admin_key, "changerelayname", json!(["new name"])).await;
    assert!(
        result["error"].as_str().unwrap_or("").contains("config"),
        "{result}"
    );

    // Blocked IPs are refused at connection admission, HTTP management
    // included; the in-process handle is the operator's escape hatch.
    let (_, result) = nip86_rpc(addr, &admin_key, "blockip", json!(["127.0.0.1", "abuse"])).await;
    assert_eq!(result["result"], json!(true), "{result}");
    let blocked = tokio_tungstenite::connect_async(&url).await;
    assert!(blocked.is_err(), "blocked IP must not upgrade to WebSocket");
    handle
        .manage(wok_relay::ManagementCmd::UnblockIp {
            ip: "127.0.0.1".into(),
        })
        .await
        .unwrap();
    let (mut ws2, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let _ = recv_until(&mut ws2, |_| true).await;

    handle.request_shutdown();
}

/// Build a raw NIP-86 POST whose signed authorization can be sent twice.
fn nip86_request(addr: std::net::SocketAddr, key: &Keypair, body: &str) -> String {
    use sha2::Digest;
    let event = sign_event_with_key(
        json!({
            "created_at": now_secs(),
            "kind": 27235,
            "tags": [
                ["u", format!("ws://{addr}")],
                ["method", "POST"],
                ["payload", hex::encode(sha2::Sha256::digest(body.as_bytes()))],
            ],
            "content": "",
        }),
        key,
    );
    let authorization = base64::engine::general_purpose::STANDARD.encode(event.to_string());
    format!(
        "POST / HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Nostr {authorization}\r\nContent-Type: application/nostr+json+rpc\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip86_replay_after_disconnect_is_refused_once_command_is_queued() {
    // A client that disconnects after its management command reached the
    // writer must not free the signed authorization for a second run: the
    // writer applies the queued command regardless (#51).
    use tokio::io::AsyncWriteExt;
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(
        dir.path(),
        EnvOptions {
            map_size: 64 * 1024 * 1024,
            ..EnvOptions::default()
        },
    )
    .unwrap();
    env.ensure_initialized().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let admin_key = Keypair::new(SECP256K1, &mut rand::thread_rng());
    let (admin_pubkey, _) = admin_key.x_only_public_key();
    let mut cfg = test_cfg(dir.path());
    cfg.admin.enabled = true;
    cfg.admin.public_url = format!("http://{addr}");
    cfg.admin.pubkeys = vec![hex::encode(admin_pubkey.serialize())];
    let handle = wok_relay::start(env.clone(), cfg).unwrap();
    let h = handle.clone();
    tokio::spawn(async move {
        let _ = wok_ws::serve_listener(h, listener).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Stall the writer: LMDB admits one write transaction at a time.
    let (locked_tx, locked_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let stall_env = env.clone();
    let stall = std::thread::spawn(move || {
        let txn = stall_env.begin_rw().unwrap();
        locked_tx.send(()).unwrap();
        let _ = release_rx.recv();
        txn.abort();
    });
    locked_rx.recv().unwrap();

    let body = json!({"method": "banpubkey", "params": ["ab".repeat(32), "spam"]}).to_string();
    let request = nip86_request(addr, &admin_key, &body);
    let mut first = tokio::net::TcpStream::connect(addr).await.unwrap();
    first.write_all(request.as_bytes()).await.unwrap();
    // Let the command reach the writer queue, then drop the connection.
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(first);
    tokio::time::sleep(Duration::from_millis(200)).await;

    let retry = tokio::time::timeout(Duration::from_secs(2), raw_http(addr, &request)).await;
    release_tx.send(()).unwrap();
    stall.join().unwrap();
    let retry = retry.expect("replayed authorization reached the stalled writer");
    assert!(retry.starts_with("HTTP/1.1 401"), "{retry}");
    assert!(retry.contains("already been used"), "{retry}");
    // The disconnected request had reached the writer: its ban still lands.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while !handle
        .moderation
        .read()
        .banned_pubkeys
        .contains_key(&[0xab; 32])
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the first banpubkey never reached the writer"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    handle.request_shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip86_restrict_writes_allowlist_e2e() {
    let dir = tempfile::tempdir().unwrap();
    // Small map: the suite default reserves 10TB of virtual space per relay
    // and concurrent relays can exceed the host's VM budget.
    let env = Env::open(
        dir.path(),
        EnvOptions {
            map_size: 64 * 1024 * 1024,
            ..EnvOptions::default()
        },
    )
    .unwrap();
    env.ensure_initialized().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let admin_key = Keypair::new(SECP256K1, &mut rand::thread_rng());
    let (admin_pubkey, _) = admin_key.x_only_public_key();
    let alice_key = Keypair::new(SECP256K1, &mut rand::thread_rng());
    let (alice_pubkey, _) = alice_key.x_only_public_key();
    let alice_hex = hex::encode(alice_pubkey.serialize());

    let mut cfg = test_cfg(dir.path());
    cfg.admin.enabled = true;
    cfg.admin.public_url = format!("http://{addr}");
    cfg.admin.pubkeys = vec![hex::encode(admin_pubkey.serialize())];
    cfg.relay.auth.write_policy = wok_relay::AccessPolicy::Members;
    let handle = wok_relay::start(env, cfg).unwrap();
    let h = handle.clone();
    tokio::spawn(async move {
        let _ = wok_ws::serve_listener(h, listener).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let url = format!("ws://{addr}/");
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let publish = |content: &str| {
        sign_event_with_key(
            json!({"created_at": now_secs(), "kind": 1, "tags": [], "content": content}),
            &alice_key,
        )
    };

    let msgs = ws_publish(&mut ws, publish("denied-before-allow")).await;
    assert!(
        msgs.iter()
            .any(|t| t.contains("false") && t.contains("restricted")),
        "{msgs:?}"
    );

    let (_, result) = nip86_rpc(addr, &admin_key, "allowpubkey", json!([alice_hex])).await;
    assert_eq!(result["result"], json!(true), "{result}");
    let msgs = ws_publish(&mut ws, publish("allowed-after-allow")).await;
    assert!(msgs.iter().any(|t| t.contains("true")), "{msgs:?}");

    // banpubkey takes the pubkey off the allow list, and allowpubkey lifts
    // the ban.
    let (_, result) = nip86_rpc(addr, &admin_key, "banpubkey", json!([alice_hex])).await;
    assert_eq!(result["result"], json!(true), "{result}");
    let (_, result) = nip86_rpc(addr, &admin_key, "listallowedpubkeys", json!([])).await;
    assert_eq!(result["result"], json!([]), "{result}");
    let msgs = ws_publish(&mut ws, publish("denied-after-ban")).await;
    assert!(
        msgs.iter()
            .any(|t| t.contains("false") && t.contains("restricted")),
        "{msgs:?}"
    );
    let (_, result) = nip86_rpc(addr, &admin_key, "allowpubkey", json!([alice_hex])).await;
    assert_eq!(result["result"], json!(true), "{result}");
    let (_, result) = nip86_rpc(addr, &admin_key, "listbannedpubkeys", json!([])).await;
    assert_eq!(result["result"], json!([]), "{result}");
    let msgs = ws_publish(&mut ws, publish("allowed-after-reallow")).await;
    assert!(msgs.iter().any(|t| t.contains("true")), "{msgs:?}");

    let (_, result) = nip86_rpc(addr, &admin_key, "unallowpubkey", json!([alice_hex])).await;
    assert_eq!(result["result"], json!(true), "{result}");
    let msgs = ws_publish(&mut ws, publish("denied-after-unallow")).await;
    assert!(
        msgs.iter()
            .any(|t| t.contains("false") && t.contains("restricted")),
        "{msgs:?}"
    );

    // A member role also grants write access.
    let (_, result) = nip86_rpc(addr, &admin_key, "assignrole", json!([alice_hex, "member"])).await;
    assert_eq!(result["result"], json!(true), "{result}");
    let msgs = ws_publish(&mut ws, publish("allowed-via-member-role")).await;
    assert!(msgs.iter().any(|t| t.contains("true")), "{msgs:?}");

    handle.request_shutdown();
}

/// `relay.auth.accepted_kinds` is a ceiling: events of other kinds are
/// refused, NIP-86 `allowkind` cannot raise it, `disallowkind` lowers it, the
/// kind lists report the effective set, and NIP-11 says writes are
/// restricted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accepted_kinds_bound_the_nip86_kind_policy() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(
        dir.path(),
        EnvOptions {
            map_size: 64 * 1024 * 1024,
            ..EnvOptions::default()
        },
    )
    .unwrap();
    env.ensure_initialized().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let admin_key = Keypair::new(SECP256K1, &mut rand::thread_rng());
    let (admin_pubkey, _) = admin_key.x_only_public_key();
    let alice_key = Keypair::new(SECP256K1, &mut rand::thread_rng());

    let mut cfg = test_cfg(dir.path());
    cfg.admin.enabled = true;
    cfg.admin.public_url = format!("http://{addr}");
    cfg.admin.pubkeys = vec![hex::encode(admin_pubkey.serialize())];
    cfg.relay.auth.accepted_kinds = vec![7, 1];
    let handle = wok_relay::start(env, cfg).unwrap();
    let h = handle.clone();
    tokio::spawn(async move {
        let _ = wok_ws::serve_listener(h, listener).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let url = format!("ws://{addr}/");
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let publish = |kind: u64| {
        sign_event_with_key(
            json!({"created_at": now_secs(), "kind": kind, "tags": [], "content": format!("{kind}")}),
            &alice_key,
        )
    };
    let accepted = |msgs: &[String]| msgs.iter().any(|t| t.contains("true"));
    assert!(accepted(&ws_publish(&mut ws, publish(1)).await));
    let msgs = ws_publish(&mut ws, publish(30023)).await;
    assert!(
        msgs.iter()
            .any(|t| t.contains("false") && t.contains("restricted: kind 30023 is not allowed")),
        "{msgs:?}"
    );
    assert_eq!(
        reqwest_get_nip11(addr).await["limitation"]["restricted_writes"],
        true
    );

    // The effective set: the ceiling, sorted, as the stored policy allows.
    let list = |method: &'static str| {
        let key = &admin_key;
        async move { nip86_rpc(addr, key, method, json!([])).await.1["result"].clone() }
    };
    assert_eq!(list("listallowedkinds").await, json!([1, 7]));
    assert_eq!(list("listdisallowedkinds").await, json!([]));

    // allowkind cannot raise the ceiling.
    let (_, result) = nip86_rpc(addr, &admin_key, "allowkind", json!([30023])).await;
    assert!(
        result["error"]
            .as_str()
            .is_some_and(|e| e.contains("not in relay.auth.accepted_kinds")),
        "{result}"
    );
    assert_eq!(list("listallowedkinds").await, json!([1, 7]));

    // disallowkind lowers it, and allowkind restores a kind under it.
    let (_, result) = nip86_rpc(addr, &admin_key, "disallowkind", json!([7])).await;
    assert_eq!(result["result"], json!(true), "{result}");
    assert_eq!(list("listallowedkinds").await, json!([1]));
    assert_eq!(list("listdisallowedkinds").await, json!([7]));
    assert!(!accepted(&ws_publish(&mut ws, publish(7)).await));
    let (_, result) = nip86_rpc(addr, &admin_key, "allowkind", json!([7])).await;
    assert_eq!(result["result"], json!(true), "{result}");
    assert_eq!(list("listallowedkinds").await, json!([1, 7]));
    assert!(accepted(&ws_publish(&mut ws, publish(7)).await));
    handle.request_shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip86_kind_policy_e2e() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(
        dir.path(),
        EnvOptions {
            map_size: 64 * 1024 * 1024,
            ..EnvOptions::default()
        },
    )
    .unwrap();
    env.ensure_initialized().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let admin_key = Keypair::new(SECP256K1, &mut rand::thread_rng());
    let (admin_pubkey, _) = admin_key.x_only_public_key();
    let alice_key = Keypair::new(SECP256K1, &mut rand::thread_rng());

    let mut cfg = test_cfg(dir.path());
    cfg.admin.enabled = true;
    cfg.admin.public_url = format!("http://{addr}");
    cfg.admin.pubkeys = vec![hex::encode(admin_pubkey.serialize())];
    let handle = wok_relay::start(env, cfg).unwrap();
    let h = handle.clone();
    tokio::spawn(async move {
        let _ = wok_ws::serve_listener(h, listener).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let url = format!("ws://{addr}/");
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let publish = |content: &str| {
        sign_event_with_key(
            json!({"created_at": now_secs(), "kind": 1, "tags": [], "content": content}),
            &alice_key,
        )
    };
    let msgs = ws_publish(&mut ws, publish("kind-policy-one")).await;
    assert!(msgs.iter().any(|t| t.contains("true")), "{msgs:?}");

    // With no policy both lists are empty, not all 65,536 kinds.
    for method in ["listallowedkinds", "listdisallowedkinds"] {
        let (_, result) = nip86_rpc(addr, &admin_key, method, json!([])).await;
        assert_eq!(result["result"], json!([]), "{method}: {result}");
    }

    // disallowkind rejects new writes and suppresses stored events, including
    // from REQs without a kinds field.
    let (_, result) = nip86_rpc(addr, &admin_key, "disallowkind", json!([1])).await;
    assert_eq!(result["result"], json!(true), "{result}");
    let (_, result) = nip86_rpc(addr, &admin_key, "listdisallowedkinds", json!([])).await;
    assert_eq!(result["result"], json!([1]), "{result}");
    let (_, result) = nip86_rpc(addr, &admin_key, "listallowedkinds", json!([])).await;
    assert_eq!(result["result"], json!([]), "{result}");
    let msgs = ws_publish(&mut ws, publish("kind-policy-two")).await;
    assert!(
        msgs.iter()
            .any(|t| t.contains("false") && t.contains("kind 1 is not allowed")),
        "{msgs:?}"
    );
    ws.send(Message::Text(
        json!(["REQ", "w1", {"limit": 10}]).to_string().into(),
    ))
    .await
    .unwrap();
    let msgs = recv_until(&mut ws, |t| t.contains("EOSE")).await;
    assert!(
        !msgs.iter().any(|t| t.contains("kind-policy-one")),
        "wildcard REQ must not return a disallowed kind, got {msgs:?}"
    );

    // allowkind restores both admission and visibility.
    let (_, result) = nip86_rpc(addr, &admin_key, "allowkind", json!([1])).await;
    assert_eq!(result["result"], json!(true), "{result}");
    let (_, result) = nip86_rpc(addr, &admin_key, "listallowedkinds", json!([])).await;
    assert_eq!(result["result"], json!([1]), "{result}");
    let (_, result) = nip86_rpc(addr, &admin_key, "listdisallowedkinds", json!([])).await;
    assert_eq!(result["result"], json!([]), "{result}");
    let msgs = ws_publish(&mut ws, publish("kind-policy-three")).await;
    assert!(msgs.iter().any(|t| t.contains("true")), "{msgs:?}");
    ws.send(Message::Text(
        json!(["REQ", "w2", {"limit": 10}]).to_string().into(),
    ))
    .await
    .unwrap();
    let msgs = recv_until(&mut ws, |t| t.contains("EOSE")).await;
    assert!(
        msgs.iter().any(|t| t.contains("kind-policy-one")),
        "allowkind must restore visibility, got {msgs:?}"
    );

    handle.request_shutdown();
}

/// NIP-86 relay-info methods save the way the dashboard does: the file on
/// disk is edited in place, so its comments and other keys survive, and a
/// value equal to the preset's is removed rather than pinned.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip86_config_methods_edit_the_file_in_place() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(
        dir.path(),
        EnvOptions {
            map_size: 64 * 1024 * 1024,
            ..EnvOptions::default()
        },
    )
    .unwrap();
    env.ensure_initialized().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let admin_key = Keypair::new(SECP256K1, &mut rand::thread_rng());
    let admin_hex = hex::encode(admin_key.x_only_public_key().0.serialize());

    let config_dir = tempfile::tempdir().unwrap();
    let path = config_dir.path().join("wok.toml");
    let text = format!(
        r#"# Test relay.
preset = "public"

[admin]
enabled = true
public_url = "http://{addr}"
pubkeys = ["{admin_hex}"]
allow_config_writes = true   # changerelayname needs it

[relay.info]
# Shown in NIP-11.
name = "Before"
description = "Kept as written."
"#
    );
    std::fs::write(&path, &text).unwrap();
    let mut cfg = test_cfg(dir.path());
    cfg.admin = wok_relay::Config::parse_toml(&text).unwrap().admin;
    let handle = wok_relay::start(env, cfg).unwrap();
    handle.set_config_path(path.clone());
    let h = handle.clone();
    tokio::spawn(async move {
        let _ = wok_ws::serve_listener(h, listener).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (_, result) = nip86_rpc(addr, &admin_key, "changerelayname", json!(["After"])).await;
    assert_eq!(result["result"], json!(true), "{result}");
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        text.replace("name = \"Before\"", "name = \"After\"")
    );
    assert_eq!(handle.config.read().relay.info.name, "After");

    let default_name = wok_relay::Config::default().relay.info.name;
    let (_, result) = nip86_rpc(addr, &admin_key, "changerelayname", json!([default_name])).await;
    assert_eq!(result["result"], json!(true), "{result}");
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        text.replace("# Shown in NIP-11.\nname = \"Before\"\n", "")
    );
    assert_eq!(handle.config.read().relay.info.name, default_name);

    handle.request_shutdown();
}

/// A DB change queued before a ban commits must not deliver the banned
/// author's events afterwards: the live monitor rechecks moderation against
/// committed state on every batch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip86_ban_suppresses_queued_live_delivery() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(
        dir.path(),
        EnvOptions {
            map_size: 64 * 1024 * 1024,
            ..EnvOptions::default()
        },
    )
    .unwrap();
    env.ensure_initialized().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let admin_key = Keypair::new(SECP256K1, &mut rand::thread_rng());
    let (admin_pubkey, _) = admin_key.x_only_public_key();
    let alice_key = Keypair::new(SECP256K1, &mut rand::thread_rng());
    let (alice_pubkey, _) = alice_key.x_only_public_key();
    let alice_hex = hex::encode(alice_pubkey.serialize());

    let mut cfg = test_cfg(dir.path());
    cfg.admin.enabled = true;
    cfg.admin.public_url = format!("http://{addr}");
    cfg.admin.pubkeys = vec![hex::encode(admin_pubkey.serialize())];
    // Out-of-band writer, like a co-resident import: bypasses the relay's
    // ingest enforcement entirely. Clone the handle rather than reopening
    // the same environment in-process, which LMDB forbids.
    let env2 = env.clone();
    let handle = wok_relay::start(env, cfg).unwrap();
    let h = handle.clone();
    tokio::spawn(async move {
        let _ = wok_ws::serve_listener(h, listener).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let url = format!("ws://{addr}/");
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    ws.send(Message::Text(
        json!(["REQ", "live", {"kinds": [1]}]).to_string().into(),
    ))
    .await
    .unwrap();
    let _ = recv_until(&mut ws, |t| t.contains("EOSE")).await;
    let external_write = |content: &str| {
        let ev = sign_event_with_key(
            json!({"created_at": now_secs(), "kind": 1, "tags": [], "content": content}),
            &alice_key,
        );
        let parsed = wok_event::parse_and_verify_event(
            &ev,
            &wok_event::EventLimits::default(),
            None,
            true,
            false,
        )
        .unwrap();
        let mut evs = vec![wok_db::EventToWrite::new(
            parsed.packed.into_bytes(),
            parsed.json,
        )];
        let mut txn = env2.begin_rw().unwrap();
        wok_db::write_events(&mut txn, &mut wok_db::NoopNegentropy, &mut evs, false).unwrap();
        txn.commit().unwrap();
    };

    // Baseline: an external write is delivered live.
    external_write("queued-live-before-ban");
    let msgs = recv_until(&mut ws, |t| t.contains("queued-live-before-ban")).await;
    assert!(
        msgs.iter().any(|t| t.contains("queued-live-before-ban")),
        "{msgs:?}"
    );

    // Ban, then an external write of the banned author: never delivered.
    let (_, result) = nip86_rpc(addr, &admin_key, "banpubkey", json!([alice_hex])).await;
    assert_eq!(result["result"], json!(true), "{result}");
    external_write("queued-live-after-ban");
    let mut delivered = false;
    for _ in 0..6 {
        if let Ok(Some(Ok(msg))) = tokio::time::timeout(Duration::from_millis(300), ws.next()).await
        {
            if msg
                .to_text()
                .unwrap_or("")
                .contains("queued-live-after-ban")
            {
                delivered = true;
            }
        }
    }
    assert!(!delivered, "banned author's queued event must not go live");

    // Unban: external writes flow again.
    let (_, result) = nip86_rpc(addr, &admin_key, "unbanpubkey", json!([alice_hex])).await;
    assert_eq!(result["result"], json!(true), "{result}");
    external_write("queued-live-after-unban");
    let msgs = recv_until(&mut ws, |t| t.contains("queued-live-after-unban")).await;
    assert!(
        msgs.iter().any(|t| t.contains("queued-live-after-unban")),
        "{msgs:?}"
    );

    handle.request_shutdown();
}
