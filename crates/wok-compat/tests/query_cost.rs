//! The query-cost gate with the public preset's limits: the client filters
//! the 2026-10-20 audit saw refused are served, and an `authors` × `kinds`
//! fan-out is still refused as a REQ, a COUNT and a NEG-OPEN (tracking issue
//! #97 §3.4).

use serde_json::{json, Value};
use std::sync::atomic::Ordering;
use std::time::Duration;
use wok_relay::{Config, ConnectionGuard, Outbound, OutboundFrame, TransportSource};

type Rx = tokio::sync::mpsc::UnboundedReceiver<OutboundFrame>;

fn keys(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("{i:064x}")).collect()
}

async fn reply(conn: &ConnectionGuard, rx: &mut Rx, msg: Value) -> Value {
    conn.client_message(msg.to_string()).await;
    let frame = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .unwrap()
        .unwrap();
    serde_json::from_str(&frame.into_text()).unwrap()
}

fn neg_initial() -> String {
    let mut store = wok_negentropy::Vector::new();
    store.seal().unwrap();
    let mut client = wok_negentropy::Negentropy::new(store, 60_000).unwrap();
    hex::encode(client.initiate().unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_cost_ceiling_serves_client_filters_and_refuses_fan_outs() {
    let (dir, env) = wok_compat::temp_db();
    let cfg = Config {
        db: dir.path().to_path_buf(),
        ..Default::default()
    };
    let handle = wok_relay::start(env, cfg).unwrap();
    // The writer reports the (tag, kind, created_at) index as it starts.
    let complete = || {
        handle
            .metrics
            .tag_kind_index_complete
            .load(Ordering::Relaxed)
    };
    for _ in 0..100 {
        if complete() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(complete(), 1);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    // A Unix connection has no address, so no per-address budget applies.
    let conn = handle
        .register_connection(TransportSource::Unix, Outbound::new(tx, 0))
        .await;

    let gid = "ab".repeat(32);
    let eleven_kinds = [1, 6, 7, 9735, 30023, 1063, 20, 21, 22, 1111, 9802];
    let reactions: Vec<Value> = keys(45)
        .into_iter()
        .map(|id| json!({"#e": [id], "kinds": [7]}))
        .collect();
    let served = [
        (
            "authors[150], limit 20",
            vec![json!({"authors": keys(150), "limit": 20})],
        ),
        (
            "11-kind feed, limit 50",
            vec![json!({"kinds": eleven_kinds, "limit": 50})],
        ),
        ("45 reaction filters", reactions),
        (
            "outbox metadata",
            vec![json!({"authors": keys(1000), "kinds": [0, 3, 10002, 10050]})],
        ),
        (
            "MDK group",
            vec![json!({"kinds": [445], "#h": [gid], "since": 1_700_000_000})],
        ),
        ("{}", vec![json!({})]),
    ];
    for (shape, filters) in served {
        let mut req = vec![json!("REQ"), json!("ok")];
        req.extend(filters);
        let eose = reply(&conn, &mut rx, json!(req)).await;
        assert_eq!(
            (&eose[0], &eose[1]),
            (&json!("EOSE"), &json!("ok")),
            "{shape}: {eose}"
        );
        conn.client_message(json!(["CLOSE", "ok"]).to_string())
            .await;
    }
    let count = reply(
        &conn,
        &mut rx,
        json!(["COUNT", "followers", {"kinds": [3], "#p": keys(1)}]),
    )
    .await;
    assert_eq!(count[0], "COUNT", "{count}");
    let sync = reply(
        &conn,
        &mut rx,
        json!(["NEG-OPEN", "group", {"kinds": [445], "#h": [gid]}, neg_initial()]),
    )
    .await;
    assert_eq!(sync[0], "NEG-MSG", "{sync}");

    let fifty_kinds: Vec<u64> = (1..=50).collect();
    let fan_out = json!({"authors": keys(2000), "kinds": fifty_kinds});
    // `blocked:`: the same request would be refused again (#97 §8).
    for (msg, refusal, cost, request) in [
        (json!(["REQ", "wide", fan_out]), "CLOSED", 102_000, "REQ"),
        (
            json!(["COUNT", "wide", fan_out]),
            "CLOSED",
            200_000,
            "COUNT",
        ),
        (
            json!(["NEG-OPEN", "wide", fan_out, neg_initial()]),
            "NEG-ERR",
            100_000,
            "NEG-OPEN",
        ),
    ] {
        let refused = reply(&conn, &mut rx, msg).await;
        assert_eq!(
            refused,
            json!([
                refusal,
                "wide",
                format!(
                    "blocked: query too broad (cost {cost} > 20000); split the {request} or \
                     narrow authors/kinds"
                )
            ])
        );
    }
    assert_eq!(
        handle
            .metrics
            .abuse_query_cost_rejections
            .load(Ordering::Relaxed),
        3
    );
    conn.close().await;
    handle.request_shutdown();
}
