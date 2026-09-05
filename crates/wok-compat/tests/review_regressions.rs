//! Expected-behavior reproducers from the September 2026 review.
//! Regression coverage retained from the audit.
#![allow(clippy::field_reassign_with_default)]

use serde_json::{json, Value};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use wok_relay::{Config, ConnectionGuard, Outbound, OutboundFrame, RelayHandle, TransportSource};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

struct Relay {
    handle: RelayHandle,
    env: wok_db::Env,
    _dir: tempfile::TempDir,
}

impl Relay {
    fn new(configure: impl FnOnce(&mut Config)) -> Self {
        let (dir, env) = wok_compat::temp_db();
        let mut cfg = Config::default();
        cfg.db = dir.path().to_path_buf();
        configure(&mut cfg);
        Self {
            handle: wok_relay::start(env.clone(), cfg).unwrap(),
            env,
            _dir: dir,
        }
    }

    async fn connection(
        &self,
    ) -> (
        ConnectionGuard,
        tokio::sync::mpsc::UnboundedReceiver<OutboundFrame>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let conn = self
            .handle
            .register_connection(TransportSource::Unix, Outbound::new(tx, 0))
            .await;
        (conn, rx)
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.handle.request_shutdown();
    }
}

async fn recv(rx: &mut tokio::sync::mpsc::UnboundedReceiver<OutboundFrame>) -> Value {
    let frame = tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .unwrap()
        .unwrap();
    serde_json::from_str(&frame.into_text()).unwrap()
}

async fn publish(
    conn: &ConnectionGuard,
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<OutboundFrame>,
    event: &Value,
) {
    conn.client_message(json!(["EVENT", event]).to_string())
        .await;
    let reply = recv(rx).await;
    assert_eq!(reply[0], "OK", "{reply}");
    assert_eq!(reply[1], event["id"], "{reply}");
    assert_eq!(reply[2], true, "{reply}");
}

async fn reconcile(
    conn: &ConnectionGuard,
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<OutboundFrame>,
    filter: Value,
) -> Vec<String> {
    let mut store = wok_negentropy::Vector::new();
    store.seal().unwrap();
    let mut client = wok_negentropy::Negentropy::new(store, 60_000).unwrap();
    let initial = client.initiate().unwrap();
    conn.client_message(json!(["NEG-OPEN", "sync", filter, hex::encode(initial)]).to_string())
        .await;
    let mut need = Vec::new();
    for _ in 0..20 {
        let reply = recv(rx).await;
        assert_eq!(reply[0], "NEG-MSG", "{reply}");
        let bytes = hex::decode(reply[2].as_str().unwrap()).unwrap();
        let mut have_ids = Vec::new();
        let mut need_ids = Vec::new();
        let next = client
            .reconcile_with_ids(&bytes, &mut have_ids, &mut need_ids)
            .unwrap();
        need.extend(need_ids.iter().map(hex::encode));
        match next {
            Some(next) => {
                conn.client_message(json!(["NEG-MSG", "sync", hex::encode(next)]).to_string())
                    .await
            }
            None => return need,
        }
    }
    panic!("reconciliation did not finish");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn review_default_negentropy_tree_respects_read_privacy() {
    let relay = Relay::new(|_| {});
    let (conn, mut rx) = relay.connection().await;
    let event = wok_compat::sign_event(json!({"created_at":now(), "kind":4,
        "tags":[["p", hex::encode([9u8;32])]], "content":"private ciphertext"}));
    publish(&conn, &mut rx, &event).await;
    conn.client_message(json!(["REQ", "ordinary", {}]).to_string())
        .await;
    assert_eq!(recv(&mut rx).await, json!(["EOSE", "ordinary"]));
    // A semantically equivalent filter with a time bound uses the same tree.
    let ids = reconcile(&conn, &mut rx, json!({})).await;
    conn.close().await;
    assert!(
        !ids.contains(&event["id"].as_str().unwrap().to_string()),
        "unauthenticated NEG disclosed restricted ID: {ids:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn review_negentropy_over_limit_is_rejected() {
    let relay = Relay::new(|cfg| cfg.relay.max_sync_events = 2);
    let (conn, mut rx) = relay.connection().await;
    for i in 0..3 {
        let event = wok_compat::sign_event(
            json!({"created_at":now(), "kind":1, "tags":[], "content":format!("event {i}")}),
        );
        publish(&conn, &mut rx, &event).await;
    }
    let mut store = wok_negentropy::Vector::new();
    store.seal().unwrap();
    let mut client = wok_negentropy::Negentropy::new(store, 60_000).unwrap();
    let initial = client.initiate().unwrap();
    conn.client_message(
        json!(["NEG-OPEN", "bounded", {"kinds":[1]}, hex::encode(initial)]).to_string(),
    )
    .await;
    let reply = recv(&mut rx).await;
    conn.close().await;
    assert_eq!(
        reply[0], "NEG-ERR",
        "must report overflow rather than claim complete set: {reply}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn review_latest_event_is_not_served_after_expiration() {
    let relay = Relay::new(|_| {});
    let (conn, mut rx) = relay.connection().await;
    let event = wok_compat::sign_event(json!({"created_at":now(), "kind":1,
        "tags":[["expiration", (now()+2).to_string()]], "content":"expires"}));
    publish(&conn, &mut rx, &event).await;
    tokio::time::sleep(Duration::from_secs(5)).await;
    conn.client_message(json!(["REQ", "expired", {"ids":[event["id"]]}]).to_string())
        .await;
    let reply = recv(&mut rx).await;
    conn.close().await;
    assert_eq!(
        reply[0], "EOSE",
        "expired event was still delivered: {reply}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn review_author_quota_recovers_after_stored_event_deleted() {
    let relay = Relay::new(|cfg| cfg.relay.abuse.max_stored_events_per_pubkey = 1);
    let (conn, mut rx) = relay.connection().await;
    let key = secp256k1::Keypair::new(secp256k1::SECP256K1, &mut rand::thread_rng());
    let event = wok_compat::sign_event_with_key(
        json!({"created_at":now(), "kind":1, "tags":[], "content":"first"}),
        &key,
    );
    publish(&conn, &mut rx, &event).await;
    {
        // Same removal path used by maintenance; all LMDB work is synchronous.
        let mut txn = relay.env.begin_rw().unwrap();
        let lev = wok_db::most_recent_levid(&txn).unwrap();
        let mut cache = wok_negentropy::NegentropyFilterCache::default();
        wok_db::delete_events(&mut txn, &mut cache, [lev]).unwrap();
        txn.commit().unwrap();
        assert_eq!(
            relay
                .env
                .begin_ro()
                .unwrap()
                .entries(relay.env.dbis().event)
                .unwrap(),
            0
        );
    }
    let next = wok_compat::sign_event_with_key(
        json!({"created_at":now(), "kind":1, "tags":[], "content":"after deletion"}),
        &key,
    );
    conn.client_message(json!(["EVENT", next]).to_string())
        .await;
    let reply = recv(&mut rx).await;
    conn.close().await;
    assert_eq!(
        reply[2], true,
        "zero stored events should leave quota available: {reply}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn review_count_and_req_use_the_same_recipient_policy() {
    let relay = Relay::new(|cfg| cfg.relay.auth.service_url = "wss://review.example".into());
    let (conn, mut rx) = relay.connection().await;
    conn.client_message(json!(["REQ","challenge",{"kinds":[4]}]).to_string())
        .await;
    let challenge = recv(&mut rx).await;
    assert_eq!(challenge[0], "AUTH");
    assert_eq!(recv(&mut rx).await[0], "CLOSED");
    let key = secp256k1::Keypair::new(secp256k1::SECP256K1, &mut rand::thread_rng());
    let pk = hex::encode(key.x_only_public_key().0.serialize());
    let auth = wok_compat::sign_event_with_key(
        json!({"created_at":now(),"kind":22242,"tags":[["relay","wss://review.example"],["challenge",challenge[1]]],"content":""}),
        &key,
    );
    conn.client_message(json!(["AUTH", auth]).to_string()).await;
    assert_eq!(recv(&mut rx).await[2], true);
    let event = wok_compat::sign_event(
        json!({"created_at":now(),"kind":4,"tags":[["p",hex::encode([9;32])],["p",pk]],"content":"private ciphertext"}),
    );
    publish(&conn, &mut rx, &event).await;
    let filter = json!({"kinds":[4],"#p":[pk]});
    conn.client_message(json!(["REQ", "read", filter]).to_string())
        .await;
    assert_eq!(recv(&mut rx).await, json!(["EOSE", "read"]));
    conn.client_message(json!(["COUNT", "count", filter]).to_string())
        .await;
    let reply = recv(&mut rx).await;
    conn.close().await;
    assert_eq!(reply[0], "COUNT", "{reply}");
    assert_eq!(
        reply[2]["count"], 0,
        "COUNT disclosed an event that the same user's REQ cannot see: {reply}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multiple_auth_keys_remain_authorized_for_reads_and_protected_writes() {
    let relay = Relay::new(|cfg| cfg.relay.auth.service_url = "wss://review.example".into());
    let (conn, mut rx) = relay.connection().await;
    conn.client_message(json!(["REQ","challenge",{"kinds":[4]}]).to_string())
        .await;
    let challenge = recv(&mut rx).await;
    assert_eq!(challenge[0], "AUTH");
    assert_eq!(recv(&mut rx).await[0], "CLOSED");
    let keys = [
        secp256k1::Keypair::new(secp256k1::SECP256K1, &mut rand::thread_rng()),
        secp256k1::Keypair::new(secp256k1::SECP256K1, &mut rand::thread_rng()),
    ];
    for key in &keys {
        let auth = wok_compat::sign_event_with_key(
            json!({"created_at":now(),"kind":22242,"tags":[["relay","wss://review.example"],["challenge",challenge[1]]],"content":""}),
            key,
        );
        conn.client_message(json!(["AUTH", auth]).to_string()).await;
        let ack = recv(&mut rx).await;
        assert_eq!(ack[2], true, "{ack}");
    }
    for (i, key) in keys.iter().enumerate() {
        let pk = hex::encode(key.x_only_public_key().0.serialize());
        let event = wok_compat::sign_event_with_key(
            json!({"created_at":now(),"kind":4,"tags":[["p",pk],["-"]],"content":format!("private {i}")}),
            key,
        );
        publish(&conn, &mut rx, &event).await;
        conn.client_message(json!(["REQ",format!("key-{i}"),{"ids":[event["id"]]}]).to_string())
            .await;
        let delivered = recv(&mut rx).await;
        assert_eq!(delivered[0], "EVENT", "{delivered}");
        assert_eq!(delivered[2], event);
        assert_eq!(recv(&mut rx).await[0], "EOSE");
    }
    conn.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_sync_is_reclaimed_without_closing_connection() {
    let relay = Relay::new(|cfg| cfg.relay.sync_idle_timeout_secs = 1);
    let (conn, mut rx) = relay.connection().await;
    let mut items = wok_negentropy::Vector::new();
    items.seal().unwrap();
    let init = wok_negentropy::Negentropy::new(items, 60_000)
        .unwrap()
        .initiate()
        .unwrap();
    conn.client_message(json!(["NEG-OPEN","idle",{"kinds":[1]},hex::encode(init)]).to_string())
        .await;
    assert_eq!(recv(&mut rx).await[0], "NEG-MSG");
    let expired = recv(&mut rx).await;
    assert_eq!(expired[0], "NEG-ERR");
    assert!(expired[2].as_str().unwrap().contains("idle"));
    conn.client_message(json!(["REQ","still-open",{"limit":0}]).to_string())
        .await;
    assert_eq!(recv(&mut rx).await, json!(["EOSE", "still-open"]));
    conn.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_global_budget_spans_workers_and_close_releases_it() {
    let relay = Relay::new(|cfg| {
        cfg.relay.sync_memory_total = 4 * 1024 * 1024;
        cfg.relay.sync_memory_per_connection = 8 * 1024 * 1024;
        cfg.relay.negentropy_threads = 2;
    });
    let (first, mut first_rx) = relay.connection().await;
    let (second, mut second_rx) = relay.connection().await;
    let mut vector = wok_negentropy::Vector::new();
    vector.seal().unwrap();
    let initial = wok_negentropy::Negentropy::new(vector, 60_000)
        .unwrap()
        .initiate()
        .unwrap();
    let open = json!(["NEG-OPEN", "budget", {}, hex::encode(initial)]).to_string();
    first.client_message(open.clone()).await;
    assert_eq!(recv(&mut first_rx).await[0], "NEG-MSG");
    second.client_message(open.clone()).await;
    assert_eq!(recv(&mut second_rx).await[0], "NEG-ERR");
    first
        .client_message(json!(["NEG-CLOSE", "budget"]).to_string())
        .await;
    let mut reopened = false;
    for _ in 0..20 {
        second.client_message(open.clone()).await;
        if recv(&mut second_rx).await[0] == "NEG-MSG" {
            reopened = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        reopened,
        "closing first worker's session must release global reservation"
    );
    first.close().await;
    second.close().await;
}
