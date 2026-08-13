use secp256k1::{Keypair, SECP256K1};
use serde_json::json;
use tempfile::TempDir;
use wok_db::{write_events, Env, EnvOptions, EventToWrite, NoopNegentropy};
use wok_event::{parse_and_verify_event, EventLimits};
use wok_query::{
    foreach_by_filter, DbQuery, NostrFilterGroup, QueryScheduler, SubId, Subscription,
};

fn sign(kind: u64, content: &str, created: u64) -> (Vec<u8>, String, String) {
    let mut rng = rand::thread_rng();
    let kp = Keypair::new(SECP256K1, &mut rng);
    sign_with_key(&kp, kind, content, created)
}

fn sign_with_key(
    kp: &Keypair,
    kind: u64,
    content: &str,
    created: u64,
) -> (Vec<u8>, String, String) {
    let (xonly, _) = kp.x_only_public_key();
    let mut ev = json!({
        "created_at": created,
        "kind": kind,
        "tags": [],
        "content": content,
        "pubkey": hex::encode(xonly.serialize()),
    });
    let id = wok_event::event_id_hash(&ev).unwrap();
    ev["id"] = json!(hex::encode(id));
    let sig = SECP256K1.sign_schnorr(&id, kp);
    ev["sig"] = json!(hex::encode(sig.as_ref()));
    let parsed = parse_and_verify_event(&ev, &EventLimits::default(), None, true, false).unwrap();
    (parsed.packed.into_bytes(), parsed.json, hex::encode(id))
}

#[test]
fn scan_kinds_and_limit() {
    let tmp = TempDir::new().unwrap();
    let env = Env::open(tmp.path(), EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let mut evs = Vec::new();
    let mut ids = Vec::new();
    for i in 0..10 {
        let (p, j, id) = sign(1, &format!("n{i}"), 1_700_000_000 + i);
        ids.push(id);
        evs.push(EventToWrite::new(p, j));
    }
    let (p, j, _) = sign(0, "meta", 1_700_000_050);
    evs.push(EventToWrite::new(p, j));
    {
        let mut txn = env.begin_rw().unwrap();
        write_events(&mut txn, &mut NoopNegentropy, &mut evs, false).unwrap();
        txn.commit().unwrap();
    }
    let txn = env.begin_ro().unwrap();
    let mut got = Vec::new();
    foreach_by_filter(&txn, &json!({"kinds":[1], "limit": 5}), 500, 3, |lev| {
        got.push(lev);
    })
    .unwrap();
    assert_eq!(got.len(), 5);
    let fg = NostrFilterGroup::from_value(&json!({"kinds":[0]}), 500, 3).unwrap();
    assert_eq!(fg.size(), 1);
}

#[test]
fn request_wide_limit_caps_deduplicated_multi_filter_results_but_not_count() {
    let tmp = TempDir::new().unwrap();
    let env = Env::open(tmp.path(), EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let mut events = Vec::new();
    for i in 0..5 {
        let (packed, json, _) = sign(1, &format!("note-{i}"), 1_700_000_000 + i);
        events.push(EventToWrite::new(packed, json));
    }
    let (packed, json, _) = sign(0, "profile", 1_700_000_100);
    events.push(EventToWrite::new(packed, json));
    let mut write = env.begin_rw().unwrap();
    write_events(&mut write, &mut NoopNegentropy, &mut events, false).unwrap();
    write.commit().unwrap();

    let request = json!(["REQ", "multi", {"kinds":[1], "limit":5}, {"kinds":[0], "limit":5}]);
    let group = NostrFilterGroup::from_req(request.as_array().unwrap(), 500, 3).unwrap();
    let txn = env.begin_ro().unwrap();

    let mut delivery = DbQuery::new(
        Subscription::new(1, SubId::new("multi").unwrap(), group.clone(), false),
        3,
    );
    let mut delivered = Vec::new();
    assert!(delivery
        .process(&txn, |_, lev| delivered.push(lev), u64::MAX)
        .unwrap());
    assert_eq!(delivered.len(), 3);
    assert_eq!(delivery.sent_count(), 3);

    let mut count = DbQuery::new(
        Subscription::new(1, SubId::new("count").unwrap(), group, true),
        3,
    );
    assert!(count.process(&txn, |_, _| {}, u64::MAX).unwrap());
    assert_eq!(count.sent_count(), 6);
}

#[test]
fn deep_author_kind_pages_are_complete_and_non_overlapping() {
    let tmp = TempDir::new().unwrap();
    let env = Env::open(tmp.path(), EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let mut rng = rand::thread_rng();
    let key = Keypair::new(SECP256K1, &mut rng);
    let (pubkey, _) = key.x_only_public_key();
    let pubkey = hex::encode(pubkey.serialize());
    let mut events = Vec::new();
    for i in 0..1_000u64 {
        let (packed, json, _) = sign_with_key(&key, 1, &format!("history-{i}"), 1_700_000_000 + i);
        events.push(EventToWrite::new(packed, json));
    }
    let mut txn = env.begin_rw().unwrap();
    write_events(&mut txn, &mut NoopNegentropy, &mut events, false).unwrap();
    txn.commit().unwrap();

    let txn = env.begin_ro().unwrap();
    let mut first = Vec::new();
    foreach_by_filter(
        &txn,
        &json!({"authors":[pubkey], "kinds":[1], "limit":500}),
        500,
        3,
        |lev| first.push(lev),
    )
    .unwrap();
    assert_eq!(first.len(), 500);

    let oldest = first
        .iter()
        .filter_map(|lev| txn.get_u64(txn.env().dbis().event, *lev).ok().flatten())
        .map(|bytes| wok_event::PackedEventView::new(bytes).unwrap().created_at())
        .min()
        .unwrap();
    let mut second = Vec::new();
    foreach_by_filter(
        &txn,
        &json!({
            "authors":[pubkey],
            "kinds":[1],
            "until":oldest.saturating_sub(1),
            "limit":500
        }),
        500,
        3,
        |lev| second.push(lev),
    )
    .unwrap();
    assert_eq!(second.len(), 500);
    assert!(first.iter().all(|lev| !second.contains(lev)));

    let request = json!(["REQ", "scheduled", {
        "authors":[pubkey], "kinds":[1], "limit":500
    }]);
    let group = NostrFilterGroup::from_req(request.as_array().unwrap(), 500, 3).unwrap();
    let mut scheduler = QueryScheduler::new(8, 2_000);
    assert!(scheduler
        .add_sub(
            &txn,
            Subscription::new(7, SubId::new("scheduled").unwrap(), group, false),
        )
        .unwrap());
    let mut scheduled = Vec::new();
    let mut completions = Vec::new();
    for _ in 0..100 {
        if !scheduler.has_running() {
            break;
        }
        scheduler
            .process(
                &txn,
                10_000,
                |_, lev, _| scheduled.push(lev),
                |_, total, _hll| completions.push(total),
            )
            .unwrap();
    }
    assert_eq!(scheduled.len(), 500);
    assert_eq!(completions, vec![500]);
}
