use secp256k1::{Keypair, SECP256K1};
use serde_json::json;
use tempfile::TempDir;
use wok_db::{write_events, Env, EnvOptions, EventToWrite, NoopNegentropy};
use wok_event::{parse_and_verify_event, EventLimits};
use wok_query::{
    foreach_by_filter, DbQuery, DbScan, NostrFilterGroup, QueryScheduler, SubId, Subscription,
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

fn sign_with_tags(content: &str, created: u64, tags: &[&str]) -> (Vec<u8>, String, String) {
    let mut rng = rand::thread_rng();
    let kp = Keypair::new(SECP256K1, &mut rng);
    let (xonly, _) = kp.x_only_public_key();
    let mut ev = json!({
        "created_at": created,
        "kind": 1,
        "tags": tags.iter().map(|value| json!(["t", value])).collect::<Vec<_>>(),
        "content": content,
        "pubkey": hex::encode(xonly.serialize()),
    });
    let id = wok_event::event_id_hash(&ev).unwrap();
    ev["id"] = json!(hex::encode(id));
    let sig = SECP256K1.sign_schnorr(&id, &kp);
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
    foreach_by_filter(&txn, &json!({"kinds":[1], "limit": 5}), 500, 3, 16, |lev| {
        got.push(lev);
    })
    .unwrap();
    assert_eq!(got.len(), 5);
    let fg = NostrFilterGroup::from_value(&json!({"kinds":[0]}), 500, 3, 16).unwrap();
    assert_eq!(fg.size(), 1);
}

#[test]
fn nip91_historical_scan_uses_one_seed_and_verifies_the_full_event() {
    let tmp = TempDir::new().unwrap();
    let env = Env::open(tmp.path(), EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let inputs = [
        ("black", 100, &["meme", "cat", "black"][..]),
        ("white", 200, &["meme", "cat", "white"][..]),
        ("missing-or", 300, &["meme", "cat"][..]),
        ("missing-and", 400, &["meme", "black"][..]),
    ];
    let mut events: Vec<_> = inputs
        .iter()
        .map(|(content, created, tags)| {
            let (packed, json, _) = sign_with_tags(content, *created, tags);
            EventToWrite::new(packed, json)
        })
        .collect();
    let mut write = env.begin_rw().unwrap();
    write_events(&mut write, &mut NoopNegentropy, &mut events, false).unwrap();
    write.commit().unwrap();

    let expected = vec![events[1].lev_id, events[0].lev_id];
    let txn = env.begin_ro().unwrap();
    let mut hits = Vec::new();
    foreach_by_filter(
        &txn,
        &json!({
            "&t":["meme", "cat"],
            "#t":["meme", "cat", "black", "white"]
        }),
        500,
        3,
        16,
        |lev| hits.push(lev),
    )
    .unwrap();
    assert_eq!(hits, expected);

    let group = NostrFilterGroup::from_value(
        &json!({
            "&t":["meme", "cat"],
            "#t":["meme", "cat", "black", "white"]
        }),
        500,
        3,
        16,
    )
    .unwrap();
    let mut count = DbQuery::new(
        Subscription::new(1, SubId::new("nip91-count").unwrap(), group, true),
        0,
        100,
    );
    assert!(count.process(&txn, |_, _| {}, u64::MAX).unwrap());
    assert_eq!(count.sent_count(), 2);
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
    let group = NostrFilterGroup::from_req(request.as_array().unwrap(), 500, 3, 16).unwrap();
    let txn = env.begin_ro().unwrap();

    let mut delivery = DbQuery::new(
        Subscription::new(1, SubId::new("multi").unwrap(), group.clone(), false),
        3,
        0,
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
        1_000_001,
    );
    assert!(count.process(&txn, |_, _| {}, u64::MAX).unwrap());
    assert_eq!(count.sent_count(), 6);
    assert!(!count.count_dedup_limited());
}

#[test]
fn count_dedup_budget_caps_multi_filter_scans_as_limited() {
    let tmp = TempDir::new().unwrap();
    let env = Env::open(tmp.path(), EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let mut events = Vec::new();
    for i in 0..5 {
        let (packed, json, _) = sign(1, &format!("note-{i}"), 1_700_000_000 + i);
        events.push(EventToWrite::new(packed, json));
    }
    for i in 0..5 {
        let (packed, json, _) = sign(3, &format!("contact-{i}"), 1_700_000_100 + i);
        events.push(EventToWrite::new(packed, json));
    }
    let mut write = env.begin_rw().unwrap();
    write_events(&mut write, &mut NoopNegentropy, &mut events, false).unwrap();
    write.commit().unwrap();

    // Two broad filters, each matching 5 events; budget below the total.
    let request = json!(["COUNT", "c", {"kinds":[1]}, {"kinds":[3]}]);
    let group = NostrFilterGroup::from_req(request.as_array().unwrap(), 500, 3, 16).unwrap();
    let txn = env.begin_ro().unwrap();
    let mut count = DbQuery::new(
        Subscription::new(1, SubId::new("c").unwrap(), group, true),
        0,
        7,
    );
    assert!(count.process(&txn, |_, _| {}, u64::MAX).unwrap());
    assert_eq!(count.sent_count(), 7);
    assert!(count.count_dedup_limited());
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
        16,
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
        16,
        |lev| second.push(lev),
    )
    .unwrap();
    assert_eq!(second.len(), 500);
    assert!(first.iter().all(|lev| !second.contains(lev)));

    let request = json!(["REQ", "scheduled", {
        "authors":[pubkey], "kinds":[1], "limit":500
    }]);
    let group = NostrFilterGroup::from_req(request.as_array().unwrap(), 500, 3, 16).unwrap();
    let mut scheduler = QueryScheduler::new(8, 2_000, 0);
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
                |_, total, _hll, _limited| completions.push(total),
            )
            .unwrap();
    }
    assert_eq!(scheduled.len(), 500);
    assert_eq!(completions, vec![500]);
}

/// A required (`&`) tag needs one cursor no matter how many values it lists,
/// while an OR tag needs one per alternative, so the required tag seeds even
/// when a smaller OR set is present. Regression guard for a seed comparison
/// that mixed value counts with cursor counts.
#[test]
fn nip91_and_tag_seeds_a_single_cursor() {
    let tmp = TempDir::new().unwrap();
    let env = Env::open(tmp.path(), EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let txn = env.begin_ro().unwrap();

    let seed_count = |filter: serde_json::Value| {
        let group = NostrFilterGroup::from_value(&filter, 500, 3, 16).unwrap();
        DbScan::new(&group.filters[0], &txn).cursor_count()
    };

    assert_eq!(seed_count(json!({"&t":["a", "b", "c"]})), 1);
    // One narrow OR alternative does not outbid the required tag.
    assert_eq!(
        seed_count(json!({"&t":["a", "b", "c"], "#e":["11".repeat(32)]})),
        1
    );
    // Several required keys: the smallest set decides which one seeds, and it
    // is still a single cursor.
    assert_eq!(seed_count(json!({"&t":["a", "b"], "&d":["x"]})), 1);
    // Without a required tag the smallest OR set seeds, one cursor per value.
    assert_eq!(
        seed_count(
            json!({"#t":["a", "b"], "#e":["11".repeat(32), "22".repeat(32), "33".repeat(32)]})
        ),
        2
    );
}
