use secp256k1::{Keypair, SECP256K1};
use serde_json::json;
use tempfile::TempDir;
use wok_db::{write_events, Env, EnvOptions, EventToWrite, NoopNegentropy};
use wok_event::{parse_and_verify_event, EventLimits};
use wok_query::{
    foreach_by_filter, foreach_visible_by_filter, visibility::ReadVisibility, DbQuery, DbScan,
    NostrFilterGroup, QueryScheduler, SubId, Subscription,
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
fn operator_scans_find_stored_auth_events_that_clients_never_see() {
    let tmp = TempDir::new().unwrap();
    let env = Env::open(tmp.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let (packed, json, _) = sign(22242, "", now);
    let mut events = vec![EventToWrite::new(packed, json)];
    let mut txn = env.begin_rw().unwrap();
    write_events(&mut txn, &mut NoopNegentropy, &mut events, false).unwrap();
    txn.commit().unwrap();

    let txn = env.begin_ro().unwrap();
    let filter = json!({"kinds": [22242]});
    let mut operator = Vec::new();
    foreach_by_filter(&txn, &filter, 500, 3, 16, |lev| operator.push(lev)).unwrap();
    assert_eq!(operator, [events[0].lev_id]);
    let mut client = Vec::new();
    foreach_visible_by_filter(
        &txn,
        &filter,
        500,
        3,
        16,
        ReadVisibility::default(),
        |lev| client.push(lev),
    )
    .unwrap();
    assert!(client.is_empty());
}

#[test]
fn scan_kinds_and_limit() {
    let tmp = TempDir::new().unwrap();
    let env = Env::open(tmp.path(), EnvOptions::for_tests()).unwrap();
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
    let env = Env::open(tmp.path(), EnvOptions::for_tests()).unwrap();
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
    let env = Env::open(tmp.path(), EnvOptions::for_tests()).unwrap();
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
    let env = Env::open(tmp.path(), EnvOptions::for_tests()).unwrap();
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
    let env = Env::open(tmp.path(), EnvOptions::for_tests()).unwrap();
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
    let env = Env::open(tmp.path(), EnvOptions::for_tests()).unwrap();
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

fn sign_note(kp: &Keypair, created: u64, tags: &[&str], content: &str) -> (Vec<u8>, String) {
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
    let sig = SECP256K1.sign_schnorr(&id, kp);
    ev["sig"] = json!(hex::encode(sig.as_ref()));
    let parsed = parse_and_verify_event(&ev, &EventLimits::default(), None, true, false).unwrap();
    (parsed.packed.into_bytes(), parsed.json)
}

/// NIP-01: "in the case of ties the event with the lowest id (first in
/// lexical order) should be first", which also decides what `limit` keeps.
/// The ties outnumber each plan's first index read, and span its cursors.
#[test]
fn created_at_ties_put_the_lowest_id_first_on_every_plan() {
    let tmp = TempDir::new().unwrap();
    let env = Env::open(tmp.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let mut rng = rand::thread_rng();
    let keys: Vec<_> = (0..3).map(|_| Keypair::new(SECP256K1, &mut rng)).collect();
    let authors: Vec<_> = keys
        .iter()
        .map(|kp| hex::encode(kp.x_only_public_key().0.serialize()))
        .collect();
    let tie = 1_700_000_000;
    let mut events = Vec::new();
    for (k, kp) in keys.iter().enumerate() {
        for i in 0..12 {
            // Some events carry both tags, so two `#t` cursors queue them.
            let tags: &[&str] = match i % 3 {
                0 => &["x"],
                1 => &["y"],
                _ => &["x", "y"],
            };
            let (packed, json) = sign_note(kp, tie, tags, &format!("tie-{k}-{i}"));
            events.push(EventToWrite::new(packed, json));
        }
    }
    for (offset, n) in [(1, 2), (-1, 3)] {
        for i in 0..n {
            let at = tie.checked_add_signed(offset).unwrap();
            let (packed, json) = sign_note(&keys[i % 3], at, &["x"], &format!("{offset}-{i}"));
            events.push(EventToWrite::new(packed, json));
        }
    }
    let mut write = env.begin_rw().unwrap();
    write_events(&mut write, &mut NoopNegentropy, &mut events, false).unwrap();
    write.commit().unwrap();

    let txn = env.begin_ro().unwrap();
    let view = |lev: u64| {
        let raw = txn.get_u64(txn.env().dbis().event, lev).unwrap().unwrap();
        wok_event::PackedEventView::new(raw).unwrap()
    };
    let id_of = |lev: u64| view(lev).id().to_vec();
    let mut expected: Vec<_> = events
        .iter()
        .map(|event| {
            (
                std::cmp::Reverse(view(event.lev_id).created_at()),
                id_of(event.lev_id),
            )
        })
        .collect();
    expected.sort();
    let expected: Vec<_> = expected.into_iter().map(|(_, id)| id).collect();

    for filter in [
        json!({"kinds": [1]}),
        json!({}),
        json!({"authors": authors}),
        json!({"authors": authors, "kinds": [1]}),
        json!({"#t": ["x", "y"]}),
    ] {
        for limit in [1, 7, 10, 500] {
            let mut filter = filter.clone();
            filter["limit"] = json!(limit);
            let mut got = Vec::new();
            foreach_by_filter(&txn, &filter, 500, 3, 16, |lev| got.push(id_of(lev))).unwrap();
            let want = &expected[..expected.len().min(limit)];
            assert_eq!(got, want, "{filter}");
        }
    }
}

/// NIP-01 `limit: 0` returns no stored event, so no plan opens a cursor, and
/// `until: 0` is a bound like any other: each cursor stops at its first newer
/// entry instead of walking the index and discarding every entry.
#[test]
fn limit_zero_and_until_zero_read_no_history() {
    let tmp = TempDir::new().unwrap();
    let env = Env::open(tmp.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let mut rng = rand::thread_rng();
    let key = Keypair::new(SECP256K1, &mut rng);
    let author = hex::encode(key.x_only_public_key().0.serialize());
    let mut events: Vec<_> = (0..200)
        .map(|i| {
            let (packed, json) = sign_note(&key, 1_700_000_000 + i, &["x"], &format!("n{i}"));
            EventToWrite::new(packed, json)
        })
        .collect();
    let mut write = env.begin_rw().unwrap();
    write_events(&mut write, &mut NoopNegentropy, &mut events, false).unwrap();
    write.commit().unwrap();

    let txn = env.begin_ro().unwrap();
    let id = hex::encode(
        wok_event::PackedEventView::new(
            txn.get_u64(txn.env().dbis().event, events[0].lev_id)
                .unwrap()
                .unwrap(),
        )
        .unwrap()
        .id(),
    );
    let parse = |filter: &serde_json::Value| {
        NostrFilterGroup::from_value(filter, 500, 3, 16)
            .unwrap()
            .filters
            .remove(0)
    };
    for filter in [
        json!({"limit": 0}),
        json!({"kinds": [1], "limit": 0}),
        json!({"authors": [author], "limit": 0}),
        json!({"authors": [author], "kinds": [1], "limit": 0}),
        json!({"authors": [author], "#t": ["x"], "limit": 0}),
        json!({"ids": [id], "limit": 0}),
    ] {
        let f = parse(&filter);
        let mut scan = DbScan::new(&f, &txn);
        assert_eq!(scan.cursor_count(), 0, "{filter}");
        assert!(scan
            .scan(&txn, &f, |_| panic!("{filter}"), |_| false)
            .unwrap());
    }
    for filter in [
        json!({"until": 0}),
        json!({"kinds": [1], "until": 0}),
        json!({"authors": [author], "until": 0}),
        json!({"authors": [author], "kinds": [1], "until": 0}),
        json!({"#t": ["x"], "until": 0}),
    ] {
        let f = parse(&filter);
        let mut scan = DbScan::new(&f, &txn);
        assert!(scan
            .scan(&txn, &f, |_| panic!("{filter}"), |_| false)
            .unwrap());
        assert!(scan.approx_work < 10, "{filter}: {}", scan.approx_work);
    }
}

/// An outbox fetch (kinds 0, 3 and 10002 for a follow list) seeks each
/// (author, kind) pair however many authors it names: those kinds hold few
/// versions per pair, while the Pubkey index would read every event the
/// authors wrote. Other kinds keep strfry's 1000-pair bound unless the seeks
/// that adds over one per author fit the limit.
#[test]
fn author_kind_plans_seek_past_a_thousand_pairs_when_seeks_read_less() {
    let tmp = TempDir::new().unwrap();
    let env = Env::open(tmp.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let txn = env.begin_ro().unwrap();
    let authors = |n: usize| (0..n).map(|i| format!("{i:064x}")).collect::<Vec<_>>();
    let plan = |n: usize, kinds: serde_json::Value, limit: u64| {
        let filter = json!({"authors": authors(n), "kinds": kinds, "limit": limit});
        let group = NostrFilterGroup::from_value(&filter, u64::MAX, 3, 16).unwrap();
        let scan = DbScan::new(&group.filters[0], &txn);
        (scan.desc, scan.cursor_count())
    };
    let outbox = json!([0, 3, 10002]);
    assert_eq!(plan(333, outbox.clone(), 500), ("PubkeyKind", 999));
    assert_eq!(plan(334, outbox.clone(), 500), ("PubkeyKind", 1002));
    assert_eq!(plan(2047, outbox, 500), ("PubkeyKind", 6141));
    assert_eq!(
        plan(2047, json!([0, 3, 10002, 30023]), 1),
        ("PubkeyKind", 8188)
    );
    // Past the cap of cursor state, every kind falls back.
    let many: Vec<_> = (10000..10009).collect();
    assert_eq!(plan(2047, json!(many), u64::MAX), ("Pubkey", 2047));

    assert_eq!(plan(333, json!([1, 6, 7]), 500), ("PubkeyKind", 999));
    assert_eq!(plan(334, json!([1, 6, 7]), 500), ("Pubkey", 334));
    assert_eq!(plan(334, json!([0, 1, 3]), 500), ("Pubkey", 334));
    // One kind adds no seeks over the Pubkey plan.
    assert_eq!(plan(2047, json!([1]), 1), ("PubkeyKind", 2047));
    // A limit (COUNT and NEG-OPEN use their caps) pays for the extra seeks.
    assert_eq!(plan(1000, json!([1, 6, 7]), 2000), ("PubkeyKind", 3000));
    assert_eq!(plan(1000, json!([1, 6, 7]), 1999), ("Pubkey", 1000));
    assert_eq!(
        plan(2047, json!([7, 9735]), 1_000_001),
        ("PubkeyKind", 4094)
    );
}

#[test]
fn outbox_fetch_past_a_thousand_pairs_returns_the_newest_versions() {
    let tmp = TempDir::new().unwrap();
    let env = Env::open(tmp.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let mut rng = rand::thread_rng();
    let keys: Vec<_> = (0..400)
        .map(|_| Keypair::new(SECP256K1, &mut rng))
        .collect();
    let mut events = Vec::new();
    for (a, key) in keys.iter().enumerate() {
        let a = a as u64;
        for (i, kind) in [0, 3, 10002].into_iter().enumerate() {
            // An older version each replaceable event supersedes.
            let (packed, json, _) = sign_with_key(key, kind, "old", 1_600_000_000 + a);
            events.push(EventToWrite::new(packed, json));
            let created = 1_700_000_000 + a * 10 + i as u64;
            let (packed, json, _) = sign_with_key(key, kind, "new", created);
            events.push(EventToWrite::new(packed, json));
        }
        let (packed, json, _) = sign_with_key(key, 1, "note", 1_800_000_000 + a);
        events.push(EventToWrite::new(packed, json));
    }
    let mut write = env.begin_rw().unwrap();
    write_events(&mut write, &mut NoopNegentropy, &mut events, false).unwrap();
    write.commit().unwrap();

    let txn = env.begin_ro().unwrap();
    let authors: Vec<_> = keys
        .iter()
        .map(|kp| hex::encode(kp.x_only_public_key().0.serialize()))
        .collect();
    let created = |lev: u64| {
        let raw = txn.get_u64(txn.env().dbis().event, lev).unwrap().unwrap();
        wok_event::PackedEventView::new(raw).unwrap().created_at()
    };
    for limit in [500, 1200] {
        let filter = json!({"authors": authors, "kinds": [0, 3, 10002], "limit": limit});
        let mut got = Vec::new();
        foreach_by_filter(&txn, &filter, 2000, 3, 16, |lev| got.push(created(lev))).unwrap();
        let want: Vec<_> = (0..400u64)
            .rev()
            .flat_map(|a| (0..3).rev().map(move |i| 1_700_000_000 + a * 10 + i))
            .take(limit)
            .collect();
        assert_eq!(got, want, "limit {limit}");
    }
}
