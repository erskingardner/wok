use secp256k1::{Keypair, SECP256K1};
use serde_json::{json, Value};
use tempfile::TempDir;
use wok_db::{
    backfill_vanish_markers, check_integrity, delete_events, get_packed_ro, is_event_vanished_ro,
    lookup_event_by_id_ro, sweep_vanished_events, vanish_timestamp_ro, write_events,
    write_events_with_policy, Env, EnvOptions, EventToWrite, EventWriteStatus, NoopNegentropy,
    VanishPolicy, VanishSweepCursor, VanishSweepStep,
};
use wok_event::{parse_and_verify_event, EventLimits, PackedEventView};

fn signed(key: &Keypair, kind: u64, created_at: u64, tags: Value) -> ([u8; 32], EventToWrite) {
    let (pubkey, _) = key.x_only_public_key();
    let mut event = json!({
        "created_at": created_at,
        "kind": kind,
        "tags": tags,
        "content": "nip62-test",
        "pubkey": hex::encode(pubkey.serialize()),
    });
    let id = wok_event::event_id_hash(&event).unwrap();
    event["id"] = json!(hex::encode(id));
    let signature = SECP256K1.sign_schnorr(&id, key);
    event["sig"] = json!(hex::encode(signature.as_ref()));
    let parsed =
        parse_and_verify_event(&event, &EventLimits::default(), None, true, false).unwrap();
    (
        id,
        EventToWrite::new(parsed.packed.into_bytes(), parsed.json),
    )
}

fn write_one(env: &Env, policy: &VanishPolicy, event: &mut EventToWrite) {
    let mut txn = env.begin_rw().unwrap();
    write_events_with_policy(
        &mut txn,
        &mut NoopNegentropy,
        std::slice::from_mut(event),
        false,
        policy,
    )
    .unwrap();
    txn.commit().unwrap();
}

fn stored(env: &Env, id: &[u8; 32]) -> bool {
    lookup_event_by_id_ro(&env.begin_ro().unwrap(), id)
        .unwrap()
        .is_some()
}

#[test]
fn vanish_is_immediate_persistent_bounded_and_cannot_be_undone() {
    let directory = TempDir::new().unwrap();
    let env = Env::open(directory.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let policy = VanishPolicy {
        enabled: true,
        service_url: "wss://relay.example.com/".into(),
    };
    let mut rng = rand::thread_rng();
    let author = Keypair::new(SECP256K1, &mut rng);
    let gift_sender = Keypair::new(SECP256K1, &mut rng);
    let (author_pubkey, _) = author.x_only_public_key();
    let author_hex = hex::encode(author_pubkey.serialize());

    let (old_id, mut old) = signed(&author, 1, 100, json!([]));
    let (new_id, mut newer) = signed(&author, 1, 300, json!([]));
    let (deletion_id, mut deletion) = signed(&author, 5, 150, json!([["e", "00".repeat(32)]]));
    let (gift_id, mut gift) = signed(&gift_sender, 1059, 400, json!([["p", author_hex.clone()]]));
    for event in [&mut old, &mut newer, &mut deletion, &mut gift] {
        write_one(&env, &policy, event);
        assert_eq!(event.status, EventWriteStatus::Written);
    }

    let (vanish_id, mut vanish) = signed(&author, 62, 200, json!([["relay", "ALL_RELAYS"]]));
    write_one(&env, &policy, &mut vanish);
    assert_eq!(vanish.status, EventWriteStatus::Written);

    let txn = env.begin_ro().unwrap();
    assert_eq!(
        vanish_timestamp_ro(&txn, &author_pubkey.serialize()).unwrap(),
        Some(200)
    );
    for id in [old_id, deletion_id, gift_id] {
        let (_, packed) = lookup_event_by_id_ro(&txn, &id).unwrap().unwrap();
        assert!(is_event_vanished_ro(&txn, PackedEventView::new(&packed).unwrap()).unwrap());
    }
    for id in [new_id, vanish_id] {
        let (_, packed) = lookup_event_by_id_ro(&txn, &id).unwrap().unwrap();
        assert!(!is_event_vanished_ro(&txn, PackedEventView::new(&packed).unwrap()).unwrap());
    }
    drop(txn);

    let (_, mut rebroadcast) = signed(&author, 1, 100, json!([["x", "rebroadcast"]]));
    write_one(&env, &policy, &mut rebroadcast);
    assert_eq!(rebroadcast.status, EventWriteStatus::Deleted);
    let (_, mut new_gift) = signed(&gift_sender, 1059, 500, json!([["p", author_hex]]));
    write_one(&env, &policy, &mut new_gift);
    assert_eq!(new_gift.status, EventWriteStatus::Deleted);

    // A kind 5 after the request has no effect on the stored bookkeeping event.
    let (_, mut delete_vanish) = signed(&author, 5, 201, json!([["e", hex::encode(vanish_id)]]));
    write_one(&env, &policy, &mut delete_vanish);
    assert_eq!(delete_vanish.status, EventWriteStatus::Written);
    assert!(stored(&env, &vanish_id));

    // Sweep one record per transaction to prove the deletion lock is bounded.
    let mut cursor = Default::default();
    let mut total_deleted = 0;
    for _ in 0..20 {
        let mut txn = env.begin_rw().unwrap();
        let deleted = sweep_vanished_events(&mut txn, &mut NoopNegentropy, 1, &mut cursor)
            .unwrap()
            .deleted;
        assert!(deleted <= 1);
        total_deleted += deleted;
        txn.commit().unwrap();
        if !stored(&env, &old_id) && !stored(&env, &gift_id) && !stored(&env, &deletion_id) {
            break;
        }
    }
    assert!(total_deleted >= 3);
    assert!(!stored(&env, &old_id));
    assert!(!stored(&env, &gift_id));
    assert!(!stored(&env, &deletion_id));
    assert!(stored(&env, &new_id));
    assert!(stored(&env, &vanish_id));

    drop(env);
    let reopened = Env::open(directory.path(), EnvOptions::for_tests()).unwrap();
    assert_eq!(
        vanish_timestamp_ro(&reopened.begin_ro().unwrap(), &author_pubkey.serialize()).unwrap(),
        Some(200)
    );
}

/// Mentions of a vanished key in events the sweep keeps cost one bounded
/// pass, examined once each, across ticks and restarts.
#[test]
fn the_sweep_examines_each_mention_of_a_vanished_key_once_in_bounded_steps() {
    let directory = TempDir::new().unwrap();
    let env = Env::open(directory.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let policy = VanishPolicy {
        enabled: true,
        service_url: "wss://relay.example.com/".into(),
    };
    let mut rng = rand::thread_rng();
    let author = Keypair::new(SECP256K1, &mut rng);
    let other = Keypair::new(SECP256K1, &mut rng);
    let sender = Keypair::new(SECP256K1, &mut rng);
    let author_hex = hex::encode(author.x_only_public_key().0.serialize());

    // Gift wraps to the author before, among and after 50 kind 1 mentions.
    let mut events = Vec::new();
    let mut mentions = Vec::new();
    for created_at in 10..60 {
        let (id, event) = signed(&sender, 1, created_at, json!([["p", author_hex]]));
        mentions.push(id);
        events.push(event);
    }
    let mut wraps = Vec::new();
    for created_at in [5, 30, 190] {
        let (id, event) = signed(&sender, 1059, created_at, json!([["p", author_hex]]));
        wraps.push(id);
        events.push(event);
    }
    let (authored, event) = signed(&author, 1, 100, json!([]));
    events.push(event);
    let (later, event) = signed(&author, 1, 300, json!([]));
    events.push(event);
    let (other_authored, event) = signed(&other, 1, 100, json!([]));
    events.push(event);
    let mut requests = Vec::new();
    for key in [&author, &other] {
        let (id, event) = signed(key, 62, 200, json!([["relay", "ALL_RELAYS"]]));
        requests.push(id);
        events.push(event);
    }
    for event in &mut events {
        write_one(&env, &policy, event);
        assert_eq!(event.status, EventWriteStatus::Written);
    }

    const BATCH: usize = 4;
    let sweep = |cursor: &mut VanishSweepCursor| {
        let mut txn = env.begin_rw().unwrap();
        let step = sweep_vanished_events(&mut txn, &mut NoopNegentropy, BATCH, cursor).unwrap();
        txn.commit().unwrap();
        assert!(step.examined <= BATCH && step.markers <= BATCH, "{step:?}");
        step
    };
    // Sweep until a step examines nothing, with a restart (a new cursor)
    // part way. Returns the entries examined.
    let pass = |cursor: &mut VanishSweepCursor| {
        let mut examined = 0;
        for tick in 1.. {
            assert!(tick < 100, "the pass never finished");
            if tick == 5 {
                *cursor = VanishSweepCursor::default();
            }
            let step = sweep(cursor);
            if step.examined == 0 {
                return examined;
            }
            examined += step.examined;
        }
        unreachable!()
    };
    let idle = |cursor: &mut VanishSweepCursor| {
        let mut steps = (0..4).map(|_| sweep(cursor)).collect::<Vec<_>>();
        assert!(steps.iter().all(|step| step.examined == 0), "{steps:?}");
        // At most a round of the markers to find every pass finished.
        steps.retain(|step| step.markers > 0);
        assert!(steps.len() <= 1, "{steps:?}");
    };

    // The author's two events through the request, the other key's two,
    // and the 53 events that p-tag the author.
    let mut cursor = VanishSweepCursor::default();
    assert_eq!(pass(&mut cursor), 2 + 2 + 53);
    for id in wraps.iter().chain([&authored, &other_authored]) {
        assert!(!stored(&env, id));
    }
    for id in mentions.iter().chain(&requests).chain([&later]) {
        assert!(stored(&env, id));
    }
    idle(&mut cursor);
    idle(&mut VanishSweepCursor::default());

    // Deleting an event changes what reads may see, not the markers.
    let (lev_id, _) = lookup_event_by_id_ro(&env.begin_ro().unwrap(), &mentions[0])
        .unwrap()
        .unwrap();
    let mut txn = env.begin_rw().unwrap();
    assert_eq!(
        delete_events(&mut txn, &mut NoopNegentropy, vec![lev_id]).unwrap(),
        1
    );
    txn.commit().unwrap();
    assert_eq!(sweep(&mut cursor), VanishSweepStep::default());

    // A later request raises the marker: one pass over the author's events
    // it adds, and none of the mentions again.
    let (raised, mut request) = signed(&author, 62, 400, json!([["relay", "ALL_RELAYS"]]));
    write_one(&env, &policy, &mut request);
    assert_eq!(request.status, EventWriteStatus::Written);
    assert_eq!(pass(&mut cursor), 2);
    assert!(!stored(&env, &later));
    assert!(stored(&env, &raised));
    idle(&mut cursor);

    assert!(check_integrity(&env.begin_ro().unwrap()).unwrap().ok());
}

#[test]
fn target_validation_max_timestamp_and_kind5_tombstone_rules() {
    let directory = TempDir::new().unwrap();
    let env = Env::open(directory.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let policy = VanishPolicy {
        enabled: true,
        service_url: "wss://relay.example.com/".into(),
    };
    let mut rng = rand::thread_rng();
    let author = Keypair::new(SECP256K1, &mut rng);
    let (pubkey, _) = author.x_only_public_key();

    let (_, mut wrong_target) = signed(
        &author,
        62,
        100,
        json!([["relay", "wss://somewhere.example/"]]),
    );
    write_one(&env, &policy, &mut wrong_target);
    assert_eq!(wrong_target.status, EventWriteStatus::Deleted);
    assert_eq!(
        vanish_timestamp_ro(&env.begin_ro().unwrap(), &pubkey.serialize()).unwrap(),
        None
    );

    let (future_id, mut future_request) = signed(
        &author,
        62,
        200,
        json!([["relay", "wss://relay.example.com"]]),
    );
    let (_, mut tombstone) = signed(&author, 5, 150, json!([["e", hex::encode(future_id)]]));
    write_one(&env, &policy, &mut tombstone);
    write_one(&env, &policy, &mut future_request);
    assert_eq!(future_request.status, EventWriteStatus::Written);

    let (_, mut older_request) = signed(&author, 62, 175, json!([["relay", "ALL_RELAYS"]]));
    write_one(&env, &policy, &mut older_request);
    assert_eq!(
        vanish_timestamp_ro(&env.begin_ro().unwrap(), &pubkey.serialize()).unwrap(),
        Some(200)
    );
    assert!(stored(&env, &future_id));

    // The marker points to a real stored event, not a dangling DBI record.
    let (lev, _) = lookup_event_by_id_ro(&env.begin_ro().unwrap(), &future_id)
        .unwrap()
        .unwrap();
    assert!(get_packed_ro(&env.begin_ro().unwrap(), lev)
        .unwrap()
        .is_some());
}

#[test]
fn existing_request_records_are_backfilled_for_migrations() {
    let directory = TempDir::new().unwrap();
    let env = Env::open(directory.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let mut rng = rand::thread_rng();
    let author = Keypair::new(SECP256K1, &mut rng);
    let (pubkey, _) = author.x_only_public_key();
    let (_, mut request) = signed(&author, 62, 200, json!([["relay", "ALL_RELAYS"]]));

    // Simulate a kind-62 record copied from a database that predates Wok's
    // NIP-62 marker table: generic storage keeps the event but has no policy
    // with which to decide whether it targets this relay.
    let mut txn = env.begin_rw().unwrap();
    write_events(
        &mut txn,
        &mut NoopNegentropy,
        std::slice::from_mut(&mut request),
        false,
    )
    .unwrap();
    txn.commit().unwrap();
    assert_eq!(request.status, EventWriteStatus::Written);
    assert_eq!(
        vanish_timestamp_ro(&env.begin_ro().unwrap(), &pubkey.serialize()).unwrap(),
        None
    );

    let policy = VanishPolicy {
        enabled: true,
        service_url: String::new(),
    };
    assert_eq!(
        backfill_vanish_markers(&env, &policy, 1_000_000).unwrap(),
        1
    );
    assert_eq!(
        vanish_timestamp_ro(&env.begin_ro().unwrap(), &pubkey.serialize()).unwrap(),
        Some(200)
    );
    assert_eq!(
        backfill_vanish_markers(&env, &policy, 1_000_000).unwrap(),
        0
    );
}

/// A request at created_at 0 leaves a marker, written live or by the
/// backfill, which reads the kind index from its first entry: it covers the
/// author's events at created_at 0 and the gift wraps that p-tag the author.
#[test]
fn a_request_at_created_at_zero_leaves_a_marker() {
    let policy = VanishPolicy {
        enabled: true,
        service_url: String::new(),
    };
    let mut rng = rand::thread_rng();
    let recipient = Keypair::new(SECP256K1, &mut rng).x_only_public_key().0;
    for backfilled in [false, true] {
        let directory = TempDir::new().unwrap();
        let env = Env::open(directory.path(), EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let author = Keypair::new(SECP256K1, &mut rng);
        let (pubkey, _) = author.x_only_public_key();
        let (_, mut request) = signed(&author, 62, 0, json!([["relay", "ALL_RELAYS"]]));
        if backfilled {
            let mut txn = env.begin_rw().unwrap();
            write_events(
                &mut txn,
                &mut NoopNegentropy,
                std::slice::from_mut(&mut request),
                false,
            )
            .unwrap();
            txn.commit().unwrap();
            assert_eq!(
                backfill_vanish_markers(&env, &policy, 1_000_000).unwrap(),
                1
            );
        } else {
            write_one(&env, &policy, &mut request);
        }
        assert_eq!(request.status, EventWriteStatus::Written);
        assert_eq!(
            vanish_timestamp_ro(&env.begin_ro().unwrap(), &pubkey.serialize()).unwrap(),
            Some(0),
            "backfilled: {backfilled}"
        );

        let (_, mut at_zero) = signed(&author, 1, 0, json!([]));
        write_one(&env, &policy, &mut at_zero);
        assert_eq!(at_zero.status, EventWriteStatus::Deleted);
        let (_, mut later) = signed(&author, 1, 1, json!([]));
        write_one(&env, &policy, &mut later);
        assert_eq!(later.status, EventWriteStatus::Written);
        let sender = Keypair::new(SECP256K1, &mut rng);
        let (_, mut wrap) = signed(
            &sender,
            1059,
            100,
            json!([["p", hex::encode(pubkey.serialize())]]),
        );
        write_one(&env, &policy, &mut wrap);
        assert_eq!(wrap.status, EventWriteStatus::Deleted);
        let (_, mut other) = signed(
            &sender,
            1059,
            100,
            json!([["p", hex::encode(recipient.serialize())]]),
        );
        write_one(&env, &policy, &mut other);
        assert_eq!(other.status, EventWriteStatus::Written);
    }
}
