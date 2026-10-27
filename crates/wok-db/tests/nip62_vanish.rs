use secp256k1::{Keypair, SECP256K1};
use serde_json::{json, Value};
use tempfile::TempDir;
use wok_db::{
    backfill_vanish_markers, get_packed_ro, is_event_vanished_ro, lookup_event_by_id_ro,
    sweep_vanished_events, vanish_timestamp_ro, write_events, write_events_with_policy, Env,
    EnvOptions, EventToWrite, EventWriteStatus, NoopNegentropy, VanishPolicy,
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
    let (gift_id, mut gift) = signed(&gift_sender, 1059, 150, json!([["p", author_hex.clone()]]));
    let (later_gift_id, mut later_gift) =
        signed(&gift_sender, 1059, 400, json!([["p", author_hex.clone()]]));
    for event in [
        &mut old,
        &mut newer,
        &mut deletion,
        &mut gift,
        &mut later_gift,
    ] {
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
    for id in [new_id, vanish_id, later_gift_id] {
        let (_, packed) = lookup_event_by_id_ro(&txn, &id).unwrap().unwrap();
        assert!(!is_event_vanished_ro(&txn, PackedEventView::new(&packed).unwrap()).unwrap());
    }
    drop(txn);

    let (_, mut rebroadcast) = signed(&author, 1, 100, json!([["x", "rebroadcast"]]));
    write_one(&env, &policy, &mut rebroadcast);
    assert_eq!(rebroadcast.status, EventWriteStatus::Deleted);
    let (_, mut backdated_gift) =
        signed(&gift_sender, 1059, 200, json!([["p", author_hex.clone()]]));
    write_one(&env, &policy, &mut backdated_gift);
    assert_eq!(backdated_gift.status, EventWriteStatus::Deleted);
    let (new_gift_id, mut new_gift) = signed(&gift_sender, 1059, 500, json!([["p", author_hex]]));
    write_one(&env, &policy, &mut new_gift);
    assert_eq!(new_gift.status, EventWriteStatus::Written);

    // A kind 5 after the request has no effect on the stored bookkeeping event.
    let (_, mut delete_vanish) = signed(&author, 5, 201, json!([["e", hex::encode(vanish_id)]]));
    write_one(&env, &policy, &mut delete_vanish);
    assert_eq!(delete_vanish.status, EventWriteStatus::Written);
    assert!(stored(&env, &vanish_id));

    // Sweep one record per transaction to prove the deletion lock is bounded.
    let mut cursor = Vec::new();
    let mut total_deleted = 0;
    for _ in 0..20 {
        let mut txn = env.begin_rw().unwrap();
        let deleted = sweep_vanished_events(&mut txn, &mut NoopNegentropy, 1, &mut cursor).unwrap();
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
    assert!(stored(&env, &later_gift_id));
    assert!(stored(&env, &new_gift_id));

    drop(env);
    let reopened = Env::open(directory.path(), EnvOptions::for_tests()).unwrap();
    assert_eq!(
        vanish_timestamp_ro(&reopened.begin_ro().unwrap(), &author_pubkey.serialize()).unwrap(),
        Some(200)
    );
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
/// author's events at created_at 0 and the gift wraps at 0 that p-tag the
/// author.
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
        for (created_at, status) in [
            (0, EventWriteStatus::Deleted),
            (1, EventWriteStatus::Written),
        ] {
            let (_, mut wrap) = signed(
                &sender,
                1059,
                created_at,
                json!([["p", hex::encode(pubkey.serialize())]]),
            );
            write_one(&env, &policy, &mut wrap);
            assert_eq!(wrap.status, status, "wrap at {created_at}");
        }
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

/// A gift wrap to a vanished pubkey falls under the request only up to its
/// created_at, as the pubkey's own events do, so the key can be sent wraps
/// again afterwards (#249). `same_batch_vanish_request_refuses_only_what_it_covers`
/// in wok-relay checks the same answers for a request and events in one
/// writer batch.
#[test]
fn gift_wraps_vanish_only_up_to_the_request() {
    let directory = TempDir::new().unwrap();
    let env = Env::open(directory.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let policy = VanishPolicy {
        enabled: true,
        service_url: String::new(),
    };
    let mut rng = rand::thread_rng();
    let recipient = Keypair::new(SECP256K1, &mut rng);
    let sender = Keypair::new(SECP256K1, &mut rng);
    let recipient_hex = hex::encode(recipient.x_only_public_key().0.serialize());
    let wrap = |created_at, label: &str| {
        signed(
            &sender,
            1059,
            created_at,
            json!([["p", recipient_hex], ["x", label]]),
        )
    };

    let (before_id, mut before) = wrap(900, "before");
    let (at_id, mut at) = wrap(1000, "at");
    let (after_id, mut after) = wrap(1100, "after");
    for event in [&mut before, &mut at, &mut after] {
        write_one(&env, &policy, event);
        assert_eq!(event.status, EventWriteStatus::Written);
    }

    let (_, mut request) = signed(&recipient, 62, 1000, json!([["relay", "ALL_RELAYS"]]));
    write_one(&env, &policy, &mut request);
    assert_eq!(request.status, EventWriteStatus::Written);
    let (_, mut late_wrap) = wrap(1000, "late");
    let (new_wrap_id, mut new_wrap) = wrap(1001, "new");
    let (_, mut late_note) = signed(&recipient, 1, 1000, json!([]));
    let (new_note_id, mut new_note) = signed(&recipient, 1, 1001, json!([]));
    for (event, status) in [
        (&mut late_wrap, EventWriteStatus::Deleted),
        (&mut new_wrap, EventWriteStatus::Written),
        (&mut late_note, EventWriteStatus::Deleted),
        (&mut new_note, EventWriteStatus::Written),
    ] {
        write_one(&env, &policy, event);
        assert_eq!(event.status, status);
    }

    let txn = env.begin_ro().unwrap();
    let vanished = |id: &[u8; 32]| {
        let (_, packed) = lookup_event_by_id_ro(&txn, id).unwrap().unwrap();
        is_event_vanished_ro(&txn, PackedEventView::new(&packed).unwrap()).unwrap()
    };
    assert!(vanished(&before_id));
    assert!(vanished(&at_id));
    assert!(!vanished(&after_id));
    assert!(!vanished(&new_wrap_id));
    assert!(!vanished(&new_note_id));
    drop(txn);

    let mut txn = env.begin_rw().unwrap();
    let deleted =
        sweep_vanished_events(&mut txn, &mut NoopNegentropy, 100, &mut Vec::new()).unwrap();
    txn.commit().unwrap();
    assert_eq!(deleted, 2);
    assert!(!stored(&env, &before_id));
    assert!(!stored(&env, &at_id));
    for id in [after_id, new_wrap_id, new_note_id] {
        assert!(stored(&env, &id));
    }
}
