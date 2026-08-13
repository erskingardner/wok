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
    let env = Env::open(directory.path(), EnvOptions::default()).unwrap();
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

    drop(env);
    let reopened = Env::open(directory.path(), EnvOptions::default()).unwrap();
    assert_eq!(
        vanish_timestamp_ro(&reopened.begin_ro().unwrap(), &author_pubkey.serialize()).unwrap(),
        Some(200)
    );
}

#[test]
fn target_validation_max_timestamp_and_kind5_tombstone_rules() {
    let directory = TempDir::new().unwrap();
    let env = Env::open(directory.path(), EnvOptions::default()).unwrap();
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
    let env = Env::open(directory.path(), EnvOptions::default()).unwrap();
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
