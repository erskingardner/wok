//! The state checker must use primary events, tolerate lazy initialization,
//! and distinguish rebuildable author counts from lost sequence information.
use serde_json::json;
use wok_db::{check_integrity, Env, EnvOptions, EventToWrite, NoopNegentropy};

fn fixture() -> (tempfile::TempDir, Env, Vec<u8>) {
    use secp256k1::{Keypair, SECP256K1};
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let key = Keypair::new(SECP256K1, &mut rand::thread_rng());
    let public = key.x_only_public_key().0.serialize();
    let mut event = json!({"pubkey":hex::encode(public),"kind":1,"created_at":100,"tags":[],"content":"state integrity"});
    let id = wok_event::event_id_hash(&event).unwrap();
    event["id"] = json!(hex::encode(id));
    event["sig"] = json!(hex::encode(SECP256K1.sign_schnorr(&id, &key).as_ref()));
    let parsed =
        wok_event::parse_and_verify_event(&event, &Default::default(), None, true, false).unwrap();
    let mut events = [EventToWrite::new(parsed.packed.into_bytes(), parsed.json)];
    let mut txn = env.begin_rw().unwrap();
    wok_db::write_events(&mut txn, &mut NoopNegentropy, &mut events, false).unwrap();
    txn.commit().unwrap();
    let mut counter = vec![b'a'];
    counter.extend_from_slice(&public);
    (dir, env, counter)
}

#[test]
fn detects_counter_drift_from_primaries_even_with_matching_corrupt_author_index() {
    let (_dir, env, counter) = fixture();
    let mut txn = env.begin_rw().unwrap();
    txn.put(env.dbis().state.unwrap(), &counter, &0u64.to_le_bytes(), 0)
        .unwrap();
    txn.clear(env.dbis().event_pubkey).unwrap();
    txn.commit().unwrap();
    let report = check_integrity(&env.begin_ro().unwrap()).unwrap();
    assert!(!report.ok());
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.category == "counter-mismatch" && i.table == "author_counts"),
        "{report:#?}"
    );
}

#[test]
fn detects_regressed_sequence_and_malformed_state() {
    for (key, value, category) in [
        (
            b"sequence".as_slice(),
            0u64.to_le_bytes().to_vec(),
            "sequence-regression",
        ),
        (b"sequence", vec![1], "malformed-value"),
        (b"visibility", vec![1], "malformed-value"),
        (b"unknown", 0u64.to_le_bytes().to_vec(), "malformed-key"),
        (b"a", 0u64.to_le_bytes().to_vec(), "malformed-key"),
    ] {
        let (_dir, env, _) = fixture();
        let mut txn = env.begin_rw().unwrap();
        txn.put(env.dbis().state.unwrap(), key, &value, 0).unwrap();
        txn.commit().unwrap();
        let report = check_integrity(&env.begin_ro().unwrap()).unwrap();
        assert!(!report.ok(), "{key:?}");
        assert!(
            report.issues.iter().any(|i| i.category == category),
            "{report:#?}"
        );
    }
}

#[test]
fn lazy_counters_missing_sequence_and_deleted_tails_are_valid() {
    let (_dir, env, counter) = fixture();
    let mut txn = env.begin_rw().unwrap();
    txn.clear(env.dbis().state.unwrap()).unwrap();
    txn.commit().unwrap();
    // This is the legitimate state of a just-upgraded v4 database.
    assert!(check_integrity(&env.begin_ro().unwrap()).unwrap().ok());
    let mut txn = env.begin_rw().unwrap();
    // Counts can initialize independently of sequence allocation.
    assert_eq!(
        wok_db::state::author_count(&mut txn, &counter[1..]).unwrap(),
        1
    );
    txn.commit().unwrap();
    assert!(check_integrity(&env.begin_ro().unwrap()).unwrap().ok());
    let mut txn = env.begin_rw().unwrap();
    wok_db::delete_event_basic(&mut txn, 1).unwrap();
    txn.commit().unwrap();
    let txn = env.begin_ro().unwrap();
    assert_eq!(wok_db::state::high_water_ro(&txn).unwrap(), Some(1));
    assert_eq!(
        txn.get(env.dbis().state.unwrap(), &counter)
            .unwrap()
            .unwrap(),
        0u64.to_le_bytes()
    );
    assert!(check_integrity(&txn).unwrap().ok());
}

#[test]
fn malformed_and_orphan_positive_author_counts_are_detected() {
    for value in [vec![1], 2u64.to_le_bytes().to_vec()] {
        let (_dir, env, counter) = fixture();
        let mut txn = env.begin_rw().unwrap();
        txn.put(env.dbis().state.unwrap(), &counter, &value, 0)
            .unwrap();
        txn.commit().unwrap();
        let report = check_integrity(&env.begin_ro().unwrap()).unwrap();
        assert!(!report.ok());
        assert!(
            report.issues.iter().any(|i| i.table == "author_counts"),
            "{report:#?}"
        );
    }
    let (_dir, env, _) = fixture();
    let mut txn = env.begin_rw().unwrap();
    let mut missing_author = vec![b'a'];
    missing_author.extend_from_slice(&[0; 32]);
    txn.put(
        env.dbis().state.unwrap(),
        &missing_author,
        &1u64.to_le_bytes(),
        0,
    )
    .unwrap();
    txn.commit().unwrap();
    assert!(!check_integrity(&env.begin_ro().unwrap()).unwrap().ok());
}
