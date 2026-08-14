use std::process::Command;

use serde_json::json;
use tempfile::TempDir;
use wok_db::{
    check_integrity, write_events, DbError, Env, EnvOptions, EventToWrite, NoopNegentropy,
};
use wok_event::{parse_and_verify_event, EventLimits};

const CRASH_CHILD_ENV: &str = "WOK_DB_CRASH_CHILD";
const CRASH_DB_ENV: &str = "WOK_DB_CRASH_PATH";

fn signed_event(content: &str, created_at: u64) -> EventToWrite {
    use secp256k1::{Keypair, SECP256K1};

    let keypair = Keypair::new(SECP256K1, &mut rand::thread_rng());
    let (public_key, _) = keypair.x_only_public_key();
    let mut event = json!({
        "created_at": created_at,
        "kind": 1,
        "tags": [],
        "content": content,
        "pubkey": hex::encode(public_key.serialize()),
    });
    let id = wok_event::event_id_hash(&event).unwrap();
    event["id"] = json!(hex::encode(id));
    event["sig"] = json!(hex::encode(SECP256K1.sign_schnorr(&id, &keypair).as_ref()));
    let parsed =
        parse_and_verify_event(&event, &EventLimits::default(), None, true, false).unwrap();
    EventToWrite::new(parsed.packed.into_bytes(), parsed.json)
}

fn write_and_commit(env: &Env, event: &mut EventToWrite) {
    let mut txn = env.begin_rw().unwrap();
    write_events(
        &mut txn,
        &mut NoopNegentropy,
        std::slice::from_mut(event),
        false,
    )
    .unwrap();
    txn.commit().unwrap();
}

#[test]
fn crash_child_leaves_a_write_transaction_uncommitted() {
    if std::env::var_os(CRASH_CHILD_ENV).is_none() {
        return;
    }

    let path = std::env::var_os(CRASH_DB_ENV).expect("child database path");
    let env = Env::open(path, EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let mut event = signed_event("must not survive abort", 1_800_000_001);
    let mut txn = env.begin_rw().unwrap();
    write_events(
        &mut txn,
        &mut NoopNegentropy,
        std::slice::from_mut(&mut event),
        false,
    )
    .unwrap();

    // Simulate abrupt process death while the LMDB writer transaction and all
    // secondary-index changes are still live.
    std::process::abort();
}

#[test]
fn restart_after_writer_crash_preserves_only_committed_events() {
    let directory = TempDir::new().unwrap();
    let env = Env::open(directory.path(), EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let mut baseline = signed_event("committed baseline", 1_800_000_000);
    write_and_commit(&env, &mut baseline);
    drop(env);

    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "crash_child_leaves_a_write_transaction_uncommitted",
            "--nocapture",
        ])
        .env(CRASH_CHILD_ENV, "1")
        .env(CRASH_DB_ENV, directory.path())
        .status()
        .unwrap();
    assert!(
        !status.success(),
        "crash fixture unexpectedly exited cleanly"
    );

    let reopened = Env::open(directory.path(), EnvOptions::default()).unwrap();
    reopened.ensure_initialized().unwrap();
    let txn = reopened.begin_ro().unwrap();
    let report = check_integrity(&txn).unwrap();
    assert!(
        report.ok(),
        "integrity failure after writer crash: {report:#?}"
    );
    assert_eq!(report.events, 1, "uncommitted event survived process death");
}

fn constrained_options() -> EnvOptions {
    EnvOptions {
        map_size: 4 * 1024 * 1024,
        ..EnvOptions::default()
    }
}

#[test]
fn map_full_aborts_the_entire_transaction() {
    let directory = TempDir::new().unwrap();
    let env = Env::open(directory.path(), constrained_options()).unwrap();
    env.ensure_initialized().unwrap();
    let dbi = env.dbis().event_payload;
    let value = vec![0x5a; 128 * 1024];
    let mut txn = env.begin_rw().unwrap();
    let mut map_full = false;

    for key in 1..=1_024 {
        match txn.put_u64(dbi, key, &value, 0) {
            Ok(_) => {}
            Err(DbError::Lmdb(code, _)) if code == lmdb_sys::MDB_MAP_FULL => {
                map_full = true;
                break;
            }
            Err(error) => panic!("unexpected LMDB failure: {error}"),
        }
    }
    assert!(map_full, "fixture did not exhaust the constrained LMDB map");
    drop(txn);
    drop(env);

    let reopened = Env::open(directory.path(), constrained_options()).unwrap();
    let txn = reopened.begin_ro().unwrap();
    assert_eq!(txn.entries(reopened.dbis().event_payload).unwrap(), 0);
}
