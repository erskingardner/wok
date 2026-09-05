//! Process-death tests at real LMDB transaction boundaries. Checkpoints exist
//! only in this unit-test build, never in the library used by the relay or CLI.
use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::json;

use crate::{check_integrity, Env, EnvOptions, EventToWrite, NoopNegentropy};

const TARGET: &str = "WOK_DB_RECOVERY_CHECKPOINT";
const READY: &str = "WOK_DB_RECOVERY_READY";
const ACTION: &str = "WOK_DB_RECOVERY_ACTION";
const DATABASE: &str = "WOK_DB_RECOVERY_DATABASE";

pub(crate) fn checkpoint(stage: &str) {
    if std::env::var(TARGET).ok().as_deref() != Some(stage) {
        return;
    }
    std::fs::write(std::env::var_os(READY).expect("readiness path"), stage).unwrap();
    loop {
        std::thread::park();
    }
}

fn options(read_only: bool) -> EnvOptions {
    EnvOptions {
        map_size: 64 * 1024 * 1024,
        read_only,
        create_dir: !read_only,
        create_dbis: !read_only,
        ..EnvOptions::default()
    }
}

fn event(author: u8, kind: u64, time: u64) -> EventToWrite {
    use secp256k1::{Keypair, SecretKey, SECP256K1};
    let secret = SecretKey::from_byte_array(&[author; 32]).unwrap();
    let key = Keypair::from_secret_key(SECP256K1, &secret);
    let mut value = json!({"pubkey":hex::encode(key.x_only_public_key().0.serialize()),
        "kind":kind,"created_at":time,"tags":[],"content":"recovery fixture"});
    let id = wok_event::event_id_hash(&value).unwrap();
    value["id"] = json!(hex::encode(id));
    value["sig"] = json!(hex::encode(
        SECP256K1.sign_schnorr_no_aux_rand(&id, &key).as_ref()
    ));
    let parsed =
        wok_event::parse_and_verify_event(&value, &Default::default(), None, true, false).unwrap();
    EventToWrite::new(parsed.packed.into_bytes(), parsed.json)
}

fn seed(path: &Path) -> Env {
    let env = Env::open(path, options(false)).unwrap();
    env.ensure_initialized().unwrap();
    let mut txn = env.begin_rw().unwrap();
    let mut events = [event(7, 0, 100), event(7, 1, 101), event(8, 1, 102)];
    crate::write_events(&mut txn, &mut NoopNegentropy, &mut events, false).unwrap();
    assert_eq!(
        events.iter().map(|e| e.lev_id).collect::<Vec<_>>(),
        [1, 2, 3]
    );
    txn.commit().unwrap();
    env
}

fn mutate(env: &Env, action: &str) {
    let mut txn = env.begin_rw().unwrap();
    let mut events = match action {
        "insert" => vec![event(7, 1, 103)],
        "replace" => vec![event(7, 0, 103)],
        "delete" => {
            crate::delete_event_basic(&mut txn, 3).unwrap();
            vec![]
        }
        "mixed" => {
            crate::delete_event_basic(&mut txn, 2).unwrap();
            vec![event(7, 0, 103), event(8, 1, 104)]
        }
        _ => panic!("unknown action: {action}"),
    };
    crate::write_events(&mut txn, &mut NoopNegentropy, &mut events, false).unwrap();
    assert!(events
        .iter()
        .all(|event| event.status == crate::EventWriteStatus::Written));
    txn.commit().unwrap();
}

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    version: u64,
    records: Vec<(u64, Vec<u8>, Vec<u8>)>,
    state: Option<BTreeMap<Vec<u8>, Vec<u8>>>,
}

fn snapshot(env: &Env) -> Snapshot {
    let version = env.db_version().unwrap();
    let txn = env.begin_ro().unwrap();
    let report = check_integrity(&txn).unwrap();
    assert!(report.ok(), "{report:#?}");
    let mut records = Vec::new();
    txn.foreach_full(env.dbis().event, &[], &[], false, |key, value| {
        let id = u64::from_ne_bytes(key.try_into().unwrap());
        records.push((
            id,
            value.to_vec(),
            txn.get_u64(env.dbis().event_payload, id)
                .unwrap()
                .unwrap()
                .to_vec(),
        ));
        true
    })
    .unwrap();
    let state = env.dbis().state.map(|dbi| {
        let mut records = BTreeMap::new();
        txn.foreach_full(dbi, &[], &[], false, |key, value| {
            records.insert(key.to_vec(), value.to_vec());
            true
        })
        .unwrap();
        records
    });
    Snapshot {
        version,
        records,
        state,
    }
}

struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn kill_at(path: &Path, action: &str, stage: &str) {
    let ready_dir = tempfile::tempdir().unwrap();
    let ready = ready_dir.path().join("ready");
    let mut child = KillOnDrop(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "crash_tests::recovery_child", "--nocapture"])
            .env(DATABASE, path)
            .env(ACTION, action)
            .env(TARGET, stage)
            .env(READY, &ready)
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if std::fs::read_to_string(&ready).ok().as_deref() == Some(stage) {
            break;
        }
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "child exited before {action}/{stage}"
        );
        assert!(
            Instant::now() < deadline,
            "child never reached {action}/{stage}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    child.0.kill().unwrap();
    let status = child.0.wait().unwrap();
    assert!(!status.success());
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(libc::SIGKILL));
    }
}

#[test]
fn recovery_child() {
    let Ok(action) = std::env::var(ACTION) else {
        return;
    };
    let env = Env::open(std::env::var_os(DATABASE).unwrap(), options(false)).unwrap();
    if action != "upgrade" {
        mutate(&env, &action);
    }
    panic!("child did not reach its checkpoint");
}

fn assert_counts_and_sequence(env: &Env, counts: [u64; 2], sequence: u64) {
    let txn = env.begin_ro().unwrap();
    assert_eq!(crate::state::high_water_ro(&txn).unwrap(), Some(sequence));
    for (author, count) in [7, 8].into_iter().zip(counts) {
        let packed = event(author, 1, 100).packed;
        let view = wok_event::PackedEventView::new(&packed).unwrap();
        let mut key = vec![b'a'];
        key.extend_from_slice(view.pubkey());
        let raw = txn.get(env.dbis().state.unwrap(), &key).unwrap().unwrap();
        assert_eq!(raw, count.to_le_bytes());
    }
}

#[test]
fn killed_writes_recover_atomic_events_counters_and_sequence() {
    for lazy in [false, true] {
        for action in ["insert", "replace", "delete", "mixed"] {
            for stage in [
                "write-before-flush",
                "sequence-staged",
                "author-count-staged",
                "write-before-commit",
                "write-after-commit",
            ] {
                let dir = tempfile::tempdir().unwrap();
                let env = seed(dir.path());
                let env = if lazy {
                    env.into_test_fixture_without_state(4);
                    Env::open(dir.path(), options(false)).unwrap()
                } else {
                    env
                };
                let before = snapshot(&env);
                drop(env);
                // Independently committed reference, including exact signed JSON
                // and PackedEvent bytes, to reject partially visible mutations.
                let expected_dir = tempfile::tempdir().unwrap();
                let expected = seed(expected_dir.path());
                let expected = if lazy {
                    expected.into_test_fixture_without_state(4);
                    Env::open(expected_dir.path(), options(false)).unwrap()
                } else {
                    expected
                };
                mutate(&expected, action);
                let after = snapshot(&expected);
                drop(expected);
                kill_at(dir.path(), action, stage);
                let reopened = Env::open(dir.path(), options(true)).unwrap();
                let committed = stage == "write-after-commit";
                assert_eq!(
                    snapshot(&reopened),
                    if committed { after } else { before },
                    "{lazy}/{action}/{stage}"
                );
                let (counts, sequence) = if committed {
                    match action {
                        "insert" => ([3, 1], 4),
                        "replace" => ([2, 1], 4),
                        "delete" => ([2, 0], 3),
                        "mixed" => ([1, 2], 5),
                        _ => unreachable!(),
                    }
                } else {
                    ([2, 1], 3)
                };
                // Lazy state can legitimately omit untouched author keys.
                if !lazy {
                    assert_counts_and_sequence(&reopened, counts, sequence);
                }
                drop(reopened);
                let reopened = Env::open(dir.path(), options(false)).unwrap();
                let mut txn = reopened.begin_rw().unwrap();
                for (author, count) in [7, 8].into_iter().zip(counts) {
                    let packed = event(author, 1, 100).packed;
                    assert_eq!(
                        crate::state::author_count(
                            &mut txn,
                            wok_event::PackedEventView::new(&packed).unwrap().pubkey()
                        )
                        .unwrap(),
                        count
                    );
                }
                let mut probe = [event(7, 1, 200)];
                crate::write_events(&mut txn, &mut NoopNegentropy, &mut probe, false).unwrap();
                assert_eq!(probe[0].lev_id, sequence + 1, "{lazy}/{action}/{stage}");
                txn.commit().unwrap();
                drop(reopened);
                snapshot(&Env::open(dir.path(), options(true)).unwrap());
            }
        }
    }
}

#[test]
fn killed_v4_upgrade_is_atomic_and_retryable() {
    for stage in [
        "upgrade-marker-staged",
        "open-before-commit",
        "open-after-commit",
    ] {
        let dir = tempfile::tempdir().unwrap();
        seed(dir.path()).into_test_fixture_without_state(4);
        let before = snapshot(&Env::open(dir.path(), options(true)).unwrap());
        assert_eq!(before.version, 4);
        assert!(before.state.is_none());
        kill_at(dir.path(), "upgrade", stage);
        let after = snapshot(&Env::open(dir.path(), options(true)).unwrap());
        assert_eq!(before.records, after.records);
        if stage == "open-after-commit" {
            assert_eq!(after.version, 5);
            assert_eq!(after.state, Some(BTreeMap::new()));
        } else {
            assert_eq!(before, after);
        }
        let env = Env::open(dir.path(), options(false)).unwrap();
        assert_eq!(env.db_version().unwrap(), 5);
        mutate(&env, "insert");
        let snapshot = snapshot(&env);
        assert_eq!(snapshot.records.last().unwrap().0, 4);
    }
}

#[test]
fn v5_without_state_table_is_corrupt() {
    let dir = tempfile::tempdir().unwrap();
    seed(dir.path()).into_test_fixture_without_state(5);
    let env = Env::open(dir.path(), options(true)).unwrap();
    let report = check_integrity(&env.begin_ro().unwrap()).unwrap();
    assert!(!report.ok());
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.category == "missing-table" && issue.table == "state"));
}
