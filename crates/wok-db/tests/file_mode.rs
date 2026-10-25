//! Permission bits of the database files Wok creates.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use wok_db::{event_fingerprint, snapshot_lmdb_readonly, Env, EnvOptions};

/// Files are created with mode `0o640` less the umask, so whatever the umask
/// they never give other users access.
fn assert_no_other_access(path: &Path) {
    let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode & !0o640, 0, "{} has mode {mode:o}", path.display());
}

fn env_with_an_event(path: &Path) -> Env {
    let env = Env::open(path, EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let packed = wok_event::PackedEventBuilder::build(
        &[1; 32],
        &[9; 32],
        1,
        1,
        0,
        &wok_event::PackedEventTagBuilder::default(),
    )
    .unwrap();
    let json = serde_json::json!({"id":hex::encode([1;32]),"pubkey":hex::encode([9;32]),"created_at":1,"kind":1,"tags":[],"content":"","sig":"00".repeat(64)});
    let mut events = [wok_db::EventToWrite::new(
        packed.into_bytes(),
        json.to_string(),
    )];
    let mut txn = env.begin_rw().unwrap();
    wok_db::write_events(&mut txn, &mut wok_db::NoopNegentropy, &mut events, false).unwrap();
    txn.commit().unwrap();
    env
}

#[test]
fn a_new_environment_gives_other_users_no_access() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    assert_no_other_access(&dir.path().join("data.mdb"));
    assert_no_other_access(&dir.path().join("lock.mdb"));
}

#[test]
fn a_compact_copy_is_the_named_file_and_gives_other_users_no_access() {
    let dir = tempfile::tempdir().unwrap();
    let env = env_with_an_event(&dir.path().join("source"));
    let copy_dir = dir.path().join("copy");
    std::fs::create_dir(&copy_dir).unwrap();
    let copy = copy_dir.join("data.mdb");

    env.compact_to_path(&copy).unwrap();
    assert_no_other_access(&copy);
    let err = env.compact_to_path(&copy).unwrap_err();
    assert!(err.to_string().contains("exists, not overwriting"), "{err}");

    let copied = Env::open(&copy_dir, EnvOptions::for_tests()).unwrap();
    assert_eq!(
        event_fingerprint(&copied).unwrap(),
        event_fingerprint(&env).unwrap()
    );
}

#[test]
fn a_migration_snapshot_gives_other_users_no_access() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    drop(env_with_an_event(&source));
    let snapshot = dir.path().join("snapshot");

    snapshot_lmdb_readonly(&source, &snapshot, false).unwrap();
    assert_no_other_access(&snapshot.join("data.mdb"));
}
