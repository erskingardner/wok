//! The directory protects every native file, including WAL and compaction output.

use std::os::unix::fs::PermissionsExt;
use wok_db::{Env, EnvOptions};

fn mode(path: &std::path::Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn new_database_directory_excludes_other_users() {
    let root = tempfile::tempdir().unwrap();
    let db = root.path().join("new-db");
    let env = Env::open(&db, EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    assert_eq!(mode(&db) & 0o077, 0);
    assert!(db.join("CURRENT").is_file());
}

#[test]
fn writable_open_protects_an_existing_directory_and_keeps_group_permissions() {
    let root = tempfile::tempdir().unwrap();
    let db = root.path().join("db");
    std::fs::create_dir(&db).unwrap();
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o755)).unwrap();
    let env = Env::open(&db, EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    assert_eq!(mode(&db), 0o750);
    drop(env);

    let backup = root.path().join("backup");
    let env = Env::open(&db, EnvOptions::for_tests()).unwrap();
    env.backup_to_directory(&backup).unwrap();
    assert_eq!(mode(&backup) & 0o007, 0);
    assert!(backup.join("CURRENT").is_file());
}

#[test]
fn rejecting_lmdb_does_not_change_its_bytes_or_permissions() {
    let root = tempfile::tempdir().unwrap();
    let db = root.path().join("legacy");
    std::fs::create_dir(&db).unwrap();
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(db.join("data.mdb"), b"preserved legacy source").unwrap();
    let error = Env::open(&db, EnvOptions::for_tests()).unwrap_err();
    assert!(error.to_string().contains("wok migrate rocksdb"));
    assert_eq!(mode(&db), 0o755);
    assert_eq!(
        std::fs::read(db.join("data.mdb")).unwrap(),
        b"preserved legacy source"
    );
    assert_eq!(std::fs::read_dir(&db).unwrap().count(), 1);
}
