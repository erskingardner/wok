//! Native directory backups preserve complete state and remain independent of
//! later writes. These checks run against each supported storage backend.

use std::collections::BTreeMap;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

use wok_db::{Env, EnvOptions, EventToWrite, NoopNegentropy};

type Records = BTreeMap<&'static str, Vec<(Vec<u8>, Vec<u8>)>>;

fn signed_event(author: u8, timestamp: u64) -> EventToWrite {
    use secp256k1::{Keypair, SecretKey, SECP256K1};
    let key = Keypair::from_secret_key(
        SECP256K1,
        &SecretKey::from_byte_array(&[author; 32]).unwrap(),
    );
    let mut json = serde_json::json!({
        "pubkey": hex::encode(key.x_only_public_key().0.serialize()),
        "created_at": timestamp,
        "kind": 1,
        "tags": [["t", "backup"]],
        "content": "complete native backup",
    });
    let id = wok_event::event_id_hash(&json).unwrap();
    json["id"] = serde_json::json!(hex::encode(id));
    json["sig"] = serde_json::json!(hex::encode(
        SECP256K1.sign_schnorr_no_aux_rand(&id, &key).as_ref()
    ));
    let parsed =
        wok_event::parse_and_verify_event(&json, &Default::default(), None, true, false).unwrap();
    EventToWrite::new(parsed.packed.into_bytes(), parsed.json)
}

fn seed(path: &Path) -> Env {
    let env = Env::open(path, EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let mut txn = env.begin_rw().unwrap();
    let mut events = [
        signed_event(7, 100),
        signed_event(7, 101),
        signed_event(8, 102),
    ];
    wok_db::write_events(&mut txn, &mut NoopNegentropy, &mut events, false).unwrap();
    wok_db::insert_compression_dictionary(&mut txn, b"backup dictionary").unwrap();
    wok_db::insert_negentropy_filter(&mut txn, r#"{"kinds":[1]}"#).unwrap();
    wok_db::mark_vanished(&mut txn, &[9; 32], 200).unwrap();
    wok_db::ban_pubkey(&mut txn, &[10; 32], "blocked").unwrap();
    wok_db::put_role(
        &mut txn,
        &wok_db::Role {
            id: "backup-reviewer".into(),
            label: "Reviewer".into(),
            description: "Preserved by backups".into(),
            color: "#336699".into(),
            order: 2,
        },
    )
    .unwrap();
    wok_db::assign_role(&mut txn, &[11; 32], "backup-reviewer").unwrap();
    // A deleted highest local ID must survive in state, rather than being
    // reconstructed from the remaining primary records after restoration.
    wok_db::delete_event_basic(&mut txn, events[2].lev_id).unwrap();
    txn.commit().unwrap();
    env
}

fn records(env: &Env) -> Records {
    let d = env.dbis();
    let tables = [
        ("meta", Some(d.meta)),
        ("negentropy_filter", Some(d.negentropy_filter)),
        ("event", Some(d.event)),
        ("event_id", Some(d.event_id)),
        ("event_pubkey_kind", Some(d.event_pubkey_kind)),
        ("event_tag", Some(d.event_tag)),
        ("event_deletion", Some(d.event_deletion)),
        ("event_replace", Some(d.event_replace)),
        ("event_created_at", Some(d.event_created_at)),
        ("event_pubkey", Some(d.event_pubkey)),
        ("event_replace_deletion", Some(d.event_replace_deletion)),
        ("event_kind", Some(d.event_kind)),
        ("event_expiration", Some(d.event_expiration)),
        ("compression_dictionary", Some(d.compression_dictionary)),
        ("event_payload", Some(d.event_payload)),
        ("negentropy", Some(d.negentropy)),
        ("event_search", d.event_search),
        ("vanish_pubkey", d.vanish_pubkey),
        ("moderation", d.moderation),
        ("state", d.state),
        ("event_tag_kind", d.event_tag_kind),
        ("event_tag_kind_build", d.event_tag_kind_build),
    ];
    assert_eq!(tables.len(), wok_db::dbi_specs().len());
    let txn = env.begin_ro().unwrap();
    tables
        .into_iter()
        .filter_map(|(name, dbi)| {
            dbi.map(|dbi| {
                let mut rows = Vec::new();
                txn.foreach_full(dbi, &[], &[], false, |key, value| {
                    rows.push((key.to_vec(), value.to_vec()));
                    true
                })
                .unwrap();
                (name, rows)
            })
        })
        .collect()
}

fn readonly(path: &Path) -> Env {
    Env::open(
        path,
        EnvOptions {
            read_only: true,
            create_dir: false,
            create_dbis: false,
            ..EnvOptions::for_tests()
        },
    )
    .unwrap()
}

#[test]
fn restored_backup_preserves_all_tables_and_is_independent_of_source_writes() {
    let dir = tempfile::tempdir().unwrap();
    let source = seed(&dir.path().join("source"));
    let before = records(&source);
    let destination = dir.path().join("backup");
    source.backup_to_directory(&destination).unwrap();
    assert_eq!(
        std::fs::metadata(&destination)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );

    let mut txn = source.begin_rw().unwrap();
    wok_db::delete_event_basic(&mut txn, 1).unwrap();
    wok_db::unban_pubkey(&mut txn, &[10; 32]).unwrap();
    let mut events = [signed_event(7, 103)];
    wok_db::write_events(&mut txn, &mut NoopNegentropy, &mut events, false).unwrap();
    assert_eq!(events[0].lev_id, 4);
    txn.commit().unwrap();
    assert_ne!(before, records(&source));
    drop(source);

    let restored = readonly(&destination);
    assert_eq!(before, records(&restored));
    assert!(wok_db::check_integrity(&restored.begin_ro().unwrap())
        .unwrap()
        .ok());
    drop(restored);

    let restored = Env::open(&destination, EnvOptions::for_tests()).unwrap();
    let mut txn = restored.begin_rw().unwrap();
    let mut events = [signed_event(8, 104)];
    wok_db::write_events(&mut txn, &mut NoopNegentropy, &mut events, false).unwrap();
    assert_eq!(events[0].lev_id, 4, "restored high-water mark was lost");
    txn.commit().unwrap();
}

#[test]
fn backup_refuses_existing_directories_files_symlinks_and_nested_outputs() {
    let dir = tempfile::tempdir().unwrap();
    let source = seed(&dir.path().join("source"));
    let empty = dir.path().join("empty");
    std::fs::create_dir(&empty).unwrap();
    let occupied = dir.path().join("occupied");
    std::fs::write(&occupied, b"keep me").unwrap();
    let dangling = dir.path().join("dangling");
    symlink(dir.path().join("missing"), &dangling).unwrap();
    for destination in [&empty, &occupied, &dangling] {
        assert!(source.backup_to_directory(destination).is_err());
    }
    assert!(empty.is_dir());
    assert_eq!(std::fs::read(&occupied).unwrap(), b"keep me");
    assert!(dangling.is_symlink());
    assert!(source
        .backup_to_directory(&source.path().join("nested"))
        .is_err());
    assert!(!source.path().join("nested").exists());
}

#[test]
fn atomic_publication_never_replaces_an_existing_empty_directory() {
    let dir = tempfile::tempdir().unwrap();
    let staging = dir.path().join("staging");
    let output = dir.path().join("output");
    std::fs::create_dir(&staging).unwrap();
    std::fs::write(staging.join("sentinel"), b"preserved").unwrap();
    std::fs::create_dir(&output).unwrap();
    assert!(wok_db::backup::promote_directory_noreplace(&staging, &output).is_err());
    assert_eq!(std::fs::read_dir(&output).unwrap().count(), 0);
    assert_eq!(
        std::fs::read(staging.join("sentinel")).unwrap(),
        b"preserved"
    );
    std::fs::remove_dir(&output).unwrap();
    wok_db::backup::promote_directory_noreplace(&staging, &output).unwrap();
    assert_eq!(
        std::fs::read(output.join("sentinel")).unwrap(),
        b"preserved"
    );
}

#[test]
fn readonly_rocksdb_backup_requires_an_exclusive_writable_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("source");
    drop(seed(&path));
    let source = readonly(&path);
    let output = dir.path().join("backup");
    assert!(source
        .backup_to_directory(&output)
        .unwrap_err()
        .to_string()
        .contains("exclusive writable"));
    assert!(!output.exists());
}
