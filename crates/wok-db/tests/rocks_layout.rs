#![cfg(feature = "rocksdb-backend")]
//! Physical layouts stay separate; authoritative bytes and writer semantics do not.

use rocksdb::{ColumnFamilyDescriptor, Options, DB};
use secp256k1::{Keypair, SecretKey, SECP256K1};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;
use wok_db::{Decompressor, Env, EnvOptions, EventToWrite, NoopNegentropy};

const COMBINED: &str = "wok_events_combined_v1";
const COVERING: &str = "wok_pubkey_covering_v1";
const FORMAT_KEY: &[u8] = b"wok-rocksdb-format";
const DUAL: &[u8] = b"wok-rocks-v1:combined:dual-author:reverse-order:sync-wal";
const COVERLESS: &[u8] = b"wok-rocks-v2:combined:thin-author:reverse-order:sync-wal";
const HEADS: &[u8] = b"wok-rocks-v3:combined:thin-author-frontiers:reverse-order:sync-wal";
const IS_COVERLESS: bool = cfg!(feature = "rocksdb-coverless");

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Layout {
    Dual,
    Coverless,
    Heads,
}
const CURRENT: Layout = if cfg!(feature = "rocksdb-author-heads") {
    Layout::Heads
} else if IS_COVERLESS {
    Layout::Coverless
} else {
    Layout::Dual
};
fn marker(layout: Layout) -> &'static [u8] {
    match layout {
        Layout::Dual => DUAL,
        Layout::Coverless => COVERLESS,
        Layout::Heads => HEADS,
    }
}
fn names(layout: Layout) -> Vec<&'static str> {
    let mut names = vec!["default", COMBINED];
    if layout == Layout::Dual {
        names.push(COVERING);
    }
    if layout == Layout::Heads {
        names.push("wok_author_frontiers_v1");
    }
    names.extend(
        wok_db::dbi_specs()
            .iter()
            .filter(|s| {
                s.name != wok_db::schema::DBI_EVENT && s.name != wok_db::schema::DBI_EVENT_PAYLOAD
            })
            .map(|s| s.name),
    );
    names
}

fn raw_fixture(path: &Path, names: &[&str], marker: Option<&[u8]>) {
    let mut options = Options::default();
    options.create_if_missing(true);
    options.create_missing_column_families(true);
    let db = DB::open_cf_descriptors(
        &options,
        path,
        names
            .iter()
            .map(|name| ColumnFamilyDescriptor::new(*name, Options::default())),
    )
    .unwrap();
    if let Some(marker) = marker {
        let mut options = rocksdb::WriteOptions::default();
        options.set_sync(true);
        db.put_opt(FORMAT_KEY, marker, &options).unwrap();
    }
}

fn inventory(path: &Path) -> BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(path)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (
                entry.file_name().into_string().unwrap(),
                std::fs::read(entry.path()).unwrap(),
            )
        })
        .collect()
}

#[test]
fn layout_has_exact_cfs_marker_and_author_accessor() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    assert_eq!(env.db_version().unwrap(), wok_event::WOK_DB_VERSION);
    assert_eq!(
        env.inner.db.get(FORMAT_KEY).unwrap().unwrap(),
        marker(CURRENT)
    );
    let mut actual = DB::list_cf(&Options::default(), dir.path()).unwrap();
    actual.sort_unstable();
    let mut expected = names(CURRENT);
    expected.sort_unstable();
    assert_eq!(actual, expected);
    assert_eq!(env.inner.db.cf_handle(COVERING).is_none(), IS_COVERLESS);
    assert_eq!(
        env.covering_pubkey_dbi(),
        if IS_COVERLESS {
            env.dbis().event_pubkey
        } else {
            23
        }
    );
    if IS_COVERLESS {
        let tx = env.begin_ro().unwrap();
        assert!(tx.get(23, b"x").is_err());
        assert!(tx.get_u64(23, 1).is_err());
        assert!(tx.entries(23).is_err());
        assert!(tx.cursor(23).is_err());
        let mut tx = env.begin_rw().unwrap();
        assert!(tx.get(23, b"x").is_err());
        assert!(tx.entries(23).is_err());
        assert!(tx.cursor(23).is_err());
        assert!(tx.put(23, b"x", b"y", 0).is_err());
        assert!(tx.del(23, b"x", None).is_err());
        assert!(tx.clear(23).is_err());
        tx.abort();
    }
    assert!(env.audit_rocksdb_layout().unwrap()["ok"].as_bool().unwrap());
}

#[test]
fn incompatible_layouts_are_refused_before_any_database_file_changes() {
    let dir = tempfile::tempdir().unwrap();
    let mut extra = names(CURRENT);
    extra.push("unrecognized-layout-cf");
    let mut missing = names(CURRENT);
    missing.retain(|name| *name != wok_db::schema::DBI_EVENT_TAG);
    let mut cases = vec![
        ("absent".to_string(), names(CURRENT), None, "layout marker"),
        (
            "extra".to_string(),
            extra,
            Some(marker(CURRENT)),
            "column family set",
        ),
        (
            "missing".to_string(),
            missing,
            Some(marker(CURRENT)),
            "column family set",
        ),
    ];
    for other in [Layout::Dual, Layout::Coverless, Layout::Heads] {
        if other != CURRENT {
            cases.extend([
                (
                    format!("other-{other:?}"),
                    names(other),
                    Some(marker(other)),
                    "column family set",
                ),
                (
                    format!("marker-{other:?}"),
                    names(CURRENT),
                    Some(marker(other)),
                    "layout marker",
                ),
                (
                    format!("mixed-{other:?}"),
                    names(other),
                    Some(marker(CURRENT)),
                    "column family set",
                ),
            ]);
        }
    }
    for (case, cfs, format, expected_error) in cases {
        let path = dir.path().join(&case);
        raw_fixture(&path, &cfs, format);
        let before = inventory(&path);
        for read_only in [false, true] {
            for create_dbis in [false, true] {
                let error = Env::open(
                    &path,
                    EnvOptions {
                        create_dir: false,
                        create_dbis,
                        read_only,
                        ..EnvOptions::for_tests()
                    },
                )
                .unwrap_err();
                assert!(
                    error.to_string().contains(expected_error),
                    "{case}: {error}"
                );
                assert_eq!(
                    inventory(&path),
                    before,
                    "{case}, read_only={read_only}, create_dbis={create_dbis}"
                );
            }
        }
    }
}

fn signed(n: u64) -> EventToWrite {
    let key = Keypair::from_secret_key(SECP256K1, &SecretKey::from_byte_array(&[7; 32]).unwrap());
    let mut event = json!({"pubkey":hex::encode(key.x_only_public_key().0.serialize()),
        "kind":1,"created_at":1700000000+n,"tags":[["t","layout"]],
        "content":format!("event {n}: 🥘\u{7f}")});
    let id = wok_event::event_id_hash(&event).unwrap();
    event["id"] = json!(hex::encode(id));
    event["sig"] = json!(hex::encode(SECP256K1.sign_schnorr(&id, &key).as_ref()));
    let parsed = wok_event::parse_and_verify_event(
        &event,
        &wok_event::EventLimits::default(),
        None,
        true,
        false,
    )
    .unwrap();
    EventToWrite::new(parsed.packed.into_bytes(), parsed.json)
}

fn insert(env: &Env, n: u64) -> EventToWrite {
    let mut events = [signed(n)];
    let mut tx = env.begin_rw().unwrap();
    wok_db::write_events(&mut tx, &mut NoopNegentropy, &mut events, false).unwrap();
    tx.commit().unwrap();
    events.into_iter().next().unwrap()
}

fn primary_fingerprint(id: u64, packed: &[u8], payload: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(id.to_le_bytes());
    hash.update((packed.len() as u64).to_le_bytes());
    hash.update(packed);
    hash.update((payload.len() as u64).to_le_bytes());
    hash.update(payload);
    hex::encode(hash.finalize())
}

#[test]
fn writer_abort_delete_snapshot_reopen_and_kept_bytes_remain_lossless() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let first = insert(&env, 1);
    let old = env.begin_ro().unwrap();
    let packed = old
        .get_u64(env.dbis().event, first.lev_id)
        .unwrap()
        .unwrap();
    let payload = old
        .get_u64(env.dbis().event_payload, first.lev_id)
        .unwrap()
        .unwrap();
    let audit = env.audit_rocksdb_layout().unwrap();
    assert_eq!(
        audit["primary_fingerprint_sha256"],
        primary_fingerprint(first.lev_id, packed, payload)
    );
    assert_eq!(audit["thin_author_records_verified"], 1);
    assert_eq!(audit["covering_records_verified"], u64::from(!IS_COVERLESS));

    let dictionary = b"layout kept dictionary bytes";
    let mut tx = env.begin_rw().unwrap();
    let dictionary_id = wok_db::insert_compression_dictionary(&mut tx, dictionary).unwrap();
    tx.commit().unwrap();
    let kept = env
        .begin_ro()
        .unwrap()
        .get_u64(env.dbis().compression_dictionary, dictionary_id)
        .unwrap()
        .unwrap()
        .to_vec();
    let mut tx = env.begin_rw().unwrap();
    wok_db::delete_events(&mut tx, &mut NoopNegentropy, [first.lev_id]).unwrap();
    let mut aborted = [signed(2)];
    wok_db::write_events(&mut tx, &mut NoopNegentropy, &mut aborted, false).unwrap();
    assert!(tx
        .get_u64(env.dbis().event, first.lev_id)
        .unwrap()
        .is_none());
    tx.abort();
    assert_eq!(
        env.audit_rocksdb_layout().unwrap()["primary_fingerprint_sha256"],
        audit["primary_fingerprint_sha256"]
    );

    let second = insert(&env, 2);
    let mut tx = env.begin_rw().unwrap();
    wok_db::delete_events(&mut tx, &mut NoopNegentropy, [first.lev_id]).unwrap();
    tx.commit().unwrap();
    assert_eq!(packed, first.packed);
    assert_eq!(payload, wok_db::encode_raw_payload(&first.json));
    assert_eq!(
        wok_db::event_json_owned(&old, &mut Decompressor::new(), first.lev_id, 1 << 20).unwrap(),
        first.json
    );
    // Uncached old-snapshot reads also exclude the later insertion.
    assert!(old
        .get_u64(env.dbis().event, second.lev_id)
        .unwrap()
        .is_none());
    assert_eq!(env.audit_rocksdb_layout().unwrap()["events"], 1);
    drop(old);
    drop(env);

    let env = Env::open(
        dir.path(),
        EnvOptions {
            create_dir: false,
            create_dbis: false,
            read_only: true,
            ..EnvOptions::for_tests()
        },
    )
    .unwrap();
    assert!(env.begin_rw().is_err());
    let tx = env.begin_ro().unwrap();
    assert!(tx
        .get_u64(env.dbis().event, first.lev_id)
        .unwrap()
        .is_none());
    assert_eq!(
        tx.get_u64(env.dbis().event, second.lev_id)
            .unwrap()
            .unwrap(),
        second.packed
    );
    let payload = tx
        .get_u64(env.dbis().event_payload, second.lev_id)
        .unwrap()
        .unwrap();
    assert_eq!(payload, wok_db::encode_raw_payload(&second.json));
    assert_eq!(
        tx.get_u64(env.dbis().compression_dictionary, dictionary_id)
            .unwrap()
            .unwrap(),
        kept
    );
    let audit = env.audit_rocksdb_layout().unwrap();
    assert_eq!(
        audit["primary_fingerprint_sha256"],
        primary_fingerprint(second.lev_id, &second.packed, payload)
    );
    assert_eq!(audit["table_counts"].get(COVERING).is_none(), IS_COVERLESS);
}

#[test]
fn missing_and_present_empty_components_are_independent_across_abort_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let db = env.dbis();
    let mut tx = env.begin_rw().unwrap();
    tx.put_u64(db.event, 1, b"", 0).unwrap();
    tx.put_u64(db.event_payload, 2, b"", 0).unwrap();
    tx.put_u64(db.event, 3, b"", 0).unwrap();
    tx.put_u64(db.event_payload, 3, b"", 0).unwrap();
    tx.commit().unwrap();
    let old = env.begin_ro().unwrap();
    let mut tx = env.begin_rw().unwrap();
    tx.clear(db.event).unwrap();
    tx.clear(db.event_payload).unwrap();
    assert_eq!(
        (
            tx.entries(db.event).unwrap(),
            tx.entries(db.event_payload).unwrap()
        ),
        (0, 0)
    );
    tx.abort();
    let mut tx = env.begin_rw().unwrap();
    tx.del_u64(db.event_payload, 3, None).unwrap();
    tx.commit().unwrap();
    assert_eq!(
        old.get_u64(db.event_payload, 3).unwrap(),
        Some(b"".as_slice())
    );
    drop(old);
    drop(env);
    let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
    let tx = env.begin_ro().unwrap();
    for (id, packed, payload) in [
        (1, true, false),
        (2, false, true),
        (3, true, false),
        (4, false, false),
    ] {
        assert_eq!(
            tx.get_u64(db.event, id).unwrap(),
            packed.then_some(b"".as_slice())
        );
        assert_eq!(
            tx.get_u64(db.event_payload, id).unwrap(),
            payload.then_some(b"".as_slice())
        );
    }
    assert_eq!(
        (
            tx.entries(db.event).unwrap(),
            tx.entries(db.event_payload).unwrap()
        ),
        (2, 1)
    );
    // Raw APIs preserve malformed primaries for maintenance; the audit must refuse them.
    assert!(env.audit_rocksdb_layout().is_err());
}

#[test]
fn audit_rejects_thin_payload_and_equal_count_stale_postings() {
    for stale in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        insert(&env, 1);
        let cf = env
            .inner
            .db
            .cf_handle(wok_db::schema::DBI_EVENT_PUBKEY)
            .unwrap();
        let mut it = env.inner.db.raw_iterator_cf(cf);
        it.seek_to_first();
        let key = it.key().unwrap().to_vec();
        drop(it);
        let mut options = rocksdb::WriteOptions::default();
        options.set_sync(true);
        if stale {
            let mut wrong = key.clone();
            *wrong.last_mut().unwrap() ^= 1;
            let mut batch = rocksdb::WriteBatch::default();
            batch.delete_cf(cf, &key);
            batch.put_cf(cf, wrong, b"");
            env.inner.db.write_opt(batch, &options).unwrap();
        } else {
            env.inner
                .db
                .put_cf_opt(cf, key, b"unexpected payload", &options)
                .unwrap();
        }
        assert_eq!(
            env.begin_ro()
                .unwrap()
                .entries(env.dbis().event_pubkey)
                .unwrap(),
            1
        );
        let error = env.audit_rocksdb_layout().unwrap_err().to_string();
        assert!(
            error.contains(if stale {
                "missing thin author posting"
            } else {
                "thin author posting contains payload"
            }),
            "{error}"
        );
    }
}
