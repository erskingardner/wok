use super::*;
use crate::EnvOptions;
use lmdb::fixture::Writer;
use secp256k1::{Keypair, SecretKey, SECP256K1};
use serde_json::json;
use std::collections::BTreeMap;
use wok_event::PackedEventView;

fn signed(n: u64, who: u8, created: u64) -> crate::EventToWrite {
    let key = Keypair::from_secret_key(SECP256K1, &SecretKey::from_byte_array(&[who; 32]).unwrap());
    let mut value = json!({"pubkey":hex::encode(key.x_only_public_key().0.serialize()),
        "kind":1,"created_at":created,"tags":[["t","full-state"]],
        "content":format!("signed offline fixture {n}: 🥘\u{7f}")});
    let id = wok_event::event_id_hash(&value).unwrap();
    value["id"] = json!(hex::encode(id));
    value["sig"] = json!(hex::encode(SECP256K1.sign_schnorr(&id, &key).as_ref()));
    let parsed = wok_event::parse_and_verify_event(
        &value,
        &wok_event::EventLimits::default(),
        None,
        true,
        false,
    )
    .unwrap();
    crate::EventToWrite::new(parsed.packed.into_bytes(), parsed.json)
}

fn fixture_dir() -> tempfile::TempDir {
    // macOS commonly exposes TMPDIR under /var -> /private/var. Exercise the
    // actual canonical-parent API contract without weakening symlink refusal.
    let parent = fs::canonicalize(std::env::temp_dir()).unwrap();
    tempfile::tempdir_in(parent).unwrap()
}

type Rows = Vec<Vec<(Vec<u8>, Vec<u8>)>>;
fn source_rows(root: &Path) -> Rows {
    let env = Env::open(root.join("fixture-rocks"), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let dbis = env.dbis();
    let mut tx = env.begin_rw().unwrap();
    let dict = br#"{"content":"fixture with repeat repeat repeat","tags":[],"kind":1}"#.repeat(8);
    tx.put_u64(14, 7, &crate::encode_compression_dictionary(&dict), 0)
        .unwrap();
    for (id, who, time) in [
        (1u64, 7u8, 0u64),
        (9, 7, 99),
        (u64::MAX - 2, 7, 99),
        (55, 8, 12),
    ] {
        let event = signed(id, who, time);
        let packed = PackedEventView::new(&event.packed).unwrap();
        let payload = if id == 9 {
            let mut compressor = zstd::bulk::Compressor::with_dictionary(3, &dict).unwrap();
            crate::payload::encode_zstd_payload(
                7,
                &compressor.compress(event.json.as_bytes()).unwrap(),
            )
        } else {
            crate::payload::encode_raw_payload(&event.json)
        };
        tx.put_u64(3, id, &event.packed, 0).unwrap();
        tx.put_u64(15, id, &payload, 0).unwrap();
        for entry in crate::write::event_index_entries(dbis, id, packed) {
            tx.put(entry.dbi, &entry.key, &entry.value, 0).unwrap();
        }
    }
    // Authoritative allocation high-water can exceed every stored local ID.
    tx.put(20, b"sequence", &u64::MAX.to_le_bytes(), 0).unwrap();
    tx.put(20, b"visibility", &117u64.to_le_bytes(), 0).unwrap();
    let mut sweep_key = [b'V'; 33];
    sweep_key[1..].copy_from_slice(&[19; 32]);
    let mut sweep = [0u8; 33];
    sweep[..8].copy_from_slice(&891u64.to_le_bytes());
    sweep[8..16].copy_from_slice(&17u64.to_le_bytes());
    sweep[16] = 0x81; // tagged pass, explicitly unverified after unreadable row
    sweep[17..25].copy_from_slice(&111u64.to_le_bytes());
    sweep[25..].copy_from_slice(&(u64::MAX - 2).to_le_bytes());
    tx.put(20, &sweep_key, &sweep, 0).unwrap();
    tx.put(20, b"future-counter-without-reader", b"\0\0\x01", 0)
        .unwrap();
    crate::mark_vanished(&mut tx, &[19; 32], 891).unwrap();
    crate::ban_pubkey(&mut tx, &[7; 32], "fixture ban").unwrap();
    crate::allow_pubkey(&mut tx, &[8; 32], "fixture allow").unwrap();
    crate::ban_event(&mut tx, &[9; 32], "fixture event ban").unwrap();
    crate::allow_event(&mut tx, &[10; 32], "fixture event allow").unwrap();
    crate::block_ip(&mut tx, "192.0.2.1", "fixture IP").unwrap();
    crate::report_event(&mut tx, &[11; 32], "fixture report", &mut 5).unwrap();
    crate::put_role(
        &mut tx,
        &crate::Role {
            id: "editor".into(),
            label: "Editor".into(),
            description: "fixture role".into(),
            color: "#fff".into(),
            order: 7,
        },
    )
    .unwrap();
    crate::assign_role(&mut tx, &[12; 32], "editor").unwrap();
    crate::disallow_kind(&mut tx, 4).unwrap();
    crate::allow_kind(&mut tx, 7).unwrap();
    tx.put(16, b"\0\xffopaque-tree-node", b"\xff\0not-event-JSON", 0)
        .unwrap();
    tx.put_u64(
        2,
        9,
        &crate::encode_negentropy_filter(r#"{"authors":["a"]}"#),
        0,
    )
    .unwrap();
    // Existing progress and indexes are copied, not silently rebuilt. Include
    // duplicate values under the same posting key and present-empty records.
    tx.put(17, b"\0schema", &4u64.to_ne_bytes(), 0).unwrap();
    tx.put(17, b"\0indexed-through", &55u64.to_ne_bytes(), 0)
        .unwrap();
    tx.put(17, b"\x01full", &9u64.to_ne_bytes(), 0).unwrap();
    tx.put(17, b"\x01full", &55u64.to_ne_bytes(), 0).unwrap();
    tx.put(21, b"\0schema", &1u64.to_ne_bytes(), 0).unwrap();
    tx.put(21, b"\0through", &0u64.to_ne_bytes(), 0).unwrap();
    tx.put(22, b"target", &999u64.to_le_bytes(), 0).unwrap();
    tx.put(22, b"cursor", b"\0\xffopaque-progress", 0).unwrap();
    tx.put(22, b"present-empty", b"", 0).unwrap();
    // Fill rarely used logical tables with byte-valid opaque records. The
    // migration preserves them without pretending to rebuild historical state.
    for dbi in [7u32, 8, 11] {
        tx.put(dbi, b"opaque-tombstone", &9u64.to_ne_bytes(), 0)
            .unwrap();
    }
    tx.put_u64(13, 1_000, &9u64.to_ne_bytes(), 0).unwrap();
    tx.commit().unwrap();
    let txn = env.begin_ro().unwrap();
    (1..=crate::dbi_specs().len() as u32)
        .map(|dbi| {
            let mut rows = Vec::new();
            txn.foreach_full(dbi, &[], &[], false, |k, v| {
                rows.push((k.to_vec(), v.to_vec()));
                true
            })
            .unwrap();
            assert!(!rows.is_empty(), "fixture omitted {}", spec(dbi).name);
            rows
        })
        .collect()
}
fn write_source(path: &Path, rows: &Rows, version: u64, missing_optional: bool, unknown: bool) {
    let writer = Writer::new(path, missing_optional);
    for (i, records) in rows.iter().enumerate() {
        if missing_optional && i >= 16 {
            break;
        }
        for (key, value) in records {
            if i == 0 && key == &1u64.to_ne_bytes() {
                let mut meta = crate::decode_meta(value).unwrap();
                meta.db_version = version;
                let mut value = crate::encode_meta(&meta);
                // Uninterpreted trailer/padding survives version normalization.
                value.extend_from_slice(b"\0preserved Meta trailer\xff");
                writer.put(1, key, &value);
            } else {
                writer.put(i as u32 + 1, key, value)
            }
        }
    }
    if unknown {
        writer.unknown()
    }
    writer.commit();
}
fn small_batches() -> LmdbToRocksOptions {
    LmdbToRocksOptions {
        batch_bytes: 512,
        ..Default::default()
    }
}
fn bytes_hash(path: &Path) -> [u8; 32] {
    Sha256::digest(fs::read(path).unwrap()).into()
}
fn readonly(path: &Path) -> Env {
    Env::open(
        path,
        EnvOptions {
            read_only: true,
            create_dir: false,
            create_dbis: false,
            ..Default::default()
        },
    )
    .unwrap()
}

#[test]
fn full_state_v5_is_byte_exact_across_bounded_commits_and_reopen() {
    let root = fixture_dir();
    let rows = source_rows(root.path());
    let source = root.path().join("source");
    write_source(&source, &rows, 5, false, false);
    let before = bytes_hash(&source.join("data.mdb"));
    let target = root.path().join("destination");
    let report = migrate_lmdb_to_rocksdb(&source, &target, &small_batches()).unwrap();
    assert!(report.verified && report.sealed && report.source_unchanged);
    assert_eq!(report.verified_events, 4);
    assert!(!report.meta_version_normalized);
    assert!(report.commits > 22);
    assert_eq!(report.tables.len(), crate::dbi_specs().len());
    assert!(report
        .tables
        .iter()
        .all(|t| t.source_sha256 == t.target_sha256));
    assert_eq!(bytes_hash(&source.join("data.mdb")), before);
    let input = lmdb::Source::open(&source).unwrap();
    let env = readonly(&target);
    for dbi in 1..=crate::dbi_specs().len() as u32 {
        let mut cursor = input.cursor(dbi).unwrap().unwrap();
        let txn = env.begin_ro().unwrap();
        let mut actual = Vec::new();
        txn.foreach_full(dbi, &[], &[], false, |k, v| {
            actual.push((k.to_vec(), v.to_vec()));
            true
        })
        .unwrap();
        for pair in &actual {
            assert_eq!(
                cursor.next().unwrap(),
                Some((pair.0.as_slice(), pair.1.as_slice()))
            )
        }
        assert!(cursor.next().unwrap().is_none());
    }
    let txn = env.begin_ro().unwrap();
    assert_eq!(crate::state::high_water_ro(&txn).unwrap(), Some(u64::MAX));
    assert_eq!(
        crate::state::policy_generation(&txn).unwrap(),
        crate::state::decode(input.get(20, b"visibility").unwrap().unwrap()).unwrap()
    );
    let mut sweep_key = [b'V'; 33];
    sweep_key[1..].copy_from_slice(&[19; 32]);
    assert_eq!(txn.get(20, &sweep_key).unwrap().unwrap()[16], 0x81);
    let fingerprint = crate::event_fingerprint(&env).unwrap();
    assert_eq!(hex(fingerprint.sha256), report.primary_fingerprint_sha256);
    #[cfg(feature = "rocksdb-author-heads")]
    {
        let event = PackedEventView::new(txn.get_u64(3, 9).unwrap().unwrap()).unwrap();
        let author: &[u8; 32] = event.pubkey().try_into().unwrap();
        let head = txn.author_heads([author]).unwrap()[0].unwrap();
        assert_eq!(head.first.local_id, u64::MAX - 2);
        assert_eq!(head.next.unwrap().local_id, 9);
    }
}

#[test]
fn v4_changes_only_the_existing_version_scalar_and_keeps_lazy_tables_empty() {
    let root = fixture_dir();
    let rows = source_rows(root.path());
    let source = root.path().join("v4");
    write_source(&source, &rows, 4, true, false);
    let before = bytes_hash(&source.join("data.mdb"));
    let target = root.path().join("upgraded");
    let report = migrate_lmdb_to_rocksdb(&source, &target, &small_batches()).unwrap();
    assert!(report.meta_version_normalized);
    assert_eq!(report.source.db_version, 4);
    let source = lmdb::Source::open(&source).unwrap();
    let old = source.get(1, &1u64.to_ne_bytes()).unwrap().unwrap();
    let env = readonly(&target);
    let txn = env.begin_ro().unwrap();
    let new = txn.get_u64(1, 1).unwrap().unwrap();
    assert_eq!(normalize_meta(old).unwrap(), new);
    assert_eq!(old.len(), new.len());
    assert_eq!(old.iter().zip(new).filter(|(a, b)| a != b).count(), 1);
    for table in &report.tables[16..] {
        assert!(!table.source_present);
        assert_eq!(table.records, 0);
    }
    assert_eq!(crate::state::high_water_ro(&txn).unwrap(), None);
    assert_eq!(bytes_hash(&source.report.source.join("data.mdb")), before);
}

#[test]
fn wrong_versions_unknown_tables_and_existing_destinations_are_refused() {
    let root = fixture_dir();
    let rows = source_rows(root.path());
    for (version, unknown, label) in [
        (3, false, "strfry"),
        (42, false, "future"),
        (5, true, "unknown"),
    ] {
        let source = root.path().join(label);
        write_source(&source, &rows, version, false, unknown);
        let before = bytes_hash(&source.join("data.mdb"));
        let destination = root.path().join(format!("out-{label}"));
        assert!(migrate_lmdb_to_rocksdb(&source, &destination, &small_batches()).is_err());
        assert!(!destination.exists());
        assert_eq!(before, bytes_hash(&source.join("data.mdb")));
    }
    let source = root.path().join("good");
    write_source(&source, &rows, 5, false, false);
    let destination = root.path().join("exists");
    fs::create_dir(&destination).unwrap();
    assert!(migrate_lmdb_to_rocksdb(&source, &destination, &small_batches()).is_err());
    assert_eq!(fs::read_dir(&destination).unwrap().count(), 0);
}

#[test]
fn native_schema_flag_mismatch_is_refused_before_destination_creation() {
    let root = fixture_dir();
    let source = root.path().join("wrong-flags");
    let writer = Writer::wrong_integer_flags(&source);
    writer.put(
        1,
        &1u64.to_ne_bytes(),
        &crate::encode_meta(&crate::Meta {
            db_version: 5,
            endianness: 1,
            negentropy_modification_counter: 0,
        }),
    );
    writer.commit();
    let before = bytes_hash(&source.join("data.mdb"));
    let destination = root.path().join("destination");
    let error = migrate_lmdb_to_rocksdb(&source, &destination, &small_batches()).unwrap_err();
    assert!(error.to_string().contains("flags mismatch"));
    assert!(!destination.exists());
    assert_eq!(bytes_hash(&source.join("data.mdb")), before);
}

#[test]
fn v5_missing_state_is_corrupt_while_v4_lazy_absence_is_supported() {
    let root = fixture_dir();
    let rows = source_rows(root.path());
    let source = root.path().join("v5-without-state");
    write_source(&source, &rows, 5, true, false);
    let before = bytes_hash(&source.join("data.mdb"));
    let error = inspect_lmdb_source(&source).unwrap_err();
    assert!(error.to_string().contains("no wok_State"));
    let destination = root.path().join("destination");
    assert!(migrate_lmdb_to_rocksdb(&source, &destination, &small_batches()).is_err());
    assert!(!destination.exists());
    assert_eq!(bytes_hash(&source.join("data.mdb")), before);
}

#[test]
fn malformed_known_state_and_regressed_allocation_sequence_are_rejected() {
    let root = fixture_dir();
    let original = source_rows(root.path());
    for (label, key, value) in [
        ("short-sequence", b"sequence".as_slice(), b"short".to_vec()),
        (
            "regressed-sequence",
            b"sequence".as_slice(),
            (u64::MAX - 3).to_le_bytes().to_vec(),
        ),
        ("short-visibility", b"visibility".as_slice(), vec![0]),
        (
            "short-vanish-generation",
            b"vanish-markers".as_slice(),
            vec![0],
        ),
        (
            "short-superseded",
            b"superseded-versions".as_slice(),
            vec![0],
        ),
        (
            "short-legacy-superseded",
            b"superseded-events".as_slice(),
            vec![0],
        ),
    ] {
        let mut rows = original.clone();
        rows[19].retain(|(k, _)| k != key);
        rows[19].push((key.to_vec(), value));
        let source = root.path().join(label);
        write_source(&source, &rows, 5, false, false);
        let before = bytes_hash(&source.join("data.mdb"));
        let destination = root.path().join(format!("out-{label}"));
        assert!(
            migrate_lmdb_to_rocksdb(&source, &destination, &small_batches()).is_err(),
            "{label}"
        );
        assert!(!destination.exists(), "{label}");
        assert_eq!(bytes_hash(&source.join("data.mdb")), before);
    }
    // Scalar keys may legitimately be absent after the atomic v4->v5 upgrade.
    // Preserve that lazy state, rather than inventing or resetting counters.
    let mut rows = original;
    rows[19].retain(|(k, _)| k != b"sequence");
    let source = root.path().join("lazy-sequence");
    write_source(&source, &rows, 5, false, false);
    let destination = root.path().join("lazy-target");
    let result = migrate_lmdb_to_rocksdb(&source, &destination, &small_batches()).unwrap();
    assert_eq!(result.verified_events, 4);
    let env = readonly(&destination);
    assert_eq!(
        crate::state::high_water_ro(&env.begin_ro().unwrap()).unwrap(),
        None
    );
}

#[test]
fn duplicate_scalar_progress_markers_are_refused_without_unbounded_mirroring() {
    let root = fixture_dir();
    let mut rows = source_rows(root.path());
    rows[20].push((b"\0through".to_vec(), 117u64.to_ne_bytes().to_vec()));
    let source = root.path().join("source");
    write_source(&source, &rows, 5, false, false);
    let before = bytes_hash(&source.join("data.mdb"));
    let destination = root.path().join("destination");
    let error = migrate_lmdb_to_rocksdb(&source, &destination, &small_batches()).unwrap_err();
    assert!(error.to_string().contains("multiple values for a scalar"));
    assert!(Env::open(&destination, EnvOptions::for_tests()).is_err());
    assert_eq!(bytes_hash(&source.join("data.mdb")), before);
}

#[test]
fn partial_failures_remain_unopenable_and_cannot_be_resumed() {
    let root = fixture_dir();
    let rows = source_rows(root.path());
    let source = root.path().join("source");
    write_source(&source, &rows, 5, false, false);
    let before = bytes_hash(&source.join("data.mdb"));
    for (i, fault) in [
        Fault::AfterPending,
        Fault::AfterBatch,
        Fault::AfterCopy,
        Fault::BeforeSeal,
        Fault::AfterSeal,
        Fault::AfterSentinelRemoval,
    ]
    .into_iter()
    .enumerate()
    {
        let destination = root.path().join(format!("partial-{i}"));
        assert!(migrate(&source, &destination, &small_batches(), fault).is_err());
        assert!(destination.join("CURRENT").exists());
        for read_only in [false, true] {
            assert!(Env::open(
                &destination,
                EnvOptions {
                    read_only,
                    create_dir: false,
                    ..Default::default()
                }
            )
            .is_err());
        }
        assert!(migrate_lmdb_to_rocksdb(&source, &destination, &small_batches()).is_err());
    }
    assert_eq!(before, bytes_hash(&source.join("data.mdb")));
}

#[test]
fn destination_overlap_traversal_symlinks_and_broken_links_are_refused() {
    let root = fixture_dir();
    let rows = source_rows(root.path());
    let source = root.path().join("source");
    write_source(&source, &rows, 5, false, false);
    let before = bytes_hash(&source.join("data.mdb"));
    let linked = root.path().join("linked-parent");
    std::os::unix::fs::symlink(root.path(), &linked).unwrap();
    let broken = root.path().join("broken");
    std::os::unix::fs::symlink(root.path().join("absent"), &broken).unwrap();
    let nested = source.join("destination");
    for path in [
        &nested,
        &source,
        &broken,
        &linked.join("out"),
        &source.join("../escape"),
    ] {
        assert!(
            migrate_lmdb_to_rocksdb(&source, path, &small_batches()).is_err(),
            "{}",
            path.display()
        );
    }
    assert!(!nested.exists());
    assert!(!root.path().join("out").exists());
    assert!(!root.path().join("escape").exists());
    assert_eq!(bytes_hash(&source.join("data.mdb")), before);
}

#[test]
fn replacing_the_source_path_does_not_switch_the_registered_snapshot() {
    let root = fixture_dir();
    let rows = source_rows(root.path());
    let path = root.path().join("source");
    write_source(&path, &rows, 5, false, false);
    let source = lmdb::Source::open(&path).unwrap();
    let before = source.get(20, b"sequence").unwrap().unwrap();
    // Simulate an external path replacement without touching the mapped file.
    fs::rename(path.join("data.mdb"), path.join("original.mdb")).unwrap();
    fs::copy(path.join("original.mdb"), path.join("data.mdb")).unwrap();
    assert_eq!(before, u64::MAX.to_le_bytes());
    assert!(source.check_unchanged().is_err());
}

#[test]
fn corrupt_or_missing_components_and_orphan_payloads_are_never_sealed() {
    let root = fixture_dir();
    let original = source_rows(root.path());
    for bad in ["missing", "orphan", "body", "packed", "dictionary"] {
        let mut rows = original.clone();
        match bad {
            "missing" => {
                rows[14].remove(0);
            }
            "orphan" => rows[14].push((
                999u64.to_ne_bytes().to_vec(),
                crate::payload::encode_raw_payload("{}"),
            )),
            "body" => rows[14][0].1 = crate::payload::encode_raw_payload("{}"),
            "packed" => rows[2][0].1 = vec![0],
            "dictionary" => rows[13].clear(),
            _ => unreachable!(),
        }
        let source = root.path().join(bad);
        write_source(&source, &rows, 5, false, false);
        let destination = root.path().join(format!("out-{bad}"));
        assert!(
            migrate_lmdb_to_rocksdb(&source, &destination, &small_batches()).is_err(),
            "{bad}"
        );
        assert!(
            Env::open(&destination, EnvOptions::for_tests()).is_err(),
            "{bad}"
        );
    }
}

#[test]
fn explicit_record_bound_and_bad_endianness_fail_without_loss() {
    let root = fixture_dir();
    let mut rows = source_rows(root.path());
    let source = root.path().join("source");
    write_source(&source, &rows, 5, false, false);
    assert!(migrate_lmdb_to_rocksdb(
        &source,
        &root.path().join("bounded"),
        &LmdbToRocksOptions {
            max_record_bytes: 10,
            ..small_batches()
        }
    )
    .is_err());
    assert!(Env::open(root.path().join("bounded"), EnvOptions::for_tests()).is_err());
    let mut meta = crate::decode_meta(&rows[0][0].1).unwrap();
    meta.endianness = 0;
    rows[0][0].1 = crate::encode_meta(&meta);
    // write_source preserves this field while selecting the requested version.
    let source = root.path().join("wrong-endian");
    write_source(&source, &rows, 5, false, false);
    assert!(inspect_lmdb_source(&source).is_err());
}

#[test]
fn registered_snapshot_detects_external_write_without_losing_its_old_bytes() {
    let root = fixture_dir();
    let rows = source_rows(root.path());
    let path = root.path().join("source");
    write_source(&path, &rows, 5, false, false);
    let source = lmdb::Source::open(&path).unwrap();
    let old = source.get(20, b"sequence").unwrap().unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "backend_migration::tests::external_writer_child",
            "--exact",
            "--nocapture",
        ])
        .env("WOK_MIGRATION_TEST_SOURCE", &path)
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(old, u64::MAX.to_le_bytes());
    assert!(source.check_unchanged().is_err());
}

#[test]
fn external_writer_child() {
    let Some(path) = std::env::var_os("WOK_MIGRATION_TEST_SOURCE") else {
        return;
    };
    let writer = Writer::new(Path::new(&path), false);
    writer.put(20, b"sequence", &17u64.to_le_bytes());
    writer.commit();
}

#[test]
fn logical_framing_distinguishes_boundaries_and_meta_unknown_bytes() {
    let mut a = Framed::new("a");
    a.row(b"ab", b"c").unwrap();
    let mut b = Framed::new("a");
    b.row(b"a", b"bc").unwrap();
    assert_ne!(a.digest(), b.digest());
    let meta = crate::Meta {
        db_version: 4,
        endianness: 1,
        negentropy_modification_counter: 123,
    };
    let mut old = crate::encode_meta(&meta);
    old.extend_from_slice(b"opaque-metadata-trailer");
    let new = normalize_meta(&old).unwrap();
    assert_eq!(old.len(), new.len());
    assert!(new.ends_with(b"opaque-metadata-trailer"));
    let map: BTreeMap<_, _> = old
        .iter()
        .zip(&new)
        .enumerate()
        .filter(|(_, (a, b))| a != b)
        .collect();
    assert_eq!(map.len(), 1);
}

#[test]
fn damaged_native_value_is_refused_before_logical_decoding_can_clone_it() {
    let root = fixture_dir();
    let env = Env::open(root.path(), EnvOptions::for_tests()).unwrap();
    let cf = env.inner.db.cf_handle(cf_name(20)).unwrap();
    env.inner
        .db
        .put_cf(cf, encode(20, b"oversized", None), vec![0; 257])
        .unwrap();
    let options = LmdbToRocksOptions {
        max_record_bytes: 64,
        ..Default::default()
    };
    let error = match hash_table(&env, 20, &options) {
        Err(error) => error,
        Ok(_) => panic!("oversized physical value was accepted"),
    };
    assert!(error.to_string().contains("physical record exceeds"));
}
