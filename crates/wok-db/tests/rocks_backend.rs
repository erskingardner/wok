//! Optimized physical-layout regressions in addition to shared storage tests.
use secp256k1::{Keypair, SecretKey, SECP256K1};
use serde_json::json;
use wok_db::{Decompressor, Env, EnvOptions, EventToWrite, NoopNegentropy};
fn signed() -> EventToWrite {
    let key = Keypair::from_secret_key(SECP256K1, &SecretKey::from_byte_array(&[7; 32]).unwrap());
    let mut v = json!({"pubkey":hex::encode(key.x_only_public_key().0.serialize()),"kind":1,"created_at":1700000000u64,"tags":[["t","rocks"]],"content":"cover compression regression"});
    let id = wok_event::event_id_hash(&v).unwrap();
    v["id"] = json!(hex::encode(id));
    v["sig"] = json!(hex::encode(SECP256K1.sign_schnorr(&id, &key).as_ref()));
    let p = wok_event::parse_and_verify_event(
        &v,
        &wok_event::EventLimits::default(),
        None,
        true,
        false,
    )
    .unwrap();
    EventToWrite::new(p.packed.into_bytes(), p.json)
}
fn insert(env: &Env) -> (u64, String, Vec<u8>) {
    let event = signed();
    let author = wok_event::PackedEventView::new(&event.packed)
        .unwrap()
        .pubkey()
        .to_vec();
    let json = event.json.clone();
    let mut events = [event];
    let mut tx = env.begin_rw().unwrap();
    wok_db::write_events(&mut tx, &mut NoopNegentropy, &mut events, false).unwrap();
    tx.commit().unwrap();
    (events[0].lev_id, json, author)
}
fn warm_cover(tx: &wok_db::RoTxn<'_>, author: &[u8]) {
    let key = wok_db::keys::make_key_string_u64(author, u64::MAX);
    let mut seen = 0;
    tx.foreach_full(
        tx.env().covering_pubkey_dbi(),
        &key,
        &u64::MAX.to_ne_bytes(),
        true,
        |k, _| {
            if !k.starts_with(author) {
                return false;
            }
            seen += 1;
            true
        },
    )
    .unwrap();
    assert_eq!(seen, 1);
}
#[test]
fn component_only_recompression_refreshes_cover_and_preserves_old_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let (id, json, author) = insert(&env);
    assert_eq!(env.audit_rocksdb_layout().unwrap()["events"], 1);
    let old = env.begin_ro().unwrap();
    warm_cover(&old, &author);
    let mut tx = env.begin_rw().unwrap();
    let dictionary = b"cover regression dictionary";
    let dictionary_id = wok_db::insert_compression_dictionary(&mut tx, dictionary).unwrap();
    let compressed = zstd::bulk::Compressor::with_dictionary(3, dictionary)
        .unwrap()
        .compress(json.as_bytes())
        .unwrap();
    tx.put_u64(
        env.dbis().event_payload,
        id,
        &wok_db::encode_zstd_payload(dictionary_id as u32, &compressed),
        0,
    )
    .unwrap();
    tx.commit().unwrap();
    let new = env.begin_ro().unwrap();
    warm_cover(&new, &author);
    assert_eq!(
        old.get_u64(env.dbis().event_payload, id).unwrap().unwrap()[0],
        wok_db::PAYLOAD_RAW
    );
    assert_eq!(
        new.get_u64(env.dbis().event_payload, id).unwrap().unwrap()[0],
        wok_db::PAYLOAD_ZSTD
    );
    assert_eq!(
        wok_db::event_json_owned(&new, &mut Decompressor::new(), id, 1 << 20).unwrap(),
        json
    );
    assert!(env.audit_rocksdb_layout().unwrap()["ok"].as_bool().unwrap());
    let mut tx = env.begin_rw().unwrap();
    wok_db::delete_events(&mut tx, &mut NoopNegentropy, [id]).unwrap();
    tx.abort();
    assert_eq!(env.audit_rocksdb_layout().unwrap()["events"], 1);
    let mut tx = env.begin_rw().unwrap();
    wok_db::delete_events(&mut tx, &mut NoopNegentropy, [id]).unwrap();
    tx.commit().unwrap();
    assert_eq!(env.audit_rocksdb_layout().unwrap()["events"], 0);
    assert_eq!(
        wok_db::event_json_owned(&old, &mut Decompressor::new(), id, 1 << 20).unwrap(),
        json
    );
}

#[test]
fn new_directory_protects_storage_and_lmdb_compact_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rocks");
    let env = Env::open(&path, EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert!(!dir.path().join("copy.mdb").exists());
    let snapshots = (0..300)
        .map(|_| env.begin_ro().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(snapshots.len(), 300);
}

#[test]
fn primary_pins_preserve_components_and_snapshot_bytes_across_commits() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let db = env.dbis();
    let payload = (0..256 * 1024).map(|i| i as u8).collect::<Vec<_>>();
    let mut tx = env.begin_rw().unwrap();
    for id in [0, 255, 256, u64::MAX] {
        tx.put_u64(db.event, id, &id.to_be_bytes(), 0).unwrap();
        tx.put_u64(db.event_payload, id, &payload, 0).unwrap();
    }
    tx.put_u64(db.event, 1, b"packed only", 0).unwrap();
    tx.put_u64(db.event_payload, 2, b"payload only", 0).unwrap();
    tx.put_u64(db.event, 3, b"", 0).unwrap();
    tx.put_u64(db.event_payload, 3, b"", 0).unwrap();
    tx.commit().unwrap();
    env.inner
        .db
        .flush_cf(env.inner.db.cf_handle("wok_events_combined_v1").unwrap())
        .unwrap();

    let old = env.begin_ro().unwrap();
    // Move an initialized read transaction before retaining its byte borrows.
    // Later uncached reads must still use this snapshot's native handle.
    assert_eq!(
        old.get_u64(db.event_payload, 255).unwrap().unwrap(),
        payload
    );
    let old = Box::new(old);
    let borrowed = old.get_u64(db.event_payload, 255).unwrap().unwrap();
    let packed = old.get(db.event, &255u64.to_ne_bytes()).unwrap().unwrap();
    assert!(std::ptr::eq(
        borrowed,
        old.get(db.event_payload, &255u64.to_ne_bytes())
            .unwrap()
            .unwrap()
    ));
    let mut tx = env.begin_rw().unwrap();
    tx.del_u64(db.event, 255, None).unwrap();
    tx.put_u64(db.event_payload, 255, b"changed", 0).unwrap();
    tx.del_u64(db.event_payload, 256, None).unwrap();
    tx.put_u64(db.event, u64::MAX, b"changed", 0).unwrap();
    tx.commit().unwrap();

    // These IDs were not cached before the writer: every native pin must read
    // the View's old snapshot, including both sides of the byte-order boundary.
    for id in [0, 256, u64::MAX] {
        assert_eq!(
            old.get_u64(db.event, id).unwrap().unwrap(),
            id.to_be_bytes()
        );
        assert_eq!(old.get_u64(db.event_payload, id).unwrap().unwrap(), payload);
    }
    assert_eq!(borrowed, payload);
    assert_eq!(packed, 255u64.to_be_bytes());
    assert_eq!(old.get_u64(db.event_payload, 1).unwrap(), None);
    assert_eq!(old.get_u64(db.event, 2).unwrap(), None);
    assert_eq!(old.get_u64(db.event, 3).unwrap(), Some(&b""[..]));
    assert_eq!(old.get_u64(db.event_payload, 3).unwrap(), Some(&b""[..]));
    assert_eq!(old.get_u64(db.event, 4).unwrap(), None);
    assert!(old.get(db.event, b"bad ID").is_err());

    let current = env.begin_ro().unwrap();
    assert_eq!(current.get_u64(db.event, 255).unwrap(), None);
    assert_eq!(
        current.get_u64(db.event_payload, 255).unwrap(),
        Some(&b"changed"[..])
    );
    assert_eq!(current.get_u64(db.event_payload, 256).unwrap(), None);
    assert_eq!(
        current.get_u64(db.event, u64::MAX).unwrap(),
        Some(&b"changed"[..])
    );
}

#[test]
fn primary_and_cover_caches_share_bytes_in_either_read_order() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let (id, _, author) = insert(&env);
    let db = env.dbis();

    let primary_first = env.begin_ro().unwrap();
    let packed = primary_first.get_u64(db.event, id).unwrap().unwrap();
    let payload = primary_first
        .get_u64(db.event_payload, id)
        .unwrap()
        .unwrap();
    let expected_packed = packed.to_vec();
    let expected_payload = payload.to_vec();
    warm_cover(&primary_first, &author);
    assert!(std::ptr::eq(
        packed,
        primary_first.get_u64(db.event, id).unwrap().unwrap()
    ));
    assert!(std::ptr::eq(
        payload,
        primary_first
            .get_u64(db.event_payload, id)
            .unwrap()
            .unwrap()
    ));

    let cover_first = env.begin_ro().unwrap();
    warm_cover(&cover_first, &author);
    let covered_packed = cover_first.get_u64(db.event, id).unwrap().unwrap();
    let covered_payload = cover_first.get_u64(db.event_payload, id).unwrap().unwrap();
    warm_cover(&cover_first, &author);
    assert!(std::ptr::eq(
        covered_packed,
        cover_first.get_u64(db.event, id).unwrap().unwrap()
    ));
    assert!(std::ptr::eq(
        covered_payload,
        cover_first.get_u64(db.event_payload, id).unwrap().unwrap()
    ));

    let mut tx = env.begin_rw().unwrap();
    tx.put_u64(db.event_payload, id, b"temporary payload", 0)
        .unwrap();
    assert_eq!(
        tx.get_u64(db.event_payload, id).unwrap(),
        Some(&b"temporary payload"[..])
    );
    tx.abort();
    assert_eq!(packed, expected_packed);
    assert_eq!(covered_packed, expected_packed);
    assert_eq!(payload, expected_payload);
    assert_eq!(covered_payload, expected_payload);
    assert!(env.audit_rocksdb_layout().unwrap()["ok"].as_bool().unwrap());
}

#[test]
fn covered_missing_payload_remains_absent_in_primary_cache() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let (id, _, author) = insert(&env);
    let db = env.dbis();
    let old = env.begin_ro().unwrap();
    let old_payload = old.get_u64(db.event_payload, id).unwrap().unwrap();
    let mut tx = env.begin_rw().unwrap();
    assert!(tx.del_u64(db.event_payload, id, None).unwrap());
    tx.commit().unwrap();

    let cover_first = env.begin_ro().unwrap();
    warm_cover(&cover_first, &author);
    let packed = cover_first.get_u64(db.event, id).unwrap().unwrap();
    assert_eq!(cover_first.get_u64(db.event_payload, id).unwrap(), None);
    let primary_first = env.begin_ro().unwrap();
    assert_eq!(primary_first.get_u64(db.event_payload, id).unwrap(), None);
    warm_cover(&primary_first, &author);
    assert_eq!(primary_first.get_u64(db.event, id).unwrap(), Some(packed));
    assert_eq!(primary_first.get_u64(db.event_payload, id).unwrap(), None);
    warm_cover(&old, &author);
    assert!(std::ptr::eq(
        old_payload,
        old.get_u64(db.event_payload, id).unwrap().unwrap()
    ));
}
