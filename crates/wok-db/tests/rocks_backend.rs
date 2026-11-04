#![cfg(feature = "rocksdb-backend")]
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
fn audit_detects_cover_divergence_even_when_counts_match() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    insert(&env);
    let cf = env.inner.db.cf_handle("wok_pubkey_covering_v1").unwrap();
    let mut it = env.inner.db.raw_iterator_cf(cf);
    it.seek_to_first();
    let (key, value) = it.item().unwrap();
    let key = key.to_vec();
    let mut damaged = value.to_vec();
    drop(it);
    *damaged.last_mut().unwrap() ^= 1;
    let mut opts = rocksdb::WriteOptions::default();
    opts.set_sync(true);
    env.inner.db.put_cf_opt(cf, key, damaged, &opts).unwrap();
    assert!(env
        .audit_rocksdb_layout()
        .unwrap_err()
        .to_string()
        .contains("cover differs"));
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
    assert!(env.compact_to_path(&dir.path().join("copy.mdb")).is_err());
    assert!(!dir.path().join("copy.mdb").exists());
    let snapshots = (0..300)
        .map(|_| env.begin_ro().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(snapshots.len(), 300);
}
