//! Safe pointer-provenance check: no freed memory is read by this reproducer.
use wok_db::{Env, EnvOptions};

#[test]
fn review_cursor_key_must_be_owned_by_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let mut txn = env.begin_rw().unwrap();
    txn.put_u64(env.dbis().event, 1, b"value", 0).unwrap();
    txn.commit().unwrap();
    let txn = env.begin_ro().unwrap();
    let mut cursor = txn.cursor(env.dbis().event).unwrap();
    let key = 1u64.to_ne_bytes().to_vec();
    let (returned, _) = cursor
        .get(Some(&key), None, lmdb_sys::MDB_SET)
        .unwrap()
        .unwrap();
    assert_ne!(returned.as_ptr(), key.as_ptr(), "transaction-lifetime slice aliases caller input; dropping key leaves a dangling safe reference");
}

#[test]
fn duplicate_cursor_seek_returns_database_owned_key_and_value() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let mut txn = env.begin_rw().unwrap();
    let key = wok_db::keys::make_key_string_u64(&[8; 32], 42);
    let value = 17u64.to_ne_bytes().to_vec();
    txn.put(env.dbis().event_pubkey, &key, &value, 0).unwrap();
    txn.commit().unwrap();
    let txn = env.begin_ro().unwrap();
    let mut cursor = txn.cursor(env.dbis().event_pubkey).unwrap();
    for op in [lmdb_sys::MDB_GET_BOTH, lmdb_sys::MDB_GET_BOTH_RANGE] {
        let (k, v) = cursor.get(Some(&key), Some(&value), op).unwrap().unwrap();
        assert_eq!(k, key);
        assert_eq!(v, value);
        assert_ne!(k.as_ptr(), key.as_ptr());
        assert_ne!(v.as_ptr(), value.as_ptr());
    }
    assert!(cursor.get(None, None, lmdb_sys::MDB_SET).is_err());
    assert!(cursor.get(None, None, lmdb_sys::MDB_GET_MULTIPLE).is_err());
}
