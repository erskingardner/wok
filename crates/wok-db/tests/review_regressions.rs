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

fn stored_event(id: u8, timestamp: u64, kind: u64) -> wok_db::EventToWrite {
    let mut tags = wok_event::PackedEventTagBuilder::default();
    if wok_event::is_replaceable_kind(kind) {
        tags.add('d', b"").unwrap();
    }
    let packed =
        wok_event::PackedEventBuilder::build(&[id; 32], &[9; 32], timestamp, kind, 0, &tags)
            .unwrap();
    wok_db::EventToWrite::new(packed.into_bytes(), serde_json::json!({"id":hex::encode([id;32]),"pubkey":hex::encode([9;32]),"created_at":timestamp,"kind":kind,"tags":[],"content":"state","sig":"00".repeat(64)}).to_string())
}

#[test]
fn sequence_and_author_counts_survive_deletion_abort_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    {
        let env = Env::open(dir.path(), EnvOptions::default()).unwrap();
        env.ensure_initialized().unwrap();
        let mut txn = env.begin_rw().unwrap();
        let mut events = vec![stored_event(1, 1, 1), stored_event(2, 2, 1)];
        wok_db::write_events(&mut txn, &mut wok_db::NoopNegentropy, &mut events, false).unwrap();
        assert_eq!(wok_db::state::author_count(&mut txn, &[9; 32]).unwrap(), 2);
        txn.commit().unwrap();
        let mut txn = env.begin_rw().unwrap();
        wok_db::delete_event_basic(&mut txn, 2).unwrap();
        txn.commit().unwrap();
        let mut txn = env.begin_rw().unwrap();
        let mut aborted = [stored_event(3, 3, 1)];
        wok_db::write_events(&mut txn, &mut wok_db::NoopNegentropy, &mut aborted, false).unwrap();
        assert_eq!(aborted[0].lev_id, 3);
        txn.abort();
    }
    let env = Env::open(dir.path(), EnvOptions::default()).unwrap();
    let mut txn = env.begin_rw().unwrap();
    assert_eq!(wok_db::state::author_count(&mut txn, &[9; 32]).unwrap(), 1);
    let mut events = [stored_event(4, 4, 1)];
    wok_db::write_events(&mut txn, &mut wok_db::NoopNegentropy, &mut events, false).unwrap();
    assert_eq!(events[0].lev_id, 3);
    assert_eq!(wok_db::state::author_count(&mut txn, &[9; 32]).unwrap(), 2);
    txn.commit().unwrap();
}

#[test]
fn quota_uses_net_replacement_and_deletion_effect() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let mut txn = env.begin_rw().unwrap();
    let mut events = [
        stored_event(1, 1, 0),
        stored_event(2, 2, 0),
        stored_event(3, 3, 1),
    ];
    wok_db::write::write_events_with_quota(
        &mut txn,
        &mut wok_db::NoopNegentropy,
        &mut events,
        &wok_db::VanishPolicy::disabled(),
        1,
    )
    .unwrap();
    assert_eq!(events[1].status, wok_db::EventWriteStatus::Written);
    assert_eq!(events[2].status, wok_db::EventWriteStatus::QuotaExceeded);
    assert_eq!(wok_db::state::author_count(&mut txn, &[9; 32]).unwrap(), 1);
    assert_eq!(txn.entries(env.dbis().event).unwrap(), 1);
    txn.commit().unwrap();
}

#[test]
fn v4_upgrade_preserves_records_and_initializes_state_lazily() {
    let dir = tempfile::tempdir().unwrap();
    let original;
    {
        let env = Env::open(dir.path(), EnvOptions::default()).unwrap();
        env.ensure_initialized().unwrap();
        let mut txn = env.begin_rw().unwrap();
        let mut events = [stored_event(1, 1, 1)];
        wok_db::write_events(&mut txn, &mut wok_db::NoopNegentropy, &mut events, false).unwrap();
        original = events[0].packed.clone();
        txn.commit().unwrap();
        let mut txn = env.begin_rw().unwrap();
        txn.clear(env.dbis().state.unwrap()).unwrap();
        let mut meta =
            wok_db::decode_meta(txn.get_u64(env.dbis().meta, 1).unwrap().unwrap()).unwrap();
        meta.db_version = 4;
        txn.put_u64(env.dbis().meta, 1, &wok_db::encode_meta(&meta), 0)
            .unwrap();
        txn.commit().unwrap();
    }
    let env = Env::open(dir.path(), EnvOptions::default()).unwrap();
    assert_eq!(env.db_version().unwrap(), wok_event::WOK_DB_VERSION);
    let mut txn = env.begin_rw().unwrap();
    assert_eq!(txn.get_u64(env.dbis().event, 1).unwrap().unwrap(), original);
    assert_eq!(wok_db::state::author_count(&mut txn, &[9; 32]).unwrap(), 1);
    wok_db::delete_event_basic(&mut txn, 1).unwrap();
    let mut events = [stored_event(2, 2, 1)];
    wok_db::write_events(&mut txn, &mut wok_db::NoopNegentropy, &mut events, false).unwrap();
    assert_eq!(events[0].lev_id, 2);
    txn.commit().unwrap();
}

#[test]
fn reindex_preserves_deleted_tail_and_rebuilds_author_counts() {
    let source_dir = tempfile::tempdir().unwrap();
    let target_dir = tempfile::tempdir().unwrap();
    let source = Env::open(source_dir.path(), EnvOptions::default()).unwrap();
    source.ensure_initialized().unwrap();
    let mut txn = source.begin_rw().unwrap();
    let mut events = [stored_event(1, 1, 1), stored_event(2, 2, 1)];
    wok_db::write_events(&mut txn, &mut wok_db::NoopNegentropy, &mut events, false).unwrap();
    txn.commit().unwrap();
    let mut txn = source.begin_rw().unwrap();
    wok_db::delete_event_basic(&mut txn, 2).unwrap();
    txn.commit().unwrap();
    // Reindex must not copy corrupt derived author counts.
    let mut txn = source.begin_rw().unwrap();
    let mut key = vec![b'a'];
    key.extend_from_slice(&[9; 32]);
    txn.put(source.dbis().state.unwrap(), &key, &999u64.to_le_bytes(), 0)
        .unwrap();
    txn.commit().unwrap();
    let target = Env::open(target_dir.path(), EnvOptions::default()).unwrap();
    let mut txn = target.begin_rw().unwrap();
    wok_db::rebuild_primary_and_event_indices(&source.begin_ro().unwrap(), &mut txn).unwrap();
    txn.commit().unwrap();
    let mut txn = target.begin_rw().unwrap();
    assert_eq!(wok_db::state::author_count(&mut txn, &[9; 32]).unwrap(), 1);
    let mut events = [stored_event(3, 3, 1)];
    wok_db::write_events(&mut txn, &mut wok_db::NoopNegentropy, &mut events, false).unwrap();
    assert_eq!(events[0].lev_id, 3);
    txn.commit().unwrap();
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
