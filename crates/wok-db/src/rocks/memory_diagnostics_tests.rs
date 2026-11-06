//! Disposable native fixtures; forced flushes below are test-only pin probes.
use super::*;

fn field(sample: &serde_json::Value, cf: &str, property: &str) -> u64 {
    sample["column_families"][cf][property].as_u64().unwrap()
}

#[test]
fn observations_preserve_snapshots_and_include_pinned_memtables() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let dbi = env.dbis().moderation.unwrap();
    let name = cf_name(dbi);
    let cf = env.inner.db.cf_handle(name).unwrap();
    let initial = env.inner.memory_sample("test");
    assert!(initial["observed_unix_millis"].is_u64());
    assert_eq!(initial["database"]["rocksdb.num-snapshots"], 0);
    assert_eq!(initial["row_cache"]["available"], true);
    assert_eq!(initial["row_cache"]["capacity_bytes"], 2u64 << 30);

    let before = vec![3; 16 << 10];
    let after = vec![7; 16 << 10];
    let mut write = env.begin_rw().unwrap();
    write.put(dbi, b"diagnostic", &before, 0).unwrap();
    write.commit().unwrap();
    let old = env.begin_ro().unwrap();
    assert_eq!(old.get(dbi, b"diagnostic").unwrap().unwrap(), before);
    let mut pinned = env.inner.db.raw_iterator_cf(cf);
    pinned.seek_to_first();
    assert!(pinned.valid());

    let mut write = env.begin_rw().unwrap();
    write.put(dbi, b"diagnostic", &after, 0).unwrap();
    write.commit().unwrap();
    // Deliberately flush this tiny fixture while the old native iterator pins
    // its memtable. Production sampling never invokes flush or compaction.
    env.inner.db.flush_cf(cf).unwrap();
    let sample = env.inner.memory_sample("test");
    assert_eq!(sample["database"]["rocksdb.num-snapshots"], 1);
    assert!(
        field(&sample, name, "rocksdb.size-all-mem-tables")
            > field(&sample, name, "rocksdb.cur-size-all-mem-tables")
    );
    assert_eq!(old.get(dbi, b"diagnostic").unwrap().unwrap(), before);
    let new = env.begin_ro().unwrap();
    assert_eq!(new.get(dbi, b"diagnostic").unwrap().unwrap(), after);
    assert_eq!(
        env.inner.memory_sample("test")["database"]["rocksdb.num-snapshots"],
        2
    );
    assert!(sample["column_families"]
        .as_object()
        .unwrap()
        .values()
        .all(|value| value.get("rocksdb.block-cache-usage").is_none()));
    assert!(sample["database"]["rocksdb.block-cache-usage"].is_u64());
    drop(new);
    drop(old);
    drop(pinned);
    assert_eq!(
        env.inner.memory_sample("test")["database"]["rocksdb.num-snapshots"],
        0
    );
}

#[test]
fn native_adapter_reports_unknown_row_cache_instead_of_zero() {
    let dir = tempfile::tempdir().unwrap();
    let (options, cfs) = native_options(true, physical_cf_names());
    let db = rocksdb::DB::open_cf_descriptors(&options, dir.path(), cfs).unwrap();
    db.put(FORMAT_KEY, FORMAT).unwrap();
    let env = Env::from_native_db(db, dir.path(), false).unwrap();
    let sample = env.inner.memory_sample("test");
    assert_eq!(sample["row_cache"]["available"], false);
    assert!(sample["row_cache"].get("usage_bytes").is_none());
    assert!(sample["row_cache"].get("capacity_bytes").is_none());
    assert!(sample["database"]["rocksdb.block-cache-usage"].is_u64());
}

#[test]
fn diagnostic_logging_accepts_non_utf8_database_paths() {
    use std::os::unix::ffi::OsStrExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(std::ffi::OsStr::from_bytes(b"db-\xff"));
    let env = Env::open(&path, EnvOptions::for_tests()).unwrap();
    // Initialization samples at transaction boundaries too. Native RocksDB
    // supports this path, so optional JSON diagnostics must not reject it.
    env.ensure_initialized().unwrap();
    assert_eq!(env.db_version().unwrap(), wok_event::WOK_DB_VERSION);
    assert!(env.inner.memory_sample("test")["database_path"].is_null());
}

#[test]
fn concurrent_transaction_boundaries_claim_only_one_sample_per_interval() {
    let diagnostics = Arc::new(MemoryDiagnostics::new(None));
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let threads = (0..8)
        .map(|_| {
            let diagnostics = Arc::clone(&diagnostics);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                diagnostics.claim_sample(0)
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(
        threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .filter(|claimed| *claimed)
            .count(),
        1
    );
    assert!(!diagnostics.claim_sample(14_999));
    assert!(diagnostics.claim_sample(15_000));
    assert!(!diagnostics.claim_sample(15_000));
}
