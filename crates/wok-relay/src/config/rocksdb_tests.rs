use super::*;

const SMALL: &str = "[database.rocksdb]\nblock_cache_bytes=16777216\nrow_cache_bytes=0\ntotal_memtable_bytes=16777216\nmax_total_wal_bytes=33554432\n";

#[test]
fn rocksdb_defaults_partial_overrides_and_config_provenance() {
    let defaults = Config::parse_toml("").unwrap();
    assert_eq!(defaults.db_rocksdb, wok_db::RocksDbOptions::default());
    assert_eq!(defaults.db_rocksdb.block_cache_bytes, 8usize << 30);
    assert_eq!(defaults.db_rocksdb.row_cache_bytes, 2 << 30);
    assert_eq!(defaults.db_rocksdb.total_memtable_bytes, 2 << 30);
    assert_eq!(defaults.db_rocksdb.max_total_wal_bytes, 1 << 30);
    let partial = Config::parse_toml("[database.rocksdb]\nrow_cache_bytes=0\n").unwrap();
    assert_eq!(partial.db_rocksdb.block_cache_bytes, 8usize << 30);
    assert_eq!(partial.db_rocksdb.row_cache_bytes, 0);
    let small = Config::parse_toml(SMALL).unwrap();
    let decoded = Config::parse_toml(&small.to_toml().unwrap()).unwrap();
    assert_eq!(decoded.db_rocksdb, small.db_rocksdb);
    assert_eq!(small.db_options().rocksdb, small.db_rocksdb);
    let explained = Config::explain_toml(SMALL).unwrap();
    assert!(explained.entries.iter().any(|entry| {
        entry.key == "database.rocksdb.row_cache_bytes"
            && entry.value == "0"
            && matches!(entry.origin, Origin::File { .. })
    }));
    let mut legacy_json = serde_json::to_value(&defaults).unwrap();
    legacy_json.as_object_mut().unwrap().remove("db_rocksdb");
    let decoded: Config = serde_json::from_value(legacy_json).unwrap();
    assert_eq!(decoded.db_rocksdb, defaults.db_rocksdb);
}

#[test]
fn rocksdb_sizing_is_restart_only() {
    let mut running = Config::default();
    let mut requested = Config::parse_toml(SMALL).unwrap();
    requested.relay.info.name = "resource reload".into();
    running.apply_reload(requested).unwrap();
    assert_eq!(running.db_rocksdb, wok_db::RocksDbOptions::default());
    assert_eq!(running.db_options().rocksdb, running.db_rocksdb);
    assert_eq!(running.relay.info.name, "resource reload");
}

#[test]
fn rocksdb_sizing_rejects_disabled_limits_negative_and_unknown_values() {
    for field in [
        "block_cache_bytes",
        "total_memtable_bytes",
        "max_total_wal_bytes",
    ] {
        let text = format!("[database.rocksdb]\n{field}=0\n");
        assert!(Config::parse_toml(&text).unwrap_err().contains(field));
    }
    for text in [
        "[database.rocksdb]\nrow_cache_bytes=-1\n",
        "[database.rocksdb]\nblock_cache_bytes=18446744073709551615\n",
        "[database.rocksdb]\nunknown_cache_bytes=1\n",
    ] {
        assert!(Config::parse_toml(text).is_err());
    }
}
