//! The ordinary operator path must pass resolved native sizing to Env::open.
use std::{fs, process::Command};

#[test]
fn configured_native_targets_reach_cli_open_and_invalid_limits_create_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("db");
    let config = dir.path().join("wok.toml");
    let prefix = format!(
        "[database]\npath={}\n[database.rocksdb]\n",
        serde_json::to_string(database.to_str().unwrap()).unwrap()
    );
    fs::write(
        &config,
        format!("{prefix}block_cache_bytes=16777216\nrow_cache_bytes=0\ntotal_memtable_bytes=16777216\nmax_total_wal_bytes=33554432\n"),
    )
    .unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_wok"))
        .args(["--config"])
        .arg(&config)
        .arg("info")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let options = fs::read_dir(&database)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("OPTIONS-")
        })
        .max()
        .unwrap();
    let options = fs::read_to_string(options).unwrap();
    assert!(options.contains("db_write_buffer_size=16777216"));
    assert!(options.contains("max_total_wal_size=33554432"));
    assert!(options.contains("write_buffer_size=67108864"));
    assert!(options.contains("max_write_buffer_number=4"));

    let rejected = dir.path().join("must-not-exist");
    fs::write(
        &config,
        format!(
            "[database]\npath={}\n[database.rocksdb]\nmax_total_wal_bytes=0\n",
            serde_json::to_string(rejected.to_str().unwrap()).unwrap()
        ),
    )
    .unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_wok"))
        .arg("--config")
        .arg(&config)
        .arg("info")
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("max_total_wal_bytes"));
    assert!(!rejected.exists());
}
