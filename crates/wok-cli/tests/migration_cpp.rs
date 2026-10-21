//! Actual CLI migration of a database created by the pinned C++ reference.
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    process::{Command, Stdio},
};

#[test]
fn cli_migrates_cpp_database_without_mutating_source_or_event_identity() {
    let reference =
        std::env::var("STRFRY_BIN").unwrap_or_else(|_| "/Users/jeff/code/strfry/strfry".into());
    if !std::path::Path::new(&reference).is_file() {
        assert!(
            std::env::var_os("WOK_REQUIRE_STRFRY").is_none(),
            "required strfry reference missing at {reference}"
        );
        eprintln!("skip: optional strfry reference missing");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("source");
    std::fs::create_dir(&db).unwrap();
    let config = dir.path().join("strfry.conf");
    std::fs::write(&config, format!("db = {:?}\nrelay {{ nofiles = 0 }}\n", db)).unwrap();
    let key = secp256k1::Keypair::new(secp256k1::SECP256K1, &mut rand::thread_rng());
    let pubkey = hex::encode(key.x_only_public_key().0.serialize());
    let sign = |mut e: serde_json::Value| {
        e["pubkey"] = json!(pubkey);
        let id = wok_event::event_id_hash(&e).unwrap();
        e["id"] = json!(hex::encode(id));
        e["sig"] = json!(hex::encode(
            secp256k1::SECP256K1.sign_schnorr(&id, &key).as_ref()
        ));
        e
    };
    let mut events = Vec::new();
    for i in 0..12 {
        events.push(sign(json!({"kind":if i % 3 == 0 { 1 } else { 1059 },"created_at":1_800_000_000+i,"tags":[["t","migration"],["p", if i % 2 == 0 { "01".repeat(32) } else { "02".repeat(32) }]],"content":format!("migration {i}: café 🦀 \\ \" \u{7f}")})));
    }
    // strfry tombstones no replaceable event an `a` tag names, and a kind
    // spelled with leading zeros tombstones that spelling. Wok's integrity
    // accepts the canonical tombstones they lack.
    events.push(sign(
        json!({"kind":10002,"created_at":1_800_000_100,"tags":[],"content":"relays"}),
    ));
    events.push(sign(json!({"kind":5,"created_at":1_800_000_200,"tags":[
        ["a", format!("10002:{pubkey}:")],
        ["a", format!("030000:{pubkey}:x")]
    ],"content":""})));
    let mut cpp = Command::new(&reference)
        .arg("--config")
        .arg(&config)
        .arg("import")
        .arg("--no-verify")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut input = cpp.stdin.take().unwrap();
        for e in &events {
            writeln!(input, "{}", wok_event::json::to_tao_string(e)).unwrap();
        }
    }
    let result = cpp.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let data_before = Sha256::digest(std::fs::read(db.join("data.mdb")).unwrap());
    let config_before = std::fs::read(&config).unwrap();
    let output = dir.path().join("migrated");
    let result = Command::new(env!("CARGO_BIN_EXE_wok"))
        .arg("--config")
        .arg(&config)
        .args(["migrate", "strfry", "--db"])
        .arg(&db)
        .arg("--output")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8_lossy(&result.stdout)
            .contains("1 deletion requests name replaceable events or kinds with leading zeros"),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    assert_eq!(
        Sha256::digest(std::fs::read(db.join("data.mdb")).unwrap()),
        data_before
    );
    assert_eq!(std::fs::read(&config).unwrap(), config_before);
    let source = wok_db::Env::open(
        &db,
        wok_db::EnvOptions {
            read_only: true,
            create_dbis: false,
            ..wok_db::EnvOptions::for_tests()
        },
    )
    .unwrap();
    let target = wok_db::Env::open(
        output.join("db"),
        wok_db::EnvOptions {
            read_only: true,
            create_dbis: false,
            ..wok_db::EnvOptions::for_tests()
        },
    )
    .unwrap();
    assert_eq!(source.db_version().unwrap(), 3);
    assert_eq!(target.db_version().unwrap(), wok_event::WOK_DB_VERSION);
    assert_eq!(
        wok_db::event_fingerprint(&source).unwrap(),
        wok_db::event_fingerprint(&target).unwrap()
    );
    let txn = target.begin_ro().unwrap();
    let report = wok_db::check_integrity(&txn).unwrap();
    assert!(report.ok(), "{report:?}");
    assert_eq!(report.events, events.len() as u64);
    assert_eq!(report.legacy_untombstoned_deletions, 1);
    let mut decompressor = wok_db::Decompressor::new();
    let mut actual = std::collections::BTreeMap::new();
    txn.foreach_full(target.dbis().event, &[], &[], false, |key, _| {
        let id = u64::from_ne_bytes(key.try_into().unwrap());
        let text = wok_db::event_json_owned(&txn, &mut decompressor, id, 65536).unwrap();
        let e = wok_event::json::parse_strict(&text).unwrap();
        actual.insert(e["id"].as_str().unwrap().to_owned(), e);
        true
    })
    .unwrap();
    assert_eq!(
        actual,
        events
            .into_iter()
            .map(|e| (e["id"].as_str().unwrap().to_owned(), e))
            .collect()
    );
}
