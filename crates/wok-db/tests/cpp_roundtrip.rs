use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;
use wok_db::{write_events, Env, EnvOptions, EventToWrite, EventWriteStatus, NoopNegentropy};
use wok_event::{parse_and_verify_event, EventLimits, PackedEventView};

fn strfry_bin() -> PathBuf {
    PathBuf::from(
        std::env::var("STRFRY_BIN")
            .unwrap_or_else(|_| "/Users/jeff/code/strfry/strfry".to_string()),
    )
}

/// Local differential tests may skip without C++; the dedicated CI job requires it.
fn strfry_available() -> bool {
    let available = strfry_bin().is_file();
    assert!(
        available || std::env::var_os("WOK_REQUIRE_STRFRY").is_none(),
        "required strfry reference is missing at {}",
        strfry_bin().display()
    );
    available
}

macro_rules! require_strfry {
    () => {
        if !strfry_available() {
            eprintln!("skip: strfry binary missing at {}", strfry_bin().display());
            return;
        }
    };
}

fn make_cpp_db() -> (TempDir, PathBuf) {
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("db");
    std::fs::create_dir_all(&db).unwrap();
    let conf = tmp.path().join("strfry.conf");
    std::fs::write(
        &conf,
        format!("db = \"{}\"\nrelay {{ nofiles = 0 }}\n", db.display()),
    )
    .unwrap();
    let out = Command::new(strfry_bin())
        .args(["--config", conf.to_str().unwrap(), "info"])
        .output()
        .expect("run strfry info");
    assert!(
        out.status.success(),
        "strfry info failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    (tmp, db)
}

#[test]
fn open_cpp_created_database() {
    require_strfry!();
    let (_tmp, db) = make_cpp_db();
    let output =
        tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
    assert_eq!(wok_db::inspect_strfry_source(&db).unwrap().db_version, 3);
    let report =
        wok_db::migrate_strfry_to_rocksdb(&db, &output.path().join("db"), &Default::default())
            .unwrap();
    assert!(report.verified && report.sealed && report.source_unchanged);
    let env = Env::open(output.path().join("db"), EnvOptions::for_tests()).unwrap();
    assert_eq!(env.db_version().unwrap(), wok_event::WOK_DB_VERSION);
    let txn = env.begin_ro().unwrap();
    let meta = txn.get_u64(env.dbis().meta, 1).unwrap().unwrap();
    let m = wok_db::decode_meta(meta).unwrap();
    assert_eq!(m.endianness, 1);
    assert_eq!(m.negentropy_modification_counter, 1);
}

#[test]
fn runtime_refuses_cpp_source_without_creating_rocks_files() {
    require_strfry!();
    let (_tmp, db) = make_cpp_db();
    let before = std::fs::read(db.join("data.mdb")).unwrap();
    assert!(Env::open(&db, EnvOptions::for_tests()).is_err());
    assert_eq!(std::fs::read(db.join("data.mdb")).unwrap(), before);
    assert!(!db.join("CURRENT").exists());
    assert_eq!(wok_db::inspect_strfry_source(&db).unwrap().db_version, 3);
}

fn sign_kind1(content: &str, created_at: u64) -> (Vec<u8>, String) {
    use secp256k1::{Keypair, SECP256K1};
    use serde_json::json;
    let mut rng = rand::thread_rng();
    let kp = Keypair::new(SECP256K1, &mut rng);
    let (xonly, _) = kp.x_only_public_key();
    let mut ev = json!({
        "created_at": created_at,
        "kind": 1,
        "tags": [],
        "content": content,
        "pubkey": hex::encode(xonly.serialize()),
    });
    let id = wok_event::event_id_hash(&ev).unwrap();
    ev["id"] = json!(hex::encode(id));
    let sig = SECP256K1.sign_schnorr(&id, &kp);
    ev["sig"] = json!(hex::encode(sig.as_ref()));
    let parsed = parse_and_verify_event(&ev, &EventLimits::default(), None, true, false).unwrap();
    (parsed.packed.into_bytes(), parsed.json)
}

#[test]
fn wok_owned_event_remains_readable_by_wok() {
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("db");
    let env = Env::open(&db, EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let (packed, json) = sign_kind1("hello wok", 1_700_000_000);
    let id_hex = hex::encode(PackedEventView::new(&packed).unwrap().id());
    {
        let mut txn = env.begin_rw().unwrap();
        let mut evs = [EventToWrite::new(packed, json)];
        write_events(&mut txn, &mut NoopNegentropy, &mut evs, false).unwrap();
        assert_eq!(evs[0].status, EventWriteStatus::Written);
        txn.commit().unwrap();
    }
    let txn = env.begin_ro().unwrap();
    let found = wok_db::lookup_event_by_id_ro(&txn, &hex::decode(id_hex).unwrap()).unwrap();
    assert!(found.is_some());
}
