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

/// Differential tests are skipped when no C++ binary is available (e.g. CI).
fn strfry_available() -> bool {
    strfry_bin().is_file()
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
    std::fs::write(&conf, format!("db = \"{}\"\n", db.display())).unwrap();
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
    let env = Env::open(&db, EnvOptions::default()).unwrap();
    assert_eq!(env.db_version().unwrap(), 3);
    let txn = env.begin_ro().unwrap();
    let meta = txn.get_u64(env.dbis().meta, 1).unwrap().unwrap();
    let m = wok_db::decode_meta(meta).unwrap();
    assert_eq!(m.endianness, 1);
    assert_eq!(m.negentropy_modification_counter, 1);
}

#[test]
fn rust_init_readable_by_cpp() {
    require_strfry!();
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("db");
    let env = Env::open(&db, EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    drop(env);

    let conf = tmp.path().join("strfry.conf");
    std::fs::write(&conf, format!("db = \"{}\"\n", db.display())).unwrap();
    let out = Command::new(strfry_bin())
        .args(["--config", conf.to_str().unwrap(), "info"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("DB version: 3"), "{stdout}");
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
fn rust_write_cpp_export() {
    require_strfry!();
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("db");
    let env = Env::open(&db, EnvOptions::default()).unwrap();
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
    drop(env);

    let conf = tmp.path().join("strfry.conf");
    std::fs::write(&conf, format!("db = \"{}\"\n", db.display())).unwrap();
    let out = Command::new(strfry_bin())
        .args(["--config", conf.to_str().unwrap(), "export"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(&id_hex), "{stdout}");
    assert!(stdout.contains("hello wok"), "{stdout}");
}
