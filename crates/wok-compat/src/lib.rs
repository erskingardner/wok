//! Shared helpers for C++/Rust differential tests.

use secp256k1::{Keypair, SECP256K1};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;
use wok_db::{Env, EnvOptions};
use wok_event::parse_and_verify_event;

pub fn strfry_bin() -> PathBuf {
    PathBuf::from(
        std::env::var("STRFRY_BIN").unwrap_or_else(|_| "/Users/jeff/code/strfry/strfry".into()),
    )
}

pub fn strfry_available() -> bool {
    strfry_bin().is_file()
}

pub fn sign_event(ev: Value) -> Value {
    let mut rng = rand::thread_rng();
    let kp = Keypair::new(SECP256K1, &mut rng);
    sign_event_with_key(ev, &kp)
}

pub fn sign_event_with_key(mut ev: Value, kp: &Keypair) -> Value {
    let (xonly, _) = kp.x_only_public_key();
    ev["pubkey"] = json!(hex::encode(xonly.serialize()));
    let id = wok_event::event_id_hash(&ev).unwrap();
    ev["id"] = json!(hex::encode(id));
    let sig = SECP256K1.sign_schnorr(&id, kp);
    ev["sig"] = json!(hex::encode(sig.as_ref()));
    ev
}

pub fn temp_db() -> (TempDir, Env) {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    (dir, env)
}

pub fn write_event_to_env(env: &Env, ev: &Value) {
    let parsed =
        parse_and_verify_event(ev, &wok_event::EventLimits::default(), None, true, false).unwrap();
    let mut txn = env.begin_rw().unwrap();
    let mut evs = vec![wok_db::EventToWrite::new(
        parsed.packed.into_bytes(),
        parsed.json,
    )];
    wok_db::write_events(&mut txn, &mut wok_db::NoopNegentropy, &mut evs, false).unwrap();
    txn.commit().unwrap();
}

pub fn strfry_export(db: &std::path::Path) -> String {
    let out = Command::new(strfry_bin())
        .args(["--config=/dev/null"])
        .env("STRFRY_CONFIG", "")
        .current_dir(db)
        .arg("export")
        .output()
        .expect("strfry export");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

pub fn nips_commit() -> &'static str {
    "656cecc7c0a815b6a2b218d3b5d6f078b3f4dbab"
}
