use serde_json::{json, Value};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use wok_compat::{sign_event, strfry_available, strfry_bin, temp_db, write_event_to_env};
use wok_db::{
    check_integrity, event_json_owned, Decompressor, Env, EnvOptions, EventToWrite, NoopNegentropy,
};
use wok_event::{parse_and_verify_event, EventLimits, PackedEventView};

fn write_conf(dir: &Path) -> std::path::PathBuf {
    let conf = dir.join("strfry.conf");
    std::fs::write(&conf, format!("db = \"{}\"\n", dir.display())).unwrap();
    conf
}

fn strfry_cmd(conf: &Path, args: &[&str]) -> std::process::Output {
    Command::new(strfry_bin())
        .arg("--config")
        .arg(conf)
        .args(args)
        .output()
        .expect("strfry")
}

fn strfry_import(conf: &Path, events: &[Value]) {
    let mut child = Command::new(strfry_bin())
        .arg("--config")
        .arg(conf)
        .args(["import", "--no-verify"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        for ev in events {
            writeln!(stdin, "{ev}").unwrap();
        }
    }
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "strfry import: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn cpp_refuses_wok_owned_database() {
    if !strfry_available() {
        eprintln!("skip: strfry binary missing at {}", strfry_bin().display());
        return;
    }
    let (dir, env) = temp_db();
    let ev = sign_event(json!({
        "created_at": 1_700_000_000u64,
        "kind": 1,
        "tags": [],
        "content": "compat-hello",
    }));
    write_event_to_env(&env, &ev);
    drop(env);
    let conf = write_conf(dir.path());
    let out = strfry_cmd(&conf, &["export"]);
    assert!(
        !out.status.success(),
        "strfry unexpectedly opened Wok v4: status={:?} stderr={} stdout={}",
        out.status,
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("Database version too new: 4"));
}

#[test]
fn rust_open_own_db_and_scan() {
    let (_dir, env) = temp_db();
    let ev = sign_event(json!({
        "created_at": 1_700_000_001u64,
        "kind": 1,
        "tags": [],
        "content": "scan-me",
    }));
    write_event_to_env(&env, &ev);
    let txn = env.begin_ro().unwrap();
    let mut decomp = Decompressor::new();
    let mut found = false;
    wok_query::foreach_by_filter(&txn, &json!({"kinds":[1]}), 500, 3, 16, |lev| {
        let json = event_json_owned(&txn, &mut decomp, lev, 65536).unwrap();
        if json.contains("scan-me") {
            found = true;
        }
    })
    .unwrap();
    assert!(found);
}

#[test]
fn cpp_write_rust_read_query() {
    if !strfry_available() {
        eprintln!("skip: strfry binary missing");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path();
    let conf = write_conf(db);
    let _ = strfry_cmd(&conf, &["info"]);
    let ev = sign_event(json!({
        "created_at": 1_700_000_010u64,
        "kind": 1,
        "tags": [["t", "compat"]],
        "content": "from-cpp",
    }));
    strfry_import(&conf, std::slice::from_ref(&ev));
    let env = Env::open(db, EnvOptions::default()).unwrap();
    assert_eq!(env.db_version().unwrap(), 3);
    let txn = env.begin_ro().unwrap();
    let mut decomp = Decompressor::new();
    let mut ids = Vec::new();
    wok_query::foreach_by_filter(
        &txn,
        &json!({"kinds":[1], "#t":["compat"]}),
        500,
        3,
        16,
        |lev| {
            ids.push(event_json_owned(&txn, &mut decomp, lev, 65536).unwrap());
        },
    )
    .unwrap();
    assert!(ids.iter().any(|j| j.contains("from-cpp")), "{ids:?}");
    let report = check_integrity(&txn).unwrap();
    assert!(report.ok(), "{report:?}");
}

#[test]
fn wok_replace_keeps_only_newest_event() {
    let (_dir, env) = temp_db();
    let mut rng = rand::thread_rng();
    let kp = secp256k1::Keypair::new(secp256k1::SECP256K1, &mut rng);
    let (xonly, _) = kp.x_only_public_key();
    let pk = hex::encode(xonly.serialize());
    let sign = |created: u64, content: &str| {
        let mut ev = json!({
            "created_at": created,
            "kind": 0,
            "tags": [],
            "content": content,
            "pubkey": pk,
        });
        let id = wok_event::event_id_hash(&ev).unwrap();
        ev["id"] = json!(hex::encode(id));
        let sig = secp256k1::SECP256K1.sign_schnorr(&id, &kp);
        ev["sig"] = json!(hex::encode(sig.as_ref()));
        ev
    };
    write_event_to_env(&env, &sign(1_700_000_100, "old-profile"));
    write_event_to_env(&env, &sign(1_700_000_200, "new-profile"));
    let txn = env.begin_ro().unwrap();
    let mut decomp = Decompressor::new();
    let mut found = Vec::new();
    wok_query::foreach_by_filter(&txn, &json!({"kinds":[0]}), 500, 3, 16, |lev| {
        found.push(event_json_owned(&txn, &mut decomp, lev, 65536).unwrap());
    })
    .unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("new-profile"), "{found:?}");
}

#[test]
fn wok_delete_removes_event_from_queries() {
    let (_dir, env) = temp_db();
    let note = sign_event(json!({
        "created_at": 1_700_000_300u64,
        "kind": 1,
        "tags": [],
        "content": "please-delete",
    }));
    write_event_to_env(&env, &note);
    let id = note["id"].as_str().unwrap().to_string();
    {
        let txn = env.begin_ro().unwrap();
        let mut levs = Vec::new();
        wok_query::foreach_by_filter(&txn, &json!({"ids":[id]}), 500, 3, 16, |lev| levs.push(lev))
            .unwrap();
        drop(txn);
        let mut txn = env.begin_rw().unwrap();
        wok_db::delete_events(&mut txn, &mut NoopNegentropy, levs).unwrap();
        txn.commit().unwrap();
    }
    let txn = env.begin_ro().unwrap();
    let mut found = Vec::new();
    wok_query::foreach_by_filter(&txn, &json!({"ids":[id]}), 500, 3, 16, |lev| {
        found.push(lev)
    })
    .unwrap();
    assert!(
        found.is_empty(),
        "deleted event remained queryable: {found:?}"
    );
}

#[test]
fn strfry_v3_database_is_read_only_to_wok() {
    if !strfry_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path();
    let conf = write_conf(db);
    let _ = strfry_cmd(&conf, &["info"]);
    let a = sign_event(json!({
        "created_at": 1_700_000_400u64,
        "kind": 1,
        "tags": [],
        "content": "cpp-a",
    }));
    strfry_import(&conf, &[a]);
    let env = Env::open(db, EnvOptions::default()).unwrap();
    let error = match env.begin_rw() {
        Ok(_) => panic!("Wok unexpectedly opened a write transaction on strfry v3"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("import source and is read-only"));
    let txn = env.begin_ro().unwrap();
    let report = check_integrity(&txn).unwrap();
    assert!(report.ok(), "{report:?}");
}

#[test]
fn rust_scan_order_matches_created_at_desc() {
    let (_dir, env) = temp_db();
    for i in 0..5u64 {
        let ev = sign_event(json!({
            "created_at": 1_700_001_000 + i,
            "kind": 1,
            "tags": [],
            "content": format!("ord-{i}"),
        }));
        write_event_to_env(&env, &ev);
    }
    let txn = env.begin_ro().unwrap();
    let mut decomp = Decompressor::new();
    let mut contents = Vec::new();
    wok_query::foreach_by_filter(&txn, &json!({"kinds":[1], "limit": 5}), 500, 3, 16, |lev| {
        let j = event_json_owned(&txn, &mut decomp, lev, 65536).unwrap();
        contents.push(j);
    })
    .unwrap();
    assert!(contents[0].contains("ord-4"), "{contents:?}");
    assert!(contents[4].contains("ord-0"), "{contents:?}");
}

#[test]
fn packed_roundtrip_survives_wok_storage() {
    let (_dir, env) = temp_db();
    let ev = sign_event(json!({
        "created_at": 1_700_000_500u64,
        "kind": 1,
        "tags": [["e", "11".repeat(32)], ["p", "22".repeat(32)], ["t", "x"]],
        "content": "tags-ok",
    }));
    let parsed = parse_and_verify_event(&ev, &EventLimits::default(), None, true, false).unwrap();
    let id = hex::encode(PackedEventView::new(parsed.packed.as_bytes()).unwrap().id());
    {
        let mut txn = env.begin_rw().unwrap();
        let mut evs = vec![EventToWrite::new(parsed.packed.into_bytes(), parsed.json)];
        wok_db::write_events(&mut txn, &mut NoopNegentropy, &mut evs, false).unwrap();
        txn.commit().unwrap();
    }
    let txn = env.begin_ro().unwrap();
    let (_, packed) = wok_db::lookup_event_by_id_ro(&txn, &hex::decode(id).unwrap())
        .unwrap()
        .unwrap();
    let view = PackedEventView::new(&packed).unwrap();
    assert_eq!(view.id(), &hex::decode(ev["id"].as_str().unwrap()).unwrap());
}
