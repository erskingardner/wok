//! `wok scan` reads the whole database: `relay.max_filter_limit` bounds client
//! REQs, not operator scans.
use secp256k1::{Keypair, SECP256K1};
use serde_json::{json, Value};
use std::{
    io::Write,
    path::Path,
    process::{Command, Output, Stdio},
};

fn sign(key: &Keypair, kind: u64, created_at: u64) -> Value {
    let mut event = json!({
        "pubkey": hex::encode(key.x_only_public_key().0.serialize()),
        "kind": kind,
        "created_at": created_at,
        "tags": [],
        "content": format!("scan {created_at}"),
    });
    let id = wok_event::event_id_hash(&event).unwrap();
    event["id"] = json!(hex::encode(id));
    event["sig"] = json!(hex::encode(SECP256K1.sign_schnorr(&id, key).as_ref()));
    event
}

fn run(config: &Path, args: &[&str], stdin: &[Value]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_wok"))
        .arg("--config")
        .arg(config)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut input = child.stdin.take().unwrap();
        for event in stdin {
            writeln!(input, "{}", wok_event::json::to_tao_string(event)).unwrap();
        }
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn scan(config: &Path, filter: &str) -> Vec<Value> {
    let output = run(config, &["scan", filter], &[]);
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn count(config: &Path, filter: &str) -> String {
    let output = run(config, &["scan", "--count", filter], &[]);
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

#[test]
fn scan_reads_past_max_filter_limit_and_honours_an_explicit_limit() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("wok.toml");
    std::fs::write(
        &config,
        format!(
            "[database]\npath={:?}\nmap_size=67108864\nmin_free_disk_bytes=0\n\
             [relay]\nmax_filter_limit=5\n",
            dir.path().join("db")
        ),
    )
    .unwrap();
    let key = Keypair::new(SECP256K1, &mut rand::thread_rng());
    let notes: Vec<_> = (0..12).map(|i| sign(&key, 1, 1_700_000_000 + i)).collect();
    let mut events = notes.clone();
    events.push(sign(&key, 7, 1_700_000_100));
    run(&config, &["import"], &events);

    assert_eq!(count(&config, r#"{"kinds":[1]}"#), "12");
    assert_eq!(count(&config, "{}"), "13");
    let newest_first: Vec<_> = notes.iter().rev().cloned().collect();
    assert_eq!(scan(&config, r#"{"kinds":[1]}"#), newest_first);
    assert_eq!(scan(&config, "{}").len(), 13);

    assert_eq!(count(&config, r#"{"kinds":[1],"limit":3}"#), "3");
    assert_eq!(
        scan(&config, r#"{"kinds":[1],"limit":3}"#),
        newest_first[..3]
    );
}
