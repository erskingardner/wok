//! Differential proof of the migration boundary for negentropy storage.

use serde_json::json;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use wok_compat::{sign_event, strfry_available, strfry_bin, temp_db, write_event_to_env};
use wok_db::{Env, EnvOptions};
use wok_event::PackedEventView;
use wok_negentropy::Storage;

fn write_conf(dir: &Path) -> std::path::PathBuf {
    let conf = dir.join("strfry.conf");
    std::fs::write(&conf, format!("db = \"{}\"\n", dir.display())).unwrap();
    conf
}

fn strfry_cmd(conf: &Path, args: &[&str]) -> std::process::Output {
    let out = Command::new(strfry_bin())
        .arg("--config")
        .arg(conf)
        .args(args)
        .output()
        .expect("strfry");
    assert!(
        out.status.success(),
        "strfry {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn strfry_import(conf: &Path, events: &[serde_json::Value]) {
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

/// Parse `tree 1` block from `strfry negentropy list` output: (size, fingerprint hex).
fn parse_list(stdout: &str, tree_id: u64) -> (u64, String) {
    let marker = format!("tree {tree_id}\n");
    let start = stdout.find(&marker).expect("tree listed");
    let block = &stdout[start..];
    let size = block
        .lines()
        .find_map(|l| l.trim().strip_prefix("size: "))
        .expect("size line")
        .trim()
        .parse::<u64>()
        .unwrap();
    let fp = block
        .lines()
        .find_map(|l| l.trim().strip_prefix("fingerprint: "))
        .expect("fingerprint line")
        .trim()
        .to_string();
    (size, fp)
}

fn corpus(n: u64) -> Vec<serde_json::Value> {
    (0..n)
        .map(|i| {
            sign_event(json!({
                "created_at": 1_700_000_000u64 + i,
                "kind": 1,
                "tags": [],
                "content": format!("negentropy-diff-{i}"),
            }))
        })
        .collect()
}

/// Rust computes the size/fingerprint of tree 1 by reading the LMDB store.
fn rust_tree_stats(dir: &Path) -> (u64, String) {
    let env = Env::open(
        dir,
        EnvOptions {
            create_dir: false,
            ..EnvOptions::default()
        },
    )
    .unwrap();
    let txn = env.begin_ro().unwrap();
    let mut tree = wok_negentropy::open_ro(&txn, 1).unwrap();
    let size = tree.size().unwrap();
    let fp = hex::encode(tree.fingerprint(0, size as usize).unwrap());
    (size, fp)
}

#[test]
fn strfry_refuses_wok_owned_tree_database() {
    if !strfry_available() {
        eprintln!("skip: strfry binary missing at {}", strfry_bin().display());
        return;
    }
    let (dir, env) = temp_db();
    for ev in corpus(50) {
        write_event_to_env(&env, &ev);
    }
    // Build tree 1 (the default "{}" filter) with wok: collect in a
    // read-only phase, then insert, like `wok negentropy build`.
    let mut recs = Vec::new();
    {
        let txn = env.begin_ro().unwrap();
        wok_query::foreach_by_filter(&txn, &json!({}), u64::MAX, 64, |lev| {
            if let Ok(Some(buf)) = wok_db::get_packed_ro(&txn, lev) {
                let p = PackedEventView::new(&buf).unwrap();
                recs.push((p.created_at(), p.id().to_vec()));
            }
        })
        .unwrap();
    }
    {
        let mut txn = env.begin_rw().unwrap();
        wok_db::bump_negentropy_mod_counter(&mut txn).unwrap();
        {
            let mut tree = wok_negentropy::open_rw(&mut txn, 1).unwrap();
            for (ts, id) in recs {
                tree.insert(ts, &id).unwrap();
            }
            tree.backend.flush().unwrap();
        }
        txn.commit().unwrap();
    }
    drop(env);
    let conf = write_conf(dir.path());
    let (rust_size, rust_fp) = rust_tree_stats(dir.path());
    assert_eq!(rust_size, 50);
    assert!(!rust_fp.is_empty());
    let out = Command::new(strfry_bin())
        .arg("--config")
        .arg(&conf)
        .args(["negentropy", "list"])
        .output()
        .unwrap();
    assert!(
        !out.status.success()
            && String::from_utf8_lossy(&out.stderr).contains("Database version too new: 4"),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn cpp_built_tree_matches_rust_listing() {
    if !strfry_available() {
        eprintln!("skip: strfry binary missing at {}", strfry_bin().display());
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let conf = write_conf(dir.path());
    strfry_cmd(&conf, &["info"]);
    strfry_import(&conf, &corpus(50));
    strfry_cmd(&conf, &["negentropy", "build", "1"]);
    let out = strfry_cmd(&conf, &["negentropy", "list"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let (cpp_size, cpp_fp) = parse_list(&stdout, 1);
    let (rust_size, rust_fp) = rust_tree_stats(dir.path());
    assert_eq!(cpp_size, 50);
    assert_eq!(
        (rust_size, rust_fp.as_str()),
        (cpp_size, cpp_fp.as_str()),
        "wok could not read the C++-built tree identically"
    );
}
