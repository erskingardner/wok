use std::process::Command;

#[test]
fn failed_trials_exit_unsuccessfully_and_preserve_reports() {
    let temp = tempfile::tempdir().unwrap();
    let out = temp.path().join("results");
    let missing = temp.path().join("missing-relay");
    let result = Command::new(env!("CARGO_BIN_EXE_wok-bench"))
        .args(["--scenario", "import", "--events", "1", "--out"])
        .arg(&out)
        .arg("--wok")
        .arg(&missing)
        .arg("--strfry")
        .arg(&missing)
        .output()
        .unwrap();
    let rows: Vec<serde_json::Value> = std::fs::read_to_string(out.join("results.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(rows.len(), 2, "both relay failures should be recorded");
    assert!(rows
        .iter()
        .all(|row| row["ok"] == false && row["errors"] == 1));
    for name in ["manifest.json", "summary.md", "corpus.jsonl"] {
        assert!(out.join(name).metadata().unwrap().len() > 0, "{name}");
    }
    assert!(
        !result.status.success(),
        "failed benchmark exited successfully: {}",
        String::from_utf8_lossy(&result.stdout)
    );
}

#[test]
fn reconciliation_fails_on_a_lost_write_and_reads_the_export_from_stdin() {
    use std::io::Write;
    let temp = tempfile::tempdir().unwrap();
    let id = "ab".repeat(32);
    let log = temp.path().join("outcomes.jsonl");
    std::fs::write(
        &log,
        format!(
            "{{\"seq\":0,\"conn\":0,\"id\":\"{id}\",\"kind\":1,\"due_us\":0,\"sent_us\":10,\"reply_us\":900,\"ok\":true,\"message\":\"\"}}\n"
        ),
    )
    .unwrap();
    let reconcile = |export: &str| {
        let out = temp.path().join("reconciled");
        let mut child = Command::new(env!("CARGO_BIN_EXE_wok-bench"))
            .arg("--reconcile")
            .arg(&log)
            .args(["--relay-export", "-", "--out"])
            .arg(&out)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(export.as_bytes())
            .unwrap();
        let status = child.wait_with_output().unwrap().status;
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(out.join("reconciliation.json")).unwrap())
                .unwrap();
        (status.success(), report)
    };
    let (ok, report) = reconcile("");
    assert!(!ok, "a lost write exited successfully");
    assert_eq!(report["acked_missing"], 1);
    assert_eq!(report["missing_ids"][0], id.as_str());
    let (ok, report) = reconcile(&format!("{{\"id\":\"{id}\",\"kind\":1}}\n"));
    assert!(ok);
    assert_eq!(report["acked_stored"], 1);
}

#[test]
fn remote_clients_need_the_corpus_and_target_facts_need_a_remote_target() {
    let temp = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_wok-bench"))
            .args(["--scenario", "clients", "--out"])
            .arg(temp.path().join("results"))
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success(), "{args:?} exited successfully");
        String::from_utf8_lossy(&output.stderr).into_owned()
    };
    let stderr = run(&["--target-url", "ws://127.0.0.1:1"]);
    assert!(
        stderr.contains("needs the --corpus the relay holds"),
        "{stderr}"
    );
    let stderr = run(&["--target-max-filter-limit", "500"]);
    assert!(stderr.contains("describe a --target-url relay"), "{stderr}");
}
