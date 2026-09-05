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
