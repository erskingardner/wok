#[path = "support/replacement.rs"]
mod replacement;
use serde_json::Value;
use std::process::Command;

fn persistent_bytes(
    database: &std::path::Path,
) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
    std::fs::read_dir(database)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            assert!(path.is_file());
            (
                path.file_name().unwrap().into(),
                std::fs::read(&path).unwrap(),
            )
        })
        .collect()
}

#[test]
fn doctor_reports_retained_replacement_history() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    let local_config = dir.path().join("wok.toml");
    let events: Vec<_> = [0, 3, 30443, 1]
        .into_iter()
        .flat_map(replacement::events)
        .collect();
    let env = replacement::seed(&source, &events, 5);
    std::fs::write(
        &local_config,
        format!("[database]\npath={source:?}\nmap_size=67108864\nmin_free_disk_bytes=0\n"),
    )
    .unwrap();
    drop(env);
    let doctor = Command::new(env!("CARGO_BIN_EXE_wok"))
        .args([
            "--config",
            local_config.to_str().unwrap(),
            "doctor",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        doctor.status.success(),
        "{}",
        String::from_utf8_lossy(&doctor.stderr)
    );
    let report: Value = serde_json::from_slice(&doctor.stdout).unwrap();
    assert_eq!(report["integrity"]["superseded_groups"], 3);
    assert_eq!(report["integrity"]["superseded_events"], 6);
    assert!(report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["name"] == "replacement-history" && c["status"] == "warn"));
}

#[test]
fn purge_superseded_removes_retained_history_after_a_dry_run() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("db");
    let config = dir.path().join("wok.toml");
    let events: Vec<_> = [0, 3, 30443, 1]
        .into_iter()
        .flat_map(replacement::events)
        .collect();
    drop(replacement::seed(&db, &events, 5));
    std::fs::write(
        &config,
        format!("[database]\npath={db:?}\nmap_size=67108864\nmin_free_disk_bytes=0\n"),
    )
    .unwrap();
    let wok = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_wok"))
            .args(["--config", config.to_str().unwrap()])
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<Value>(&output.stdout).unwrap()
    };
    // Export is a physical archive; scan would hide superseded versions.
    let stored_kinds = || -> Vec<u64> {
        let output = Command::new(env!("CARGO_BIN_EXE_wok"))
            .args(["--config", config.to_str().unwrap(), "export"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let mut kinds: Vec<_> = String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(|line| {
                serde_json::from_str::<Value>(line).unwrap()["kind"]
                    .as_u64()
                    .unwrap()
            })
            .collect();
        kinds.sort();
        kinds
    };

    let dry_run = wok(&["purge-superseded", "--dry-run", "--json"]);
    assert_eq!(dry_run["dry_run"], true);
    assert_eq!(dry_run["superseded_groups"], 3);
    assert_eq!(dry_run["superseded_events"], 6);
    assert_eq!(stored_kinds().len(), 12);

    let purged = wok(&["purge-superseded", "--json"]);
    assert_eq!(purged["dry_run"], false);
    assert_eq!(purged["superseded_groups"], 3);
    assert_eq!(purged["superseded_events"], 6);
    // One version per address and every regular event survive.
    assert_eq!(stored_kinds(), [0, 1, 1, 1, 3, 30443]);

    let report = wok(&["doctor", "--json"]);
    assert_eq!(report["integrity"]["superseded_groups"], 0);
    assert_eq!(report["integrity"]["superseded_events"], 0);
    assert!(report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["name"] == "replacement-history" && c["status"] == "pass"));
}

#[test]
fn purge_superseded_dry_run_never_writes() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("db");
    let config = dir.path().join("wok.toml");
    let events = replacement::events(3);
    // An older v4 marker would be upgraded by any writable open.
    drop(replacement::seed(&db, &events, 4));
    let dry_run = |db: &std::path::Path| {
        std::fs::write(
            &config,
            format!("[database]\npath={db:?}\nmap_size=67108864\nmin_free_disk_bytes=0\n"),
        )
        .unwrap();
        Command::new(env!("CARGO_BIN_EXE_wok"))
            .args(["--config", config.to_str().unwrap()])
            .args(["purge-superseded", "--dry-run", "--json"])
            .output()
            .unwrap()
    };

    let before = persistent_bytes(&db);
    let output = dry_run(&db);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let outcome: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(outcome["superseded_events"], 2);
    assert!(
        persistent_bytes(&db) == before,
        "dry run changed persistent database files"
    );

    let missing = dir.path().join("missing");
    assert!(!dry_run(&missing).status.success());
    assert!(!missing.exists());
}
