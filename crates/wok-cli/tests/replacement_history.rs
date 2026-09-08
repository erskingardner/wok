#[path = "support/replacement.rs"]
mod replacement;
use serde_json::Value;
use std::process::Command;

#[test]
fn doctor_and_migration_report_history_while_preserving_lossless_records() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    let source_config = dir.path().join("strfry.conf");
    let local_config = dir.path().join("wok.toml");
    let output = dir.path().join("migration");
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
    let env = replacement::seed(&source, &events, 3);
    let fingerprint = wok_db::event_fingerprint(&env).unwrap();
    drop(env);
    let source_bytes = std::fs::read(source.join("data.mdb")).unwrap();
    std::fs::write(
        &source_config,
        format!(
            "db = \"{}\"\ndbParams {{ mapsize = 67108864 }}\nrelay {{ port = 7777 }}\n",
            source.display()
        ),
    )
    .unwrap();
    let args = [
        "migrate",
        "strfry",
        "--db",
        source.to_str().unwrap(),
        "--config",
        source_config.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ];
    let preflight = Command::new(env!("CARGO_BIN_EXE_wok"))
        .args(args)
        .args(["--check", "--json"])
        .output()
        .unwrap();
    assert!(
        preflight.status.success(),
        "{}",
        String::from_utf8_lossy(&preflight.stderr)
    );
    let report: Value = serde_json::from_slice(&preflight.stdout).unwrap();
    assert_eq!(report["source_integrity"]["superseded_events"], 6);
    assert!(report["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s.as_str().unwrap().contains("6 superseded events")));
    assert!(!output.exists());
    let migrated = Command::new(env!("CARGO_BIN_EXE_wok"))
        .args(args)
        .output()
        .unwrap();
    assert!(
        migrated.status.success(),
        "{}",
        String::from_utf8_lossy(&migrated.stderr)
    );
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(output.join("migration-manifest.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["superseded_groups"], 3);
    assert_eq!(manifest["superseded_events"], 6);
    let target = wok_db::Env::open(
        output.join("db"),
        wok_db::EnvOptions {
            map_size: 67108864,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(wok_db::event_fingerprint(&target).unwrap(), fingerprint);
    assert_eq!(
        std::fs::read(source.join("data.mdb")).unwrap(),
        source_bytes
    );
}
