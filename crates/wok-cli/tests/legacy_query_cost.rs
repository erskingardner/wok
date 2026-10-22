//! A file that still sets `relay.abuse.max_query_cost`, as copies of the 0.7
//! `docs/wok.toml` do, starts with the old ceiling ignored and a warning, and
//! serves filters that ceiling would refuse in the units of `max_query_work`.
use serde_json::{json, Value};
use std::{
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Guard(Child);
impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

const SAMPLE_0_7_0: &str = include_str!("../../wok-relay/src/config/testdata/wok-0.7.0.toml");
const WARNING: &str = "relay.abuse.max_query_cost is deprecated and ignored";

/// Writes a relay file for a temporary directory.
type ConfigFile = fn(&Path) -> String;

/// The 0.7.0 sample, with a temporary database and only a Unix listener.
fn sample(dir: &Path) -> String {
    let mut text = SAMPLE_0_7_0.to_string();
    for (old, new) in [
        (
            "path = \"./wok-db/\"".to_string(),
            format!("path = {:?}", dir.join("db")),
        ),
        (
            "map_size = 68719476736".into(),
            "map_size = 67108864".into(),
        ),
        (
            "min_free_disk_bytes = 1073741824".into(),
            "min_free_disk_bytes = 0".into(),
        ),
        ("port = 7777".into(), "port = 0".into()),
        ("nofiles = 524288".into(), "nofiles = 0".into()),
        (
            "[relay.unix]\nenabled = false\npath = \"./wok-db/wok.sock\"".into(),
            format!(
                "[relay.unix]\nenabled = true\npath = {:?}",
                dir.join("s.sock")
            ),
        ),
    ] {
        assert!(text.contains(&old), "{old}");
        text = text.replace(&old, &new);
    }
    assert!(text.contains("max_query_cost = 1000"));
    text
}

/// A file that pins only the old ceiling.
fn pinned(dir: &Path) -> String {
    format!(
        "[database]\npath = {:?}\nmap_size = 67108864\nmin_free_disk_bytes = 0\n\
         [relay]\nbind = \"127.0.0.1\"\nport = 0\nnofiles = 0\n\
         [relay.unix]\nenabled = true\npath = {:?}\n\
         [relay.abuse]\nmax_query_cost = 1000\n",
        dir.join("db"),
        dir.join("s.sock")
    )
}

async fn req(stream: &mut tokio::net::UnixStream, filters: &[Value]) -> Value {
    let mut msg = vec![json!("REQ"), json!("q")];
    msg.extend(filters.iter().cloned());
    wok_unix::write_frame(stream, json!(msg).to_string().as_bytes())
        .await
        .unwrap();
    let reply = tokio::time::timeout(
        Duration::from_secs(5),
        wok_unix::read_frame(stream, 1 << 20),
    )
    .await
    .unwrap()
    .unwrap();
    let reply: Value = serde_json::from_slice(&reply).unwrap();
    wok_unix::write_frame(stream, json!(["CLOSE", "q"]).to_string().as_bytes())
        .await
        .unwrap();
    reply
}

#[tokio::test]
async fn an_old_query_cost_ceiling_is_ignored_with_a_warning() {
    let gid = "ab".repeat(32);
    let shapes = [
        vec![json!({})],
        vec![json!({"kinds": [1]})],
        vec![json!({"kinds": [445], "#h": [gid]})],
        // 1,002 with the sample's 0.7 limits (`max_filter_limit = 500`).
        vec![json!({}), json!({"kinds": [1]})],
    ];
    let files: [(&str, ConfigFile); 2] = [("0.7.0 sample", sample), ("pinned", pinned)];
    for (label, file) in files {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("wok.toml");
        std::fs::write(&cfg, file(dir.path())).unwrap();
        let stderr_path = dir.path().join("relay.stderr");
        let mut child = Guard(
            Command::new(env!("CARGO_BIN_EXE_wok"))
                .args(["--config", cfg.to_str().unwrap(), "relay"])
                .stdout(Stdio::null())
                .stderr(Stdio::from(std::fs::File::create(&stderr_path).unwrap()))
                .spawn()
                .unwrap(),
        );
        let socket = dir.path().join("s.sock");
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut stream = loop {
            if let Ok(stream) = wok_unix::connect(&socket).await {
                break stream;
            }
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "{label}: relay exited during startup: {}",
                std::fs::read_to_string(&stderr_path).unwrap()
            );
            assert!(Instant::now() < deadline, "{label}: startup deadline");
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        for filters in &shapes {
            let reply = req(&mut stream, filters).await;
            assert_eq!(reply[0], "EOSE", "{label}: {filters:?} got {reply}");
        }
        let stderr = std::fs::read_to_string(&stderr_path).unwrap();
        assert!(stderr.contains(WARNING), "{label}: {stderr}");
        assert!(
            stderr.contains("relay.abuse.max_query_work"),
            "{label}: {stderr}"
        );
    }
}
