//! What `wok relay` warns about when it starts with a file, before any
//! reload: read classes wider than the preset's, and inbox kinds outsiders
//! could publish for others to read.
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

const STARTED: &str = "Started websocket server on";
const WIDENED: &str = "relay.auth lets more readers read kinds than preset public does: \
                       1059 (recipient-only -> anyone), 21059 (recipient-only -> anyone)";
const INBOX: &str = "relay.auth.inbox_kinds lists kinds [1059, 21059], which are not \
                     recipient-only";

/// Start the relay with `auth` as its `[relay.auth]` table and return what
/// it logged by the time it listens.
fn startup_log(dir: &Path, auth: &str) -> String {
    let cfg = dir.join("wok.toml");
    std::fs::write(
        &cfg,
        format!(
            "[database]\npath = {:?}\nmap_size = 67108864\nmin_free_disk_bytes = 0\n\
             [relay]\nbind = \"127.0.0.1\"\nport = 0\nnofiles = 0\n[relay.auth]\n{auth}\n",
            dir.join("db"),
        ),
    )
    .unwrap();
    let stderr_path = dir.join("relay.stderr");
    let mut child = Guard(
        Command::new(env!("CARGO_BIN_EXE_wok"))
            .args(["--config", cfg.to_str().unwrap(), "relay"])
            .env_remove("RUST_LOG")
            .stdout(Stdio::null())
            .stderr(Stdio::from(std::fs::File::create(&stderr_path).unwrap()))
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let log = std::fs::read_to_string(&stderr_path).unwrap();
        if log.contains(STARTED) {
            return log;
        }
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "relay exited during startup: {log}"
        );
        assert!(Instant::now() < deadline, "startup deadline: {log}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn a_file_that_widens_read_classes_is_warned_about_at_startup() {
    let dir = tempfile::tempdir().unwrap();
    let log = startup_log(
        dir.path(),
        "recipient_only_kinds = [4]\nwrite_policy = \"members\"",
    );
    assert!(log.contains(WIDENED), "{log}");
    assert!(log.contains(INBOX), "{log}");

    let dir = tempfile::tempdir().unwrap();
    let log = startup_log(dir.path(), "");
    assert!(!log.contains("relay.auth lets more readers"), "{log}");
    assert!(!log.contains("relay.auth.inbox_kinds"), "{log}");
}
