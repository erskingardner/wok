//! Exercise the packaged CLI's actual signal handler and socket cleanup.
use serde_json::json;
use std::{
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

#[tokio::test]
async fn sigterm_closes_cleanly_and_preserves_acknowledged_event() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("s.sock");
    let cfg = dir.path().join("wok.toml");
    std::fs::write(&cfg,format!("[database]\npath={:?}\nmap_size=67108864\nmin_free_disk_bytes=0\n[relay]\nbind=\"127.0.0.1\"\nport=0\nnofiles=0\n[relay.unix]\nenabled=true\npath={:?}\n",dir.path().join("db"),socket)).unwrap();
    let stderr_path = dir.path().join("relay.stderr");
    let mut child = Guard(
        Command::new(env!("CARGO_BIN_EXE_wok"))
            .args(["--config", cfg.to_str().unwrap(), "relay"])
            .stdout(Stdio::null())
            .stderr(Stdio::from(std::fs::File::create(&stderr_path).unwrap()))
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut stream = loop {
        if let Ok(stream) = wok_unix::connect(&socket).await {
            break stream;
        }
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "relay exited during startup: {}",
            std::fs::read_to_string(&stderr_path).unwrap()
        );
        assert!(Instant::now() < deadline, "startup deadline");
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    let key = secp256k1::Keypair::new(secp256k1::SECP256K1, &mut rand::thread_rng());
    let mut event = json!({"pubkey":hex::encode(key.x_only_public_key().0.serialize()),"kind":1,"created_at":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),"tags":[],"content":"must survive SIGTERM"});
    let id = wok_event::event_id_hash(&event).unwrap();
    event["id"] = json!(hex::encode(id));
    event["sig"] = json!(hex::encode(
        secp256k1::SECP256K1.sign_schnorr(&id, &key).as_ref()
    ));
    wok_unix::write_frame(&mut stream, json!(["EVENT", event]).to_string().as_bytes())
        .await
        .unwrap();
    let reply = tokio::time::timeout(
        Duration::from_secs(5),
        wok_unix::read_frame(&mut stream, 10000),
    )
    .await
    .unwrap()
    .unwrap();
    let reply: serde_json::Value = serde_json::from_slice(&reply).unwrap();
    assert_eq!(reply[0], "OK");
    assert_eq!(reply[1], event["id"]);
    assert_eq!(reply[2], true);
    assert!(Command::new("kill")
        .args(["-TERM", &child.0.id().to_string()])
        .status()
        .unwrap()
        .success());
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "shutdown deadline");
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert!(
        status.success(),
        "SIGTERM bypassed graceful shutdown: {status}"
    );
    assert!(!socket.exists(), "Unix socket was not removed");
    let env = wok_db::Env::open(
        dir.path().join("db"),
        wok_db::EnvOptions {
            read_only: true,
            create_dbis: false,
            ..Default::default()
        },
    )
    .unwrap();
    let txn = env.begin_ro().unwrap();
    let report = wok_db::check_integrity(&txn).unwrap();
    assert!(report.ok(), "{report:?}");
    assert_eq!(report.events, 1);
    assert_eq!(wok_db::state::high_water_ro(&txn).unwrap(), Some(1));
}
