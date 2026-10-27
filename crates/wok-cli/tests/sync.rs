//! Exercise actual CLI transfers, summaries and operator imports over real sockets.
use futures_util::{SinkExt, StreamExt};
use secp256k1::{Keypair, SECP256K1};
use serde_json::{json, Value};
use std::{
    io::Write,
    path::Path,
    process::{Command, Output, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio_tungstenite::tungstenite::Message;
use wok_relay::Config;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn key() -> Keypair {
    Keypair::new(SECP256K1, &mut rand::thread_rng())
}
fn sign(mut event: Value, key: &Keypair) -> Value {
    event["pubkey"] = json!(hex::encode(key.x_only_public_key().0.serialize()));
    let id = wok_event::event_id_hash(&event).unwrap();
    event["id"] = json!(hex::encode(id));
    event["sig"] = json!(hex::encode(SECP256K1.sign_schnorr(&id, key).as_ref()));
    event
}
fn event(kind: u64) -> Value {
    sign(
        json!({"kind":kind,"created_at":now(),"tags":[],"content":"sync"}),
        &key(),
    )
}
fn config(dir: &Path, extra: &str) -> std::path::PathBuf {
    let path = dir.join("wok.toml");
    std::fs::write(
        &path,
        format!(
            "[database]\npath={:?}\nmap_size=67108864\nmin_free_disk_bytes=0\n{extra}",
            dir.join("db")
        ),
    )
    .unwrap();
    path
}
fn cli(config: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_wok"))
        .arg("--config")
        .arg(config)
        .args(args)
        .env("RUST_LOG", "info")
        .output()
        .unwrap()
}
fn import(config: &Path, events: &[Value]) {
    let output = import_output(config, events);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn import_output(config: &Path, events: &[Value]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_wok"))
        .arg("--config")
        .arg(config)
        .arg("import")
        .env("RUST_LOG", "info")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut input = child.stdin.take().unwrap();
        for event in events {
            writeln!(input, "{}", wok_event::json::to_tao_string(event)).unwrap();
        }
    }
    child.wait_with_output().unwrap()
}
struct Server {
    handle: wok_relay::RelayHandle,
    task: tokio::task::JoinHandle<()>,
    url: String,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.handle.request_shutdown();
        self.task.abort();
    }
}
async fn serve(config: &Path) -> Server {
    let mut cfg = Config::load(config).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    cfg.relay.auth.service_url = url.clone();
    let env = wok_db::Env::open(
        &cfg.db,
        wok_db::EnvOptions {
            map_size: 67108864,
            ..Default::default()
        },
    )
    .unwrap();
    env.ensure_initialized().unwrap();
    let handle = wok_relay::start(env, cfg).unwrap();
    let h = handle.clone();
    let task = tokio::spawn(async move {
        wok_ws::serve_listener(h, listener).await.unwrap();
    });
    Server { handle, task, url }
}
fn summary(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "{e}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}
fn sync(config: &Path, url: &str, args: &[&str]) -> Output {
    let mut all = vec!["sync", url, "--timeout", "2"];
    all.extend_from_slice(args);
    cli(config, &all)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn import_sync_compare_and_delete_keep_trees_and_primary_events_equal() {
    let source = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    let src = config(source.path(), "[relay.auth]\nrecipient_only_kinds=[]\n");
    let dst = config(target.path(), "");
    let events: Vec<_> = (0..125).map(|_| event(1)).collect();
    import(&src, &events); // No manual negentropy build: this was the missing-index bug.
    let server = serve(&src).await;
    let output = sync(&dst, &server.url, &["--print-missing"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let ids: std::collections::BTreeSet<_> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(
        ids,
        events
            .iter()
            .map(|e| format!("need,{}", e["id"].as_str().unwrap()))
            .collect()
    );
    let check = sync(&dst, &server.url, &["--check", "--json"]);
    assert!(!check.status.success());
    assert_eq!(summary(&check)["need"], 125);
    let output = sync(&dst, &server.url, &["--dir", "down", "--json"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(summary(&output)["written"], 125);
    let output = sync(&dst, &server.url, &["--check", "--json"]);
    assert!(output.status.success());
    assert_eq!(summary(&output)["need"], 0);
    assert_eq!(summary(&output)["have"], 0);
    let deletion = cli(&dst, &["delete", "--filter", "{\"kinds\":[1]}"]);
    assert!(deletion.status.success());
    let output = cli(&dst, &["doctor", "--json"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let output = sync(&dst, &server.url, &["--check", "--json"]);
    assert_eq!(summary(&output)["need"], 125);
}

#[test]
fn doctor_and_sync_reject_incomplete_and_same_size_wrong_trees() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path(), "");
    let ev = event(1);
    import(&cfg, std::slice::from_ref(&ev));
    for wrong_item in [false, true] {
        {
            let env = wok_db::Env::open(
                dir.path().join("db"),
                wok_db::EnvOptions {
                    map_size: 67108864,
                    ..Default::default()
                },
            )
            .unwrap();
            let mut txn = env.begin_rw().unwrap();
            let mut tree = wok_negentropy::open_rw(&mut txn, 1).unwrap();
            tree.erase(
                ev["created_at"].as_u64().unwrap(),
                &hex::decode(ev["id"].as_str().unwrap()).unwrap(),
            )
            .unwrap();
            if wrong_item {
                tree.insert(now(), &[9; 32]).unwrap();
            }
            tree.backend.flush().unwrap();
            drop(tree);
            txn.commit().unwrap();
        }
        let output = cli(&cfg, &["doctor", "--json"]);
        assert!(!output.status.success());
        let report = summary(&output);
        assert!(report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["name"] == "negentropy" && c["status"] == "fail"));
    }
    let output = sync(&cfg, "ws://127.0.0.1:1", &["--check", "--json"]);
    assert!(!output.status.success());
    assert!(summary(&output)["error"]
        .as_str()
        .unwrap()
        .contains("tree 1"));
    // Repair keeps the primary event and reconstructs the exact tree.
    let output = cli(&cfg, &["reindex", "--confirm-relay-stopped"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = cli(&cfg, &["doctor", "--json"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timestamp_rejections_and_negative_upload_acks_fail_the_command() {
    let source = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    let src = config(
        source.path(),
        "[relay.auth]\nrecipient_only_kinds=[]\nwrite_policy=\"members\"\n",
    );
    let dst = config(target.path(), "[events]\nreject_older_than_secs=1\n");
    let old = sign(
        json!({"kind":1,"created_at":now()-100,"tags":[],"content":"old"}),
        &key(),
    );
    import(&src, &[old]);
    let server = serve(&src).await;
    let output = sync(&dst, &server.url, &["--dir", "down", "--json"]);
    assert!(!output.status.success());
    assert_eq!(summary(&output)["rejected"], 1);
    assert_eq!(summary(&output)["written"], 0);
    import(&dst, &[event(1)]);
    let output = sync(&dst, &server.url, &["--dir", "up", "--json"]);
    assert!(!output.status.success());
    assert_eq!(summary(&output)["upload_rejected"], 1);
}

async fn recv(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Value {
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(3), ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        if let Message::Text(text) = msg {
            return serde_json::from_str(&text).unwrap();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_users_gift_wraps_transfer_then_require_the_correct_nip42_identity() {
    let source = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    let src = config(
        source.path(),
        "[relay.auth]\nenabled=false\nrecipient_only_kinds=[]\n",
    );
    let dst = config(
        target.path(),
        "[relay.auth]\nenabled=true\nrecipient_only_kinds=[1059]\n",
    );
    let keys = [key(), key()];
    let events: Vec<_>=keys.iter().map(|k| sign(json!({"kind":1059,"created_at":now()-86400,"tags":[["p",hex::encode(k.x_only_public_key().0.serialize())]],"content":"encrypted gift wrap"}),&key())).collect();
    import(&src, &events);
    let source_server = serve(&src).await;
    let output = sync(
        &dst,
        &source_server.url,
        &["--dir", "down", "--filter", "{\"kinds\":[1059]}", "--json"],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(summary(&output)["written"], 2);
    let exported = cli(&dst, &["export"]);
    let actual: Vec<Value> = String::from_utf8(exported.stdout)
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert_eq!(actual.len(), 2);
    for event in &events {
        assert!(actual.contains(event));
    }
    let server = serve(&dst).await;
    for (i, key) in keys.iter().enumerate() {
        let (mut ws, _) = tokio_tungstenite::connect_async(&server.url).await.unwrap();
        let challenge = recv(&mut ws).await;
        assert_eq!(challenge[0], "AUTH");
        ws.send(Message::Text(
            json!(["REQ", "broad", {}]).to_string().into(),
        ))
        .await
        .unwrap();
        // The gift wraps are hidden until the connection authenticates.
        assert_eq!(
            recv(&mut ws).await,
            json!(["EOSE", "broad", ["auth", "finish"]])
        );
        ws.send(Message::Text(
            json!(["REQ","private",{"kinds":[1059]}]).to_string().into(),
        ))
        .await
        .unwrap();
        assert_eq!(recv(&mut ws).await[0], "CLOSED");
        let auth = sign(
            json!({"kind":22242,"created_at":now(),"tags":[["relay",server.url],["challenge",challenge[1]]],"content":""}),
            key,
        );
        ws.send(Message::Text(json!(["AUTH", auth]).to_string().into()))
            .await
            .unwrap();
        assert_eq!(recv(&mut ws).await[2], true);
        // Broad query after authentication must still return only this recipient's event.
        ws.send(Message::Text(
            json!(["REQ","private",{"kinds":[1059]}]).to_string().into(),
        ))
        .await
        .unwrap();
        let reply = recv(&mut ws).await;
        assert_eq!(reply[0], "EVENT");
        assert_eq!(reply[2], events[i]);
        assert_eq!(recv(&mut ws).await[0], "EOSE");
        ws.close(None).await.unwrap();
    }
    let outsider = tempfile::tempdir().unwrap();
    let outsider_cfg = config(outsider.path(), "");
    let output = sync(
        &outsider_cfg,
        &server.url,
        &["--dir", "down", "--filter", "{\"kinds\":[1059]}", "--json"],
    );
    assert!(!output.status.success());
    assert_eq!(summary(&output)["written"], 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_eose_events_and_wrong_subscription_messages_cannot_report_success() {
    let target = tempfile::tempdir().unwrap();
    let cfg = config(target.path(), "");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let event = event(1);
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let mut vector = wok_negentropy::Vector::new();
        vector
            .insert(
                event["created_at"].as_u64().unwrap(),
                &hex::decode(event["id"].as_str().unwrap()).unwrap(),
            )
            .unwrap();
        vector.seal().unwrap();
        let mut server = wok_negentropy::Negentropy::new(vector, 60_000).unwrap();
        while let Some(Ok(Message::Text(text))) = ws.next().await {
            let message: Value = serde_json::from_str(&text).unwrap();
            match message[0].as_str().unwrap() {
                "NEG-OPEN" | "NEG-MSG" => {
                    let payload = if message[0] == "NEG-OPEN" {
                        &message[3]
                    } else {
                        &message[2]
                    };
                    let response = server
                        .reconcile(&hex::decode(payload.as_str().unwrap()).unwrap())
                        .unwrap();
                    ws.send(Message::Text(
                        json!(["NEG-MSG", "N", hex::encode(response)])
                            .to_string()
                            .into(),
                    ))
                    .await
                    .unwrap();
                }
                "REQ" => {
                    // A correct ID on another subscription must not satisfy our request.
                    for reply in [
                        json!(["EVENT", "unsolicited", event]),
                        json!(["EOSE", "unsolicited"]),
                        json!(["EOSE", "R"]),
                    ] {
                        ws.send(Message::Text(reply.to_string().into()))
                            .await
                            .unwrap();
                    }
                }
                "CLOSE" => break,
                _ => {}
            }
        }
    });
    let output = sync(&cfg, &url, &["--dir", "down", "--json"]);
    assert!(!output.status.success());
    let report = summary(&output);
    assert_eq!(report["unavailable"], 1);
    assert_eq!(report["downloaded"], 0);
    assert_eq!(report["written"], 0);
    task.await.unwrap();
}

#[test]
fn import_failure_is_nonzero_and_logging_does_not_contaminate_exports() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path(), "");
    let good = event(1);
    let mut bad = good.clone();
    bad["content"] = json!("invalid signature");
    let mut child = Command::new(env!("CARGO_BIN_EXE_wok"))
        .arg("--config")
        .arg(&cfg)
        .arg("import")
        .env("RUST_LOG", "info")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        writeln!(stdin, "{good}\n{bad}").unwrap();
    }
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("1 records rejected"));
    let output = cli(&cfg, &["export"]);
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        good
    );
}

type Client =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn subscribe(ws: &mut Client, sub: &str, filter: Value) {
    ws.send(Message::Text(
        json!(["REQ", sub, filter]).to_string().into(),
    ))
    .await
    .unwrap();
    let eose = recv(ws).await;
    // Whatever NIP-67 hints follow.
    assert!(eose[0] == "EOSE" && eose[1] == sub, "{eose}");
}

/// A peer that offers `events` over NIP-77 and answers every REQ with them,
/// like a strfry relay that stored them.
async fn serving_peer(events: Vec<Value>) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let mut vector = wok_negentropy::Vector::new();
        for event in &events {
            vector
                .insert(
                    event["created_at"].as_u64().unwrap(),
                    &hex::decode(event["id"].as_str().unwrap()).unwrap(),
                )
                .unwrap();
        }
        vector.seal().unwrap();
        let mut negentropy = wok_negentropy::Negentropy::new(vector, 60_000).unwrap();
        while let Some(Ok(Message::Text(text))) = ws.next().await {
            let message: Value = serde_json::from_str(&text).unwrap();
            let replies: Vec<Value> = match message[0].as_str().unwrap() {
                "NEG-OPEN" | "NEG-MSG" => {
                    let payload = if message[0] == "NEG-OPEN" {
                        &message[3]
                    } else {
                        &message[2]
                    };
                    let response = negentropy
                        .reconcile(&hex::decode(payload.as_str().unwrap()).unwrap())
                        .unwrap();
                    vec![json!(["NEG-MSG", message[1], hex::encode(response)])]
                }
                "REQ" => events
                    .iter()
                    .map(|event| json!(["EVENT", message[1], event]))
                    .chain([json!(["EOSE", message[1]])])
                    .collect(),
                _ => Vec::new(),
            };
            for reply in replies {
                ws.send(Message::Text(reply.to_string().into()))
                    .await
                    .unwrap();
            }
        }
    });
    (url, task)
}

fn printed_events(output: &Output) -> Vec<Value> {
    String::from_utf8(output.stdout.clone())
        .unwrap()
        .lines()
        .map(|line| wok_event::json::parse_strict(line).unwrap())
        .collect()
}

/// A relay that answers the first REQ with `frames`, then hangs up.
async fn scripted_peer(frames: Vec<Message>) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        while let Some(Ok(message)) = ws.next().await {
            if message
                .to_text()
                .is_ok_and(|text| text.starts_with(r#"["REQ""#))
            {
                break;
            }
        }
        // The client may leave after EOSE, before these finish.
        for frame in frames {
            let _ = ws.send(frame).await;
        }
        let _ = ws.close(None).await;
    });
    (url, task)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn download_prints_only_events_that_verify_unless_told_not_to() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path(), "");
    let good = event(1);
    let mut forged = event(1);
    forged["content"] = json!("forged");
    let forged_id = forged["id"].as_str().unwrap().to_string();
    let text = |value: Value| Message::Text(value.to_string().into());
    let frames = || {
        vec![
            text(json!(["EVENT", "_", good])),
            Message::Ping(b"ping".to_vec().into()),
            Message::Text("not json".into()),
            text(json!(["EVENT", "_", forged])),
            text(json!(["EOSE", "_"])),
        ]
    };

    let (url, task) = scripted_peer(frames()).await;
    let output = cli(&cfg, &["download", &url]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert_eq!(printed_events(&output), vec![good.clone()], "{stderr}");
    assert!(stderr.contains(&forged_id), "{stderr}");
    assert!(stderr.contains("1 printed, 2 rejected"), "{stderr}");
    task.await.unwrap();

    let (url, task) = scripted_peer(frames()).await;
    let output = cli(&cfg, &["download", &url, "--no-verify"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert_eq!(
        printed_events(&output),
        vec![good.clone(), forged.clone()],
        "{stderr}"
    );
    assert!(stderr.contains("2 printed, 1 rejected"), "{stderr}");
    task.await.unwrap();

    let (url, task) = scripted_peer(vec![
        text(json!(["EVENT", "_", good])),
        text(json!(["EVENT", "_", forged])),
        text(json!(["EOSE", "_"])),
    ])
    .await;
    let output = cli(&cfg, &["download", &url, "--no-verify"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert_eq!(
        printed_events(&output),
        vec![good.clone(), forged],
        "{stderr}"
    );
    task.await.unwrap();

    // A dump the relay cuts short is not complete, however valid its events.
    let (url, task) = scripted_peer(vec![text(json!(["EVENT", "_", good]))]).await;
    let output = cli(&cfg, &["download", &url]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert_eq!(printed_events(&output), vec![good], "{stderr}");
    assert!(stderr.contains("closed before EOSE"), "{stderr}");
    task.await.unwrap();
}

/// A relay that answers the first REQ with `frames`, then holds the
/// connection open, pinging, until the client leaves.
async fn holding_peer(frames: Vec<Message>) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        while let Some(Ok(message)) = ws.next().await {
            if message
                .to_text()
                .is_ok_and(|text| text.starts_with(r#"["REQ""#))
            {
                break;
            }
        }
        for frame in frames {
            let _ = ws.send(frame).await;
        }
        let mut ping = tokio::time::interval(Duration::from_millis(200));
        loop {
            let open = tokio::select! {
                message = ws.next() => matches!(message, Some(Ok(_))),
                _ = ping.tick() => ws.send(Message::Ping(b"ping".to_vec().into())).await.is_ok(),
            };
            if !open {
                break;
            }
        }
    });
    (url, task)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn download_ends_when_the_relay_refuses_or_stalls_the_req() {
    // #251: download waited for EOSE or a Close frame, so a relay that
    // refused the REQ but kept the socket open held it forever.
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path(), "");
    let good = event(1);
    let text = |value: Value| Message::Text(value.to_string().into());
    // Long enough that only the refusal itself can end these runs in time.
    let patient = ["--timeout", "120"];
    let download = |url: &str, extra: &[&str]| {
        let started = std::time::Instant::now();
        let output = cli(&cfg, &[&["download", url][..], extra].concat());
        (output, started.elapsed())
    };

    let (url, task) = holding_peer(vec![
        text(json!(["EVENT", "_", good])),
        text(json!(["CLOSED", "_", "auth-required: sign in first"])),
    ])
    .await;
    let (output, elapsed) = download(&url, &patient);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(elapsed < Duration::from_secs(60), "{elapsed:?} {stderr}");
    assert_eq!(printed_events(&output), vec![good.clone()], "{stderr}");
    assert!(stderr.contains("auth-required: sign in first"), "{stderr}");
    assert!(stderr.contains("1 printed, 0 rejected"), "{stderr}");
    task.await.unwrap();

    // strfry and Wok refuse a REQ they cannot parse with a NOTICE.
    let (url, task) = holding_peer(vec![text(json!([
        "NOTICE",
        "ERROR: bad msg: invalid filter"
    ]))])
    .await;
    let (output, elapsed) = download(&url, &patient);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(elapsed < Duration::from_secs(60), "{elapsed:?} {stderr}");
    assert!(stderr.contains("bad msg: invalid filter"), "{stderr}");
    task.await.unwrap();

    // A greeting, a CLOSED for another subscription, and a NOTICE once events
    // flow are logged, not fatal.
    let (url, task) = holding_peer(vec![
        text(json!(["NOTICE", "welcome"])),
        text(json!(["CLOSED", "other", "error: not yours"])),
        text(json!(["EVENT", "_", good])),
        text(json!(["NOTICE", "error: slow down"])),
        text(json!(["EOSE", "_"])),
    ])
    .await;
    let (output, _) = download(&url, &patient);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert_eq!(printed_events(&output), vec![good.clone()], "{stderr}");
    assert!(
        stderr.contains("welcome") && stderr.contains("slow down"),
        "{stderr}"
    );
    task.await.unwrap();

    // A relay that stops short of EOSE times out, though it keeps pinging.
    let (url, task) = holding_peer(vec![text(json!(["EVENT", "_", good]))]).await;
    let (output, elapsed) = download(&url, &["--timeout", "2"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(elapsed >= Duration::from_secs(2), "{elapsed:?} {stderr}");
    assert!(elapsed < Duration::from_secs(60), "{elapsed:?} {stderr}");
    assert_eq!(printed_events(&output), vec![good], "{stderr}");
    assert!(stderr.contains("no event or EOSE for 2s"), "{stderr}");
    assert!(stderr.contains("1 printed, 0 rejected"), "{stderr}");
    task.await.unwrap();
}

struct KillOnDrop(std::process::Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_events_from_import_sync_and_router_are_neither_stored_nor_delivered() {
    // NIP-42: relays MUST exclude kind 22242 from broadcast. These writers
    // skip EVENT ingest, and the relay delivers their commits to live
    // subscribers through its DB-change monitor.
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(
        dir.path(),
        "[events]\nephemeral_persistence=\"ttl\"\n[relay.auth]\nenabled=false\n",
    );
    let server = serve(&cfg).await;
    let (mut by_kind, _) = tokio_tungstenite::connect_async(&server.url).await.unwrap();
    subscribe(&mut by_kind, "auth", json!({"kinds": [22242]})).await;
    subscribe(&mut by_kind, "marker", json!({"kinds": [1]})).await;
    let (mut everything, _) = tokio_tungstenite::connect_async(&server.url).await.unwrap();
    subscribe(&mut everything, "everything", json!({})).await;
    // Each AUTH event is older than its marker and commits with it, so it
    // would be delivered first on the same connection.
    let feed = || {
        let auth = sign(
            json!({
                "kind": 22242,
                "created_at": now() - 2,
                "tags": [["relay", server.url], ["challenge", "replayed"]],
                "content": "",
            }),
            &key(),
        );
        (auth, event(1))
    };

    let (auth, marker) = feed();
    let output = import_output(&cfg, &[auth, marker.clone()]);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("kind 22242 AUTH events are never stored")
    );
    assert_eq!(recv(&mut by_kind).await, json!(["EVENT", "marker", marker]));
    assert_eq!(
        recv(&mut everything).await,
        json!(["EVENT", "everything", marker])
    );

    let (auth, marker) = feed();
    let (url, peer) = serving_peer(vec![auth, marker.clone()]).await;
    let output = sync(&cfg, &url, &["--dir", "down", "--json"]);
    assert!(!output.status.success());
    let report = summary(&output);
    assert_eq!(
        (report["written"].as_u64(), report["rejected"].as_u64()),
        (Some(1), Some(1))
    );
    peer.await.unwrap();
    assert_eq!(recv(&mut by_kind).await, json!(["EVENT", "marker", marker]));
    assert_eq!(
        recv(&mut everything).await,
        json!(["EVENT", "everything", marker])
    );

    let (auth, marker) = feed();
    let (url, peer) = serving_peer(vec![auth, marker.clone()]).await;
    let routes = dir.path().join("router.conf");
    std::fs::write(
        &routes,
        format!("streams {{\n  peer {{\n    dir = \"down\"\n    urls = [\"{url}\"]\n  }}\n}}\n"),
    )
    .unwrap();
    let router = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_wok"))
            .arg("--config")
            .arg(&cfg)
            .arg("router")
            .arg(&routes)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    assert_eq!(recv(&mut by_kind).await, json!(["EVENT", "marker", marker]));
    assert_eq!(
        recv(&mut everything).await,
        json!(["EVENT", "everything", marker])
    );
    drop(router);
    peer.await.unwrap();

    let exported = cli(&cfg, &["export"]);
    assert!(exported.status.success());
    let kinds: Vec<u64> = String::from_utf8(exported.stdout)
        .unwrap()
        .lines()
        .map(|line| {
            serde_json::from_str::<Value>(line).unwrap()["kind"]
                .as_u64()
                .unwrap()
        })
        .collect();
    assert_eq!(kinds, [1, 1, 1]);
}

#[test]
fn operators_can_reindex_scan_and_delete_a_stored_auth_event() {
    // `wok import` refuses kind 22242, but `wok migrate strfry` or another
    // writer can leave one stored. Clients never see it; operator tools must.
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path(), "");
    let note = event(1);
    import(&cfg, std::slice::from_ref(&note));
    let auth = sign(
        json!({"kind":22242,"created_at":now(),"tags":[["challenge","migrated"]],"content":""}),
        &key(),
    );
    {
        let env = wok_db::Env::open(
            dir.path().join("db"),
            wok_db::EnvOptions {
                map_size: 67108864,
                ..Default::default()
            },
        )
        .unwrap();
        let parsed = wok_event::parse_and_verify_event(
            &auth,
            &wok_event::EventLimits::default(),
            None,
            true,
            false,
        )
        .unwrap();
        let mut events = vec![wok_db::EventToWrite::new(
            parsed.packed.into_bytes(),
            parsed.json,
        )];
        let mut txn = env.begin_rw().unwrap();
        wok_db::write_events(&mut txn, &mut wok_db::NoopNegentropy, &mut events, false).unwrap();
        txn.commit().unwrap();
    }
    // A rebuilt tree must still match the physical records doctor counts.
    let output = cli(&cfg, &["reindex", "--confirm-relay-stopped"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = cli(&cfg, &["doctor", "--json"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let output = cli(&cfg, &["scan", "{\"kinds\":[22242]}"]);
    assert!(output.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        auth
    );
    let output = cli(&cfg, &["delete", "--filter", "{\"kinds\":[22242]}"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = cli(&cfg, &["export"]);
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        note
    );
}

#[test]
fn stream_command_is_removed_from_the_cli() {
    let output = Command::new(env!("CARGO_BIN_EXE_wok"))
        .arg("stream")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unrecognized subcommand"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remote_empty_match_all_tree_is_an_error_instead_of_false_convergence() {
    let source = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    let src = config(source.path(), "[relay.auth]\nrecipient_only_kinds=[]\n");
    let dst = config(target.path(), "");
    let event = event(1);
    import(&src, std::slice::from_ref(&event));
    {
        let env = wok_db::Env::open(
            source.path().join("db"),
            wok_db::EnvOptions {
                map_size: 67108864,
                ..Default::default()
            },
        )
        .unwrap();
        let mut txn = env.begin_rw().unwrap();
        let mut tree = wok_negentropy::open_rw(&mut txn, 1).unwrap();
        tree.erase(
            event["created_at"].as_u64().unwrap(),
            &hex::decode(event["id"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        tree.backend.flush().unwrap();
        drop(tree);
        txn.commit().unwrap();
    }
    let server = serve(&src).await;
    let output = sync(&dst, &server.url, &["--check", "--json"]);
    assert!(!output.status.success());
    let report = summary(&output);
    assert_eq!(report["reconciled"], false);
    assert!(report["error"]
        .as_str()
        .unwrap()
        .contains("inconsistent negentropy tree"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cpp_peer_syncs_both_directions_including_all_users_gift_wraps() {
    let reference =
        std::env::var("STRFRY_BIN").unwrap_or_else(|_| "/Users/jeff/code/strfry/strfry".into());
    if !Path::new(&reference).is_file() {
        assert!(
            std::env::var_os("WOK_REQUIRE_STRFRY").is_none(),
            "required strfry reference missing"
        );
        eprintln!("skip: optional strfry reference missing");
        return;
    }
    struct ChildGuard(std::process::Child, std::path::PathBuf);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
            // SIGKILL skips mdb_env_close. Reopening the same lock file
            // unlinks the dead relay's POSIX semaphores before the temp
            // directory (and with it the only way to name them) is removed.
            let _ = wok_db::Env::open(
                &self.1,
                wok_db::EnvOptions {
                    read_only: true,
                    create_dir: false,
                    create_dbis: false,
                    ..wok_db::EnvOptions::for_tests()
                },
            );
        }
    }
    let source = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    let db = source.path().join("db");
    std::fs::create_dir(&db).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let src = source.path().join("strfry.conf");
    std::fs::write(&src,format!("db={db:?}\ndbParams {{ mapsize=67108864 }}\nrelay {{ bind=\"127.0.0.1\" port={port} nofiles=0 auth {{ enabled=false restrictedReadKinds=\"\" }} }}\n")).unwrap();
    let gift = |recipient: &str| {
        sign(
            json!({"kind":1059,"created_at":now()-86400,"tags":[["p",recipient]],"content":"encrypted"}),
            &key(),
        )
    };
    let from_cpp = [event(445), gift(&"01".repeat(32))];
    let from_wok = [event(445), gift(&"02".repeat(32))];
    let mut child = Command::new(&reference)
        .arg("--config")
        .arg(&src)
        .arg("import")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        for event in &from_cpp {
            writeln!(stdin, "{}", wok_event::json::to_tao_string(event)).unwrap();
        }
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new(&reference)
        .arg("--config")
        .arg(&src)
        .args(["negentropy", "build", "1"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let log = source.path().join("relay.log");
    let mut process = ChildGuard(
        Command::new(&reference)
            .arg("--config")
            .arg(&src)
            .arg("relay")
            .stdout(Stdio::null())
            .stderr(Stdio::from(std::fs::File::create(&log).unwrap()))
            .spawn()
            .unwrap(),
        db.clone(),
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        assert!(
            process.0.try_wait().unwrap().is_none(),
            "strfry startup failed: {}",
            std::fs::read_to_string(&log).unwrap()
        );
        assert!(
            std::time::Instant::now() < deadline,
            "strfry startup timeout"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let dst = config(target.path(), "");
    import(&dst, &from_wok);
    let url = format!("ws://127.0.0.1:{port}");
    let output = sync(
        &dst,
        &url,
        &[
            "--dir",
            "both",
            "--filter",
            "{\"kinds\":[445,1059]}",
            "--json",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = summary(&output);
    assert_eq!(report["written"], 2);
    assert_eq!(report["uploaded"], 2);
    let output = sync(
        &dst,
        &url,
        &["--check", "--filter", "{\"kinds\":[445,1059]}", "--json"],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = cli(&dst, &["export"]);
    let actual: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert_eq!(actual.len(), 4);
    for event in from_cpp.iter().chain(&from_wok) {
        assert!(actual.contains(event));
    }
}

#[path = "support/replacement.rs"]
mod replacement;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_tree_and_vector_views_offer_only_current_replaceable_versions() {
    for kind in [3, 30443] {
        let source = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        let src = config(
            source.path(),
            "[relay.auth]\nenabled=false\nrecipient_only_kinds=[]\n",
        );
        let dst = config(
            target.path(),
            "[relay.auth]\nenabled=false\nrecipient_only_kinds=[]\n",
        );
        let events = replacement::events(kind);
        drop(replacement::seed(&source.path().join("db"), &events, 5));
        import(&dst, &[events[2].clone()]);
        let server = serve(&dst).await;
        for filter in ["{}".to_string(), format!("{{\"kinds\":[{kind}]}}")] {
            let output = sync(
                &src,
                &server.url,
                &["--check", "--filter", &filter, "--json"],
            );
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
            assert_eq!(summary(&output)["have"], 0);
            assert_eq!(summary(&output)["need"], 0);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn superseded_transfers_are_reported_without_failing_sync() {
    for kind in [3, 30443] {
        for direction in ["up", "down"] {
            let local = tempfile::tempdir().unwrap();
            let remote = tempfile::tempdir().unwrap();
            let lc = config(
                local.path(),
                "[relay.auth]\nenabled=false\nrecipient_only_kinds=[]\n",
            );
            let rc = config(
                remote.path(),
                "[relay.auth]\nenabled=false\nrecipient_only_kinds=[]\n",
            );
            let events = replacement::events(kind);
            let (le, re) = if direction == "up" {
                (&events[0], &events[2])
            } else {
                (&events[2], &events[0])
            };
            import(&lc, std::slice::from_ref(le));
            import(&rc, std::slice::from_ref(re));
            let server = serve(&rc).await;
            let output = sync(&lc, &server.url, &["--dir", direction, "--json"]);
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
            let report = summary(&output);
            assert_eq!(report["rejected"], 0);
            assert_eq!(report["upload_rejected"], 0);
            assert_eq!(
                report[if direction == "up" {
                    "upload_superseded"
                } else {
                    "superseded"
                }],
                1
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_ephemeral_events_are_reported_without_failing_sync() {
    // A ttl-mode relay keeps an ephemeral record, which packs the ephemeral
    // marker, until its purge, even after its NIP-40 expiration. Relays drop
    // expired events, so neither direction transfers it, and that is not a
    // failure.
    let ttl = "[events]\nephemeral_persistence=\"ttl\"\n[relay.auth]\nenabled=false\nrecipient_only_kinds=[]\n";
    let expired = sign(
        json!({
            "kind": 20001,
            "created_at": now() - 5,
            "tags": [["expiration", (now() - 1).to_string()]],
            "content": "expired",
        }),
        &key(),
    );
    for direction in ["up", "down"] {
        let local = tempfile::tempdir().unwrap();
        let remote = tempfile::tempdir().unwrap();
        let lc = config(local.path(), ttl);
        let rc = config(remote.path(), ttl);
        let holder = if direction == "up" { &lc } else { &rc };
        import(holder, std::slice::from_ref(&expired));
        let server = serve(&rc).await;
        let output = sync(&lc, &server.url, &["--dir", direction, "--json"]);
        let report = summary(&output);
        assert!(output.status.success(), "{direction}: {report}");
        assert_eq!(report["rejected"], 0, "{direction}: {report}");
        assert_eq!(report["upload_rejected"], 0, "{direction}: {report}");
        let counter = if direction == "up" {
            "upload_expired"
        } else {
            "expired"
        };
        assert_eq!(report[counter], 1, "{direction}: {report}");
    }
}

#[test]
fn filtered_sync_view_respects_the_configured_event_budget() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path(), "[relay]\nmax_sync_events=1\n");
    let mut events = replacement::events(3);
    events.extend(replacement::events(1));
    drop(replacement::seed(&dir.path().join("db"), &events, 5));
    let output = sync(&cfg, "ws://127.0.0.1:1", &["--check", "--json"]);
    assert!(!output.status.success());
    assert!(summary(&output)["error"]
        .as_str()
        .unwrap()
        .contains("filtered sync view exceeds"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clean_replacement_databases_sync_above_the_memory_view_event_limit() {
    let local = tempfile::tempdir().unwrap();
    let remote = tempfile::tempdir().unwrap();
    let options =
        "[relay]\nmax_sync_events=1\n[relay.auth]\nenabled=false\nrecipient_only_kinds=[]\n";
    let lc = config(local.path(), options);
    let rc = config(remote.path(), options);
    let events: Vec<_> = [0, 3, 10000, 10002, 30443].into_iter().map(event).collect();
    import(&lc, &events);
    import(&rc, &events);
    let server = serve(&rc).await;
    let output = sync(&lc, &server.url, &["--check", "--json"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(summary(&output)["have"], 0);
    assert_eq!(summary(&output)["need"], 0);
}

#[test]
fn filtered_sync_reports_insufficient_round_memory_explicitly() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path(), "[relay]\nsync_memory_per_connection=1048576\n");
    drop(replacement::seed(
        &dir.path().join("db"),
        &replacement::events(3),
        5,
    ));
    let output = sync(&cfg, "ws://127.0.0.1:1", &["--check", "--json"]);
    assert!(!output.status.success());
    assert!(summary(&output)["error"]
        .as_str()
        .unwrap()
        .contains("sync_memory_per_connection and sync_memory_total for protocol rounds"));
}

#[test]
fn empty_sync_filter_returns_a_structured_error_without_opening_the_database() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path(), "");
    let output = sync(
        &cfg,
        "ws://127.0.0.1:1",
        &["--filter", "[]", "--check", "--json"],
    );
    assert!(!output.status.success());
    assert!(summary(&output)["error"]
        .as_str()
        .unwrap()
        .contains("at least one filter"));
    assert!(!dir.path().join("db").exists());
}
