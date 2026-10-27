//! `wok upload` against a scripted relay: it succeeds only when the relay
//! acknowledged every event it sent, and stored them.
use futures_util::{SinkExt, StreamExt};
use secp256k1::{Keypair, SECP256K1};
use serde_json::{json, Value};
use std::{
    io::Write,
    process::{Command, Output, Stdio},
};
use tokio_tungstenite::tungstenite::Message;

fn event(n: u64) -> Value {
    let key = Keypair::new(SECP256K1, &mut rand::thread_rng());
    let mut event = json!({
        "pubkey": hex::encode(key.x_only_public_key().0.serialize()),
        "kind": 1,
        "created_at": 1_700_000_000 + n,
        "tags": [],
        "content": format!("upload {n}"),
    });
    let id = wok_event::event_id_hash(&event).unwrap();
    event["id"] = json!(hex::encode(id));
    event["sig"] = json!(hex::encode(SECP256K1.sign_schnorr(&id, &key).as_ref()));
    event
}

fn id(event: &Value) -> String {
    event["id"].as_str().unwrap().to_string()
}

fn text(value: Value) -> Message {
    Message::Text(value.to_string().into())
}

fn ok(id: &str, accepted: bool, reason: &str) -> Message {
    text(json!(["OK", id, accepted, reason]))
}

/// A relay that answers the `n`th EVENT it receives, from 0, with the frames
/// `reply(n, id)` returns, and drops the connection, without a close frame,
/// when they are none. Returns the ids it received.
async fn relay(
    reply: fn(usize, &str) -> Vec<Message>,
) -> (String, tokio::task::JoinHandle<Vec<String>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let mut received = Vec::new();
        while let Some(Ok(message)) = ws.next().await {
            let Message::Text(message) = message else {
                continue;
            };
            let message: Value = serde_json::from_str(&message).unwrap();
            assert_eq!(message[0], "EVENT");
            let id = id(&message[1]);
            let frames = reply(received.len(), &id);
            received.push(id);
            if frames.is_empty() {
                return received;
            }
            for frame in frames {
                // The client may leave before these finish.
                let _ = ws.send(frame).await;
            }
        }
        received
    });
    (url, task)
}

fn upload(url: &str, args: &[&str], lines: &[String]) -> Output {
    let dir = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_wok"))
        .arg("--config")
        .arg(dir.path().join("wok.toml"))
        .arg("upload")
        .arg(url)
        .args(args)
        .env("RUST_LOG", "info")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut input = child.stdin.take().unwrap();
        for line in lines {
            // The upload may end before it reads them all.
            let _ = writeln!(input, "{line}");
        }
    }
    child.wait_with_output().unwrap()
}

fn lines(events: &[&Value]) -> Vec<String> {
    events
        .iter()
        .map(|event| wok_event::json::to_tao_string(event))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_upload_every_event_of_which_is_stored_exits_zero() {
    let events = [event(0), event(1), event(2)];
    // A NOTICE that says OK is not an acknowledgment, and the relay answers
    // each copy of a repeated event.
    let (url, task) = relay(|n, id| match n {
        3 => vec![ok(id, true, "duplicate: have this event")],
        _ => vec![text(json!(["NOTICE", "OK"])), ok(id, true, "")],
    })
    .await;
    let output = upload(
        &url,
        &[],
        &lines(&[&events[0], &events[1], &events[2], &events[0]]),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains("Upload complete: lines=4 sent=4 accepted=3 duplicates=1 superseded=0 refused=0 invalid=0 unacknowledged=0"),
        "{stderr}"
    );
    assert_eq!(
        task.await.unwrap(),
        [&events[0], &events[1], &events[2], &events[0]].map(id)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_event_fails_the_upload() {
    let events = [event(0), event(1), event(2)];
    let (url, task) = relay(|n, id| match n {
        1 => vec![ok(id, false, "blocked: not on the list")],
        // Not a failure: the relay holds a newer version.
        2 => vec![ok(id, false, "blocked: have a newer version")],
        _ => vec![ok(id, true, "")],
    })
    .await;
    let output = upload(&url, &[], &lines(&[&events[0], &events[1], &events[2]]));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains(&id(&events[1])), "{stderr}");
    assert!(stderr.contains("blocked: not on the list"), "{stderr}");
    assert!(
        stderr.contains("Upload failed: lines=3 sent=3 accepted=1 duplicates=0 superseded=1 refused=1 invalid=0 unacknowledged=0"),
        "{stderr}"
    );
    assert!(
        stderr.contains("upload incomplete: 1 events refused"),
        "{stderr}"
    );
    task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relay_that_disconnects_midway_fails_the_upload() {
    let events = [event(0), event(1), event(2)];
    let input = lines(&[&events[0], &events[1], &events[2]]);

    // A dropped connection, with input left unread.
    let (url, task) = relay(|n, id| match n {
        0 => vec![ok(id, true, "")],
        _ => vec![],
    })
    .await;
    let output = upload(&url, &["--pipeline", "1"], &input);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains("Upload failed: lines=2 sent=2 accepted=1 duplicates=0 superseded=0 refused=0 invalid=0 unacknowledged=1"),
        "{stderr}"
    );
    assert!(
        stderr.contains("connection lost with 1 acknowledgments outstanding and input left unsent"),
        "{stderr}"
    );
    assert_eq!(task.await.unwrap(), [&events[0], &events[1]].map(id));

    // A close after the whole input was sent. Neither a NOTICE that says OK
    // nor an OK for another event acknowledges the last one.
    let (url, task) = relay(|n, id| match n {
        2 => vec![
            text(json!(["NOTICE", "OK"])),
            ok(&"0".repeat(64), true, ""),
            Message::Close(None),
        ],
        _ => vec![ok(id, true, "")],
    })
    .await;
    let output = upload(&url, &[], &input);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains("Upload failed: lines=3 sent=3 accepted=2 duplicates=0 superseded=0 refused=0 invalid=0 unacknowledged=1"),
        "{stderr}"
    );
    assert!(
        stderr.contains("connection lost with 1 acknowledgments outstanding"),
        "{stderr}"
    );
    assert!(!stderr.contains("input left unsent"), "{stderr}");
    task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lines_that_are_not_events_are_not_sent_and_fail_the_upload() {
    let good = event(0);
    let mut upper = event(1);
    upper["id"] = json!(id(&upper).to_uppercase());
    let (url, task) = relay(|_, id| vec![ok(id, true, "")]).await;
    let input = [
        "not json".to_string(),
        r#"{"kind":1}"#.to_string(),
        wok_event::json::to_tao_string(&upper),
        wok_event::json::to_tao_string(&good),
    ];
    let output = upload(&url, &[], &input);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    for line in 1..=3 {
        assert!(
            stderr.contains(&format!("Not uploading line {line}:")),
            "{stderr}"
        );
    }
    assert!(
        stderr.contains("Upload failed: lines=4 sent=1 accepted=1 duplicates=0 superseded=0 refused=0 invalid=3 unacknowledged=0"),
        "{stderr}"
    );
    assert_eq!(task.await.unwrap(), vec![id(&good)]);
}

#[test]
fn a_pipeline_of_zero_is_refused() {
    let output = Command::new(env!("CARGO_BIN_EXE_wok"))
        .args(["upload", "ws://127.0.0.1:9", "--pipeline", "0"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("--pipeline"), "{stderr}");
}
