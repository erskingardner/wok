//! Pins the C++ RelayIngester error routing: which failures produce
//! OK / CLOSED / NOTICE and with what message prefixes.

use futures_util::{SinkExt, Stream, StreamExt};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;
use wok_db::{Env, EnvOptions};
use wok_relay::Config;

#[allow(clippy::field_reassign_with_default)]
fn test_cfg(dir: &std::path::Path) -> Config {
    let mut cfg = Config::default();
    cfg.db = dir.to_path_buf();
    cfg.relay.bind = "127.0.0.1".into();
    cfg.relay.port = 0;
    cfg.relay.unix.enabled = false;
    cfg.relay.auth.enabled = false;
    cfg.relay.max_req_filter_size = 2;
    cfg
}

async fn recv_until<S>(ws: &mut S, pred: impl Fn(&str) -> bool) -> Vec<String>
where
    S: Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let mut out = Vec::new();
    for _ in 0..20 {
        match tokio::time::timeout(Duration::from_secs(2), ws.next()).await {
            Ok(Some(Ok(msg))) => {
                let t = msg.to_text().unwrap_or("").to_string();
                let hit = pred(&t);
                out.push(t);
                if hit {
                    break;
                }
            }
            _ => break,
        }
    }
    out
}

struct Rig {
    handle: wok_relay::RelayHandle,
    addr: std::net::SocketAddr,
}

async fn start_rig(dir: &std::path::Path) -> Rig {
    let env = Env::open(dir, EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let cfg = test_cfg(dir);
    let handle = wok_relay::start(env, cfg).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let h = handle.clone();
    tokio::spawn(async move {
        let _ = wok_ws::serve_listener(h, listener).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    Rig { handle, addr }
}

async fn send_and_expect(rig: &Rig, payload: String, pred: impl Fn(&str) -> bool, what: &str) {
    let url = format!("ws://{}/", rig.addr);
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    ws.send(Message::Text(payload.into())).await.unwrap();
    // Each of these inputs produces exactly one reply.
    let msgs = recv_until(&mut ws, |_| true).await;
    assert!(
        msgs.iter().any(|t| pred(t)),
        "{what}: no matching reply, got {msgs:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cpp_error_routing() {
    let dir = tempfile::tempdir().unwrap();
    let rig = start_rig(dir.path()).await;

    // Unparseable / envelope errors -> NOTICE "ERROR: bad msg: ..."
    send_and_expect(
        &rig,
        "hello".into(),
        |t| t == r#"["NOTICE","ERROR: bad msg: unparseable message"]"#,
        "unparseable",
    )
    .await;
    send_and_expect(
        &rig,
        r#"["NOPE","x"]"#.into(),
        |t| t == r#"["NOTICE","ERROR: bad msg: unknown cmd"]"#,
        "unknown cmd",
    )
    .await;
    send_and_expect(
        &rig,
        r#"["REQ"]"#.into(),
        |t| t == r#"["NOTICE","ERROR: bad msg: too few array elements"]"#,
        "short envelope",
    )
    .await;
    // Duplicate JSON object keys are rejected at parse time like tao::json.
    send_and_expect(
        &rig,
        r#"["EVENT",{"id":"x","id":"y"}]"#.into(),
        |t| t.starts_with(r#"["NOTICE","ERROR: bad msg: duplicate JSON object key"#),
        "dup keys",
    )
    .await;

    // REQ with no filters -> NOTICE (sub id not yet known in C++).
    send_and_expect(
        &rig,
        r#"["REQ","s"]"#.into(),
        |t| t == r#"["NOTICE","ERROR: bad req: arr too small"]"#,
        "arr too small",
    )
    .await;
    // REQ with too many filters -> CLOSED.
    send_and_expect(
        &rig,
        r#"["REQ","s",{},{},{}]"#.into(),
        |t| t == r#"["CLOSED","s","ERROR: bad req: arr too big"]"#,
        "arr too big",
    )
    .await;
    // REQ with an invalid filter -> CLOSED.
    send_and_expect(
        &rig,
        r#"["REQ","s",{"kinds":"nope"}]"#.into(),
        |t| t.starts_with(r#"["CLOSED","s","ERROR: bad req:"#),
        "bad filter",
    )
    .await;

    // CLOSE with an invalid sub id -> NOTICE "bad close:".
    let long_sub = format!(r#"["CLOSE","{}"]"#, "x".repeat(65));
    send_and_expect(
        &rig,
        long_sub,
        |t| t.starts_with(r#"["NOTICE","ERROR: bad close:"#),
        "bad close",
    )
    .await;

    // AUTH without serviceUrl -> OK false "error: ...".
    send_and_expect(
        &rig,
        r#"["AUTH",{"id":"ab"}]"#.into(),
        |t| {
            t == r#"["OK","ab",false,"error: relay needs serviceUrl to be configured before AUTH can work"]"#
        },
        "auth error",
    )
    .await;

    // EVENT with an invalid event -> OK false "invalid: ...".
    send_and_expect(
        &rig,
        r#"["EVENT",{"id":"ab","kind":1}]"#.into(),
        |t| t.starts_with(r#"["OK","ab",false,"invalid:"#),
        "invalid event",
    )
    .await;

    rig.handle.request_shutdown();
}
