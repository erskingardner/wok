//! Write-policy plugin end-to-end: the canonical executable `whitelist.js`
//! from strfry's docs/plugins.md (bare path, no spaces — the stat/mtime
//! reload path) accepts a whitelisted pubkey and rejects a stranger with the
//! plugin's own message, through the full relay writer pipeline.

use futures_util::{SinkExt, StreamExt};
use secp256k1::{Keypair, SECP256K1};
use serde_json::json;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio_tungstenite::tungstenite::Message;
use wok_compat::{sign_event, sign_event_with_key};
use wok_db::{Env, EnvOptions};
use wok_relay::Config;

const WRITE_POLICY_TIMEOUT_SECS: u64 = 5;
const CLIENT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The canonical whitelist.js from strfry's docs/plugins.md, whitelisting one
/// pubkey. Configured as a bare executable path (no spaces), which is the
/// documented strfry deployment and exercises wok's stat/mtime reload path.
fn write_whitelist_plugin(dir: &std::path::Path, pubkey_hex: &str) -> std::path::PathBuf {
    let script = dir.join("whitelist.js");
    std::fs::write(
        &script,
        format!(
            "#!/usr/bin/env node\n\
             const whiteList = {{\n\
             \x20   '{pubkey_hex}': true,\n\
             }};\n\
             const rl = require('readline').createInterface({{\n\
             \x20   input: process.stdin,\n\
             \x20   output: process.stdout,\n\
             \x20   terminal: false\n\
             }});\n\
             rl.on('line', (line) => {{\n\
             \x20   let req = JSON.parse(line);\n\
             \x20   if (req.type !== 'new') {{\n\
             \x20       console.error(\"unexpected request type\");\n\
             \x20       return;\n\
             \x20   }}\n\
             \x20   let res = {{ id: req.event.id }};\n\
             \x20   if (whiteList[req.event.pubkey]) {{\n\
             \x20       res.action = 'accept';\n\
             \x20   }} else {{\n\
             \x20       res.action = 'reject';\n\
             \x20       res.msg = 'blocked: not on white-list';\n\
             \x20   }}\n\
             \x20   console.log(JSON.stringify(res));\n\
             }});\n"
        ),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    script
}

#[allow(clippy::field_reassign_with_default)]
fn test_cfg(dir: &std::path::Path, plugin_cmd: String) -> Config {
    let mut cfg = Config::default();
    cfg.db = dir.to_path_buf();
    cfg.relay.bind = "127.0.0.1".into();
    cfg.relay.port = 0;
    cfg.relay.unix.enabled = false;
    cfg.relay.auth.enabled = false;
    cfg.relay.write_policy_plugin = plugin_cmd;
    cfg.relay.write_policy_timeout_secs = WRITE_POLICY_TIMEOUT_SECS;
    cfg
}

async fn start(
    dir: &std::path::Path,
    cfg: Config,
) -> (wok_relay::RelayHandle, std::net::SocketAddr) {
    let env = Env::open(dir, EnvOptions::default()).unwrap();
    env.ensure_initialized().unwrap();
    let handle = wok_relay::start(env, cfg).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let h = handle.clone();
    tokio::spawn(async move {
        let _ = wok_ws::serve_listener(h, listener).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    (handle, addr)
}

async fn publish(addr: std::net::SocketAddr, ev: serde_json::Value) -> String {
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/"))
        .await
        .unwrap();
    ws.send(Message::Text(json!(["EVENT", ev]).to_string().into()))
        .await
        .unwrap();
    for _ in 0..20 {
        // The client must outlive the relay's plugin deadline. On a loaded CI
        // runner, starting the external Node process can consume most of that
        // window before the relay sends its OK response.
        match tokio::time::timeout(CLIENT_RESPONSE_TIMEOUT, ws.next()).await {
            Ok(Some(Ok(m))) => {
                let t = m.to_text().unwrap_or("").to_string();
                if t.contains("\"OK\"") {
                    return t;
                }
            }
            _ => break,
        }
    }
    panic!("no OK received");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn whitelist_js_accepts_whitelisted_and_rejects_others() {
    let dir = tempfile::tempdir().unwrap();
    let mut rng = rand::thread_rng();
    let friend = Keypair::new(SECP256K1, &mut rng);
    let (friend_xonly, _) = friend.x_only_public_key();
    let plugin = write_whitelist_plugin(dir.path(), &hex::encode(friend_xonly.serialize()));
    let cfg = test_cfg(dir.path(), plugin.to_string_lossy().into_owned());
    let (handle, addr) = start(dir.path(), cfg).await;

    // Whitelisted pubkey -> accept.
    let ev = sign_event_with_key(
        json!({"created_at": now_secs(), "kind": 1, "tags": [], "content": "hi from friend"}),
        &friend,
    );
    let verdict = publish(addr, ev).await;
    assert!(
        verdict.contains("true"),
        "whitelisted pubkey rejected: {verdict}"
    );

    // Stranger -> reject with the plugin's message.
    let ev = sign_event(
        json!({"created_at": now_secs(), "kind": 1, "tags": [], "content": "hi from stranger"}),
    );
    let verdict = publish(addr, ev).await;
    assert!(
        verdict.contains("false") && verdict.contains("blocked: not on white-list"),
        "stranger not rejected by plugin: {verdict}"
    );
    handle.request_shutdown();
}
