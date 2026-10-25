//! The probe `scripts/attack-surface-reach.py` runs under coverage to measure
//! which relay code each kind of caller reaches. Each test is one phase
//! against a relay of the profile `WOK_REACH_PROFILE` names; the script runs
//! them one at a time and subtracts startup from the others. They are
//! ignored by a normal `cargo test`.
//!
//! The probe shares its process, and so its coverage counters, with the
//! relay. It never calls the relay's crates itself: it signs events, frames
//! Unix messages and holds its NIP-77 message on its own, so that what the
//! script counts is what the relay ran.

use secp256k1::{Keypair, SECP256K1};
use serde_json::{json, Value};
use sha2::Digest;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[path = "support/surface.rs"]
mod surface;
use surface::*;

fn profile() -> (String, wok_relay::Config) {
    let name = std::env::var("WOK_REACH_PROFILE").expect("set WOK_REACH_PROFILE");
    let cfg = load_profile(&name);
    (name, cfg)
}

/// Start the relay and stop it: what every other phase also runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "run by scripts/attack-surface-reach.py"]
async fn reach_startup() {
    let (_, cfg) = profile();
    let relay = Relay::start(cfg.clone()).await;
    let _unix = unix_listener(&relay, &cfg, my_uid()).await;
    stop(relay).await;
}

/// Everything a client that never authenticates can send.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "run by scripts/attack-surface-reach.py"]
async fn reach_anonymous() {
    let (_, cfg) = profile();
    let relay = Relay::start(cfg.clone()).await;
    let mut conn = Conn::Ws(Box::new(Wire::connect(relay.addr).await));
    anonymous_messages(&mut conn, &cfg).await;
    conn.close().await;
    deflated_messages(&relay).await;
    anonymous_http(&relay, &cfg).await;
    // A local peer the Unix socket does not admit.
    if let Some((_dir, path)) = unix_listener(&relay, &cfg, my_uid().wrapping_add(1)).await {
        let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
        let _ = write_frame(&mut stream, r#"["REQ","x",{}]"#).await;
        let mut rest = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut rest)).await;
    }
    stop(relay).await;
}

/// A client that authenticates, then sends what AUTH unlocks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "run by scripts/attack-surface-reach.py"]
async fn reach_authenticated() {
    let (_, cfg) = profile();
    if !cfg.auth_usable() {
        return;
    }
    let relay = Relay::start(cfg.clone()).await;
    let mut wire = Conn::Ws(Box::new(Wire::connect(relay.addr).await));
    let challenge = wire.challenge().await;
    let author = key(1);
    let auth = event(
        &author,
        22242,
        json!([
            ["relay", cfg.relay.auth.service_url],
            ["challenge", challenge]
        ]),
        "",
    );
    let id = auth["id"].clone();
    wire.send(json!(["AUTH", auth])).await;
    wire.until("AUTH", |frame| frame[0] == "OK" && frame[1] == id)
        .await;
    let me = hex::encode(author.x_only_public_key().0.serialize());
    for (n, message) in [
        json!(["EVENT", event(&author, 1, json!([["-"]]), "protected")]),
        json!(["EVENT", event(&author, 30078, json!([["d", "app"]]), "{}")]),
        json!(["EVENT", event(&author, 1, json!([]), "note")]),
    ]
    .into_iter()
    .enumerate()
    {
        let id = message[1]["id"].clone();
        wire.send(message).await;
        wire.until(&format!("OK {n}"), |frame| {
            frame[0] == "OK" && frame[1] == id
        })
        .await;
    }
    for (sub, filter) in [
        ("dms", json!({"kinds": [4, 1059], "#p": [me]})),
        ("app", json!({"kinds": [30078], "authors": [me]})),
        ("notes", json!({"kinds": [1], "authors": [me]})),
    ] {
        wire.send(json!(["REQ", sub, filter])).await;
        until_end(&mut wire, sub).await;
        wire.send(json!(["COUNT", format!("{sub}-count"), filter]))
            .await;
        until_end(&mut wire, &format!("{sub}-count")).await;
    }
    wire.send(json!(["NEG-OPEN", "neg", {"kinds": [1], "authors": [me]}, NEG_INITIAL]))
        .await;
    until_end(&mut wire, "neg").await;
    wire.close().await;
    stop(relay).await;
}

/// An admin of the `gated` profile, using the dashboard API and NIP-86.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "run by scripts/attack-surface-reach.py"]
async fn reach_admin() {
    let (_, cfg) = profile();
    if !cfg.admin.enabled {
        return;
    }
    let relay = Relay::start(cfg.clone()).await;
    let admin = key(1);
    let public_url = cfg.admin.public_url.clone();
    for (method, path, body) in [
        ("GET", "/admin/api/overview", ""),
        ("PUT", "/admin/api/config", r#"{"info":{"name":"probe"}}"#),
    ] {
        let auth = nip98(&admin, method, &format!("{public_url}{path}"), body);
        let request = http_request(method, path, &auth, "application/json", body);
        let (status, _, reply) = http(relay.addr, &request).await;
        let refused = method == "PUT" && !cfg.admin.allow_config_writes;
        assert_eq!(
            status,
            if refused { 403 } else { 200 },
            "{method} {path}: {reply}"
        );
    }
    let stranger = hex::encode(key(2).x_only_public_key().0.serialize());
    let role = json!(["probe", "Probe", "a probe role", "#000000", 1]);
    // Every NIP-86 method, each with parameters it accepts.
    for (n, (method, params)) in [
        ("supportedmethods", json!([])),
        ("banpubkey", json!([stranger, "probe"])),
        ("unbanpubkey", json!([stranger])),
        ("listbannedpubkeys", json!([])),
        ("allowpubkey", json!([stranger, "probe"])),
        ("unallowpubkey", json!([stranger])),
        ("listallowedpubkeys", json!([])),
        ("createrole", role.clone()),
        ("editrole", role),
        ("assignrole", json!([stranger, "probe"])),
        ("unassignrole", json!([stranger, "probe"])),
        ("deleterole", json!(["probe"])),
        ("listeventsneedingmoderation", json!([])),
        ("allowevent", json!([UNKNOWN_ID, "probe"])),
        ("unallowevent", json!([UNKNOWN_ID])),
        ("listallowedevents", json!([])),
        ("banevent", json!([UNKNOWN_ID, "probe"])),
        ("unbanevent", json!([UNKNOWN_ID])),
        ("listbannedevents", json!([])),
        ("changerelayname", json!(["probe"])),
        ("changerelaydescription", json!(["probe"])),
        (
            "changerelayicon",
            json!(["https://relay.example.com/icon.png"]),
        ),
        ("allowkind", json!([1])),
        ("disallowkind", json!([1])),
        ("listallowedkinds", json!([])),
        ("listdisallowedkinds", json!([])),
        ("blockip", json!(["192.0.2.1", "probe"])),
        ("unblockip", json!(["192.0.2.1"])),
        ("listblockedips", json!([])),
    ]
    .into_iter()
    .enumerate()
    {
        let body = json!({"method": method, "params": params, "id": n}).to_string();
        let auth = nip98(&admin, "POST", &public_url, &body);
        let request = http_request("POST", "/", &auth, "application/nostr+json+rpc", &body);
        let (status, _, reply) = http(relay.addr, &request).await;
        // A call refused for its parameters never reaches the method, so
        // the phase would not measure it. Without `allow_config_writes`,
        // methods that edit the file are refused by that gate instead.
        let reply: Value = serde_json::from_str(&reply).unwrap_or_default();
        let gated =
            !cfg.admin.allow_config_writes && reply["error"] == "config writes are disabled";
        assert!(
            status == 200 && (reply.get("error").is_none() || gated),
            "{method}: {status} {reply}"
        );
    }
    stop(relay).await;
}

/// A local peer the Unix socket admits, sending what an anonymous client
/// sends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "run by scripts/attack-surface-reach.py"]
async fn reach_local() {
    let (_, cfg) = profile();
    let relay = Relay::start(cfg.clone()).await;
    if let Some((_dir, path)) = unix_listener(&relay, &cfg, my_uid()).await {
        let stream = tokio::net::UnixStream::connect(&path).await.unwrap();
        let mut conn = Conn::Unix(stream, Vec::new());
        anonymous_messages(&mut conn, &cfg).await;
        conn.close().await;
    }
    stop(relay).await;
}

/// Every client message, valid and not, from a connection that never
/// authenticates.
async fn anonymous_messages(wire: &mut Conn, cfg: &wok_relay::Config) {
    let stranger = key(2);
    let note = event(&stranger, 1, json!([]), "hello");
    let mut forged = note.clone();
    forged["sig"] = json!("00".repeat(64));
    let mut events = vec![
        note.clone(),
        note,
        forged,
        event(&stranger, 22242, json!([]), ""),
        event(&stranger, 1, json!([["-"]]), "protected"),
        event(&stranger, 30078, json!([["d", "app"]]), "{}"),
        event(&stranger, 5, json!([["e", UNKNOWN_ID]]), ""),
        event(
            &stranger,
            62,
            json!([["relay", "wss://elsewhere.example"]]),
            "",
        ),
        event(&stranger, 0, json!([]), "{}"),
        event(&stranger, 30023, json!([["d", "post"]]), "long"),
        event(&stranger, 1059, json!([["p", UNKNOWN_ID]]), "wrap"),
    ];
    if cfg.relay.nip62.enabled && !cfg.relay.auth.service_url.is_empty() {
        let url = cfg.relay.auth.service_url.clone();
        events.push(event(&stranger, 62, json!([["relay", url]]), ""));
    }
    for (n, ev) in events.into_iter().enumerate() {
        let id = ev["id"].clone();
        wire.send(json!(["EVENT", ev])).await;
        wire.until(&format!("OK {n}"), |frame| {
            frame[0] == "OK" && frame[1] == id
        })
        .await;
    }
    for (sub, filter) in [
        ("ids", json!({"ids": [UNKNOWN_ID]})),
        ("kinds", json!({"kinds": [1], "limit": 5})),
        ("tags", json!({"#p": [UNKNOWN_ID], "kinds": [1059]})),
        ("and", json!({"&t": ["a", "b"], "kinds": [1]})),
        ("search", json!({"search": "hello", "kinds": [1]})),
        ("wraps", json!({"kinds": [1059]})),
        ("bad", json!({"kinds": "one"})),
    ] {
        wire.send(json!(["REQ", sub, filter])).await;
        if until_end(wire, sub).await {
            wire.send(json!(["CLOSE", sub])).await;
        }
        wire.send(json!(["COUNT", format!("{sub}-count"), filter]))
            .await;
        until_end(wire, &format!("{sub}-count")).await;
    }
    wire.send(json!(["NEG-OPEN", "neg", {"ids": [UNKNOWN_ID]}, NEG_INITIAL]))
        .await;
    until_end(wire, "neg").await;
    wire.send(json!(["NEG-MSG", "neg", NEG_INITIAL])).await;
    wire.send(json!(["NEG-CLOSE", "neg"])).await;
    wire.send(json!(["NEG-OPEN", "neg-bad", {"ids": [UNKNOWN_ID]}, "zz"]))
        .await;
    until_end(wire, "neg-bad").await;
    for text in [
        "[",
        "\n",
        r#"["HELLO",1]"#,
        r#"["CLOSE","none"]"#,
        r#"["CLOSE",1]"#,
    ] {
        wire.send_text(text.to_string()).await;
    }
    let challenge = if cfg.auth_usable() {
        wire.challenge().await
    } else {
        "none".into()
    };
    let mut forged_auth = event(
        &stranger,
        22242,
        json!([
            ["relay", cfg.relay.auth.service_url],
            ["challenge", challenge]
        ]),
        "",
    );
    forged_auth["sig"] = json!("00".repeat(64));
    for (n, auth) in [
        event(&stranger, 22242, json!([["challenge", "wrong"]]), ""),
        forged_auth,
    ]
    .into_iter()
    .enumerate()
    {
        let id = auth["id"].clone();
        wire.send(json!(["AUTH", auth])).await;
        wire.until(&format!("AUTH {n}"), |frame| {
            frame[0] == "OK" && frame[1] == id
        })
        .await;
    }
    // Everything sent has been answered or ingested before this answer.
    wire.send(json!(["REQ", "end", {"ids": [UNKNOWN_ID]}]))
        .await;
    until_end(wire, "end").await;
}

/// Every path and method of the listeners, unsigned, signed by a stranger
/// and forged.
async fn anonymous_http(relay: &Relay, cfg: &wok_relay::Config) {
    for path in [
        "/",
        "/metrics",
        "/.well-known/nodeinfo",
        "/nodeinfo/2.1",
        "/favicon.ico",
        "/admin",
        "/admin/api/overview",
        "/x",
    ] {
        for method in METHODS {
            let request = format!(
                "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            http(relay.addr, &request).await;
        }
    }
    let nip11 = "GET / HTTP/1.1\r\nHost: localhost\r\nAccept: application/nostr+json\r\nConnection: close\r\n\r\n";
    http(relay.addr, nip11).await;
    status(
        relay.addr,
        "GET /x HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
    )
    .await;
    let public_url = if cfg.admin.public_url.is_empty() {
        "https://relay.example.com".to_string()
    } else {
        cfg.admin.public_url.clone()
    };
    let body = r#"{"method":"supportedmethods","params":[]}"#;
    let stranger = key(2);
    // Anyone can claim an admin's key; only the signature check stops them.
    let claimed_admin = key(1);
    let signed = nip98(&stranger, "POST", &public_url, body);
    let forged = |key: &Keypair, method: &str, url: &str, body: &str| {
        let mut event = nip98(key, method, url, body);
        event["sig"] = json!("00".repeat(64));
        event
    };
    for auth in [
        Some(signed),
        Some(forged(&stranger, "POST", &public_url, body)),
        Some(forged(&claimed_admin, "POST", &public_url, body)),
        None,
    ] {
        let request = match &auth {
            Some(auth) => http_request("POST", "/", auth, "application/nostr+json+rpc", body),
            None => format!(
                "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/nostr+json+rpc\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ),
        };
        http(relay.addr, &request).await;
    }
    let overview = format!("{public_url}/admin/api/overview");
    for auth in [
        nip98(&stranger, "GET", &overview, ""),
        forged(&stranger, "GET", &overview, ""),
        forged(&claimed_admin, "GET", &overview, ""),
    ] {
        let request = http_request("GET", "/admin/api/overview", &auth, "application/json", "");
        http(relay.addr, &request).await;
    }
    if let Some(metrics) = relay.metrics {
        for method in METHODS {
            let request = format!(
                "{method} /metrics HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            http(metrics, &request).await;
        }
    }
}

/// Read until the reply that ends subscription `sub`; whether it was EOSE.
async fn until_end(wire: &mut Conn, sub: &str) -> bool {
    let end = wire
        .until(sub, |frame| {
            frame[1] == sub
                && ["EOSE", "CLOSED", "COUNT", "NEG-MSG", "NEG-ERR"]
                    .iter()
                    .any(|kind| frame[0] == *kind)
        })
        .await;
    end[0] == "EOSE"
}

fn event(key: &Keypair, kind: u64, tags: Value, content: &str) -> Value {
    sign(
        key,
        json!({"created_at": now(), "kind": kind, "tags": tags, "content": content}),
    )
}

/// Sign `event` as `key` without the relay's crates: its NIP-01 id is the
/// SHA-256 of `[0, pubkey, created_at, kind, tags, content]`, which compact
/// JSON writes as NIP-01 does for the ASCII the probe sends.
fn sign(key: &Keypair, mut event: Value) -> Value {
    let pubkey = hex::encode(key.x_only_public_key().0.serialize());
    let preimage = json!([
        0,
        pubkey,
        event["created_at"],
        event["kind"],
        event["tags"],
        event["content"]
    ]);
    let id: [u8; 32] = sha2::Sha256::digest(preimage.to_string()).into();
    event["pubkey"] = json!(pubkey);
    event["id"] = json!(hex::encode(id));
    event["sig"] = json!(hex::encode(SECP256K1.sign_schnorr(&id, key).as_ref()));
    event
}

fn nip98(key: &Keypair, method: &str, url: &str, body: &str) -> Value {
    let payload = hex::encode(sha2::Sha256::digest(body.as_bytes()));
    event(
        key,
        27235,
        json!([
            ["u", url],
            ["method", method],
            ["payload", payload],
            ["nonce", now().to_string() + url + body]
        ]),
        "",
    )
}

fn http_request(method: &str, path: &str, auth: &Value, content_type: &str, body: &str) -> String {
    use base64::Engine;
    format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Nostr {}\r\n\
         Content-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        base64::engine::general_purpose::STANDARD.encode(auth.to_string()),
        body.len()
    )
}

/// The client's first NIP-77 message over an empty set, as
/// `surface::neg_initial` builds it.
const NEG_INITIAL: &str = "6100000200";

/// A client connection over either transport.
enum Conn {
    Ws(Box<Wire>),
    /// A Unix socket, and every frame read from it.
    Unix(tokio::net::UnixStream, Vec<Value>),
}

impl Conn {
    async fn send(&mut self, message: Value) {
        self.send_text(message.to_string()).await;
    }

    async fn send_text(&mut self, text: String) {
        match self {
            Self::Ws(wire) => wire.send_text(text).await,
            Self::Unix(stream, _) => write_frame(stream, &text).await.unwrap(),
        }
    }

    /// Read frames until one matches `answers`, keeping each.
    async fn until(&mut self, what: &str, answers: impl Fn(&Value) -> bool) -> Value {
        let (stream, seen) = match self {
            Self::Ws(wire) => return wire.until(what, answers).await,
            Self::Unix(stream, seen) => (stream, seen),
        };
        loop {
            let mut length = [0u8; 4];
            tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut length))
                .await
                .unwrap_or_else(|_| panic!("no {what} within 5 s"))
                .expect("the relay closed the connection");
            let mut body = vec![0u8; u32::from_be_bytes(length) as usize];
            stream.read_exact(&mut body).await.unwrap();
            let Ok(frame) = serde_json::from_slice::<Value>(&body) else {
                continue;
            };
            seen.push(frame.clone());
            if answers(&frame) {
                return frame;
            }
        }
    }

    /// Hang up, and read until the relay closes the connection too.
    async fn close(self) {
        match self {
            Self::Ws(wire) => wire.close().await,
            Self::Unix(mut stream, _) => {
                stream.shutdown().await.unwrap();
                let mut rest = Vec::new();
                tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut rest))
                    .await
                    .expect("the relay closes a connection whose client closed")
                    .unwrap();
            }
        }
    }

    /// The NIP-42 challenge the relay sent on connect.
    async fn challenge(&mut self) -> String {
        let seen = match self {
            Self::Ws(wire) => return wire.challenge().await,
            Self::Unix(_, seen) => seen,
        };
        let frame = match seen.iter().find(|frame| frame[0] == "AUTH") {
            Some(frame) => frame.clone(),
            None => {
                self.until("an AUTH challenge", |frame| frame[0] == "AUTH")
                    .await
            }
        };
        frame[1].as_str().unwrap().to_string()
    }
}

/// One frame of the Unix transport: a four-byte big-endian length, then the
/// message.
async fn write_frame(stream: &mut tokio::net::UnixStream, text: &str) -> std::io::Result<()> {
    stream.write_all(&(text.len() as u32).to_be_bytes()).await?;
    stream.write_all(text.as_bytes()).await?;
    stream.flush().await
}

/// Serve the profile's Unix socket, admitting only `uid`, when the profile
/// enables it. Returns the socket and the directory that holds it.
async fn unix_listener(
    relay: &Relay,
    cfg: &wok_relay::Config,
    uid: u32,
) -> Option<(tempfile::TempDir, PathBuf)> {
    if !cfg.relay.unix.enabled {
        return None;
    }
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = cfg.clone();
    cfg.relay.unix.path = dir.path().join("probe.sock");
    cfg.relay.unix.auth_uids = vec![uid];
    let path = cfg.relay.unix.path.clone();
    tokio::spawn(wok_unix::serve(relay.handle.clone(), cfg));
    for _ in 0..500 {
        if path.exists() {
            return Some((dir, path));
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the Unix socket was not bound within 5 s");
}

/// Stop the relay once every connection the phase opened has queued its
/// teardown, so the teardown runs in this phase on every run. A connection
/// still open when the relay stops is closed by the stop itself, and its
/// `Close` races the ingester's `Stop`: the workers drain their queues before
/// they exit, but get the connection's `Close` only if it reached the
/// ingester first. The gauge drops once `Close` is queued.
async fn stop(relay: Relay) {
    let metrics = relay.handle.metrics.clone();
    for _ in 0..500 {
        if metrics.active_connections.load(Ordering::Relaxed) == 0 {
            return relay.stop().await;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the relay still holds a connection 5 s after the probe closed its last");
}

/// The probe's own user ID, read from a file it creates.
fn my_uid() -> u32 {
    tempfile::tempfile().unwrap().metadata().unwrap().uid()
}

/// The probe's stand-ins for the relay's crates agree with them. Not a phase:
/// a normal `cargo test` runs it.
#[test]
fn probe_helpers_match_the_relay() {
    assert_eq!(NEG_INITIAL, neg_initial());
    let event = event(&key(2), 1, json!([["t", "probe"]]), "hello");
    let id = wok_event::event_id_hash(&event).unwrap();
    assert_eq!(event["id"], json!(hex::encode(id)));
}

/// A WebSocket that offers permessage-deflate, as browsers do, and sends two
/// compressed messages, the second against the first's window. Compressed
/// and framed with `flate2` here, not the relay's codec.
async fn deflated_messages(relay: &Relay) {
    let mut stream = tokio::net::TcpStream::connect(relay.addr).await.unwrap();
    stream
        .write_all(
            b"GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\
              Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n",
        )
        .await
        .unwrap();
    let mut buf = Vec::new();
    let end = loop {
        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        read_more(&mut stream, &mut buf, "the upgrade").await;
    };
    let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
    buf.drain(..end);
    if !head.contains("sec-websocket-extensions: permessage-deflate") {
        // Close and read to the end, so the relay sees the stream end rather
        // than a reset over frames left unread, such as an AUTH challenge.
        stream.shutdown().await.unwrap();
        let mut rest = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut rest))
            .await
            .expect("the relay closes a connection whose client closed")
            .unwrap();
        return;
    }
    let mut deflate = flate2::Compress::new(flate2::Compression::default(), false);
    let mut inflate = flate2::Decompress::new(false);
    for n in 0..2 {
        let sub = format!("deflate-{n}");
        let text = json!(["REQ", sub, {"ids": [UNKNOWN_ID]}]).to_string();
        let mut payload = Vec::with_capacity(text.len() + 64);
        deflate
            .compress_vec(text.as_bytes(), &mut payload, flate2::FlushCompress::Sync)
            .unwrap();
        // RFC 7692: a message ends without the flush's empty block.
        payload.truncate(payload.len() - 4);
        assert!(payload.len() < 126, "one length byte");
        // FIN, RSV1 (compressed), text; masked, as a client must.
        let mut frame = vec![0xc1, 0x80 | payload.len() as u8, 1, 2, 3, 4];
        frame.extend(
            payload
                .iter()
                .enumerate()
                .map(|(i, byte)| byte ^ [1, 2, 3, 4][i % 4]),
        );
        stream.write_all(&frame).await.unwrap();
        loop {
            let reply = next_message(&mut stream, &mut buf, &mut inflate).await;
            if reply[1] == sub.as_str() {
                break;
            }
        }
    }
}

/// The next message the relay sends on a deflate-negotiated WebSocket.
async fn next_message(
    stream: &mut tokio::net::TcpStream,
    buf: &mut Vec<u8>,
    inflate: &mut flate2::Decompress,
) -> Value {
    loop {
        if let Some((compressed, payload, used)) = server_frame(buf) {
            buf.drain(..used);
            let text = if compressed {
                let mut input = payload;
                input.extend_from_slice(&[0, 0, 0xff, 0xff]);
                let mut out = Vec::with_capacity(input.len() * 16 + 4096);
                inflate
                    .decompress_vec(&input, &mut out, flate2::FlushDecompress::Sync)
                    .unwrap();
                out
            } else {
                payload
            };
            if let Ok(message) = serde_json::from_slice(&text) {
                return message;
            }
            continue;
        }
        read_more(stream, buf, "a message").await;
    }
}

/// An unmasked frame at the start of `buf`: whether it is compressed, its
/// payload, and how many bytes it took.
fn server_frame(buf: &[u8]) -> Option<(bool, Vec<u8>, usize)> {
    let (&first, &second) = (buf.first()?, buf.get(1)?);
    let (len, start) = match second & 0x7f {
        126 => (
            u16::from_be_bytes(buf.get(2..4)?.try_into().unwrap()) as usize,
            4,
        ),
        127 => (
            u64::from_be_bytes(buf.get(2..10)?.try_into().unwrap()) as usize,
            10,
        ),
        len => (len as usize, 2),
    };
    let payload = buf.get(start..start + len)?.to_vec();
    Some((first & 0x40 != 0, payload, start + len))
}

async fn read_more(stream: &mut tokio::net::TcpStream, buf: &mut Vec<u8>, what: &str) {
    let mut chunk = [0u8; 4096];
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
        .await
        .unwrap_or_else(|_| panic!("no {what} within 5 s"))
        .unwrap();
    assert!(read > 0, "the relay closed the connection before {what}");
    buf.extend_from_slice(&chunk[..read]);
}
