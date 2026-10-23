//! The probe `scripts/attack-surface-reach.py` runs under coverage to measure
//! which relay code each kind of caller reaches. Each test is one phase
//! against a relay of the profile `WOK_REACH_PROFILE` names; the script runs
//! them one at a time and subtracts startup from the others. They are
//! ignored by a normal `cargo test`.

use serde_json::{json, Value};
use sha2::Digest;

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
    Relay::start(cfg).await.stop().await;
}

/// Everything a client that never authenticates can send.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "run by scripts/attack-surface-reach.py"]
async fn reach_anonymous() {
    let (_, cfg) = profile();
    let relay = Relay::start(cfg.clone()).await;
    anonymous_messages(&relay, &cfg).await;
    anonymous_http(&relay, &cfg).await;
    relay.stop().await;
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
    let mut wire = Wire::connect(relay.addr).await;
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
    wire.send(json!(["NEG-OPEN", "neg", {"kinds": [1], "authors": [me]}, neg_initial()]))
        .await;
    until_end(&mut wire, "neg").await;
    drop(wire);
    relay.stop().await;
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
        http(relay.addr, &request).await;
    }
    let stranger = hex::encode(key(2).x_only_public_key().0.serialize());
    for (n, (method, params)) in [
        ("supportedmethods", json!([])),
        ("banpubkey", json!([stranger, "probe"])),
        ("listbannedpubkeys", json!([])),
        ("allowkind", json!([1])),
        ("blockip", json!(["192.0.2.1", "probe"])),
        ("listblockedips", json!([])),
        ("changerelayname", json!(["probe"])),
    ]
    .into_iter()
    .enumerate()
    {
        let body = json!({"method": method, "params": params, "id": n}).to_string();
        let auth = nip98(&admin, "POST", &public_url, &body);
        let request = http_request("POST", "/", &auth, "application/nostr+json+rpc", &body);
        http(relay.addr, &request).await;
    }
    relay.stop().await;
}

/// Every client message, valid and not, from a connection that never
/// authenticates.
async fn anonymous_messages(relay: &Relay, cfg: &wok_relay::Config) {
    let mut wire = Wire::connect(relay.addr).await;
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
        if until_end(&mut wire, sub).await {
            wire.send(json!(["CLOSE", sub])).await;
        }
        wire.send(json!(["COUNT", format!("{sub}-count"), filter]))
            .await;
        until_end(&mut wire, &format!("{sub}-count")).await;
    }
    wire.send(json!(["NEG-OPEN", "neg", {"ids": [UNKNOWN_ID]}, neg_initial()]))
        .await;
    until_end(&mut wire, "neg").await;
    wire.send(json!(["NEG-MSG", "neg", neg_initial()])).await;
    wire.send(json!(["NEG-CLOSE", "neg"])).await;
    wire.send(json!(["NEG-OPEN", "neg-bad", {"ids": [UNKNOWN_ID]}, "zz"]))
        .await;
    until_end(&mut wire, "neg-bad").await;
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
    until_end(&mut wire, "end").await;
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
    let signed = nip98(&stranger, "POST", &public_url, body);
    let mut forged = signed.clone();
    forged["sig"] = json!("00".repeat(64));
    for auth in [Some(signed), Some(forged), None] {
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
    let overview = nip98(
        &stranger,
        "GET",
        &format!("{public_url}/admin/api/overview"),
        "",
    );
    let request = http_request(
        "GET",
        "/admin/api/overview",
        &overview,
        "application/json",
        "",
    );
    http(relay.addr, &request).await;
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
async fn until_end(wire: &mut Wire, sub: &str) -> bool {
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

fn event(key: &secp256k1::Keypair, kind: u64, tags: Value, content: &str) -> Value {
    wok_compat::sign_event_with_key(
        json!({"created_at": now(), "kind": kind, "tags": tags, "content": content}),
        key,
    )
}

fn nip98(key: &secp256k1::Keypair, method: &str, url: &str, body: &str) -> Value {
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
