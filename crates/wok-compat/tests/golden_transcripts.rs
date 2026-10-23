//! Golden transcripts: one fixed script of client messages and HTTP requests,
//! sent to a relay of every profile in `tests/profiles/`, with what the relay
//! answers saved in `tests/transcripts/<profile>.txt`. A change that alters
//! what a client sees, such as refusing a request at an earlier check, shows
//! up as a diff of those files. Rewrite them with `WOK_BLESS_TRANSCRIPTS=1`
//! and review the diff in the pull request.

use serde_json::{json, Value};
use sha2::Digest;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::PathBuf;
use wok_relay::Config;

#[path = "support/surface.rs"]
mod surface;
use surface::*;

const BLESS: &str = "WOK_BLESS_TRANSCRIPTS";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_profile_answers_as_its_transcript_says() {
    let bless = std::env::var_os(BLESS).is_some();
    let names = profile_names();
    let mut problems = Vec::new();
    for name in &names {
        let cfg = load_profile(name);
        let relay = Relay::start(cfg.clone()).await;
        let transcript = record(name, &relay, &cfg).await;
        relay.stop().await;
        let path = transcripts_dir().join(format!("{name}.txt"));
        if bless {
            std::fs::write(&path, &transcript).unwrap();
            continue;
        }
        let golden = std::fs::read_to_string(&path).unwrap_or_default();
        if golden != transcript {
            problems.push(first_difference(name, &golden, &transcript));
        }
    }
    for file in std::fs::read_dir(transcripts_dir()).unwrap() {
        let file = file.unwrap().path();
        let stem = file.file_stem().unwrap().to_string_lossy().into_owned();
        if !names.contains(&stem) {
            problems.push(format!("{} has no profile", file.display()));
        }
    }
    assert!(
        problems.is_empty(),
        "the relay's answers differ from tests/transcripts/:\n{}\n\nIf the change is intended, \
         rerun with {BLESS}=1 and review the diff of tests/transcripts/ in the pull request.",
        problems.join("\n")
    );
}

fn transcripts_dir() -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/transcripts")
}

fn first_difference(name: &str, golden: &str, now: &str) -> String {
    let (golden, now): (Vec<&str>, Vec<&str>) = (golden.lines().collect(), now.lines().collect());
    let at = golden
        .iter()
        .zip(&now)
        .position(|(a, b)| a != b)
        .unwrap_or(golden.len().min(now.len()));
    let context =
        |lines: &[&str]| lines[at.saturating_sub(2)..(at + 3).min(lines.len())].join("\n  ");
    format!(
        "{name}.txt, line {}:\n  golden:\n  {}\n  now:\n  {}",
        at + 1,
        context(&golden),
        context(&now)
    )
}

/// Run the script against `relay` and return its transcript.
async fn record(name: &str, relay: &Relay, cfg: &Config) -> String {
    let base = now() - 1_000;
    let mut out = Transcript::new(base);
    writeln!(out.text, "# profile: {name}").unwrap();
    let author = key(1);
    let stranger = key(2);
    let service_url = if cfg.relay.auth.service_url.is_empty() {
        "wss://relay.example.com".to_string()
    } else {
        cfg.relay.auth.service_url.clone()
    };

    let mut wire = Wire::connect(relay.addr).await;
    out.step("connect");
    let frames = marked(&mut wire, None).await;
    let challenge = if cfg.auth_usable() {
        wire.challenge().await
    } else {
        "none sent".to_string()
    };
    out.literal(&challenge, "<challenge>");
    out.frames(&frames);

    let note = event(&author, base + 1, 1, json!([]), "hello");
    let steps: Vec<(&str, Value)> = vec![
        ("EVENT a note", json!(["EVENT", note])),
        ("EVENT the same note again", json!(["EVENT", note])),
        (
            "EVENT a note from another key",
            json!(["EVENT", event(&stranger, base + 2, 1, json!([]), "hi")]),
        ),
        (
            "EVENT a forged signature",
            json!(["EVENT", forged(&note, "sig")]),
        ),
        (
            "EVENT an id that does not match",
            json!(["EVENT", forged(&note, "content")]),
        ),
        (
            "EVENT an AUTH event",
            json!(["EVENT", event(&author, now(), 22242, json!([]), "")]),
        ),
        (
            "EVENT a protected event",
            json!(["EVENT", event(&author, base + 4, 1, json!([["-"]]), "mine")]),
        ),
        (
            "EVENT owner-only app data",
            json!([
                "EVENT",
                event(&author, base + 5, 30078, json!([["d", "app"]]), "{}")
            ]),
        ),
        (
            "EVENT dated an hour ahead",
            json!([
                "EVENT",
                event(&author, now() + 3_600, 1, json!([]), "later")
            ]),
        ),
        (
            "EVENT a vanish request for another relay",
            json!([
                "EVENT",
                event(
                    &author,
                    base + 6,
                    62,
                    json!([["relay", "wss://elsewhere.example"]]),
                    ""
                )
            ]),
        ),
    ];
    for (label, message) in steps {
        out.step(label);
        let id = message[1]["id"].clone();
        wire.send(message).await;
        let ok = wire
            .until(label, |frame| frame[0] == "OK" && frame[1] == id)
            .await;
        out.frames(&[ok]);
    }

    let author_hex = hex::encode(author.x_only_public_key().0.serialize());
    let subs: Vec<(&str, &str, Value)> = vec![
        (
            "REQ the author's notes",
            "notes",
            json!({"authors": [author_hex], "kinds": [1]}),
        ),
        (
            "REQ only gift wraps",
            "wraps",
            json!({"kinds": [1059], "#p": [author_hex]}),
        ),
        (
            "REQ a filter that does not parse",
            "bad",
            json!({"kinds": "one"}),
        ),
        ("REQ every note", "all", json!({"kinds": [1]})),
    ];
    for (label, sub, filter) in subs {
        out.step(label);
        wire.send(json!(["REQ", sub, filter])).await;
        let frames = until_sub(&mut wire, sub, &["EOSE", "CLOSED"]).await;
        out.frames(&frames);
        if frames.last().is_some_and(|frame| frame[0] == "EOSE") {
            wire.send(json!(["CLOSE", sub])).await;
            marked(&mut wire, Some("CLOSE")).await;
        }
    }

    out.step("COUNT notes");
    wire.send(json!(["COUNT", "count", {"kinds": [1], "authors": [author_hex]}]))
        .await;
    out.frames(&until_sub(&mut wire, "count", &["COUNT", "CLOSED"]).await);

    out.step("NEG-OPEN");
    wire.send(json!(["NEG-OPEN", "neg", {"ids": [UNKNOWN_ID]}, neg_initial()]))
        .await;
    out.frames(&until_sub(&mut wire, "neg", &["NEG-MSG", "NEG-ERR"]).await);
    out.step("NEG-CLOSE an open session");
    wire.send(json!(["NEG-CLOSE", "neg"])).await;
    out.frames(&marked(&mut wire, Some("NEG-CLOSE")).await);
    out.step("NEG-OPEN with a payload that is not hex");
    wire.send(json!(["NEG-OPEN", "neg-bad", {"ids": [UNKNOWN_ID]}, "zz"]))
        .await;
    out.frames(&until_sub(&mut wire, "neg-bad", &["NEG-MSG", "NEG-ERR"]).await);
    out.step("NEG-MSG for no session");
    wire.send(json!(["NEG-MSG", "neg-none", neg_initial()]))
        .await;
    out.frames(&until_sub(&mut wire, "neg-none", &["NEG-MSG", "NEG-ERR"]).await);

    for (label, text) in [
        ("CLOSE an unknown subscription", r#"["CLOSE","nothing"]"#),
        ("a message that is not JSON", "["),
        ("an unknown verb", r#"["HELLO",1]"#),
    ] {
        out.step(label);
        wire.send_text(text.to_string()).await;
        out.frames(&marked(&mut wire, Some(label)).await);
    }

    let auth = |key: &secp256k1::Keypair, challenge: &str, created_at| {
        event(
            key,
            created_at,
            22242,
            json!([["relay", service_url], ["challenge", challenge]]),
            "",
        )
    };
    let attempts: Vec<(&str, Value)> = vec![
        (
            "AUTH with the wrong challenge",
            auth(&author, "wrong", now()),
        ),
        (
            "AUTH with a forged signature",
            forged(&auth(&author, &challenge, now()), "sig"),
        ),
        (
            "AUTH with the wrong challenge and a forged signature",
            forged(&auth(&author, "wrong", now()), "sig"),
        ),
        ("AUTH as the author", auth(&author, &challenge, now())),
    ];
    for (label, attempt) in attempts {
        out.step(label);
        let id = attempt["id"].clone();
        wire.send(json!(["AUTH", attempt])).await;
        let ok = wire
            .until(label, |frame| frame[0] == "OK" && frame[1] == id)
            .await;
        out.frames(&[ok]);
    }
    out.step("REQ only gift wraps, after AUTH");
    wire.send(json!(["REQ", "wraps-authed", {"kinds": [1059], "#p": [author_hex]}]))
        .await;
    out.frames(&until_sub(&mut wire, "wraps-authed", &["EOSE", "CLOSED"]).await);
    drop(wire);

    http_steps(&mut out, relay, cfg, &stranger).await;
    out.text
}

/// The HTTP requests of the script.
async fn http_steps(
    out: &mut Transcript,
    relay: &Relay,
    cfg: &Config,
    stranger: &secp256k1::Keypair,
) {
    let public_url = if cfg.admin.public_url.is_empty() {
        "https://relay.example.com".to_string()
    } else {
        cfg.admin.public_url.clone()
    };
    let rpc_body = r#"{"method":"supportedmethods","params":[]}"#;
    let nip98 = |method: &str, url: String, body: &str| {
        let payload = hex::encode(sha2::Sha256::digest(body.as_bytes()));
        event(
            stranger,
            now(),
            27235,
            json!([["u", url], ["method", method], ["payload", payload]]),
            "",
        )
    };
    let header = |event: &Value| {
        use base64::Engine;
        format!(
            "Authorization: Nostr {}\r\n",
            base64::engine::general_purpose::STANDARD.encode(event.to_string())
        )
    };
    let signed_rpc = nip98("POST", public_url.clone(), rpc_body);
    let signed_overview = nip98("GET", format!("{public_url}/admin/api/overview"), "");
    let requests: Vec<(&str, String, String, &str)> = vec![
        (
            "GET / for NIP-11",
            "GET".into(),
            "Accept: application/nostr+json\r\n".into(),
            "",
        ),
        (
            "GET / for the landing page",
            "GET".into(),
            String::new(),
            "",
        ),
        ("OPTIONS /", "OPTIONS".into(), String::new(), ""),
        ("GET /metrics", "GET /metrics".into(), String::new(), ""),
        ("GET /admin", "GET /admin".into(), String::new(), ""),
        (
            "GET /admin/api/overview unsigned",
            "GET /admin/api/overview".into(),
            String::new(),
            "",
        ),
        (
            "GET /admin/api/overview signed by a stranger",
            "GET /admin/api/overview".into(),
            header(&signed_overview),
            "",
        ),
        (
            "GET /admin/api/overview with a forged signature",
            "GET /admin/api/overview".into(),
            header(&forged(&signed_overview, "sig")),
            "",
        ),
        (
            "NIP-86 unsigned",
            "POST".into(),
            "Content-Type: application/nostr+json+rpc\r\n".into(),
            rpc_body,
        ),
        (
            "NIP-86 signed by a stranger",
            "POST".into(),
            format!(
                "Content-Type: application/nostr+json+rpc\r\n{}",
                header(&signed_rpc)
            ),
            rpc_body,
        ),
        (
            "NIP-86 with a forged signature",
            "POST".into(),
            format!(
                "Content-Type: application/nostr+json+rpc\r\n{}",
                header(&forged(&signed_rpc, "sig"))
            ),
            rpc_body,
        ),
    ];
    for (label, method_and_path, headers, body) in requests {
        out.step(&format!("HTTP {label}"));
        let (method, path) = method_and_path
            .split_once(' ')
            .unwrap_or((method_and_path.as_str(), "/"));
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let (status, head, body) = http(relay.addr, &request).await;
        out.http(status, &head, &body);
    }
    if let Some(metrics) = relay.metrics {
        out.step("HTTP GET /metrics on the metrics listener");
        let request = "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        let (status, head, _) = http(metrics, request).await;
        out.http(status, &head, "");
    }
}

/// Read frames until the reply that ends subscription `sub`, keeping them.
async fn until_sub(wire: &mut Wire, sub: &str, ends: &[&str]) -> Vec<Value> {
    let start = wire.seen.len();
    wire.until(sub, |frame| {
        frame[1] == sub && ends.iter().any(|end| frame[0] == *end)
    })
    .await;
    wire.seen[start..]
        .iter()
        .filter(|frame| frame[1] == sub || frame[0] == "NOTICE")
        .cloned()
        .collect()
}

/// The frames the relay sends before it answers a marker REQ sent now. The
/// ingester answers a message, if at all, before it reads the next one, so
/// those are the answer to `after`, the message just sent.
async fn marked(wire: &mut Wire, after: Option<&str>) -> Vec<Value> {
    let start = wire.seen.len();
    wire.send(json!(["REQ", "mark", {"ids": [UNKNOWN_ID]}]))
        .await;
    wire.until(after.unwrap_or("the marker"), |frame| {
        frame[1] == "mark" && (frame[0] == "EOSE" || frame[0] == "CLOSED")
    })
    .await;
    let answer: Vec<Value> = wire.seen[start..]
        .iter()
        .filter(|frame| frame[1] != "mark")
        .cloned()
        .collect();
    wire.send(json!(["CLOSE", "mark"])).await;
    answer
}

fn event(
    key: &secp256k1::Keypair,
    created_at: u64,
    kind: u64,
    tags: Value,
    content: &str,
) -> Value {
    wok_compat::sign_event_with_key(
        json!({"created_at": created_at, "kind": kind, "tags": tags, "content": content}),
        key,
    )
}

/// `event` with one field broken after signing: `sig` flips a signature
/// byte, `content` changes the content so the id no longer matches.
fn forged(event: &Value, field: &str) -> Value {
    let mut event = event.clone();
    match field {
        "sig" => {
            let sig = event["sig"].as_str().unwrap();
            let flipped = if sig.starts_with('0') { "1" } else { "0" };
            event["sig"] = json!(format!("{flipped}{}", &sig[1..]));
        }
        "content" => event["content"] = json!("changed"),
        other => panic!("no forgery for {other}"),
    }
    event
}

/// A transcript under construction, with the normalization that keeps it
/// the same from run to run: hex strings of 32 characters or more become
/// `<hN>` in order of first appearance, timestamps become offsets from the
/// script's base time, and registered literals become their placeholders.
struct Transcript {
    text: String,
    base: u64,
    hex: HashMap<String, usize>,
    literals: Vec<(String, String)>,
}

impl Transcript {
    fn new(base: u64) -> Self {
        Self {
            text: String::new(),
            base,
            hex: HashMap::new(),
            literals: Vec::new(),
        }
    }

    fn step(&mut self, label: &str) {
        writeln!(self.text, "\n## {label}").unwrap();
    }

    fn literal(&mut self, literal: &str, placeholder: &str) {
        self.literals
            .push((literal.to_string(), placeholder.to_string()));
    }

    fn frames(&mut self, frames: &[Value]) {
        if frames.is_empty() {
            writeln!(self.text, "(no reply)").unwrap();
        }
        for frame in frames {
            let mut frame = frame.clone();
            if frame[0] == "EVENT" {
                if let Some(created_at) = frame[2]["created_at"].as_u64() {
                    frame[2]["created_at"] =
                        json!(format!("<t{:+}>", created_at as i64 - self.base as i64));
                }
            }
            let line = self.normalize(&frame.to_string());
            writeln!(self.text, "< {line}").unwrap();
        }
    }

    fn http(&mut self, status: u16, head: &str, body: &str) {
        let content_type = head
            .lines()
            .find_map(|line| line.strip_prefix("content-type: "))
            .unwrap_or("none")
            .to_string();
        writeln!(self.text, "< {status} {content_type}").unwrap();
        if content_type.starts_with("text/html")
            || body.is_empty()
            || content_type.starts_with("text/plain; version=0.0.4")
        {
            return;
        }
        let body = match serde_json::from_str::<Value>(body) {
            Ok(mut json) => {
                if json.get("version").is_some() {
                    json["version"] = json!("<version>");
                }
                json.to_string()
            }
            Err(_) => body.trim().to_string(),
        };
        let line = self.normalize(&body);
        writeln!(self.text, "< {line}").unwrap();
    }

    fn normalize(&mut self, text: &str) -> String {
        let mut text = text.to_string();
        for (literal, placeholder) in &self.literals {
            text = text.replace(literal.as_str(), placeholder);
        }
        let mut out = String::with_capacity(text.len());
        let mut run = String::new();
        let flush = |run: &mut String, out: &mut String, hex: &mut HashMap<String, usize>| {
            if run.len() >= 32 {
                let next = hex.len() + 1;
                let n = *hex.entry(std::mem::take(run)).or_insert(next);
                write!(out, "<h{n}>").unwrap();
            } else {
                out.push_str(run);
                run.clear();
            }
        };
        for c in text.chars() {
            if c.is_ascii_hexdigit() && !c.is_ascii_uppercase() {
                run.push(c);
            } else {
                flush(&mut run, &mut out, &mut self.hex);
                out.push(c);
            }
        }
        flush(&mut run, &mut out, &mut self.hex);
        out
    }
}
