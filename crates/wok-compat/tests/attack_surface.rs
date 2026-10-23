//! The entry points the relay serves, in every configuration profile, must be
//! the ones `docs/attack-surface.md` lists. Candidates come from the
//! inventory and from the source, so a new route or verb fails here before
//! anyone documents it.

use futures_util::{SinkExt, StreamExt};
use secp256k1::{Keypair, SecretKey, SECP256K1};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;
use wok_db::{Env, EnvOptions};
use wok_relay::protocol::ParseFailure;
use wok_relay::{
    AccessPolicy, CapabilityCondition, ClientCommand, Config, Preset, RELAY_CAPABILITY_CATALOG,
};

const INVENTORY: &str = include_str!("../../../docs/attack-surface.md");

/// Methods tried on each path; one answer other than 404 makes it reachable.
const METHODS: &[&str] = &["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"];

/// Paths no route should answer, to catch a route that starts matching more
/// than its own path.
const DECOY_PATHS: &[&str] = &[
    "/x",
    "/admin/x",
    "/admin/apix",
    "/metrics/x",
    "/.well-known/x",
    "/nodeinfo",
];

#[test]
fn every_profile_loads_and_keeps_its_properties() {
    let names = profile_names();
    let documented: BTreeSet<String> = table("## Profiles")
        .iter()
        .flat_map(|row| ticked(&row[0]))
        .collect();
    assert_eq!(
        names.iter().cloned().collect::<BTreeSet<_>>(),
        documented,
        "tests/profiles/ and the Profiles table of docs/attack-surface.md differ"
    );
    for name in &names {
        let cfg = load_profile(name);
        // A deprecated key loads as its translation, which can change what
        // the profile stands for; spell the profile in today's keys.
        assert!(
            cfg.deprecations.is_empty(),
            "profile {name} sets deprecated keys: {:?}",
            cfg.deprecations
        );
        check_profile(name, &cfg);
    }
}

/// The properties `docs/attack-surface.md` gives each profile.
fn check_profile(name: &str, cfg: &Config) {
    let nips: BTreeSet<u64> = wok_relay::supported_nips(cfg).into_iter().collect();
    match name {
        "default" => {
            assert_eq!(
                cfg.to_toml().unwrap(),
                Config::default().to_toml().unwrap(),
                "the default profile must set nothing"
            );
            assert!(!cfg.auth_usable());
            assert!(!cfg.admin.enabled);
            assert!(!cfg.relay.unix.enabled);
        }
        "public" => {
            assert!(cfg.auth_usable());
            assert_eq!(cfg.relay.auth.read_policy, AccessPolicy::Open);
            assert_eq!(cfg.relay.auth.write_policy, AccessPolicy::Open);
            assert!(!cfg.admin.enabled);
            assert!(!cfg.relay.unix.enabled);
            assert!(
                nips.contains(&42) && nips.contains(&59) && nips.contains(&78),
                "{nips:?}"
            );
        }
        "gated" => {
            assert!(cfg.auth_usable());
            assert_eq!(cfg.relay.auth.read_policy, AccessPolicy::Members);
            assert_eq!(cfg.relay.auth.write_policy, AccessPolicy::Members);
            assert!(cfg.admin.enabled);
            assert!(nips.contains(&86), "{nips:?}");
            let mut secret = [0u8; 32];
            secret[31] = 1;
            let key =
                Keypair::from_secret_key(SECP256K1, &SecretKey::from_byte_array(&secret).unwrap());
            assert_eq!(
                cfg.admin.pubkeys,
                [hex::encode(key.x_only_public_key().0.serialize())],
                "the gated admin must be the key of secret 1"
            );
        }
        "marmot" => {
            assert_eq!(cfg.preset, Preset::Marmot);
            assert!(cfg.auth_usable());
            assert!(!cfg.relay.auth.accepted_kinds.is_empty());
            assert!(cfg.relay.filter_validation.require_scoped_filters);
            assert_eq!(cfg.relay.auth.write_policy, AccessPolicy::Open);
            assert!(!cfg.admin.enabled);
            assert!(nips.contains(&42) && nips.contains(&59), "{nips:?}");
        }
        "monitored" => {
            assert!(cfg.auth_usable());
            assert!(cfg.observability.metrics_enabled);
            assert!(!cfg.observability.metrics_listen.is_empty());
            assert!(!cfg.metrics_on_relay_listener());
        }
        "minimal" => {
            let always: BTreeSet<u64> = RELAY_CAPABILITY_CATALOG
                .iter()
                .filter(|capability| capability.enabled_when == CapabilityCondition::Always)
                .map(|capability| capability.nip)
                .collect();
            assert_eq!(
                nips, always,
                "the minimal profile must turn off every capability a setting can turn off"
            );
            assert!(!cfg.relay.compression_enabled);
            assert!(!cfg.observability.metrics_enabled);
        }
        "proxied" => {
            assert!(!cfg.relay.real_ip_header.is_empty());
            assert!(cfg.auth_usable());
        }
        "unix" => {
            assert!(cfg.relay.unix.enabled);
            assert!(!cfg.relay.unix.auth_uids.is_empty());
            assert_eq!(cfg.relay.unix.mode, 0o600);
        }
        other => panic!(
            "profile {other} has no checks; give it the properties docs/attack-surface.md lists"
        ),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_paths_match_the_inventory() {
    let relay_rows = http_rows("## Network listener");
    let metrics_rows = http_rows("## Metrics listener");
    let mut candidates: BTreeSet<String> =
        path_literals(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../wok-ws/src"));
    candidates.extend(DECOY_PATHS.iter().map(|path| path.to_string()));
    for row in relay_rows.iter().chain(&metrics_rows) {
        for path in &row.paths {
            candidates.insert(match path.strip_suffix('*') {
                Some(prefix) => format!("{prefix}x"),
                None => path.clone(),
            });
        }
    }

    let mut problems = Vec::new();
    for name in profile_names() {
        let cfg = load_profile(&name);
        let relay = Relay::start(cfg.clone()).await;
        let mut listeners = vec![("relay listener", relay.addr, &relay_rows)];
        if let Some(metrics) = relay.metrics {
            listeners.push(("metrics listener", metrics, &metrics_rows));
        }
        for (listener, addr, rows) in listeners {
            for path in &candidates {
                let row = rows.iter().find(|row| row.matches(path));
                let expected = row.is_some_and(|row| gate_open(&cfg, &row.gate));
                if reachable(addr, path).await != expected {
                    problems.push(match (row, expected) {
                        (None, _) => {
                            format!("{name}: the {listener} answers {path} but has no row")
                        }
                        (Some(row), true) => format!(
                            "{name}: {path} is unreachable on the {listener} while {} is open",
                            row.gate
                        ),
                        (Some(row), false) => format!(
                            "{name}: {path} is reachable on the {listener} while {} is closed",
                            row.gate
                        ),
                    });
                }
            }
        }
        for path in candidates.iter().filter(|path| *path != "/") {
            if status(relay.addr, &upgrade_request(path)).await != 404 {
                problems.push(format!("{name}: a WebSocket upgrade on {path} is served"));
            }
        }
        let rpc = status(relay.addr, &rpc_request()).await;
        if (rpc != 404) != cfg.admin.enabled {
            problems.push(format!(
                "{name}: NIP-86 answers {rpc} with admin.enabled = {}",
                cfg.admin.enabled
            ));
        }
        relay.stop().await;
    }
    assert!(
        problems.is_empty(),
        "the listeners and the listener tables of docs/attack-surface.md differ:\n{}",
        problems.join("\n")
    );
}

/// The rows of a listener table: their paths, and the gate as written.
fn http_rows(heading: &str) -> Vec<HttpRow> {
    table(heading)
        .iter()
        .map(|row| HttpRow {
            paths: ticked(&row[0]),
            gate: row[2].clone(),
        })
        .collect()
}

#[test]
fn client_verbs_match_the_inventory() {
    let documented: BTreeSet<String> = table("## Messages")
        .iter()
        .flat_map(|row| ticked(&row[0]))
        .collect();
    let mut candidates = upper_case_literals(include_str!("../../wok-relay/src/protocol.rs"));
    candidates.extend(documented.iter().cloned());
    let accepted: BTreeSet<String> = candidates
        .into_iter()
        .filter(|verb| accepts(verb))
        .collect();
    assert_eq!(
        accepted, documented,
        "ClientCommand::parse and the Messages table of docs/attack-surface.md differ"
    );
}

/// Whether some message naming `verb` parses to that verb's command.
fn accepts(verb: &str) -> bool {
    let messages = [
        format!(r#"["{verb}","s"]"#),
        format!(r#"["{verb}",{{}}]"#),
        format!(r#"["{verb}","s",{{}}]"#),
        format!(r#"["{verb}","s","00"]"#),
        format!(r#"["{verb}","s",{{}},"00"]"#),
    ];
    let mut recognized = false;
    for message in &messages {
        match ClientCommand::parse(message) {
            Ok(command) => {
                assert_eq!(
                    verb_of(&command),
                    Some(verb),
                    "{message} parsed as {command:?}"
                );
                return true;
            }
            Err(ParseFailure::BadMsg(reason)) if reason == "unknown cmd" => return false,
            Err(_) => recognized = true,
        }
    }
    assert!(
        !recognized,
        "{verb} is a verb, but no message shape here parses; add one"
    );
    false
}

/// The verb a parsed command came from. There is no wildcard, so a new
/// command does not compile until it is named here.
fn verb_of(command: &ClientCommand) -> Option<&'static str> {
    match command {
        ClientCommand::Newline => None,
        ClientCommand::Event(_) => Some("EVENT"),
        ClientCommand::Req { .. } => Some("REQ"),
        ClientCommand::Count { .. } => Some("COUNT"),
        ClientCommand::Close { .. } => Some("CLOSE"),
        ClientCommand::Auth(_) => Some("AUTH"),
        ClientCommand::NegOpen { .. } => Some("NEG-OPEN"),
        ClientCommand::NegMsg { .. } => Some("NEG-MSG"),
        ClientCommand::NegClose { .. } => Some("NEG-CLOSE"),
    }
}

/// Every Messages row with a gate, sent as a valid message over a WebSocket
/// to a relay of each profile: the gate's refusal must come back exactly
/// when the profile closes the gate, so a verb left reachable behind a
/// disabled feature fails here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_message_gates_match_the_inventory() {
    let gated: Vec<(String, String)> = table("## Messages")
        .iter()
        .filter(|row| row[2] != "none")
        .map(|row| (ticked(&row[0]).remove(0), row[2].clone()))
        .collect();
    let mut problems = Vec::new();
    for name in profile_names() {
        let cfg = load_profile(&name);
        let relay = Relay::start(cfg.clone()).await;
        let mut wire = Wire::connect(relay.addr).await;
        for (verb, gate) in &gated {
            let open = message_gate_open(&cfg, gate);
            let reply = wire.probe(verb, &cfg).await;
            let text = serde_json::to_string(&reply).unwrap();
            let refused = gate_refusals(verb)
                .iter()
                .any(|refusal| text.contains(refusal));
            if refused == open {
                problems.push(if open {
                    format!("{name}: {verb} is refused while {gate} is open: {text}")
                } else {
                    format!("{name}: {verb} is served while {gate} is closed: {text}")
                });
            } else if verb == "AUTH" && open && reply[0][2] != json!(true) {
                problems.push(format!("{name}: a valid AUTH is not accepted: {text}"));
            }
        }
        drop(wire);
        relay.stop().await;
    }
    assert!(
        problems.is_empty(),
        "the relay's message gates and the Messages table of docs/attack-surface.md differ:\n{}",
        problems.join("\n")
    );
}

/// Whether a profile opens the gate a Messages row names.
fn message_gate_open(cfg: &Config, gate: &str) -> bool {
    match gate {
        "`relay.auth.enabled` and `relay.auth.service_url`" => cfg.auth_usable(),
        "`relay.max_filter_limit_count` above 0" => cfg.relay.max_filter_limit_count > 0,
        "`relay.negentropy_enabled`" => cfg.relay.negentropy_enabled,
        other => panic!("teach message_gate_open the gate {other}"),
    }
}

/// The text of the refusal a gated verb gets while its gate is closed.
fn gate_refusals(verb: &str) -> &'static [&'static str] {
    match verb {
        "AUTH" => &["AUTH is disabled", "needs service_url"],
        "COUNT" => &["COUNT disabled"],
        "NEG-OPEN" | "NEG-MSG" => &["negentropy is disabled"],
        "NEG-CLOSE" => &["negentropy disabled"],
        other => panic!("{other} has a gate in the Messages table; give it a probe and a refusal"),
    }
}

/// An id no stored event has: a scoped filter that matches nothing.
const UNKNOWN_ID: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// A WebSocket client that keeps every frame it reads.
struct Wire {
    ws: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    seen: Vec<Value>,
}

impl Wire {
    async fn connect(addr: SocketAddr) -> Self {
        let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/"))
            .await
            .unwrap();
        Self {
            ws,
            seen: Vec::new(),
        }
    }

    async fn send(&mut self, message: Value) {
        self.ws
            .send(Message::Text(message.to_string().into()))
            .await
            .unwrap();
    }

    /// Read frames until one matches `answers`, keeping each.
    async fn until(&mut self, what: &str, answers: impl Fn(&Value) -> bool) -> Value {
        loop {
            let message = tokio::time::timeout(Duration::from_secs(5), self.ws.next())
                .await
                .unwrap_or_else(|_| panic!("no {what} within 5 s"))
                .expect("the relay closed the connection")
                .unwrap();
            let Ok(frame) = serde_json::from_str::<Value>(message.to_text().unwrap_or("")) else {
                continue;
            };
            self.seen.push(frame.clone());
            if answers(&frame) {
                return frame;
            }
        }
    }

    /// The NIP-42 challenge the relay sent on connect.
    async fn challenge(&mut self) -> String {
        let is_challenge = |frame: &Value| frame[0] == "AUTH";
        let frame = match self.seen.iter().find(|frame| is_challenge(frame)) {
            Some(frame) => frame.clone(),
            None => self.until("an AUTH challenge", is_challenge).await,
        };
        frame[1].as_str().unwrap().to_string()
    }

    /// Send a valid message for `verb` and return the frames that answer it.
    async fn probe(&mut self, verb: &str, cfg: &Config) -> Vec<Value> {
        match verb {
            "AUTH" => {
                let challenge = if cfg.auth_usable() {
                    self.challenge().await
                } else {
                    "none sent".to_string()
                };
                let created_at = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let event = wok_compat::sign_event(json!({
                    "created_at": created_at,
                    "kind": 22242,
                    "tags": [
                        ["relay", cfg.relay.auth.service_url],
                        ["challenge", challenge],
                    ],
                    "content": "",
                }));
                let id = event["id"].clone();
                self.send(json!(["AUTH", event])).await;
                vec![
                    self.until("an OK for AUTH", |frame| frame[0] == "OK" && frame[1] == id)
                        .await,
                ]
            }
            "COUNT" => {
                self.send(json!(["COUNT", "gate-count", {"ids": [UNKNOWN_ID]}]))
                    .await;
                vec![
                    self.until("a COUNT reply", |frame| frame[1] == "gate-count")
                        .await,
                ]
            }
            "NEG-OPEN" => {
                let open = json!(["NEG-OPEN", "gate-open", {"ids": [UNKNOWN_ID]}, neg_initial()]);
                self.send(open).await;
                vec![
                    self.until("a NEG-OPEN reply", |frame| frame[1] == "gate-open")
                        .await,
                ]
            }
            "NEG-MSG" => {
                self.send(json!(["NEG-MSG", "gate-msg", neg_initial()]))
                    .await;
                vec![
                    self.until("a NEG-MSG reply", |frame| frame[1] == "gate-msg")
                        .await,
                ]
            }
            "NEG-CLOSE" => {
                // A valid NEG-CLOSE gets no reply. The ingester sends the
                // refusal, if any, before it reads the next message, so the
                // answer to a REQ sent after it marks the end.
                let start = self.seen.len();
                self.send(json!(["NEG-CLOSE", "gate-close"])).await;
                self.send(json!(["REQ", "gate-mark", {"ids": [UNKNOWN_ID]}]))
                    .await;
                self.until("a REQ reply", |frame| frame[1] == "gate-mark")
                    .await;
                self.seen[start..]
                    .iter()
                    .filter(|frame| frame[0] == "NOTICE")
                    .cloned()
                    .collect()
            }
            other => panic!("no probe for {other}"),
        }
    }
}

/// A client's first message of a NIP-77 sync, over an empty set.
fn neg_initial() -> String {
    let mut store = wok_negentropy::Vector::new();
    store.seal().unwrap();
    let mut client = wok_negentropy::Negentropy::new(store, 60_000).unwrap();
    hex::encode(client.initiate().unwrap())
}

struct HttpRow {
    paths: Vec<String>,
    gate: String,
}

impl HttpRow {
    /// A path ending in `*` stands for every path under its prefix.
    fn matches(&self, path: &str) -> bool {
        self.paths
            .iter()
            .any(|row_path| match row_path.strip_suffix('*') {
                Some(prefix) => path.starts_with(prefix),
                None => path == row_path,
            })
    }
}

fn gate_open(cfg: &Config, gate: &str) -> bool {
    match gate {
        "none" => true,
        "`admin.enabled`" => cfg.admin.enabled,
        "`observability.metrics_enabled` and no `observability.metrics_listen`" => {
            cfg.metrics_on_relay_listener()
        }
        "`observability.metrics_enabled`" => cfg.observability.metrics_enabled,
        other => panic!("teach gate_open the gate {other}"),
    }
}

/// A relay serving one profile on a loopback port.
struct Relay {
    addr: SocketAddr,
    /// The metrics listener, when the profile sets one.
    metrics: Option<SocketAddr>,
    handle: wok_relay::RelayHandle,
    _dir: tempfile::TempDir,
}

impl Relay {
    async fn start(mut cfg: Config) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(
            dir.path(),
            EnvOptions {
                map_size: 64 * 1024 * 1024,
                ..EnvOptions::default()
            },
        )
        .unwrap();
        env.ensure_initialized().unwrap();
        cfg.db = dir.path().to_path_buf();
        cfg.relay.port = 0;
        cfg.relay.unix.path = dir.path().join("wok.sock");
        // Every probe comes from one address; the connection budget would
        // answer 429 long before the probe has tried every path.
        cfg.relay.abuse.connection_rate_per_second = 0;
        let wants_metrics_listener = !cfg.observability.metrics_listen.is_empty();
        let handle = wok_relay::start(env, cfg).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let serving = handle.clone();
        tokio::spawn(async move {
            let _ = wok_ws::serve_listener(serving, listener).await;
        });
        let mut metrics = None;
        if wants_metrics_listener {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            metrics = Some(listener.local_addr().unwrap());
            tokio::spawn(wok_ws::serve_metrics(handle.clone(), listener));
        }
        Self {
            addr,
            metrics,
            handle,
            _dir: dir,
        }
    }

    async fn stop(self) {
        let handle = self.handle;
        tokio::task::spawn_blocking(move || handle.shutdown_and_join(Duration::from_secs(10)))
            .await
            .unwrap()
            .unwrap();
    }
}

/// Whether some method gets an answer other than 404 for `path` at `addr`.
async fn reachable(addr: SocketAddr, path: &str) -> bool {
    for method in METHODS {
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        if status(addr, &request).await != 404 {
            return true;
        }
    }
    false
}

/// The status code of the response to `request` sent to `addr`.
async fn status(addr: SocketAddr, request: &str) -> u16 {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut head = Vec::new();
    let mut buf = [0u8; 512];
    while !head.windows(2).any(|pair| pair == b"\r\n") {
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await
            .expect("no response within 5 s")
            .unwrap();
        assert!(
            read > 0,
            "connection closed before a status line: {request:?}"
        );
        head.extend_from_slice(&buf[..read]);
    }
    let head = String::from_utf8_lossy(&head);
    head.split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no status in {head:?}"))
}

fn upgrade_request(path: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
}

fn rpc_request() -> String {
    "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/nostr+json+rpc\r\n\
     Content-Length: 0\r\nConnection: close\r\n\r\n"
        .to_string()
}

fn profiles_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/profiles")
}

fn profile_names() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(profiles_dir())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
        .map(|path| path.file_stem().unwrap().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn load_profile(name: &str) -> Config {
    let path = profiles_dir().join(format!("{name}.toml"));
    Config::load(&path).unwrap_or_else(|error| panic!("profile {name}: {error}"))
}

/// The cells of each row of the first table under `heading`.
fn table(heading: &str) -> Vec<Vec<String>> {
    let section = INVENTORY
        .split_once(&format!("\n{heading}\n"))
        .unwrap_or_else(|| panic!("docs/attack-surface.md has no {heading:?}"))
        .1;
    section
        .lines()
        .take_while(|line| !line.starts_with('#'))
        .skip_while(|line| !line.starts_with('|'))
        .take_while(|line| line.starts_with('|'))
        .skip(2)
        .map(|line| {
            line.trim_matches('|')
                .split(" | ")
                .map(|cell| cell.trim().to_string())
                .collect()
        })
        .collect()
}

/// The backticked spans in a table cell.
fn ticked(cell: &str) -> Vec<String> {
    cell.split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect()
}

/// Every string literal in the Rust files under `dir`, submodules included,
/// that looks like a URL path.
fn path_literals(dir: &Path) -> BTreeSet<String> {
    let mut paths = BTreeSet::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let file = entry.unwrap().path();
        if file.is_dir() {
            paths.extend(path_literals(&file));
            continue;
        }
        if file.extension().is_none_or(|ext| ext != "rs") {
            continue;
        }
        let source = std::fs::read_to_string(&file).unwrap();
        for literal in literals(&source) {
            if literal.starts_with('/')
                && literal.len() <= 64
                && literal
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "/._-".contains(c))
            {
                paths.insert(literal.to_string());
            }
        }
    }
    paths
}

fn upper_case_literals(source: &str) -> BTreeSet<String> {
    literals(source)
        .filter(|literal| {
            literal.starts_with(|c: char| c.is_ascii_uppercase())
                && literal.chars().all(|c| c.is_ascii_uppercase() || c == '-')
        })
        .map(str::to_string)
        .collect()
}

/// The text between each double quote and the next. Some of it lies between
/// two literals; the callers' filters reject it.
fn literals(source: &str) -> impl Iterator<Item = &str> {
    source.match_indices('"').filter_map(move |(start, _)| {
        let rest = &source[start + 1..];
        rest.find('"').map(|end| &rest[..end])
    })
}
