//! Shared by the attack-surface tests: the configuration profiles in
//! `tests/profiles/`, a relay that serves one, and raw HTTP and WebSocket
//! clients that report exactly what the relay answers.
#![allow(dead_code)]

use futures_util::{SinkExt, StreamExt};
use secp256k1::{Keypair, SecretKey, SECP256K1};
use serde_json::Value;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;
use wok_db::{Env, EnvOptions};
use wok_relay::Config;

/// An id no stored event has: a scoped filter that matches nothing.
pub const UNKNOWN_ID: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Methods tried on each path; one answer other than 404 makes it reachable.
pub const METHODS: &[&str] = &["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"];

pub fn profiles_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/profiles")
}

pub fn profile_names() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(profiles_dir())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
        .map(|path| path.file_stem().unwrap().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

pub fn load_profile(name: &str) -> Config {
    let path = profiles_dir().join(format!("{name}.toml"));
    Config::load(&path).unwrap_or_else(|error| panic!("profile {name}: {error}"))
}

/// The key of secret `n`. Secret 1 is the `gated` profile's admin.
pub fn key(n: u8) -> Keypair {
    let mut secret = [0u8; 32];
    secret[31] = n;
    Keypair::from_secret_key(SECP256K1, &SecretKey::from_byte_array(&secret).unwrap())
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A relay serving one profile on a loopback port.
pub struct Relay {
    pub addr: SocketAddr,
    /// The metrics listener, when the profile sets one.
    pub metrics: Option<SocketAddr>,
    pub handle: wok_relay::RelayHandle,
    _dir: tempfile::TempDir,
}

impl Relay {
    pub async fn start(cfg: Config) -> Self {
        Self::try_start(cfg).await.unwrap()
    }

    /// Start a relay, or return why Wok refuses to serve `cfg`.
    pub async fn try_start(mut cfg: Config) -> Result<Self, String> {
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
        let handle = wok_relay::start(env, cfg)?;
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
        Ok(Self {
            addr,
            metrics,
            handle,
            _dir: dir,
        })
    }

    pub async fn stop(self) {
        let handle = self.handle;
        tokio::task::spawn_blocking(move || handle.shutdown_and_join(Duration::from_secs(10)))
            .await
            .unwrap()
            .unwrap();
    }
}

/// Whether some method gets an answer other than 404 for `path` at `addr`.
pub async fn reachable(addr: SocketAddr, path: &str) -> bool {
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
pub async fn status(addr: SocketAddr, request: &str) -> u16 {
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

/// The status, the lower-cased headers and the body of the response to
/// `request`, which must ask the relay to close the connection.
pub async fn http(addr: SocketAddr, request: &str) -> (u16, String, String) {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .expect("no complete response within 5 s")
        .unwrap();
    let response = String::from_utf8_lossy(&response).into_owned();
    let (head, body) = response.split_once("\r\n\r\n").unwrap_or((&response, ""));
    let code = head.split(' ').nth(1).and_then(|code| code.parse().ok());
    (
        code.unwrap_or_else(|| panic!("no status in {head:?}")),
        head.to_ascii_lowercase(),
        body.to_string(),
    )
}

/// A WebSocket client that keeps every frame it reads.
pub struct Wire {
    ws: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    pub seen: Vec<Value>,
}

impl Wire {
    pub async fn connect(addr: SocketAddr) -> Self {
        let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/"))
            .await
            .unwrap();
        Self {
            ws,
            seen: Vec::new(),
        }
    }

    pub async fn send(&mut self, message: Value) {
        self.send_text(message.to_string()).await;
    }

    /// Send text that need not be JSON.
    pub async fn send_text(&mut self, text: String) {
        self.ws.send(Message::Text(text.into())).await.unwrap();
    }

    /// Read frames until one matches `answers`, keeping each.
    pub async fn until(&mut self, what: &str, answers: impl Fn(&Value) -> bool) -> Value {
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

    /// Send a close frame and read until the relay closes the connection, so
    /// it sees the close rather than a reset over frames left unread.
    pub async fn close(mut self) {
        self.ws.close(None).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(Ok(_)) = self.ws.next().await {}
        })
        .await
        .expect("the relay closes a connection whose client closed");
    }

    /// The NIP-42 challenge the relay sent on connect.
    pub async fn challenge(&mut self) -> String {
        let is_challenge = |frame: &Value| frame[0] == "AUTH";
        let frame = match self.seen.iter().find(|frame| is_challenge(frame)) {
            Some(frame) => frame.clone(),
            None => self.until("an AUTH challenge", is_challenge).await,
        };
        frame[1].as_str().unwrap().to_string()
    }
}

/// A client's first message of a NIP-77 sync, over an empty set.
pub fn neg_initial() -> String {
    let mut store = wok_negentropy::Vector::new();
    store.seal().unwrap();
    let mut client = wok_negentropy::Negentropy::new(store, 60_000).unwrap();
    hex::encode(client.initiate().unwrap())
}
