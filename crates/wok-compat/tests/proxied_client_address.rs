//! Behind a reverse proxy a client is the address in `relay.real_ip_header`.
//! A list header such as X-Forwarded-For also carries whatever the client
//! sent: only the address the proxy in front of Wok added, the last one, is
//! the client's. A client that sends the header itself must still be refused
//! when its own address is blocked with NIP-86 `blockip`. A last entry that is
//! not an address leaves the connecting address, and is counted. The cap on
//! the connections an address holds open counts the client's address too.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wok_relay::{Config, ManagementCmd, RelayHandle};

/// The client's own address, blocked.
const BLOCKED: &str = "203.0.113.7";
/// The address the client claims in an X-Forwarded-For of its own.
const CLAIMED: &str = "198.51.100.9";

/// A relay that trusts X-Forwarded-For, with [`BLOCKED`] blocked.
async fn start() -> (tempfile::TempDir, RelayHandle, SocketAddr) {
    let (dir, env) = wok_compat::temp_db();
    let mut cfg = Config {
        db: dir.path().to_path_buf(),
        ..Default::default()
    };
    cfg.relay.real_ip_header = "x-forwarded-for".into();
    let handle = wok_relay::start(env, cfg).unwrap();
    // The command NIP-86 `blockip` submits.
    handle
        .manage(ManagementCmd::BlockIp {
            ip: BLOCKED.into(),
            reason: "abuse".into(),
        })
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serving = handle.clone();
    tokio::spawn(async move {
        let _ = wok_ws::serve_listener(serving, listener).await;
    });
    (dir, handle, addr)
}

/// The status of a WebSocket upgrade that arrives from the proxy with one
/// X-Forwarded-For line per entry of `forwarded`.
async fn upgrade_status(addr: SocketAddr, forwarded: &[&str]) -> u16 {
    upgrade(addr, forwarded).await.0
}

/// [`upgrade_status`], with the connection, still open.
async fn upgrade(addr: SocketAddr, forwarded: &[&str]) -> (u16, tokio::net::TcpStream) {
    let lines: String = forwarded
        .iter()
        .map(|value| format!("X-Forwarded-For: {value}\r\n"))
        .collect();
    let request = format!(
        "GET / HTTP/1.1\r\nHost: localhost\r\n{lines}Upgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut head = Vec::new();
    let mut buf = [0u8; 512];
    while !head.windows(2).any(|pair| pair == b"\r\n") {
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await
            .expect("no response within 5 s")
            .unwrap();
        assert!(read > 0, "connection closed before a status line");
        head.extend_from_slice(&buf[..read]);
    }
    let head = String::from_utf8_lossy(&head);
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no status in {head:?}"));
    (status, stream)
}

/// A proxy that replaces the header, such as nginx with
/// `proxy_set_header X-Forwarded-For $remote_addr`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blocked_client_is_refused_when_the_proxy_replaces_the_header() {
    let (_dir, _handle, addr) = start().await;
    assert_eq!(upgrade_status(addr, &[BLOCKED]).await, 429);
}

/// A proxy that appends the client's address to the client's own header,
/// such as nginx with `$proxy_add_x_forwarded_for`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blocked_client_is_refused_when_the_proxy_appends_to_its_header() {
    let (_dir, _handle, addr) = start().await;
    let appended = format!("{CLAIMED}, {BLOCKED}");
    assert_eq!(
        upgrade_status(addr, &[&appended]).await,
        429,
        "a blocked client that sends X-Forwarded-For: {CLAIMED} reaches the relay as \
         \"{appended}\" and must still be refused"
    );
}

/// A proxy that adds its own header line after the client's, such as
/// HAProxy with `option forwardfor`. The two lines are one list.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blocked_client_is_refused_when_the_proxy_adds_a_header_line() {
    let (_dir, _handle, addr) = start().await;
    assert_eq!(
        upgrade_status(addr, &[CLAIMED, BLOCKED]).await,
        429,
        "a blocked client that sends X-Forwarded-For: {CLAIMED} ahead of the proxy's line \
         must still be refused"
    );
}

/// A proxy that writes RFC 7239 `Forwarded` syntax into X-Forwarded-For.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unparsed_last_entry_leaves_the_connecting_address_and_is_counted() {
    let (_dir, handle, addr) = start().await;
    // The connecting address, 127.0.0.1, is not blocked.
    assert_eq!(
        upgrade_status(addr, &[&format!("for={BLOCKED}")]).await,
        101
    );
    let metrics = handle.metrics.render();
    assert!(
        metrics.contains("\nwok_real_ip_header_unparsed_total 1\n"),
        "{metrics}"
    );
}

/// Connections from behind the proxy count against the client's address,
/// not the proxy's, and one that ends gives its place back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn open_connections_are_capped_per_client_address() {
    let (_dir, handle, addr) = start().await;
    handle
        .config
        .write()
        .relay
        .abuse
        .max_connections_per_address = 2;
    let (first, held) = upgrade(addr, &[CLAIMED]).await;
    let (second, _also_held) = upgrade(addr, &[CLAIMED]).await;
    assert_eq!((first, second), (101, 101));
    assert_eq!(upgrade_status(addr, &[CLAIMED]).await, 429);
    let metrics = handle.metrics.render();
    let refused = "\nwok_refusals_total{setting=\"relay.abuse.max_connections_per_address\"} 1\n";
    assert!(metrics.contains(refused), "{metrics}");
    // Another client of the same proxy has a cap of its own.
    let (other, _other_held) = upgrade(addr, &["198.51.100.10"]).await;
    assert_eq!(other, 101);
    drop(held);
    let reopened = async {
        loop {
            let (status, stream) = upgrade(addr, &[CLAIMED]).await;
            if status == 101 {
                return stream;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    let _reopened = tokio::time::timeout(Duration::from_secs(5), reopened)
        .await
        .expect("a closed connection gives its place back");
}
