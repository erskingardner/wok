//! What each rate budget is keyed on (tracking issue #97 §3.3): per-address
//! budgets group an IPv6 client by its network, not its full address.

use serde_json::{json, Value};
use std::time::{Duration, Instant};
use wok_relay::{Config, ConnectionGuard, Outbound, OutboundFrame, RelayHandle, TransportSource};

type Rx = tokio::sync::mpsc::UnboundedReceiver<OutboundFrame>;

fn start(tweak: impl FnOnce(&mut Config)) -> (tempfile::TempDir, RelayHandle) {
    let (dir, env) = wok_compat::temp_db();
    let mut cfg = Config {
        db: dir.path().to_path_buf(),
        ..Default::default()
    };
    tweak(&mut cfg);
    (dir, wok_relay::start(env, cfg).unwrap())
}

fn source(ip: &str) -> TransportSource {
    TransportSource::ip_address(ip.parse().unwrap())
}

async fn connect(handle: &RelayHandle, ip: &str) -> (ConnectionGuard, Rx) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let conn = handle
        .register_connection(source(ip), Outbound::new(tx, 0))
        .await;
    (conn, rx)
}

/// Send a REQ and return the frame that ends its history: `EOSE`, or the
/// `CLOSED` that refused it.
async fn req(conn: &ConnectionGuard, rx: &mut Rx, sub_id: &str) -> Value {
    conn.client_message(json!(["REQ", sub_id, {"kinds": [1], "limit": 1}]).to_string())
        .await;
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("a reply to the REQ")
            .unwrap();
        let msg: Value = serde_json::from_str(&frame.into_text()).unwrap();
        if matches!(msg[0].as_str(), Some("EOSE" | "CLOSED")) && msg[1] == sub_id {
            return msg;
        }
    }
}

/// REQs `conn` gets answered with EOSE before the first refusal, which
/// must be the per-address budget's.
async fn reqs_until_refused(conn: &ConnectionGuard, rx: &mut Rx, max: usize) -> usize {
    for i in 0..max {
        let reply = req(conn, rx, &format!("s{i}")).await;
        if reply[0] == "CLOSED" {
            assert_eq!(reply[2], "rate-limited: REQ budget exhausted", "{reply}");
            return i;
        }
    }
    max
}

/// `got` REQs were admitted from a bucket that held `expected` at `since`
/// and refills one token a second, so a slow run may have earned a few more.
fn assert_admitted(got: usize, expected: usize, since: Instant, what: &str) {
    let refilled = since.elapsed().as_secs() as usize;
    assert!(
        (expected..=expected + refilled).contains(&got),
        "{what}: {got} admitted, expected {expected} (+{refilled} refilled)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ipv6_network_shares_one_per_address_budget() {
    let (_dir, handle) = start(|cfg| {
        // One token a second: the bucket does not refill during the test.
        cfg.relay.abuse.req_rate_per_second = 1;
        cfg.relay.abuse.req_burst = 4;
        cfg.relay.abuse.connection_rate_per_second = 1;
        cfg.relay.abuse.connection_burst = 1;
    });
    // Two addresses in one /64, as one host or home network would use.
    let (a, mut a_rx) = connect(&handle, "2001:db8:1:2::a").await;
    let (b, mut b_rx) = connect(&handle, "2001:db8:1:2:ffff::b").await;
    let started = Instant::now();
    for i in 0..2 {
        assert_eq!(req(&a, &mut a_rx, &format!("a{i}")).await[0], "EOSE");
    }
    // The neighbour gets what is left of the network's budget, not its own.
    let got = reqs_until_refused(&b, &mut b_rx, 10).await;
    assert_admitted(got, 2, started, "same /64");
    // The next /64 has a budget of its own.
    let (c, mut c_rx) = connect(&handle, "2001:db8:1:3::a").await;
    let started = Instant::now();
    let got = reqs_until_refused(&c, &mut c_rx, 10).await;
    assert_admitted(got, 4, started, "next /64");

    // The connection budget is keyed the same way.
    assert!(handle.admit_connection(&source("2001:db8:9:9::1")));
    assert!(!handle.admit_connection(&source("2001:db8:9:9::2")));
    assert!(handle.admit_connection(&source("2001:db8:9:a::1")));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_ipv6_prefix_keys_each_address_on_its_own() {
    let (_dir, handle) = start(|cfg| {
        cfg.relay.abuse.ipv6_prefix_len = 128;
        cfg.relay.abuse.req_rate_per_second = 1;
        cfg.relay.abuse.req_burst = 2;
    });
    for ip in [
        "2001:db8:1:2::a",
        "2001:db8:1:2::b",
        "192.0.2.1",
        "192.0.2.2",
    ] {
        let (conn, mut rx) = connect(&handle, ip).await;
        let started = Instant::now();
        let got = reqs_until_refused(&conn, &mut rx, 10).await;
        assert_admitted(got, 2, started, ip);
    }
}
