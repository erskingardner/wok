//! What each rate budget is keyed on (tracking issue #97 §3.3): a
//! connection has REQ, NEG-MSG and COUNT budgets of its own, larger once it
//! has authenticated, under a backstop its address shares; and per-address
//! budgets group an IPv6 client by its network, not its full address.

use secp256k1::{Keypair, SECP256K1};
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use wok_relay::{Config, ConnectionGuard, Outbound, OutboundFrame, RelayHandle, TransportSource};

const AUTH_RELAY: &str = "wss://rates.test";
const OWN_REQ_REFUSAL: &str = "rate-limited: REQ budget exhausted";
const ADDRESS_REQ_REFUSAL: &str = "rate-limited: REQ budget exhausted for this address";

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

struct Client {
    conn: ConnectionGuard,
    rx: tokio::sync::mpsc::UnboundedReceiver<OutboundFrame>,
    /// The NIP-42 challenge, once the relay has sent it.
    challenge: Option<String>,
}

impl Client {
    async fn connect(handle: &RelayHandle, ip: &str) -> Self {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let conn = handle
            .register_connection(source(ip), Outbound::new(tx, 0))
            .await;
        Self {
            conn,
            rx,
            challenge: None,
        }
    }

    async fn send(&self, msg: Value) {
        self.conn.client_message(msg.to_string()).await;
    }

    async fn recv(&mut self) -> Value {
        let frame = tokio::time::timeout(Duration::from_secs(5), self.rx.recv())
            .await
            .expect("a frame from the relay")
            .unwrap();
        let msg: Value = serde_json::from_str(&frame.into_text()).unwrap();
        if msg[0] == "AUTH" {
            self.challenge = msg[1].as_str().map(str::to_string);
        }
        msg
    }

    /// The next frame for `sub_id` that is one of `types`.
    async fn reply(&mut self, sub_id: &str, types: &[&str]) -> Value {
        loop {
            let msg = self.recv().await;
            if msg[1] == sub_id && types.iter().any(|t| msg[0] == *t) {
                return msg;
            }
        }
    }

    /// Send a REQ and return the frame that ends its history: `EOSE`, or
    /// the `CLOSED` that refused it.
    async fn req(&mut self, sub_id: &str) -> Value {
        self.send(json!(["REQ", sub_id, {"kinds": [1], "limit": 1}]))
            .await;
        self.reply(sub_id, &["EOSE", "CLOSED"]).await
    }

    /// Send REQs until one is refused, at most `max`: how many were
    /// admitted, and the refusal's reason.
    async fn reqs_until_refused(&mut self, max: usize) -> (usize, String) {
        for i in 0..max {
            let reply = self.req(&format!("s{i}")).await;
            if reply[0] == "CLOSED" {
                return (i, reply[2].as_str().unwrap().to_string());
            }
        }
        (max, String::new())
    }

    async fn auth(&mut self, key: &Keypair) {
        while self.challenge.is_none() {
            self.recv().await;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let event = wok_compat::sign_event_with_key(
            json!({
                "created_at": now,
                "kind": 22242,
                "tags": [["relay", AUTH_RELAY], ["challenge", self.challenge]],
                "content": "",
            }),
            key,
        );
        let id = event["id"].as_str().unwrap().to_string();
        self.send(json!(["AUTH", event])).await;
        let ok = self.reply(&id, &["OK"]).await;
        assert_eq!(ok[2], true, "{ok}");
    }
}

/// `got` requests were admitted from a bucket that held `expected` at
/// `since` and refills `rate` tokens a second, so a slow run may have
/// earned a few more.
fn assert_admitted(got: usize, expected: usize, since: Instant, rate: u32, what: &str) {
    let refilled = (since.elapsed().as_secs_f64() * f64::from(rate)) as usize;
    assert!(
        (expected..=expected + refilled).contains(&got),
        "{what}: {got} admitted, expected {expected} (+{refilled} refilled)"
    );
}

fn neg_initial() -> String {
    let mut store = wok_negentropy::Vector::new();
    store.seal().unwrap();
    let mut client = wok_negentropy::Negentropy::new(store, 60_000).unwrap();
    hex::encode(client.initiate().unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_startup_of_60_reqs_is_not_refused() {
    // C3: a 60-REQ startup lost 20 to the per-IP budget of 20 a second,
    // burst 40. With the defaults, one connection's own burst is 100.
    let (_dir, handle) = start(|_| {});
    let mut client = Client::connect(&handle, "192.0.2.1").await;
    for i in 0..60 {
        client
            .send(json!(["REQ", format!("s{i}"), {"kinds": [1], "limit": 10}]))
            .await;
    }
    let mut eose = 0;
    while eose < 60 {
        let msg = client.recv().await;
        assert_ne!(msg[0], "CLOSED", "{msg}");
        if msg[0] == "EOSE" {
            eose += 1;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connections_from_one_address_have_their_own_budgets_under_its_backstop() {
    let (_dir, handle) = start(|cfg| {
        // One token a second: the buckets barely refill during the test.
        let own = &mut cfg.relay.abuse.per_connection;
        own.req_rate_per_second = 1;
        own.req_burst = 100;
        cfg.relay.abuse.req_rate_per_second = 1;
        cfg.relay.abuse.req_burst = 150;
    });
    let started = Instant::now();
    let mut first = Client::connect(&handle, "192.0.2.1").await;
    let (got, reason) = first.reqs_until_refused(200).await;
    assert_admitted(got, 100, started, 1, "first connection");
    assert_eq!(reason, OWN_REQ_REFUSAL);
    // A second connection from the same address has a budget of its own,
    // until the address's backstop runs out. The first connection's refused
    // REQ did not spend any of it.
    let mut second = Client::connect(&handle, "192.0.2.1").await;
    let (got, reason) = second.reqs_until_refused(200).await;
    assert_admitted(got, 50, started, 1, "second connection");
    assert_eq!(reason, ADDRESS_REQ_REFUSAL);
    // Another address is untouched.
    let started = Instant::now();
    let mut other = Client::connect(&handle, "198.51.100.1").await;
    let (got, reason) = other.reqs_until_refused(200).await;
    assert_admitted(got, 100, started, 1, "another address");
    assert_eq!(reason, OWN_REQ_REFUSAL);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_authenticated_connection_gets_four_times_its_budget() {
    let (_dir, handle) = start(|cfg| {
        cfg.relay.auth.service_url = AUTH_RELAY.into();
        let own = &mut cfg.relay.abuse.per_connection;
        own.req_rate_per_second = 1;
        own.req_burst = 5;
        assert_eq!(own.authenticated_multiplier, 4);
    });
    let started = Instant::now();
    let mut anonymous = Client::connect(&handle, "192.0.2.1").await;
    let (got, reason) = anonymous.reqs_until_refused(50).await;
    assert_admitted(got, 5, started, 1, "anonymous");
    assert_eq!(reason, OWN_REQ_REFUSAL);
    // F1: AUTH used to add a per-pubkey bucket with the address's rate, so
    // it made the budget stricter, and two connections with one key shared
    // it. Now each AUTHed connection gets four times its own budget.
    let key = Keypair::new(SECP256K1, &mut rand::thread_rng());
    for ip in ["192.0.2.2", "198.51.100.2"] {
        let started = Instant::now();
        let mut client = Client::connect(&handle, ip).await;
        for i in 0..2 {
            assert_eq!(client.req(&format!("before{i}")).await[0], "EOSE");
        }
        client.auth(&key).await;
        // The larger burst applies at once: 4 × 5, less the 2 spent.
        let (got, reason) = client.reqs_until_refused(50).await;
        assert_admitted(got, 18, started, 4, ip);
        assert_eq!(reason, OWN_REQ_REFUSAL);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_nip77_pass_per_group_does_not_spend_the_req_budget() {
    // A Marmot client syncs each group with NIP-77 and then subscribes to
    // it. NEG-MSG rounds used to cost REQ tokens, so the subscriptions were
    // refused. With the defaults, 45 groups cost 90 of the connection's 100
    // REQ tokens (a NEG-OPEN and a REQ each) and 90 of its 200 NEG-MSG
    // tokens.
    let (_dir, handle) = start(|_| {});
    let mut client = Client::connect(&handle, "192.0.2.1").await;
    let init = neg_initial();
    for group in 0..45 {
        let filter = json!({"kinds": [445], "#h": [format!("{group:064x}")]});
        let sync = format!("sync{group}");
        client.send(json!(["NEG-OPEN", sync, filter, init])).await;
        let reply = client.reply(&sync, &["NEG-MSG", "NEG-ERR"]).await;
        assert_eq!(reply[0], "NEG-MSG", "{reply}");
        for _ in 0..2 {
            client.send(json!(["NEG-MSG", sync, init])).await;
            let reply = client.reply(&sync, &["NEG-MSG", "NEG-ERR"]).await;
            assert_eq!(reply[0], "NEG-MSG", "{reply}");
        }
        client.send(json!(["NEG-CLOSE", sync])).await;
        let live = format!("group{group}");
        client.send(json!(["REQ", live, filter])).await;
        let reply = client.reply(&live, &["EOSE", "CLOSED"]).await;
        assert_eq!(reply[0], "EOSE", "{reply}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ipv6_network_shares_one_per_address_budget() {
    let (_dir, handle) = start(|cfg| {
        cfg.relay.abuse.req_rate_per_second = 1;
        cfg.relay.abuse.req_burst = 4;
        cfg.relay.abuse.connection_rate_per_second = 1;
        cfg.relay.abuse.connection_burst = 1;
    });
    // Two addresses in one /64, as one host or home network would use.
    let started = Instant::now();
    let mut a = Client::connect(&handle, "2001:db8:1:2::a").await;
    let mut b = Client::connect(&handle, "2001:db8:1:2:ffff::b").await;
    for i in 0..2 {
        assert_eq!(a.req(&format!("a{i}")).await[0], "EOSE");
    }
    // The neighbour gets what is left of the network's backstop.
    let (got, reason) = b.reqs_until_refused(10).await;
    assert_admitted(got, 2, started, 1, "same /64");
    assert_eq!(reason, ADDRESS_REQ_REFUSAL);
    // The next /64 has a backstop of its own.
    let started = Instant::now();
    let mut c = Client::connect(&handle, "2001:db8:1:3::a").await;
    let (got, reason) = c.reqs_until_refused(10).await;
    assert_admitted(got, 4, started, 1, "next /64");
    assert_eq!(reason, ADDRESS_REQ_REFUSAL);

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
        let started = Instant::now();
        let mut client = Client::connect(&handle, ip).await;
        let (got, reason) = client.reqs_until_refused(10).await;
        assert_admitted(got, 2, started, 1, ip);
        assert_eq!(reason, ADDRESS_REQ_REFUSAL, "{ip}");
    }
}
