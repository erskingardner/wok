//! Pins the machine-readable prefixes on refusals that clients act on:
//! `auth-required:` only while AUTH can still help, a final `restricted:` or
//! `blocked:` otherwise, `invalid:` and `unsupported:` for requests the relay
//! cannot serve as sent, and NIP-77 refusals as NEG-ERR (which closes the
//! session) rather than NOTICE.
#![allow(clippy::field_reassign_with_default)]

use serde_json::{json, Value};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use wok_relay::{Config, ConnectionGuard, Outbound, OutboundFrame, RelayHandle, TransportSource};

const SERVICE_URL: &str = "wss://prefixes.example";

type Rx = tokio::sync::mpsc::UnboundedReceiver<OutboundFrame>;
type Configure = fn(&mut Config);

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

struct Relay {
    handle: RelayHandle,
    _dir: tempfile::TempDir,
}

impl Relay {
    fn new(configure: impl FnOnce(&mut Config)) -> Self {
        let (dir, env) = wok_compat::temp_db();
        let mut cfg = Config::default();
        cfg.db = dir.path().to_path_buf();
        configure(&mut cfg);
        Self {
            handle: wok_relay::start(env, cfg).unwrap(),
            _dir: dir,
        }
    }

    async fn connection(&self) -> (ConnectionGuard, Rx) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let conn = self
            .handle
            .register_connection(TransportSource::Unix, Outbound::new(tx, 0))
            .await;
        (conn, rx)
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.handle.request_shutdown();
    }
}

async fn recv(rx: &mut Rx) -> Value {
    let frame = tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .unwrap()
        .unwrap();
    serde_json::from_str(&frame.into_text()).unwrap()
}

async fn send(conn: &ConnectionGuard, msg: Value) {
    conn.client_message(msg.to_string()).await;
}

fn assert_reply(reply: &Value, kind: &str, sub_id: &str, prefix: &str) {
    assert_eq!(reply[0], kind, "{reply}");
    assert_eq!(reply[1], sub_id, "{reply}");
    let reason = reply[2].as_str().unwrap_or_default();
    assert!(
        reason.starts_with(prefix),
        "expected a {prefix:?} reason, got {reply}"
    );
}

fn neg_initial() -> String {
    let mut store = wok_negentropy::Vector::new();
    store.seal().unwrap();
    let mut client = wok_negentropy::Negentropy::new(store, 60_000).unwrap();
    hex::encode(client.initiate().unwrap())
}

/// With AUTH unusable, a restricted read is refused for good: no challenge
/// (the first reply is the refusal itself) and no `auth-required:` that would
/// send a NIP-42 client into an AUTH that cannot succeed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restricted_reads_are_final_when_auth_is_unusable() {
    let cases: [(&str, Configure); 2] = [
        ("no service_url", |_| {}),
        ("auth disabled", |cfg| {
            cfg.relay.auth.enabled = false;
            cfg.relay.auth.service_url = SERVICE_URL.into();
        }),
    ];
    for (label, configure) in cases {
        let relay = Relay::new(configure);
        let (conn, mut rx) = relay.connection().await;

        send(&conn, json!(["REQ", "dm", {"kinds":[4]}])).await;
        assert_reply(&recv(&mut rx).await, "CLOSED", "dm", "restricted:");

        send(&conn, json!(["COUNT", "count", {"kinds":[1059]}])).await;
        assert_reply(&recv(&mut rx).await, "CLOSED", "count", "restricted:");

        send(
            &conn,
            json!(["NEG-OPEN", "sync", {"kinds":[1059]}, neg_initial()]),
        )
        .await;
        assert_reply(&recv(&mut rx).await, "NEG-ERR", "sync", "restricted:");

        send(&conn, json!(["AUTH", {"id":"ab"}])).await;
        let reply = recv(&mut rx).await;
        assert_eq!(reply[0], "OK", "{label}: {reply}");
        assert_eq!(reply[2], false, "{label}: {reply}");
        assert!(
            reply[3].as_str().unwrap().starts_with("blocked: "),
            "{label}: {reply}"
        );
        conn.close().await;
    }
}

/// A full disk is the relay's failure, not a policy decision about the event or
/// its author, so it is `error:` (NIP-01: "for when none of that fits"), not
/// `blocked:`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disk_reserve_refusals_are_errors() {
    let relay = Relay::new(|cfg| cfg.db_min_free_disk_bytes = u64::MAX);
    let (conn, mut rx) = relay.connection().await;
    let event =
        wok_compat::sign_event(json!({"created_at":now(),"kind":1,"tags":[],"content":"reserve"}));
    send(&conn, json!(["EVENT", event])).await;
    let reply = recv(&mut rx).await;
    assert_eq!(reply[0], "OK", "{reply}");
    assert_eq!(reply[2], false, "{reply}");
    assert_eq!(
        reply[3],
        format!("error: disk reserve requires {} free bytes", u64::MAX),
        "{reply}"
    );
    conn.close().await;
}

/// NIP-01: a refused REQ or COUNT gets CLOSED with the prefix that fits, and
/// `error:` only "for when none of that fits". Malformed filters and requests
/// over a size limit are `invalid:`, filter elements NIP-01 does not define
/// are `unsupported:` (NIP-01's own example), and operator rules that apply
/// to every client are `blocked:`. The text after the prefix is strfry's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn req_refusals_use_the_prefix_that_fits() {
    let relay = Relay::new(|cfg| {
        cfg.relay.max_filters_per_req = 2;
        cfg.relay.max_tags_per_filter = 1;
        cfg.relay.max_and_entries = 1;
    });
    let (conn, mut rx) = relay.connection().await;
    let hex = "ab".repeat(32);
    let cases = [
        (json!(["REQ", "s"]), "invalid: bad req: arr too small"),
        (json!(["COUNT", "s"]), "invalid: bad req: arr too small"),
        (
            json!(["REQ", "s", {}, {}, {}]),
            "invalid: bad req: arr too big",
        ),
        (
            json!(["REQ", "s", "kinds"]),
            "invalid: bad req: provided filter is not an object",
        ),
        (
            json!(["REQ", "s", {"kinds": "1"}]),
            "invalid: bad req: kinds not an array",
        ),
        (
            json!(["REQ", "s", {"kinds": [70000]}]),
            "invalid: bad req: error parsing kinds: kind must be between 0 and 65535",
        ),
        (
            json!(["REQ", "s", {"ids": ["zz".repeat(32)]}]),
            "invalid: bad req: error parsing ids: hex must be lowercase ASCII",
        ),
        (
            json!(["REQ", "s", {"authors": ["abcd"]}]),
            "invalid: bad req: error parsing authors: filter item too small",
        ),
        (
            json!(["REQ", "s", {"#p": [7]}]),
            "invalid: bad req: error parsing #p: filter item not a string",
        ),
        (
            json!(["REQ", "s", {"limit": -1}]),
            "invalid: bad req: error parsing limit",
        ),
        (
            json!(["REQ", "s", {"#e": [hex], "#p": [hex]}]),
            "invalid: bad req: too many tags in filter",
        ),
        (
            json!(["REQ", "s", {"&t": ["a", "b"]}]),
            "invalid: bad req: too many AND entries in filter",
        ),
        (
            json!(["REQ", "x".repeat(65), {}]),
            "invalid: bad req: invalid subscription id length",
        ),
        (
            json!(["REQ", "s", {"colour": ["red"]}]),
            "unsupported: bad req: unrecognised filter item: colour",
        ),
        (
            json!(["COUNT", "s", {"colour": ["red"]}]),
            "unsupported: bad req: unrecognised filter item: colour",
        ),
        (
            json!(["REQ", "s", {"#tt": ["x"]}]),
            "unsupported: bad req: unindexed tag filter",
        ),
        (
            json!(["REQ", "s", {"#1": ["x"]}]),
            "unsupported: bad req: unindexed tag filter",
        ),
        (
            json!(["REQ", "s", {"&tt": ["x"]}]),
            "unsupported: bad req: unindexed AND tag filter",
        ),
        // An undefined key is unsupported whatever its value.
        (
            json!(["REQ", "s", {"#tt": "x"}]),
            "unsupported: bad req: unindexed tag filter",
        ),
        (
            json!(["REQ", "s", {"#1": 1}]),
            "unsupported: bad req: unindexed tag filter",
        ),
        (
            json!(["REQ", "s", {"&tt": []}]),
            "unsupported: bad req: unindexed AND tag filter",
        ),
        (
            json!(["REQ", "s", {"#t": "x"}]),
            "invalid: bad req: #t not an array",
        ),
        (
            json!(["REQ", "s", {"&t": []}]),
            "invalid: bad req: &t array must not be empty",
        ),
    ];
    for (req, reason) in cases {
        send(&conn, req.clone()).await;
        let sub_id = req[1].as_str().unwrap();
        assert_eq!(
            recv(&mut rx).await,
            json!(["CLOSED", sub_id, reason]),
            "{req}"
        );
    }
    conn.close().await;

    let relay = Relay::new(|cfg| {
        cfg.relay.max_filter_limit_count = 0;
        cfg.relay.filter_validation.allowed_kinds = "1".into();
        cfg.relay.filter_validation.require_author_or_tag = true;
        cfg.relay.abuse.max_query_work = 10;
    });
    let (conn, mut rx) = relay.connection().await;
    let author = "ab".repeat(32);
    let cases = [
        (
            json!(["COUNT", "s", {"kinds": [1]}]),
            "blocked: bad req: COUNT disabled",
        ),
        (
            json!(["REQ", "s", {"authors": [author], "kinds": [7]}]),
            "blocked: bad req: filter validation failed: kind not allowed: 7",
        ),
        (
            json!(["REQ", "s", {"kinds": [1]}]),
            "blocked: bad req: filter validation failed: filter must have exactly one author, p tag, or e tag",
        ),
        // Resending a request over the query-work ceiling cannot help.
        (
            json!(["REQ", "s", {"authors": [author], "kinds": [1], "limit": 20}]),
            "blocked: query too broad (cost 21 > 10); split the REQ or narrow authors/kinds",
        ),
    ];
    for (req, reason) in cases {
        send(&conn, req.clone()).await;
        assert_eq!(recv(&mut rx).await, json!(["CLOSED", "s", reason]), "{req}");
    }
    conn.close().await;
}

/// With `relay.search_enabled` off, NIP-50 is not advertised, and a REQ,
/// COUNT or NEG-OPEN with a `search` filter is `blocked:`, like COUNT and
/// NIP-77 while they are off. The query is not parsed: one the parser
/// refuses gets the same answer. Filters without `search` are served.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn search_filters_are_blocked_while_search_is_off() {
    let too_long = "x".repeat(2_000);
    let relay = Relay::new(|_| {});
    let (conn, mut rx) = relay.connection().await;
    send(&conn, json!(["REQ", "s", {"search": too_long}])).await;
    assert_reply(&recv(&mut rx).await, "CLOSED", "s", "invalid: ");
    conn.close().await;

    let relay = Relay::new(|cfg| cfg.relay.search_enabled = false);
    let (conn, mut rx) = relay.connection().await;
    let cases = [
        json!(["REQ", "s", {"search": "nostr"}]),
        json!(["REQ", "s", {"kinds": [1]}, {"search": "nostr", "kinds": [1]}]),
        json!(["REQ", "s", {"search": too_long}]),
        json!(["REQ", "s", {"search": 7}]),
        json!(["COUNT", "s", {"search": "nostr"}]),
    ];
    for req in cases {
        send(&conn, req.clone()).await;
        assert_eq!(
            recv(&mut rx).await,
            json!(["CLOSED", "s", "blocked: bad req: search disabled"]),
            "{req}"
        );
    }
    send(
        &conn,
        json!(["NEG-OPEN", "n", {"search": "nostr"}, neg_initial()]),
    )
    .await;
    assert_eq!(
        recv(&mut rx).await,
        json!(["NEG-ERR", "n", "blocked: search disabled"])
    );
    send(&conn, json!(["REQ", "plain", {"kinds": [1]}])).await;
    assert_eq!(recv(&mut rx).await[0], "EOSE");
    conn.close().await;
}

/// While more than 100,000 stored events wait for the search index, as after
/// search is turned back on, NIP-11 omits NIP-50 and a REQ, COUNT or NEG-OPEN
/// with a `search` filter gets `error:`. Filters without `search` are served.
/// Free disk space below the reserve holds the build back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn search_filters_are_refused_while_the_search_index_builds() {
    let (dir, env) = wok_compat::temp_db();
    // Unsigned gift wraps: the writer does not check signatures.
    let mut stored: Vec<_> = (0..100_001u64)
        .map(|n| {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&n.to_be_bytes());
            let packed = wok_event::PackedEventBuilder::build(
                &id,
                &[0x51; 32],
                1_700_000_000 + n,
                1059,
                0,
                &wok_event::PackedEventTagBuilder::default(),
            )
            .unwrap();
            let json = json!({
                "id": hex::encode(id),
                "pubkey": hex::encode([0x51; 32]),
                "created_at": 1_700_000_000 + n,
                "kind": 1059,
                "tags": [],
                "content": "",
                "sig": "00".repeat(64),
            })
            .to_string();
            wok_db::EventToWrite::new(packed.into_bytes(), json)
        })
        .collect();
    let mut txn = env.begin_rw().unwrap();
    wok_db::write_events(&mut txn, &mut wok_db::NoopNegentropy, &mut stored, false).unwrap();
    txn.commit().unwrap();
    let mut cfg = Config::default();
    cfg.db = dir.path().to_path_buf();
    cfg.db_min_free_disk_bytes = u64::MAX;
    let relay = Relay {
        handle: wok_relay::start(env, cfg).unwrap(),
        _dir: dir,
    };
    // The writer reads how far the index lags as it starts.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while relay.handle.supported_nips().contains(&50) {
        assert!(std::time::Instant::now() < deadline, "NIP-50 still listed");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let (conn, mut rx) = relay.connection().await;
    let reason = "error: search index is building";
    for req in [
        json!(["REQ", "s", {"search": "nostr"}]),
        json!(["REQ", "s", {"kinds": [1]}, {"search": "nostr", "kinds": [1]}]),
        json!(["COUNT", "s", {"search": "nostr"}]),
    ] {
        send(&conn, req.clone()).await;
        assert_eq!(recv(&mut rx).await, json!(["CLOSED", "s", reason]), "{req}");
    }
    send(
        &conn,
        json!(["NEG-OPEN", "n", {"search": "nostr"}, neg_initial()]),
    )
    .await;
    assert_eq!(recv(&mut rx).await, json!(["NEG-ERR", "n", reason]));
    send(&conn, json!(["REQ", "plain", {"kinds": [1]}])).await;
    assert_eq!(recv(&mut rx).await[0], "EOSE");
    conn.close().await;
}

/// NIP-42 flow: `auth-required:` and a challenge, AUTH, then the same REQ id
/// is re-sent and served. Once authenticated, a COUNT not scoped to an
/// authenticated key is `restricted:` rather than another `auth-required:`, so
/// a client does not loop re-authenticating with the same key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_required_only_while_authenticating_can_help() {
    let relay = Relay::new(|cfg| cfg.relay.auth.service_url = SERVICE_URL.into());
    let (conn, mut rx) = relay.connection().await;

    send(&conn, json!(["REQ", "dm", {"kinds":[4]}])).await;
    let challenge = recv(&mut rx).await;
    assert_eq!(challenge[0], "AUTH", "{challenge}");
    assert_reply(&recv(&mut rx).await, "CLOSED", "dm", "auth-required: ");

    let key = secp256k1::Keypair::new(secp256k1::SECP256K1, &mut rand::thread_rng());
    let auth = wok_compat::sign_event_with_key(
        json!({"created_at":now(),"kind":22242,
            "tags":[["relay",SERVICE_URL],["challenge",challenge[1]]],"content":""}),
        &key,
    );
    send(&conn, json!(["AUTH", auth])).await;
    assert_eq!(recv(&mut rx).await[2], true);

    send(&conn, json!(["REQ", "dm", {"kinds":[4]}])).await;
    assert_eq!(recv(&mut rx).await, json!(["EOSE", "dm", ["finish"]]));

    send(&conn, json!(["COUNT", "count", {"kinds":[4]}])).await;
    assert_reply(&recv(&mut rx).await, "CLOSED", "count", "restricted: ");
    conn.close().await;
}

/// NIP-46 over a relay that restricts kind 24133: the client subscribes to its
/// responses and publishes a request straight away. The response is ephemeral
/// and reaches only live subscriptions, so if the relay challenged only after
/// refusing the REQ, the response could arrive while the client was still
/// authenticating and re-subscribing, and be lost. With AUTH usable, the
/// challenge comes on connect so the client can authenticate before its first
/// REQ.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_challenge_is_sent_on_connect() {
    let relay = Relay::new(|cfg| {
        cfg.relay.auth.service_url = SERVICE_URL.into();
        cfg.relay.auth.recipient_only_kinds = vec![24133];
    });
    let client_key = secp256k1::Keypair::new(secp256k1::SECP256K1, &mut rand::thread_rng());
    let client_pk = hex::encode(client_key.x_only_public_key().0.serialize());

    let (client, mut client_rx) = relay.connection().await;
    let challenge = recv(&mut client_rx).await;
    assert_eq!(challenge[0], "AUTH", "{challenge}");
    let auth = wok_compat::sign_event_with_key(
        json!({"created_at":now(),"kind":22242,
            "tags":[["relay",SERVICE_URL],["challenge",challenge[1]]],"content":""}),
        &client_key,
    );
    send(&client, json!(["AUTH", auth])).await;
    assert_eq!(recv(&mut client_rx).await[2], true);
    send(
        &client,
        json!(["REQ", "nip46", {"kinds":[24133],"#p":[client_pk]}]),
    )
    .await;
    assert_eq!(
        recv(&mut client_rx).await,
        json!(["EOSE", "nip46", ["finish"]])
    );

    let (bunker, mut bunker_rx) = relay.connection().await;
    assert_eq!(recv(&mut bunker_rx).await[0], "AUTH");
    let response = wok_compat::sign_event(
        json!({"created_at":now(),"kind":24133,"tags":[["p",client_pk]],"content":"ack"}),
    );
    send(&bunker, json!(["EVENT", response])).await;
    assert_eq!(recv(&mut bunker_rx).await[2], true);

    let delivered = recv(&mut client_rx).await;
    assert_eq!(delivered[0], "EVENT", "{delivered}");
    assert_eq!(delivered[2]["id"], response["id"], "{delivered}");
    client.close().await;
    bunker.close().await;
}

/// Every NEG-OPEN / NEG-MSG refusal that can name its subscription is a
/// NEG-ERR, so sync clients stop waiting. A NEG-OPEN is refused like a REQ
/// even when its sub id is invalid; only a NEG-MSG with one is a NOTICE.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn negentropy_refusals_are_neg_err() {
    let relay = Relay::new(|_| {});
    let (conn, mut rx) = relay.connection().await;

    send(&conn, json!(["NEG-OPEN", "hex", {}, "zz"])).await;
    assert_reply(&recv(&mut rx).await, "NEG-ERR", "hex", "invalid: ");

    send(
        &conn,
        json!(["NEG-OPEN", "filter", {"kinds":"nope"}, neg_initial()]),
    )
    .await;
    assert_reply(&recv(&mut rx).await, "NEG-ERR", "filter", "invalid: ");

    send(
        &conn,
        json!(["NEG-OPEN", "unknown", {"colour":["red"]}, neg_initial()]),
    )
    .await;
    assert_eq!(
        recv(&mut rx).await,
        json!([
            "NEG-ERR",
            "unknown",
            "unsupported: unrecognised filter item: colour"
        ])
    );

    send(&conn, json!(["NEG-MSG", "msg", "zz"])).await;
    assert_reply(&recv(&mut rx).await, "NEG-ERR", "msg", "invalid: ");

    // Malformed envelopes that still name their subscription.
    for (sid, msg) in [
        ("null-open", json!(["NEG-OPEN", "null-open", {}, null])),
        ("short-open", json!(["NEG-OPEN", "short-open", {}])),
        ("null-msg", json!(["NEG-MSG", "null-msg", null])),
        ("short-msg", json!(["NEG-MSG", "short-msg"])),
    ] {
        send(&conn, msg).await;
        assert_reply(&recv(&mut rx).await, "NEG-ERR", sid, "invalid: ");
    }

    let long = "x".repeat(65);
    send(&conn, json!(["NEG-OPEN", long, {}, neg_initial()])).await;
    assert_eq!(
        recv(&mut rx).await,
        json!(["NEG-ERR", long, "invalid: invalid subscription id length"])
    );
    send(&conn, json!(["NEG-MSG", long, neg_initial()])).await;
    let reply = recv(&mut rx).await;
    assert_eq!(reply[0], "NOTICE", "{reply}");
    assert!(
        reply[1].as_str().unwrap().contains("negentropy error"),
        "{reply}"
    );
    conn.close().await;

    let disabled = Relay::new(|cfg| cfg.relay.negentropy_enabled = false);
    let (conn, mut rx) = disabled.connection().await;
    send(&conn, json!(["NEG-OPEN", "off", {}, neg_initial()])).await;
    assert_reply(&recv(&mut rx).await, "NEG-ERR", "off", "blocked: ");
    conn.close().await;
}

/// NIP-77: after NEG-ERR the subscription is closed, so the relay must not
/// keep reconciling a session it has already reported as failed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn neg_err_closes_the_session() {
    let relay = Relay::new(|_| {});
    let (conn, mut rx) = relay.connection().await;

    send(
        &conn,
        json!(["NEG-OPEN", "sync", {"kinds":[1]}, neg_initial()]),
    )
    .await;
    assert_eq!(recv(&mut rx).await[0], "NEG-MSG");

    send(&conn, json!(["NEG-MSG", "sync", "zz"])).await;
    assert_reply(&recv(&mut rx).await, "NEG-ERR", "sync", "invalid: ");

    send(&conn, json!(["NEG-MSG", "sync", neg_initial()])).await;
    assert_eq!(
        recv(&mut rx).await,
        json!(["NEG-ERR", "sync", "closed: unknown subscription handle"])
    );
    conn.close().await;
}

/// The NEG-ERR is ordered after any reply the worker already owes for the
/// session: a NEG-OPEN immediately followed by a failing NEG-MSG never yields
/// a NEG-MSG for that id after its NEG-ERR.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn neg_err_follows_in_flight_replies() {
    let relay = Relay::new(|_| {});
    let (conn, mut rx) = relay.connection().await;
    for i in 0..50 {
        let event = wok_compat::sign_event(
            json!({"created_at":now(),"kind":1,"tags":[],"content":format!("event {i}")}),
        );
        send(&conn, json!(["EVENT", event])).await;
        assert_eq!(recv(&mut rx).await[2], true);
    }

    for round in 0..20 {
        let sid = format!("sync-{round}");
        send(
            &conn,
            json!(["NEG-OPEN", sid, {"kinds":[1]}, neg_initial()]),
        )
        .await;
        send(&conn, json!(["NEG-MSG", sid, "zz"])).await;
        // Same connection, same worker: once this reply arrives, everything
        // the worker produced for `sid` has already been sent.
        send(
            &conn,
            json!(["NEG-OPEN", "barrier", {"kinds":[2]}, neg_initial()]),
        )
        .await;

        let mut errored = false;
        loop {
            let reply = recv(&mut rx).await;
            if reply[1] == "barrier" {
                assert_eq!(reply[0], "NEG-MSG", "{reply}");
                break;
            }
            assert_eq!(reply[1], sid.as_str(), "{reply}");
            assert!(!errored, "reply after NEG-ERR: {reply}");
            if reply[0] == "NEG-ERR" {
                assert_reply(&reply, "NEG-ERR", &sid, "invalid: ");
                errored = true;
            }
        }
        assert!(errored, "{sid} was never refused");
    }
    conn.close().await;
}
