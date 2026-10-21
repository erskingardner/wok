//! Independently grounded NIP tests. NIPs pin: 656cecc7c0a815b6a2b218d3b5d6f078b3f4dbab

use secp256k1::{Keypair, SECP256K1};
use serde_json::{json, Value};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use wok_compat::{sign_event, sign_event_with_key};
use wok_event::{parse_and_verify_event, EventLimits};
use wok_query::NostrFilterGroup;
use wok_relay::{
    ClientCommand, ConnectionGuard, Outbound, OutboundFrame, RelayHandle, RelayMessage,
    TransportSource,
};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// An in-process relay for observing NIP behavior on the wire protocol.
struct Relay {
    handle: RelayHandle,
    /// The relay's own LMDB environment, for writes that bypass its writer.
    env: wok_db::Env,
    _dir: tempfile::TempDir,
}

impl Relay {
    fn new(configure: impl FnOnce(&mut wok_relay::Config)) -> Self {
        let (dir, env) = wok_compat::temp_db();
        let mut cfg = wok_relay::Config {
            db: dir.path().to_path_buf(),
            ..Default::default()
        };
        configure(&mut cfg);
        Self {
            handle: wok_relay::start(env.clone(), cfg).unwrap(),
            env,
            _dir: dir,
        }
    }

    async fn connect(&self) -> Conn {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let guard = self
            .handle
            .register_connection(TransportSource::Unix, Outbound::new(tx, 0))
            .await;
        Conn { guard, rx }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.handle.request_shutdown();
    }
}

struct Conn {
    guard: ConnectionGuard,
    rx: tokio::sync::mpsc::UnboundedReceiver<OutboundFrame>,
}

impl Conn {
    async fn send(&self, message: Value) {
        self.guard.client_message(message.to_string()).await;
    }

    async fn recv(&mut self) -> Value {
        let frame = tokio::time::timeout(Duration::from_secs(3), self.rx.recv())
            .await
            .expect("relay reply")
            .expect("connection open");
        serde_json::from_str(&frame.into_text()).unwrap()
    }

    /// The next frame, if one arrives within a short grace period.
    async fn try_recv(&mut self) -> Option<Value> {
        let frame = tokio::time::timeout(Duration::from_millis(300), self.rx.recv())
            .await
            .ok()??;
        Some(serde_json::from_str(&frame.into_text()).unwrap())
    }

    /// Answer the challenge sent on connect as `key`.
    async fn auth(&mut self, key: &Keypair) {
        let reply = self.auth_at(key, now()).await;
        assert_eq!(reply[2], true, "{reply}");
    }

    /// Answer the challenge sent on connect as `key` with an AUTH event
    /// dated `created_at`, and return the OK reply.
    async fn auth_at(&mut self, key: &Keypair, created_at: u64) -> Value {
        let challenge = self.recv().await;
        assert_eq!(challenge[0], "AUTH", "{challenge}");
        let event = sign_event_with_key(
            json!({
                "created_at": created_at,
                "kind": 22242,
                "tags": [["relay", AUTH_RELAY], ["challenge", challenge[1]]],
                "content": "",
            }),
            key,
        );
        self.send(json!(["AUTH", event])).await;
        let reply = self.recv().await;
        assert_eq!(reply[0], "OK", "{reply}");
        reply
    }

    /// Subscribe and wait until stored events are done, so live delivery
    /// applies from here on.
    async fn subscribe(&mut self, sub_id: &str, filter: Value) {
        self.send(json!(["REQ", sub_id, filter])).await;
        let eose = self.recv().await;
        assert_eq!(eose, json!(["EOSE", sub_id]));
    }

    /// Publish and return the OK reply.
    async fn publish(&mut self, event: &Value) -> Value {
        self.send(json!(["EVENT", event])).await;
        let reply = self.recv().await;
        assert_eq!(reply[0], "OK", "{reply}");
        assert_eq!(reply[1], event["id"], "{reply}");
        reply
    }

    /// Stored events matching `filter`, up to EOSE.
    async fn history(&mut self, filter: Value) -> Vec<Value> {
        self.send(json!(["REQ", "history", filter])).await;
        let mut events = Vec::new();
        loop {
            let frame = self.recv().await;
            match frame[0].as_str() {
                Some("EVENT") => events.push(frame[2].clone()),
                Some("EOSE") => break,
                _ => panic!("unexpected {frame}"),
            }
        }
        self.send(json!(["CLOSE", "history"])).await;
        events
    }
}

fn key() -> Keypair {
    Keypair::new(SECP256K1, &mut rand::thread_rng())
}

const AUTH_RELAY: &str = "wss://conformance.test";

/// A relay where NIP-42 AUTH can succeed.
fn auth_relay() -> Relay {
    Relay::new(|cfg| cfg.relay.auth.service_url = AUTH_RELAY.into())
}

fn pubkey_hex(key: &Keypair) -> String {
    hex::encode(key.x_only_public_key().0.serialize())
}

#[test]
fn nip01_event_id_and_sig() {
    let ev = sign_event(json!({
        "created_at": 1_700_000_010u64,
        "kind": 1,
        "tags": [],
        "content": "nip01",
    }));
    parse_and_verify_event(&ev, &EventLimits::default(), None, true, false).unwrap();
}

#[test]
fn nip01_malformed_json_rejected() {
    assert!(ClientCommand::parse("not-json").is_err());
    assert!(ClientCommand::parse("{}").is_err());
    assert!(ClientCommand::parse(r#"["EVENT"]"#).is_err());
}

#[test]
fn nip01_kind_is_limited_to_u16() {
    let ev = sign_event(json!({
        "created_at": 1_700_000_010u64,
        "kind": 65536,
        "tags": [],
        "content": "kind out of range",
    }));
    assert!(parse_and_verify_event(&ev, &EventLimits::default(), None, true, false).is_err());
}

#[test]
fn nip01_all_tag_elements_must_be_strings() {
    let ev = sign_event(json!({
        "created_at": 1_700_000_010u64,
        "kind": 1,
        "tags": [["e", "11".repeat(32), 7]],
        "content": "invalid tag",
    }));
    assert!(parse_and_verify_event(&ev, &EventLimits::default(), None, true, false).is_err());
}

#[test]
fn nip01_identifiers_are_lowercase_hex() {
    let ev = json!({
        "id": "AA".repeat(32),
        "pubkey": "22".repeat(32),
        "created_at": 1,
        "kind": 1,
        "content": "",
        "tags": [],
        "sig": "00".repeat(64),
    });
    assert!(wok_event::nostr_json_to_packed_event(&ev, &EventLimits::default()).is_err());
}

#[test]
fn nip01_filter_kinds_since_until_limit() {
    let fg = NostrFilterGroup::from_value(
        &json!({"kinds":[1],"since":10,"until":20,"limit":5}),
        500,
        3,
        16,
    )
    .unwrap();
    assert_eq!(fg.filters[0].limit, 5);
}

#[test]
fn nip01_filter_ids_and_kinds_use_event_field_grammar() {
    assert!(NostrFilterGroup::from_value(&json!({"ids":["AA".repeat(32)]}), 500, 3, 16).is_err());
    assert!(NostrFilterGroup::from_value(
        &json!({"authors":[format!("0x{}", "11".repeat(32))]}),
        500,
        3,
        16,
    )
    .is_err());
    assert!(NostrFilterGroup::from_value(&json!({"kinds":[65536]}), 500, 3, 16).is_err());
    assert!(NostrFilterGroup::from_value(&json!({"#1":["value"]}), 500, 3, 16).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip01_empty_filter_lists_match_nothing() {
    // "If any of these lists is empty, no event can satisfy that condition,
    // so the filter MUST NOT match any events. An empty list MUST NOT be
    // treated as if the attribute were absent."
    let relay = Relay::new(|_| {});
    let mut conn = relay.connect().await;
    let p = "11".repeat(32);
    let signed = |content: &str| {
        sign_event(json!({
            "created_at": now(),
            "kind": 1,
            "tags": [["p", p]],
            "content": content,
        }))
    };
    let stored = signed("stored");
    assert_eq!(conn.publish(&stored).await[2], true);

    // The subscription gets EOSE and stays open, not CLOSED.
    let empty = [
        json!({"ids": []}),
        json!({"authors": []}),
        json!({"kinds": []}),
        json!({"#p": []}),
    ];
    let mut req = vec![json!("REQ"), json!("empty")];
    req.extend(empty.iter().cloned());
    conn.send(Value::Array(req)).await;
    assert_eq!(conn.recv().await, json!(["EOSE", "empty"]));
    // The REQ's other filters still apply.
    conn.send(json!(["REQ", "mixed", {"kinds": []}, {"kinds": [1]}]))
        .await;
    assert_eq!(conn.recv().await, json!(["EVENT", "mixed", stored]));
    assert_eq!(conn.recv().await, json!(["EOSE", "mixed"]));

    let live = signed("live");
    let mut publisher = relay.connect().await;
    assert_eq!(publisher.publish(&live).await[2], true);
    assert_eq!(conn.recv().await, json!(["EVENT", "mixed", live]));
    assert_eq!(conn.try_recv().await, None);

    for filter in &empty {
        conn.send(json!(["COUNT", "count", filter])).await;
        assert_eq!(conn.recv().await, json!(["COUNT", "count", {"count": 0}]));
    }
    conn.send(json!(["COUNT", "count", {"kinds": []}, {"kinds": [1]}]))
        .await;
    assert_eq!(conn.recv().await, json!(["COUNT", "count", {"count": 2}]));

    // NIP-77 reconciles against no events, not against the whole database.
    for (filter, needed) in [(json!({"kinds": []}), 0), (json!({"kinds": [1]}), 2)] {
        let mut store = wok_negentropy::Vector::new();
        store.seal().unwrap();
        let mut client = wok_negentropy::Negentropy::new(store, 60_000).unwrap();
        let init = client.initiate().unwrap();
        conn.send(json!(["NEG-OPEN", "neg", filter, hex::encode(init)]))
            .await;
        let reply = conn.recv().await;
        assert_eq!(reply[0], "NEG-MSG", "{filter}: {reply}");
        let reply = hex::decode(reply[2].as_str().unwrap()).unwrap();
        let (mut have, mut need) = (Vec::new(), Vec::new());
        client
            .reconcile_with_ids(&reply, &mut have, &mut need)
            .unwrap();
        assert_eq!((have.len(), need.len()), (0, needed), "{filter}");
        conn.send(json!(["NEG-CLOSE", "neg"])).await;
    }
}

#[test]
fn nip01_unknown_filter_field_rejected() {
    assert!(NostrFilterGroup::from_value(&json!({"foo":1}), 500, 3, 16).is_err());
}

#[test]
fn nip01_eose_encoding() {
    let s = RelayMessage::Eose {
        sub_id: "abc".into(),
    }
    .to_json();
    assert_eq!(s, r#"["EOSE","abc"]"#);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip01_stale_replaceable_versions_are_refused_with_a_standard_prefix() {
    // A false OK "MUST be a string formed by a machine-readable single-word
    // prefix followed by a `:`" from the standardized list. strfry replied
    // `replaced: have newer event`.
    let relay = Relay::new(|_| {});
    let mut conn = relay.connect().await;
    let key = key();
    for (kind, tags) in [(0, json!([])), (30000, json!([["d", "x"]]))] {
        let signed = |created_at: u64| {
            sign_event_with_key(
                json!({"created_at": created_at, "kind": kind, "tags": tags, "content": ""}),
                &key,
            )
        };
        assert_eq!(conn.publish(&signed(now())).await[2], true);
        let reply = conn.publish(&signed(now() - 60)).await;
        assert_eq!(reply[2], false, "{reply}");
        assert_eq!(reply[3], "blocked: have a newer version", "{reply}");
        assert!(wok_relay::protocol::has_reason_prefix(
            reply[3].as_str().unwrap()
        ));
    }
}

#[test]
fn nip09_kind5_is_deletion() {
    assert_eq!(wok_event::DELETION_KIND, 5);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip09_deleting_a_deletion_request_has_no_effect() {
    // "Publishing a deletion request event against a deletion request has no
    // effect." The deletion request and its tombstone both stay in force.
    let relay = Relay::new(|_| {});
    let mut conn = relay.connect().await;
    let key = key();
    let signed = |kind: u64, tags: Value, content: &str| {
        sign_event_with_key(
            json!({"created_at": now(), "kind": kind, "tags": tags, "content": content}),
            &key,
        )
    };
    let note = signed(1, json!([]), "first");
    let d1 = signed(5, json!([["e", note["id"]]]), "");
    let d2 = signed(5, json!([["e", d1["id"]]]), "");
    for event in [&note, &d1, &d2] {
        assert_eq!(conn.publish(event).await[2], true);
    }
    let ids = |events: &[&Value]| {
        let mut ids: Vec<_> = events.iter().map(|event| event["id"].clone()).collect();
        ids.sort_by_key(|id| id.as_str().unwrap().to_owned());
        ids
    };
    let mut stored: Vec<_> = conn
        .history(json!({"ids": [note["id"], d1["id"], d2["id"]]}))
        .await
        .into_iter()
        .map(|event| event["id"].clone())
        .collect();
    stored.sort_by_key(|id| id.as_str().unwrap().to_owned());
    assert_eq!(stored, ids(&[&d1, &d2]));
    let reply = conn.publish(&note).await;
    assert_eq!(reply[2], false, "{reply}");
    assert_eq!(reply[3], "blocked: user requested deletion", "{reply}");

    // A request against a deletion request that arrives first does not
    // tombstone it either: the later deletion request is stored and applied.
    let note = signed(1, json!([]), "second");
    let d1 = signed(5, json!([["e", note["id"]]]), "");
    let d2 = signed(5, json!([["e", d1["id"]]]), "");
    for event in [&note, &d2, &d1] {
        assert_eq!(conn.publish(event).await[2], true);
    }
    let mut stored: Vec<_> = conn
        .history(json!({"ids": [note["id"], d1["id"], d2["id"]]}))
        .await
        .into_iter()
        .map(|event| event["id"].clone())
        .collect();
    stored.sort_by_key(|id| id.as_str().unwrap().to_owned());
    assert_eq!(stored, ids(&[&d1, &d2]));
}

#[test]
fn nip40_expiration_too_small_rejected() {
    let ev = json!({
        "id": "11".repeat(32),
        "pubkey": "22".repeat(32),
        "created_at": 1,
        "kind": 1,
        "content": "",
        "tags": [["expiration","50"]],
        "sig": "00".repeat(64),
    });
    assert!(wok_event::nostr_json_to_packed_event(&ev, &EventLimits::default()).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip40_expired_ephemeral_events_are_refused_and_not_broadcast() {
    // "Relays SHOULD drop any events that are published to them if they are
    // expired." Live-only ephemeral events are never stored, so the only
    // place to drop one is at publication.
    let relay = Relay::new(|_| {});
    let mut subscriber = relay.connect().await;
    subscriber
        .subscribe("ephemeral", json!({"kinds": [20001]}))
        .await;
    let mut publisher = relay.connect().await;
    let ephemeral = |expiration: u64| {
        sign_event(json!({
            "created_at": now(),
            "kind": 20001,
            "tags": [["expiration", expiration.to_string()]],
            "content": "",
        }))
    };
    let expired = ephemeral(now() - 1);
    let reply = publisher.publish(&expired).await;
    assert_eq!(reply[2], false, "{reply}");
    assert_eq!(reply[3], "invalid: event expired", "{reply}");
    assert_eq!(subscriber.try_recv().await, None);

    let live = ephemeral(now() + 60);
    assert_eq!(publisher.publish(&live).await[2], true);
    assert_eq!(subscriber.recv().await, json!(["EVENT", "ephemeral", live]));
}

/// 2020-01-01T00:00:00Z, older than the 3-year bound Wok inherited from
/// strfry.
const JAN_2020: u64 = 1_577_836_800;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip01_reject_older_than_zero_means_no_lower_bound() {
    // Audit C2: a 2020 profile could not be rebroadcast. A configured 0 used
    // to refuse every event dated in the past.
    let relay = Relay::new(|cfg| cfg.events.reject_older_than_secs = 0);
    let mut conn = relay.connect().await;
    for kind in [0, 1] {
        let old = sign_event(json!({
            "created_at": JAN_2020,
            "kind": kind,
            "tags": [],
            "content": "",
        }));
        let reply = conn.publish(&old).await;
        assert_eq!(reply[2], true, "kind {kind}: {reply}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip01_lower_bound_spares_replaceable_addressable_deletion_and_vanish() {
    // An operator-set bound applies to regular events only, so profiles,
    // lists, deletions and vanish requests can still be rebroadcast.
    let relay = Relay::new(|cfg| cfg.events.reject_older_than_secs = 86_400);
    let mut conn = relay.connect().await;
    let old = |kind: u64, tags: Value| {
        sign_event(json!({
            "created_at": JAN_2020,
            "kind": kind,
            "tags": tags,
            "content": "",
        }))
    };
    for (kind, tags) in [
        (0, json!([])),
        (3, json!([])),
        (10_002, json!([["r", "wss://relay.example.com"]])),
        (30_023, json!([["d", "post"]])),
        (5, json!([["e", "11".repeat(32)]])),
        (62, json!([["relay", "ALL_RELAYS"]])),
    ] {
        let reply = conn.publish(&old(kind, tags)).await;
        assert_eq!(reply[2], true, "kind {kind}: {reply}");
    }
    let regular = old(1, json!([]));
    assert_eq!(
        conn.publish(&regular).await,
        json!(["OK", regular["id"], false, "invalid: created_at too early"])
    );
}

#[test]
fn nip70_protected_tag_constant() {
    assert_eq!(wok_event::PROTECTED_TAG, '-');
}

#[test]
fn nip42_auth_kind() {
    assert_eq!(wok_event::AUTH_KIND, 22242);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip42_auth_events_sent_as_event_are_never_stored_or_broadcast() {
    // "Relays MUST exclude kind: 22242 events from being broadcasted to any
    // client." Covers both ephemeral modes, since `ttl` would also store it.
    for persistence in [
        wok_relay::EphemeralPersistence::LiveOnly,
        wok_relay::EphemeralPersistence::Ttl,
    ] {
        let relay = Relay::new(|cfg| cfg.events.ephemeral_persistence = persistence);
        let mut by_kind = relay.connect().await;
        by_kind.subscribe("auth", json!({"kinds": [22242]})).await;
        let mut everything = relay.connect().await;
        everything.subscribe("everything", json!({})).await;

        let mut publisher = relay.connect().await;
        let auth = sign_event(json!({
            "created_at": now(),
            "kind": 22242,
            "tags": [["relay", AUTH_RELAY], ["challenge", "replayed"]],
            "content": "",
        }));
        let reply = publisher.publish(&auth).await;
        assert_eq!(
            reply,
            json!([
                "OK",
                auth["id"],
                false,
                "invalid: AUTH events must be sent with AUTH"
            ])
        );
        assert_eq!(by_kind.try_recv().await, None, "{persistence:?}");
        assert_eq!(everything.try_recv().await, None, "{persistence:?}");
        assert!(publisher
            .history(json!({"ids": [auth["id"]]}))
            .await
            .is_empty());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip42_auth_events_written_by_other_writers_are_never_sent() {
    // strfry, an older release or any outside writer can commit a kind 22242
    // straight to LMDB. The relay picks such commits up through its DB-change
    // monitor and must still send the event to no client, live or stored.
    for persistence in [
        wok_relay::EphemeralPersistence::LiveOnly,
        wok_relay::EphemeralPersistence::Ttl,
    ] {
        let relay = Relay::new(|cfg| cfg.events.ephemeral_persistence = persistence);
        let mut by_kind = relay.connect().await;
        by_kind.subscribe("auth", json!({"kinds": [22242]})).await;
        by_kind.subscribe("marker", json!({"kinds": [1]})).await;
        let mut everything = relay.connect().await;
        everything.subscribe("everything", json!({})).await;

        let auth = sign_event(json!({
            "created_at": now() - 2,
            "kind": 22242,
            "tags": [["relay", AUTH_RELAY], ["challenge", "replayed"]],
            "content": "",
        }));
        let marker = sign_event(json!({
            "created_at": now(),
            "kind": 1,
            "tags": [],
            "content": "marker",
        }));
        // Committed first, a delivered AUTH event would precede the marker.
        wok_compat::write_event_to_env(&relay.env, &auth);
        wok_compat::write_event_to_env(&relay.env, &marker);
        let auth_id = hex::decode(auth["id"].as_str().unwrap()).unwrap();
        assert!(
            wok_db::lookup_event_by_id_ro(&relay.env.begin_ro().unwrap(), &auth_id)
                .unwrap()
                .is_some(),
            "{persistence:?}"
        );

        let live = json!(["EVENT", "marker", marker]);
        assert_eq!(by_kind.recv().await, live, "{persistence:?}");
        let live = json!(["EVENT", "everything", marker]);
        assert_eq!(everything.recv().await, live, "{persistence:?}");
        assert!(by_kind.history(json!({"kinds": [22242]})).await.is_empty());
        assert_eq!(everything.history(json!({})).await, [marker]);
        by_kind
            .send(json!(["COUNT", "count", {"kinds": [22242]}]))
            .await;
        let count = by_kind.recv().await;
        assert_eq!(
            (&count[0], &count[2]["count"]),
            (&json!("COUNT"), &json!(0))
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip42_auth_accepts_about_ten_minutes_of_clock_skew() {
    // NIP-42 suggests a window of about ten minutes. Audit B3: an AUTH signed
    // 120 s earlier was refused by the 60 s ephemeral window.
    let relay = auth_relay();
    let now = now();
    for (created_at, refusal) in [
        (now - 120, None),
        (now + 120, None),
        (now - 700, Some("invalid: ephemeral event expired")),
        (now + 700, Some("invalid: created_at too late")),
    ] {
        let mut conn = relay.connect().await;
        let reply = conn.auth_at(&key(), created_at).await;
        match refusal {
            None => assert_eq!(reply[2], true, "{reply}"),
            Some(reason) => assert_eq!(
                (&reply[2], &reply[3]),
                (&json!(false), &json!(reason)),
                "{reply}"
            ),
        }
    }
}

#[test]
fn nip45_count_encoding() {
    let s = RelayMessage::Count {
        sub_id: "c".into(),
        count: 3,
        limited: true,
        hll: Some("00".repeat(256)),
    }
    .to_json();
    assert!(s.contains("\"count\":3"));
    assert!(s.contains("\"limited\":true"));
    assert!(!s.contains("\"hll\""));

    let s = RelayMessage::Count {
        sub_id: "c".into(),
        count: 0,
        limited: false,
        hll: Some("00".repeat(256)),
    }
    .to_json();
    assert!(s.contains("\"hll\""));
}

#[test]
fn nip50_search_filter_and_extensions() {
    let filters = NostrFilterGroup::from_value(
        &json!({
            "search":"best nostr apps domain:example.com include:spam",
            "kinds":[1],
            "limit":20
        }),
        500,
        3,
        16,
    )
    .unwrap();
    let search = filters.filters[0].search.as_ref().unwrap();
    assert_eq!(search.terms, vec!["apps", "best", "nostr"]);
    assert_eq!(search.phrase, "best nostr apps");
    assert_eq!(filters.filters[0].limit, 20);
    assert!(NostrFilterGroup::from_value(&json!({"search":7}), 500, 3, 16).is_err());
}

#[test]
fn nip11_software_not_strfry_when_unconfigured() {
    let cfg = wok_relay::Config::default();
    let nips = wok_relay::supported_nips(&cfg);
    assert_eq!(nips, vec![1, 9, 11, 40, 45, 50, 62, 70, 77, 91]);
    assert!(!nips.contains(&2), "client-side NIP-02 is not advertised");
    assert!(!nips.contains(&4), "client-side NIP-04 is not advertised");
    assert!(!nips.contains(&28), "client-side NIP-28 is not advertised");
}

#[test]
fn nip01_invalid_signature_rejected() {
    let mut ev = sign_event(json!({
        "created_at": 1_700_000_011u64,
        "kind": 1,
        "tags": [],
        "content": "bad-sig",
    }));
    ev["sig"] = json!("00".repeat(64));
    assert!(parse_and_verify_event(&ev, &EventLimits::default(), None, true, false).is_err());
}

#[test]
fn nip01_filter_ids_are_exact_length() {
    assert!(NostrFilterGroup::from_value(&json!({"ids":["aabb"]}), 500, 3, 16).is_err());
}

#[test]
fn nip01_close_and_unknown_cmd() {
    let c = ClientCommand::parse(r#"["CLOSE","abc"]"#).unwrap();
    assert!(matches!(c, ClientCommand::Close { .. }));
    assert!(ClientCommand::parse(r#"["NOPE","x"]"#).is_err());
}

#[test]
fn nip01_duplicate_filters_still_parse() {
    let fg = NostrFilterGroup::from_req(
        &[
            json!("REQ"),
            json!("s"),
            json!({"kinds":[1]}),
            json!({"kinds":[1], "limit": 2}),
        ],
        500,
        3,
        16,
    )
    .unwrap();
    assert_eq!(fg.size(), 2);
}

#[test]
fn nip01_kinds_4_to_44_are_regular() {
    // Includes kind 41, which the pinned strfry replaces per author.
    for kind in 4..45 {
        assert!(!wok_event::is_replaceable_kind(kind), "kind {kind}");
        assert!(!wok_event::is_param_replaceable_kind(kind), "kind {kind}");
        assert!(!wok_event::is_ephemeral_kind(kind), "kind {kind}");
    }
}

#[test]
fn nip02_kind3_is_replaceable() {
    assert!(wok_event::is_replaceable_kind(3));
}

#[test]
fn nip59_gift_wrap_kinds() {
    assert!(wok_event::GIFT_WRAP_KINDS.contains(&1059));
    assert!(wok_event::GIFT_WRAP_KINDS.contains(&21059));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip59_ephemeral_gift_wraps_reach_only_their_recipient() {
    // Kind 21059 is live-only, so its privacy rests on live delivery alone.
    let relay = auth_relay();
    let recipient = key();
    let mut anonymous = relay.connect().await;
    assert_eq!(anonymous.recv().await[0], "AUTH");
    anonymous
        .send(json!(["REQ", "wraps", {"kinds": [21059]}]))
        .await;
    let refused = anonymous.recv().await;
    assert_eq!(refused[0], "CLOSED", "{refused}");
    assert!(
        refused[2].as_str().unwrap().starts_with("auth-required:"),
        "{refused}"
    );
    anonymous.subscribe("everything", json!({})).await;
    let mut stranger = relay.connect().await;
    stranger.auth(&key()).await;
    stranger.subscribe("wraps", json!({"kinds": [21059]})).await;
    let mut inbox = relay.connect().await;
    inbox.auth(&recipient).await;
    inbox
        .subscribe(
            "inbox",
            json!({"kinds": [21059], "#p": [pubkey_hex(&recipient)]}),
        )
        .await;

    let mut publisher = relay.connect().await;
    assert_eq!(publisher.recv().await[0], "AUTH");
    let wrap = |created_at: u64| {
        sign_event(json!({
            "created_at": created_at,
            "kind": 21059,
            "tags": [["p", pubkey_hex(&recipient)]],
            "content": "sealed",
        }))
    };
    // NIP-59 backdates wraps by up to two days, far past the 60 s window for
    // other ephemeral kinds (audit B3).
    for created_at in [now(), now() - 3600] {
        let wrap = wrap(created_at);
        assert_eq!(publisher.publish(&wrap).await[2], true);

        let delivered = inbox.recv().await;
        assert_eq!(delivered, json!(["EVENT", "inbox", wrap]));
        assert_eq!(anonymous.try_recv().await, None);
        assert_eq!(stranger.try_recv().await, None);
    }
    let stale = wrap(now() - wok_event::GIFT_WRAP_BACKDATE_SECS - 60);
    let reply = publisher.publish(&stale).await;
    assert_eq!(reply[3], "invalid: ephemeral event expired", "{reply}");
    assert_eq!(inbox.try_recv().await, None);
}

#[test]
fn nip62_is_enabled_by_default_and_can_be_disabled() {
    let mut cfg = wok_relay::Config::default();
    assert!(wok_relay::supported_nips(&cfg).contains(&62));
    cfg.relay.nip62.enabled = false;
    assert!(!wok_relay::supported_nips(&cfg).contains(&62));
}

#[test]
fn nip77_neg_open_parse() {
    let c = ClientCommand::parse(r#"["NEG-OPEN","s",{"kinds":[1]},"61"]"#).unwrap();
    assert!(matches!(c, ClientCommand::NegOpen { .. }));
}

#[test]
fn nip77_payload_hex_has_no_prefix_or_half_byte() {
    assert!(wok_event::from_hex_strict("61").is_ok());
    assert!(wok_event::from_hex_strict("0x61").is_err());
    assert!(wok_event::from_hex_strict("1").is_err());
}

#[test]
fn nip91_and_tags_take_precedence_over_compatibility_or_tags() {
    let filters = NostrFilterGroup::from_value(
        &json!({
            "&t":["meme", "cat"],
            "#t":["meme", "cat", "black", "white"]
        }),
        500,
        3,
        16,
    )
    .unwrap();
    let filter = &filters.filters[0];
    assert_eq!(filter.and_tags[&'t'].size(), 2);
    assert_eq!(filter.tags[&'t'].size(), 2);
    assert!(!filter.index_only_scans);
}

#[test]
fn advertised_nips_are_subset_of_tested() {
    // NIP-86 coverage lives in e2e_transports.rs (management API e2e tests).
    let tested = [1u64, 9, 11, 13, 40, 42, 45, 50, 59, 62, 70, 77, 86, 91];
    assert_eq!(
        wok_relay::RELAY_CAPABILITY_CATALOG
            .iter()
            .map(|capability| capability.nip)
            .collect::<Vec<_>>(),
        tested
    );
    let cfg = wok_relay::Config::default();
    for n in wok_relay::supported_nips(&cfg) {
        assert!(
            tested.contains(&n),
            "advertised NIP-{n} has no conformance coverage"
        );
    }
}
