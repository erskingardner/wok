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
            handle: wok_relay::start(env, cfg).unwrap(),
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
        let challenge = self.recv().await;
        assert_eq!(challenge[0], "AUTH", "{challenge}");
        let event = sign_event_with_key(
            json!({
                "created_at": now(),
                "kind": 22242,
                "tags": [["relay", AUTH_RELAY], ["challenge", challenge[1]]],
                "content": "",
            }),
            key,
        );
        self.send(json!(["AUTH", event])).await;
        let reply = self.recv().await;
        assert_eq!(reply[0], "OK", "{reply}");
        assert_eq!(reply[2], true, "{reply}");
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
    assert!(NostrFilterGroup::from_value(&json!({"ids":[]}), 500, 3, 16).is_err());
    assert!(NostrFilterGroup::from_value(&json!({"#1":["value"]}), 500, 3, 16).is_err());
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
    assert!(
        reply[3].as_str().unwrap().starts_with("deleted:"),
        "{reply}"
    );

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
    let wrap = sign_event(json!({
        "created_at": now(),
        "kind": 21059,
        "tags": [["p", pubkey_hex(&recipient)]],
        "content": "sealed",
    }));
    assert_eq!(publisher.publish(&wrap).await[2], true);

    let delivered = inbox.recv().await;
    assert_eq!(delivered, json!(["EVENT", "inbox", wrap]));
    assert_eq!(anonymous.try_recv().await, None);
    assert_eq!(stranger.try_recv().await, None);
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
