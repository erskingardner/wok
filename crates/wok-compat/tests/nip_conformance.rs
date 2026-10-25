//! Independently grounded NIP tests. NIPs pin: 0b5532c0355ab27f447e071a93c09cf3a2b4aad5

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
        self.answer(key, &challenge, created_at).await
    }

    /// Answer `challenge`, an AUTH frame already received, as `key`, and
    /// return the OK reply.
    async fn answer(&mut self, key: &Keypair, challenge: &Value, created_at: u64) -> Value {
        self.answer_for(AUTH_RELAY, key, challenge, created_at)
            .await
    }

    /// [`answer`](Self::answer) with an AUTH event naming `relay`.
    async fn answer_for(
        &mut self,
        relay: &str,
        key: &Keypair,
        challenge: &Value,
        created_at: u64,
    ) -> Value {
        let event = sign_event_with_key(
            json!({
                "created_at": created_at,
                "kind": 22242,
                "tags": [["relay", relay], ["challenge", challenge[1]]],
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
        // Whatever NIP-67 hints follow.
        assert!(eose[0] == "EOSE" && eose[1] == sub_id, "{eose}");
    }

    /// Publish and return the OK reply.
    async fn publish(&mut self, event: &Value) -> Value {
        self.send(json!(["EVENT", event])).await;
        let reply = self.recv().await;
        assert_eq!(reply[0], "OK", "{reply}");
        assert_eq!(reply[1], event["id"], "{reply}");
        reply
    }

    /// What a REQ sends up to its EOSE: the EVENTs' events, the other frames
    /// (AUTH), and the EOSE.
    async fn backfill(&mut self, sub_id: &str, filters: Value) -> (Vec<Value>, Vec<Value>, Value) {
        let mut req = vec![json!("REQ"), json!(sub_id)];
        req.extend(filters.as_array().unwrap().iter().cloned());
        self.send(Value::Array(req)).await;
        let (mut events, mut other) = (Vec::new(), Vec::new());
        loop {
            let frame = self.recv().await;
            match frame[0].as_str() {
                Some("EVENT") => events.push(frame[2].clone()),
                Some("EOSE") => return (events, other, frame),
                _ => other.push(frame),
            }
        }
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
    assert_eq!(conn.recv().await, json!(["EOSE", "empty", ["finish"]]));
    // The REQ's other filters still apply.
    conn.send(json!(["REQ", "mixed", {"kinds": []}, {"kinds": [1]}]))
        .await;
    assert_eq!(conn.recv().await, json!(["EVENT", "mixed", stored]));
    assert_eq!(conn.recv().await, json!(["EOSE", "mixed", ["finish"]]));

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip01_limit_zero_sends_eose_and_stays_live() {
    // "When `limit` is zero, the relay MUST NOT return stored events for that
    // filter. After the initial queries for all filters are complete, the
    // relay MUST send `EOSE` and MUST keep the subscription active for newly
    // received matching events."
    let relay = Relay::new(|_| {});
    let mut conn = relay.connect().await;
    let note = |content: &str| {
        sign_event(json!({
            "created_at": now(),
            "kind": 1,
            "tags": [],
            "content": content,
        }))
    };
    let stored = note("stored");
    assert_eq!(conn.publish(&stored).await[2], true);

    conn.subscribe("live", json!({"kinds": [1], "limit": 0}))
        .await;
    // Only the filter with `limit: 0` returns no stored events.
    conn.send(json!([
        "REQ",
        "mixed",
        {"kinds": [1], "limit": 0},
        {"ids": [stored["id"]]}
    ]))
    .await;
    assert_eq!(conn.recv().await, json!(["EVENT", "mixed", stored]));
    assert_eq!(conn.recv().await, json!(["EOSE", "mixed"]));

    let live = note("live");
    let mut publisher = relay.connect().await;
    assert_eq!(publisher.publish(&live).await[2], true);
    let mut delivered = vec![conn.recv().await, conn.recv().await];
    delivered.sort_by_key(|frame| frame[1].as_str().unwrap().to_owned());
    assert_eq!(
        delivered,
        [
            json!(["EVENT", "live", live]),
            json!(["EVENT", "mixed", live])
        ]
    );
    assert_eq!(conn.try_recv().await, None);
}

#[test]
fn nip01_unknown_filter_field_rejected() {
    assert!(NostrFilterGroup::from_value(&json!({"foo":1}), 500, 3, 16).is_err());
}

#[test]
fn nip01_eose_encoding() {
    let s = RelayMessage::Eose {
        sub_id: "abc".into(),
        hints: wok_relay::EoseHints::default(),
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip70_reposts_that_embed_a_protected_event_are_refused() {
    // "Reposts of protected events MUST NOT embed the reposted event. If a
    // repost of a protected event embeds the event anyway, relays SHOULD
    // summarily reject it." The content is parsed: a protected event is
    // found however its JSON is spaced, and nothing else is mistaken for one.
    // An object the strict parser refuses counts as protected, since
    // clients' parsers can still read a protected event in it.
    let relay = Relay::new(|_| {});
    let mut conn = relay.connect().await;
    let note = |tags: Value, content: String| {
        sign_event(json!({"created_at": now(), "kind": 1, "tags": tags, "content": content}))
    };
    let protected = note(json!([["-"]]), "members only".into());
    let protected_text = protected.to_string();
    // The protected event with one more member, ahead of the others.
    let with = |member: &str| format!("{{{member},{}", &protected_text[1..]);
    let embedded = [
        ("compact", protected_text.clone()),
        ("pretty", serde_json::to_string_pretty(&protected).unwrap()),
        ("leading whitespace", format!("\n  {protected_text}")),
        (
            "spaced tag",
            protected_text.replace(r#"[["-"]]"#, r#"[ [ "-" ] ]"#),
        ),
        (
            "tag with a value",
            note(json!([["-", ""]]), "members only".into()).to_string(),
        ),
        (
            "not the first tag",
            note(json!([["t", "x"], ["-"]]), "members only".into()).to_string(),
        ),
        // What `JSON.parse` reads as the protected event but the relay's
        // strict parser refuses.
        (
            "repeated key",
            with(&format!(r#""id":{}"#, protected["id"])),
        ),
        // `JSON.parse` keeps the last `tags`, the protected one.
        ("repeated tags", with(r#""tags":[]"#)),
        (
            "deep extra member",
            with(&format!(r#""x":{}0{}"#, "[".repeat(130), "]".repeat(130))),
        ),
        ("lone surrogate", with(r#""x":"\ud800""#)),
        (
            "leading whitespace, lone surrogate",
            format!(" \t\r\n{}", with(r#""x":"\ud800""#)),
        ),
        ("huge number", with(r#""x":1e400"#)),
        ("malformed", format!("{{{protected_text}")),
        (
            "huge",
            note(json!([["-"]]), "x".repeat(600_000)).to_string(),
        ),
    ];
    let not_embedded = [
        (
            "text",
            r#"not an event, though it mentions ["-"]"#.to_string(),
        ),
        ("empty", String::new()),
        ("array", r#"[["-"]]"#.to_string()),
        (
            "unprotected",
            note(json!([["t", "x"]]), "public".into()).to_string(),
        ),
        (
            "\"-\" only in the content",
            note(json!([]), r#"[["-"]]"#.into()).to_string(),
        ),
        (
            "\"-\" only as a value",
            note(json!([["t", "-"]]), "public".into()).to_string(),
        ),
        (
            "object without tags",
            r#"{"content":"[\"-\"]"}"#.to_string(),
        ),
        ("not an object", format!("}}{protected_text}")),
        (
            "huge unprotected",
            note(json!([["t", "x"]]), "x".repeat(600_000)).to_string(),
        ),
        ("huge text", r#"["-"] "#.repeat(100_000)),
    ];
    for kind in wok_event::REPOST_KINDS {
        let repost = |content: &str| {
            sign_event(json!({
                "created_at": now(), "kind": kind, "tags": [["e", protected["id"]]],
                "content": content,
            }))
        };
        for (label, content) in &embedded {
            let event = repost(content);
            assert_eq!(
                conn.publish(&event).await,
                json!([
                    "OK",
                    event["id"],
                    false,
                    "blocked: reposts can't embed protected events"
                ]),
                "kind {kind}, {label}"
            );
        }
        for (label, content) in &not_embedded {
            let reply = conn.publish(&repost(content)).await;
            assert_eq!(reply[2], true, "kind {kind}, {label}: {reply}");
        }
    }
    // Only reposts are checked.
    let quote = note(json!([]), protected_text);
    assert_eq!(conn.publish(&quote).await[2], true);
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip42_relay_tag_must_name_the_relay_path() {
    // Relays that share a host by path must not accept each other's AUTH, so
    // one cannot pass on its challenge to sign in as a user of the other.
    let relay = Relay::new(|cfg| cfg.relay.auth.service_url = "wss://host.test/relayA".into());
    for (tag, accepted) in [
        ("wss://host.test/relayA", true),
        ("wss://Host.Test:443/relayA/", true),
        ("wss://host.test/relayA?client=x", true),
        ("wss://host.test/relayB", false),
        ("wss://host.test", false),
        ("wss://host.test/relayA/sub", false),
    ] {
        let mut conn = relay.connect().await;
        let challenge = conn.recv().await;
        assert_eq!(challenge[0], "AUTH", "{challenge}");
        let reply = conn.answer_for(tag, &key(), &challenge, now()).await;
        assert_eq!(reply[2], accepted, "{tag}: {reply}");
        if !accepted {
            assert_eq!(
                reply[3], "error: incorrect or missing relay tag, expected: wss://host.test/relayA",
                "{tag}: {reply}"
            );
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
    assert_eq!(nips, vec![1, 9, 11, 40, 45, 50, 62, 67, 70, 77, 91]);
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip78_app_data_is_served_to_and_accepted_from_its_author_only() {
    let relay = auth_relay();
    assert!(wok_relay::supported_nips(&relay.handle.config.read()).contains(&78));
    let (owner, stranger_key) = (key(), key());
    for kind in wok_event::APP_DATA_KINDS {
        let settings = |content: &str| {
            sign_event_with_key(
                json!({
                    "created_at": now(),
                    "kind": kind,
                    "tags": [["d", "example-app/settings"]],
                    "content": content,
                }),
                &owner,
            )
        };
        // NIP-78: relays SHOULD require AUTH before accepting app data.
        let mut app = relay.connect().await;
        let challenge = app.recv().await;
        assert_eq!(challenge[0], "AUTH", "{challenge}");
        let early = settings("before AUTH");
        let refused = app.publish(&early).await;
        assert_eq!(refused[2], false, "{refused}");
        assert_eq!(
            refused[3],
            format!("auth-required: kind {kind} is accepted only from its author")
        );
        assert_eq!(app.answer(&owner, &challenge, now()).await[2], true);
        let data = settings("after AUTH");
        assert_eq!(app.publish(&data).await[2], true);

        // Authenticated as another key, the author's event is refused.
        let mut stranger = relay.connect().await;
        stranger.auth(&stranger_key).await;
        let relayed = stranger.publish(&settings("relayed")).await;
        assert_eq!(relayed[2], false, "{relayed}");
        assert_eq!(relayed[3], "restricted: must be published by the author");

        // ... and served only to the author.
        let mine = json!({"kinds": [kind], "authors": [pubkey_hex(&owner)]});
        assert_eq!(app.history(mine.clone()).await, std::slice::from_ref(&data));
        assert_eq!(stranger.history(mine.clone()).await, Vec::<Value>::new());
        let mut anonymous = relay.connect().await;
        assert_eq!(anonymous.recv().await[0], "AUTH");
        anonymous.send(json!(["REQ", "data", mine])).await;
        let closed = anonymous.recv().await;
        assert_eq!(closed[0], "CLOSED", "{closed}");
        assert!(
            closed[2].as_str().unwrap().starts_with("auth-required:"),
            "{closed}"
        );
        // A REQ that mixes in an open kind is served without it.
        let (events, _, _) = anonymous
            .backfill("mixed", json!([{"authors": [pubkey_hex(&owner)]}]))
            .await;
        assert!(events.is_empty(), "{events:?}");
    }
}

/// Kind-`kind` events, a second apart, the newest now.
async fn publish_notes(conn: &mut Conn, kind: u64, count: u64) -> Vec<Value> {
    let mut events = Vec::new();
    for i in (0..count).rev() {
        let event = sign_event(json!({
            "created_at": now() - i,
            "kind": kind,
            "tags": [],
            "content": format!("{kind}/{i}"),
        }));
        assert_eq!(conn.publish(&event).await[2], true);
        events.push(event);
    }
    events
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip67_finish_once_every_stored_match_was_sent() {
    let relay = Relay::new(|_| {});
    let mut conn = relay.connect().await;
    publish_notes(&mut conn, 1, 3).await;

    let (events, _, eose) = conn.backfill("all", json!([{"kinds": [1]}])).await;
    assert_eq!(events.len(), 3);
    assert_eq!(eose, json!(["EOSE", "all", ["finish"]]));
    // Exactly `limit` matches: the limit cut nothing.
    let (events, _, eose) = conn
        .backfill("three", json!([{"kinds": [1], "limit": 3}]))
        .await;
    assert_eq!(events.len(), 3);
    assert_eq!(eose, json!(["EOSE", "three", ["finish"]]));
    // Filters with an empty list match nothing, so nothing is left.
    let (events, _, eose) = conn
        .backfill("empty", json!([{"kinds": []}, {"#p": []}]))
        .await;
    assert!(events.is_empty());
    assert_eq!(eose, json!(["EOSE", "empty", ["finish"]]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip67_more_when_a_limit_or_the_request_ceiling_leaves_matches() {
    let relay = Relay::new(|cfg| {
        cfg.relay.max_filter_limit = 4;
        cfg.relay.max_total_events_per_req = 5;
    });
    let mut conn = relay.connect().await;
    let notes = publish_notes(&mut conn, 1, 3).await;
    publish_notes(&mut conn, 7, 3).await;

    // The client's limit.
    let (events, _, eose) = conn
        .backfill("limit", json!([{"kinds": [1], "limit": 2}]))
        .await;
    assert_eq!(events.len(), 2);
    assert_eq!(eose, json!(["EOSE", "limit", ["more"]]));
    // The relay's clamp of it, `relay.max_filter_limit`.
    let (events, _, eose) = conn.backfill("clamp", json!([{"kinds": [1, 7]}])).await;
    assert_eq!(events.len(), 4);
    assert_eq!(eose, json!(["EOSE", "clamp", ["more"]]));
    // `relay.max_total_events_per_req` across filters.
    let (events, _, eose) = conn
        .backfill("ceiling", json!([{"kinds": [1]}, {"kinds": [7]}]))
        .await;
    assert_eq!(events.len(), 5);
    assert_eq!(eose, json!(["EOSE", "ceiling", ["more"]]));
    // The ceiling reached by exactly the matches there are.
    let since = notes[1]["created_at"].clone();
    let (events, _, eose) = conn
        .backfill(
            "exact",
            json!([{"kinds": [7]}, {"kinds": [1], "since": since}]),
        )
        .await;
    assert_eq!(events.len(), 5);
    assert_eq!(eose, json!(["EOSE", "exact", ["finish"]]));
    // `limit: 0` asks for no stored events: no hints.
    let (events, _, eose) = conn
        .backfill("zero", json!([{"kinds": [1], "limit": 0}]))
        .await;
    assert!(events.is_empty());
    assert_eq!(eose, json!(["EOSE", "zero"]));
}

/// A note and a kind 4 to `recipient`, by different authors.
async fn publish_note_and_dm(relay: &Relay, recipient: &Keypair) -> (Value, Value) {
    let mut publisher = relay.connect().await;
    let note = sign_event(json!({"created_at": now(), "kind": 1, "tags": [], "content": "hi"}));
    let dm = sign_event(json!({
        "created_at": now() - 1,
        "kind": 4,
        "tags": [["p", pubkey_hex(recipient)]],
        "content": "ciphertext",
    }));
    if relay.handle.config.read().auth_usable() {
        assert_eq!(publisher.recv().await[0], "AUTH");
    }
    for event in [&note, &dm] {
        assert_eq!(publisher.publish(event).await[2], true);
    }
    (note, dm)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip67_auth_follows_a_challenge_until_authenticated_as_the_recipient() {
    let relay = auth_relay();
    let recipient = key();
    let (note, dm) = publish_note_and_dm(&relay, &recipient).await;

    let mut reader = relay.connect().await;
    // NIP-67: the challenge comes before an EOSE with `auth`.
    let challenge = reader.recv().await;
    assert_eq!(challenge[0], "AUTH", "{challenge}");
    let (events, other, eose) = reader.backfill("mixed", json!([{"kinds": [1, 4]}])).await;
    assert_eq!((events, other), (vec![note.clone()], vec![]));
    assert_eq!(eose, json!(["EOSE", "mixed", ["auth", "finish"]]));
    // What a REQ that cannot match a restricted kind leaves hidden is nothing.
    let (_, _, eose) = reader.backfill("public", json!([{"kinds": [1]}])).await;
    assert_eq!(eose, json!(["EOSE", "public", ["finish"]]));

    let auth = sign_event_with_key(
        json!({
            "created_at": now(),
            "kind": 22242,
            "tags": [["relay", AUTH_RELAY], ["challenge", challenge[1]]],
            "content": "",
        }),
        &recipient,
    );
    reader.send(json!(["AUTH", auth])).await;
    assert_eq!(reader.recv().await[2], true);
    let (events, _, eose) = reader.backfill("mixed", json!([{"kinds": [1, 4]}])).await;
    assert_eq!(events, [note, dm]);
    assert_eq!(eose, json!(["EOSE", "mixed", ["finish"]]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip67_auth_waits_for_usable_auth_and_its_challenge() {
    // The DM is stored while AUTH is usable, as it is refused otherwise.
    let relay = auth_relay();
    let recipient = key();
    let (note, _) = publish_note_and_dm(&relay, &recipient).await;

    // A reload makes AUTH unusable: no challenge on connect, and no `auth`
    // hint.
    relay.handle.config.write().relay.auth.service_url.clear();
    let mut reader = relay.connect().await;
    let (events, other, eose) = reader.backfill("mixed", json!([{"kinds": [1, 4]}])).await;
    assert_eq!((events, other), (vec![note.clone()], vec![]));
    assert_eq!(eose, json!(["EOSE", "mixed", ["finish"]]));

    // Once a reload makes it usable, the connection gets its challenge ahead
    // of the EOSE that names `auth`.
    relay.handle.config.write().relay.auth.service_url = AUTH_RELAY.into();
    let (events, other, eose) = reader.backfill("mixed", json!([{"kinds": [1, 4]}])).await;
    assert_eq!(events, [note]);
    assert_eq!(other.len(), 1, "{other:?}");
    assert_eq!(other[0][0], "AUTH", "{other:?}");
    assert_eq!(eose, json!(["EOSE", "mixed", ["auth", "finish"]]));
}

/// Store `event` straight to LMDB with its payload compressed, as a relay
/// with a trained dictionary and a larger `events.max_event_size` would have.
fn store_compressed(env: &wok_db::Env, event: &Value) {
    let parsed = parse_and_verify_event(event, &EventLimits::default(), None, true, false).unwrap();
    let json = parsed.json.clone();
    let mut txn = env.begin_rw().unwrap();
    let mut events = vec![wok_db::EventToWrite::new(
        parsed.packed.into_bytes(),
        parsed.json,
    )];
    wok_db::write_events(&mut txn, &mut wok_db::NoopNegentropy, &mut events, false).unwrap();
    let dict = br#"{"content":"xxxxxxxxxxxxxxxx","kind":1,"tags":[]}"#.repeat(32);
    let dict_id = wok_db::insert_compression_dictionary(&mut txn, &dict).unwrap();
    let compressed = zstd::bulk::Compressor::with_dictionary(3, &dict)
        .unwrap()
        .compress(json.as_bytes())
        .unwrap();
    let payload = wok_db::encode_zstd_payload(u32::try_from(dict_id).unwrap(), &compressed);
    let event_payload = txn.env().dbis().event_payload;
    txn.put_u64(event_payload, events[0].lev_id, &payload, 0)
        .unwrap();
    txn.commit().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nip67_no_finish_when_a_stored_event_could_not_be_sent() {
    // A compressed payload larger than a lowered `events.max_event_size`
    // cannot be decoded, so the relay skips the event. EOSE must not then
    // say that every stored match was sent.
    let relay = Relay::new(|cfg| cfg.events.max_event_size = 65_536);
    let large = sign_event(json!({
        "created_at": now() - 10,
        "kind": 1,
        "tags": [],
        "content": "x".repeat(70_000),
    }));
    store_compressed(&relay.env, &large);
    let mut conn = relay.connect().await;
    let small = publish_notes(&mut conn, 1, 1).await;

    let (events, _, eose) = conn.backfill("s", json!([{"kinds": [1]}])).await;
    assert_eq!(events, small);
    assert_eq!(eose, json!(["EOSE", "s"]));
    // Without the large event, the same REQ is finished.
    let (_, _, eose) = conn
        .backfill("t", json!([{"kinds": [1], "since": now() - 5}]))
        .await;
    assert_eq!(eose, json!(["EOSE", "t", ["finish"]]));
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
    let tested = [
        1u64, 9, 11, 13, 40, 42, 45, 50, 59, 62, 67, 70, 77, 78, 86, 91,
    ];
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
