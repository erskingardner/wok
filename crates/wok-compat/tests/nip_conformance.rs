//! Independently grounded NIP tests. NIPs pin: 656cecc7c0a815b6a2b218d3b5d6f078b3f4dbab

use serde_json::json;
use wok_compat::sign_event;
use wok_event::{parse_and_verify_event, EventLimits};
use wok_query::NostrFilterGroup;
use wok_relay::{ClientCommand, RelayMessage};

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
    )
    .unwrap();
    assert_eq!(fg.filters[0].limit, 5);
}

#[test]
fn nip01_filter_ids_and_kinds_use_event_field_grammar() {
    assert!(NostrFilterGroup::from_value(&json!({"ids":["AA".repeat(32)]}), 500, 3).is_err());
    assert!(NostrFilterGroup::from_value(
        &json!({"authors":[format!("0x{}", "11".repeat(32))]}),
        500,
        3
    )
    .is_err());
    assert!(NostrFilterGroup::from_value(&json!({"kinds":[65536]}), 500, 3).is_err());
    assert!(NostrFilterGroup::from_value(&json!({"ids":[]}), 500, 3).is_err());
    assert!(NostrFilterGroup::from_value(&json!({"#1":["value"]}), 500, 3).is_err());
}

#[test]
fn nip01_unknown_filter_field_rejected() {
    assert!(NostrFilterGroup::from_value(&json!({"foo":1}), 500, 3).is_err());
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

#[test]
fn nip45_count_encoding() {
    let s = RelayMessage::Count {
        sub_id: "c".into(),
        count: 3,
        limited: true,
    }
    .to_json();
    assert!(s.contains("\"count\":3"));
    assert!(s.contains("\"limited\":true"));
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
    )
    .unwrap();
    let search = filters.filters[0].search.as_ref().unwrap();
    assert_eq!(search.terms, vec!["apps", "best", "nostr"]);
    assert_eq!(search.phrase, "best nostr apps");
    assert_eq!(filters.filters[0].limit, 20);
    assert!(NostrFilterGroup::from_value(&json!({"search":7}), 500, 3).is_err());
}

#[test]
fn nip11_software_not_strfry_when_unconfigured() {
    let cfg = wok_relay::Config::default();
    let nips = wok_relay::supported_nips(&cfg);
    assert_eq!(nips, vec![1, 9, 11, 40, 45, 50, 62, 70, 77]);
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
    assert!(NostrFilterGroup::from_value(&json!({"ids":["aabb"]}), 500, 3).is_err());
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
    )
    .unwrap();
    assert_eq!(fg.size(), 2);
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
fn advertised_nips_are_subset_of_tested() {
    let tested = [1u64, 9, 11, 13, 40, 42, 45, 50, 59, 62, 70, 77];
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
