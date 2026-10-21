//! `wok_Event__tagKind` stays equal to `Event__tag` keyed by kind through
//! every write and deletion path, reindex rebuilds it, and integrity reports
//! the entries that do not match.

use secp256k1::{Keypair, SECP256K1};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use tempfile::TempDir;
use wok_db::keys::parse_key_string_u64;
use wok_db::{
    check_integrity, delete_events, get_packed_ro, rebuild_primary_and_event_indices,
    sweep_vanished_events, tag_kind_index_state_ro, tag_kind_key, write_events_with_policy, Env,
    EnvOptions, EventToWrite, EventWriteStatus, NoopNegentropy, PackedEventRebuild, VanishPolicy,
};
use wok_event::PackedEventView;

type Postings = BTreeSet<(Vec<u8>, u64)>;

fn signed(key: &Keypair, kind: u64, created_at: u64, tags: Value) -> ([u8; 32], EventToWrite) {
    let (pubkey, _) = key.x_only_public_key();
    let mut event = json!({
        "created_at": created_at,
        "kind": kind,
        "tags": tags,
        "content": "tag-kind fixture",
        "pubkey": hex::encode(pubkey.serialize()),
    });
    let id = wok_event::event_id_hash(&event).unwrap();
    event["id"] = json!(hex::encode(id));
    event["sig"] = json!(hex::encode(SECP256K1.sign_schnorr(&id, key).as_ref()));
    let parsed =
        wok_event::parse_and_verify_event(&event, &Default::default(), None, true, false).unwrap();
    (
        id,
        EventToWrite::new(parsed.packed.into_bytes(), parsed.json),
    )
}

fn pubkey_hex(key: &Keypair) -> String {
    hex::encode(key.x_only_public_key().0.serialize())
}

fn open(dir: &TempDir) -> Env {
    let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    env
}

fn write(env: &Env, events: &mut [EventToWrite]) {
    let policy = VanishPolicy {
        enabled: true,
        service_url: "wss://relay.example.com/".into(),
    };
    let mut txn = env.begin_rw().unwrap();
    write_events_with_policy(&mut txn, &mut NoopNegentropy, events, false, &policy).unwrap();
    txn.commit().unwrap();
    for event in events {
        assert_eq!(event.status, EventWriteStatus::Written);
    }
}

fn stored(env: &Env, lev_id: u64) -> bool {
    get_packed_ro(&env.begin_ro().unwrap(), lev_id)
        .unwrap()
        .is_some()
}

/// What the table must hold, derived independently: one posting per
/// `Event__tag` entry, under the kind of the event it names.
fn expected_postings(env: &Env) -> Postings {
    let txn = env.begin_ro().unwrap();
    let mut postings = Postings::new();
    txn.foreach_full(env.dbis().event_tag, &[], &[], false, |key, value| {
        let lev_id = u64::from_ne_bytes(value.try_into().unwrap());
        let (tag, created_at) = parse_key_string_u64(key).unwrap();
        let packed = get_packed_ro(&txn, lev_id).unwrap().unwrap();
        let kind = PackedEventView::new(&packed).unwrap().kind();
        postings.insert((tag_kind_key(tag[0], &tag[1..], kind, created_at), lev_id));
        true
    })
    .unwrap();
    postings
}

/// The postings stored, without the two markers (keys under 16 bytes).
fn stored_postings(env: &Env) -> Postings {
    let txn = env.begin_ro().unwrap();
    let mut postings = Postings::new();
    txn.foreach_full(
        env.dbis().event_tag_kind.unwrap(),
        &[],
        &[],
        false,
        |key, value| {
            if key.len() >= 16 {
                postings.insert((key.to_vec(), u64::from_ne_bytes(value.try_into().unwrap())));
            }
            true
        },
    )
    .unwrap();
    postings
}

fn tag_kind_keys(packed: &[u8]) -> Vec<Vec<u8>> {
    let view = PackedEventView::new(packed).unwrap();
    let mut keys = Vec::new();
    view.foreach_tag(|name, value| {
        keys.push(tag_kind_key(
            name as u8,
            value,
            view.kind(),
            view.created_at(),
        ));
        true
    });
    keys
}

/// The table matches the tag index, is complete, and integrity agrees.
fn assert_consistent(env: &Env) {
    assert_eq!(stored_postings(env), expected_postings(env));
    let txn = env.begin_ro().unwrap();
    let state = tag_kind_index_state_ro(&txn).unwrap().unwrap();
    assert!(state.complete(), "{state:?}");
    assert_eq!(state.indexed_through, state.high_water);
    let report = check_integrity(&txn).unwrap();
    assert!(report.ok(), "{:#?}", report.issues);
    let tag_kind = report.tag_kind_index.unwrap();
    assert_eq!(tag_kind.stale_entries, 0);
    assert_eq!(tag_kind.expected_entries, tag_kind.actual_entries);
}

#[test]
fn every_write_and_deletion_path_keeps_the_index_equal_to_the_tag_index() {
    let dir = TempDir::new().unwrap();
    let env = open(&dir);
    assert_consistent(&env);
    let mut rng = rand::thread_rng();
    let alice = Keypair::new(SECP256K1, &mut rng);
    let bob = Keypair::new(SECP256K1, &mut rng);
    let sender = Keypair::new(SECP256K1, &mut rng);
    let alice_hex = pubkey_hex(&alice);
    let bob_hex = pubkey_hex(&bob);
    let long_url = format!("https://example.com/{}", "r".repeat(300));

    // Inserts: tags of several kinds, a hashed long value, the virtual `d` of
    // a replaceable kind, an addressable event, a gift wrap and an expiring
    // event.
    let (note_id, note) = signed(
        &alice,
        1,
        1_000,
        json!([
            ["t", "nostr"],
            ["t", "rust"],
            ["p", &bob_hex],
            ["r", &long_url]
        ]),
    );
    let (_, reaction) = signed(
        &bob,
        7,
        1_001,
        json!([["e", hex::encode(note_id)], ["p", &alice_hex], ["k", "1"]]),
    );
    let (_, zap) = signed(
        &bob,
        9735,
        1_002,
        json!([
            ["e", hex::encode(note_id)],
            ["p", &alice_hex],
            ["P", &bob_hex]
        ]),
    );
    let (gift_id, gift) = signed(&sender, 1059, 1_003, json!([["p", &alice_hex]]));
    let (_, profile) = signed(&alice, 0, 1_004, json!([]));
    let (_, article) = signed(&alice, 30023, 1_005, json!([["d", "post"], ["t", "nostr"]]));
    let (_, expiring) = signed(
        &alice,
        1,
        1_006,
        json!([["t", "soon"], ["expiration", "4000000000"]]),
    );
    let (_, bob_note) = signed(&bob, 1, 1_007, json!([["t", "nostr"], ["p", &alice_hex]]));
    let mut events = [
        note, reaction, zap, gift, profile, article, expiring, bob_note,
    ];
    write(&env, &mut events);
    let lev = |i: usize| events[i].lev_id;
    // An addressable event also packs a virtual empty `d` after its tags.
    assert_eq!(expected_postings(&env).len(), 18);
    assert_consistent(&env);

    // Replacement of a replaceable and an addressable event.
    let (_, profile) = signed(&alice, 0, 2_000, json!([["t", "profile"]]));
    let (_, article) = signed(
        &alice,
        30023,
        2_001,
        json!([["d", "post"], ["t", "edited"]]),
    );
    let mut replacements = [profile, article];
    write(&env, &mut replacements);
    assert!(!stored(&env, lev(4)) && !stored(&env, lev(5)));
    assert_consistent(&env);

    // NIP-09: by id, by address, and a gift wrap deleted by its recipient.
    let address = format!("30023:{alice_hex}:post");
    let (_, by_id) = signed(&alice, 5, 3_000, json!([["e", hex::encode(note_id)]]));
    let (_, by_address) = signed(&alice, 5, 3_001, json!([["a", &address]]));
    let (_, by_recipient) = signed(&alice, 5, 3_002, json!([["e", hex::encode(gift_id)]]));
    let mut deletions = [by_id, by_address, by_recipient];
    write(&env, &mut deletions);
    assert!(!stored(&env, lev(0)) && !stored(&env, lev(3)));
    assert!(!stored(&env, replacements[1].lev_id));
    assert_consistent(&env);

    // NIP-40 expiry, as the relay's maintenance deletes it.
    let mut expired = Vec::new();
    {
        let txn = env.begin_ro().unwrap();
        txn.foreach_full(env.dbis().event_expiration, &[], &[], false, |_, value| {
            expired.push(u64::from_ne_bytes(value.try_into().unwrap()));
            true
        })
        .unwrap();
    }
    assert_eq!(expired, [lev(6)]);
    let mut txn = env.begin_rw().unwrap();
    assert_eq!(
        delete_events(&mut txn, &mut NoopNegentropy, expired).unwrap(),
        1
    );
    txn.commit().unwrap();
    assert_consistent(&env);

    // NIP-62: the request deletes Bob's earlier events in the sweep.
    let (_, vanish) = signed(&bob, 62, 4_000, json!([["relay", "ALL_RELAYS"]]));
    let mut vanish = [vanish];
    write(&env, &mut vanish);
    let mut cursor = Vec::new();
    let mut txn = env.begin_rw().unwrap();
    let swept = sweep_vanished_events(&mut txn, &mut NoopNegentropy, 100, &mut cursor).unwrap();
    txn.commit().unwrap();
    assert_eq!(swept, 3);
    assert!(!stored(&env, lev(1)) && !stored(&env, lev(2)) && !stored(&env, lev(7)));
    assert_consistent(&env);
}

/// A database whose table has a stale, a missing and an unexpected entry,
/// and the postings it holds without them.
fn drifted_database(dir: &TempDir) -> (Env, Postings) {
    let env = open(dir);
    let mut rng = rand::thread_rng();
    let author = Keypair::new(SECP256K1, &mut rng);
    let other = pubkey_hex(&Keypair::new(SECP256K1, &mut rng));
    let mut events = Vec::new();
    for i in 0..6 {
        let (_, event) = signed(
            &author,
            [1, 7, 1059][i % 3],
            1_000 + i as u64,
            json!([["p", &other], ["t", format!("t{i}")]]),
        );
        events.push(event);
    }
    write(&env, &mut events);
    let deleted = &events[1];
    let mut txn = env.begin_rw().unwrap();
    delete_events(&mut txn, &mut NoopNegentropy, [deleted.lev_id]).unwrap();
    txn.commit().unwrap();
    assert_consistent(&env);
    let clean = stored_postings(&env);

    let dbi = env.dbis().event_tag_kind.unwrap();
    let mut txn = env.begin_rw().unwrap();
    // An earlier release deleting an event leaves its entries.
    for key in tag_kind_keys(&deleted.packed) {
        txn.put(dbi, &key, &deleted.lev_id.to_ne_bytes(), 0)
            .unwrap();
    }
    // An entry a stored event lacks.
    let missing = &events[2];
    let key = &tag_kind_keys(&missing.packed)[0];
    assert!(txn
        .del(dbi, key, Some(&missing.lev_id.to_ne_bytes()))
        .unwrap());
    // An entry a stored event does not derive: the right tag, another kind.
    let view = PackedEventView::new(&events[3].packed).unwrap();
    let unexpected = tag_kind_key(b't', b"t3", 30023, view.created_at());
    txn.put(dbi, &unexpected, &events[3].lev_id.to_ne_bytes(), 0)
        .unwrap();
    txn.commit().unwrap();
    (env, clean)
}

#[test]
fn integrity_reports_missing_stale_and_unexpected_entries() {
    let dir = TempDir::new().unwrap();
    let (env, _) = drifted_database(&dir);
    let report = check_integrity(&env.begin_ro().unwrap()).unwrap();
    assert!(!report.ok());
    let tag_kind = report.tag_kind_index.as_ref().unwrap();
    assert!(tag_kind.complete);
    assert_eq!(tag_kind.missing_entries, 1, "{tag_kind:?}");
    assert_eq!(tag_kind.unexpected_entries, 1, "{tag_kind:?}");
    assert_eq!(tag_kind.stale_entries, 2, "{tag_kind:?}");
    for category in ["missing-index", "unexpected-index", "stale-index"] {
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.category == category && issue.table == "event_tag_kind"),
            "{category}: {:#?}",
            report.issues
        );
    }
    // The other indexes are intact.
    assert_eq!(report.missing_index_entries, 0);
    assert_eq!(report.extra_index_entries, 0);
}

#[test]
fn stale_entries_alone_leave_the_database_healthy() {
    let dir = TempDir::new().unwrap();
    let env = open(&dir);
    let author = Keypair::new(SECP256K1, &mut rand::thread_rng());
    let (_, event) = signed(&author, 1059, 1_000, json!([["p", "11".repeat(32)]]));
    let mut events = [event];
    write(&env, &mut events);
    let mut txn = env.begin_rw().unwrap();
    delete_events(&mut txn, &mut NoopNegentropy, [events[0].lev_id]).unwrap();
    for key in tag_kind_keys(&events[0].packed) {
        txn.put(
            env.dbis().event_tag_kind.unwrap(),
            &key,
            &events[0].lev_id.to_ne_bytes(),
            0,
        )
        .unwrap();
    }
    txn.commit().unwrap();
    let report = check_integrity(&env.begin_ro().unwrap()).unwrap();
    assert!(report.ok(), "{:#?}", report.issues);
    let tag_kind = report.tag_kind_index.unwrap();
    assert_eq!((tag_kind.stale_entries, tag_kind.actual_entries), (1, 1));
    assert!(tag_kind.complete);
}

#[test]
fn reindex_rebuilds_the_index_the_write_path_keeps() {
    let dir = TempDir::new().unwrap();
    let (source, clean) = drifted_database(&dir);
    let target_dir = TempDir::new().unwrap();
    let target = open(&target_dir);
    let mut txn = target.begin_rw().unwrap();
    rebuild_primary_and_event_indices(
        &source.begin_ro().unwrap(),
        &mut txn,
        PackedEventRebuild::RepackLongTags,
    )
    .unwrap();
    txn.commit().unwrap();

    assert_eq!(stored_postings(&target), clean);
    assert_consistent(&target);
    let txn = target.begin_ro().unwrap();
    let state = tag_kind_index_state_ro(&txn).unwrap().unwrap();
    let source_state = tag_kind_index_state_ro(&source.begin_ro().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(state.high_water, source_state.high_water);
}
