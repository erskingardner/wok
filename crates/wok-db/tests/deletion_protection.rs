//! NIP-D9 (nips#2531 at 56fd367): stored, imported, and republished copies.

use secp256k1::{Keypair, SECP256K1};
use serde_json::{json, Value};
use wok_db::{
    check_integrity, delete_events, is_event_vanished_ro, lookup_event_by_id_ro,
    sweep_vanished_events, write_events_with_policy, Env, EnvOptions, EventToWrite,
    EventWriteStatus, NoopNegentropy, VanishPolicy,
};
use wok_event::{parse_and_verify_event, EventLimits, PackedEventView};

fn key() -> Keypair {
    Keypair::new(SECP256K1, &mut rand::thread_rng())
}

fn signed(key: &Keypair, kind: u64, created_at: u64, tags: Value) -> EventToWrite {
    let mut event = json!({
        "pubkey": hex::encode(key.x_only_public_key().0.serialize()),
        "created_at": created_at, "kind": kind, "tags": tags, "content": "history",
    });
    let id = wok_event::event_id_hash(&event).unwrap();
    event["id"] = json!(hex::encode(id));
    event["sig"] = json!(hex::encode(SECP256K1.sign_schnorr(&id, key).as_ref()));
    let parsed =
        parse_and_verify_event(&event, &EventLimits::default(), None, true, false).unwrap();
    EventToWrite::new(parsed.packed.into_bytes(), parsed.json)
}

fn id(event: &EventToWrite) -> String {
    hex::encode(PackedEventView::new(&event.packed).unwrap().id())
}

fn write(env: &Env, event: &mut EventToWrite) {
    let mut txn = env.begin_rw().unwrap();
    write_events_with_policy(
        &mut txn,
        &mut NoopNegentropy,
        std::slice::from_mut(event),
        false,
        &VanishPolicy {
            enabled: true,
            service_url: "wss://relay.example/".into(),
        },
    )
    .unwrap();
    txn.commit().unwrap();
}

fn stored(env: &Env, event: &EventToWrite) -> Option<u64> {
    lookup_event_by_id_ro(
        &env.begin_ro().unwrap(),
        PackedEventView::new(&event.packed).unwrap().id(),
    )
    .unwrap()
    .map(|(lev, _)| lev)
}

fn sweep(env: &Env) {
    let mut cursor = Default::default();
    for _ in 0..100 {
        let mut txn = env.begin_rw().unwrap();
        let step = sweep_vanished_events(&mut txn, &mut NoopNegentropy, 1, &mut cursor).unwrap();
        assert!(step.examined <= 1 && step.deleted <= 1);
        txn.commit().unwrap();
        if step.markers == 0 {
            return;
        }
    }
    panic!("bounded sweep did not finish");
}

#[test]
fn same_author_deletion_exempts_only_marked_targets_in_both_arrival_orders() {
    for deletion_first in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let author = key();
        let pubkey = hex::encode(author.x_only_public_key().0.serialize());
        let mut marked = signed(&author, 445, 100, json!([["no_delete"]]));
        let mut plain = signed(&author, 1, 100, json!([]));
        let mut replaceable = signed(&author, 10002, 100, json!([]));
        let mut addressable = signed(&author, 30023, 100, json!([["d", "article"]]));
        let mut deletion = signed(
            &author,
            5,
            200,
            json!([
                ["no_delete"],
                ["e", id(&marked)],
                ["e", id(&plain)],
                ["a", format!("10002:{pubkey}:")],
                ["a", format!("30023:{pubkey}:article")],
            ]),
        );
        if deletion_first {
            write(&env, &mut deletion);
        }
        for event in [&mut marked, &mut plain, &mut replaceable, &mut addressable] {
            write(&env, event);
        }
        if !deletion_first {
            write(&env, &mut deletion);
        }
        assert!(stored(&env, &marked).is_some());
        for event in [&plain, &replaceable, &addressable] {
            assert!(stored(&env, event).is_none());
        }
        // Neither the request's own marker nor the tombstone affects the
        // target's identity or its eligibility for byte-identical republication.
        let lev = stored(&env, &marked).unwrap();
        let mut txn = env.begin_rw().unwrap();
        delete_events(&mut txn, &mut NoopNegentropy, [lev]).unwrap();
        txn.commit().unwrap();
        marked.status = EventWriteStatus::Pending;
        write(&env, &mut marked);
        assert_eq!(marked.status, EventWriteStatus::Written);
        assert!(check_integrity(&env.begin_ro().unwrap()).unwrap().ok());
    }
}

#[test]
fn vanish_keeps_marked_history_after_sweep_restart_and_republication() {
    for request_first in [false, true] {
        for relay in ["ALL_RELAYS", "wss://relay.example/"] {
            let dir = tempfile::tempdir().unwrap();
            let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
            env.ensure_initialized().unwrap();
            let author = key();
            let mut marked = signed(&author, 445, 100, json!([["no_delete"]]));
            let mut expired = signed(
                &author,
                1,
                100,
                json!([["no_delete"], ["expiration", "150"]]),
            );
            let mut marked_request = signed(&author, 5, 100, json!([["no_delete"]]));
            let mut plain = signed(&author, 1, 100, json!([]));
            let mut vanish = signed(&author, 62, 200, json!([["relay", relay], ["no_delete"]]));
            if request_first {
                write(&env, &mut vanish);
            }
            for event in [&mut marked, &mut expired, &mut marked_request, &mut plain] {
                write(&env, event);
            }
            if !request_first {
                write(&env, &mut vanish);
            }
            for event in [&marked, &expired, &marked_request] {
                assert!(stored(&env, event).is_some());
                let txn = env.begin_ro().unwrap();
                assert!(
                    !is_event_vanished_ro(&txn, PackedEventView::new(&event.packed).unwrap())
                        .unwrap()
                );
            }
            sweep(&env);
            assert!(stored(&env, &plain).is_none());
            assert!(
                stored(&env, &expired).is_some(),
                "expiry does not authorize request-based erasure"
            );
            drop(env);
            let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
            sweep(&env);
            assert!(stored(&env, &marked_request).is_some());
            // A completed sweep must also accept protected events it has
            // never seen, with timestamps within the existing author cutoff.
            let mut backfill = signed(&author, 1, 90, json!([["no_delete"]]));
            write(&env, &mut backfill);
            assert_eq!(backfill.status, EventWriteStatus::Written);
            assert!(check_integrity(&env.begin_ro().unwrap()).unwrap().ok());
        }
    }
}

#[test]
fn gift_wrap_recipient_authority_overrides_marker_even_when_recipient_is_signer() {
    for same_key in [false, true] {
        for (kind, explicit_id) in [(5, false), (5, true), (62, false)] {
            let dir = tempfile::tempdir().unwrap();
            let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
            env.ensure_initialized().unwrap();
            let recipient = key();
            let sender = if same_key { recipient } else { key() };
            let mut gift = signed(
                &sender,
                1059,
                100,
                json!([
                    ["no_delete"],
                    [
                        "p",
                        hex::encode(recipient.x_only_public_key().0.serialize())
                    ],
                ]),
            );
            write(&env, &mut gift);
            let tags = if kind == 62 {
                json!([["relay", "ALL_RELAYS"]])
            } else if explicit_id {
                json!([["e", id(&gift)]])
            } else {
                json!([])
            };
            let mut request = signed(&recipient, kind, 200, tags);
            write(&env, &mut request);
            if kind == 62 {
                assert!(is_event_vanished_ro(
                    &env.begin_ro().unwrap(),
                    PackedEventView::new(&gift.packed).unwrap()
                )
                .unwrap());
                sweep(&env);
            }
            assert!(stored(&env, &gift).is_none());
        }
    }
}

#[test]
fn unchecked_import_does_not_protect_unsigned_or_malformed_markers() {
    for tags in [
        json!([["no_delete"]]),
        json!([["no_delete", "1"]]),
        json!([["no_delete"], ["no_delete"]]),
        json!([["no_delete"], ["expiration", "0100"]]),
        json!([
            ["no_delete"],
            ["expiration", "1000"],
            ["expiration", "2000"]
        ]),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let author = key();
        let mut event =
            wok_event::json::parse_strict(&signed(&author, 1, 100, json!([])).json).unwrap();
        event["tags"] = tags;
        let id = wok_event::event_id_hash(&event).unwrap();
        event["id"] = json!(hex::encode(id));
        if event["tags"] != json!([["no_delete"]]) {
            event["sig"] = json!(hex::encode(SECP256K1.sign_schnorr(&id, &author).as_ref()));
        }
        // The single valid marker keeps the old signature: an unchecked
        // import must not gain protection by adding unsigned metadata. The
        // malformed markers above are signed, but still grant no protection.
        let packed =
            wok_event::nostr_json_to_packed_event(&event, &EventLimits::default()).unwrap();
        let mut imported = EventToWrite::new(
            packed.into_bytes(),
            wok_event::normalize_event_json(&event).unwrap(),
        );
        write(&env, &mut imported);
        let lev = stored(&env, &imported).unwrap();
        let mut request = signed(&author, 5, 200, json!([["e", hex::encode(id)]]));
        write(&env, &mut request);
        assert!(wok_db::get_packed_ro(&env.begin_ro().unwrap(), lev)
            .unwrap()
            .is_none());
    }
}

#[test]
fn compressed_historical_payloads_keep_protection_without_repacking() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let author = key();
    let mut event = signed(&author, 41, 100, json!([["no_delete"]]));
    write(&env, &mut event);
    let lev = stored(&env, &event).unwrap();
    let escaped = event.json.replace("no_delete", "no_\\u0064elete");
    let compressed = zstd::bulk::compress(escaped.as_bytes(), 3).unwrap();
    let mut txn = env.begin_rw().unwrap();
    let dict = wok_db::insert_compression_dictionary(&mut txn, b"").unwrap();
    txn.put_u64(
        env.dbis().event_payload,
        lev,
        &wok_db::encode_zstd_payload(dict.try_into().unwrap(), &compressed),
        0,
    )
    .unwrap();
    txn.commit().unwrap();
    let mut vanish = signed(&author, 62, 200, json!([["relay", "ALL_RELAYS"]]));
    write(&env, &mut vanish);
    assert!(!is_event_vanished_ro(
        &env.begin_ro().unwrap(),
        PackedEventView::new(&event.packed).unwrap()
    )
    .unwrap());
    sweep(&env);
    assert_eq!(
        wok_db::get_packed_ro(&env.begin_ro().unwrap(), lev)
            .unwrap()
            .unwrap(),
        event.packed
    );
    assert!(check_integrity(&env.begin_ro().unwrap()).unwrap().ok());
}
