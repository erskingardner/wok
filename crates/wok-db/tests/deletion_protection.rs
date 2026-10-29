//! NIP-D9 (nips#2531 at 807264f): stored, imported, and republished copies.

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
            if kind == 62 || !explicit_id {
                assert!(is_event_vanished_ro(
                    &env.begin_ro().unwrap(),
                    PackedEventView::new(&gift.packed).unwrap()
                )
                .unwrap());
                assert!(
                    stored(&env, &gift).is_some(),
                    "cleanup is deferred to bounded maintenance"
                );
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

#[test]
fn recipient_cleanup_is_bounded_resumes_after_restart_and_preserves_later_arrivals() {
    for indexed in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let recipient = key();
        let sender = key();
        let recipient_hex = hex::encode(recipient.x_only_public_key().0.serialize());
        let mut mentions = Vec::new();
        let mut gifts = Vec::new();
        for n in 0..20 {
            mentions.push(signed(&sender, 1, n, json!([["p", recipient_hex]])));
        }
        for kind in [1059, 21059] {
            for at in [0, 100, u64::MAX] {
                let mut tags = json!([["p", recipient_hex]]);
                if kind == 1059 {
                    tags.as_array_mut().unwrap().push(json!(["no_delete"]));
                }
                gifts.push(signed(&sender, kind, at, tags));
            }
        }
        for event in mentions.iter_mut().chain(gifts.iter_mut()) {
            let mut txn = env.begin_rw().unwrap();
            if !indexed {
                wok_db::skip_tag_kind_postings(&mut txn);
            }
            wok_db::write_events(
                &mut txn,
                &mut NoopNegentropy,
                std::slice::from_mut(event),
                false,
            )
            .unwrap();
            txn.commit().unwrap();
        }
        let mut request = signed(&recipient, 5, 200, json!([]));
        let before = wok_db::state::policy_generation(&env.begin_ro().unwrap()).unwrap();
        write(&env, &mut request);
        assert!(wok_db::state::policy_generation(&env.begin_ro().unwrap()).unwrap() > before);
        for gift in &gifts {
            assert!(
                stored(&env, gift).is_some(),
                "publication only records a cutoff"
            );
            assert!(is_event_vanished_ro(
                &env.begin_ro().unwrap(),
                PackedEventView::new(&gift.packed).unwrap()
            )
            .unwrap());
        }
        let mut later = signed(
            &sender,
            1059,
            0,
            json!([["p", recipient_hex], ["x", "later"]]),
        );
        write(&env, &mut later);
        assert_eq!(later.status, EventWriteStatus::Written);
        assert!(!is_event_vanished_ro(
            &env.begin_ro().unwrap(),
            PackedEventView::new(&later.packed).unwrap()
        )
        .unwrap());

        // An aborted maintenance transaction cannot advance persisted progress
        // or remove records. The caller discards its speculative cursor too.
        {
            let mut txn = env.begin_rw().unwrap();
            let step =
                sweep_vanished_events(&mut txn, &mut NoopNegentropy, 1, &mut Default::default())
                    .unwrap();
            assert!(step.examined <= 1 && step.deleted <= 1 && step.markers <= 1);
        }
        assert!(gifts.iter().all(|gift| stored(&env, gift).is_some()));
        let mut cursor = Default::default();
        let mut txn = env.begin_rw().unwrap();
        let first = sweep_vanished_events(&mut txn, &mut NoopNegentropy, 1, &mut cursor).unwrap();
        txn.commit().unwrap();
        let mut examined = first.examined;
        let mut deleted = first.deleted;
        drop(env);
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
        let mut cursor = Default::default();
        let mut done = false;
        for _ in 0..100 {
            let mut txn = env.begin_rw().unwrap();
            let step =
                sweep_vanished_events(&mut txn, &mut NoopNegentropy, 1, &mut cursor).unwrap();
            assert!(step.examined <= 1 && step.deleted <= 1 && step.markers <= 1);
            examined += step.examined;
            deleted += step.deleted;
            txn.commit().unwrap();
            if step.markers == 0 {
                done = true;
                break;
            }
        }
        assert!(done);
        assert_eq!(deleted, gifts.len() as u64);
        assert_eq!(
            examined,
            gifts.len() + 1 + if indexed { 0 } else { mentions.len() }
        );
        assert!(gifts.iter().all(|gift| stored(&env, gift).is_none()));
        for mention in &mentions {
            assert!(stored(&env, mention).is_some());
            assert!(!is_event_vanished_ro(
                &env.begin_ro().unwrap(),
                PackedEventView::new(&mention.packed).unwrap()
            )
            .unwrap());
        }
        assert!(stored(&env, &later).is_some());
        assert!(
            !wok_db::has_deletion_markers_ro(&env.begin_ro().unwrap()).unwrap(),
            "completed recipient work releases its read-time marker"
        );

        // A raised cutoff wakes an idle cursor. Only arrivals before this
        // second request join the next pass, including backdated wraps.
        let mut second = signed(&recipient, 5, 201, json!([]));
        write(&env, &mut second);
        let mut newest = signed(
            &sender,
            1059,
            0,
            json!([["p", recipient_hex], ["x", "newest"]]),
        );
        write(&env, &mut newest);
        let mut txn = env.begin_rw().unwrap();
        let step = sweep_vanished_events(&mut txn, &mut NoopNegentropy, 1, &mut cursor).unwrap();
        assert_eq!(step.markers, 1);
        txn.commit().unwrap();
        sweep(&env);
        assert!(stored(&env, &later).is_none());
        assert!(stored(&env, &newest).is_some());
        assert!(check_integrity(&env.begin_ro().unwrap()).unwrap().ok());
    }
}

#[test]
fn recipient_sweep_handles_a_raised_cutoff_and_index_reset_mid_pass() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let recipient = key();
    let sender = key();
    let recipient_hex = hex::encode(recipient.x_only_public_key().0.serialize());
    let mut gifts = Vec::new();
    for at in 0..4 {
        let mut gift = signed(
            &sender,
            1059,
            at,
            json!([["p", recipient_hex], ["no_delete"]]),
        );
        write(&env, &mut gift);
        gifts.push(gift);
    }
    write(&env, &mut signed(&recipient, 5, 100, json!([])));
    let mut txn = env.begin_rw().unwrap();
    let step =
        sweep_vanished_events(&mut txn, &mut NoopNegentropy, 1, &mut Default::default()).unwrap();
    assert_eq!(step.deleted, 1);
    txn.commit().unwrap();
    let mut later = signed(
        &sender,
        1059,
        1,
        json!([["p", recipient_hex], ["x", "later"]]),
    );
    write(&env, &mut later);
    write(&env, &mut signed(&recipient, 5, 101, json!([])));
    let mut txn = env.begin_rw().unwrap();
    wok_db::reset_tag_kind_index(&mut txn).unwrap();
    txn.commit().unwrap();
    sweep(&env);
    assert!(gifts.iter().all(|gift| stored(&env, gift).is_none()));
    assert!(stored(&env, &later).is_none());
    assert!(check_integrity(&env.begin_ro().unwrap()).unwrap().ok());
}

#[test]
fn reindex_preserves_pending_recipient_deletions_and_later_arrivals() {
    for packing in [
        wok_db::PackedEventRebuild::Copy,
        wok_db::PackedEventRebuild::RepackLongTags,
    ] {
        for partial_sweep in [false, true] {
            for keep_request in [false, true] {
                let source_dir = tempfile::tempdir().unwrap();
                let source = Env::open(source_dir.path(), EnvOptions::for_tests()).unwrap();
                source.ensure_initialized().unwrap();
                let recipient = key();
                let sender = key();
                let recipient_hex = hex::encode(recipient.x_only_public_key().0.serialize());
                let mut gifts = Vec::new();
                for at in 0..3 {
                    let mut gift = signed(
                        &sender,
                        1059,
                        at,
                        json!([["p", recipient_hex], ["no_delete"]]),
                    );
                    write(&source, &mut gift);
                    gifts.push(gift);
                }
                let mut request = signed(&recipient, 5, 100, json!([]));
                write(&source, &mut request);
                if partial_sweep {
                    let mut txn = source.begin_rw().unwrap();
                    let step = sweep_vanished_events(
                        &mut txn,
                        &mut NoopNegentropy,
                        1,
                        &mut Default::default(),
                    )
                    .unwrap();
                    assert_eq!(step.deleted, 1);
                    txn.commit().unwrap();
                }
                let mut later = signed(
                    &sender,
                    1059,
                    0,
                    json!([["p", recipient_hex], ["x", "later"]]),
                );
                write(&source, &mut later);
                if !keep_request {
                    // The cutoff is authoritative even after operator deletion
                    // removes the request; it cannot be derived from events.
                    let lev = stored(&source, &request).unwrap();
                    let mut txn = source.begin_rw().unwrap();
                    delete_events(&mut txn, &mut NoopNegentropy, [lev]).unwrap();
                    txn.commit().unwrap();
                }
                let remaining: Vec<_> = gifts
                    .iter()
                    .filter(|gift| stored(&source, gift).is_some())
                    .collect();
                let target_dir = tempfile::tempdir().unwrap();
                let target = Env::open(target_dir.path(), EnvOptions::for_tests()).unwrap();
                {
                    let original = source.begin_ro().unwrap();
                    let mut rebuilt = target.begin_rw().unwrap();
                    wok_db::rebuild_primary_and_event_indices(&original, &mut rebuilt, packing)
                        .unwrap();
                    rebuilt.commit().unwrap();
                }
                drop(target);
                let target = Env::open(target_dir.path(), EnvOptions::for_tests()).unwrap();
                if keep_request {
                    request.status = EventWriteStatus::Pending;
                    write(&target, &mut request);
                    assert_eq!(request.status, EventWriteStatus::Duplicate);
                }
                for gift in remaining {
                    assert!(stored(&target, gift).is_some());
                    assert!(
                        is_event_vanished_ro(
                            &target.begin_ro().unwrap(),
                            PackedEventView::new(&gift.packed).unwrap()
                        )
                        .unwrap(),
                        "reindex must not reveal a pending recipient deletion"
                    );
                }
                assert!(!is_event_vanished_ro(
                    &target.begin_ro().unwrap(),
                    PackedEventView::new(&later.packed).unwrap()
                )
                .unwrap());
                sweep(&target);
                assert!(gifts.iter().all(|gift| stored(&target, gift).is_none()));
                assert!(stored(&target, &later).is_some());
                assert!(check_integrity(&target.begin_ro().unwrap()).unwrap().ok());
            }
        }
    }
}

#[test]
fn verification_cache_respects_payload_changes_and_old_read_snapshots() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let author = key();
    let mut event = signed(&author, 1, 100, json!([["no_delete"]]));
    write(&env, &mut event);
    let lev = stored(&env, &event).unwrap();
    write(
        &env,
        &mut signed(&author, 62, 200, json!([["relay", "ALL_RELAYS"]])),
    );
    let packed = PackedEventView::new(&event.packed).unwrap();
    let old = env.begin_ro().unwrap();
    assert!(!is_event_vanished_ro(&old, packed).unwrap());
    // LMDB permits one read transaction per OS thread. Query newer snapshots
    // on another thread while this reader retains its original snapshot.
    let fresh = || {
        std::thread::scope(|scope| {
            scope
                .spawn(|| is_event_vanished_ro(&env.begin_ro().unwrap(), packed).unwrap())
                .join()
                .unwrap()
        })
    };
    let change_payload = |json: &str| {
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let mut txn = env.begin_rw().unwrap();
                    txn.put_u64(
                        env.dbis().event_payload,
                        lev,
                        &wok_db::encode_raw_payload(json),
                        0,
                    )
                    .unwrap();
                    txn.commit().unwrap();
                })
                .join()
                .unwrap();
        })
    };
    let mut invalid = wok_event::json::parse_strict(&event.json).unwrap();
    invalid["sig"] = json!("00".repeat(64));
    let json = wok_event::normalize_event_json(&invalid).unwrap();
    change_payload(&json);
    assert!(fresh());
    assert!(!is_event_vanished_ro(&old, packed).unwrap());
    change_payload(&event.json);
    assert!(!fresh());
}
