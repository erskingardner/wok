//! The frontier is derived metadata; authoritative event/payload bytes stay exact.

use secp256k1::{Keypair, SecretKey, SECP256K1};
use serde_json::json;
use wok_db::{AuthorHead, AuthorPosition, Env, EnvOptions, EventToWrite, NoopNegentropy};
use wok_event::PackedEventView;

const HEAD_CF: &str = "wok_author_frontiers_v1";

fn event(n: u64, who: u8, created: u64) -> EventToWrite {
    let key = Keypair::from_secret_key(SECP256K1, &SecretKey::from_byte_array(&[who; 32]).unwrap());
    let mut value = json!({"pubkey":hex::encode(key.x_only_public_key().0.serialize()),
        "kind":1,"created_at":created,"tags":[["t","frontier"]],"content":format!("{n}: 🥘\u{7f}")});
    let id = wok_event::event_id_hash(&value).unwrap();
    value["id"] = json!(hex::encode(id));
    value["sig"] = json!(hex::encode(SECP256K1.sign_schnorr(&id, &key).as_ref()));
    let parsed = wok_event::parse_and_verify_event(
        &value,
        &wok_event::EventLimits::default(),
        None,
        true,
        false,
    )
    .unwrap();
    EventToWrite::new(parsed.packed.into_bytes(), parsed.json)
}
fn author(event: &EventToWrite) -> [u8; 32] {
    PackedEventView::new(&event.packed)
        .unwrap()
        .pubkey()
        .try_into()
        .unwrap()
}
fn position(event: &EventToWrite) -> AuthorPosition {
    AuthorPosition {
        created_at: PackedEventView::new(&event.packed).unwrap().created_at(),
        local_id: event.lev_id,
    }
}
fn write(env: &Env, mut events: Vec<EventToWrite>) -> Vec<EventToWrite> {
    let mut txn = env.begin_rw().unwrap();
    write_in_order(&mut txn, &mut events);
    txn.commit().unwrap();
    events
}
fn write_in_order(txn: &mut wok_db::RwTxn<'_>, events: &mut [EventToWrite]) {
    // The writer sorts its mutable batch by timestamp/event ID. Restore only
    // this fixture's named input order while retaining the assigned local IDs.
    let ids: Vec<[u8; 32]> = events
        .iter()
        .map(|event| {
            PackedEventView::new(&event.packed)
                .unwrap()
                .id()
                .try_into()
                .unwrap()
        })
        .collect();
    wok_db::write_events(txn, &mut NoopNegentropy, events, false).unwrap();
    events.sort_by_key(|event| {
        ids.iter()
            .position(|id| id.as_slice() == PackedEventView::new(&event.packed).unwrap().id())
            .unwrap()
    });
}
fn fixture() -> (tempfile::TempDir, Env, Vec<EventToWrite>) {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let events = write(
        &env,
        vec![
            event(1, 7, 10),
            event(2, 8, 20),
            event(3, 7, 30),
            event(4, 8, 20),
        ],
    );
    (dir, env, events)
}
fn raw_position(position: AuthorPosition) -> Vec<u8> {
    [
        position.created_at.to_be_bytes(),
        position.local_id.to_be_bytes(),
    ]
    .concat()
}
fn raw_head(first: AuthorPosition, next: Option<AuthorPosition>) -> Vec<u8> {
    let mut raw = raw_position(first);
    if let Some(next) = next {
        raw.extend(raw_position(next));
    }
    raw
}
fn native_head(env: &Env, author: &[u8; 32]) -> Option<Vec<u8>> {
    env.inner
        .db
        .get_cf(env.inner.db.cf_handle(HEAD_CF).unwrap(), author)
        .unwrap()
}

#[test]
fn borrowed_batches_preserve_order_duplicates_snapshots_and_primary_cache() {
    let (_dir, env, events) = fixture();
    let (a, b, missing) = (author(&events[0]), author(&events[1]), [0; 32]);
    let heads = [
        Some(AuthorHead {
            first: position(&events[2]),
            next: Some(position(&events[0])),
        }),
        Some(AuthorHead {
            first: position(&events[3]).max(position(&events[1])),
            next: Some(position(&events[3]).min(position(&events[1]))),
        }),
    ];
    let old = env.begin_ro().unwrap();
    let inputs = [&b, &a, &missing, &b];
    assert_eq!(
        old.author_heads(inputs).unwrap(),
        vec![heads[1], heads[0], None, heads[1]]
    );
    // A native snapshot handle survives moving its Rust wrapper after options
    // have been initialized by a head batch, before later uncached pin reads.
    let old = Box::new(old);
    let packed = old
        .get_u64(env.dbis().event, events[2].lev_id)
        .unwrap()
        .unwrap();
    let payload = old
        .get_u64(env.dbis().event_payload, events[2].lev_id)
        .unwrap()
        .unwrap();
    #[cfg(feature = "rocksdb-read-diagnostics")]
    {
        use wok_db::read_diagnostics::measure;
        let (_, m) = measure(|| old.author_heads(std::iter::empty::<&[u8; 32]>())).unwrap();
        assert_eq!(m.wrapper, Default::default());
        let txn = env.begin_ro().unwrap();
        let (result, m) = measure(|| txn.author_heads(inputs)).unwrap();
        assert_eq!(result.unwrap(), vec![heads[1], heads[0], None, heads[1]]);
        assert_eq!(m.wrapper.author_head_multiget_calls, 1);
        assert_eq!(m.wrapper.author_head_keys, 4);
        assert_eq!(m.wrapper.primary_pin_lookups, 0);
        assert_eq!(m.wrapper.primary_cached_pinned_hits, 0);
        let (_, m) = measure(|| txn.get_u64(env.dbis().event, events[2].lev_id)).unwrap();
        assert_eq!(m.wrapper.primary_pin_lookups, 1);
        assert_eq!(m.wrapper.primary_cached_pinned_hits, 0);
    }
    // Explicit sorted and repeated-key requests use the same per-input contract.
    let mut sorted = [a, b, a];
    sorted.sort();
    let actual = old.author_heads(&sorted).unwrap();
    assert_eq!(
        actual,
        sorted
            .iter()
            .map(|key| if key == &a { heads[0] } else { heads[1] })
            .collect::<Vec<_>>()
    );
    let mut txn = env.begin_rw().unwrap();
    wok_db::delete_events(
        &mut txn,
        &mut NoopNegentropy,
        [heads[1].unwrap().first.local_id],
    )
    .unwrap();
    let mut inserted = [event(5, 7, 99), event(6, 9, 15)];
    write_in_order(&mut txn, &mut inserted);
    txn.commit().unwrap();
    assert_eq!(
        old.author_heads(inputs).unwrap(),
        vec![heads[1], heads[0], None, heads[1]]
    );
    let current = env.begin_ro().unwrap();
    let now = current
        .author_heads([&a, &b, &author(&inserted[1])])
        .unwrap();
    assert_eq!(
        now[0],
        Some(AuthorHead {
            first: position(&inserted[0]),
            next: Some(position(&events[2]))
        })
    );
    assert_eq!(
        now[1],
        Some(AuthorHead {
            first: heads[1].unwrap().next.unwrap(),
            next: None
        })
    );
    assert_eq!(
        now[2],
        Some(AuthorHead {
            first: position(&inserted[1]),
            next: None
        })
    );
    assert!(heads[0].unwrap().first.created_at <= 30 && now[0].unwrap().first.created_at > 30);
    assert_eq!(packed, events[2].packed);
    assert_eq!(payload, wok_db::encode_raw_payload(&events[2].json));
    let audit = env.audit_rocksdb_layout().unwrap();
    assert_eq!(audit["author_head_records_verified"], 3);
    assert_eq!(audit["author_frontier_positions_verified"], 4);
    assert_eq!(audit["derived_cf_counts"][HEAD_CF], 3);
    assert!(audit["table_counts"].get(HEAD_CF).is_none());
}

#[test]
fn abort_and_multiple_staged_deletes_use_final_overlay_then_reopen_exactly() {
    let (dir, env, events) = fixture();
    let a = author(&events[0]);
    let before = native_head(&env, &a).unwrap();
    for abort in [true, false] {
        let old = env.begin_ro().unwrap();
        let mut txn = env.begin_rw().unwrap();
        wok_db::delete_events(
            &mut txn,
            &mut NoopNegentropy,
            [events[0].lev_id, events[2].lev_id],
        )
        .unwrap();
        let mut inserted = [event(7, 7, 15), event(8, 7, 40), event(9, 7, 12)];
        write_in_order(&mut txn, &mut inserted);
        wok_db::delete_events(&mut txn, &mut NoopNegentropy, [inserted[1].lev_id]).unwrap();
        // No head is published while any of the paired postings are staged.
        assert_eq!(native_head(&env, &a), Some(before.clone()));
        if abort {
            txn.abort();
            assert_eq!(native_head(&env, &a), Some(before.clone()));
        } else {
            txn.commit().unwrap();
            assert_eq!(
                env.begin_ro().unwrap().author_heads([&a]).unwrap(),
                vec![Some(AuthorHead {
                    first: position(&inserted[0]),
                    next: Some(position(&inserted[2]))
                })]
            );
        }
        assert_eq!(
            old.author_heads([&a]).unwrap()[0],
            Some(AuthorHead {
                first: position(&events[2]),
                next: Some(position(&events[0]))
            })
        );
    }
    let expected = native_head(&env, &a);
    let fingerprint = env.audit_rocksdb_layout().unwrap()["primary_fingerprint_sha256"].clone();
    drop(env);
    let env = Env::open(
        dir.path(),
        EnvOptions {
            read_only: true,
            create_dbis: false,
            create_dir: false,
            ..EnvOptions::for_tests()
        },
    )
    .unwrap();
    assert_eq!(native_head(&env, &a), expected);
    assert_eq!(
        env.audit_rocksdb_layout().unwrap()["primary_fingerprint_sha256"],
        fingerprint
    );
}

#[test]
fn raw_posting_ties_keep_full_width_positions_and_clear_removes_frontiers() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let a = [255; 32];
    let dbi = env.dbis().event_pubkey;
    let mut txn = env.begin_rw().unwrap();
    for (time, id) in [(u64::MAX, u64::MAX), (u64::MAX, 0), (0, 0)] {
        txn.put(
            dbi,
            &wok_db::keys::make_key_string_u64(&a, time),
            &id.to_ne_bytes(),
            0,
        )
        .unwrap();
    }
    txn.commit().unwrap();
    let old = env.begin_ro().unwrap();
    let expected = AuthorHead {
        first: AuthorPosition {
            created_at: u64::MAX,
            local_id: u64::MAX,
        },
        next: Some(AuthorPosition {
            created_at: u64::MAX,
            local_id: 0,
        }),
    };
    assert_eq!(old.author_heads([&a]).unwrap(), vec![Some(expected)]);
    assert_eq!(
        native_head(&env, &a),
        Some(raw_head(expected.first, expected.next))
    );
    let mut txn = env.begin_rw().unwrap();
    txn.del(dbi, &wok_db::keys::make_key_string_u64(&a, u64::MAX), None)
        .unwrap();
    txn.commit().unwrap();
    assert_eq!(
        env.begin_ro().unwrap().author_heads([&a]).unwrap(),
        vec![Some(AuthorHead {
            first: AuthorPosition {
                created_at: 0,
                local_id: 0
            },
            next: None
        })]
    );
    assert_eq!(native_head(&env, &a).unwrap().len(), 16);
    let mut txn = env.begin_rw().unwrap();
    txn.clear(dbi).unwrap();
    txn.abort();
    assert!(native_head(&env, &a).is_some());
    let mut txn = env.begin_rw().unwrap();
    txn.clear(dbi).unwrap();
    txn.commit().unwrap();
    assert_eq!(
        env.begin_ro().unwrap().author_heads([&a]).unwrap(),
        vec![None]
    );
    assert_eq!(old.author_heads([&a]).unwrap(), vec![Some(expected)]);
}

#[test]
fn unchanged_frontier_is_not_rewritten_by_duplicate_posting_or_recompression() {
    let (_dir, env, events) = fixture();
    let a = author(&events[0]);
    let raw = native_head(&env, &a);
    let before = env.inner.db.latest_sequence_number();
    let mut txn = env.begin_rw().unwrap();
    txn.put(
        env.dbis().event_pubkey,
        &wok_db::keys::make_key_string_u64(&a, 30),
        &events[2].lev_id.to_ne_bytes(),
        0,
    )
    .unwrap();
    txn.commit().unwrap();
    assert_eq!(
        env.inner.db.latest_sequence_number() - before,
        1,
        "only the requested posting put may write"
    );
    assert_eq!(native_head(&env, &a), raw);
    let dictionary = b"author frontier payload dictionary";
    let mut txn = env.begin_rw().unwrap();
    let dictionary_id = wok_db::insert_compression_dictionary(&mut txn, dictionary).unwrap();
    txn.commit().unwrap();
    let compressed = zstd::bulk::Compressor::with_dictionary(3, dictionary)
        .unwrap()
        .compress(events[2].json.as_bytes())
        .unwrap();
    let before = env.inner.db.latest_sequence_number();
    let mut txn = env.begin_rw().unwrap();
    txn.put_u64(
        env.dbis().event_payload,
        events[2].lev_id,
        &wok_db::encode_zstd_payload(u32::try_from(dictionary_id).unwrap(), &compressed),
        0,
    )
    .unwrap();
    txn.commit().unwrap();
    assert_eq!(
        env.inner.db.latest_sequence_number() - before,
        1,
        "component maintenance does not rewrite author frontiers"
    );
    assert_eq!(native_head(&env, &a), raw);
    assert_eq!(
        wok_db::event_json_owned(
            &env.begin_ro().unwrap(),
            &mut wok_db::Decompressor::new(),
            events[2].lev_id,
            1 << 20
        )
        .unwrap(),
        events[2].json
    );
    assert!(env.audit_rocksdb_layout().unwrap()["ok"].as_bool().unwrap());
}

#[test]
fn malformed_frontier_lengths_and_non_descending_next_fail_without_primary_reads() {
    let (_dir, env, events) = fixture();
    let a = author(&events[0]);
    let cf = env.inner.db.cf_handle(HEAD_CF).unwrap();
    let original = native_head(&env, &a).unwrap();
    let first = position(&events[2]);
    let mut invalid = vec![vec![], vec![0; 15], vec![0; 17], vec![0; 31], vec![0; 33]];
    invalid.push(raw_head(first, Some(first)));
    invalid.push(raw_head(
        first,
        Some(AuthorPosition {
            created_at: first.created_at + 1,
            local_id: 0,
        }),
    ));
    for value in invalid {
        env.inner.db.put_cf(cf, a, value).unwrap();
        let txn = env.begin_ro().unwrap();
        #[cfg(feature = "rocksdb-read-diagnostics")]
        {
            let b = author(&events[1]);
            let (result, m) =
                wok_db::read_diagnostics::measure(|| txn.author_heads([&a, &b])).unwrap();
            assert!(result.is_err());
            assert_eq!(m.wrapper.author_head_keys, 2);
            assert_eq!(m.wrapper.primary_pin_lookups, 0);
        }
        assert!(txn.author_heads([&a]).is_err());
        assert!(env.audit_rocksdb_layout().is_err());
    }
    env.inner.db.put_cf(cf, a, original).unwrap();
    assert!(env.audit_rocksdb_layout().is_ok());
}

#[test]
fn audit_rejects_missing_stale_second_or_extra_frontiers_despite_equal_counts() {
    let (_dir, env, events) = fixture();
    let a = author(&events[0]);
    let b = author(&events[1]);
    let middle = write(&env, vec![event(10, 7, 20)]).remove(0);
    let original = native_head(&env, &a).unwrap();
    let cf = env.inner.db.cf_handle(HEAD_CF).unwrap();
    for (value, message) in [
        (
            Some(raw_head(position(&middle), Some(position(&events[0])))),
            "author head is older",
        ),
        (
            Some(raw_head(position(&events[2]), Some(position(&events[0])))),
            "author next position is older",
        ),
        (
            Some(raw_head(position(&events[2]), None)),
            "author next position is older",
        ),
        (
            Some(raw_head(
                AuthorPosition {
                    created_at: 99,
                    local_id: 999,
                },
                Some(position(&events[2])),
            )),
            "missing primary",
        ),
        (
            Some(raw_head(
                AuthorPosition {
                    created_at: 99,
                    local_id: events[2].lev_id,
                },
                Some(position(&events[2])),
            )),
            "primary author or timestamp",
        ),
        (None, "missing author head"),
    ] {
        match value {
            Some(value) => env.inner.db.put_cf(cf, a, value).unwrap(),
            None => env.inner.db.delete_cf(cf, a).unwrap(),
        }
        let error = env.audit_rocksdb_layout().unwrap_err().to_string();
        assert!(error.contains(message), "{error}");
        env.inner.db.put_cf(cf, a, &original).unwrap();
    }
    let extra = [3; 32];
    env.inner.db.put_cf(cf, extra, &original).unwrap();
    assert!(env
        .audit_rocksdb_layout()
        .unwrap_err()
        .to_string()
        .contains("primary author or timestamp"));
    env.inner.db.delete_cf(cf, extra).unwrap();
    env.inner.db.put_cf(cf, &a[..31], &original).unwrap();
    assert!(env
        .audit_rocksdb_layout()
        .unwrap_err()
        .to_string()
        .contains("head key"));
    env.inner.db.delete_cf(cf, &a[..31]).unwrap();
    // Both authors remain checked, and exact derived counts are separate.
    assert!(native_head(&env, &b).is_some());
    let audit = env.audit_rocksdb_layout().unwrap();
    assert_eq!(audit["derived_cf_counts"][HEAD_CF], 2);
}

#[test]
fn malformed_thin_duplicate_removes_shortcut_and_repair_restores_exact_frontier() {
    let (_dir, env, events) = fixture();
    let a = author(&events[0]);
    write(&env, vec![event(11, 7, 20)]);
    let original = env.begin_ro().unwrap().author_heads([&a]).unwrap();
    let old = env.begin_ro().unwrap();
    let key = wok_db::keys::make_key_string_u64(&a, 25);
    let malformed = b"bad duplicate";
    let mut txn = env.begin_rw().unwrap();
    txn.put(env.dbis().event_pubkey, &key, malformed, 0)
        .unwrap();
    txn.commit().unwrap();
    assert_eq!(
        env.begin_ro().unwrap().author_heads([&a]).unwrap(),
        vec![None]
    );
    assert!(env.audit_rocksdb_layout().is_err());
    // Without a shortcut, consuming the same chronological duplicate still
    // fails in the ordinary thin reader rather than jumping to the second row.
    let txn = env.begin_ro().unwrap();
    let start = wok_db::keys::make_key_string_u64(&a, u64::MAX);
    let mut bad = false;
    txn.cursor(env.dbis().event_pubkey)
        .unwrap()
        .foreach_index(&start, u64::MAX, |entry| {
            if !entry.prefix_matches(&a, true) {
                return false;
            }
            if entry.local_id().is_err() {
                bad = true;
                return false;
            }
            true
        })
        .unwrap();
    assert!(bad);
    let mut txn = env.begin_rw().unwrap();
    txn.del(env.dbis().event_pubkey, &key, Some(malformed))
        .unwrap();
    txn.commit().unwrap();
    assert_eq!(
        env.begin_ro().unwrap().author_heads([&a]).unwrap(),
        original
    );
    assert_eq!(old.author_heads([&a]).unwrap(), original);
    assert!(env.audit_rocksdb_layout().is_ok());
}
