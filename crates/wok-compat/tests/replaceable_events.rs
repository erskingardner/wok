//! Latest-only reads must hold even for losslessly imported primary records.
#[path = "support/wire.rs"]
mod wire;

use secp256k1::{Keypair, SECP256K1};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use tempfile::TempDir;
use wire::Wire;
use wok_compat::sign_event_with_key;
use wok_db::{Env, EnvOptions};
use wok_event::{parse_and_verify_event, EventLimits, PackedEventView};
use wok_query::visibility::{ReadSnapshot, ReadVisibility};
use wok_query::{DbQuery, NostrFilterGroup, SubId, Subscription};

fn key() -> Keypair {
    Keypair::new(SECP256K1, &mut rand::thread_rng())
}

fn event(key: &Keypair, kind: u64, time: u64, tags: Value, content: &str) -> Value {
    sign_event_with_key(
        json!({"kind":kind,"created_at":time,"tags":tags,"content":content}),
        key,
    )
}

// Intentionally bypass publication replacement, as a lossless snapshot does.
// Rebuild all derived indexes, then verify structural integrity. The read fix
// must not depend on physical deletion, insertion order, or damaged indexes.
fn snapshot(events: &[Value]) -> (TempDir, Env) {
    let records: Vec<_> = events
        .iter()
        .map(|event| {
            let parsed =
                parse_and_verify_event(event, &EventLimits::default(), None, true, false).unwrap();
            (parsed.packed.into_bytes(), parsed.json)
        })
        .collect();
    snapshot_records(&records)
}

fn snapshot_records(records: &[(Vec<u8>, String)]) -> (TempDir, Env) {
    let source_dir = tempfile::tempdir().unwrap();
    let source = Env::open(
        source_dir.path(),
        EnvOptions {
            map_size: 64 * 1024 * 1024,
            ..EnvOptions::default()
        },
    )
    .unwrap();
    source.ensure_initialized().unwrap();
    {
        let mut txn = source.begin_rw().unwrap();
        for (index, (packed, json)) in records.iter().enumerate() {
            let lev = index as u64 + 1;
            txn.put_u64(source.dbis().event, lev, packed, 0).unwrap();
            txn.put_u64(
                source.dbis().event_payload,
                lev,
                &wok_db::encode_raw_payload(json),
                0,
            )
            .unwrap();
        }
        txn.commit().unwrap();
    }
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(
        dir.path(),
        EnvOptions {
            map_size: 64 * 1024 * 1024,
            ..EnvOptions::default()
        },
    )
    .unwrap();
    {
        let mut txn = env.begin_rw().unwrap();
        wok_db::rebuild_primary_and_event_indices(
            &source.begin_ro().unwrap(),
            &mut txn,
            wok_db::PackedEventRebuild::Copy,
        )
        .unwrap();
        // Keep the persistent match-all negentropy tree structurally correct too.
        let mut tree = wok_negentropy::open_rw(&mut txn, 1).unwrap();
        for (packed, _) in records {
            let packed = PackedEventView::new(packed).unwrap();
            tree.insert(packed.created_at(), packed.id()).unwrap();
        }
        tree.backend.flush().unwrap();
        drop(tree);
        txn.commit().unwrap();
    }
    assert!(wok_db::check_integrity(&env.begin_ro().unwrap())
        .unwrap()
        .ok());
    (dir, env)
}

fn query(env: &Env, filters: &[Value], count: bool) -> Vec<String> {
    let mut request = vec![json!("REQ"), json!("test")];
    request.extend_from_slice(filters);
    let group = NostrFilterGroup::from_req(&request, 500, 3, 16).unwrap();
    let txn = env.begin_ro().unwrap();
    let mut sub = Subscription::new(1, SubId::new("test").unwrap(), group, count);
    sub.latest_event_id = wok_db::most_recent_levid_ro(&txn).unwrap();
    let mut query = DbQuery::new(sub, 500, 1000);
    let mut ids = Vec::new();
    while !query
        .process(
            &txn,
            |_, lev| {
                let packed =
                    PackedEventView::new(txn.get_u64(env.dbis().event, lev).unwrap().unwrap())
                        .unwrap();
                ids.push(hex::encode(packed.id()));
            },
            1,
        )
        .unwrap()
    {}
    assert_eq!(query.sent_count(), ids.len() as u64);
    ids.sort();
    ids
}

fn ids(events: &[Value]) -> Vec<String> {
    let mut result: Vec<_> = events
        .iter()
        .map(|event| event["id"].as_str().unwrap().to_owned())
        .collect();
    result.sort();
    result
}

#[test]
fn all_replaceable_kinds_hide_imported_history_in_req_and_count() {
    let key = key();
    for kind in [0, 3, 10000, 10002, 19999, 30000, 30023, 30443, 39999] {
        let old = event(&key, kind, 100, json!([["d", "address"]]), "old");
        let newest = event(&key, kind, 300, json!([["d", "address"]]), "newest");
        let middle = event(&key, kind, 200, json!([["d", "address"]]), "middle");
        let (_dir, env) = snapshot(&[newest.clone(), old, middle]);
        for filter in [
            json!({}),
            json!({"kinds":[kind]}),
            json!({"authors":[newest["pubkey"]]}),
            json!({"kinds":[kind],"authors":[newest["pubkey"]]}),
        ] {
            for count in [false, true] {
                assert_eq!(
                    query(&env, std::slice::from_ref(&filter), count),
                    ids(std::slice::from_ref(&newest)),
                    "kind {kind}, count {count}, filter {filter}"
                );
            }
        }
        assert_eq!(
            env.begin_ro().unwrap().entries(env.dbis().event).unwrap(),
            3
        );
    }
}

#[test]
fn addresses_authors_kinds_and_regular_events_remain_independent() {
    let a = key();
    let b = key();
    let mut events = Vec::new();
    let mut expected = Vec::new();
    for key in [&a, &b] {
        for kind in [30000, 30443] {
            for d in ["a", "b", ""] {
                events.push(event(key, kind, 10, json!([["d", d]]), "old"));
                let newest = event(key, kind, 20, json!([["d", d]]), "newest");
                events.push(newest.clone());
                expected.push(newest);
            }
        }
    }
    // NIP-01: 4 <= n < 45 is regular, so kind 41 channel metadata is too.
    for kind in [1, 2, 41, 44, 9999, 40000, 65535] {
        for time in [10, 20] {
            let regular = event(&a, kind, time, json!([["d", "a"]]), "regular");
            events.push(regular.clone());
            expected.push(regular);
        }
    }
    let (_dir, env) = snapshot(&events);
    assert_eq!(query(&env, &[json!({})], false), ids(&expected));
}

#[test]
fn contact_lists_ignore_d_tags_and_addressable_events_use_first_or_empty_d() {
    let key = key();
    let mut events = Vec::new();
    let mut expected = Vec::new();
    for kind in [0, 3, 10002] {
        events.push(event(&key, kind, 10, json!([["d", "old-label"]]), "old"));
        let newest = event(&key, kind, 20, json!([["d", "new-label"]]), "newest");
        events.push(newest.clone());
        expected.push(newest);
    }
    events.push(event(&key, 30443, 10, json!([]), "missing d"));
    let empty = event(&key, 30443, 20, json!([["d", ""]]), "empty d");
    events.push(empty.clone());
    expected.push(empty);
    events.push(event(
        &key,
        30443,
        10,
        json!([["d", "a"], ["d", "old"]]),
        "old",
    ));
    let first = event(&key, 30443, 20, json!([["d", "a"], ["d", "new"]]), "newest");
    events.push(first.clone());
    expected.push(first);
    let (_dir, env) = snapshot(&events);
    assert_eq!(query(&env, &[json!({})], false), ids(&expected));
}

#[test]
fn equal_timestamps_choose_lowest_id_independently_of_insertion_order() {
    let key = key();
    for kind in [3, 10002, 30443] {
        let mut events: Vec<_> = (0..3)
            .map(|i| event(&key, kind, 100, json!([["d", "a"]]), &format!("tie {i}")))
            .collect();
        let winner = ids(&events)[0].clone();
        for _ in 0..2 {
            let (_dir, env) = snapshot(&events);
            assert_eq!(query(&env, &[json!({})], false), vec![winner.clone()]);
            events.reverse();
        }
    }
}

#[test]
fn filters_cannot_resurrect_superseded_events_and_limits_count_only_winners() {
    let key = key();
    for kind in [0, 3, 10002, 30023, 30443] {
        // Search reads a profile's metadata and an article's content, and
        // nothing of the other kinds.
        let searched = matches!(kind, 0 | 30023);
        let content = |word: &str| {
            if kind == 0 {
                json!({ "name": word }).to_string()
            } else {
                word.to_string()
            }
        };
        let old = event(
            &key,
            kind,
            100,
            json!([["d", "a"], ["t", "obsolete"]]),
            &content("obsoleteword"),
        );
        let newest = event(
            &key,
            kind,
            300,
            json!([["d", "a"], ["t", "current"]]),
            &content("currentword"),
        );
        let (_dir, env) = snapshot(&[old.clone(), newest.clone()]);
        for filter in [
            json!({"ids":[old["id"]]}),
            json!({"until":200}),
            json!({"#t":["obsolete"]}),
            json!({"search":"obsoleteword"}),
        ] {
            for count in [false, true] {
                assert!(
                    query(&env, std::slice::from_ref(&filter), count).is_empty(),
                    "kind {kind}, filter {filter}, count {count}"
                );
            }
        }
        // Both the all-search merge and mixed search/chronological paths.
        let winner = ids(std::slice::from_ref(&newest));
        for (filters, expected) in [
            (
                vec![
                    json!({"search":"obsoleteword"}),
                    json!({"search":"currentword"}),
                ],
                if searched { winner.clone() } else { Vec::new() },
            ),
            (
                vec![json!({"search":"obsoleteword"}), json!({"kinds":[kind]})],
                winner.clone(),
            ),
        ] {
            assert_eq!(query(&env, &filters, false), expected, "kind {kind}");
        }
    }
    let old = event(&key, 30443, 200, json!([["d", "a"]]), "old");
    let newest = event(&key, 30443, 300, json!([["d", "a"]]), "newest");
    let other = event(&key, 30443, 100, json!([["d", "b"]]), "other address");
    let (_dir, env) = snapshot(&[old, newest.clone(), other.clone()]);
    assert_eq!(
        query(&env, &[json!({"limit":2})], false),
        ids(&[newest, other])
    );
}

#[test]
fn hidden_winner_does_not_restore_an_older_version() {
    let key = key();
    for kind in [3, 30443] {
        for expire in [false, true] {
            let old = event(&key, kind, 100, json!([["d", "a"]]), "old");
            let tags = if expire {
                json!([["d", "a"], ["expiration", "200"]])
            } else {
                json!([["d", "a"]])
            };
            let newest = event(&key, kind, 200, tags, "newest");
            let (_dir, env) = snapshot(&[old, newest.clone()]);
            if !expire {
                let mut txn = env.begin_rw().unwrap();
                wok_db::ban_event(
                    &mut txn,
                    &hex::decode(newest["id"].as_str().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap(),
                    "test",
                )
                .unwrap();
                txn.commit().unwrap();
            }
            assert!(query(&env, &[json!({})], false).is_empty());
        }
    }
}

#[test]
fn replacement_visibility_refreshes_with_the_read_transaction() {
    let key = key();
    let old = event(&key, 30443, 100, json!([["d", "a"]]), "old");
    let (_dir, env) = snapshot(std::slice::from_ref(&old));
    let read = env.begin_ro().unwrap();
    let packed = PackedEventView::new(read.get_u64(env.dbis().event, 1).unwrap().unwrap()).unwrap();
    let policy = ReadVisibility::default();
    assert!(policy
        .allows(&ReadSnapshot::for_stored(&read), packed)
        .unwrap());
    let newest = event(&key, 30443, 200, json!([["d", "a"]]), "newest");
    std::thread::scope(|scope| {
        scope
            .spawn(|| wok_compat::write_event_to_env(&env, &newest))
            .join()
            .unwrap()
    });
    assert!(policy
        .allows(&ReadSnapshot::for_stored(&read), packed)
        .unwrap());
    let owned = read.get_u64(env.dbis().event, 1).unwrap().unwrap().to_vec();
    drop(read);
    // The copy is no longer stored, so only a snapshot for any event sees
    // that the newest version, which is, replaces it.
    assert!(!policy
        .allows(
            &ReadSnapshot::new(&env.begin_ro().unwrap()),
            PackedEventView::new(&owned).unwrap()
        )
        .unwrap());
}

async fn server(env: Env, dir: &std::path::Path) -> (wok_relay::RelayHandle, Wire) {
    let mut cfg = wok_relay::Config {
        db: dir.to_path_buf(),
        ..Default::default()
    };
    cfg.relay.auth.enabled = false;
    let handle = wok_relay::start(env, cfg).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let relay = handle.clone();
    tokio::spawn(async move {
        let _ = wok_ws::serve_listener(relay, listener).await;
    });
    (
        handle,
        Wire::connect(&format!("ws://{addr}/")).await.unwrap(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_history_count_and_live_updates_only_serve_current_versions() {
    let key = key();
    for kind in [0, 3, 10002, 30443] {
        let old = event(&key, kind, 100, json!([["d", "a"]]), "old");
        let newest = event(&key, kind, 200, json!([["d", "a"]]), "newest");
        let (_dir, env) = snapshot(&[newest.clone(), old]);
        let (handle, mut wire) = server(env, _dir.path()).await;
        wire.send(json!(["REQ","history",{"kinds":[kind]}]))
            .await
            .unwrap();
        let mut historical = Vec::new();
        loop {
            let frame = wire.recv().await.unwrap();
            match frame[0].as_str() {
                Some("EVENT") => historical.push(frame[2].clone()),
                Some("EOSE") => break,
                _ => panic!("unexpected {frame}"),
            }
        }
        assert_eq!(
            ids(&historical),
            ids(std::slice::from_ref(&newest)),
            "kind {kind}"
        );
        wire.send(json!(["COUNT","count",{"kinds":[kind]}]))
            .await
            .unwrap();
        let count = wire.recv().await.unwrap();
        assert_eq!(count[0], "COUNT");
        assert_eq!(count[2]["count"], 1);
        let update = event(&key, kind, 300, json!([["d", "a"]]), "update");
        wire.send(json!(["EVENT", update])).await.unwrap();
        let mut ack = false;
        let mut live = false;
        for _ in 0..2 {
            let frame = wire.recv().await.unwrap();
            match frame[0].as_str() {
                Some("OK") => {
                    assert_eq!(frame[1], update["id"]);
                    assert_eq!(frame[2], true);
                    ack = true;
                }
                Some("EVENT") => {
                    assert_eq!(frame[2]["id"], update["id"]);
                    live = true;
                }
                _ => panic!("unexpected {frame}"),
            }
        }
        assert!(ack && live);
        handle.request_shutdown();
    }
}

async fn publish(wire: &mut Wire, event: &Value) -> Value {
    wire.send(json!(["EVENT", event])).await.unwrap();
    let ok = wire.recv().await.unwrap();
    assert_eq!(ok[0], "OK", "{ok}");
    assert_eq!(ok[1], event["id"], "{ok}");
    ok
}

async fn history(wire: &mut Wire, filter: Value) -> Vec<Value> {
    wire.send(json!(["REQ", "history", filter])).await.unwrap();
    let mut stored = Vec::new();
    loop {
        let frame = wire.recv().await.unwrap();
        match frame[0].as_str() {
            Some("EVENT") => stored.push(frame[2].clone()),
            Some("EOSE") => break,
            _ => panic!("unexpected {frame}"),
        }
    }
    wire.send(json!(["CLOSE", "history"])).await.unwrap();
    stored
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn long_d_tags_keep_distinct_addresses() {
    // Single-letter tag values over 255 bytes are indexed by hash. Without
    // that, d="", a 300-byte d and a 301-byte d were one address, and a
    // deletion a tag naming a long d never matched it.
    let key = key();
    let (dir, env) = snapshot(&[]);
    let (handle, mut wire) = server(env, dir.path()).await;
    let pubkey = key.x_only_public_key().0.to_string();
    let (d300, d301) = ("z".repeat(300), "z".repeat(301));
    let empty = event(&key, 30000, 100, json!([["d", ""]]), "empty d");
    let long = event(&key, 30000, 200, json!([["d", &d300]]), "300");
    let longer = event(&key, 30000, 300, json!([["d", &d301]]), "301");
    for event in [&empty, &long, &longer] {
        assert_eq!(publish(&mut wire, event).await[2], true);
    }
    assert_eq!(
        ids(&history(&mut wire, json!({"kinds": [30000]})).await),
        ids(&[empty.clone(), long.clone(), longer.clone()])
    );
    for (d, expected) in [(&d300, &long), (&d301, &longer)] {
        let found = history(&mut wire, json!({"kinds": [30000], "#d": [d]})).await;
        assert_eq!(
            ids(&found),
            ids(std::slice::from_ref(expected)),
            "d {}",
            d.len()
        );
    }

    // A live #d subscription for a long value sees its replacement, which
    // replaces only that address.
    wire.send(json!(["REQ", "live", {"#d": [&d300]}]))
        .await
        .unwrap();
    assert_eq!(wire.recv().await.unwrap()[2]["id"], long["id"]);
    assert_eq!(wire.recv().await.unwrap()[0], "EOSE");
    let replacement = event(&key, 30000, 250, json!([["d", &d300]]), "300 again");
    wire.send(json!(["EVENT", replacement])).await.unwrap();
    let mut frames = vec![wire.recv().await.unwrap(), wire.recv().await.unwrap()];
    frames.sort_by_key(|frame| frame[0].as_str().unwrap().to_owned());
    assert_eq!(frames[0][0], "EVENT", "{frames:?}");
    assert_eq!(frames[0][2]["id"], replacement["id"]);
    assert_eq!(frames[1][0], "OK", "{frames:?}");
    assert_eq!(frames[1][2], true, "{frames:?}");
    wire.send(json!(["CLOSE", "live"])).await.unwrap();
    assert_eq!(
        ids(&history(&mut wire, json!({"kinds": [30000]})).await),
        ids(&[empty.clone(), replacement, longer.clone()])
    );

    // A deletion a tag naming the long address deletes it and nothing else,
    // and stays matchable by #a.
    let address = format!("30000:{pubkey}:{d300}");
    let deletion = event(&key, 5, 400, json!([["a", &address]]), "");
    assert_eq!(publish(&mut wire, &deletion).await[2], true);
    assert_eq!(
        ids(&history(&mut wire, json!({"kinds": [30000, 5]})).await),
        ids(&[empty, longer, deletion.clone()])
    );
    assert_eq!(
        ids(&history(&mut wire, json!({"#a": [&address]})).await),
        ids(std::slice::from_ref(&deletion))
    );
    // An older version of the deleted address cannot come back.
    let stale = event(&key, 30000, 350, json!([["d", &d300]]), "stale");
    let ok = publish(&mut wire, &stale).await;
    assert_eq!(ok[2], false, "{ok}");
    assert_eq!(ok[3], "blocked: user requested deletion", "{ok}");

    // Every stored address fits the a tag that names it: `30000:`, 64 hex
    // digits and `:` leave max_tag_val_size - 71 bytes for d.
    let max = EventLimits::default().max_tag_val_size;
    for len in [max - 70, max] {
        let unnamed = event(&key, 30000, 500, json!([["d", "z".repeat(len)]]), "");
        let ok = publish(&mut wire, &unnamed).await;
        assert_eq!(ok[2], false, "{ok}");
        assert!(ok[3].as_str().unwrap().starts_with("invalid:"), "{ok}");
    }
    let d_max = "z".repeat(max - 71);
    let longest = event(&key, 30000, 500, json!([["d", &d_max]]), "longest");
    assert_eq!(publish(&mut wire, &longest).await[2], true);
    let address = format!("30000:{pubkey}:{d_max}");
    assert_eq!(address.len(), max);
    let deletion = event(&key, 5, 600, json!([["a", &address]]), "");
    assert_eq!(publish(&mut wire, &deletion).await[2], true);
    assert!(
        history(&mut wire, json!({"kinds": [30000], "#d": [&d_max]}))
            .await
            .is_empty()
    );
    handle.request_shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tag_deletions_remove_and_tombstone_replaceable_events() {
    // NIP-01 names a replaceable event `<kind>:<pubkey>:`, with an empty d,
    // and NIP-09 deletes its versions up to the request's created_at.
    let key = key();
    let pubkey = key.x_only_public_key().0.to_string();
    for kind in [0, 10002] {
        let versions: Vec<_> = [100, 200]
            .iter()
            .map(|t| event(&key, kind, *t, json!([]), "version"))
            .collect();
        // Imported history keeps both versions stored.
        let (dir, env) = snapshot(&versions);
        let (handle, mut wire) = server(env, dir.path()).await;
        let filter = json!({"kinds": [kind], "authors": [&pubkey]});
        assert_eq!(
            ids(&history(&mut wire, filter.clone()).await),
            ids(&versions[1..])
        );
        let address = format!("{kind}:{pubkey}:");
        let deletion = event(&key, 5, 300, json!([["a", &address]]), "");
        assert_eq!(publish(&mut wire, &deletion).await[2], true);
        // The older version would be the winner had it survived.
        assert!(
            history(&mut wire, filter.clone()).await.is_empty(),
            "kind {kind}"
        );
        // Neither a deleted version nor another one up to the request's
        // created_at can come back.
        let at_deletion = event(&key, kind, 300, json!([]), "at deletion");
        for stale in versions.iter().chain([&at_deletion]) {
            let ok = publish(&mut wire, stale).await;
            assert_eq!(ok[2], false, "kind {kind}: {ok}");
            assert_eq!(ok[3], "blocked: user requested deletion", "{ok}");
        }
        let newer = event(&key, kind, 301, json!([]), "newer");
        assert_eq!(publish(&mut wire, &newer).await[2], true);
        assert_eq!(
            ids(&history(&mut wire, filter).await),
            ids(std::slice::from_ref(&newer))
        );
        handle.request_shutdown();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deletion_a_tags_spelling_kinds_with_leading_zeros_are_refused() {
    // `030000:<pubkey>:x` deleted the stored versions of `30000:<pubkey>:x`,
    // but its tombstone, the hash of that spelling, never refused later ones.
    let key = key();
    let pubkey = key.x_only_public_key().0.to_string();
    let addressable = event(&key, 30000, 100, json!([["d", "x"]]), "addressable");
    let replaceable = event(&key, 10002, 100, json!([]), "replaceable");
    let (dir, env) = snapshot(&[addressable.clone(), replaceable.clone()]);
    let (handle, mut wire) = server(env, dir.path()).await;
    let filter = json!({"kinds": [10002, 30000]});
    let stored = ids(&[addressable, replaceable]);
    for address in [
        format!("030000:{pubkey}:x"),
        format!("010002:{pubkey}:"),
        format!("00:{pubkey}:"),
    ] {
        let deletion = event(&key, 5, 200, json!([["a", &address]]), "");
        let ok = publish(&mut wire, &deletion).await;
        assert_eq!(ok[2], false, "{ok}");
        assert_eq!(ok[3], "invalid: a tag kind has leading zeros", "{ok}");
    }
    assert_eq!(ids(&history(&mut wire, filter.clone()).await), stored);

    // The canonical spellings delete both, and refuse older versions.
    let deletion = event(
        &key,
        5,
        200,
        json!([
            ["a", format!("30000:{pubkey}:x")],
            ["a", format!("10002:{pubkey}:")]
        ]),
        "",
    );
    assert_eq!(publish(&mut wire, &deletion).await[2], true);
    assert!(history(&mut wire, filter).await.is_empty());
    for stale in [
        event(&key, 30000, 150, json!([["d", "x"]]), "stale"),
        event(&key, 10002, 150, json!([]), "stale"),
    ] {
        let ok = publish(&mut wire, &stale).await;
        assert_eq!(ok[2], false, "{ok}");
        assert_eq!(ok[3], "blocked: user requested deletion", "{ok}");
    }
    handle.request_shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn channel_metadata_for_each_channel_survives() {
    // NIP-01 makes 4 <= n < 45 regular. NIP-28 kind 41 names its channel
    // with an e tag, so one author's metadata for two channels is two
    // events, not a replacement.
    let key = key();
    let (dir, env) = snapshot(&[]);
    let (handle, mut wire) = server(env, dir.path()).await;
    let channels = ["aa".repeat(32), "bb".repeat(32)];
    let mut published = Vec::new();
    for (time, channel) in [(100, &channels[0]), (200, &channels[1])] {
        let metadata = event(&key, 41, time, json!([["e", channel]]), "{}");
        assert_eq!(publish(&mut wire, &metadata).await[2], true);
        published.push(metadata);
    }
    for (filter, expected) in [
        (json!({"kinds": [41]}), published.clone()),
        (
            json!({"kinds": [41], "#e": [channels[0]]}),
            vec![published[0].clone()],
        ),
    ] {
        wire.send(json!(["REQ", "channels", filter])).await.unwrap();
        let mut stored = Vec::new();
        loop {
            let frame = wire.recv().await.unwrap();
            match frame[0].as_str() {
                Some("EVENT") => stored.push(frame[2].clone()),
                Some("EOSE") => break,
                _ => panic!("unexpected {frame}"),
            }
        }
        assert_eq!(ids(&stored), ids(&expected), "{filter}");
    }
    handle.request_shutdown();
}

/// A read snapshot reads which policy tables can hide an event once, and
/// then skips the lookups they cannot answer. For every stored event, with
/// and without retained history and as each kind of policy record is added,
/// it must answer exactly as the lookups themselves do.
#[test]
fn read_snapshots_answer_as_the_policy_lookups_do() {
    let (author, other, recipient) = (key(), key(), key());
    let pubkey = |key: &Keypair| key.x_only_public_key().0.serialize();
    let note = event(&author, 1, 100, json!([]), "note");
    let latest = vec![
        note.clone(),
        event(&other, 1, 101, json!([]), "other note"),
        event(&author, 7, 102, json!([]), "reaction"),
        event(&author, 0, 200, json!([]), "profile"),
        event(&other, 30023, 200, json!([["d", "a"]]), "article"),
        event(&other, 30023, 150, json!([["d", "b"]]), "other article"),
        event(
            &other,
            1059,
            103,
            json!([["p", hex::encode(pubkey(&recipient))]]),
            "wrap",
        ),
    ];
    let mut history = latest.clone();
    history.push(event(&author, 0, 100, json!([]), "old profile"));
    history.push(event(
        &other,
        30023,
        100,
        json!([["d", "a"]]),
        "old article",
    ));
    let note_id: [u8; 32] = hex::decode(note["id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    type Step<'a> = (&'a str, Box<dyn Fn(&mut wok_db::RwTxn<'_>) + 'a>);
    let steps: Vec<Step> = vec![
        ("no policy records", Box::new(|_| {})),
        (
            "an allowed pubkey",
            Box::new(|txn| wok_db::allow_pubkey(txn, &pubkey(&other), "").unwrap()),
        ),
        (
            "a banned event",
            Box::new(|txn| wok_db::ban_event(txn, &note_id, "").unwrap()),
        ),
        (
            "a disallowed kind",
            Box::new(|txn| wok_db::disallow_kind(txn, 7).unwrap()),
        ),
        (
            "a vanished recipient",
            Box::new(|txn| wok_db::mark_vanished(txn, &pubkey(&recipient), 1).unwrap()),
        ),
        (
            "a vanished author",
            Box::new(|txn| wok_db::mark_vanished(txn, &pubkey(&other), 150).unwrap()),
        ),
        (
            "a banned author",
            Box::new(|txn| wok_db::ban_pubkey(txn, &pubkey(&author), "").unwrap()),
        ),
    ];
    for (events, superseded) in [(&latest, 0), (&history, 2)] {
        let (_dir, env) = snapshot(events);
        assert_eq!(
            wok_db::state::superseded_events_ro(&env.begin_ro().unwrap()).unwrap(),
            Some(superseded)
        );
        let mut hidden = Vec::new();
        for (step, apply) in &steps {
            let mut txn = env.begin_rw().unwrap();
            apply(&mut txn);
            txn.commit().unwrap();
            let txn = env.begin_ro().unwrap();
            let (any, stored) = (ReadSnapshot::new(&txn), ReadSnapshot::for_stored(&txn));
            let mut count = 0;
            wok_db::foreach_event_from(&txn, 1, |_, raw| {
                let packed = PackedEventView::new(raw).unwrap();
                let expected = !wok_db::is_event_vanished_ro(&txn, packed).unwrap()
                    && !wok_db::is_event_moderated_ro(&txn, packed).unwrap()
                    && !wok_db::is_event_superseded_ro(&txn, packed).unwrap();
                for snapshot in [&any, &stored] {
                    assert_eq!(
                        ReadVisibility::default()
                            .globally_visible(snapshot, packed)
                            .unwrap(),
                        expected,
                        "{step}, kind {}, {superseded} superseded",
                        packed.kind()
                    );
                }
                count += usize::from(!expected);
                true
            })
            .unwrap();
            hidden.push(count);
        }
        // Each step hides more, so every kind of record was exercised.
        assert!(hidden.windows(2).skip(1).all(|w| w[0] < w[1]), "{hidden:?}");
    }
}

#[test]
fn kind41_history_packed_as_replaceable_is_regular_after_upgrade() {
    // strfry and earlier Wok releases packed kind 41 with a virtual empty d
    // and counted extra versions per author as superseded history under the
    // state key "superseded-events". Both versions must now be visible, and
    // the count is redone on the next writable open.
    let key = key();
    let channels = ["aa".repeat(32), "bb".repeat(32)];
    let records: Vec<_> = [(100, &channels[0]), (200, &channels[1])]
        .into_iter()
        .map(|(time, channel)| {
            let metadata = event(&key, 41, time, json!([["e", channel]]), "{}");
            let parsed =
                parse_and_verify_event(&metadata, &EventLimits::default(), None, true, false)
                    .unwrap();
            let view = parsed.packed.view();
            let mut tags = wok_event::PackedEventTagBuilder::default();
            tags.add('d', b"").unwrap();
            tags.add('e', &hex::decode(channel).unwrap()).unwrap();
            let legacy =
                wok_event::PackedEventBuilder::build(view.id(), view.pubkey(), time, 41, 0, &tags)
                    .unwrap();
            (metadata, (legacy.into_bytes(), parsed.json))
        })
        .collect();
    let (published, records): (Vec<_>, Vec<_>) = records.into_iter().unzip();
    let (_dir, env) = snapshot_records(&records);
    let state = env.dbis().state.unwrap();
    {
        // What a writable open by an older release leaves behind.
        let mut txn = env.begin_rw().unwrap();
        txn.clear(state).unwrap();
        txn.put(state, b"superseded-events", &1u64.to_le_bytes(), 0)
            .unwrap();
        txn.commit().unwrap();
    }
    let txn = env.begin_ro().unwrap();
    assert_eq!(wok_db::state::superseded_events_ro(&txn).unwrap(), None);
    let report = wok_db::check_integrity(&txn).unwrap();
    assert!(report.ok(), "{:?}", report.issues);
    assert_eq!((report.superseded_groups, report.superseded_events), (0, 0));
    drop(txn);
    assert_eq!(query(&env, &[json!({})], false), ids(&published));

    env.ensure_initialized().unwrap();
    let txn = env.begin_ro().unwrap();
    assert!(txn.get(state, b"superseded-events").unwrap().is_none());
    assert_eq!(wok_db::state::superseded_events_ro(&txn).unwrap(), Some(0));
    assert!(wok_db::check_integrity(&txn).unwrap().ok());
    drop(txn);
    assert_eq!(query(&env, &[json!({})], false), ids(&published));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn negentropy_hides_stale_ids_with_and_without_a_matching_persistent_tree() {
    let key = key();
    let mut events = Vec::new();
    let mut expected = Vec::new();
    for kind in [3, 30443] {
        let old = event(&key, kind, 100, json!([["d", "a"]]), "old");
        let newest = event(&key, kind, 200, json!([["d", "a"]]), "newest");
        events.extend([old, newest.clone()]);
        expected.push(newest);
    }
    for filter in [json!({}), json!({"kinds":[3,30443]})] {
        let (dir, env) = snapshot(&events);
        let (handle, mut wire) = server(env, dir.path()).await;
        let mut store = wok_negentropy::Vector::new();
        store.seal().unwrap();
        let mut client = wok_negentropy::Negentropy::new(store, 60000).unwrap();
        wire.send(json!([
            "NEG-OPEN",
            "sync",
            filter,
            hex::encode(client.initiate().unwrap())
        ]))
        .await
        .unwrap();
        let mut have = Vec::new();
        let mut need = Vec::new();
        loop {
            let frame = wire.recv().await.unwrap();
            assert_eq!(frame[0], "NEG-MSG", "{frame}");
            let response = client
                .reconcile_with_ids(
                    &hex::decode(frame[2].as_str().unwrap()).unwrap(),
                    &mut have,
                    &mut need,
                )
                .unwrap();
            if let Some(response) = response {
                wire.send(json!(["NEG-MSG", "sync", hex::encode(response)]))
                    .await
                    .unwrap();
            } else {
                break;
            }
        }
        let mut need: Vec<_> = need.iter().map(hex::encode).collect();
        need.sort();
        assert_eq!(need, ids(&expected), "filter {filter}");
        handle.request_shutdown();
    }
}

fn stored_ids(env: &Env) -> Vec<String> {
    let txn = env.begin_ro().unwrap();
    let mut result = Vec::new();
    wok_db::foreach_event_from(&txn, 0, |_, raw| {
        result.push(hex::encode(PackedEventView::new(raw).unwrap().id()));
        true
    })
    .unwrap();
    result.sort();
    result
}

fn write_with_quota(
    env: &Env,
    event: &Value,
    quota: u64,
    commit: bool,
) -> wok_db::EventWriteStatus {
    let parsed = parse_and_verify_event(event, &EventLimits::default(), None, true, false).unwrap();
    let mut events = [wok_db::EventToWrite::new(
        parsed.packed.into_bytes(),
        parsed.json,
    )];
    let mut txn = env.begin_rw().unwrap();
    let mut sink = wok_negentropy::NegentropyFilterCache::default();
    wok_db::write::write_events_with_quota(
        &mut txn,
        &mut sink,
        &mut events,
        &wok_db::VanishPolicy::disabled(),
        quota,
    )
    .unwrap();
    if commit {
        txn.commit().unwrap();
    } else {
        txn.abort();
    }
    events[0].status
}

#[test]
fn replacement_writer_removes_all_versions_atomically_and_uses_net_quota() {
    for kind in [0, 3, 10000, 19999, 30000, 30443, 39999] {
        let key = key();
        let events: Vec<_> = [300, 100, 200]
            .iter()
            .map(|t| event(&key, kind, *t, json!([["d", "a"]]), "old"))
            .collect();
        let (_dir, env) = snapshot(&events);
        let newest = event(&key, kind, 400, json!([["d", "a"]]), "newest");
        assert_eq!(
            write_with_quota(&env, &newest, 1, false),
            wok_db::EventWriteStatus::Written
        );
        assert_eq!(
            stored_ids(&env),
            ids(&events),
            "abort must retain every record"
        );
        wok_negentropy::verify_tree(&env.begin_ro().unwrap(), 1, "{}").unwrap();
        assert_eq!(
            write_with_quota(&env, &newest, 1, true),
            wok_db::EventWriteStatus::Written,
            "kind {kind}"
        );
        assert_eq!(stored_ids(&env), ids(std::slice::from_ref(&newest)));
        assert!(wok_db::check_integrity(&env.begin_ro().unwrap())
            .unwrap()
            .ok());
        wok_negentropy::verify_tree(&env.begin_ro().unwrap(), 1, "{}").unwrap();
        let mut txn = env.begin_rw().unwrap();
        assert_eq!(
            wok_db::state::author_count(
                &mut txn,
                &hex::decode(newest["pubkey"].as_str().unwrap()).unwrap()
            )
            .unwrap(),
            1
        );
    }
}

#[test]
fn stale_arrivals_compare_every_version_and_do_not_mutate_storage() {
    for kind in [3, 10002, 30443] {
        let key = key();
        let mut ties: Vec<_> = (0..3)
            .map(|i| event(&key, kind, 300, json!([["d", "a"]]), &format!("tie{i}")))
            .collect();
        ties.sort_by_key(|v| v["id"].as_str().unwrap().to_owned());
        let oldest = event(&key, kind, 100, json!([["d", "a"]]), "oldest");
        let stored = [ties[0].clone(), oldest];
        let (_dir, env) = snapshot(&stored);
        for incoming in [
            event(&key, kind, 200, json!([["d", "a"]]), "middle"),
            ties[1].clone(),
        ] {
            assert_eq!(
                write_with_quota(&env, &incoming, 0, true),
                wok_db::EventWriteStatus::Replaced
            );
            assert_eq!(stored_ids(&env), ids(&stored));
        }
        assert_eq!(
            write_with_quota(&env, &ties[0], 0, true),
            wok_db::EventWriteStatus::Duplicate
        );
        assert_eq!(stored_ids(&env), ids(&stored));
        wok_negentropy::verify_tree(&env.begin_ro().unwrap(), 1, "{}").unwrap();
    }
}

#[test]
fn rejected_replacements_leave_candidates_intact() {
    let key = key();
    let old = event(&key, 30443, 100, json!([["d", "a"]]), "old");
    let other = event(&key, 1, 100, json!([]), "other");
    let newer = event(&key, 30443, 150, json!([["d", "a"]]), "new");
    let (_dir, env) = snapshot(&[old.clone(), other.clone()]);
    assert_eq!(
        write_with_quota(&env, &newer, 1, true),
        wok_db::EventWriteStatus::QuotaExceeded
    );
    assert_eq!(stored_ids(&env), ids(&[old.clone(), other]));
    let address = format!("30443:{}:a", old["pubkey"].as_str().unwrap());
    let deletion = event(&key, 5, 200, json!([["a", address]]), "delete");
    // Imported deletion history can coexist with a record it tombstones.
    let (_dir, env) = snapshot(&[old.clone(), deletion.clone()]);
    assert_eq!(
        write_with_quota(&env, &newer, 0, true),
        wok_db::EventWriteStatus::Deleted
    );
    assert_eq!(stored_ids(&env), ids(&[old, deletion]));
}

#[test]
fn address_deletion_removes_all_eligible_versions_and_keeps_newer_versions() {
    let key = key();
    let events: Vec<_> = [300, 100, 200]
        .iter()
        .map(|t| event(&key, 30443, *t, json!([["d", "a"]]), "version"))
        .collect();
    let other = event(&key, 30443, 100, json!([["d", "b"]]), "other address");
    let mut input = events.clone();
    input.push(other.clone());
    let (_dir, env) = snapshot(&input);
    let address = format!("30443:{}:a", events[0]["pubkey"].as_str().unwrap());
    let deletion = event(
        &key,
        5,
        250,
        json!([["a", address], ["a", address]]),
        "delete",
    );
    assert_eq!(
        write_with_quota(&env, &deletion, 0, true),
        wok_db::EventWriteStatus::Written
    );
    assert_eq!(stored_ids(&env), ids(&[events[0].clone(), other, deletion]));
    wok_negentropy::verify_tree(&env.begin_ro().unwrap(), 1, "{}").unwrap();
}

#[test]
fn long_addresses_are_deleted_and_tombstoned_through_their_hashes() {
    // A 200-byte d is packed as is but its a tag is hashed; a 300-byte d is
    // hashed as well. Either deletion removes and tombstones the address, and
    // removing the deletion request removes its hashed tombstone too.
    let key = key();
    let pubkey = key.x_only_public_key().0.to_string();
    for d in ["y".repeat(200), "z".repeat(300)] {
        let versions: Vec<_> = [100, 200]
            .iter()
            .map(|t| event(&key, 30443, *t, json!([["d", &d]]), "version"))
            .collect();
        let other = event(&key, 30443, 100, json!([["d", "short"]]), "other");
        let mut input = versions.clone();
        input.push(other.clone());
        let (_dir, env) = snapshot(&input);
        let address = format!("30443:{pubkey}:{d}");
        assert!(address.len() > wok_event::MAX_INDEXED_TAG_VAL_SIZE);
        let deletion = event(&key, 5, 300, json!([["a", &address]]), "delete");
        assert_eq!(
            write_with_quota(&env, &deletion, 0, true),
            wok_db::EventWriteStatus::Written
        );
        assert_eq!(
            stored_ids(&env),
            ids(&[other.clone(), deletion.clone()]),
            "d {}",
            d.len()
        );
        let stale = event(&key, 30443, 250, json!([["d", &d]]), "stale");
        assert_eq!(
            write_with_quota(&env, &stale, 0, true),
            wok_db::EventWriteStatus::Deleted,
            "d {}",
            d.len()
        );
        assert!(wok_db::check_integrity(&env.begin_ro().unwrap())
            .unwrap()
            .ok());

        let id = hex::decode(deletion["id"].as_str().unwrap()).unwrap();
        let (lev, _) = wok_db::lookup_event_by_id_ro(&env.begin_ro().unwrap(), &id)
            .unwrap()
            .unwrap();
        let mut txn = env.begin_rw().unwrap();
        wok_db::delete_events(&mut txn, &mut wok_db::NoopNegentropy, [lev]).unwrap();
        txn.commit().unwrap();
        let txn = env.begin_ro().unwrap();
        assert_eq!(txn.entries(env.dbis().event_replace_deletion).unwrap(), 0);
        assert!(wok_db::check_integrity(&txn).unwrap().ok());
        drop(txn);
        let fresh = event(&key, 30443, 250, json!([["d", &d]]), "fresh");
        assert_eq!(
            write_with_quota(&env, &fresh, 0, true),
            wok_db::EventWriteStatus::Written
        );
    }
}

#[test]
fn replaceable_address_deletion_removes_eligible_versions_and_keeps_newer_versions() {
    let key = key();
    let pubkey = key.x_only_public_key().0.to_string();
    for kind in [0, 3, 10000, 19999] {
        let versions: Vec<_> = [300, 100, 200]
            .iter()
            .map(|t| event(&key, kind, *t, json!([]), "version"))
            .collect();
        // Neither another author's version nor the addressable `30000:pk:`
        // shares the address.
        let other_author = event(&self::key(), kind, 100, json!([]), "other author");
        let addressable = event(&key, 30000, 100, json!([]), "addressable");
        let mut input = versions.clone();
        input.extend([other_author.clone(), addressable.clone()]);
        let (_dir, env) = snapshot(&input);
        let deletion = event(
            &key,
            5,
            250,
            json!([["a", format!("{kind}:{pubkey}:")]]),
            "delete",
        );
        assert_eq!(
            write_with_quota(&env, &deletion, 0, true),
            wok_db::EventWriteStatus::Written
        );
        assert_eq!(
            stored_ids(&env),
            ids(&[
                versions[0].clone(),
                other_author,
                addressable,
                deletion.clone()
            ]),
            "kind {kind}"
        );
        assert_eq!(
            env.begin_ro()
                .unwrap()
                .entries(env.dbis().event_replace_deletion)
                .unwrap(),
            1
        );
        let report = wok_db::check_integrity(&env.begin_ro().unwrap()).unwrap();
        assert!(report.ok(), "{:?}", report.issues);
        assert_eq!(report.legacy_untombstoned_deletions, 0);
        wok_negentropy::verify_tree(&env.begin_ro().unwrap(), 1, "{}").unwrap();

        // Once the newer version is gone too, the tombstone refuses older ones.
        let (_dir, env) = snapshot(&versions[1..]);
        assert_eq!(
            write_with_quota(&env, &deletion, 0, true),
            wok_db::EventWriteStatus::Written
        );
        assert_eq!(stored_ids(&env), ids(std::slice::from_ref(&deletion)));
        for time in [150, 250] {
            let stale = event(&key, kind, time, json!([]), "stale");
            assert_eq!(
                write_with_quota(&env, &stale, 0, true),
                wok_db::EventWriteStatus::Deleted,
                "kind {kind} at {time}"
            );
        }
        let newer = event(&key, kind, 251, json!([]), "newer");
        assert_eq!(
            write_with_quota(&env, &newer, 0, true),
            wok_db::EventWriteStatus::Written
        );

        // Removing the request removes its tombstone.
        let id = hex::decode(deletion["id"].as_str().unwrap()).unwrap();
        let (lev, _) = wok_db::lookup_event_by_id_ro(&env.begin_ro().unwrap(), &id)
            .unwrap()
            .unwrap();
        let mut txn = env.begin_rw().unwrap();
        wok_db::delete_events(&mut txn, &mut wok_db::NoopNegentropy, [lev]).unwrap();
        txn.commit().unwrap();
        let txn = env.begin_ro().unwrap();
        assert_eq!(txn.entries(env.dbis().event_replace_deletion).unwrap(), 0);
        assert!(wok_db::check_integrity(&txn).unwrap().ok());
    }

    // A replaceable event's address has an empty d; `10002:pk:x` names nothing.
    let version = event(&key, 10002, 100, json!([["d", "x"]]), "version");
    let (_dir, env) = snapshot(std::slice::from_ref(&version));
    let deletion = event(
        &key,
        5,
        200,
        json!([["a", format!("10002:{pubkey}:x")]]),
        "",
    );
    assert_eq!(
        write_with_quota(&env, &deletion, 0, true),
        wok_db::EventWriteStatus::Written
    );
    assert_eq!(stored_ids(&env), ids(&[version, deletion]));
    let txn = env.begin_ro().unwrap();
    assert_eq!(txn.entries(env.dbis().event_replace_deletion).unwrap(), 0);
}

#[test]
fn deletions_stored_without_tombstones_are_applied_by_reindex() {
    // strfry and earlier Wok releases did not tombstone `<kind>:<pubkey>:`,
    // and tombstoned a padded kind by its spelling, so the versions such a
    // request names were never deleted or came back. Integrity accepts the
    // missing tombstones and counts the requests; reindex applies them.
    let key = key();
    let pubkey = key.x_only_public_key().0.to_string();
    let replaceable = event(&key, 10002, 100, json!([]), "never deleted");
    let newer = event(&key, 10002, 300, json!([]), "newer");
    let came_back = event(&key, 30000, 150, json!([["d", "x"]]), "came back");
    let deletion = event(
        &key,
        5,
        200,
        json!([
            ["a", format!("10002:{pubkey}:")],
            ["a", format!("030000:{pubkey}:x")]
        ]),
        "",
    );
    let (_dir, env) = snapshot_records(&[
        packing(&replaceable),
        packing(&newer),
        packing(&came_back),
        stored_packing(&deletion),
    ]);
    {
        let mut txn = env.begin_rw().unwrap();
        for address in [format!("10002:{pubkey}:"), format!("30000:{pubkey}:x")] {
            let key =
                wok_db::keys::make_key_string_u64(&wok_event::sha256(address.as_bytes()), 200);
            let lev = 4u64.to_ne_bytes();
            assert!(txn
                .del(env.dbis().event_replace_deletion, &key, Some(&lev))
                .unwrap());
        }
        txn.commit().unwrap();
    }
    let report = wok_db::check_integrity(&env.begin_ro().unwrap()).unwrap();
    assert!(report.ok(), "{:?}", report.issues);
    assert_eq!(report.legacy_untombstoned_deletions, 1);
    assert_eq!(report.expected_index_entries, report.actual_index_entries);

    let (_repaired_dir, repaired, stats) = reindex(&env);
    assert_eq!(stats.deleted_versions, BTreeSet::from([1, 3]));
    assert_eq!(stored_ids(&repaired), ids(&[newer, deletion]));
    let report = wok_db::check_integrity(&repaired.begin_ro().unwrap()).unwrap();
    assert!(report.ok(), "{:?}", report.issues);
    assert_eq!(report.legacy_untombstoned_deletions, 0);
    // The padded spelling's own entry, and both canonical ones.
    let txn = repaired.begin_ro().unwrap();
    assert_eq!(
        txn.entries(repaired.dbis().event_replace_deletion).unwrap(),
        3
    );
    drop(txn);
    let stale = event(&key, 30000, 180, json!([["d", "x"]]), "stale");
    assert_eq!(
        write_with_quota(&env, &stale, 0, false),
        wok_db::EventWriteStatus::Written
    );
    assert_eq!(
        write_with_quota(&repaired, &stale, 0, false),
        wok_db::EventWriteStatus::Deleted
    );
}

#[test]
fn stored_deletions_spelling_kinds_with_leading_zeros_act_on_the_canonical_address() {
    // Ingest refuses such requests now; strfry and earlier releases stored
    // them. Written directly, one deletes what the canonical spelling names
    // and refuses older versions of it.
    let key = key();
    let pubkey = key.x_only_public_key().0.to_string();
    for (kind, address) in [
        (30000, format!("030000:{pubkey}:")),
        (10002, format!("010002:{pubkey}:")),
    ] {
        let version = event(&key, kind, 100, json!([]), "version");
        let (_dir, env) = snapshot(std::slice::from_ref(&version));
        let deletion = event(&key, 5, 200, json!([["a", &address]]), "");
        assert!(
            parse_and_verify_event(&deletion, &EventLimits::default(), None, true, false).is_err()
        );
        let (packed, json) = stored_packing(&deletion);
        let mut events = [wok_db::EventToWrite::new(packed, json)];
        let mut txn = env.begin_rw().unwrap();
        wok_db::write::write_events(&mut txn, &mut wok_db::NoopNegentropy, &mut events, false)
            .unwrap();
        txn.commit().unwrap();
        assert_eq!(events[0].status, wok_db::EventWriteStatus::Written);
        assert_eq!(stored_ids(&env), ids(&[deletion]), "{address}");
        let stale = event(&key, kind, 150, json!([]), "stale");
        assert_eq!(
            write_with_quota(&env, &stale, 0, false),
            wok_db::EventWriteStatus::Deleted,
            "{address}"
        );
        let report = wok_db::check_integrity(&env.begin_ro().unwrap()).unwrap();
        assert!(report.ok(), "{:?}", report.issues);
        assert_eq!(report.legacy_untombstoned_deletions, 0);
    }
}

#[test]
fn integrity_reports_retained_versions_without_treating_them_as_corruption() {
    let key = key();
    let mut events = Vec::new();
    for kind in [0, 3, 30443, 1] {
        for time in [100, 200, 300] {
            events.push(event(&key, kind, time, json!([["d", "a"]]), "version"));
        }
    }
    let (_dir, env) = snapshot(&events);
    let report = wok_db::check_integrity(&env.begin_ro().unwrap()).unwrap();
    assert!(report.ok());
    let json = serde_json::to_value(report).unwrap();
    assert_eq!(json["superseded_groups"], 3);
    assert_eq!(json["superseded_events"], 6);
}

#[test]
fn physical_tree_fast_path_tracks_retained_history_transactionally() {
    let key = key();
    for kind in [0, 3, 10002, 30443] {
        let old = event(&key, kind, 100, json!([]), "old");
        let newest = event(&key, kind, 200, json!([]), "newest");
        let (_dir, env) = snapshot(std::slice::from_ref(&old));
        let filter = NostrFilterGroup::from_value(&json!({}), 500, 3, 16).unwrap();
        let visible = |env: &Env| {
            wok_query::visibility::physical_tree_is_globally_visible(
                &env.begin_ro().unwrap(),
                &filter.filters[0],
            )
            .unwrap()
        };
        assert!(visible(&env), "clean kind {kind}");
        wok_compat::write_event_to_env(&env, &newest);
        assert!(visible(&env), "normal replacement kind {kind}");

        let (_dir, dirty) = snapshot(&[old, newest]);
        assert!(!visible(&dirty));
        {
            let mut txn = dirty.begin_rw().unwrap();
            wok_db::delete_events(&mut txn, &mut wok_db::NoopNegentropy, [1]).unwrap();
            // Abort must not turn the committed history into a clean proof.
        }
        assert!(!visible(&dirty));
        let before = dirty.begin_ro().unwrap();
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let mut txn = dirty.begin_rw().unwrap();
                    wok_db::delete_events(&mut txn, &mut wok_db::NoopNegentropy, [1]).unwrap();
                    txn.commit().unwrap();
                })
                .join()
                .unwrap();
        });
        assert!(!wok_query::visibility::physical_tree_is_globally_visible(
            &before,
            &filter.filters[0]
        )
        .unwrap());
        drop(before);
        assert!(visible(&dirty), "history cleared kind {kind}");
    }
}

#[test]
fn older_databases_initialize_history_counts_without_changing_events() {
    let key = key();
    let events = [
        event(&key, 3, 100, json!([]), "old"),
        event(&key, 3, 200, json!([]), "new"),
    ];
    for records in [&events[..1], &events[..]] {
        let (_dir, env) = snapshot(records);
        let before = stored_ids(&env);
        let filter = NostrFilterGroup::from_value(&json!({}), 500, 3, 16).unwrap();
        {
            let mut txn = env.begin_rw().unwrap();
            // Model a database written before replacement bookkeeping existed.
            txn.clear(env.dbis().state.unwrap()).unwrap();
            txn.commit().unwrap();
        }
        assert!(!wok_query::visibility::physical_tree_is_globally_visible(
            &env.begin_ro().unwrap(),
            &filter.filters[0]
        )
        .unwrap());
        env.ensure_initialized().unwrap();
        let txn = env.begin_ro().unwrap();
        assert_eq!(
            wok_db::state::superseded_events_ro(&txn).unwrap(),
            Some(records.len() as u64 - 1)
        );
        assert_eq!(
            wok_query::visibility::physical_tree_is_globally_visible(&txn, &filter.filters[0])
                .unwrap(),
            records.len() == 1
        );
        assert!(wok_db::check_integrity(&txn).unwrap().ok());
        wok_negentropy::verify_tree(&txn, 1, "{}").unwrap();
        drop(txn);
        assert_eq!(stored_ids(&env), before);
    }
}

#[test]
fn corrupt_replacement_indices_do_not_report_spurious_counter_drift() {
    let key = key();
    let events: Vec<_> = (1..=3)
        .map(|time| event(&key, 3, time, json!([]), "history"))
        .collect();
    let (_dir, env) = snapshot(&events);
    {
        let mut txn = env.begin_rw().unwrap();
        // Leave dangling secondary entries, including the middle replacement.
        txn.del_u64(env.dbis().event, 2, None).unwrap();
        txn.commit().unwrap();
    }
    let report = wok_db::check_integrity(&env.begin_ro().unwrap()).unwrap();
    assert!(!report.ok());
    assert!(report.extra_index_entries > 0);
    assert_eq!(report.metadata_errors, 0);
    assert!(!report
        .issues
        .iter()
        .any(|issue| issue.category == "counter-drift"));
}

#[test]
fn purging_superseded_history_keeps_one_winner_per_address() {
    let a = key();
    let b = key();
    let mut events = Vec::new();
    let mut winners = Vec::new();
    for key in [&a, &b] {
        for kind in [0, 3, 10000, 19999] {
            let versions: Vec<_> = [200, 300, 100]
                .iter()
                .map(|t| event(key, kind, *t, json!([["d", "ignored"]]), "version"))
                .collect();
            winners.push(versions[1].clone());
            events.extend(versions);
        }
        for d in ["x", "y"] {
            let old = event(key, 30443, 100, json!([["d", d]]), "old");
            // A hidden winner still wins; older versions must not survive it.
            let newest = event(
                key,
                30443,
                200,
                json!([["d", d], ["expiration", "150"]]),
                "newest",
            );
            winners.push(newest.clone());
            events.extend([newest, old]);
        }
        let mut ties: Vec<_> = (0..3)
            .map(|i| event(key, 10002, 500, json!([]), &format!("tie{i}")))
            .collect();
        ties.sort_by_key(|v| v["id"].as_str().unwrap().to_owned());
        winners.push(ties[0].clone());
        events.extend(ties.into_iter().rev());
        for kind in [1, 41] {
            for time in [100, 200] {
                let regular = event(key, kind, time, json!([["d", "x"]]), "regular");
                winners.push(regular.clone());
                events.push(regular);
            }
        }
    }
    let groups = 2 * (4 + 2 + 1);
    let superseded = 2 * (4 * 2 + 2 + 2);
    let (_dir, env) = snapshot(&events);
    let before = wok_db::count_superseded_ro(&env.begin_ro().unwrap()).unwrap();
    assert_eq!((before.groups, before.events), (groups, superseded));
    assert_eq!(stored_ids(&env), ids(&events), "counting must not delete");

    // One version per transaction exercises resumption between groups.
    let purged =
        wok_db::purge_superseded(&env, wok_negentropy::NegentropyFilterCache::default, 1).unwrap();
    assert_eq!((purged.groups, purged.events), (groups, superseded));
    assert_eq!(stored_ids(&env), ids(&winners));

    let txn = env.begin_ro().unwrap();
    let report = wok_db::check_integrity(&txn).unwrap();
    assert!(report.ok(), "{:?}", report.issues);
    assert_eq!((report.superseded_groups, report.superseded_events), (0, 0));
    // A zero counter is what restores the persistent-tree fast path.
    assert_eq!(wok_db::state::superseded_events_ro(&txn).unwrap(), Some(0));
    wok_negentropy::verify_tree(&txn, 1, "{}").unwrap();
    drop(txn);
    let mut txn = env.begin_rw().unwrap();
    for key in [&a, &b] {
        let pubkey = key.x_only_public_key().0.serialize();
        assert_eq!(
            wok_db::state::author_count(&mut txn, &pubkey).unwrap(),
            (winners.len() / 2) as u64
        );
    }
    txn.abort();

    let again =
        wok_db::purge_superseded(&env, wok_negentropy::NegentropyFilterCache::default, 1000)
            .unwrap();
    assert_eq!((again.groups, again.events), (0, 0));
    assert_eq!(stored_ids(&env), ids(&winners));
}

#[test]
fn purging_commits_between_addresses_without_superseded_history() {
    let key = key();
    let current: Vec<_> = [0, 3, 10002, 30443]
        .iter()
        .map(|kind| event(&key, *kind, 100, json!([["d", "a"]]), "current"))
        .collect();
    let (_dir, env) = snapshot(&current);
    let mut transactions = 0;
    let purged = wok_db::purge_superseded(
        &env,
        || {
            transactions += 1;
            wok_db::NoopNegentropy
        },
        1,
    )
    .unwrap();
    assert_eq!((purged.groups, purged.events), (0, 0));
    // Each address is a completed unit of scan work, even with no losers.
    assert_eq!(transactions, current.len());
    assert_eq!(stored_ids(&env), ids(&current));
}

fn packing(event: &Value) -> (Vec<u8>, String) {
    let parsed = parse_and_verify_event(event, &EventLimits::default(), None, true, false).unwrap();
    (parsed.packed.into_bytes(), parsed.json)
}

/// Pack `event` as a stored record, without ingest's checks: strfry and
/// earlier releases stored deletions whose `a` tags pad the kind.
fn stored_packing(event: &Value) -> (Vec<u8>, String) {
    let packed = wok_event::nostr_json_to_packed_event(event, &EventLimits::default()).unwrap();
    let json = wok_event::normalize_event_json(event).unwrap();
    (packed.into_bytes(), json)
}

/// What strfry and earlier Wok releases stored: every single-letter tag value
/// longer than 255 bytes dropped.
fn legacy_packing(event: &Value) -> (Vec<u8>, String) {
    let (packed, json) = stored_packing(event);
    let view = PackedEventView::new(&packed).unwrap();
    let mut tags = wok_event::PackedEventTagBuilder::default();
    for tag in view.tags() {
        if wok_event::hashed_tag_value_digest(&tag.value).is_none() {
            tags.add(tag.name, &tag.value).unwrap();
        }
    }
    let legacy = wok_event::PackedEventBuilder::build(
        view.id(),
        view.pubkey(),
        view.created_at(),
        view.kind(),
        view.expiration(),
        &tags,
    )
    .unwrap();
    (legacy.into_bytes(), json)
}

/// Each stored record and its payload, by local ID.
fn stored_records(env: &Env) -> BTreeMap<u64, (Vec<u8>, Vec<u8>)> {
    let txn = env.begin_ro().unwrap();
    let mut records = BTreeMap::new();
    wok_db::foreach_event_from(&txn, 0, |lev, raw| {
        let payload = txn.get_u64(env.dbis().event_payload, lev).unwrap().unwrap();
        records.insert(lev, (raw.to_vec(), payload.to_vec()));
        true
    })
    .unwrap();
    records
}

#[test]
fn reindex_restores_long_tag_values_to_legacy_records() {
    let key = key();
    let pubkey = key.x_only_public_key().0.to_string();
    let (d200, d300, d301, d400) = (
        "v".repeat(200),
        "x".repeat(300),
        "y".repeat(301),
        "z".repeat(400),
    );
    let url = format!("https://example.com/{}", "r".repeat(300));
    let target_address = format!("30023:{pubkey}:{d400}");
    let gone_address = format!("30402:{pubkey}:{d400}");
    // A d short enough to index whole still makes an a tag over 255 bytes.
    let short_d_address = format!("30818:{pubkey}:{d200}");
    let list_address = format!("31922:{pubkey}:{d400}");
    let empty_d = event(&key, 30000, 100, json!([["d", ""]]), "empty d");
    let long301 = event(&key, 30000, 150, json!([["d", &d301]]), "301");
    let long300 = event(&key, 30000, 200, json!([["d", &d300]]), "300");
    let newer300 = event(&key, 30000, 300, json!([["d", &d300]]), "300 again");
    // Versions of long addresses on both sides of a deletion naming them.
    let target = event(&key, 30023, 400, json!([["d", &d400]]), "target");
    let deletion = event(
        &key,
        5,
        500,
        json!([
            ["a", &target_address],
            ["a", &gone_address],
            ["a", &short_d_address]
        ]),
        "",
    );
    let edited_target = event(&key, 30023, 500, json!([["d", &d400]]), "edited");
    let newest_target = event(&key, 30023, 600, json!([["d", &d400]]), "newest");
    let gone = event(&key, 30402, 450, json!([["d", &d400]]), "gone");
    let short_d = event(&key, 30818, 300, json!([["d", &d200]]), "short d");
    // A deletion packed with its tombstone, against a legacy version: the
    // same d under another kind is another address.
    let old_list = event(&key, 31922, 100, json!([["d", &d400]]), "old list");
    let list_deletion = event(&key, 5, 200, json!([["a", &list_address]]), "");
    let newer_list = event(&key, 31922, 300, json!([["d", &d400]]), "newer list");
    let legacy_note = event(&key, 1, 100, json!([["r", &url]]), "legacy");
    let current_note = event(&key, 1, 200, json!([["r", &url]]), "current");
    let plain = event(&key, 1, 300, json!([["t", "short"]]), "plain");
    let channel = event(
        &key,
        41,
        100,
        json!([["e", "aa".repeat(32)], ["r", &url]]),
        "{}",
    );
    // Older releases packed kind 41 with a virtual d, so it cannot repack.
    let (_, channel_json) = packing(&channel);
    let mut tags = wok_event::PackedEventTagBuilder::default();
    tags.add('d', b"").unwrap();
    tags.add('e', &[0xaa; 32]).unwrap();
    let id = hex::decode(channel["id"].as_str().unwrap()).unwrap();
    let author = key.x_only_public_key().0.serialize();
    let channel_legacy = wok_event::PackedEventBuilder::build(&id, &author, 100, 41, 0, &tags)
        .unwrap()
        .into_bytes();
    // Local IDs follow this order, from 1.
    let events = [
        &empty_d,
        &long301,
        &long300,
        &newer300,
        &target,
        &deletion,
        &legacy_note,
        &current_note,
        &plain,
        &channel,
        &edited_target,
        &newest_target,
        &old_list,
        &list_deletion,
        &newer_list,
        &gone,
        &short_d,
    ];
    let current = [
        &empty_d,
        &newer300,
        &current_note,
        &plain,
        &edited_target,
        &list_deletion,
        &short_d,
    ];
    let records: Vec<_> = events
        .iter()
        .map(|event| {
            if *event == &channel {
                (channel_legacy.clone(), channel_json.clone())
            } else if current.contains(event) {
                packing(event)
            } else {
                legacy_packing(event)
            }
        })
        .collect();
    let (_dir, env) = snapshot_records(&records);
    let before = stored_records(&env);

    // The legacy rows: long values unmatched, long addresses collapsed onto
    // the empty d, and the long deletion without a tombstone.
    let txn = env.begin_ro().unwrap();
    let report = wok_db::check_integrity(&txn).unwrap();
    assert!(report.ok(), "{:?}", report.issues);
    // The kind 41 record lacks its long value too, but cannot be repacked.
    assert_eq!(report.legacy_long_tag_records, 9);
    assert_eq!((report.superseded_groups, report.superseded_events), (3, 4));
    drop(txn);
    assert_eq!(
        query(&env, &[json!({"#r": [&url]})], false),
        ids(std::slice::from_ref(&current_note))
    );
    assert_eq!(
        query(&env, &[json!({"kinds": [30000]})], false),
        ids(&[long300.clone(), newer300.clone()])
    );
    // Neither deletion removed the versions it names, and the legacy one
    // lacks its a tags.
    assert_eq!(
        query(
            &env,
            &[json!({"kinds": [30818, 30402, 31922, 30023]})],
            false
        ),
        ids(&[
            edited_target.clone(),
            newest_target.clone(),
            newer_list.clone(),
            gone.clone(),
            short_d.clone()
        ])
    );
    assert!(query(&env, &[json!({"#a": [&target_address]})], false).is_empty());
    let older301 = event(&key, 30000, 120, json!([["d", &d301]]), "older 301");
    let stale_gone = event(&key, 30402, 480, json!([["d", &d400]]), "stale");
    for probe in [&older301, &stale_gone] {
        assert_eq!(
            write_with_quota(&env, probe, 0, false),
            wok_db::EventWriteStatus::Written
        );
    }

    let (_repaired_dir, repaired, stats) = reindex(&env);
    // The deletions remove the versions at or before them, as the write path
    // does: the target, the edit at the deletion's own timestamp, the old
    // list, and the only versions at the other addresses. Newer versions and
    // the deletions themselves stay.
    let deleted = BTreeSet::from([5, 11, 13, 16, 17]);
    assert_eq!(stats.deleted_versions, deleted);
    assert_eq!(stats.events, 12);
    assert_eq!(stats.payloads, 12);
    assert_eq!(
        (
            stats.repacked_long_tag_records,
            stats.skipped_long_tag_records
        ),
        (9, 1)
    );
    // Repacked records equal what Wok packs today; the others and every
    // payload are untouched.
    assert_eq!(stored_records(&env), before, "the source changed");
    let after = stored_records(&repaired);
    assert_eq!(
        after.keys().copied().collect::<BTreeSet<_>>(),
        before
            .keys()
            .copied()
            .filter(|lev| !deleted.contains(lev))
            .collect()
    );
    for (lev, record) in &after {
        let event = events[*lev as usize - 1];
        if event == &channel {
            assert_eq!(record, &before[lev]);
            assert_eq!(record.0, channel_legacy);
        } else {
            assert_eq!(record.0, packing(event).0, "record {lev}");
            assert_eq!(record.1, before[lev].1, "payload {lev}");
        }
    }
    assert_ne!(
        wok_db::event_fingerprint(&repaired).unwrap(),
        wok_db::event_fingerprint(&env).unwrap()
    );
    assert_eq!(
        wok_db::event_fingerprint_without_hashed_tag_values(&repaired).unwrap(),
        wok_db::event_fingerprint_excluding(&env, &deleted, true).unwrap()
    );
    // A record left out of a fingerprint must be stored.
    assert!(wok_db::event_fingerprint_excluding(&repaired, &deleted, true).is_err());

    let txn = repaired.begin_ro().unwrap();
    let report = wok_db::check_integrity(&txn).unwrap();
    assert!(report.ok(), "{:?}", report.issues);
    assert_eq!(report.events, 12);
    assert_eq!(report.legacy_long_tag_records, 0);
    assert_eq!((report.superseded_groups, report.superseded_events), (1, 1));
    assert_eq!(wok_db::state::superseded_events_ro(&txn).unwrap(), Some(1));
    drop(txn);
    // The search index forgot the deleted versions too.
    for (content, matches) in [
        ("target", 0),
        ("edited", 0),
        ("gone", 0),
        ("short", 0),
        ("newest", 1),
        ("list", 1),
    ] {
        assert_eq!(
            query(&repaired, &[json!({"search": content})], false).len(),
            matches,
            "{content}"
        );
    }
    assert_eq!(
        query(&repaired, &[json!({"#r": [&url]})], false),
        ids(&[legacy_note, current_note])
    );
    assert_eq!(
        query(&repaired, &[json!({"kinds": [30000]})], false),
        ids(&[empty_d, long301, newer300.clone()])
    );
    assert_eq!(
        query(
            &repaired,
            &[json!({"kinds": [30000], "#d": [&d300]})],
            false
        ),
        ids(&[newer300])
    );
    assert_eq!(
        query(
            &repaired,
            &[json!({"kinds": [30818, 30402, 31922, 30023]})],
            false
        ),
        ids(&[newest_target, newer_list])
    );
    assert_eq!(
        query(&repaired, &[json!({"kinds": [5]})], false),
        ids(&[deletion.clone(), list_deletion])
    );
    assert_eq!(
        query(&repaired, &[json!({"#a": [&target_address]})], false),
        ids(&[deletion])
    );
    // The long addresses are their own now, and the deletion tombstones its
    // targets.
    assert_eq!(
        write_with_quota(&repaired, &older301, 0, false),
        wok_db::EventWriteStatus::Replaced
    );
    assert_eq!(
        write_with_quota(&repaired, &stale_gone, 0, false),
        wok_db::EventWriteStatus::Deleted
    );

    let (_again_dir, again, stats) = reindex(&repaired);
    assert_eq!(
        (
            stats.repacked_long_tag_records,
            stats.skipped_long_tag_records
        ),
        (0, 1)
    );
    assert!(stats.deleted_versions.is_empty());
    assert_eq!(stored_records(&again), after);
}

#[test]
fn reindex_deletes_under_long_addresses_spelled_with_a_padded_kind() {
    // Ingest refuses an `a` tag whose kind has leading zeros, but strfry and
    // earlier releases stored such requests, with the long tag dropped or
    // hashed. Reindex must apply them like the write path did, not fail.
    let key = key();
    let pubkey = key.x_only_public_key().0.to_string();
    let d = "x".repeat(300);
    let version = event(&key, 30000, 100, json!([["d", &d]]), "version");
    let deletion = event(
        &key,
        5,
        200,
        json!([["a", format!("030000:{pubkey}:{d}")]]),
        "",
    );
    assert!(parse_and_verify_event(&deletion, &EventLimits::default(), None, true, false).is_err());

    for stored_deletion in [legacy_packing(&deletion), stored_packing(&deletion)] {
        let (_dir, env) = snapshot_records(&[legacy_packing(&version), stored_deletion]);
        let (_repaired_dir, repaired, stats) = reindex(&env);
        assert_eq!(stats.deleted_versions, BTreeSet::from([1]));
        assert_eq!(stats.skipped_long_tag_records, 0);
        assert_eq!(stored_ids(&repaired), ids(std::slice::from_ref(&deletion)));
        let report = wok_db::check_integrity(&repaired.begin_ro().unwrap()).unwrap();
        assert!(report.ok(), "{:?}", report.issues);
    }
}

/// Rebuild `source` as `wok reindex` does, repacking long tag values.
fn reindex(source: &Env) -> (TempDir, Env, wok_db::ReindexStats) {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(
        dir.path(),
        EnvOptions {
            map_size: 64 * 1024 * 1024,
            ..EnvOptions::default()
        },
    )
    .unwrap();
    env.ensure_initialized().unwrap();
    let mut txn = env.begin_rw().unwrap();
    let stats = wok_db::rebuild_primary_and_event_indices(
        &source.begin_ro().unwrap(),
        &mut txn,
        wok_db::PackedEventRebuild::RepackLongTags,
    )
    .unwrap();
    txn.commit().unwrap();
    (dir, env, stats)
}
