//! Latest-only reads must hold even for losslessly imported primary records.
#[path = "support/wire.rs"]
mod wire;

use secp256k1::{Keypair, SECP256K1};
use serde_json::{json, Value};
use tempfile::TempDir;
use wire::Wire;
use wok_compat::sign_event_with_key;
use wok_db::{Env, EnvOptions};
use wok_event::{parse_and_verify_event, EventLimits, PackedEventView};
use wok_query::visibility::ReadVisibility;
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
        for (index, event) in events.iter().enumerate() {
            let parsed =
                parse_and_verify_event(event, &EventLimits::default(), None, true, false).unwrap();
            let lev = index as u64 + 1;
            txn.put_u64(source.dbis().event, lev, &parsed.packed.into_bytes(), 0)
                .unwrap();
            txn.put_u64(
                source.dbis().event_payload,
                lev,
                &wok_db::encode_raw_payload(&parsed.json),
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
        wok_db::rebuild_primary_and_event_indices(&source.begin_ro().unwrap(), &mut txn).unwrap();
        // Keep the persistent match-all negentropy tree structurally correct too.
        let mut tree = wok_negentropy::open_rw(&mut txn, 1).unwrap();
        for event in events {
            tree.insert(
                event["created_at"].as_u64().unwrap(),
                &hex::decode(event["id"].as_str().unwrap()).unwrap(),
            )
            .unwrap();
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
    for kind in [0, 3, 41, 10000, 10002, 19999, 30000, 30023, 30443, 39999] {
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
    for kind in [1, 2, 9999, 40000, 65535] {
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
    for kind in [3, 10002, 30443] {
        let old = event(
            &key,
            kind,
            100,
            json!([["d", "a"], ["t", "obsolete"]]),
            "obsoleteword",
        );
        let newest = event(
            &key,
            kind,
            300,
            json!([["d", "a"], ["t", "current"]]),
            "currentword",
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
        for filters in [
            vec![
                json!({"search":"obsoleteword"}),
                json!({"search":"currentword"}),
            ],
            vec![json!({"search":"obsoleteword"}), json!({"kinds":[kind]})],
        ] {
            assert_eq!(
                query(&env, &filters, false),
                ids(std::slice::from_ref(&newest))
            );
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
    assert!(policy.allows(&read, packed).unwrap());
    let newest = event(&key, 30443, 200, json!([["d", "a"]]), "newest");
    std::thread::scope(|scope| {
        scope
            .spawn(|| wok_compat::write_event_to_env(&env, &newest))
            .join()
            .unwrap()
    });
    assert!(policy.allows(&read, packed).unwrap());
    let owned = read.get_u64(env.dbis().event, 1).unwrap().unwrap().to_vec();
    drop(read);
    assert!(!policy
        .allows(
            &env.begin_ro().unwrap(),
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
    cfg.events.reject_older_than_secs = u64::MAX / 4;
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
