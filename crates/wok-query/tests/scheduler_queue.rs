//! A connection's queries over its concurrency cap wait in arrival order
//! and are refused only when its queue is full (tracking issue #97 F2).

use secp256k1::{Keypair, SECP256K1};
use serde_json::json;
use tempfile::TempDir;
use wok_db::{write_events, Env, EnvOptions, EventToWrite, NoopNegentropy};
use wok_event::{parse_and_verify_event, EventLimits};
use wok_query::{NostrFilterGroup, QueryScheduler, Scheduled, SubId, Subscription};

fn store() -> (TempDir, Env) {
    let dir = TempDir::new().unwrap();
    let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let key = Keypair::new(SECP256K1, &mut rand::thread_rng());
    let (xonly, _) = key.x_only_public_key();
    let mut events: Vec<EventToWrite> = (0..3u64)
        .map(|i| {
            let mut event = json!({
                "created_at": 1_700_000_000 + i,
                "kind": 1,
                "tags": [],
                "content": format!("note {i}"),
                "pubkey": hex::encode(xonly.serialize()),
            });
            let id = wok_event::event_id_hash(&event).unwrap();
            event["id"] = json!(hex::encode(id));
            event["sig"] = json!(hex::encode(SECP256K1.sign_schnorr(&id, &key).as_ref()));
            let parsed =
                parse_and_verify_event(&event, &EventLimits::default(), None, true, false).unwrap();
            EventToWrite::new(parsed.packed.into_bytes(), parsed.json)
        })
        .collect();
    let mut txn = env.begin_rw().unwrap();
    write_events(&mut txn, &mut NoopNegentropy, &mut events, false).unwrap();
    txn.commit().unwrap();
    (dir, env)
}

fn query(conn_id: u64, sub_id: &str, generation: u64, count_only: bool) -> Subscription {
    let group = NostrFilterGroup::from_value(&json!({"kinds": [1]}), 500, 8, 16).unwrap();
    let mut sub = Subscription::new(conn_id, SubId::new(sub_id).unwrap(), group, count_only);
    sub.generation = generation;
    sub
}

/// Run every query to its end: the `(conn, id, generation)` of each, in the
/// order they ended.
fn run(scheduler: &mut QueryScheduler, env: &Env) -> Vec<(u64, String, u64)> {
    let txn = env.begin_ro().unwrap();
    let mut ended = Vec::new();
    while scheduler.has_running() {
        scheduler
            .process(
                &txn,
                10_000,
                |_, _, _| true,
                |sub, _, _, _, _| ended.push((sub.conn_id, sub.sub_id.to_string(), sub.generation)),
            )
            .unwrap();
    }
    ended
}

fn ids(ended: &[(u64, String, u64)]) -> Vec<&str> {
    ended.iter().map(|(_, id, _)| id.as_str()).collect()
}

#[test]
fn queries_over_the_cap_wait_their_turn_and_overflow_is_refused() {
    let (_dir, env) = store();
    let txn = env.begin_ro().unwrap();
    let mut scheduler = QueryScheduler::new(2, 0, 0);
    scheduler.set_max_waiting_per_connection(3);
    let add = |scheduler: &mut QueryScheduler, sub| scheduler.add_sub(&txn, sub).unwrap();
    assert_eq!(
        add(&mut scheduler, query(1, "a", 1, false)),
        Scheduled::Running
    );
    assert_eq!(
        add(&mut scheduler, query(1, "b", 2, false)),
        Scheduled::Running
    );
    assert_eq!(
        add(&mut scheduler, query(1, "c", 3, false)),
        Scheduled::Waiting
    );
    assert_eq!(
        add(&mut scheduler, query(1, "d", 4, true)),
        Scheduled::Waiting
    );
    assert_eq!(
        add(&mut scheduler, query(1, "e", 5, false)),
        Scheduled::Waiting
    );
    assert_eq!(scheduler.waiting(), 3);
    // The queue holds three; a COUNT is queued like a REQ.
    assert_eq!(
        add(&mut scheduler, query(1, "f", 6, true)),
        Scheduled::Refused
    );
    // Another connection has its own cap and queue.
    assert_eq!(
        add(&mut scheduler, query(2, "a", 7, false)),
        Scheduled::Running
    );
    drop(txn);
    let ended = run(&mut scheduler, &env);
    // Those that waited start in arrival order as running ones end.
    let first: Vec<&str> = ended
        .iter()
        .filter(|(conn, _, _)| *conn == 1)
        .map(|(_, id, _)| id.as_str())
        .collect();
    assert_eq!(first, ["b", "a", "c", "d", "e"]);
    assert!(ended.contains(&(2, "a".into(), 7)));
    assert_eq!(scheduler.waiting(), 0);
}

#[test]
fn a_waiting_query_can_be_cancelled_replaced_or_closed() {
    let (_dir, env) = store();
    let txn = env.begin_ro().unwrap();
    let mut scheduler = QueryScheduler::new(1, 0, 0);
    scheduler.set_max_waiting_per_connection(10);
    let add = |scheduler: &mut QueryScheduler, sub| scheduler.add_sub(&txn, sub).unwrap();
    assert_eq!(
        add(&mut scheduler, query(1, "run", 1, false)),
        Scheduled::Running
    );
    for (id, generation) in [("closed", 2), ("replaced", 3), ("kept", 4)] {
        assert_eq!(
            add(&mut scheduler, query(1, id, generation, false)),
            Scheduled::Waiting
        );
    }
    // A CLOSE cancels the generation that was queued, and a stale cancel
    // (an older generation of the id) leaves the queued one alone.
    scheduler.remove_generation(1, &SubId::new("closed").unwrap(), false, 2);
    scheduler.remove_generation(1, &SubId::new("kept").unwrap(), false, 1);
    // A REQ that reuses a queued id replaces it, at the back of the queue.
    assert_eq!(
        add(&mut scheduler, query(1, "replaced", 5, false)),
        Scheduled::Waiting
    );
    // Its COUNT namesake is a separate query.
    assert_eq!(
        add(&mut scheduler, query(1, "kept", 6, true)),
        Scheduled::Waiting
    );
    drop(txn);
    let ended = run(&mut scheduler, &env);
    assert_eq!(ids(&ended), ["run", "kept", "replaced", "kept"]);
    assert_eq!(ended[2].2, 5, "only the replacing generation runs");

    // A closed connection's waiting queries go with it.
    let txn = env.begin_ro().unwrap();
    let mut scheduler = QueryScheduler::new(1, 0, 0);
    scheduler.set_max_waiting_per_connection(10);
    assert_eq!(
        scheduler.add_sub(&txn, query(1, "a", 1, false)).unwrap(),
        Scheduled::Running
    );
    assert_eq!(
        scheduler.add_sub(&txn, query(1, "b", 2, false)).unwrap(),
        Scheduled::Waiting
    );
    scheduler.close_conn(1);
    assert_eq!(scheduler.waiting(), 0);
    assert!(!scheduler.has_running());
}

#[test]
fn the_cap_and_queue_follow_reloads() {
    let (_dir, env) = store();
    let txn = env.begin_ro().unwrap();
    // Without a queue, as before, a query over the cap is refused.
    let mut scheduler = QueryScheduler::new(1, 0, 0);
    assert_eq!(
        scheduler.add_sub(&txn, query(1, "a", 1, false)).unwrap(),
        Scheduled::Running
    );
    assert_eq!(
        scheduler.add_sub(&txn, query(1, "b", 2, false)).unwrap(),
        Scheduled::Refused
    );
    scheduler.set_max_waiting_per_connection(4);
    assert_eq!(
        scheduler.add_sub(&txn, query(1, "b", 2, false)).unwrap(),
        Scheduled::Waiting
    );
    assert_eq!(
        scheduler.add_sub(&txn, query(1, "c", 3, false)).unwrap(),
        Scheduled::Waiting
    );
    // Raising the cap starts waiting queries at once.
    scheduler.set_max_subs_per_connection(2);
    assert_eq!(scheduler.waiting(), 1);
    // A cap of zero refuses new queries, and those already waiting still
    // run, one at a time, rather than never answering.
    scheduler.set_max_subs_per_connection(0);
    assert_eq!(
        scheduler.add_sub(&txn, query(1, "d", 4, false)).unwrap(),
        Scheduled::Refused
    );
    drop(txn);
    // A query that waited takes its turn behind those already running.
    assert_eq!(ids(&run(&mut scheduler, &env)), ["a", "b", "c"]);
}
