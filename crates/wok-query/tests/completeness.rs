//! NIP-67 completeness of finished REQ history scans.

use secp256k1::{Keypair, SECP256K1};
use serde_json::{json, Value};
use tempfile::TempDir;
use wok_db::{write_events, Env, EnvOptions, EventToWrite, NoopNegentropy};
use wok_event::{parse_and_verify_event, EventLimits};
use wok_query::visibility::{ReadRestrictor, ReadVisibility};
use wok_query::{
    Completeness, DbQuery, NostrFilterGroup, QueryScheduler, Scheduled, SubId, Subscription,
};

const FINISH: Completeness = Completeness {
    finish: true,
    more: false,
    restricted: false,
};
const MORE: Completeness = Completeness {
    finish: false,
    more: true,
    restricted: false,
};
const NEITHER: Completeness = Completeness {
    finish: false,
    more: false,
    restricted: false,
};

fn event(
    keypair: &Keypair,
    kind: u64,
    created_at: u64,
    tags: Value,
    content: &str,
) -> EventToWrite {
    let (public_key, _) = keypair.x_only_public_key();
    let mut event = json!({
        "created_at": created_at,
        "kind": kind,
        "tags": tags,
        "content": content,
        "pubkey": hex::encode(public_key.serialize()),
    });
    let id = wok_event::event_id_hash(&event).unwrap();
    event["id"] = json!(hex::encode(id));
    let signature = SECP256K1.sign_schnorr(&id, keypair);
    event["sig"] = json!(hex::encode(signature.as_ref()));
    let parsed =
        parse_and_verify_event(&event, &EventLimits::default(), None, true, false).unwrap();
    EventToWrite::new(parsed.packed.into_bytes(), parsed.json)
}

fn keypair() -> Keypair {
    Keypair::new(SECP256K1, &mut rand::thread_rng())
}

fn pubkey(keypair: &Keypair) -> [u8; 32] {
    keypair.x_only_public_key().0.serialize()
}

/// A database holding `events`, oldest first.
fn store(mut events: Vec<EventToWrite>) -> (TempDir, Env) {
    let dir = TempDir::new().unwrap();
    let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let mut txn = env.begin_rw().unwrap();
    write_events(&mut txn, &mut NoopNegentropy, &mut events, false).unwrap();
    txn.commit().unwrap();
    (dir, env)
}

/// `count` kind-`kind` notes by one author, a second apart, ending `newest`.
fn notes(kind: u64, count: u64, newest: u64) -> Vec<EventToWrite> {
    let author = keypair();
    (0..count)
        .map(|i| event(&author, kind, newest - (count - 1 - i), json!([]), "n"))
        .collect()
}

fn query(filters: Value, max_total_events: u64) -> DbQuery {
    let filters = filters.as_array().cloned().unwrap_or_else(|| vec![filters]);
    let mut request = vec![json!("REQ"), json!("s")];
    request.extend(filters);
    let group = NostrFilterGroup::from_req(&request, 500, 3, 16).unwrap();
    let mut query = DbQuery::new(
        Subscription::new(1, SubId::new("s").unwrap(), group, false),
        max_total_events,
        0,
    );
    query.track_completeness();
    query
}

/// Run `query` to the end; the events it sent, and what it knows.
fn run(env: &Env, mut query: DbQuery, visibility: ReadVisibility) -> (usize, Completeness) {
    let txn = env.begin_ro().unwrap();
    query.set_visibility(visibility);
    let mut sent = 0;
    while !query.process(&txn, |_, _| sent += 1, u64::MAX).unwrap() {}
    (sent, query.completeness())
}

fn complete(env: &Env, filters: Value) -> (usize, Completeness) {
    run(env, query(filters, 0), ReadVisibility::default())
}

#[test]
fn a_scan_that_runs_out_of_matches_finished() {
    let (_dir, env) = store(notes(1, 7, 1_700_000_100));
    assert_eq!(complete(&env, json!({"kinds": [1]})), (7, FINISH));
    assert_eq!(
        complete(&env, json!({"kinds": [1], "limit": 8})),
        (7, FINISH)
    );
    assert_eq!(complete(&env, json!({"kinds": [7]})), (0, FINISH));
    assert_eq!(
        complete(&env, json!({"kinds": [1], "since": 1_700_000_099})),
        (2, FINISH)
    );
}

#[test]
fn a_limit_that_leaves_matches_says_more() {
    let (_dir, env) = store(notes(1, 7, 1_700_000_100));
    // The last match sent is the last one its cursor had read, so the peek
    // has to read the cursor's next entries to find the one left.
    assert_eq!(complete(&env, json!({"kinds": [1], "limit": 5})), (5, MORE));
    assert_eq!(complete(&env, json!({"kinds": [1], "limit": 6})), (6, MORE));
    assert_eq!(complete(&env, json!({"kinds": [1], "limit": 1})), (1, MORE));
}

#[test]
fn exactly_limit_matches_finished() {
    let (_dir, env) = store(notes(1, 7, 1_700_000_100));
    assert_eq!(
        complete(&env, json!({"kinds": [1], "limit": 7})),
        (7, FINISH)
    );

    let author = keypair();
    let mut events: Vec<_> = (0..4)
        .map(|i| event(&author, 1, 1_700_000_000 + i, json!([]), "note"))
        .collect();
    events.extend((0..3).map(|i| event(&author, 7, 1_700_000_010 + i, json!([]), "+")));
    let (_dir, env) = store(events);
    let author = hex::encode(pubkey(&author));
    for filter in [
        json!({"kinds": [1, 7], "limit": 7}),
        json!({"authors": [author], "limit": 7}),
        json!({"authors": [author], "kinds": [1, 7], "limit": 7}),
    ] {
        assert_eq!(complete(&env, filter.clone()), (7, FINISH), "{filter}");
        let mut cut = filter.clone();
        cut["limit"] = json!(6);
        assert_eq!(complete(&env, cut), (6, MORE), "{filter}");
    }
}

#[test]
fn a_clamped_limit_that_leaves_matches_says_more() {
    let (_dir, env) = store(notes(1, 3, 1_700_000_100));
    let group = NostrFilterGroup::from_value(&json!({"kinds": [1]}), 2, 3, 16).unwrap();
    let mut query = DbQuery::new(
        Subscription::new(1, SubId::new("s").unwrap(), group, false),
        0,
        0,
    );
    query.track_completeness();
    assert_eq!(run(&env, query, ReadVisibility::default()), (2, MORE));
}

#[test]
fn the_request_ceiling_says_more_only_when_a_match_is_left() {
    let mut events = notes(1, 3, 1_700_000_100);
    events.extend(notes(7, 2, 1_700_000_050));
    let (_dir, env) = store(events);
    let two = json!([{"kinds": [1]}, {"kinds": [7]}]);
    // The second filter is never scanned: its matches are found by a peek.
    assert_eq!(
        run(&env, query(two.clone(), 3), Default::default()),
        (3, MORE)
    );
    assert_eq!(
        run(&env, query(two.clone(), 4), Default::default()),
        (4, MORE)
    );
    assert_eq!(run(&env, query(two, 5), Default::default()), (5, FINISH));
    // Matches of an unscanned filter that were already sent are not more.
    let again = json!([{"kinds": [1]}, {"kinds": [1], "since": 1_700_000_099}]);
    assert_eq!(run(&env, query(again, 3), Default::default()), (3, FINISH));
}

#[test]
fn a_match_left_by_one_filter_and_sent_by_another_proves_nothing() {
    let (_dir, env) = store(notes(1, 4, 1_700_000_100));
    assert_eq!(
        complete(&env, json!([{"kinds": [1], "limit": 2}, {"kinds": [1]}])),
        (4, NEITHER)
    );
    assert_eq!(
        complete(
            &env,
            json!([{"kinds": [1], "limit": 2}, {"kinds": [1], "limit": 3}])
        ),
        (3, MORE)
    );
}

#[test]
fn limit_zero_and_empty_lists() {
    let (_dir, env) = store(notes(1, 3, 1_700_000_100));
    assert_eq!(
        complete(&env, json!({"kinds": [1], "limit": 0})),
        (0, NEITHER)
    );
    assert_eq!(
        complete(
            &env,
            json!([{"kinds": [1], "limit": 0}, {"kinds": [1], "limit": 1}])
        ),
        (1, MORE)
    );
    assert_eq!(complete(&env, json!({"kinds": []})), (0, FINISH));
    assert_eq!(
        complete(&env, json!([{"authors": []}, {"kinds": [1]}])),
        (3, FINISH)
    );
}

fn restricted(identities: Vec<[u8; 32]>) -> ReadVisibility {
    ReadVisibility {
        restrictor: ReadRestrictor::new(vec![4], true),
        identities,
        ..ReadVisibility::default()
    }
}

#[test]
fn matches_hidden_by_the_restricted_read_rule_are_noted() {
    let (author, recipient) = (keypair(), keypair());
    let to = json!([["p", hex::encode(pubkey(&recipient))]]);
    let mut events = notes(1, 2, 1_700_000_100);
    events.push(event(&author, 4, 1_700_000_050, to.clone(), "dm"));
    // Expired: AUTH would not reveal it.
    let expired = json!([
        ["p", hex::encode(pubkey(&recipient))],
        ["expiration", "100"]
    ]);
    events.push(event(&author, 4, 1_700_000_040, expired.clone(), "old"));
    let (_dir, env) = store(events);

    let mixed = || query(json!({"kinds": [1, 4]}), 0);
    let hidden = Completeness {
        restricted: true,
        ..FINISH
    };
    assert_eq!(run(&env, mixed(), restricted(vec![])), (2, hidden));
    assert_eq!(
        run(&env, mixed(), restricted(vec![pubkey(&recipient)])),
        (3, FINISH)
    );
    // Hidden only past the limit, where the peek found it.
    let cut = query(json!({"kinds": [1, 4], "limit": 2}), 0);
    assert_eq!(run(&env, cut, restricted(vec![])), (2, hidden));

    let (_dir, env) = store(vec![event(&author, 4, 1_700_000_040, expired, "old")]);
    assert_eq!(run(&env, mixed(), restricted(vec![])), (0, FINISH));
}

#[test]
fn a_peek_that_runs_out_of_budget_says_nothing() {
    let (author, recipient) = (keypair(), keypair());
    let to = json!([["p", hex::encode(pubkey(&recipient))]]);
    let mut events = vec![event(&author, 1, 1_700_000_000, json!([]), "oldest")];
    events.extend((0..80).map(|i| event(&author, 4, 1_700_000_100 + i, to.clone(), "dm")));
    events.push(event(&author, 1, 1_700_000_500, json!([]), "newest"));
    let (_dir, env) = store(events);

    let cut = query(json!({"kinds": [1, 4], "limit": 1}), 0);
    let (sent, completeness) = run(&env, cut, restricted(vec![]));
    assert_eq!(sent, 1);
    assert!(
        !completeness.finish && !completeness.more,
        "{completeness:?}"
    );
    assert!(completeness.restricted);
}

#[test]
fn a_search_says_more_when_hits_rank_below_its_limit() {
    let author = keypair();
    let (_dir, env) = store(
        (0..3)
            .map(|i| event(&author, 1, 1_700_000_000 + i, json!([]), "nostr relay"))
            .collect(),
    );
    assert_eq!(
        complete(&env, json!({"search": "nostr", "limit": 2})),
        (2, MORE)
    );
    assert_eq!(
        complete(&env, json!({"search": "nostr", "limit": 3})),
        (3, FINISH)
    );
    assert_eq!(
        complete(
            &env,
            json!([{"search": "nostr", "limit": 2}, {"kinds": [7]}])
        ),
        (2, MORE)
    );
    assert_eq!(
        complete(
            &env,
            json!([{"search": "nostr", "limit": 3}, {"kinds": [7]}])
        ),
        (3, FINISH)
    );
}

#[test]
fn a_read_policy_change_between_slices_says_nothing() {
    let author = keypair();
    let (_dir, env) = store(
        (0..600)
            .map(|i| event(&author, 1, 1_700_000_000 + i, json!([["t", "x"]]), "n"))
            .collect(),
    );
    // Kind and tag: every candidate's event is read, so a slice with no
    // time left stops at the first check.
    let filter = json!({"kinds": [1], "#t": ["x"]});
    assert_eq!(complete(&env, filter.clone()), (500, MORE));
    let mut query = query(filter, 0);
    let txn = env.begin_ro().unwrap();
    query.set_visibility(ReadVisibility::default());
    assert!(!query.process(&txn, |_, _| {}, 0).unwrap(), "one slice");
    query.set_visibility(restricted(vec![[9; 32]]));
    while !query.process(&txn, |_, _| {}, u64::MAX).unwrap() {}
    assert_eq!(query.completeness(), Completeness::default());
}

#[test]
fn the_scheduler_reports_completeness_for_reqs_only() {
    let (_dir, env) = store(notes(1, 3, 1_700_000_100));
    let txn = env.begin_ro().unwrap();
    let mut scheduler = QueryScheduler::new(8, 0, 0);
    scheduler.set_completeness(true);
    for (sub_id, count_only) in [("req", false), ("count", true)] {
        let group =
            NostrFilterGroup::from_value(&json!({"kinds": [1], "limit": 2}), 500, 3, 16).unwrap();
        let sub = Subscription::new(1, SubId::new(sub_id).unwrap(), group, count_only);
        assert_eq!(scheduler.add_sub(&txn, sub).unwrap(), Scheduled::Running);
    }
    let mut done = Vec::new();
    while scheduler.has_running() {
        scheduler
            .process(
                &txn,
                u64::MAX,
                |_, _, _| true,
                |sub, _, _, _, completeness| done.push((sub.sub_id.to_string(), completeness)),
            )
            .unwrap();
    }
    done.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        done,
        [
            ("count".into(), Completeness::default()),
            ("req".into(), MORE)
        ]
    );
}

#[test]
fn an_event_that_did_not_reach_the_reader_gives_up_finish() {
    let (_dir, env) = store(notes(1, 3, 1_700_000_100));
    let txn = env.begin_ro().unwrap();
    for (lost, expected) in [(0u32, FINISH), (1, NEITHER)] {
        let mut scheduler = QueryScheduler::new(8, 0, 0);
        scheduler.set_completeness(true);
        let group = NostrFilterGroup::from_value(&json!({"kinds": [1]}), 500, 3, 16).unwrap();
        let sub = Subscription::new(1, SubId::new("s").unwrap(), group, false);
        assert_eq!(scheduler.add_sub(&txn, sub).unwrap(), Scheduled::Running);
        // The relay could not decode this many of the payloads.
        let mut to_lose = lost;
        let mut done = None;
        while scheduler.has_running() {
            scheduler
                .process(
                    &txn,
                    u64::MAX,
                    |_, _, _| {
                        let delivered = to_lose == 0;
                        to_lose = to_lose.saturating_sub(1);
                        delivered
                    },
                    |_, _, _, _, completeness| done = Some(completeness),
                )
                .unwrap();
        }
        assert_eq!(done, Some(expected), "{lost} lost");
    }
}

#[test]
fn a_moderation_change_between_slices_says_nothing() {
    let author = keypair();
    let (_dir, env) = store(
        (0..600)
            .map(|i| event(&author, 1, 1_700_000_000 + i, json!([["t", "x"]]), "n"))
            .collect(),
    );
    let set_ban = |banned: bool| {
        let mut txn = env.begin_rw().unwrap();
        if banned {
            wok_db::moderation::ban_pubkey(&mut txn, &pubkey(&author), "spam").unwrap();
        } else {
            wok_db::moderation::unban_pubkey(&mut txn, &pubkey(&author)).unwrap();
        }
        txn.commit().unwrap();
    };
    // The first slice reads with the author banned, so it sends nothing of
    // what it covers; after the unban, the rest is sent and the filter runs
    // out below its limit, though what the first slice hid is now readable.
    set_ban(true);
    let mut query = query(json!({"kinds": [1], "#t": ["x"]}), 0);
    query.set_visibility(ReadVisibility::default());
    let first = env.begin_ro().unwrap();
    let mut sent = 0;
    assert!(
        !query.process(&first, |_, _| sent += 1, 0).unwrap(),
        "one slice"
    );
    drop(first);
    set_ban(false);
    let rest = env.begin_ro().unwrap();
    while !query.process(&rest, |_, _| sent += 1, u64::MAX).unwrap() {}
    assert!(sent < 500, "{sent}");
    assert_eq!(query.completeness(), Completeness::default());
}
