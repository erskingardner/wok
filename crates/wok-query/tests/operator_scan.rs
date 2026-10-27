//! Operator scans (`wok scan`, `wok delete`, `wok dict`) send what a REQ with
//! the same filters would, each event once, without remembering every event
//! they sent.
use serde_json::{json, Value};
use wok_db::{Env, EnvOptions, EventToWrite, NoopNegentropy, RoTxn};
use wok_event::{PackedEventBuilder, PackedEventTagBuilder};
use wok_query::{
    foreach_by_filter, visibility::ReadVisibility, DbQuery, NostrFilterGroup, SubId, Subscription,
};

/// Kind 1 event `i`, with a `t` tag for each of `tags`.
fn event(i: u64, created: u64, tags: &[&str], content: &str) -> EventToWrite {
    let mut id = [0; 32];
    id[..8].copy_from_slice(&i.to_be_bytes());
    let mut builder = PackedEventTagBuilder::default();
    for tag in tags {
        builder.add('t', tag.as_bytes()).unwrap();
    }
    let packed = PackedEventBuilder::build(&id, &[7; 32], created, 1, 0, &builder).unwrap();
    EventToWrite::new(
        packed.into_bytes(),
        json!({ "content": content }).to_string(),
    )
}

fn store(events: &mut [EventToWrite]) -> (tempfile::TempDir, Env) {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let mut txn = env.begin_rw().unwrap();
    wok_db::write_events(&mut txn, &mut NoopNegentropy, events, false).unwrap();
    txn.commit().unwrap();
    (dir, env)
}

fn operator(txn: &RoTxn<'_>, filter: &Value) -> Vec<u64> {
    let mut sent = Vec::new();
    foreach_by_filter(txn, filter, u64::MAX, 3, 16, |lev| sent.push(lev)).unwrap();
    sent
}

/// What a REQ that may read AUTH events sends for `filter`.
fn req(txn: &RoTxn<'_>, filter: &Value) -> Vec<u64> {
    let group = NostrFilterGroup::from_value(filter, u64::MAX, 3, 16).unwrap();
    let sub = Subscription::new(1, SubId::new("req").unwrap(), group, false);
    let mut query = DbQuery::new(sub, 0, 0);
    query.visibility = ReadVisibility {
        include_auth_events: true,
        ..ReadVisibility::default()
    };
    let mut sent = Vec::new();
    while !query
        .process(txn, |_, lev| sent.push(lev), u64::MAX)
        .unwrap()
    {}
    sent
}

#[test]
fn operator_scans_send_what_a_req_would_once_each() {
    // Four events share each created_at, and an event tagged both `a` and `b`
    // is read by both of an `a`/`b` filter's cursors.
    let mut events: Vec<_> = (1..=60u64)
        .map(|i| {
            let tags: Vec<_> = [("a", 2), ("b", 3), ("c", 5)]
                .into_iter()
                .filter(|(_, n)| i % n == 0)
                .map(|(tag, _)| tag)
                .collect();
            event(i, 1_700_000_000 + i / 4, &tags, "note")
        })
        .collect();
    let (_dir, env) = store(&mut events);
    let txn = env.begin_ro().unwrap();

    let a_or_b = operator(&txn, &json!({"#t":["a","b"]}));
    assert_eq!(
        a_or_b.len(),
        (1..=60).filter(|i| i % 2 == 0 || i % 3 == 0).count()
    );
    for filter in [
        json!({"#t":["a","b"]}),
        json!({"#t":["a","b","c"], "limit":7}),
        json!([{"#t":["a"]}, {"#t":["b"]}]),
        json!([{"#t":["a"], "limit":4}, {"#t":["b","c"]}, {"kinds":[1]}]),
        json!([{"kinds":[1], "limit":3}, {"#t":["a","b"], "limit":5}, {}]),
        json!([{"#t":["c"]}, {"#t":["a","c"], "limit":10}, {"since":1_700_000_010}]),
        json!([{"#t":["a"], "limit":0}, {"#t":["a","b"]}]),
    ] {
        let sent = operator(&txn, &filter);
        assert_eq!(sent, req(&txn, &filter), "{filter}");
        let mut unique = sent.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), sent.len(), "{filter}");
    }
}

/// A search yields every few thousand postings. An operator scan resumes it
/// rather than stopping there.
#[test]
fn operator_search_scans_run_to_the_end() {
    let mut events: Vec<_> = (1..=5_000u64).map(|i| event(i, i, &[], "common")).collect();
    let (_dir, env) = store(&mut events);
    let txn = env.begin_ro().unwrap();
    assert_eq!(operator(&txn, &json!({"search":"common"})).len(), 5_000);
    assert_eq!(
        operator(&txn, &json!({"search":"common", "limit":10})).len(),
        10
    );
    // Beside other filters, a search runs on its own.
    for filter in [
        json!([{"search":"common"}, {"kinds":[1]}]),
        json!([{"kinds":[1], "limit":3}, {"search":"common", "limit":10}, {"since":4_990}]),
    ] {
        let sent = operator(&txn, &filter);
        assert_eq!(sent, req(&txn, &filter), "{filter}");
    }
    assert_eq!(
        operator(&txn, &json!([{"search":"common"}, {"kinds":[1]}])).len(),
        5_000
    );
}
