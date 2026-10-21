//! Time slices of multi-filter REQ scans: a REQ's filters share one slice's
//! budget, and every filter checks it as often as the first.
//!
//! The tests use a budget of 0, so a slice ends at the first check and how
//! much a slice does depends on the work alone.

use serde_json::{json, Value};
use tempfile::TempDir;
use wok_db::{write_events, Env, EnvOptions, EventToWrite, NoopNegentropy};
use wok_event::{PackedEventBuilder, PackedEventTagBuilder};
use wok_query::{DbQuery, NostrFilterGroup, SubId, Subscription};

/// A database of kind-1 events, a second apart, oldest first: one for each
/// entry of `tags`, which lists the event's single-letter tags.
fn store(tags: impl IntoIterator<Item = Vec<(char, Vec<u8>)>>) -> (TempDir, Env) {
    let dir = TempDir::new().unwrap();
    let env = Env::open(
        dir.path(),
        EnvOptions {
            map_size: 4 << 30,
            ..EnvOptions::for_tests()
        },
    )
    .unwrap();
    env.ensure_initialized().unwrap();
    let mut events: Vec<EventToWrite> = tags
        .into_iter()
        .enumerate()
        .map(|(i, tags)| {
            let mut id = [0; 32];
            id[..8].copy_from_slice(&(i as u64).to_be_bytes());
            let mut packed_tags = PackedEventTagBuilder::default();
            for (name, value) in &tags {
                packed_tags.add(*name, value).unwrap();
            }
            let packed = PackedEventBuilder::build(
                &id,
                &[7; 32],
                1_700_000_000 + i as u64,
                1,
                0,
                &packed_tags,
            )
            .unwrap();
            EventToWrite::new(packed.into_bytes(), json!({"content": ""}).to_string())
        })
        .collect();
    while !events.is_empty() {
        let mut chunk: Vec<_> = events.drain(..events.len().min(10_000)).collect();
        let mut txn = env.begin_rw().unwrap();
        write_events(&mut txn, &mut NoopNegentropy, &mut chunk, false).unwrap();
        txn.commit().unwrap();
    }
    (dir, env)
}

fn sub(sub_id: &str, filters: Vec<Value>) -> Subscription {
    let mut request = vec![json!("REQ"), json!(sub_id)];
    request.extend(filters);
    let group = NostrFilterGroup::from_req(&request, 10_000, 3, 16).unwrap();
    Subscription::new(1, SubId::new(sub_id).unwrap(), group, false)
}

/// Run `filters` to the end in slices of `budget_us`: the events each slice
/// sent.
fn slices(env: &Env, filters: Vec<Value>, budget_us: u64) -> Vec<usize> {
    let txn = env.begin_ro().unwrap();
    let mut query = DbQuery::new(sub("s", filters), 0, 0);
    let mut slices = Vec::new();
    loop {
        let mut sent = 0;
        let complete = query.process(&txn, |_, _| sent += 1, budget_us).unwrap();
        slices.push(sent);
        if complete {
            return slices;
        }
    }
}

/// A filter that starts after a long one gets its first work check as soon
/// as the long one did, not once it has done as much work. The C++ DBQuery
/// carried the last check's work count over to the next filter's scanner.
#[test]
fn each_filter_checks_the_budget_from_its_start() {
    let (_dir, env) = store((0..12_000).map(|i| {
        let tag = if i < 6_000 { "a" } else { "b" };
        vec![('t', tag.as_bytes().to_vec())]
    }));
    // Kind and tag: every candidate's event is read, so each event sent
    // costs at least 11 work units, and the budget is checked every 2000.
    // Without the reset, the second filter's first check came once it had
    // done as much work as the whole first filter: all 5000 events.
    let filters = vec![
        json!({"kinds": [1], "#t": ["a"], "limit": 5_000}),
        json!({"kinds": [1], "#t": ["b"], "limit": 5_000}),
    ];
    let slices = slices(&env, filters, 0);
    assert_eq!(slices.iter().sum::<usize>(), 10_000);
    let largest = slices.iter().max().unwrap();
    assert!(*largest < 500, "a slice sent {largest} events: {slices:?}");
}

/// Filters that each finish between work checks still share one slice's
/// budget: once it is spent, the next filter waits for the next slice. The
/// C++ DBQuery started each filter's clock afresh.
#[test]
fn a_spent_slice_starts_no_further_filter() {
    let (_dir, env) = store((0..300).map(|i| vec![('t', format!("{}", i % 30).into_bytes())]));
    let filters: Vec<Value> = (0..30)
        .map(|i| json!({"kinds": [1], "#t": [format!("{i}")], "limit": 10}))
        .collect();
    assert_eq!(slices(&env, filters.clone(), 0), vec![10; 30]);
    assert_eq!(slices(&env, filters, u64::MAX), vec![300]);
}
