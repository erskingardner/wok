//! Time slices of multi-filter REQ scans: a REQ's filters share one slice's
//! budget, and every filter checks it as often as the first.
//!
//! The regression tests use a budget of 0, so a slice ends at the first
//! check and how much a slice does depends on the work alone. The ignored
//! `many_filter_req_slices` times slices at a real budget; run it by hand, in
//! release mode, to compare builds:
//!
//! ```text
//! cargo test --release -p wok-query --test timeslice -- --ignored --nocapture
//! ```

use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use wok_db::{write_events, Env, EnvOptions, EventToWrite, NoopNegentropy};
use wok_event::{PackedEventBuilder, PackedEventTagBuilder};
use wok_query::{DbQuery, NostrFilterGroup, QueryScheduler, SubId, Subscription};

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

fn knob(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn percentiles(label: &str, mut samples: Vec<Duration>) {
    if samples.is_empty() {
        println!("{label:<28} n=0");
        return;
    }
    samples.sort();
    let at = |p: f64| {
        let i = ((samples.len() as f64 - 1.0) * p).round() as usize;
        samples[i].as_secs_f64() * 1e3
    };
    println!(
        "{label:<28} n={:<6} p50={:>8.2} ms  p90={:>8.2} ms  p99={:>8.2} ms  max={:>8.2} ms",
        samples.len(),
        at(0.5),
        at(0.9),
        at(0.99),
        at(1.0),
    );
}

/// Not a regression test. One REQ of `FILTERS` (30) filters, each asking for
/// the reactions (kind 7) to one of `FILTERS` accounts, where every one of
/// `EVENTS` (20000) stored notes mentions all of them: each filter reads
/// every note to find no reaction. It runs through a `QueryScheduler` in
/// slices of `BUDGET_US` (10000), as on a req worker, while a small REQ
/// (`{"kinds":[1],"limit":5}`) arrives every `ARRIVAL_US` (2000) and goes
/// first. Prints the many-filter REQ's slice lengths, its REQ-to-end time,
/// and each small REQ's time from arrival to its end: how long it waited for
/// the slice it arrived during.
#[test]
#[ignore]
fn many_filter_req_slices() {
    let events = knob("EVENTS", 20_000);
    let filters = knob("FILTERS", 30);
    let budget_us = knob("BUDGET_US", 10_000) as u64;
    let arrival = Duration::from_micros(knob("ARRIVAL_US", 2_000) as u64);
    let account = |i: usize| {
        let mut pubkey = [0xAA; 32];
        pubkey[..8].copy_from_slice(&(i as u64).to_be_bytes());
        pubkey
    };
    let (_dir, env) =
        store((0..events).map(|_| (0..filters).map(|i| ('p', account(i).to_vec())).collect()));
    let txn = env.begin_ro().unwrap();
    let many: Vec<Value> = (0..filters)
        .map(|i| json!({"kinds": [7], "#p": [hex::encode(account(i))], "limit": 500}))
        .collect();
    for round in 0..3 {
        let mut scheduler = QueryScheduler::new(100_000, 0, 0);
        assert!(scheduler.add_sub(&txn, sub("many", many.clone())).unwrap());
        let started = Instant::now();
        let mut next_arrival = started + arrival;
        let mut arrivals = HashMap::new();
        let mut waits = Vec::new();
        let mut slices = Vec::new();
        let mut took: Option<Duration> = None;
        // Small REQs arrive until the many-filter one is done; those queued
        // behind its last slice then run.
        loop {
            let until = took.map_or_else(Instant::now, |took| started + took);
            while next_arrival <= until {
                let sub_id = format!("small{}", arrivals.len());
                let small = sub(&sub_id, vec![json!({"kinds": [1], "limit": 5})]);
                assert!(scheduler.add_sub(&txn, small).unwrap());
                arrivals.insert(sub_id, next_arrival);
                next_arrival += arrival;
            }
            if !scheduler.has_running() {
                break;
            }
            let many_slice = scheduler
                .next_query()
                .is_some_and(|s| s.sub_id.to_string() == "many");
            let slice_start = Instant::now();
            scheduler
                .process(
                    &txn,
                    budget_us,
                    |_, _, _| true,
                    |sub, _, _, _, _| match arrivals.get(&sub.sub_id.to_string()) {
                        Some(arrived) => waits.push(arrived.elapsed()),
                        None => took = Some(started.elapsed()),
                    },
                )
                .unwrap();
            if many_slice {
                slices.push(slice_start.elapsed());
            }
        }
        println!(
            "round {round}: {filters} filters over {events} notes, {budget_us} us slices: \
             REQ to end {:.1} ms",
            took.unwrap().as_secs_f64() * 1e3
        );
        percentiles("  many-filter slice", slices);
        percentiles("  small REQ wait", waits);
    }
}
