//! Wide feeds collect range heads, then deepen only the ranges that win the
//! chronological merge. Compare against stored metadata, including ties and
//! resumptions after both work budgets and handler stops.

use serde_json::json;
use std::time::{Duration, Instant};
use wok_db::{write_events, Env, EnvOptions, EventToWrite, NoopNegentropy};
use wok_event::{PackedEventBuilder, PackedEventTagBuilder, PackedEventView};
use wok_query::{DbScan, NostrFilterGroup};

const BASE: u64 = 1_700_000_000;

fn author(n: u64) -> [u8; 32] {
    let mut author = [0; 32];
    author[..8].copy_from_slice(&n.to_be_bytes());
    author
}

fn event(n: u64, who: u64, created: u64, tags: &[&str]) -> EventToWrite {
    let mut id = [0; 32];
    id[..8].copy_from_slice(&n.to_be_bytes());
    let mut packed_tags = PackedEventTagBuilder::default();
    for tag in tags {
        packed_tags.add('t', tag.as_bytes()).unwrap();
    }
    let packed = PackedEventBuilder::build(&id, &author(who), created, 1, 0, &packed_tags).unwrap();
    EventToWrite::new(packed.into_bytes(), json!({"content": ""}).to_string())
}

fn store(events: &mut [EventToWrite]) -> (tempfile::TempDir, Env) {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let mut txn = env.begin_rw().unwrap();
    write_events(&mut txn, &mut NoopNegentropy, events, false).unwrap();
    txn.commit().unwrap();
    (dir, env)
}

fn feed(authors: u64, limit: u64) -> NostrFilterGroup {
    NostrFilterGroup::from_value(
        &json!({"authors": (0..authors).map(|n| hex::encode(author(n))).collect::<Vec<_>>(),
            "since": BASE, "until": BASE + 10_000, "limit": limit}),
        20_000,
        8,
        16,
    )
    .unwrap()
}

fn ordered(events: &[EventToWrite], copies: usize) -> Vec<u64> {
    let mut expected: Vec<_> = events
        .iter()
        .flat_map(|event| {
            let packed = PackedEventView::new(&event.packed).unwrap();
            std::iter::repeat_n((packed.created_at(), event.lev_id), copies)
        })
        .collect();
    expected.sort_unstable_by(|a, b| b.cmp(a));
    expected.into_iter().map(|(_, lev_id)| lev_id).collect()
}

fn uniform_events() -> Vec<EventToWrite> {
    (0..500)
        .flat_map(|who| {
            (0..20).map(move |depth| {
                // The newest layer spans many authors, with equal times.
                event(who * 100 + depth + 1, who, BASE + depth * 4 + who % 3, &[])
            })
        })
        .collect()
}

fn skewed_events() -> Vec<EventToWrite> {
    (0..500)
        .flat_map(|who| {
            let count = if who == 0 {
                1_000
            } else if who % 3 == 0 {
                0
            } else {
                2
            };
            (0..count).map(move |depth| {
                let created = if who == 0 {
                    BASE + 1_000 + depth / 2
                } else {
                    BASE + who % 5
                };
                event(who * 10_000 + depth + 1, who, created, &[])
            })
        })
        .collect()
}

#[test]
fn wide_feed_finds_fifty_newest_without_reading_five_from_every_author() {
    let mut events = uniform_events();
    let (_dir, env) = store(&mut events);
    let expected = ordered(&events, 1);
    let group = feed(500, 50);
    let filter = &group.filters[0];
    let txn = env.begin_ro().unwrap();
    let mut scan = DbScan::new(filter, &txn);
    assert_eq!(scan.cursor_count(), 500);
    let mut got = Vec::new();
    assert!(scan
        .scan(
            &txn,
            filter,
            |lev_id| {
                got.push(lev_id);
                true
            },
            |_| false,
        )
        .unwrap());
    // Five entries from each author plus the range attempts cost over 3,000
    // units before the first result. One frontier needs about 1,000.
    assert!(scan.approx_work < 1_100, "{}", scan.approx_work);
    assert!(scan
        .scan(
            &txn,
            filter,
            |lev_id| {
                got.push(lev_id);
                got.len() == 50
            },
            |_| false,
        )
        .unwrap());
    assert_eq!(got, expected[..50]);
    assert!(scan.approx_work < 1_300, "{}", scan.approx_work);
}

#[test]
fn skewed_and_empty_ranges_resume_in_order_with_bounded_refill_work() {
    let mut events = skewed_events();
    let (_dir, env) = store(&mut events);
    let expected = ordered(&events, 1);
    let group = feed(500, 50);
    let filter = &group.filters[0];
    let txn = env.begin_ro().unwrap();
    let mut scan = DbScan::new(filter, &txn);
    let mut got = Vec::new();
    let mut calls = 0;
    let mut yielded = false;
    while got.len() < expected.len() {
        let start_work = scan.approx_work;
        let complete = scan
            .scan(
                &txn,
                filter,
                |lev_id| {
                    got.push(lev_id);
                    got.len() % 7 == 0
                },
                |work| work.saturating_sub(start_work) >= 17,
            )
            .unwrap();
        yielded |= !complete;
        // A slice can settle one winning range before checking its work
        // budget. The refill stays bounded even for the prolific author.
        assert!(scan.approx_work - start_work <= 80);
        calls += 1;
        assert!(calls < 10_000, "feed stopped making progress");
    }
    assert!(yielded);
    assert_eq!(got, expected);
    let before_end = got.len();
    assert!(scan
        .scan(
            &txn,
            filter,
            |lev_id| {
                got.push(lev_id);
                false
            },
            |_| false,
        )
        .unwrap());
    assert_eq!(got.len(), before_end);
}

#[test]
fn overlapping_tag_ranges_keep_equal_events_through_heap_refills() {
    let mut events: Vec<_> = (0..600)
        .map(|n| event(n + 1, n % 7, BASE + n / 3, &["a", "b"]))
        .collect();
    let (_dir, env) = store(&mut events);
    let expected = ordered(&events, 2);
    let group = NostrFilterGroup::from_value(&json!({"#t": ["a", "b"], "limit": 3}), 20_000, 8, 16)
        .unwrap();
    let filter = &group.filters[0];
    let txn = env.begin_ro().unwrap();
    let mut scan = DbScan::new(filter, &txn);
    let mut got = Vec::new();
    while got.len() < expected.len() {
        assert!(scan
            .scan(
                &txn,
                filter,
                |lev_id| {
                    got.push(lev_id);
                    true
                },
                |_| false,
            )
            .unwrap());
    }
    // DbScan leaves request-wide duplicate suppression to DbQuery.
    assert_eq!(got, expected);
    assert!(scan
        .scan(
            &txn,
            filter,
            |_| panic!("overlapping ranges emitted more candidates than stored"),
            |_| false,
        )
        .unwrap());
}

/// Compare successive native-interface and feed-merge builds with the same
/// fixture. This is a local scan diagnostic; network campaign timings remain
/// the performance evidence. Run with `--release --ignored --nocapture`.
#[test]
#[ignore]
fn feed_frontier_benchmark() {
    let sparse = (0..5)
        .flat_map(|who| {
            (0..2_000).map(move |depth| event(who * 10_000 + depth + 1, who, BASE + depth / 2, &[]))
        })
        .collect();
    for (shape, events) in [
        ("uniform", uniform_events()),
        ("skewed", skewed_events()),
        ("sparse", sparse),
    ] {
        benchmark_shape(shape, events);
    }
}

fn benchmark_shape(shape: &str, mut events: Vec<EventToWrite>) {
    let (_dir, env) = store(&mut events);
    let expected = ordered(&events, 1);
    let group = feed(500, 50);
    let filter = &group.filters[0];
    let rounds = std::env::var("WOK_FEED_BENCH_ROUNDS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(200);
    let mut timings = Vec::with_capacity(rounds);
    let mut work = 0;
    for round in 0..rounds + 20 {
        let started = Instant::now();
        let txn = env.begin_ro().unwrap();
        let mut scan = DbScan::new(filter, &txn);
        let mut got = Vec::new();
        scan.scan(
            &txn,
            filter,
            |lev_id| {
                got.push(lev_id);
                got.len() == 50
            },
            |_| false,
        )
        .unwrap();
        drop(txn);
        let elapsed = started.elapsed();
        assert_eq!(got, expected[..50]);
        work = scan.approx_work;
        if round >= 20 {
            timings.push(elapsed);
        }
    }
    assert!(!timings.is_empty());
    timings.sort_unstable();
    let micros = |p: usize| {
        let duration: Duration =
            timings[((timings.len() * p).div_ceil(100) - 1).min(timings.len() - 1)];
        duration.as_micros()
    };
    println!(
        "{}",
        json!({"diagnostic": "feed500-local", "shape": shape, "rounds": rounds, "work_units": work,
            "p50_us": micros(50), "p99_us": micros(99)})
    );
}
