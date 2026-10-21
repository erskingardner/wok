//! What read visibility costs a history scan, in process, under each kind of
//! policy record. Not a regression test: run it by hand, in release mode, to
//! compare builds. It uses only `DbQuery`'s public API, so the same file runs
//! against older revisions.
//!
//! ```text
//! cargo test --release -p wok-query --test visibility_cost -- --ignored --nocapture
//! ```

use serde_json::{json, Value};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use wok_db::{write_events, Env, EnvOptions, EventToWrite, NoopNegentropy};
use wok_event::{PackedEventBuilder, PackedEventTagBuilder};
use wok_query::{DbQuery, NostrFilterGroup, SubId, Subscription};

fn knob(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn pubkey(i: usize, salt: u8) -> [u8; 32] {
    let mut pubkey = [salt; 32];
    pubkey[..8].copy_from_slice(&(i as u64).to_be_bytes());
    pubkey
}

/// `notes` kind-1 notes by `authors` authors, a second apart, and one kind 0
/// and one kind 3 event for each author.
fn store(notes: usize, authors: usize) -> (TempDir, Env) {
    let dir = TempDir::new().unwrap();
    let env = Env::open(
        dir.path(),
        EnvOptions {
            map_size: 8 << 30,
            ..EnvOptions::for_tests()
        },
    )
    .unwrap();
    env.ensure_initialized().unwrap();
    let records = (0..authors)
        .flat_map(|a| [(a, 0), (a, 3)])
        .chain((0..notes).map(|i| (i % authors, 1)));
    let mut events: Vec<EventToWrite> = records
        .enumerate()
        .map(|(i, (author, kind))| {
            let mut id = [0x11; 32];
            id[..8].copy_from_slice(&(i as u64).to_be_bytes());
            let packed = PackedEventBuilder::build(
                &id,
                &pubkey(author, 0xAA),
                1_700_000_000 + i as u64,
                kind,
                0,
                &PackedEventTagBuilder::default(),
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

/// Run `filter` to the end `runs` times; the events it sent, and the median
/// time.
fn time(env: &Env, filter: &Value, count_only: bool, runs: usize) -> (u64, Duration) {
    let txn = env.begin_ro().unwrap();
    let mut times = Vec::new();
    let mut sent = 0;
    for _ in 0..runs {
        let group = NostrFilterGroup::from_value(filter, 1_000_000, 3, 16).unwrap();
        let mut sub = Subscription::new(1, SubId::new("s").unwrap(), group, count_only);
        sub.latest_event_id = wok_db::most_recent_levid_ro(&txn).unwrap();
        let mut query = DbQuery::new(sub, 0, 0);
        let start = Instant::now();
        while !query.process(&txn, |_, _| {}, u64::MAX).unwrap() {}
        times.push(start.elapsed());
        sent = query.sent_count();
    }
    times.sort();
    (sent, times[times.len() / 2])
}

/// Not a regression test. `NOTES` (200000) kind-1 notes by `AUTHORS` (1000)
/// authors, each with a kind 0 and a kind 3. Three queries run `RUNS` (21)
/// times each, and the median is printed: the newest 2,000 notes, every
/// author's kind 0 and 3 (replaceable, so each event also gets a replacement
/// check), and a COUNT of every note. They run as policy records are added,
/// none of which hides an event the queries match: 1,000 banned pubkeys and
/// 1,000 banned event ids, then a kind policy without kind 7, then 1,000
/// vanish markers.
#[test]
#[ignore]
fn visibility_cost_by_policy_record() {
    let notes = knob("NOTES", 200_000);
    let authors = knob("AUTHORS", 1_000);
    let runs = knob("RUNS", 21);
    let (_dir, env) = store(notes, authors);
    let author_list: Vec<String> = (0..authors).map(|a| hex::encode(pubkey(a, 0xAA))).collect();
    let queries = [
        (
            "REQ kinds [1], limit 2000",
            json!({"kinds": [1], "limit": 2_000}),
            false,
        ),
        (
            "REQ authors, kinds [0,3]",
            json!({"authors": author_list, "kinds": [0, 3], "limit": 2 * authors}),
            false,
        ),
        ("COUNT kinds [1]", json!({"kinds": [1]}), true),
    ];
    type Step = (&'static str, fn(&mut wok_db::RwTxn<'_>));
    let steps: [Step; 4] = [
        ("no policy records", |_| {}),
        ("+ 1000 banned pubkeys and ids", |txn| {
            for i in 0..1_000 {
                wok_db::ban_pubkey(txn, &pubkey(i, 0xBB), "").unwrap();
                wok_db::ban_event(txn, &pubkey(i, 0xCC), "").unwrap();
            }
        }),
        ("+ kind policy without kind 7", |txn| {
            wok_db::disallow_kind(txn, 7).unwrap();
        }),
        ("+ 1000 vanish markers", |txn| {
            for i in 0..1_000 {
                wok_db::mark_vanished(txn, &pubkey(i, 0xDD), u64::MAX >> 1).unwrap();
            }
        }),
    ];
    println!("{notes} notes by {authors} authors, median of {runs} runs");
    for (step, apply) in steps {
        let mut txn = env.begin_rw().unwrap();
        apply(&mut txn);
        txn.commit().unwrap();
        println!("{step}");
        for (label, filter, count_only) in &queries {
            let (sent, took) = time(&env, filter, *count_only, runs);
            println!(
                "  {label:<28} {sent:>7} events  {:>9.3} ms  {:>7.0} ns/event",
                took.as_secs_f64() * 1e3,
                took.as_nanos() as f64 / sent.max(1) as f64
            );
        }
    }
}
