//! Diagnostic only: compare a bounded chronological membership probe with the
//! established author merge. No planner or storage format changes are made.

use serde_json::json;
use std::collections::BTreeSet;
use std::time::{Duration, Instant};
use wok_db::{write_events, Env, EnvOptions, EventToWrite, NoopNegentropy, RoTxn};
use wok_event::{PackedEventBuilder, PackedEventTagBuilder, PackedEventView};
use wok_query::{DbScan, NostrFilter, NostrFilterGroup};

const BASE: u64 = 1_700_000_000;
const SINCE: u64 = BASE + 500;
const UNTIL: u64 = BASE + 9_500;
const LIMIT: usize = 50;
const PROBE_ROWS: u64 = 256;
const SLICE_ROWS: u64 = 64;

fn author(n: u64) -> [u8; 32] {
    let mut key = [0; 32];
    key[..8].copy_from_slice(&n.to_be_bytes());
    key
}

fn events(clustered: bool) -> Vec<EventToWrite> {
    (0u64..2_048)
        .flat_map(|who| {
            (0..32).map(move |depth| {
                let local = who * 32 + depth + 1;
                let mut id = [0; 32];
                id[..8].copy_from_slice(&local.to_be_bytes());
                let created = if clustered {
                    BASE + if who < 500 { 500 } else { 5_000 } + depth * 7 + who % 11
                } else {
                    BASE + (local * 1_103_515_245 + 12_345) % 10_000
                };
                let packed = PackedEventBuilder::build(
                    &id,
                    &author(who),
                    created,
                    1,
                    0,
                    &PackedEventTagBuilder::default(),
                )
                .unwrap();
                EventToWrite::new(packed.into_bytes(), json!({"content": ""}).to_string())
            })
        })
        .collect()
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
struct ProbeStats {
    index_entries_visited: u64,
    candidate_rows: u64,
    metadata_gets: u64,
    metadata_bytes: u64,
    range_seeks: u64,
    work_units: u64,
    max_slice_work: u64,
    matched_rows: usize,
    capped: bool,
    exhausted: bool,
}

/// Probe candidates are buffered until enough matches are known. A poor
/// probe is discarded and the author merge runs from the original boundary;
/// this diagnostic never needs to merge two plans' output or resume fences.
fn probe(txn: &RoTxn<'_>, filter: &NostrFilter) -> (Vec<u64>, ProbeStats) {
    let mut result = Vec::with_capacity(LIMIT);
    let mut stats = ProbeStats::default();
    let mut next = Some((filter.until, u64::MAX));
    while let Some((time, local)) = next {
        let mut cursor = txn.cursor(txn.env().dbis().event_created_at).unwrap();
        let mut slice_rows = 0;
        let mut slice_work = 1;
        stats.range_seeks += 1;
        let complete = cursor
            .foreach_index(&time.to_ne_bytes(), local, |entry| {
                stats.index_entries_visited += 1;
                // One collected posting and its processing step, matching
                // DbScan's units, then ten for a primary metadata lookup.
                slice_work += 2;
                let Some(created_at) = entry.created_at else {
                    return true;
                };
                if created_at < filter.since {
                    stats.exhausted = true;
                    return false;
                }
                assert!(created_at <= filter.until);
                stats.candidate_rows += 1;
                stats.metadata_gets += 1;
                slice_rows += 1;
                slice_work += 10;
                let local_id = entry.local_id().unwrap();
                let raw = txn
                    .get_u64(txn.env().dbis().event, local_id)
                    .unwrap()
                    .expect("fixture posting has no stored metadata");
                stats.metadata_bytes += raw.len() as u64;
                let packed = PackedEventView::new(raw).unwrap();
                if filter.does_match(packed) {
                    result.push(local_id);
                }
                // Resume strictly below this (time, id), including ties. No
                // iterator, borrowed entry or stored metadata crosses slices.
                next = local_id
                    .checked_sub(1)
                    .map(|id| (created_at, id))
                    .or_else(|| created_at.checked_sub(1).map(|t| (t, u64::MAX)));
                if result.len() == LIMIT {
                    return false;
                }
                if stats.candidate_rows == PROBE_ROWS {
                    stats.capped = true;
                    return false;
                }
                slice_rows < SLICE_ROWS
            })
            .unwrap();
        stats.work_units += slice_work;
        stats.max_slice_work = stats.max_slice_work.max(slice_work);
        if complete || next.is_none() {
            stats.exhausted = true;
        }
        if stats.exhausted || stats.capped || result.len() == LIMIT {
            break;
        }
    }
    stats.matched_rows = result.len();
    assert!(stats.candidate_rows <= PROBE_ROWS);
    assert!(stats.range_seeks <= PROBE_ROWS.div_ceil(SLICE_ROWS) + 1);
    assert!(stats.max_slice_work <= 1 + SLICE_ROWS * 12);
    (result, stats)
}

fn author_merge(txn: &RoTxn<'_>, filter: &NostrFilter) -> (Vec<u64>, u64) {
    let mut scan = DbScan::new(filter, txn);
    let mut found = Vec::with_capacity(LIMIT);
    scan.scan(
        txn,
        filter,
        |id| {
            found.push(id);
            found.len() == LIMIT
        },
        |_| false,
    )
    .unwrap();
    (found, scan.approx_work)
}

fn micros(samples: &mut [Duration], percentile: usize) -> u128 {
    samples.sort_unstable();
    samples[(samples.len() * percentile).div_ceil(100) - 1].as_micros()
}

/// Run by hand with `--release --ignored --nocapture`. This intentionally
/// checks current-schema viability before any new covering-index experiment.
#[test]
#[ignore]
fn global_membership_probe_benchmark() {
    for (shape, clustered, sparse) in [
        ("dense500-of2048", false, false),
        ("sparse5-of2048", false, true),
        ("older-followed-authors", true, false),
    ] {
        let selected: BTreeSet<_> = (0..500)
            .map(|n| author(if sparse && n >= 5 { 20_000 + n } else { n }))
            .collect();
        let group = NostrFilterGroup::from_value(
            &json!({"authors": selected.iter().map(hex::encode).collect::<Vec<_>>(),
                "since": SINCE, "until": UNTIL, "limit": LIMIT}),
            10_000,
            8,
            16,
        )
        .unwrap();
        let filter = &group.filters[0];
        let mut events = events(clustered);
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let mut txn = env.begin_rw().unwrap();
        write_events(&mut txn, &mut NoopNegentropy, &mut events, false).unwrap();
        txn.commit().unwrap();
        // The reference is independently sorted stored metadata, rather than
        // either query plan's matcher or index order.
        let mut expected: Vec<_> = events
            .iter()
            .filter_map(|event| {
                let packed = PackedEventView::new(&event.packed).unwrap();
                let pubkey: [u8; 32] = packed.pubkey().try_into().unwrap();
                (selected.contains(&pubkey) && (SINCE..=UNTIL).contains(&packed.created_at()))
                    .then_some((packed.created_at(), event.lev_id))
            })
            .collect();
        expected.sort_unstable_by(|a, b| b.cmp(a));
        let expected: Vec<_> = expected.into_iter().take(LIMIT).map(|(_, id)| id).collect();
        assert_eq!(expected.len(), LIMIT, "fixture has too few matches");
        let rounds = std::env::var("WOK_GLOBAL_BENCH_ROUNDS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(100);
        assert!(rounds > 0);
        let mut author_times = Vec::with_capacity(rounds);
        let mut probe_times = Vec::with_capacity(rounds);
        let mut expected_stats = None;
        let mut merge_work = 0;
        let mut fallback_work = 0;
        let mut fallback = false;
        for round in 0..rounds + 10 {
            // Alternate the plans' order, with ten excluded warm-up rounds.
            for is_probe in if round % 2 == 0 {
                [false, true]
            } else {
                [true, false]
            } {
                let started = Instant::now();
                let txn = env.begin_ro().unwrap();
                let found = if is_probe {
                    let (found, stats) = probe(&txn, filter);
                    fallback = found.len() < LIMIT && !stats.exhausted;
                    let found = if fallback {
                        let (found, work) = author_merge(&txn, filter);
                        fallback_work = work;
                        found
                    } else {
                        found
                    };
                    if let Some(expected_stats) = &expected_stats {
                        assert_eq!(stats, *expected_stats, "probe work varied in one snapshot");
                    } else {
                        expected_stats = Some(stats);
                    }
                    found
                } else {
                    let (found, work) = author_merge(&txn, filter);
                    merge_work = work;
                    found
                };
                drop(txn);
                let elapsed = started.elapsed();
                assert_eq!(found, expected, "shape {shape}, probe {is_probe}");
                if round >= 10 {
                    if is_probe {
                        probe_times.push(elapsed);
                    } else {
                        author_times.push(elapsed);
                    }
                }
            }
        }
        let stats = expected_stats.unwrap();
        println!(
            "{}",
            json!({
                "diagnostic": "global-probe-local", "shape": shape, "rounds": rounds,
                "fixture_events": events.len(), "authors_in_filter": selected.len(),
                "since": SINCE, "until": UNTIL, "limit": LIMIT,
                "probe_row_cap": PROBE_ROWS, "rows_per_work_slice": SLICE_ROWS,
                "probe_index_entries_visited": stats.index_entries_visited,
                "probe_candidate_rows": stats.candidate_rows,
                "probe_metadata_gets": stats.metadata_gets,
                "probe_metadata_bytes": stats.metadata_bytes,
                "probe_range_seeks": stats.range_seeks,
                "probe_max_slice_work_units": stats.max_slice_work,
                "probe_work_units": stats.work_units, "probe_matches": stats.matched_rows,
                "probe_capped": stats.capped, "used_author_fallback": fallback,
                "fallback_work_units": fallback_work,
                "probe_plus_fallback_work_units": stats.work_units + fallback_work,
                "author_merge_work_units": merge_work,
                "author_merge_p50_us": micros(&mut author_times, 50),
                "author_merge_p99_us": micros(&mut author_times, 99),
                "probe_plus_fallback_p50_us": micros(&mut probe_times, 50),
                "probe_plus_fallback_p99_us": micros(&mut probe_times, 99),
            })
        );
    }
}
