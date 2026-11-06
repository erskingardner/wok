//! Historical-window heuristic guards; all fixtures use new local test DBs.

use super::*;

const BASE: u64 = 1_700_000_000;

fn historical_events(authors: u64) -> Vec<wok_db::EventToWrite> {
    (0..authors)
        .flat_map(|who| {
            [BASE + 300, BASE + 100, BASE + 50]
                .into_iter()
                .enumerate()
                .map(move |(depth, time)| event(who * 10 + depth as u64 + 1, who, time, 1, 0))
        })
        .collect()
}

fn historical_feed(authors: u64, limit: u64) -> NostrFilterGroup {
    let mut value = feed(0..authors, limit);
    value["since"] = json!(BASE + 60);
    value["until"] = json!(BASE + 150);
    group(&value)
}

#[test]
fn uniformly_newer_first_batch_stops_headers_but_preserves_full_query_hints_and_work() {
    let fixture = store(historical_events(2048));
    for authors in [500, 2047] {
        for time_budget_us in [u64::MAX, 0] {
            let options = QueryOptions {
                time_budget_us,
                ..QueryOptions::default()
            };
            let (control, history) = equal_pair(&fixture, &historical_feed(authors, 50), &options);
            assert_eq!(
                history.measurements.wrapper.author_head_keys,
                BATCH_KEYS as u64
            );
            assert_eq!(history.measurements.wrapper.author_head_multiget_calls, 1);
            assert_eq!(
                history.measurements.wrapper.seek,
                control.measurements.wrapper.seek
            );
            assert_eq!(history.chronological_work, control.chronological_work);
            assert_eq!(history.peek_work, control.peek_work);
            assert_eq!(history.peek_candidates, control.peek_candidates);
            assert!(history.completeness.more);
            assert_eq!(
                history.author_frontier_initialization.issued_keys,
                BATCH_KEYS as u64
            );
            assert_eq!(
                history.author_frontier_initialization.fallback_above_until,
                BATCH_KEYS as u64
            );
            assert_eq!(
                history
                    .author_frontier_initialization
                    .fallback_postings_collected,
                BATCH_KEYS as u64
            );
            assert_eq!(
                history.author_frontier_initialization.classified_keys(),
                BATCH_KEYS as u64
            );
            assert_eq!(
                history
                    .author_frontier_initialization
                    .header_keys_during_peek,
                0
            );
            evidence(
                &format!("history_{authors}_budget_{time_budget_us}"),
                &control,
                &history,
            );
        }
    }
}

#[test]
fn sampled_authors_do_not_imply_anything_about_remaining_ranges() {
    let mut events = historical_events(500);
    events.retain(|event| {
        let packed = wok_event::PackedEventView::new(&event.packed).unwrap();
        ![32, 33, 34, 35, 36]
            .into_iter()
            .any(|who| packed.pubkey() == author(who))
    });
    // Beyond the sample, include an in-window head that must win the merge,
    // an absent author, unsupported/newer metadata with an older match, an
    // entirely old range, and a one-position range. All use ordinary seeks.
    events.extend([
        event(100_001, 32, BASE + 140, 1, 0),
        event(100_002, 34, PACKED_TIME_MAX + 1, 1, 0),
        event(100_003, 34, BASE + 100, 1, 0),
        event(100_004, 35, BASE + 50, 1, 0),
        event(100_005, 36, BASE + 100, 1, 0),
    ]);
    let fixture = store(events);
    let filters = historical_feed(500, 50);
    let (control, history) = equal_pair(&fixture, &filters, &QueryOptions::default());
    assert_eq!(
        history.measurements.wrapper.author_head_keys,
        BATCH_KEYS as u64
    );
    assert_eq!(history.chronological_work, control.chronological_work);
    let winner = fixture
        .events
        .iter()
        .find(|event| {
            let packed = wok_event::PackedEventView::new(&event.packed).unwrap();
            packed.pubkey() == author(32)
        })
        .unwrap()
        .lev_id;
    assert_eq!(history.delivery.ids.first(), Some(&winner));
    assert_eq!(history.author_frontier_initialization.seeded_heads, 0);
    assert_eq!(history.author_frontier_initialization.fallback_missing, 0);
    assert_eq!(
        history
            .author_frontier_initialization
            .fallback_unsupported_timestamp,
        0
    );
    assert_eq!(
        history.author_frontier_initialization.fallback_below_since,
        0
    );
    assert_eq!(
        history.author_frontier_initialization.fallback_above_until,
        BATCH_KEYS as u64
    );
}

#[test]
fn transition_preserves_exact_state_and_raw_ids_across_pause_and_snapshot_refresh() {
    let fixture = store(historical_events(500));
    let filters = historical_feed(500, 50);
    let txn = fixture.env.begin_ro().unwrap();
    let mut scans = Vec::new();
    for enabled in [false, true] {
        let mut scan = scanner(&txn, &filters.filters[0], enabled);
        let (complete, counters) = measure(|| {
            scan.scan(
                &txn,
                &filters.filters[0],
                |_| panic!("all frontiers must be initialized before an emission"),
                |work| work > 2 * BATCH_KEYS as u64,
            )
        })
        .unwrap();
        assert!(!complete.unwrap());
        assert_eq!(scan.next_init_index, BATCH_KEYS);
        assert_eq!(scan.approx_work, 2 * BATCH_KEYS as u64 + 1);
        assert!(!scan.author_head_reads);
        assert_eq!(
            counters.wrapper.author_head_keys,
            if enabled { BATCH_KEYS as u64 } else { 0 }
        );
        scans.push(scan);
    }
    assert_eq!(logical_state(&scans[0]), logical_state(&scans[1]));
    drop(txn);

    // The initialized author must keep its original saved lookahead. A later
    // author is initialized in the refreshed snapshot by both ordinary paths.
    let mut inserted = vec![
        event(100_001, 0, BASE + 125, 1, 0),
        event(100_002, 32, BASE + 125, 1, 0),
    ];
    let mut txn = fixture.env.begin_rw().unwrap();
    write_events(&mut txn, &mut NoopNegentropy, &mut inserted, false).unwrap();
    txn.commit().unwrap();
    let txn = fixture.env.begin_ro().unwrap();
    let mut ids = Vec::new();
    for scan in &mut scans {
        let mut raw = Vec::new();
        let (complete, counters) = measure(|| {
            scan.scan(
                &txn,
                &filters.filters[0],
                |id| {
                    raw.push(id);
                    false
                },
                |_| false,
            )
        })
        .unwrap();
        assert!(complete.unwrap());
        assert_eq!(counters.wrapper.author_head_keys, 0);
        assert_eq!(raw.len(), raw.iter().collect::<HashSet<_>>().len());
        ids.push(raw);
    }
    assert_eq!(ids[0], ids[1]);
    assert!(!ids[0].contains(&inserted[0].lev_id));
    assert!(ids[0].contains(&inserted[1].lev_id));
    assert_eq!(scans[0].approx_work, scans[1].approx_work);
    assert_eq!(logical_state(&scans[0]), logical_state(&scans[1]));
}

#[test]
fn mixed_short_and_later_batches_keep_the_reader_enabled() {
    for exception in ["usable", "missing", "unsupported", "below_since", "short"] {
        let authors = if exception == "short" { 31 } else { 500 };
        let mut events = historical_events(authors);
        if exception != "short" {
            events.retain(|event| {
                wok_event::PackedEventView::new(&event.packed)
                    .unwrap()
                    .pubkey()
                    != author(0)
            });
            if exception != "missing" {
                let time = match exception {
                    "usable" => BASE + 100,
                    "unsupported" => PACKED_TIME_MAX + 1,
                    "below_since" => BASE + 50,
                    _ => unreachable!(),
                };
                events.push(event(100_001, 0, time, 1, 0));
            }
        }
        let fixture = store(events);
        let filters = historical_feed(authors, 1);
        let (control, heads) = equal_pair(&fixture, &filters, &QueryOptions::default());
        // All later full batches are too new. Only the first full batch may
        // make this deliberately narrow whole-scanner decision.
        assert_eq!(heads.measurements.wrapper.author_head_keys, authors);
        assert_eq!(heads.chronological_work, control.chronological_work);
        let txn = fixture.env.begin_ro().unwrap();
        let mut scan = scanner(&txn, &filters.filters[0], true);
        let mut physical = None;
        scan.approx_work = 1;
        assert!(initialize(&mut scan, &txn, &mut physical).unwrap());
        assert!(scan.author_head_reads, "{exception}");
    }
}
