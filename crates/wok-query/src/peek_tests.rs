//! Completeness probes reuse queued candidates and collect only the next
//! range head they need. Work assertions cover both storage backends.

use super::*;
use crate::visibility::ReadRestrictor;
use serde_json::{json, Value};
use wok_db::{write_events, Env, EnvOptions, EventToWrite, NoopNegentropy};
use wok_event::{PackedEventBuilder, PackedEventTagBuilder};

const BASE: u64 = 1_700_000_000;

fn author(who: u64) -> [u8; 32] {
    let mut key = [0; 32];
    key[..8].copy_from_slice(&who.to_be_bytes());
    key
}

fn event(n: u64, who: u64, kind: u64, tags: &[&str]) -> EventToWrite {
    let mut id = [0; 32];
    id[..8].copy_from_slice(&n.to_be_bytes());
    let mut packed_tags = PackedEventTagBuilder::default();
    for tag in tags {
        packed_tags.add('t', tag.as_bytes()).unwrap();
    }
    if kind == 4 {
        packed_tags.add('p', &[9; 32]).unwrap();
    }
    let packed =
        PackedEventBuilder::build(&id, &author(who), BASE + n / 3, kind, 0, &packed_tags).unwrap();
    EventToWrite::new(packed.into_bytes(), json!({"content": ""}).to_string())
}

fn store(mut events: Vec<EventToWrite>) -> (tempfile::TempDir, Env, Vec<EventToWrite>) {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let mut txn = env.begin_rw().unwrap();
    write_events(&mut txn, &mut NoopNegentropy, &mut events, false).unwrap();
    txn.commit().unwrap();
    (dir, env, events)
}

fn filter(value: Value) -> NostrFilter {
    NostrFilter::parse(&value, 10_000, 8, 16).unwrap()
}

fn stop_after(scan: &mut DbScan, txn: &RoTxn<'_>, filter: &NostrFilter, n: usize) -> Vec<u64> {
    let mut sent = Vec::new();
    assert!(scan
        .scan(
            txn,
            filter,
            |id| {
                sent.push(id);
                sent.len() == n
            },
            |_| false,
        )
        .unwrap());
    assert_eq!(sent.len(), n);
    sent
}

fn budget() -> PeekBudget {
    PeekBudget {
        work: PEEK_WORK,
        candidates: PEEK_CANDIDATES,
    }
}

fn found(peek: Peek) -> u64 {
    match peek {
        Peek::Found(id) => id,
        _ => panic!("peek did not find the next visible match"),
    }
}

fn restricted() -> ReadVisibility {
    ReadVisibility {
        restrictor: ReadRestrictor {
            recipient_only: vec![4],
            ..ReadRestrictor::default()
        },
        ..ReadVisibility::default()
    }
}

#[test]
fn peek_fetches_one_posting_after_exhausting_initial_batch() {
    let (_dir, env, events) = store((1..=700).map(|n| event(n, 0, 1, &[])).collect());
    let txn = env.begin_ro().unwrap();
    let snapshot = ReadSnapshot::for_stored(&txn);
    for value in [
        json!({"authors": [hex::encode(author(0))], "limit": 50}),
        json!({"kinds": [1], "limit": 50}),
        json!({"limit": 50}),
    ] {
        let filter = filter(value);
        let mut scan = DbScan::new(&filter, &txn);
        let sent = stop_after(&mut scan, &txn, &filter, 50);
        assert_eq!(scan.refill_scan_depths, [500]);
        assert!(scan.event_queue.is_empty());
        let start = scan.approx_work;
        let mut budget = budget();
        let id = found(
            DbQuery::peek(
                &mut scan,
                &snapshot,
                &filter,
                u64::MAX,
                &sent.into_iter().collect(),
                &ReadVisibility::default(),
                &mut false,
                &mut budget,
            )
            .unwrap(),
        );
        assert_eq!(id, events[649].lev_id);
        // One collected posting and one candidate attempt, not a 500-row
        // refill. Normal scan batching is retained for a later continuation.
        assert_eq!(scan.approx_work - start, 2);
        assert_eq!(budget.work, PEEK_WORK - 2);
        assert_eq!(budget.candidates, PEEK_CANDIDATES - 1);
        assert_eq!(scan.refill_scan_depths, [500]);
        assert_eq!(scan.cursors[0].outstanding, 1);
        assert!(scan.event_queue.is_empty());
    }
}

#[test]
fn peek_reuses_queued_candidates_and_caps_unscanned_filters() {
    let (_dir, env, events) = store((1..=700).map(|n| event(n, 0, 1, &[])).collect());
    let txn = env.begin_ro().unwrap();
    let snapshot = ReadSnapshot::for_stored(&txn);
    let filter = filter(json!({"authors": [hex::encode(author(0))], "limit": 50}));
    for (sent_count, expected_work, expected_id) in
        [(0, 3, events[699].lev_id), (1, 1, events[698].lev_id)]
    {
        let mut scan = DbScan::new(&filter, &txn);
        let sent = if sent_count == 0 {
            Vec::new()
        } else {
            stop_after(&mut scan, &txn, &filter, sent_count)
        };
        let start = scan.approx_work;
        let mut budget = budget();
        assert_eq!(
            found(
                DbQuery::peek(
                    &mut scan,
                    &snapshot,
                    &filter,
                    u64::MAX,
                    &sent.into_iter().collect(),
                    &ReadVisibility::default(),
                    &mut false,
                    &mut budget,
                )
                .unwrap()
            ),
            expected_id
        );
        assert_eq!(scan.approx_work - start, expected_work);
    }
}

#[test]
fn peek_skips_hidden_matches_with_one_posting_refills() {
    let (_dir, env, events) = store(
        (1..=700)
            .map(|n| event(n, 0, if (639..=650).contains(&n) { 4 } else { 1 }, &[]))
            .collect(),
    );
    let txn = env.begin_ro().unwrap();
    let snapshot = ReadSnapshot::for_stored(&txn);
    let filter = filter(json!({"authors": [hex::encode(author(0))], "limit": 50}));
    let mut scan = DbScan::new(&filter, &txn);
    let sent = stop_after(&mut scan, &txn, &filter, 50);
    let start = scan.approx_work;
    let mut budget = budget();
    let mut hidden = false;
    assert_eq!(
        found(
            DbQuery::peek(
                &mut scan,
                &snapshot,
                &filter,
                u64::MAX,
                &sent.into_iter().collect(),
                &restricted(),
                &mut hidden,
                &mut budget,
            )
            .unwrap()
        ),
        events[637].lev_id
    );
    assert!(hidden);
    assert_eq!(scan.approx_work - start, 2 * 13);
    assert_eq!(budget.work, PEEK_WORK - 2 * 13);
    assert_eq!(budget.candidates, PEEK_CANDIDATES - 13);
}

#[test]
fn sparse_peek_charges_filter_checks_and_stops_at_its_work_budget() {
    let (_dir, env, _events) = store(
        (1..=700)
            .map(|n| event(n, u64::from(n <= 650), 1, &["all"]))
            .collect(),
    );
    let txn = env.begin_ro().unwrap();
    let snapshot = ReadSnapshot::for_stored(&txn);
    let filter = filter(json!({"authors": [hex::encode(author(0))], "#t": ["all"], "limit": 50}));
    let mut scan = DbScan::new(&filter, &txn);
    assert!(!scan.index_only);
    let sent = stop_after(&mut scan, &txn, &filter, 50);
    let sent = sent.into_iter().collect();
    let start = scan.approx_work;
    let mut budget = PeekBudget {
        work: 25,
        candidates: PEEK_CANDIDATES,
    };
    assert!(matches!(
        DbQuery::peek(
            &mut scan,
            &snapshot,
            &filter,
            u64::MAX,
            &sent,
            &ReadVisibility::default(),
            &mut false,
            &mut budget,
        )
        .unwrap(),
        Peek::Unknown
    ));
    // Two rejected full-filter checks cost 10 each, three collected heads
    // cost one each, and three loop attempts cost one each. The next head
    // stays queued; no third full-filter check runs after the budget.
    assert_eq!(scan.approx_work - start, 26);
    assert_eq!(scan.event_queue.heap.len(), 1);
    assert_eq!(budget.work, 0);
    assert_eq!(budget.candidates, PEEK_CANDIDATES);
    let stopped = scan.approx_work;
    assert!(matches!(
        DbQuery::peek(
            &mut scan,
            &snapshot,
            &filter,
            u64::MAX,
            &sent,
            &ReadVisibility::default(),
            &mut false,
            &mut budget,
        )
        .unwrap(),
        Peek::Unknown
    ));
    assert_eq!(scan.approx_work, stopped);
}

#[test]
fn candidate_budget_distinguishes_exhaustion_from_an_unchecked_match() {
    for more in [false, true] {
        let extra = u64::from(more);
        let (_dir, env, _events) = store(
            (1..=50 + 64 + extra)
                .map(|n| {
                    let kind = if n > extra && n <= 64 + extra { 4 } else { 1 };
                    event(n, 0, kind, &[])
                })
                .collect(),
        );
        let txn = env.begin_ro().unwrap();
        let snapshot = ReadSnapshot::for_stored(&txn);
        let filter = filter(json!({"authors": [hex::encode(author(0))], "limit": 50}));
        let mut scan = DbScan::new(&filter, &txn);
        let sent = stop_after(&mut scan, &txn, &filter, 50);
        let start = scan.approx_work;
        let mut budget = budget();
        let mut hidden = false;
        let result = DbQuery::peek(
            &mut scan,
            &snapshot,
            &filter,
            u64::MAX,
            &sent.into_iter().collect(),
            &restricted(),
            &mut hidden,
            &mut budget,
        )
        .unwrap();
        if more {
            assert!(matches!(result, Peek::Unknown));
        } else {
            assert!(matches!(result, Peek::Exhausted));
        }
        assert!(hidden);
        assert_eq!(budget.candidates, 0);
        assert_eq!(scan.approx_work - start, 129 + extra);
        assert_eq!(budget.work, PEEK_WORK - (129 + extra));
        let stopped = scan.approx_work;
        assert!(matches!(
            DbQuery::peek(
                &mut scan,
                &snapshot,
                &filter,
                u64::MAX,
                &HashSet::new(),
                &restricted(),
                &mut hidden,
                &mut budget,
            )
            .unwrap(),
            Peek::Unknown
        ));
        assert_eq!(scan.approx_work, stopped);
    }
}

#[test]
fn peek_skips_newer_and_previously_sent_events_before_spending_candidate_budget() {
    let (_dir, env, events) = store((1..=700).map(|n| event(n, 0, 1, &[])).collect());
    let txn = env.begin_ro().unwrap();
    let snapshot = ReadSnapshot::for_stored(&txn);
    let filter = filter(json!({"authors": [hex::encode(author(0))], "limit": 50}));
    let mut scan = DbScan::new(&filter, &txn);
    let mut sent: HashSet<_> = stop_after(&mut scan, &txn, &filter, 50)
        .into_iter()
        .collect();
    // The first two remaining entries exceed admission's local-ID bound;
    // another filter already sent the third. Only the fourth is a witness.
    let latest = events[647].lev_id;
    sent.insert(latest);
    let start = scan.approx_work;
    let mut budget = budget();
    assert_eq!(
        found(
            DbQuery::peek(
                &mut scan,
                &snapshot,
                &filter,
                latest,
                &sent,
                &ReadVisibility::default(),
                &mut false,
                &mut budget,
            )
            .unwrap()
        ),
        events[646].lev_id
    );
    assert_eq!(scan.approx_work - start, 8);
    assert_eq!(budget.candidates, PEEK_CANDIDATES - 1);
}

#[test]
fn a_partial_frontier_cannot_prove_more_before_all_ranges_are_initialized() {
    let (_dir, env, events) = store((1..=700).map(|n| event(n, n % 3, 1, &[])).collect());
    let txn = env.begin_ro().unwrap();
    let snapshot = ReadSnapshot::for_stored(&txn);
    let filter = filter(json!({
        "authors": (0..3).map(|n| hex::encode(author(n))).collect::<Vec<_>>(),
        "limit": 50,
    }));
    let mut scan = DbScan::new(&filter, &txn);
    let mut spent = PeekBudget {
        work: 2,
        candidates: PEEK_CANDIDATES,
    };
    assert!(matches!(
        DbQuery::peek(
            &mut scan,
            &snapshot,
            &filter,
            u64::MAX,
            &HashSet::new(),
            &ReadVisibility::default(),
            &mut false,
            &mut spent,
        )
        .unwrap(),
        Peek::Unknown
    ));
    assert_eq!(scan.approx_work, 3);
    assert_eq!(scan.next_init_index, 1);
    assert_eq!(scan.event_queue.heap.len(), 1);
    assert_eq!(spent.work, 0);
    assert_eq!(spent.candidates, PEEK_CANDIDATES);

    // Resuming the same scan with fresh diagnostic budget still initializes
    // the other heads before taking the newest, including an equal-time tie.
    let start = scan.approx_work;
    assert_eq!(
        found(
            DbQuery::peek(
                &mut scan,
                &snapshot,
                &filter,
                u64::MAX,
                &HashSet::new(),
                &ReadVisibility::default(),
                &mut false,
                &mut budget(),
            )
            .unwrap()
        ),
        events[699].lev_id
    );
    assert_eq!(scan.approx_work - start, 5);
    assert_eq!(scan.next_init_index, 3);
    assert_eq!(scan.refill_scan_depths, [32; 3]);
}

#[test]
fn zero_budget_preserves_pending_state_and_peeks_do_not_grow_adaptive_depths() {
    let (_dir, env, events) = store((1..=700).map(|n| event(n, n % 3, 1, &[])).collect());
    let txn = env.begin_ro().unwrap();
    let snapshot = ReadSnapshot::for_stored(&txn);
    let filter = filter(json!({
        "authors": (0..3).map(|n| hex::encode(author(n))).collect::<Vec<_>>(),
        "limit": 3,
    }));
    let mut scan = DbScan::new(&filter, &txn);
    let sent = stop_after(&mut scan, &txn, &filter, 1);
    assert_eq!(scan.refill_scan_depths, [2; 3]);
    let start = scan.approx_work;
    let pending = scan.unsettled;
    let initialized = scan.next_init_index;
    let queued = scan.event_queue.heap.len();
    let cursor_state = |scan: &DbScan| {
        scan.cursors
            .iter()
            .map(|cursor| {
                (
                    cursor.resume_key.clone(),
                    cursor.resume_val,
                    cursor.outstanding,
                )
            })
            .collect::<Vec<_>>()
    };
    let cursors = cursor_state(&scan);
    for (work, candidates) in [(0, PEEK_CANDIDATES), (PEEK_WORK, 0)] {
        let mut budget = PeekBudget { work, candidates };
        assert!(matches!(
            DbQuery::peek(
                &mut scan,
                &snapshot,
                &filter,
                u64::MAX,
                &HashSet::new(),
                &ReadVisibility::default(),
                &mut false,
                &mut budget,
            )
            .unwrap(),
            Peek::Unknown
        ));
        assert_eq!(scan.approx_work, start);
        assert_eq!(scan.unsettled, pending);
        assert_eq!(scan.next_init_index, initialized);
        assert_eq!(scan.event_queue.heap.len(), queued);
        assert_eq!(cursor_state(&scan), cursors);
        assert_eq!((budget.work, budget.candidates), (work, candidates));
        assert_eq!(scan.refill_scan_depths, [2; 3]);
    }
    // Settling the winning range now fetches one replacement head. Its
    // ordinary adaptive depth must not double because of that capped read.
    assert_eq!(
        found(
            DbQuery::peek(
                &mut scan,
                &snapshot,
                &filter,
                u64::MAX,
                &sent.into_iter().collect(),
                &ReadVisibility::default(),
                &mut false,
                &mut budget(),
            )
            .unwrap()
        ),
        events[698].lev_id
    );
    assert_eq!(scan.approx_work - start, 2);
    assert_eq!(scan.refill_scan_depths, [2; 3]);
}

#[test]
fn capped_and_normal_scans_resume_tied_and_overlapping_ranges_in_order() {
    let (_dir, env, events) = store((1..=180).map(|n| event(n, n % 3, 1, &["a", "b"])).collect());
    let txn = env.begin_ro().unwrap();
    for (value, copies) in [
        (
            json!({"authors": (0..3).map(|n| hex::encode(author(n))).collect::<Vec<_>>(),
                "since": BASE + 5, "until": BASE + 55, "limit": 50}),
            1,
        ),
        (
            json!({"#t": ["a", "b"], "since": BASE + 5, "until": BASE + 55, "limit": 50}),
            2,
        ),
    ] {
        let filter = filter(value);
        let mut expected: Vec<_> = events
            .iter()
            .filter_map(|event| {
                let packed = PackedEventView::new(&event.packed).unwrap();
                filter
                    .does_match(packed)
                    .then_some((packed.created_at(), event.lev_id))
            })
            .flat_map(|event| std::iter::repeat_n(event, copies))
            .collect();
        expected.sort_unstable_by(|a, b| b.cmp(a));
        let expected: Vec<_> = expected.into_iter().map(|(_, id)| id).collect();
        let mut scan = DbScan::new(&filter, &txn);
        let mut got = Vec::new();
        let mut yielded = false;
        for round in 0..1_000 {
            let start_work = scan.approx_work;
            let start_len = got.len();
            let handle = |id| {
                got.push(id);
                got.len() - start_len == 7
            };
            let pause = |work| work - start_work >= 17;
            let complete = if round % 2 == 0 {
                scan.scan_with_depth_cap(&txn, &filter, 1, handle, pause)
            } else {
                scan.scan(&txn, &filter, handle, pause)
            }
            .unwrap();
            yielded |= !complete;
            assert!(scan.approx_work - start_work <= if round % 2 == 0 { 19 } else { 69 });
            // The handler's stopped candidate is counted until the next
            // call settles it. Every other outstanding row is in the heap.
            assert_eq!(
                scan.cursors
                    .iter()
                    .map(|cursor| cursor.outstanding)
                    .sum::<u64>(),
                scan.event_queue.heap.len() as u64 + u64::from(scan.unsettled.is_some())
            );
            if complete && scan.event_queue.is_empty() && scan.unsettled.is_none() {
                assert_eq!(got, expected);
                assert!(yielded);
                break;
            }
            assert!(round < 999, "scan stopped making progress");
        }
    }
}
