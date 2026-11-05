//! Same-layout seek/control and optional frontier-reader comparisons.

#[path = "author_history_tests.rs"]
mod history_tests;

use super::*;
use crate::scan::feed_query_diagnostic::*;
use crate::visibility::ReadRestrictor;
use crate::NostrFilterGroup;
use serde_json::{json, Value};
use wok_db::read_diagnostics::measure;
use wok_db::{write_events, AuthorPosition, NoopNegentropy};

const BASE: u64 = 1_700_000_000;

fn scanner(txn: &RoTxn<'_>, filter: &NostrFilter, use_heads: bool) -> DbScan {
    let mut scan = DbScan::new(filter, txn);
    scan.author_head_reads &= use_heads;
    scan
}

fn equal_pair(
    fixture: &Fixture,
    filters: &NostrFilterGroup,
    options: &QueryOptions,
) -> (Sample, Sample) {
    let control = read_arm(&fixture.env, filters, Arm::Pubkey, options).unwrap();
    let heads = read_arm(&fixture.env, filters, Arm::AuthorHeads, options).unwrap();
    assert!(control.completed && heads.completed);
    assert!(!control.delivery.payload_failed && !heads.delivery.payload_failed);
    assert_eq!(control.delivery, heads.delivery);
    assert_eq!(heads.delivery.ids, expected(fixture, filters, options));
    assert_eq!(control.completeness, heads.completeness);
    (control, heads)
}

fn evidence(label: &str, control: &Sample, heads: &Sample) {
    let brief = |s: &Sample| {
        json!({
            "completed":s.completed,"sent_count":s.delivery.sent_count,
            "body_sha256":s.delivery.body_sha256,"body_bytes":s.delivery.body_bytes,
            "packed_sha256":s.delivery.packed_sha256,"packed_bytes":s.delivery.packed_bytes,
            "payload_sha256":s.delivery.payload_sha256,"payload_bytes":s.delivery.payload_bytes,
            "payload_failed":s.delivery.payload_failed,
            "completeness":{"finish":s.completeness.finish,"more":s.completeness.more,"restricted":s.completeness.restricted},
            "chronological_work":s.chronological_work,"peek_work":s.peek_work,"peek_candidates":s.peek_candidates,
            "slice_work":s.slice_work,"plan":{"desc":s.plan.desc,"cursors":s.plan.cursors,"index_only":s.plan.index_only},
            "measurements":s.measurements
        })
    };
    let report = json!({
        "format":"wok-author-frontier-local-evidence-v1","label":label,
        "delivery_equal":control.delivery==heads.delivery,"completeness_equal":control.completeness==heads.completeness,
        "strict_pair_eligible":control.completed&&heads.completed&&control.delivery==heads.delivery&&control.completeness==heads.completeness&&!control.delivery.payload_failed&&!heads.delivery.payload_failed,
        "control":brief(control),"frontier_reader":brief(heads),
        "scope":"Same v3 frontier layout, fresh transaction per arm, ordinary seek control versus opt-in32-key initial reader. Full normal DbQuery and body hashing; counters/work only, no clean timing/network/physical-I/O claim. Mid-initialization pause checks are coarser by at most one batch. No per-author arrays or event bodies emitted."
    });
    println!("WOK_AUTHOR_FRONTIER_LOCAL_RESULT={report}");
}

#[test]
fn eligibility_and_constructor_keep_nonwide_or_residual_plans_unchanged_without_io() {
    let fixture = store(dense_events(512, 2, false));
    let txn = fixture.env.begin_ro().unwrap();
    for (value, eligible) in [
        (feed(0..500, 50), true),
        (feed(0..2047, 50), true),
        (feed(0..1, 50), false),
        (feed(0..500, 10000), false),
        (feed(0..500, 0), false),
        (
            json!({"authors":[hex::encode(author(0)),hex::encode(author(1))],"kinds":[1],"limit":1}),
            false,
        ),
        (
            json!({"authors":[hex::encode(author(0)),hex::encode(author(1))],"#t":["red"],"limit":1}),
            false,
        ),
        (json!({"kinds":[1],"limit":50}), false),
        (json!({"limit":50}), false),
    ] {
        let filter = group(&value).filters.remove(0);
        // Residual-tag planning has an established optional probe; constructor
        // no-I/O assertion concerns only the newly eligible pure-author path.
        let (scan, measurements) = measure(|| DbScan::new(&filter, &txn)).unwrap();
        assert_eq!(scan.author_head_reads, eligible, "{value}");
        assert_eq!(measurements.wrapper.author_head_multiget_calls, 0);
        assert_eq!(measurements.wrapper.author_head_keys, 0);
        if eligible {
            assert_eq!(measurements.wrapper, Default::default());
            assert_eq!(scan.approx_work, 0);
            assert_eq!(scan.next_init_index, 0);
        }
    }
}

fn logical_state(scan: &DbScan) -> Value {
    let mut queue: Vec<_> = scan
        .event_queue
        .heap
        .iter()
        .map(|q| {
            (
                q.event.created(),
                q.event.lev_id(),
                q.event.scan_index(),
                q.sequence,
            )
        })
        .collect();
    queue.sort_unstable();
    json!({
        "next_init_index":scan.next_init_index,"queue":queue,"work":scan.approx_work,
        "outstanding":scan.cursors.iter().map(|c|c.outstanding).collect::<Vec<_>>(),
        "resume":scan.cursors.iter().map(|c|(&c.resume_key,c.resume_val)).collect::<Vec<_>>(),
        "refill_depths":scan.refill_scan_depths,"unsettled":scan.unsettled
    })
}

#[test]
fn initial_frontier_is_identical_with_500_or_2047_fewer_range_seeks() {
    let fixture = store(dense_events(2048, 3, false));
    for authors in [500, 2047] {
        let filters = group(&feed(0..authors, 50));
        let mut states = Vec::new();
        let mut counters = Vec::new();
        let mut firsts = Vec::new();
        for enabled in [false, true] {
            let txn = fixture.env.begin_ro().unwrap();
            let mut scan = scanner(&txn, &filters.filters[0], enabled);
            let mut first = None;
            let (complete, measurements) = measure(|| {
                scan.scan(
                    &txn,
                    &filters.filters[0],
                    |id| {
                        first = Some(id);
                        true
                    },
                    |_| false,
                )
            })
            .unwrap();
            assert!(complete.unwrap());
            firsts.push(first.unwrap());
            states.push(logical_state(&scan));
            counters.push(measurements);
        }
        assert_eq!(states[0], states[1]);
        assert_eq!(firsts[0], firsts[1]);
        assert_eq!(counters[0].wrapper.seek, authors);
        assert_eq!(counters[1].wrapper.seek, 0);
        assert_eq!(counters[1].wrapper.iterator_creations, 0);
        assert_eq!(counters[1].wrapper.author_head_keys, authors);
        assert_eq!(
            counters[1].wrapper.author_head_multiget_calls,
            authors.div_ceil(BATCH_KEYS as u64)
        );
        assert_eq!(counters[1].wrapper.primary_pin_lookups, 0);
        assert_eq!(counters[1].wrapper.generic_row_materializations, 0);
        println!(
            "WOK_AUTHOR_FRONTIER_INITIAL_RESULT={}",
            json!({"authors":authors,"initial_depth":1,"first_id":firsts[0],"logical_state_equal":true,"approx_work":states[0]["work"],"control":counters[0],"frontier_reader":counters[1]})
        );
    }
}

#[test]
fn dense_full_queries_and_completeness_are_equal_for_both_slice_budgets() {
    let fixture = store(dense_events(2048, 3, false));
    for authors in [500, 2047] {
        for time_budget_us in [u64::MAX, 0] {
            let options = QueryOptions {
                time_budget_us,
                ..QueryOptions::default()
            };
            let (control, heads) = equal_pair(&fixture, &group(&feed(0..authors, 50)), &options);
            assert_eq!(heads.measurements.wrapper.author_head_keys, authors);
            assert_eq!(
                heads.measurements.wrapper.author_head_multiget_calls,
                authors.div_ceil(BATCH_KEYS as u64)
            );
            assert!(heads.measurements.wrapper.seek < control.measurements.wrapper.seek);
            assert_eq!(
                heads.measurements.wrapper.primary_pin_lookups,
                control.measurements.wrapper.primary_pin_lookups
            );
            assert_eq!(heads.peek_work, control.peek_work);
            if time_budget_us == u64::MAX {
                assert_eq!(heads.chronological_work, control.chronological_work);
            }
            evidence(
                &format!("dense_{authors}_budget_{time_budget_us}"),
                &control,
                &heads,
            );
        }
    }
}

#[test]
fn missing_and_out_of_window_heads_fall_back_without_omitting_matches() {
    let fixture = store(dense_events(512, 3, false));
    for (since, until) in [
        (0, BASE + 20000),
        (0, BASE + 62),
        (BASE + 1000, BASE + 20000),
        (0, 0),
    ] {
        let mut value = feed(0..2047, 50);
        value["since"] = json!(since);
        value["until"] = json!(until);
        let (control, heads) = equal_pair(&fixture, &group(&value), &QueryOptions::default());
        assert_eq!(
            heads.measurements.wrapper.author_head_keys,
            if until == 0 { BATCH_KEYS as u64 } else { 2047 }
        );
        // Absent authors are None, not a reason to omit ordinary range reads.
        assert!(heads.measurements.wrapper.seek >= 2047 - 512);
        assert_eq!(heads.chronological_work, control.chronological_work);
        evidence(
            &format!("missing_or_window_{since}_{until}"),
            &control,
            &heads,
        );
    }
}

#[test]
fn missing_header_on_a_populated_range_really_uses_the_ordinary_index() {
    let fixture = store(dense_events(128, 3, false));
    let filters = group(&feed(0..500, 50));
    let txn = fixture.env.begin_ro().unwrap();
    let mut missing = scanner(&txn, &filters.filters[0], true);
    missing.approx_work = 1; // caller already charged the first loop attempt
    let mut physical = None;
    let (result, measurements) = measure(|| {
        initialize_entries(&mut missing, &txn, &mut physical, 0, vec![None; BATCH_KEYS])
    })
    .unwrap();
    result.unwrap();
    assert_eq!(missing.next_init_index, BATCH_KEYS);
    assert_eq!(missing.approx_work, 2 * BATCH_KEYS as u64);
    assert!(missing.cursors[..BATCH_KEYS]
        .iter()
        .all(|c| c.outstanding == 1));
    assert_eq!(measurements.wrapper.seek, BATCH_KEYS as u64);
    assert_eq!(measurements.wrapper.author_head_keys, 0); // supplied missing records, no API call in this scope
    let mut control = scanner(&txn, &filters.filters[0], false);
    let mut expected = VecDeque::new();
    let mut cursor = txn.cursor(control.index_dbi).unwrap();
    for index in 0..BATCH_KEYS {
        control.cursors[index]
            .collect(
                &mut cursor,
                index as u64,
                control.since,
                control.until,
                1,
                &mut expected,
            )
            .unwrap();
    }
    let mut actual: Vec<_> = missing
        .event_queue
        .heap
        .iter()
        .map(|c| c.event.lev_id())
        .collect();
    actual.sort_unstable();
    let mut expected: Vec<_> = expected.into_iter().map(|c| c.lev_id()).collect();
    expected.sort_unstable();
    assert_eq!(actual, expected);
}

#[test]
fn single_posting_and_below_since_next_keep_finish_more_and_logical_work() {
    for below_since in [false, true] {
        let mut events = Vec::new();
        for who in 0..500 {
            events.push(event(who * 10 + 1, who, BASE + 100, 1, 0));
            if below_since {
                events.push(event(who * 10 + 2, who, BASE + 10, 1, 0));
                events.push(event(who * 10 + 3, who, 0, 1, 0));
            }
        }
        let fixture = store(events);
        for limit in [50, 500] {
            let mut value = feed(0..500, limit);
            value["since"] = json!(BASE + 50);
            let (control, heads) = equal_pair(&fixture, &group(&value), &QueryOptions::default());
            assert_eq!(heads.chronological_work, control.chronological_work);
            assert_eq!(heads.peek_work, control.peek_work);
            assert_eq!(heads.completeness.more, limit == 50);
            assert_eq!(heads.completeness.finish, limit == 500);
            assert_eq!(heads.measurements.wrapper.author_head_keys, 500);
            evidence(
                &format!("single_or_old_next_{below_since}_limit_{limit}"),
                &control,
                &heads,
            );
        }
    }
}

#[test]
fn fallback_error_still_charges_every_key_of_the_issued_batch() {
    let fixture = store(dense_events(128, 3, false));
    let mut txn = fixture.env.begin_rw().unwrap();
    let mut bad_key = author(0).to_vec();
    bad_key.extend_from_slice(&(BASE + 19999).to_ne_bytes());
    txn.put(
        fixture.env.dbis().event_pubkey,
        &bad_key,
        &7u32.to_ne_bytes(),
        0,
    )
    .unwrap();
    txn.commit().unwrap();
    let filters = group(&feed(0..500, 50));
    let txn = fixture.env.begin_ro().unwrap();
    let key = author(0);
    assert_eq!(txn.author_heads([&key]).unwrap(), vec![None]);
    let mut scan = scanner(&txn, &filters.filters[0], true);
    let (result, measurements) = measure(|| {
        scan.scan(
            &txn,
            &filters.filters[0],
            |_| panic!("damaged range"),
            |_| false,
        )
    })
    .unwrap();
    assert!(result.is_err());
    assert!(scan.author_head_reads);
    assert_eq!(scan.approx_work, BATCH_KEYS as u64);
    assert_eq!(scan.next_init_index, 0);
    assert_eq!(measurements.wrapper.author_head_keys, BATCH_KEYS as u64);
    assert_eq!(measurements.wrapper.author_head_multiget_calls, 1);
}

#[test]
fn peek_never_batches_headers_even_for_an_uninitialized_2047_range_scan() {
    let fixture = store(dense_events(2048, 3, false));
    for authors in [500, 2047] {
        let filters = group(&feed(0..authors, 50));
        for use_heads in [false, true] {
            let txn = fixture.env.begin_ro().unwrap();
            let snapshot = ReadSnapshot::for_stored(&txn);
            let mut scan = scanner(&txn, &filters.filters[0], use_heads);
            let mut budget = PeekBudget {
                work: PEEK_WORK,
                candidates: PEEK_CANDIDATES,
            };
            let (result, counters) = measure(|| {
                DbQuery::peek(
                    &mut scan,
                    &snapshot,
                    &filters.filters[0],
                    u64::MAX,
                    &HashSet::new(),
                    &ReadVisibility::default(),
                    &mut false,
                    &mut budget,
                )
            })
            .unwrap();
            assert_eq!(counters.wrapper.author_head_keys, 0);
            assert_eq!(counters.wrapper.author_head_multiget_calls, 0);
            if authors == 500 {
                assert!(matches!(result.unwrap(), Peek::Found(_)));
            } else {
                assert!(matches!(result.unwrap(), Peek::Unknown));
            }
        }
    }
}

#[test]
fn batching_charges_all_keys_before_a_bounded_initialization_pause() {
    let fixture = store(dense_events(2048, 3, false));
    let filters = group(&feed(0..2047, 50));
    let txn = fixture.env.begin_ro().unwrap();
    let mut scan = scanner(&txn, &filters.filters[0], true);
    let (complete, counters) = measure(|| {
        scan.scan(
            &txn,
            &filters.filters[0],
            |_| panic!("must not emit before all frontiers"),
            |work| work > 2000,
        )
    })
    .unwrap();
    assert!(!complete.unwrap());
    assert_eq!(scan.next_init_index, 1024);
    assert_eq!(scan.approx_work, 2 * 1024 + 1);
    assert!(scan.approx_work - 2001 <= 2 * BATCH_KEYS as u64);
    assert_eq!(
        counters.wrapper.author_head_keys,
        scan.next_init_index as u64
    );
    assert_eq!(
        counters.wrapper.author_head_multiget_calls,
        1024_u64.div_ceil(BATCH_KEYS as u64)
    );
    assert_eq!(counters.wrapper.iterator_creations, 0);
    assert_eq!(scan.event_queue.heap.len(), 1024);
    assert!(scan.cursors[..1024].iter().all(|c| c.outstanding == 1));
    assert!(scan.cursors[1024..].iter().all(|c| c.outstanding == 0));
}

#[test]
fn exact_saved_lookahead_avoids_new_backdated_rows_after_snapshot_refresh_without_dedup() {
    let mut original = Vec::new();
    for who in 0..500 {
        for (depth, time) in [BASE + 100, BASE + 10, BASE].into_iter().enumerate() {
            original.push(event(who * 10 + depth as u64 + 1, who, time, 1, 0));
        }
    }
    let fixture = store(original);
    let filters = group(&feed(0..500, 50));
    let expected = expected(
        &fixture,
        &group(&feed(0..500, 10000)),
        &QueryOptions::default(),
    );
    let txn = fixture.env.begin_ro().unwrap();
    let mut scans = Vec::new();
    let mut ids = Vec::new();
    for enabled in [false, true] {
        let mut scan = scanner(&txn, &filters.filters[0], enabled);
        let mut out = Vec::new();
        assert!(scan
            .scan(
                &txn,
                &filters.filters[0],
                |id| {
                    out.push(id);
                    true
                },
                |_| false
            )
            .unwrap());
        scans.push(scan);
        ids.push(out);
    }
    assert_eq!(logical_state(&scans[0]), logical_state(&scans[1]));
    drop(txn);
    let mut inserted: Vec<_> = (0..500)
        .map(|who| event(100000 + who, who, BASE + 99, 1, 0))
        .collect();
    let mut txn = fixture.env.begin_rw().unwrap();
    write_events(&mut txn, &mut NoopNegentropy, &mut inserted, false).unwrap();
    txn.commit().unwrap();
    let txn = fixture.env.begin_ro().unwrap();
    for (scan, out) in scans.iter_mut().zip(&mut ids) {
        assert!(scan
            .scan(
                &txn,
                &filters.filters[0],
                |id| {
                    out.push(id);
                    false
                },
                |_| false
            )
            .unwrap());
        assert_eq!(*out, expected);
        assert!(inserted.iter().all(|new| !out.contains(&new.lev_id)));
    }
    assert_eq!(scans[0].approx_work, scans[1].approx_work);
    assert_eq!(ids[0], ids[1]);
}

#[test]
fn exact_second_tuple_keeps_full_width_ids_and_zero_endpoints() {
    for next in [
        Some(AuthorPosition {
            created_at: BASE,
            local_id: u64::MAX - 1,
        }),
        Some(AuthorPosition {
            created_at: BASE,
            local_id: 0,
        }),
        Some(AuthorPosition {
            created_at: 0,
            local_id: 0,
        }),
        None,
    ] {
        let mut range = ScanCursor {
            resume_key: [author(0).as_slice(), &u64::MAX.to_ne_bytes()].concat(),
            resume_val: u64::MAX,
            search: author(0).to_vec(),
            match_mode: MatchMode::Prefix,
            outstanding: 0,
        };
        let candidate = seed(
            &mut range,
            AuthorHead {
                first: AuthorPosition {
                    created_at: BASE,
                    local_id: u64::MAX,
                },
                next,
            },
            0,
        );
        assert_eq!(candidate.lev_id(), u64::MAX);
        assert_eq!(range.outstanding, 1);
        if let Some(next) = next {
            assert!(range.active());
            assert_eq!(range.resume_val, next.local_id);
            assert_eq!(&range.resume_key[32..], &next.created_at.to_ne_bytes());
        } else {
            assert!(!range.active());
        }
    }
}

#[test]
fn full_query_refresh_latest_visibility_and_payload_rules_remain_normal() {
    let fixture = store(dense_events(2048, 3, true));
    let filters = group(&feed(0..2047, 1000));
    let latest = fixture
        .events
        .iter()
        .map(|event| event.lev_id)
        .max()
        .unwrap();
    let options = QueryOptions {
        latest,
        visibility: ReadVisibility {
            restrictor: ReadRestrictor {
                authenticated: vec![7],
                recipient_only: vec![4],
                ..ReadRestrictor::default()
            },
            ..ReadVisibility::default()
        },
        ..QueryOptions::default()
    };
    let expected = expected(&fixture, &filters, &options);
    for (round, use_heads) in [false, true].into_iter().enumerate() {
        let mut query = DbQuery::new(subscription(filters.clone(), latest), 0, 0);
        query.track_completeness();
        query.set_visibility(options.visibility.clone());
        let mut ids = Vec::new();
        let mut slices = 0;
        loop {
            let txn = fixture.env.begin_ro().unwrap();
            if slices == 0 {
                query.scanner = Some(QueryScanner::Chronological(scanner(
                    &txn,
                    &filters.filters[0],
                    use_heads,
                )));
            }
            let complete = query
                .process(
                    &txn,
                    |_, id| {
                        ids.push(id);
                        assert!(wok_db::event_json_owned(
                            &txn,
                            &mut Decompressor::new(),
                            id,
                            1 << 20
                        )
                        .is_ok());
                    },
                    0,
                )
                .unwrap();
            drop(txn);
            slices += 1;
            if slices == 1 {
                assert!(!complete);
                let mut inserted: Vec<_> = (0..64)
                    .map(|n| event(100000 + round as u64 * 1000 + n, n, BASE + 64, 1, 0))
                    .collect();
                let mut txn = fixture.env.begin_rw().unwrap();
                write_events(&mut txn, &mut NoopNegentropy, &mut inserted, false).unwrap();
                txn.commit().unwrap();
                assert!(inserted.iter().all(|event| event.lev_id > latest));
            }
            if complete {
                break;
            }
            assert!(slices < 64);
        }
        assert_eq!(ids, expected);
        assert!(query.completeness().more);
        assert!(query.completeness().restricted);
        assert!(slices > 1);
    }
}

#[test]
fn residuals_high_depth_and_request_caps_use_the_established_owners() {
    let fixture = store(dense_events(512, 4, false));
    for mut value in [feed(0..500, 10000), feed(0..500, 1000), feed(0..500, 50)] {
        value["kinds"] = json!([1, 7]);
        value["#t"] = json!(["red"]);
        let (control, heads) = equal_pair(&fixture, &group(&value), &QueryOptions::default());
        assert_eq!(heads.measurements.wrapper.author_head_keys, 0);
        assert_eq!(heads.chronological_work, control.chronological_work);
    }
    let filters = group(&json!([feed(0..500, 10), feed(0..512, 100)]));
    for max_total in [0, 12] {
        let (control, heads) = equal_pair(
            &fixture,
            &filters,
            &QueryOptions {
                max_total,
                time_budget_us: 0,
                ..QueryOptions::default()
            },
        );
        assert!(heads.completeness.more);
        assert_eq!(heads.peek_work, control.peek_work);
    }
}

#[test]
fn both_gap_shapes_preserve_more_without_global_membership_peek_cost() {
    let mut events: Vec<_> = (0..50)
        .map(|n| event(n + 1, 0, BASE + 20000, 1, 0))
        .collect();
    events.extend((0..700).map(|n| event(1000 + n, 10000 + n % 512, BASE + 19000, 1, 0)));
    events.push(event(2000, 0, BASE + 18000, 1, 0));
    let fixture = store(events);
    for authors in [500, 2047] {
        let (control, heads) = equal_pair(
            &fixture,
            &group(&feed(0..authors, 50)),
            &QueryOptions::default(),
        );
        assert!(heads.completeness.more);
        assert_eq!(heads.peek_work, control.peek_work);
        assert_eq!(heads.peek_candidates, control.peek_candidates);
        evidence(&format!("gap_{authors}_same_more"), &control, &heads);
    }
}

#[test]
fn request_cap_peek_of_unscanned_filters_uses_no_extra_frontier_batch() {
    let mut events: Vec<_> = (0..5).map(|n| event(n + 1, 0, BASE + 100, 1, 0)).collect();
    events.push(event(1000, 1000, BASE + 90, 1, 0));
    let fixture = store(events);
    let filters = group(&json!([feed(0..500, 10), feed(1000..1500, 10)]));
    let (control, heads) = equal_pair(
        &fixture,
        &filters,
        &QueryOptions {
            max_total: 5,
            ..QueryOptions::default()
        },
    );
    assert!(heads.completeness.more);
    assert_eq!(heads.measurements.wrapper.author_head_keys, 500);
    assert_eq!(
        heads.measurements.wrapper.author_head_multiget_calls,
        500_u64.div_ceil(BATCH_KEYS as u64)
    );
    assert_eq!(heads.chronological_work, control.chronological_work);
}

#[test]
fn count_queries_keep_all_request_counts_limits_and_visibility_with_both_readers() {
    let fixture = store(dense_events(1024, 4, true));
    let filters = group(&json!([feed(0..500, 400), feed(256..756, 400)]));
    let latest = fixture
        .events
        .iter()
        .map(|event| event.lev_id)
        .max()
        .unwrap()
        - 50;
    let options = QueryOptions {
        latest,
        visibility: ReadVisibility {
            restrictor: ReadRestrictor {
                authenticated: vec![7],
                recipient_only: vec![4],
                ..ReadRestrictor::default()
            },
            ..ReadVisibility::default()
        },
        ..QueryOptions::default()
    };
    let model = expected(&fixture, &filters, &options);
    assert!(model.len() > 400);
    for dedup_budget in [0, 31] {
        for time_budget_us in [u64::MAX, 0] {
            let mut results = Vec::new();
            let mut work = Vec::new();
            for use_heads in [false, true] {
                let txn = fixture.env.begin_ro().unwrap();
                let mut sub = subscription(filters.clone(), latest);
                sub.count_only = true;
                // COUNT ignores the delivery ceiling, but has its own dedup cap.
                let mut query = DbQuery::new(sub, 5, dedup_budget);
                query.track_completeness();
                query.set_visibility(options.visibility.clone());
                query.diagnostic_author_head_reads = Some(use_heads);
                let mut ids = Vec::new();
                let (completed, measured) = measure(|| {
                    for _ in 0..64 {
                        if query
                            .process(&txn, |_, id| ids.push(id), time_budget_us)
                            .unwrap()
                        {
                            return true;
                        }
                    }
                    false
                })
                .unwrap();
                assert!(completed && !query.dead);
                let wanted = if dedup_budget == 0 {
                    model.as_slice()
                } else {
                    &model[..dedup_budget as usize]
                };
                assert_eq!(ids, wanted);
                assert_eq!(query.sent_count(), ids.len() as u64);
                assert!(query.sent_count() > 5);
                assert_eq!(query.count_dedup_limited(), dedup_budget != 0);
                // Pure author filters have no NIP-45 HLL target. COUNT never
                // spends or advertises a REQ completeness peek, even when asked.
                assert_eq!(query.hll_hex(), None);
                assert_eq!(query.completeness(), Completeness::default());
                assert_eq!(query.peek_budget.work, PEEK_WORK);
                assert_eq!(query.peek_budget.candidates, PEEK_CANDIDATES);
                assert_eq!(
                    measured.wrapper.author_head_keys,
                    if use_heads {
                        if dedup_budget == 0 {
                            1000
                        } else {
                            500
                        }
                    } else {
                        0
                    }
                );
                work.push(query.diagnostic_chronological_work);
                println!(
                    "WOK_AUTHOR_FRONTIER_COUNT_RESULT={}",
                    json!({
                        "count_only":true,"use_heads":use_heads,"time_budget_us":time_budget_us,
                        "dedup_budget":dedup_budget,"completed":completed,"sent_count":query.sent_count(),
                        "limited":query.count_dedup_limited(),"hll":query.hll_hex(),
                        "chronological_work":query.diagnostic_chronological_work,"measurements":measured,
                        "scope":"Deterministic local count parity, two overlapping wide-author filters, all-request reader control. No payload or timing claim."
                    })
                );
                results.push((
                    ids,
                    query.sent_count(),
                    query.count_dedup_limited(),
                    query.hll_hex(),
                    query.completeness(),
                ));
            }
            assert_eq!(results[0], results[1]);
            if time_budget_us == u64::MAX {
                assert_eq!(work[0], work[1]);
            }
        }
    }
}

#[test]
fn failed_payload_keeps_both_completed_reader_samples_conservative_and_strict_ineligible() {
    let fixture = store((0..500).map(|n| event(n + 1, n, BASE + n, 1, 0)).collect());
    let filters = group(&feed(0..500, 500));
    let bad_id = expected(&fixture, &filters, &QueryOptions::default())[0];
    let mut txn = fixture.env.begin_rw().unwrap();
    txn.put_u64(fixture.env.dbis().event_payload, bad_id, &[0xFF], 0)
        .unwrap();
    txn.commit().unwrap();
    let control = read_arm(
        &fixture.env,
        &filters,
        Arm::Pubkey,
        &QueryOptions::default(),
    )
    .unwrap();
    let heads = read_arm(
        &fixture.env,
        &filters,
        Arm::AuthorHeads,
        &QueryOptions::default(),
    )
    .unwrap();
    assert!(control.completed && heads.completed);
    assert_eq!(control.delivery, heads.delivery);
    assert_eq!(control.delivery.ids.len(), 500);
    assert!(control.delivery.payload_failed && heads.delivery.payload_failed);
    assert_eq!(control.completeness, heads.completeness);
    assert!(!heads.completeness.finish && !heads.completeness.more);
    assert_eq!(heads.measurements.wrapper.author_head_keys, 500);
    let strict_pair_eligible = control.completed
        && heads.completed
        && control.delivery == heads.delivery
        && control.completeness == heads.completeness
        && !control.delivery.payload_failed
        && !heads.delivery.payload_failed;
    assert!(!strict_pair_eligible);
    evidence("failed_payload_strict_ineligible", &control, &heads);
}
