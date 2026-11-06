//! Test-only bounded chronological prefix with an ordinary author suffix.
//!
//! This is not a production planner. Every inspected raw entry counts toward
//! the shared 256-entry cap; membership reads and pauses are charged. A suffix
//! starts strictly below the last fully handled raw row, never a lookahead.
//! Both peek policies deliberately retain the ordinary budgets: a truthful
//! Unknown can differ from the control and is a strict comparison failure.

use super::feed_query_diagnostic::*;
use super::*;
use crate::visibility::ReadRestrictor;
use crate::NostrFilterGroup;
use serde_json::{json, Value};
use wok_db::read_diagnostics::measure;
use wok_db::{write_events, Env, EnvOptions, NoopNegentropy};

const RAW_CAP: u64 = 256;
const PACKED_TIME_MAX: u64 = 0xFF_FFFFFFFF;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PeekPolicy {
    GlobalUntilCap,
    AuthorOnPeek,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Fence {
    time: u64,
    id: u64,
}

impl Fence {
    fn before(self) -> Option<Self> {
        self.id
            .checked_sub(1)
            .map(|id| Self {
                time: self.time,
                id,
            })
            .or_else(|| {
                self.time
                    .checked_sub(1)
                    .map(|time| Self { time, id: u64::MAX })
            })
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Prefix {
    policy: PeekPolicy,
    until: u64,
    consumed: Option<Fence>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Stats {
    pub(super) configured: bool,
    unsupported_window: bool,
    raw_visits: u64,
    handled_rows: u64,
    primary_reads: u64,
    matched_rows: u64,
    pauses: u64,
    prefix_work: u64,
    author_suffix: bool,
    suffix_start_work: u64,
    suffix_fence: Option<Fence>,
    exhausted: bool,
}

impl Stats {
    fn json(self) -> Value {
        json!({
            "configured":self.configured,"unsupported_window":self.unsupported_window,
            "raw_cap":RAW_CAP,"raw_visits":self.raw_visits,"handled_rows":self.handled_rows,
            "primary_read_calls":self.primary_reads,"matched_rows":self.matched_rows,
            "pauses":self.pauses,"prefix_work":self.prefix_work,"author_suffix":self.author_suffix,
            "suffix_start_work":self.suffix_start_work,
            "suffix_fence":self.suffix_fence.map(|f|json!({"created_at":f.time,"local_id":f.id})),
            "exhausted":self.exhausted
        })
    }
}

pub(super) fn configure(filter: &NostrFilter, txn: &RoTxn<'_>, policy: PeekPolicy) -> DbScan {
    // Keep the inherited 40-bit heap representation untouched. Unsupported
    // windows take the unchanged plan, including absent/MAX until, without a
    // preliminary DB read. This restriction is not a new filter validation rule.
    if filter.until > PACKED_TIME_MAX
        || filter.authors.is_none()
        || filter.ids.is_some()
        || filter.search.is_some()
        || filter.never_match
        || filter.limit == 0
    {
        let mut scan = DbScan::new(filter, txn);
        scan.diagnostic_feed_stats = Stats {
            configured: true,
            unsupported_window: filter.until > PACKED_TIME_MAX,
            ..Stats::default()
        };
        return scan;
    }
    // A forced author suffix also lets the local tests exercise residuals.
    // It does not alter the established constructor or production plan choice.
    let mut seed = filter.clone();
    seed.kinds = None;
    seed.tags.clear();
    seed.and_tags.clear();
    let mut scan = DbScan::new(&seed, txn);
    // The normal authors+kinds plan can be index-only because PubkeyKind
    // guarantees the kind. This suffix uses Pubkey, so the original selectors
    // must remain residuals even when the original parser marked that plan
    // index-only. Required/OR tags likewise were removed only from the seed.
    scan.index_only = filter.index_only_scans
        && filter.kinds.is_none()
        && filter.tags.is_empty()
        && filter.and_tags.is_empty();
    assert_eq!(scan.desc, "Pubkey");
    scan.diagnostic_feed_stats.configured = true;
    scan.diagnostic_feed_prefix = Some(Prefix {
        policy,
        until: filter.until,
        consumed: None,
    });
    scan
}

fn suffix(scan: &mut DbScan, consumed: Option<Fence>) {
    assert_eq!(scan.next_init_index, 0);
    assert!(scan.event_queue.is_empty());
    assert!(scan.unsettled.is_none());
    scan.diagnostic_feed_stats.author_suffix = true;
    scan.diagnostic_feed_stats.suffix_start_work = scan.approx_work;
    scan.diagnostic_feed_stats.suffix_fence = consumed;
    if let Some(consumed) = consumed {
        match consumed.before() {
            Some(bound) => {
                for cursor in &mut scan.cursors {
                    let time_at = cursor.resume_key.len() - 8;
                    cursor.resume_key[time_at..].copy_from_slice(&bound.time.to_ne_bytes());
                    cursor.resume_val = bound.id;
                }
            }
            None => {
                scan.cursors.clear();
                scan.refill_scan_depths.clear();
                scan.diagnostic_feed_stats.exhausted = true;
            }
        }
    }
}

/// Some(result) stops this scan call; None continues the unchanged author scan.
pub(super) fn advance<H, P>(
    scan: &mut DbScan,
    txn: &RoTxn<'_>,
    filter: &NostrFilter,
    depth_cap: u64,
    handle: &mut H,
    pause: &mut P,
) -> Result<Option<bool>, wok_db::DbError>
where
    H: FnMut(u64) -> bool,
    P: FnMut(u64) -> bool,
{
    let mut prefix = scan.diagnostic_feed_prefix.take().expect("active prefix");
    // depth_cap=1 is exclusively DbQuery's peek in the normal full-query path.
    // A production interface should use an explicit demand, not overload this.
    if scan.diagnostic_feed_stats.raw_visits == RAW_CAP
        || (depth_cap == 1 && prefix.policy == PeekPolicy::AuthorOnPeek)
    {
        suffix(scan, prefix.consumed);
        return Ok(None);
    }
    let bound = match prefix.consumed {
        Some(fence) => match fence.before() {
            Some(bound) => bound,
            None => {
                scan.diagnostic_feed_stats.exhausted = true;
                scan.cursors.clear();
                scan.refill_scan_depths.clear();
                return Ok(Some(true));
            }
        },
        None => Fence {
            time: prefix.until,
            id: u64::MAX,
        },
    };
    let mut physical = txn.cursor(txn.env().dbis().event_created_at)?;
    let work_before = scan.approx_work;
    let (mut stopped, mut paused, mut exhausted) = (false, false, false);
    let mut error = None;
    let walk = physical.foreach_index(&bound.time.to_ne_bytes(), bound.id, |entry| {
        // The entry was actually visited by the native iterator, even if its
        // processing pauses now. Charge it and do not advance its consumed fence.
        scan.diagnostic_feed_stats.raw_visits += 1;
        scan.approx_work += 2; // one visit and one attempt, including short rows
        if pause(scan.approx_work) {
            scan.diagnostic_feed_stats.pauses += 1;
            paused = true;
            return false;
        }
        let Some(created) = entry.created_at else {
            // As in the ordinary scanner, skip a returned short key without
            // interpreting its duplicate. It still spends a visit/work; with
            // no proven tuple it cannot move the consumed fence. Re-visits on
            // a pause count again and the shared cap still bounds this prefix.
            return scan.diagnostic_feed_stats.raw_visits < RAW_CAP;
        };
        if created < filter.since {
            exhausted = true;
            return false;
        }
        if created > filter.until || created > PACKED_TIME_MAX {
            error = Some(wok_db::DbError::msg(
                "unsupported bounded prefix time boundary",
            ));
            return false;
        }
        let id = match entry.local_id() {
            Ok(id) => id,
            Err(e) => {
                error = Some(e);
                return false;
            }
        };
        scan.approx_work += 10;
        scan.diagnostic_feed_stats.primary_reads += 1;
        // Global membership inspects nonmembers too, so malformed-primary
        // detection need not match an author-only plan's incidental reads.
        // Every malformed row actually returned/consumed here remains an
        // error; full corruption auditing is separate from valid-row parity.
        let matches = match txn.get_u64(txn.env().dbis().event, id) {
            Ok(Some(bytes)) => match PackedEventView::new(bytes) {
                Ok(view) => filter.does_match(view),
                Err(_) => {
                    error = Some(wok_db::DbError::msg("malformed bounded prefix metadata"));
                    return false;
                }
            },
            Ok(None) => false,
            Err(e) => {
                error = Some(e);
                return false;
            }
        };
        scan.diagnostic_feed_stats.handled_rows += 1;
        if matches {
            scan.diagnostic_feed_stats.matched_rows += 1;
            // DbQuery owns the meaning of true: limit, visibility error,
            // dedup cap or peek stop. Calling the handler consumes this row.
            stopped = handle(id);
        }
        prefix.consumed = Some(Fence { time: created, id });
        !stopped && scan.diagnostic_feed_stats.raw_visits < RAW_CAP
    });
    scan.diagnostic_feed_stats.prefix_work += scan.approx_work - work_before;
    drop(physical); // no native iterator can cross the suffix or a snapshot
    let naturally_finished = walk?;
    if let Some(error) = error {
        return Err(error);
    }
    if exhausted || naturally_finished {
        scan.diagnostic_feed_stats.exhausted = true;
        scan.cursors.clear();
        scan.refill_scan_depths.clear();
        return Ok(Some(true));
    }
    if paused || stopped {
        scan.diagnostic_feed_prefix = Some(prefix);
        return Ok(Some(!paused));
    }
    assert_eq!(scan.diagnostic_feed_stats.raw_visits, RAW_CAP);
    suffix(scan, prefix.consumed);
    Ok(None)
}

const BASE: u64 = 1_700_000_000;

fn bounded_pair(
    fixture: &Fixture,
    filters: &NostrFilterGroup,
    options: &QueryOptions,
    arm: Arm,
) -> (Sample, Sample) {
    let control = read_arm(&fixture.env, filters, Arm::Pubkey, options).unwrap();
    let candidate = read_arm(&fixture.env, filters, arm, options).unwrap();
    assert!(control.completed && candidate.completed);
    assert!(!control.delivery.payload_failed && !candidate.delivery.payload_failed);
    assert_eq!(control.delivery, candidate.delivery);
    assert_eq!(candidate.delivery.ids, expected(fixture, filters, options));
    (control, candidate)
}

fn strict_equal(control: &Sample, candidate: &Sample) -> bool {
    control.completed
        && candidate.completed
        && control.delivery == candidate.delivery
        && control.completeness == candidate.completeness
        && !control.delivery.payload_failed
        && !candidate.delivery.payload_failed
}

/// Small local records deliberately omit per-range arrays and event bodies.
/// A successful regression for an expected hint loss is still strict-ineligible.
fn evidence(label: &str, policy: &str, control: &Sample, candidate: &Sample) {
    let summarize = |sample: &Sample| {
        json!({
            "completed":sample.completed,"sent_count":sample.delivery.sent_count,
            "body_sha256":sample.delivery.body_sha256,"body_bytes":sample.delivery.body_bytes,
            "packed_sha256":sample.delivery.packed_sha256,"packed_bytes":sample.delivery.packed_bytes,
            "payload_sha256":sample.delivery.payload_sha256,"payload_bytes":sample.delivery.payload_bytes,
            "payload_failed":sample.delivery.payload_failed,
            "completeness":{"finish":sample.completeness.finish,"more":sample.completeness.more,"restricted":sample.completeness.restricted},
            "chronological_work":sample.chronological_work,"peek_work":sample.peek_work,
            "peek_candidates":sample.peek_candidates,"slice_work":sample.slice_work,
            "plan":{"desc":sample.plan.desc,"cursors":sample.plan.cursors,"index_only":sample.plan.index_only},
            "measurements":sample.measurements,"bounded":sample.bounded.map(Stats::json)
        })
    };
    let report = json!({
        "format":"wok-bounded-feed-local-evidence-v1","label":label,"peek_policy":policy,
        "delivery_equal":control.delivery==candidate.delivery,
        "completeness_equal":control.completeness==candidate.completeness,
        "strict_pair_eligible":strict_equal(control,candidate),
        "control":summarize(control),"candidate":summarize(candidate),
        "scope":"Test-only streaming prefix, capped256 actual iterator visits, then ordinary Pubkey suffix below the last fully handled chronological row. Fresh transaction per full-query arm. Named counters and work are instrumented, not clean timing, physical I/O or production-planner evidence. Expected hint differences remain strict-ineligible.",
        "bounded_source_sha256":super::range_seed_diagnostic::digest(include_bytes!("bounded_feed_diagnostic.rs")),
        "query_source_sha256":super::range_seed_diagnostic::digest(include_bytes!("scan.rs"))
    });
    println!("WOK_BOUNDED_FEED_LOCAL_RESULT={report}");
}

#[test]
fn exclusive_fence_uses_all_local_id_bits_and_checked_timestamp_predecessor() {
    for (fence, before) in [
        (
            Fence {
                time: 7,
                id: u64::MAX,
            },
            Some(Fence {
                time: 7,
                id: u64::MAX - 1,
            }),
        ),
        (Fence { time: 7, id: 1 }, Some(Fence { time: 7, id: 0 })),
        (
            Fence { time: 7, id: 0 },
            Some(Fence {
                time: 6,
                id: u64::MAX,
            }),
        ),
        (
            Fence {
                time: u64::MAX,
                id: 0,
            },
            Some(Fence {
                time: u64::MAX - 1,
                id: u64::MAX,
            }),
        ),
        (Fence { time: 0, id: 0 }, None),
    ] {
        assert_eq!(fence.before(), before);
    }
}

#[test]
fn configuring_supported_and_unsupported_windows_opens_no_iterator_or_primary() {
    let fixture = store(vec![event(1, 0, BASE, 1, 0)]);
    let txn = fixture.env.begin_ro().unwrap();
    for authors in [500, 2047] {
        for until in [0, BASE, PACKED_TIME_MAX, PACKED_TIME_MAX + 1, u64::MAX] {
            let mut value = feed(0..authors, 50);
            value["until"] = json!(until);
            let filters = group(&value);
            let (scan, measurements) =
                measure(|| configure(&filters.filters[0], &txn, PeekPolicy::GlobalUntilCap))
                    .unwrap();
            assert_eq!(measurements.wrapper, Default::default());
            assert_eq!(scan.approx_work, 0);
            assert_eq!(scan.next_init_index, 0);
            assert!(scan.event_queue.is_empty());
            assert_eq!(
                scan.diagnostic_feed_stats.unsupported_window,
                until > PACKED_TIME_MAX
            );
            assert_eq!(
                scan.diagnostic_feed_prefix.is_some(),
                until <= PACKED_TIME_MAX
            );
        }
    }
    let mut absent_until = feed(0..500, 50);
    absent_until.as_object_mut().unwrap().remove("until");
    let filters = group(&absent_until);
    let (scan, measurements) =
        measure(|| configure(&filters.filters[0], &txn, PeekPolicy::AuthorOnPeek)).unwrap();
    assert_eq!(measurements.wrapper, Default::default());
    assert!(scan.diagnostic_feed_stats.unsupported_window);
    assert!(scan.diagnostic_feed_prefix.is_none());
}

fn raw_order(fixture: &Fixture) -> Vec<Fence> {
    let mut rows: Vec<_> = fixture
        .events
        .iter()
        .map(|event| Fence {
            time: PackedEventView::new(&event.packed).unwrap().created_at(),
            id: event.lev_id,
        })
        .collect();
    rows.sort_unstable_by(|a, b| b.time.cmp(&a.time).then_with(|| b.id.cmp(&a.id)));
    rows
}

#[test]
fn streaming_cap_visits_exactly_256_rows_without_lookahead_or_resume_copies() {
    let fixture = store(
        (0..320)
            .map(|n| event(n + 1, 5000 + n, BASE + n, 1, 0))
            .collect(),
    );
    let filters = group(&feed(0..500, 50));
    let txn = fixture.env.begin_ro().unwrap();
    let mut scan = configure(&filters.filters[0], &txn, PeekPolicy::GlobalUntilCap);
    let (result, measurements) = measure(|| {
        advance(
            &mut scan,
            &txn,
            &filters.filters[0],
            u64::MAX,
            &mut |_| false,
            &mut |_| false,
        )
    })
    .unwrap();
    assert_eq!(result.unwrap(), None); // ready for the ordinary suffix, not run yet
    let stats = scan.diagnostic_feed_stats;
    assert_eq!(stats.raw_visits, RAW_CAP);
    assert_eq!(stats.handled_rows, RAW_CAP);
    assert_eq!(stats.primary_reads, RAW_CAP);
    assert_eq!(stats.prefix_work, 12 * RAW_CAP);
    assert_eq!(scan.approx_work, stats.prefix_work);
    assert!(stats.author_suffix);
    assert_eq!(stats.suffix_fence, Some(raw_order(&fixture)[255]));
    let bound = stats.suffix_fence.unwrap().before().unwrap();
    for cursor in &scan.cursors {
        assert_eq!(
            u64::from_ne_bytes(cursor.resume_key[32..].try_into().unwrap()),
            bound.time
        );
        assert_eq!(cursor.resume_val, bound.id);
    }
    let c = measurements.wrapper;
    assert_eq!(c.iterator_creations, 1);
    assert_eq!(c.seek, 1);
    assert_eq!(c.next, 255);
    assert_eq!(c.typed_index_entries, 256);
    assert_eq!(c.primary_pin_lookups, 256);
    assert_eq!(c.resume_key_copies, 0);
    assert_eq!(c.generic_row_materializations, 0);
    assert_eq!(c.cover_records_copied, 0);
    println!(
        "WOK_BOUNDED_PREFIX_CAP_RESULT={}",
        json!({"stats":stats.json(),"measurements":measurements})
    );
}

#[test]
fn pause_on_cap_does_not_consume_the_paused_row_or_reopen_the_global_cursor() {
    let fixture = store((0..320).map(|n| event(n + 1, 0, BASE, 1, 0)).collect());
    let rows = raw_order(&fixture);
    let filters = group(&feed(0..500, 10000));
    let txn = fixture.env.begin_ro().unwrap();
    let mut scan = configure(&filters.filters[0], &txn, PeekPolicy::GlobalUntilCap);
    let mut handled = Vec::new();
    let result = advance(
        &mut scan,
        &txn,
        &filters.filters[0],
        u64::MAX,
        &mut |id| {
            handled.push(id);
            false
        },
        &mut |work| work == 3062,
    )
    .unwrap();
    assert_eq!(result, Some(false));
    assert_eq!(scan.diagnostic_feed_stats.raw_visits, 256);
    assert_eq!(scan.diagnostic_feed_stats.handled_rows, 255);
    assert_eq!(
        scan.diagnostic_feed_prefix.unwrap().consumed,
        Some(rows[254])
    );
    assert_eq!(
        handled,
        rows[..255].iter().map(|f| f.id).collect::<Vec<_>>()
    );
    drop(txn);
    let txn = fixture.env.begin_ro().unwrap();
    let mut suffix_first = None;
    let (complete, measurements) = measure(|| {
        scan.scan(
            &txn,
            &filters.filters[0],
            |id| {
                suffix_first = Some(id);
                true
            },
            |_| false,
        )
    })
    .unwrap();
    assert!(complete.unwrap());
    assert_eq!(suffix_first, Some(rows[255].id));
    assert_eq!(scan.diagnostic_feed_stats.suffix_fence, Some(rows[254]));
    assert_eq!(scan.diagnostic_feed_stats.raw_visits, 256);
    // One ordinary physical reader, no restarted global reader after the cap.
    assert_eq!(measurements.wrapper.iterator_creations, 1);
    assert!(scan.approx_work > 3062);
}

#[test]
fn dense_full_queries_keep_order_bodies_and_hints_with_streaming_work() {
    let fixture = store(dense_events(2048, 3, false));
    let options = QueryOptions {
        time_budget_us: 0,
        ..QueryOptions::default()
    };
    for authors in [500, 2047] {
        let filters = group(&feed(0..authors, 50));
        let (control, candidate) =
            bounded_pair(&fixture, &filters, &options, Arm::BoundedGlobalPeek);
        assert!(strict_equal(&control, &candidate));
        let stats = candidate.bounded.unwrap();
        assert!(stats.raw_visits <= 256);
        assert!(stats.handled_rows <= stats.raw_visits);
        assert_eq!(
            candidate.measurements.wrapper.generic_row_materializations,
            0
        );
        if !stats.author_suffix {
            assert_eq!(
                candidate.measurements.wrapper.typed_index_entries,
                stats.raw_visits
            );
            assert!(candidate.measurements.wrapper.seek < control.measurements.wrapper.seek);
        }
        evidence(
            if authors == 500 {
                "dense500_of2048"
            } else {
                "dense2047_of2048"
            },
            "global_until_cap",
            &control,
            &candidate,
        );
    }
    let (control, candidate) = bounded_pair(
        &fixture,
        &group(&feed(0..500, 50)),
        &options,
        Arm::BoundedAuthorPeek,
    );
    assert!(strict_equal(&control, &candidate));
    assert!(candidate.bounded.unwrap().author_suffix);
    evidence(
        "dense500_rebuild_on_peek",
        "author_on_peek",
        &control,
        &candidate,
    );
}

#[test]
fn inclusive_time_cuts_empty_windows_and_max_guard_keep_existing_query_results() {
    let fixture = store(dense_events(512, 3, false));
    for (since, until) in [
        (0, 0),
        (BASE + 62, BASE + 62),
        (BASE + 100, BASE + 20),
        (0, PACKED_TIME_MAX + 1),
        (0, u64::MAX),
    ] {
        let mut value = feed(0..500, 50);
        value["since"] = json!(since);
        value["until"] = json!(until);
        let filters = group(&value);
        let (control, candidate) = bounded_pair(
            &fixture,
            &filters,
            &QueryOptions::default(),
            Arm::BoundedGlobalPeek,
        );
        assert!(strict_equal(&control, &candidate));
        if until > PACKED_TIME_MAX {
            let stats = candidate.bounded.unwrap();
            assert!(stats.unsupported_window);
            assert_eq!(stats.raw_visits, 0);
            assert_eq!(candidate.measurements.wrapper, control.measurements.wrapper);
        }
    }
    let empty = store(Vec::new());
    let (control, candidate) = bounded_pair(
        &empty,
        &group(&feed(0..2047, 50)),
        &QueryOptions::default(),
        Arm::BoundedGlobalPeek,
    );
    assert!(strict_equal(&control, &candidate));
    assert!(candidate.completeness.finish);
    assert_eq!(candidate.bounded.unwrap().raw_visits, 0);
    assert!(candidate.bounded.unwrap().exhausted);
}

#[test]
fn absent_sparse_and_adverse_prefixes_fallback_with_bounded_charged_overhead() {
    let mut events: Vec<_> = (0..600)
        .map(|n| event(n + 1, 1000 + n % 512, BASE + 19000, 1, 0))
        .collect();
    events.extend((0..20).map(|n| event(10000 + n, n, BASE + 18000, 1, 0)));
    let fixture = store(events);
    let options = QueryOptions {
        time_budget_us: 0,
        ..QueryOptions::default()
    };
    for (start, label) in [(0, "sparse500_fallback"), (3000, "absent500_fallback")] {
        for (arm, policy) in [
            (Arm::BoundedGlobalPeek, "global_until_cap"),
            (Arm::BoundedAuthorPeek, "author_on_peek"),
        ] {
            let (control, candidate) = bounded_pair(
                &fixture,
                &group(&feed(start..start + 500, 50)),
                &options,
                arm,
            );
            assert!(strict_equal(&control, &candidate));
            let stats = candidate.bounded.unwrap();
            assert_eq!(stats.raw_visits, 256);
            assert!(stats.author_suffix);
            assert!(stats.primary_reads <= 256);
            assert!(stats.prefix_work <= 12 * RAW_CAP);
            assert_eq!(stats.prefix_work, stats.suffix_start_work);
            assert!(candidate.chronological_work >= stats.prefix_work);
            assert!(candidate.slice_work.len() > 1);
            evidence(label, policy, &control, &candidate);
        }
    }
}

/// These fixtures need exact local IDs, including zero/MAX. They write only
/// canonical primary/payload and the two queried indexes, outside measurement;
/// they are not complete writer-generated databases for an integrity audit.
fn exact_id_fixture(rows: &[(u64, u64, u64)]) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let mut events = Vec::new();
    let mut txn = env.begin_rw().unwrap();
    for (n, &(id, created, who)) in rows.iter().enumerate() {
        let mut event = event(n as u64 + 1, who, created, 1, 0);
        event.lev_id = id;
        txn.put_u64(env.dbis().event, id, &event.packed, 0).unwrap();
        txn.put_u64(
            env.dbis().event_payload,
            id,
            &wok_db::encode_raw_payload(&event.json),
            0,
        )
        .unwrap();
        txn.put_u64(env.dbis().event_created_at, created, &id.to_ne_bytes(), 0)
            .unwrap();
        let mut key = author(who).to_vec();
        key.extend_from_slice(&created.to_ne_bytes());
        txn.put(env.dbis().event_pubkey, &key, &id.to_ne_bytes(), 0)
            .unwrap();
        events.push(event);
    }
    txn.commit().unwrap();
    Fixture { dir, env, events }
}

#[test]
fn suffix_fences_preserve_full_u64_ties_zero_ids_and_timestamp_borrow() {
    let mut high_ids: Vec<_> = (0..300).map(|n| (u64::MAX - n, BASE, n % 2)).collect();
    high_ids.extend([(1, BASE, 0), (0, BASE, 1), (2, BASE - 1, 0), (3, 0, 1)]);
    let mut borrow: Vec<_> = (1..=255).map(|id| (id, BASE + 1, id % 2)).collect();
    borrow.extend([(0, BASE, 0), (u64::MAX, BASE - 1, 1)]);
    let mut bottom: Vec<_> = (1..=255).map(|id| (id, 1, id % 2)).collect();
    bottom.push((0, 0, 0));
    for (rows, expected_fence) in [
        (
            high_ids,
            Fence {
                time: BASE,
                id: u64::MAX - 255,
            },
        ),
        (borrow, Fence { time: BASE, id: 0 }),
        (bottom, Fence { time: 0, id: 0 }),
    ] {
        let fixture = exact_id_fixture(&rows);
        let (control, candidate) = bounded_pair(
            &fixture,
            &group(&feed(0..500, 10000)),
            &QueryOptions::default(),
            Arm::BoundedGlobalPeek,
        );
        assert!(strict_equal(&control, &candidate));
        let stats = candidate.bounded.unwrap();
        assert_eq!(stats.raw_visits, 256);
        assert_eq!(stats.suffix_fence, Some(expected_fence));
        assert!(stats.author_suffix);
        assert_eq!(candidate.delivery.ids.len(), rows.len());
        assert_eq!(
            candidate.delivery.ids.len(),
            candidate.delivery.ids.iter().collect::<HashSet<_>>().len()
        );
        // Check the raw scanner too: DbQuery's sent-ID set must not hide a
        // fallback that rereads its proven chronological prefix.
        let txn = fixture.env.begin_ro().unwrap();
        let filters = group(&feed(0..500, 10000));
        let mut scan = configure(&filters.filters[0], &txn, PeekPolicy::GlobalUntilCap);
        let mut scanned = Vec::new();
        assert!(scan
            .scan(
                &txn,
                &filters.filters[0],
                |id| {
                    scanned.push(id);
                    false
                },
                |_| false,
            )
            .unwrap());
        assert_eq!(
            scanned,
            raw_order(&fixture)
                .iter()
                .map(|row| row.id)
                .collect::<Vec<_>>()
        );
        if expected_fence == (Fence { time: 0, id: 0 }) {
            assert!(stats.exhausted);
            assert_eq!(candidate.measurements.wrapper.seek, 1);
        }
    }
}

#[test]
fn kinds_and_tags_remain_residual_after_the_cap_even_if_normal_plan_is_index_only() {
    let mut events: Vec<_> = (0..256)
        .map(|n| event(n + 1, 1000 + n, BASE + 19000, 1, 0))
        .collect();
    events.extend((0..200).map(|n| event(1000 + n, n % 500, BASE + 18000, 7, 0)));
    events.extend((0..20).map(|n| event(2000 + n, n % 500, BASE + 17000, 1, 0)));
    let fixture = store(events);
    for selector in ["kinds", "or_tag", "and_tag"] {
        let mut value = feed(0..500, 10000);
        match selector {
            "kinds" => value["kinds"] = json!([1]),
            "or_tag" => {
                value["kinds"] = json!([1]);
                value["#t"] = json!(["red"]);
            }
            "and_tag" => {
                value["kinds"] = json!([1]);
                value["&t"] = json!(["red"]);
            }
            _ => unreachable!(),
        }
        let filters = group(&value);
        if selector == "kinds" {
            assert!(filters.filters[0].index_only_scans);
        }
        let (control, candidate) = bounded_pair(
            &fixture,
            &filters,
            &QueryOptions::default(),
            Arm::BoundedGlobalPeek,
        );
        assert!(strict_equal(&control, &candidate));
        assert!(!candidate.plan.index_only);
        assert!(candidate.bounded.unwrap().author_suffix);
        assert_eq!(
            candidate.bounded.unwrap().suffix_fence.unwrap().time,
            BASE + 19000
        );
        let txn = fixture.env.begin_ro().unwrap();
        assert!(candidate.delivery.ids.iter().all(|id| PackedEventView::new(
            txn.get_u64(fixture.env.dbis().event, *id).unwrap().unwrap()
        )
        .unwrap()
        .kind()
            == 1));
        assert_eq!(
            candidate.delivery.ids.len(),
            if selector == "kinds" { 20 } else { 10 }
        );
        evidence(selector, "global_until_cap", &control, &candidate);
    }
}

#[test]
fn normal_visibility_latest_residuals_and_dictionary_payloads_survive_suffix_switch() {
    let fixture = store(dense_events(512, 5, true));
    let chosen = fixture
        .events
        .iter()
        .find(|event| {
            let view = PackedEventView::new(&event.packed).unwrap();
            view.pubkey() == author(0) && view.kind() == 1 && view.expiration() == 0
        })
        .unwrap();
    let dictionary = b"feed content body red blue".repeat(64);
    let mut txn = fixture.env.begin_rw().unwrap();
    let dict_id =
        u32::try_from(wok_db::insert_compression_dictionary(&mut txn, &dictionary).unwrap())
            .unwrap();
    let compressed = zstd::bulk::Compressor::with_dictionary(3, &dictionary)
        .unwrap()
        .compress(chosen.json.as_bytes())
        .unwrap();
    txn.put_u64(
        fixture.env.dbis().event_payload,
        chosen.lev_id,
        &wok_db::encode_zstd_payload(dict_id, &compressed),
        0,
    )
    .unwrap();
    txn.commit().unwrap();
    for identities in [vec![], vec![author(9)]] {
        let options = QueryOptions {
            visibility: ReadVisibility {
                restrictor: ReadRestrictor {
                    recipient_only: vec![4],
                    authenticated: vec![7],
                    ..ReadRestrictor::default()
                },
                identities,
                ..ReadVisibility::default()
            },
            latest: fixture.events.iter().map(|e| e.lev_id).max().unwrap() - 100,
            time_budget_us: 0,
            ..QueryOptions::default()
        };
        for residual in [false, true] {
            let mut value = feed(0..500, 10000);
            if residual {
                value["kinds"] = json!([1, 4, 7]);
                value["#t"] = json!(["red"]);
            }
            let (control, candidate) =
                bounded_pair(&fixture, &group(&value), &options, Arm::BoundedGlobalPeek);
            assert!(strict_equal(&control, &candidate));
            assert_eq!(
                candidate.completeness.restricted,
                options.visibility.identities.is_empty()
            );
            assert!(candidate.bounded.unwrap().author_suffix);
        }
    }
    let (control, candidate) = bounded_pair(
        &fixture,
        &group(&feed(0..500, 10000)),
        &QueryOptions::default(),
        Arm::BoundedGlobalPeek,
    );
    assert!(strict_equal(&control, &candidate));
    assert!(candidate.delivery.ids.contains(&chosen.lev_id));
}

#[test]
fn partial_filter_dedup_and_request_cap_keep_normal_completeness_owner() {
    let fixture = store(dense_events(512, 4, false));
    let filters = group(&json!([feed(0..500, 10), feed(0..512, 100)]));
    for max_total in [0, 12] {
        let options = QueryOptions {
            max_total,
            time_budget_us: 0,
            ..QueryOptions::default()
        };
        let (control, candidate) =
            bounded_pair(&fixture, &filters, &options, Arm::BoundedGlobalPeek);
        assert!(strict_equal(&control, &candidate));
        assert!(candidate.completeness.more);
        assert!(candidate.slice_work.len() > 1);
        assert_eq!(
            candidate.delivery.ids.len(),
            candidate.delivery.ids.iter().collect::<HashSet<_>>().len()
        );
    }
}

#[test]
fn full_query_yields_before_unhandled_row_and_resumes_across_refreshed_snapshots() {
    let fixture = store(dense_events(512, 6, false));
    let filters = group(&feed(0..500, 10000));
    let latest = fixture.events.iter().map(|e| e.lev_id).max().unwrap();
    let expected = expected(
        &fixture,
        &filters,
        &QueryOptions {
            latest,
            ..QueryOptions::default()
        },
    );
    for (round, policy) in [PeekPolicy::GlobalUntilCap, PeekPolicy::AuthorOnPeek]
        .into_iter()
        .enumerate()
    {
        let mut query = DbQuery::new(subscription(filters.clone(), latest), 0, 0);
        query.track_completeness();
        let mut ids = Vec::new();
        let mut prior_work = 0;
        let mut slices = 0;
        loop {
            let txn = fixture.env.begin_ro().unwrap();
            if slices == 0 {
                query.scanner = Some(QueryScanner::Chronological(configure(
                    &filters.filters[0],
                    &txn,
                    policy,
                )));
            }
            let complete = query.process(&txn, |_, id| ids.push(id), 0).unwrap();
            assert!(query.diagnostic_chronological_work > prior_work);
            prior_work = query.diagnostic_chronological_work;
            slices += 1;
            if slices == 1 {
                assert!(!complete);
                let stats = query.diagnostic_feed_stats.unwrap();
                assert!(stats.pauses > 0 && stats.raw_visits < RAW_CAP);
                assert_eq!(stats.raw_visits, stats.handled_rows + 1);
                // Normal DbQuery checks after >2000 weighted work; the prefix
                // reaches its pause before paying this row's membership read.
                assert!((2001..=2012).contains(&prior_work));
                let mut other = DbQuery::new(subscription(group(&feed(1..2, 1)), latest), 0, 0);
                let mut short_ids = Vec::new();
                assert!(other.process(&txn, |_, id| short_ids.push(id), 0).unwrap());
                assert_eq!(short_ids.len(), 1);
                // The paused feed remains owned and unfinished while another
                // normal query gets a turn; no borrowed cursor/transaction.
                assert!(query.scanner.is_some());
            }
            drop(txn);
            if slices == 1 {
                let mut inserted: Vec<_> = (0..64)
                    .map(|n| event(100000 + round as u64 * 1000 + n, n, BASE + 64, 1, 0))
                    .collect();
                let mut txn = fixture.env.begin_rw().unwrap();
                write_events(&mut txn, &mut NoopNegentropy, &mut inserted, false).unwrap();
                txn.commit().unwrap();
                assert!(inserted.iter().all(|e| e.lev_id > latest));
            }
            if complete {
                break;
            }
            assert!(slices < 64);
        }
        assert_eq!(ids, expected);
        let stats = query.diagnostic_feed_stats.unwrap();
        assert_eq!(stats.raw_visits, RAW_CAP);
        assert!(stats.author_suffix);
        assert!(query.completeness().finish);
        assert!(slices > 2);
        println!(
            "WOK_BOUNDED_REFRESH_RESULT={}",
            json!({"policy":format!("{policy:?}"),"slices":slices,"chronological_work":prior_work,"stats":stats.json(),"sent_count":ids.len(),"snapshot_refresh_between_slices":true})
        );
    }
}

#[test]
fn zero_budget_peek_performs_no_work_or_transition_for_either_policy() {
    let fixture = store(dense_events(512, 2, false));
    let filters = group(&feed(0..500, 50));
    for policy in [PeekPolicy::GlobalUntilCap, PeekPolicy::AuthorOnPeek] {
        let txn = fixture.env.begin_ro().unwrap();
        let snapshot = ReadSnapshot::for_stored(&txn);
        let mut scan = configure(&filters.filters[0], &txn, policy);
        let mut sent = HashSet::new();
        assert!(scan
            .scan(
                &txn,
                &filters.filters[0],
                |id| {
                    sent.insert(id);
                    true
                },
                |_| false
            )
            .unwrap());
        let before = scan.diagnostic_feed_stats;
        let work_before = scan.approx_work;
        for (work, candidates) in [(0, PEEK_CANDIDATES), (PEEK_WORK, 0)] {
            let mut budget = PeekBudget { work, candidates };
            let (peek, measurements) = measure(|| {
                DbQuery::peek(
                    &mut scan,
                    &snapshot,
                    &filters.filters[0],
                    u64::MAX,
                    &sent,
                    &ReadVisibility::default(),
                    &mut false,
                    &mut budget,
                )
            })
            .unwrap();
            assert!(matches!(peek.unwrap(), Peek::Unknown));
            assert_eq!(measurements.wrapper, Default::default());
            assert_eq!(scan.diagnostic_feed_stats, before);
            assert_eq!(scan.approx_work, work_before);
            assert!(scan.diagnostic_feed_prefix.is_some());
        }
    }
}

#[test]
fn failed_payload_remains_ineligible_and_invalid_in_range_metadata_is_an_error() {
    let fixture = store(
        (0..30)
            .map(|n| event(n + 1, n % 5, BASE + n, 1, 0))
            .collect(),
    );
    let id = fixture.events[0].lev_id;
    let mut txn = fixture.env.begin_rw().unwrap();
    txn.put_u64(fixture.env.dbis().event_payload, id, &[0xFF], 0)
        .unwrap();
    txn.commit().unwrap();
    let filters = group(&feed(0..500, 50));
    let control = read_arm(
        &fixture.env,
        &filters,
        Arm::Pubkey,
        &QueryOptions::default(),
    )
    .unwrap();
    let candidate = read_arm(
        &fixture.env,
        &filters,
        Arm::BoundedGlobalPeek,
        &QueryOptions::default(),
    )
    .unwrap();
    assert!(control.completed && candidate.completed);
    assert_eq!(control.delivery, candidate.delivery);
    assert!(candidate.delivery.payload_failed);
    assert!(!strict_equal(&control, &candidate));
    assert!(!candidate.completeness.finish);
    evidence("failed_payload", "global_until_cap", &control, &candidate);
    let mut txn = fixture.env.begin_rw().unwrap();
    txn.put_u64(fixture.env.dbis().event, id, &[0xFF], 0)
        .unwrap();
    txn.commit().unwrap();
    assert!(read_arm(
        &fixture.env,
        &filters,
        Arm::BoundedGlobalPeek,
        &QueryOptions::default()
    )
    .is_err());
}

#[path = "bounded_feed_counterexamples.rs"]
mod counterexamples;
