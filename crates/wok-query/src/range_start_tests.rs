//! Compare a direct inclusive upper endpoint with the previous MAX/reposition
//! path in the same binary. The legacy override is private to these tests;
//! ordinary scans have no runtime plan switch or diagnostic counters.

use super::*;
use crate::visibility::ReadRestrictor;
use crate::{NostrFilterGroup, SubId};
use serde_json::{json, Value};
use wok_db::{write_events, Env, EnvOptions, EventToWrite, NoopNegentropy};
use wok_event::{PackedEventBuilder, PackedEventTagBuilder};

const BASE: u64 = 1_700_000_000;

#[derive(Clone, Copy, Debug)]
enum Start {
    Direct,
    LegacyMax,
}

impl Start {
    fn scan(self, txn: &RoTxn<'_>, filter: &NostrFilter) -> DbScan {
        let mut scan = DbScan::new(filter, txn);
        if matches!(self, Self::LegacyMax) {
            // Restore only fresh execution endpoints, after the ordinary
            // planner has made its unbounded author/tag probes.
            for cursor in &mut scan.cursors {
                let time_at = cursor.resume_key.len() - 8;
                cursor.resume_key[time_at..].copy_from_slice(&u64::MAX.to_ne_bytes());
            }
        }
        scan
    }
}

fn author(n: u64) -> [u8; 32] {
    let mut key = [0; 32];
    key[..8].copy_from_slice(&n.to_be_bytes());
    key
}

fn event(n: u64, who: u64, created: u64, kind: u64, expiration: u64) -> EventToWrite {
    let mut id = [0; 32];
    id[..8].copy_from_slice(&n.to_be_bytes());
    let mut tags = PackedEventTagBuilder::default();
    tags.add('t', b"all").unwrap();
    tags.add('t', if n % 2 == 0 { b"red" } else { b"blue" })
        .unwrap();
    if n % 5 == 0 {
        tags.add('t', b"red").unwrap();
        tags.add('t', b"blue").unwrap();
    }
    let packed =
        PackedEventBuilder::build(&id, &author(who), created, kind, expiration, &tags).unwrap();
    EventToWrite::new(
        packed.into_bytes(),
        wok_event::json::to_tao_string(&json!({"content": format!("range {n}: 🥘\u{7f}")})),
    )
}

fn corpus(authors: u64, rows: u64) -> Vec<EventToWrite> {
    (0..authors)
        .flat_map(|who| {
            (0..rows).map(move |depth| {
                event(
                    1 + who * rows + depth,
                    who,
                    if depth == 0 { 0 } else { BASE + depth / 3 },
                    if depth % 2 == 0 { 1 } else { 7 },
                    0,
                )
            })
        })
        .collect()
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

fn filter(value: &Value) -> NostrFilter {
    NostrFilter::parse(value, 100_000, 8, 16).unwrap()
}

fn expected(events: &[EventToWrite], filter: &NostrFilter) -> Vec<u64> {
    let mut entries: Vec<_> = events
        .iter()
        .filter_map(|event| {
            let view = PackedEventView::new(&event.packed).unwrap();
            filter
                .does_match(view)
                .then_some((view.created_at(), event.lev_id))
        })
        .collect();
    entries.sort_unstable_by(|a, b| b.cmp(a));
    entries.into_iter().map(|(_, id)| id).collect()
}

#[derive(Debug, PartialEq, Eq)]
struct Slice {
    ids: Vec<u64>,
    work: u64,
    complete: bool,
    initialized: usize,
    unsettled: Option<usize>,
    outstanding: Vec<u64>,
    refill_depths: Vec<u64>,
}

fn trace(txn: &RoTxn<'_>, filter: &NostrFilter, start: Start) -> Vec<Slice> {
    let mut scan = start.scan(txn, filter);
    let mut result = Vec::new();
    for slice in 0..10_000 {
        let work = scan.approx_work;
        let mut ids = Vec::new();
        let complete = scan
            .scan_with_depth_cap(
                txn,
                filter,
                if slice % 3 == 0 { 1 } else { u64::MAX },
                |id| {
                    ids.push(id);
                    ids.len() == 3
                },
                // Include a pause before initialization, then frequent
                // partial-frontier pauses and ordinary continuations.
                |current| slice == 0 || current > work + 17,
            )
            .unwrap();
        result.push(Slice {
            ids,
            work: scan.approx_work,
            complete,
            initialized: scan.next_init_index,
            unsettled: scan.unsettled,
            outstanding: scan
                .cursors
                .iter()
                .map(|cursor| cursor.outstanding)
                .collect(),
            refill_depths: scan.refill_scan_depths.clone(),
        });
        if complete && scan.unsettled.is_none() {
            return result;
        }
    }
    panic!("fixture scan failed to finish");
}

fn shapes(events: &[EventToWrite]) -> Vec<(&'static str, Value, &'static str)> {
    // write_events may reorder its batch. Pick timestamps explicitly so the
    // ID plan includes exact-boundary, older and excluded newer identities.
    let ids: Vec<_> = [0, BASE, BASE + 5, BASE + 10, BASE + 15]
        .into_iter()
        .flat_map(|created| {
            events
                .iter()
                .filter_map(move |event| {
                    let view = PackedEventView::new(&event.packed).unwrap();
                    (view.created_at() == created).then(|| hex::encode(view.id()))
                })
                .take(2)
        })
        .collect();
    vec![
        ("created", json!({}), "CreatedAt"),
        ("kind", json!({"kinds": [1, 7]}), "Kind"),
        ("id", json!({"ids": ids}), "ID"),
        (
            "author",
            json!({"authors": [hex::encode(author(0))]}),
            "Pubkey",
        ),
        (
            "feed",
            json!({"authors": [hex::encode(author(0)), hex::encode(author(2)), hex::encode(author(5)), hex::encode(author(99))]}),
            "Pubkey",
        ),
        (
            "author-kind",
            json!({"authors": [hex::encode(author(0)), hex::encode(author(2))], "kinds": [1, 7]}),
            "PubkeyKind",
        ),
        ("tag", json!({"#t": ["red", "blue", "missing"]}), "Tag"),
        (
            "tag-kind",
            json!({"#t": ["red", "blue"], "kinds": [1, 7]}),
            "TagKind",
        ),
        (
            "and-tag",
            json!({"&t": ["all", "red"], "kinds": [1, 7]}),
            "Tag",
        ),
    ]
}

#[test]
fn direct_upper_endpoint_preserves_all_plans_ties_resumes_and_work() {
    let (_dir, env, events) = store(corpus(6, 48));
    for (shape, value, plan) in shapes(&events) {
        for cuts in [
            json!({}),
            json!({"since": 0, "until": u64::MAX}),
            json!({"since": u64::MAX}),
            json!({"until": 0}),
            json!({"since": 0, "until": 0}),
            json!({"since": BASE + 5, "until": BASE + 5}),
            json!({"since": BASE + 9, "until": BASE + 4}),
            json!({"since": BASE + 3, "until": BASE + 11}),
        ] {
            let mut value = value.clone();
            value
                .as_object_mut()
                .unwrap()
                .extend(cuts.as_object().unwrap().clone());
            value["limit"] = json!(5);
            let filter = filter(&value);
            let txn = env.begin_ro().unwrap();
            assert_eq!(DbScan::new(&filter, &txn).desc, plan, "{shape}: {value}");
            let legacy = trace(&txn, &filter, Start::LegacyMax);
            drop(txn);
            // Separate transaction record caches keep cover and primary
            // cache population from affecting the other path.
            let txn = env.begin_ro().unwrap();
            let direct = trace(&txn, &filter, Start::Direct);
            assert_eq!(direct, legacy, "{shape}: {value}");
            let mut ids: Vec<_> = direct.into_iter().flat_map(|slice| slice.ids).collect();
            // OR-tag ranges deliberately revisit overlapping postings.
            ids.dedup();
            assert_eq!(ids, expected(&events, &filter), "{shape}: {value}");
        }
    }
}

#[test]
fn upper_endpoint_is_applied_after_unbounded_author_tag_probe_selection() {
    let events = (0..200)
        .map(|n| event(n + 1, u64::from(n >= 3), BASE + n, 1, 0))
        .collect();
    let (_dir, env, _) = store(events);
    // All postings are newer than until. Time-bounding the probes would
    // incorrectly turn the ubiquitous tag's 64-row probe into zero and
    // change the established small-author choice.
    let filter =
        filter(&json!({"authors": [hex::encode(author(0))], "#t": ["all"], "until": BASE - 1}));
    for start in [Start::LegacyMax, Start::Direct] {
        let txn = env.begin_ro().unwrap();
        let scan = start.scan(&txn, &filter);
        assert_eq!(scan.desc, "Pubkey");
        assert!(!scan.index_only);
        assert_eq!(trace(&txn, &filter, start).last().unwrap().work, 3);
    }
}

#[test]
fn bounded_initialization_keeps_the_read_snapshot_across_later_commits() {
    let (_dir, env, events) = store(corpus(6, 48));
    let filter = filter(
        &json!({"authors": (0..6).map(|n| hex::encode(author(n))).collect::<Vec<_>>(), "since": BASE + 2, "until": BASE + 10, "limit": 1}),
    );
    let old = env.begin_ro().unwrap();
    let mut legacy = Start::LegacyMax.scan(&old, &filter);
    let mut direct = Start::Direct.scan(&old, &filter);
    let first = |scan: &mut DbScan| {
        let mut id = None;
        scan.scan(
            &old,
            &filter,
            |next| {
                id = Some(next);
                true
            },
            |_| false,
        )
        .unwrap();
        id.unwrap()
    };
    let first_id = first(&mut legacy);
    assert_eq!(first(&mut direct), first_id);
    let extra = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let mut extra = vec![event(100_000, 0, BASE + 10, 1, 0)];
                let mut txn = env.begin_rw().unwrap();
                write_events(&mut txn, &mut NoopNegentropy, &mut extra, false).unwrap();
                txn.commit().unwrap();
                extra
            })
            .join()
            .unwrap()
    });
    let finish = |mut scan: DbScan| {
        let mut ids = vec![first_id];
        while !(scan
            .scan(
                &old,
                &filter,
                |id| {
                    ids.push(id);
                    true
                },
                |_| false,
            )
            .unwrap()
            && scan.unsettled.is_none())
        {}
        (ids, scan.approx_work)
    };
    let legacy = finish(legacy);
    let direct = finish(direct);
    assert_eq!(direct, legacy);
    assert_eq!(direct.0, expected(&events, &filter));
    drop(old);
    let now = env.begin_ro().unwrap();
    let current: Vec<_> = trace(&now, &filter, Start::Direct)
        .into_iter()
        .flat_map(|s| s.ids)
        .collect();
    assert_eq!(current.first(), Some(&extra[0].lev_id));
    assert_eq!(current.len(), direct.0.len() + 1);
}

#[test]
fn bounded_query_preserves_visibility_hints_limits_and_completeness() {
    let events = (0..90)
        .map(|n| {
            event(
                n + 1,
                n % 3,
                BASE + n / 3,
                if n % 5 == 0 { 4 } else { 1 },
                if n % 7 == 0 { 2 } else { 0 },
            )
        })
        .collect();
    let (_dir, env, events) = store(events);
    let value = json!([{"authors": (0..3).map(|n| hex::encode(author(n))).collect::<Vec<_>>(), "until": BASE + 20, "limit": 5}, {"#t": ["all"], "since": BASE + 5, "until": BASE + 10, "limit": 3}]);
    let run = |start: Start| {
        let txn = env.begin_ro().unwrap();
        let group = NostrFilterGroup::from_value(&value, 100_000, 8, 16).unwrap();
        let mut subscription =
            Subscription::new(1, SubId::new("range-bound").unwrap(), group, false);
        subscription.latest_event_id = events[50].lev_id;
        let mut query = DbQuery::new(subscription, 7, 0);
        query.track_completeness();
        query.set_visibility(ReadVisibility {
            restrictor: ReadRestrictor {
                recipient_only: vec![4],
                ..ReadRestrictor::default()
            },
            ..ReadVisibility::default()
        });
        query.scanner = Some(QueryScanner::Chronological(
            start.scan(&txn, &query.sub.filter_group.filters[0]),
        ));
        let mut ids = Vec::new();
        while !query.process(&txn, |_, id| ids.push(id), 0).unwrap() {}
        (
            ids,
            query.sent_count(),
            query.completeness(),
            PEEK_WORK - query.peek_budget.work,
            PEEK_CANDIDATES - query.peek_budget.candidates,
        )
    };
    let legacy = run(Start::LegacyMax);
    let direct = run(Start::Direct);
    assert_eq!(direct, legacy);
    assert_eq!(direct.0.len(), 7);
    assert!(!direct.2.finish);
    assert!(direct.2.more);
}

#[test]
fn bounded_seek_retains_in_range_duplicate_errors_and_skips_unrequested_cover_damage() {
    for (created, in_range) in [(BASE + 5, true), (BASE + 30, false)] {
        let (_dir, env, events) = store(vec![event(1, 0, BASE + 1, 1, 0)]);
        let mut txn = env.begin_rw().unwrap();
        txn.put(
            env.dbis().event_pubkey,
            &wok_db::keys::make_key_string_u64(&author(0), created),
            &7u32.to_ne_bytes(),
            0,
        )
        .unwrap();
        txn.commit().unwrap();
        let audit = wok_db::check_integrity(&env.begin_ro().unwrap()).unwrap();
        assert!(!audit.ok());
        assert!(audit.malformed_records > 0);
        let filter = filter(&json!({"authors": [hex::encode(author(0))], "until": BASE + 10}));
        let run = |start: Start, thin: bool| {
            let txn = env.begin_ro().unwrap();
            let mut scan = start.scan(&txn, &filter);
            if thin {
                scan.index_dbi = env.dbis().event_pubkey;
            }
            let mut ids = Vec::new();
            scan.scan(
                &txn,
                &filter,
                |id| {
                    ids.push(id);
                    false
                },
                |_| false,
            )
            .map(|_| ids)
        };
        for thin in [true, false] {
            let legacy = run(Start::LegacyMax, thin);
            let direct = run(Start::Direct, thin);
            if in_range {
                assert!(legacy.is_err());
                assert!(direct.is_err());
            } else {
                assert_eq!(direct.unwrap(), [events[0].lev_id]);
                if thin
                    || env.covering_pubkey_dbi() == env.dbis().event_pubkey
                    || cfg!(feature = "rocksdb-thin-author-reads")
                {
                    assert_eq!(legacy.unwrap(), [events[0].lev_id]);
                } else {
                    // Rocks cover caching validates a duplicate before the
                    // callback. Direct initialization intentionally does not
                    // visit corrupt rows above until. Offline integrity, not
                    // an unrelated bounded query, audits the full index.
                    assert!(legacy.is_err());
                }
            }
        }
    }
}

#[test]
fn returned_nonmatching_or_short_boundaries_keep_lazy_validation() {
    let (_dir, env, _) = store(Vec::new());
    let mut txn = env.begin_rw().unwrap();
    let dbi = env.dbis().event_tag;
    txn.put(
        dbi,
        &wok_db::keys::make_key_string_u64(b"ta", BASE + 5),
        &7u32.to_ne_bytes(),
        0,
    )
    .unwrap();
    txn.put(dbi, b"short", &7u32.to_ne_bytes(), 0).unwrap();
    txn.commit().unwrap();
    let txn = env.begin_ro().unwrap();
    let filter = filter(&json!({"#t": ["b"], "until": BASE + 10}));
    assert!(trace(&txn, &filter, Start::Direct)
        .iter()
        .all(|slice| slice.ids.is_empty()));
    // An Always cursor skips a short malformed key before interpreting the
    // malformed duplicate. This exercises the same generic fallback used by
    // a native iterator when a returned physical key is noncanonical.
    let mut cursor = ScanCursor {
        resume_key: b"short".to_vec(),
        resume_val: u64::MAX,
        search: Vec::new(),
        match_mode: MatchMode::Always,
        outstanding: 0,
    };
    let mut physical = txn.cursor(dbi).unwrap();
    let mut out = VecDeque::new();
    assert_eq!(
        cursor
            .collect(&mut physical, 0, 0, BASE + 10, 1, &mut out)
            .unwrap(),
        0
    );
    assert!(!cursor.active());
}

#[test]
fn a_returned_cover_boundary_still_validates_its_duplicate() {
    let (_dir, env, _) = store(Vec::new());
    let mut txn = env.begin_rw().unwrap();
    txn.put(
        env.dbis().event_pubkey,
        &wok_db::keys::make_key_string_u64(&author(0), BASE + 5),
        &7u32.to_ne_bytes(),
        0,
    )
    .unwrap();
    txn.commit().unwrap();
    let filter = filter(&json!({"authors": [hex::encode(author(1))], "until": BASE + 10}));
    for start in [Start::Direct, Start::LegacyMax] {
        let txn = env.begin_ro().unwrap();
        let mut scan = start.scan(&txn, &filter);
        let covering = scan.index_dbi != env.dbis().event_pubkey;
        let result = scan.scan(&txn, &filter, |_| panic!("nonmatching author"), |_| false);
        assert_eq!(result.is_err(), covering);
    }
}

#[test]
fn raw_upper_endpoint_keeps_max_and_zero_duplicate_ties_inclusive() {
    let (_dir, env, _) = store(Vec::new());
    let mut txn = env.begin_rw().unwrap();
    let dbi = env.dbis().event_tag;
    for (created, id) in [
        (u64::MAX, 1u64),
        (u64::MAX, 2),
        (u64::MAX, u64::MAX),
        (0, 3),
        (0, 4),
    ] {
        txn.put(
            dbi,
            &wok_db::keys::make_key_string_u64(b"tb", created),
            &id.to_ne_bytes(),
            0,
        )
        .unwrap();
    }
    txn.commit().unwrap();
    let txn = env.begin_ro().unwrap();
    for (since, until, expected) in [
        (u64::MAX, u64::MAX, vec![u64::MAX, 2, 1]),
        (0, 0, vec![4, 3]),
        (0, u64::MAX, vec![u64::MAX, 2, 1, 4, 3]),
    ] {
        for start in [Start::Direct, Start::LegacyMax] {
            let filter = filter(&json!({"#t": ["b"], "since": since, "until": until}));
            let mut scan = start.scan(&txn, &filter);
            let cursor = &mut scan.cursors[0];
            let mut physical = txn.cursor(dbi).unwrap();
            let mut out = VecDeque::new();
            let endpoint = (cursor.resume_key.clone(), cursor.resume_val);
            assert_eq!(
                cursor
                    .collect(&mut physical, 0, since, until, 0, &mut out)
                    .unwrap(),
                0
            );
            assert_eq!((cursor.resume_key.clone(), cursor.resume_val), endpoint);
            let mut ids = Vec::new();
            while cursor.active() {
                cursor
                    .collect(&mut physical, 0, since, until, 1, &mut out)
                    .unwrap();
                ids.extend(out.drain(..).map(|entry| entry.lev_id()));
            }
            assert_eq!(ids, expected, "{start:?}: since={since}, until={until}");
        }
    }
}

#[cfg(feature = "rocksdb-read-diagnostics")]
fn measured_first(
    txn: &RoTxn<'_>,
    filter: &NostrFilter,
    start: Start,
) -> ((u64, u64), wok_db::read_diagnostics::ReadMeasurements) {
    let mut scan = start.scan(txn, filter);
    wok_db::read_diagnostics::measure(|| {
        let mut first = None;
        scan.scan_with_depth_cap(
            txn,
            filter,
            1,
            |id| {
                first = Some(id);
                true
            },
            |_| false,
        )
        .unwrap();
        (first.unwrap(), scan.approx_work)
    })
    .unwrap()
}

#[cfg(feature = "rocksdb-read-diagnostics")]
#[test]
fn direct_until_uses_one_initial_seek_per_populated_feed_range() {
    let (_dir, env, _) = store(corpus(500, 24));
    let filter = filter(
        &json!({"authors": (0..500).map(|n| hex::encode(author(n))).collect::<Vec<_>>(), "until": BASE + 5, "limit": 50}),
    );
    let legacy = measured_first(&env.begin_ro().unwrap(), &filter, Start::LegacyMax);
    let direct = measured_first(&env.begin_ro().unwrap(), &filter, Start::Direct);
    assert_eq!(direct.0, legacy.0);
    assert_eq!(direct.0 .1, 1001);
    assert_eq!(legacy.1.wrapper.seek, 1000);
    assert_eq!(
        direct.1.wrapper.seek, 500,
        "one native position operation per populated author range"
    );
    assert_eq!(legacy.1.wrapper.typed_index_entries, 1500);
    assert_eq!(direct.1.wrapper.typed_index_entries, 1000);
    assert_eq!(legacy.1.wrapper.resume_key_copies, 1000);
    assert_eq!(direct.1.wrapper.resume_key_copies, 500);
    assert_eq!(direct.1.wrapper.ordered_key_encodes, 500);
    assert_eq!(direct.1.wrapper.iterator_creations, 1);
    assert_eq!(direct.1.wrapper.cover_records_copied, 0);
    assert_eq!(direct.1.wrapper.primary_pin_lookups, 0);
}

#[cfg(feature = "rocksdb-read-diagnostics")]
#[test]
fn absent_and_max_until_do_not_change_native_execution_operations() {
    let (_dir, env, _) = store(corpus(6, 48));
    for value in [
        json!({"authors": [hex::encode(author(0))]}),
        json!({"authors": [hex::encode(author(0))], "until": u64::MAX}),
    ] {
        let filter = filter(&value);
        let legacy = measured_first(&env.begin_ro().unwrap(), &filter, Start::LegacyMax);
        let direct = measured_first(&env.begin_ro().unwrap(), &filter, Start::Direct);
        assert_eq!(direct.0, legacy.0);
        assert_eq!(direct.1.wrapper, legacy.1.wrapper);
    }
}

#[cfg(feature = "rocksdb-read-diagnostics")]
#[test]
fn author_start_only_copies_records_in_the_covering_layout() {
    let (_dir, env, events) = store(corpus(1, 24));
    let has_cover = u64::from(env.covering_pubkey_dbi() != env.dbis().event_pubkey);
    let filter = filter(&json!({"authors": [hex::encode(author(0))], "until": BASE + 5}));
    let run = |start: Start| {
        let txn = env.begin_ro().unwrap();
        let mut scan = start.scan(&txn, &filter);
        // Use a physical cover even in the thin-read control build. In the
        // coverless layout this accessor is thin and must copy no record.
        scan.index_dbi = env.covering_pubkey_dbi();
        wok_db::read_diagnostics::measure(|| {
            let mut id = None;
            scan.scan_with_depth_cap(
                &txn,
                &filter,
                1,
                |next| {
                    id = Some(next);
                    true
                },
                |_| false,
            )
            .unwrap();
            (id.unwrap(), scan.approx_work)
        })
        .unwrap()
    };
    let legacy = run(Start::LegacyMax);
    let direct = run(Start::Direct);
    assert_eq!(direct.0, legacy.0);
    assert_eq!(legacy.1.wrapper.cover_records_copied, 3 * has_cover);
    assert_eq!(direct.1.wrapper.cover_records_copied, 2 * has_cover);
    assert_eq!(legacy.1.wrapper.seek, 2);
    assert_eq!(direct.1.wrapper.seek, 1);
    let txn = env.begin_ro().unwrap();
    let excluded = events.last().unwrap().lev_id;
    let bytes = txn
        .get_u64(env.dbis().event, excluded)
        .unwrap()
        .unwrap()
        .len()
        + txn
            .get_u64(env.dbis().event_payload, excluded)
            .unwrap()
            .unwrap()
            .len()
        + 8;
    assert_eq!(
        legacy.1.wrapper.cover_record_bytes_copied - direct.1.wrapper.cover_record_bytes_copied,
        bytes as u64 * has_cover
    );
    assert_eq!(direct.1.wrapper.primary_pin_lookups, 0);
}

#[cfg(feature = "rocksdb-read-diagnostics")]
#[test]
fn pause_before_initialization_does_no_native_position_work() {
    let (_dir, env, _) = store(corpus(4, 24));
    let filter = filter(
        &json!({"authors": (0..4).map(|n| hex::encode(author(n))).collect::<Vec<_>>(), "until": BASE + 5}),
    );
    for start in [Start::Direct, Start::LegacyMax] {
        let txn = env.begin_ro().unwrap();
        let mut scan = start.scan(&txn, &filter);
        let (_, measured) = wok_db::read_diagnostics::measure(|| {
            assert!(!scan
                .scan(&txn, &filter, |_| panic!("paused"), |_| true)
                .unwrap());
        })
        .unwrap();
        assert_eq!(scan.next_init_index, 0);
        assert_eq!(scan.approx_work, 1);
        assert_eq!(measured.wrapper.iterator_creations, 1);
        assert_eq!(measured.wrapper.seek, 0);
        assert_eq!(measured.wrapper.typed_index_entries, 0);
        assert_eq!(measured.wrapper.resume_key_copies, 0);
    }
}

#[cfg(feature = "rocksdb-read-diagnostics")]
#[test]
fn diagnostic_query_work_includes_paused_slices_and_the_final_capped_peek() {
    let (_dir, env, _) = store(corpus(4, 2000));
    let value = json!({"authors": (0..4).map(|n| hex::encode(author(n))).collect::<Vec<_>>(), "until": BASE + 500, "limit": 1000});
    let filter = filter(&value);
    for start in [Start::Direct, Start::LegacyMax] {
        let txn = env.begin_ro().unwrap();
        let group = NostrFilterGroup::from_value(&value, 100_000, 8, 16).unwrap();
        let mut query = DbQuery::new(
            Subscription::new(1, SubId::new("work-counter").unwrap(), group, false),
            0,
            0,
        );
        query.track_completeness();
        query.scanner = Some(QueryScanner::Chronological(start.scan(&txn, &filter)));
        let mut emitted = Vec::new();
        let mut slices = 0;
        let mut prior_work = 0;
        loop {
            slices += 1;
            let complete = query.process(&txn, |_, id| emitted.push(id), 0).unwrap();
            assert!(query.diagnostic_chronological_work > prior_work);
            prior_work = query.diagnostic_chronological_work;
            if complete {
                break;
            }
        }
        assert!(
            slices > 1,
            "the diagnostic must retain work from paused slices"
        );
        assert!(
            query.scanner.is_none(),
            "completed scanner has been dropped"
        );
        assert_eq!(emitted.len(), 1000);
        assert_eq!(PEEK_WORK - query.peek_budget.work, 2);
        assert!(query.completeness().more);

        // Independently drive the same logical work ceiling, retaining the
        // scanner's own final counter rather than consulting DbQuery's hook.
        let snapshot = ReadSnapshot::for_stored(&txn);
        let mut scan = start.scan(&txn, &filter);
        let mut ids = Vec::new();
        let mut last_check = 0;
        let mut raw_slices = 0;
        loop {
            raw_slices += 1;
            let complete = scan
                .scan(
                    &txn,
                    &filter,
                    |id| {
                        ids.push(id);
                        ids.len() == 1000
                    },
                    |work| {
                        if work > last_check + 2000 {
                            last_check = work;
                            true
                        } else {
                            false
                        }
                    },
                )
                .unwrap();
            if complete {
                break;
            }
        }
        let before_peek = scan.approx_work;
        let peek = DbQuery::peek(
            &mut scan,
            &snapshot,
            &filter,
            u64::MAX,
            &ids.iter().copied().collect(),
            &ReadVisibility::default(),
            &mut false,
            &mut PeekBudget {
                work: PEEK_WORK,
                candidates: PEEK_CANDIDATES,
            },
        )
        .unwrap();
        assert!(matches!(peek, Peek::Found(_)));
        assert_eq!(scan.approx_work - before_peek, 2);
        assert_eq!(raw_slices, slices);
        assert_eq!(ids, emitted);
        assert_eq!(query.diagnostic_chronological_work, scan.approx_work);
    }
}

#[cfg(feature = "rocksdb-read-diagnostics")]
#[test]
#[ignore = "operation diagnostic; opt-in counters and native PerfContext are not clean timings"]
fn range_initialization_native_operations() {
    let (_dir, env, events) = store(corpus(500, 48));
    let mut cases = shapes(&events);
    cases.push((
        "feed-500",
        json!({"authors": (0..500).map(|n| hex::encode(author(n))).collect::<Vec<_>>() }),
        "Pubkey",
    ));
    let mut samples = Vec::new();
    for repetition in 0..3 {
        for (shape, value, plan) in &cases {
            for until in [None, Some(u64::MAX), Some(BASE + 5), Some(0)] {
                let mut value = value.clone();
                value["limit"] = json!(50);
                if let Some(until) = until {
                    value["until"] = json!(until);
                }
                let filter = filter(&value);
                let arms = if repetition % 2 == 0 {
                    [Start::LegacyMax, Start::Direct]
                } else {
                    [Start::Direct, Start::LegacyMax]
                };
                let mut results = Vec::new();
                for start in arms {
                    let txn = env.begin_ro().unwrap();
                    let (mut scan, planning) =
                        wok_db::read_diagnostics::measure(|| start.scan(&txn, &filter)).unwrap();
                    assert_eq!(scan.desc, *plan);
                    let (ids, execution) = wok_db::read_diagnostics::measure(|| {
                        let mut ids = Vec::new();
                        scan.scan(
                            &txn,
                            &filter,
                            |id| {
                                ids.push(id);
                                ids.len() == 50
                            },
                            |_| false,
                        )
                        .unwrap();
                        ids
                    })
                    .unwrap();
                    results.push((ids.clone(), scan.approx_work));
                    samples.push(json!({"repetition": repetition, "shape": shape, "filter": value, "arm": format!("{start:?}"), "plan": scan.desc, "range_count": scan.cursor_count(), "emitted_local_ids": ids, "approx_work": scan.approx_work, "planning": planning, "execution": execution}));
                }
                assert_eq!(results[0], results[1], "{shape}: {value}");
            }
        }
    }
    println!(
        "{}",
        json!({"format": "wok-range-initialization-operations-v1", "fixture": {"authors": 500, "rows_per_author": 48, "events": events.len(), "storage": "disposable temporary database, no explicit flush/compaction"}, "scope": "Same binary, fresh transaction per arm; environment opening and fixture writes are outside measurement. Planning and execution scopes are separate. All repetitions retained; no measured latency claim. Wrapper calls/copies and native internal counters are distinct; neither establishes physical I/O.", "samples": samples})
    );
}
