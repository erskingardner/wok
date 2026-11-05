//! The author read experiment changes only the selected index. These private
//! tests force either index in one binary. The coverless layout aliases the
//! accessor to thin postings; the model and full-query assertions still apply.

use super::*;
use crate::visibility::ReadRestrictor;
use crate::{NostrFilterGroup, SubId};
use serde_json::{json, Value};
use std::time::Instant;
use wok_db::{write_events, Env, EnvOptions, EventToWrite, NoopNegentropy};
use wok_event::{PackedEventBuilder, PackedEventTagBuilder};

const BASE: u64 = 1_700_000_000;

#[derive(Clone, Copy, Debug)]
enum AuthorIndex {
    Thin,
    Covering,
}

impl AuthorIndex {
    fn scan(self, txn: &RoTxn<'_>, filter: &NostrFilter) -> DbScan {
        let mut scan = DbScan::new(filter, txn);
        assert_eq!(scan.desc, "Pubkey", "fixture must select an author seed");
        scan.index_dbi = match self {
            Self::Thin => txn.env().dbis().event_pubkey,
            Self::Covering => txn.env().covering_pubkey_dbi(),
        };
        scan
    }
}

fn author(n: u64) -> [u8; 32] {
    let mut key = [0; 32];
    key[..8].copy_from_slice(&n.to_be_bytes());
    key
}

fn event(n: u64, who: u64, kind: u64, expiration: u64, tags: &[&str]) -> EventToWrite {
    let mut id = [0; 32];
    id[..8].copy_from_slice(&n.to_be_bytes());
    let mut packed_tags = PackedEventTagBuilder::default();
    for tag in tags {
        packed_tags.add('t', tag.as_bytes()).unwrap();
    }
    if kind == 4 {
        packed_tags.add('p', &author(9)).unwrap();
    }
    let packed = PackedEventBuilder::build(
        &id,
        &author(who),
        BASE + n / 3,
        kind,
        expiration,
        &packed_tags,
    )
    .unwrap();
    EventToWrite::new(
        packed.into_bytes(),
        wok_event::json::to_tao_string(&json!({"content": format!("note {n}: 🥘\u{7f}")})),
    )
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
    let mut matches: Vec<_> = events
        .iter()
        .filter_map(|event| {
            let packed = PackedEventView::new(&event.packed).unwrap();
            filter
                .does_match(packed)
                .then_some((packed.created_at(), event.lev_id))
        })
        .collect();
    matches.sort_unstable_by(|a, b| b.cmp(a));
    matches.into_iter().map(|(_, id)| id).collect()
}

/// Stop and resume across both a handler stop and a work-budget pause.
fn collect_scan(txn: &RoTxn<'_>, filter: &NostrFilter, index: AuthorIndex) -> (Vec<u64>, u64) {
    let mut scan = index.scan(txn, filter);
    let mut ids = Vec::new();
    loop {
        let before = ids.len();
        let work = scan.approx_work;
        let complete = scan
            .scan(
                txn,
                filter,
                |id| {
                    ids.push(id);
                    ids.len() - before == 13
                },
                |current| current > work + 37,
            )
            .unwrap();
        if complete && scan.unsettled.is_none() {
            return (ids, scan.approx_work);
        }
    }
}

#[derive(Default)]
struct QueryOptions {
    visibility: ReadVisibility,
    latest: Option<u64>,
    max_total: u64,
    count_only: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct StoredHit {
    id: u64,
    packed: Option<Vec<u8>>,
    payload: Option<Vec<u8>>,
    json: Result<String, String>,
}

#[derive(Debug, PartialEq, Eq)]
struct QueryResult {
    hits: Vec<StoredHit>,
    sent_count: u64,
    completeness: Completeness,
    hll: Option<String>,
    peek_work: u64,
    peek_candidates: u32,
}

fn collect_query(
    txn: &RoTxn<'_>,
    value: &Value,
    index: AuthorIndex,
    options: &QueryOptions,
) -> QueryResult {
    let group = NostrFilterGroup::from_value(value, 100_000, 8, 16).unwrap();
    let mut sub = Subscription::new(
        1,
        SubId::new("author-index").unwrap(),
        group,
        options.count_only,
    );
    sub.latest_event_id = options.latest.unwrap_or(u64::MAX);
    let mut query = DbQuery::new(sub, options.max_total, 0);
    query.track_completeness();
    query.set_visibility(options.visibility.clone());
    // Private injection retains DbQuery's normal visibility, dedup, limit,
    // payload-failure notification and completeness paths after index choice.
    query.scanner = Some(QueryScanner::Chronological(
        index.scan(txn, &query.sub.filter_group.filters[0]),
    ));
    let mut hits = Vec::new();
    let mut decompressor = Decompressor::new();
    loop {
        let mut payload_failed = false;
        let complete = query
            .process(
                txn,
                |_, id| {
                    let packed = txn
                        .get_u64(txn.env().dbis().event, id)
                        .unwrap()
                        .map(<[u8]>::to_vec);
                    let payload = txn
                        .get_u64(txn.env().dbis().event_payload, id)
                        .unwrap()
                        .map(<[u8]>::to_vec);
                    let json = wok_db::event_json_owned(txn, &mut decompressor, id, 1 << 20)
                        .map_err(|error| error.to_string());
                    payload_failed |= json.is_err();
                    hits.push(StoredHit {
                        id,
                        packed,
                        payload,
                        json,
                    });
                },
                0,
            )
            .unwrap();
        if payload_failed && !options.count_only {
            query.mark_incomplete();
        }
        if complete {
            break;
        }
    }
    QueryResult {
        hits,
        sent_count: query.sent_count(),
        completeness: query.completeness(),
        hll: query.hll_hex(),
        peek_work: PEEK_WORK - query.peek_budget.work,
        peek_candidates: PEEK_CANDIDATES - query.peek_budget.candidates,
    }
}

#[test]
fn author_index_order_resume_and_work_match() {
    let (_dir, env, events) = store(
        (1..=720)
            .map(|n| event(n, u64::from(n > 700), 1, 0, &[]))
            .collect(),
    );
    for value in [
        json!({"authors": [hex::encode(author(0))], "limit": 50}),
        json!({"authors": [hex::encode(author(0))], "since": BASE + 17, "until": BASE + 173, "limit": 1}),
        json!({"authors": [hex::encode(author(0))], "since": BASE + 500}),
    ] {
        let filter = filter(&value);
        let thin = collect_scan(&env.begin_ro().unwrap(), &filter, AuthorIndex::Thin);
        let cover = collect_scan(&env.begin_ro().unwrap(), &filter, AuthorIndex::Covering);
        assert_eq!(thin, cover, "{value}");
        assert_eq!(thin.0, expected(&events, &filter), "{value}");
    }
}

#[cfg(feature = "rocksdb-coverless")]
#[test]
fn coverless_public_author_and_feed_plans_use_thin_postings() {
    let (_dir, env, events) = store((1..=300).map(|n| event(n, n % 3, 1, 0, &[])).collect());
    assert!(env.inner.db.cf_handle("wok_pubkey_covering_v1").is_none());
    for value in [
        json!({"authors": [hex::encode(author(0))], "until": BASE + 83, "limit": 50}),
        json!({"authors": [hex::encode(author(0)), hex::encode(author(1))], "since": BASE + 17, "until": BASE + 83, "limit": 50}),
    ] {
        let txn = env.begin_ro().unwrap();
        let filter = filter(&value);
        let scan = DbScan::new(&filter, &txn);
        assert_eq!(scan.desc, "Pubkey");
        assert_eq!(scan.index_dbi, env.dbis().event_pubkey);
        let (ids, _) = collect_scan(&txn, &filter, AuthorIndex::Covering);
        assert_eq!(ids, expected(&events, &filter));
        let result = collect_query(
            &txn,
            &value,
            AuthorIndex::Covering,
            &QueryOptions::default(),
        );
        assert_eq!(result.sent_count, 50);
        assert!(result.completeness.more);
        assert!(result.hits.iter().all(|hit| hit.json.is_ok()));
        assert_eq!(
            result.hits.iter().map(|hit| hit.id).collect::<Vec<_>>(),
            ids[..50]
        );
    }
}

#[test]
fn author_queries_preserve_policy_limits_hints_and_encoded_payloads() {
    let (_dir, env, events) = store(
        (1..=150)
            .map(|n| {
                let kind = if n % 11 == 0 {
                    22242
                } else if n % 7 == 0 {
                    4
                } else {
                    1
                };
                event(n, 0, kind, if n % 13 == 0 { 100 } else { 0 }, &[])
            })
            .collect(),
    );
    // The cover must retain the encoded bytes, including the dictionary ID;
    // decoding through the actual query callback must recover the same JSON.
    let compressed_id = events[148].lev_id;
    let dictionary = b"note content author index payload".repeat(64);
    let mut txn = env.begin_rw().unwrap();
    let dict_id =
        u32::try_from(wok_db::insert_compression_dictionary(&mut txn, &dictionary).unwrap())
            .unwrap();
    let compressed = zstd::bulk::Compressor::with_dictionary(3, &dictionary)
        .unwrap()
        .compress(events[148].json.as_bytes())
        .unwrap();
    txn.put_u64(
        env.dbis().event_payload,
        compressed_id,
        &wok_db::encode_zstd_payload(dict_id, &compressed),
        0,
    )
    .unwrap();
    txn.commit().unwrap();
    for (limit, latest, max_total, identities, count_only) in [
        (50, None, 0, vec![], false),
        (1000, None, 0, vec![], false),
        (50, Some(events[99].lev_id), 12, vec![author(9)], false),
        (1000, None, 0, vec![author(0)], true),
        (0, None, 0, vec![], false),
    ] {
        let value = json!({"authors": [hex::encode(author(0))], "limit": limit});
        let options = QueryOptions {
            visibility: ReadVisibility {
                restrictor: ReadRestrictor {
                    recipient_only: vec![4],
                    ..ReadRestrictor::default()
                },
                identities,
                ..ReadVisibility::default()
            },
            latest,
            max_total,
            count_only,
        };
        let thin = collect_query(
            &env.begin_ro().unwrap(),
            &value,
            AuthorIndex::Thin,
            &options,
        );
        let cover = collect_query(
            &env.begin_ro().unwrap(),
            &value,
            AuthorIndex::Covering,
            &options,
        );
        assert_eq!(
            thin, cover,
            "limit={limit}, latest={latest:?}, max_total={max_total}"
        );
        assert!(thin.hits.iter().all(|hit| hit.json.is_ok()));
        if limit == 50 && latest.is_none() {
            assert_eq!(thin.sent_count, 50);
            assert!(thin.completeness.more);
            let hit = thin
                .hits
                .iter()
                .find(|hit| hit.id == compressed_id)
                .unwrap();
            assert_eq!(hit.payload.as_ref().unwrap()[0], wok_db::PAYLOAD_ZSTD);
            assert_eq!(hit.json.as_ref().unwrap(), &events[148].json);
        } else if limit == 1000 && !count_only {
            assert!(thin.completeness.finish);
            assert!(thin.completeness.restricted);
            assert!(thin.sent_count > 50);
        } else if let Some(latest) = latest {
            assert_eq!(thin.sent_count, 12);
            assert!(thin.completeness.more);
            assert!(thin.hits.iter().all(|hit| hit.id <= latest));
        } else if limit == 0 {
            assert_eq!(thin.sent_count, 0);
            assert_eq!(thin.completeness, Completeness::default());
        }
    }
}

#[test]
fn author_alternative_keeps_residual_tags_and_full_query_checks() {
    let (_dir, env, events) = store(
        (1..=100)
            .map(|n| {
                event(
                    n,
                    u64::from(n > 12),
                    1,
                    0,
                    if n % 3 == 0 || n > 12 {
                        &["common"]
                    } else {
                        &[]
                    },
                )
            })
            .collect(),
    );
    let value = json!({"authors": [hex::encode(author(0))], "#t": ["common"], "limit": 3});
    let filter = filter(&value);
    let txn = env.begin_ro().unwrap();
    assert_eq!(ScanPlan::choose(&filter, || false), ScanPlan::Tag);
    let scan = DbScan::new(&filter, &txn);
    assert_eq!(scan.desc, "Pubkey");
    assert!(
        !scan.index_only,
        "author seed must check the original tag filter"
    );
    let thin = collect_scan(&txn, &filter, AuthorIndex::Thin);
    let cover = collect_scan(&txn, &filter, AuthorIndex::Covering);
    assert_eq!(thin, cover);
    assert_eq!(thin.0, expected(&events, &filter));
    let thin = collect_query(&txn, &value, AuthorIndex::Thin, &QueryOptions::default());
    let cover = collect_query(
        &txn,
        &value,
        AuthorIndex::Covering,
        &QueryOptions::default(),
    );
    assert_eq!(thin, cover);
    assert_eq!(
        thin.hits.iter().map(|hit| hit.id).collect::<Vec<_>>(),
        expected(&events, &filter)[..3]
    );
    assert!(thin.completeness.more);
}

#[test]
fn author_indexes_preserve_snapshots_and_independent_record_components() {
    let (_dir, env, events) = store((1..=40).map(|n| event(n, 0, 1, 0, &[])).collect());
    let value = json!({"authors": [hex::encode(author(0))], "limit": 100});
    let options = QueryOptions::default();
    let old = env.begin_ro().unwrap();
    let before = collect_query(&old, &value, AuthorIndex::Thin, &options);
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let mut txn = env.begin_rw().unwrap();
                txn.del_u64(env.dbis().event_payload, events[38].lev_id, None)
                    .unwrap();
                txn.del_u64(env.dbis().event, events[37].lev_id, None)
                    .unwrap();
                wok_db::mark_vanished(&mut txn, &author(0), BASE + 2).unwrap();
                txn.commit().unwrap();
            })
            .join()
            .unwrap();
    });
    assert_eq!(
        before,
        collect_query(&old, &value, AuthorIndex::Thin, &options)
    );
    assert_eq!(
        before,
        collect_query(&old, &value, AuthorIndex::Covering, &options)
    );
    assert!(before.completeness.finish);
    drop(old);
    let thin = collect_query(
        &env.begin_ro().unwrap(),
        &value,
        AuthorIndex::Thin,
        &options,
    );
    let cover = collect_query(
        &env.begin_ro().unwrap(),
        &value,
        AuthorIndex::Covering,
        &options,
    );
    assert_eq!(thin, cover);
    assert!(!thin.hits.iter().any(|hit| hit.id == events[37].lev_id));
    let missing = thin
        .hits
        .iter()
        .find(|hit| hit.id == events[38].lev_id)
        .unwrap();
    assert!(missing.packed.is_some());
    assert!(missing.payload.is_none());
    assert!(missing.json.is_err());
    assert_eq!(thin.completeness, Completeness::default());
    assert!(thin.sent_count < before.sent_count);
}

fn knob(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .map(|value| value.parse().unwrap())
        .unwrap_or(default)
}

/// Warm in-process diagnostic, not a capacity or cold-storage benchmark.
/// Fresh read transactions prevent either arm inheriting the other's record
/// cache. Both indexes, database options and writes are identical. Native
/// block reads, pin/copy counts and bytes retained are not measured here.
/// Contiguous IDs from one author favor primary locality compared with a
/// corpus whose authors' events are interleaved.
#[test]
#[ignore]
fn author_index_causal_diagnostic() {
    if matches!(
        wok_db::storage_backend_name(),
        "lmdb" | "rocksdb-coverless-experimental"
    ) {
        println!("This layout aliases the two author DBIs; no distinct physical index comparison");
        return;
    }
    let rows = knob("AUTHOR_INDEX_ROWS", 10_000);
    let runs = knob("AUTHOR_INDEX_RUNS", 21);
    let payload_bytes = knob("AUTHOR_INDEX_PAYLOAD_BYTES", 1024);
    assert!(rows > 500 && runs > 0);
    let (_dir, env, _events) = store(
        (1..=rows as u64)
            .map(|n| {
                let mut event = event(n, 0, 1, 0, &[]);
                event.json =
                    wok_event::json::to_tao_string(&json!({"content": "x".repeat(payload_bytes)}));
                event
            })
            .collect(),
    );
    println!(
        "{}",
        json!({"backend": wok_db::storage_backend_name(), "rows": rows,
        "runs": runs, "payload_content_bytes": payload_bytes, "cache": "warm shared native cache; fresh transaction per arm",
        "scope": "one author, contiguous local IDs favoring primary locality; both indexes written; full query plus decoded payload collection; no pin/copy/block counters"})
    );
    for limit in [50, 500] {
        let value = json!({"authors": [hex::encode(author(0))], "limit": limit});
        let options = QueryOptions::default();
        let baseline = collect_query(
            &env.begin_ro().unwrap(),
            &value,
            AuthorIndex::Thin,
            &options,
        );
        assert_eq!(
            baseline,
            collect_query(
                &env.begin_ro().unwrap(),
                &value,
                AuthorIndex::Covering,
                &options
            )
        );
        let payload_read_bytes: usize = baseline
            .hits
            .iter()
            .map(|hit| hit.payload.as_ref().unwrap().len())
            .sum();
        let mut times = [Vec::new(), Vec::new()];
        for repetition in 0..runs {
            let arms = if repetition % 2 == 0 {
                [AuthorIndex::Thin, AuthorIndex::Covering]
            } else {
                [AuthorIndex::Covering, AuthorIndex::Thin]
            };
            for arm in arms {
                let start = Instant::now();
                let txn = env.begin_ro().unwrap();
                let result = collect_query(&txn, &value, arm, &options);
                drop(txn);
                let elapsed = start.elapsed().as_nanos();
                assert_eq!(result, baseline);
                times[match arm {
                    AuthorIndex::Thin => 0,
                    AuthorIndex::Covering => 1,
                }]
                .push(elapsed);
            }
        }
        for (arm, mut samples) in [AuthorIndex::Thin, AuthorIndex::Covering]
            .into_iter()
            .zip(times)
        {
            samples.sort_unstable();
            println!(
                "{}",
                json!({"index": format!("{arm:?}"), "limit": limit,
                "requests": runs, "sent": baseline.sent_count, "decoded_payload_encoded_bytes": payload_read_bytes,
                "peek_work": baseline.peek_work, "peek_candidates": baseline.peek_candidates,
                "median_ns": samples[samples.len() / 2], "max_ns": samples.last().unwrap(), "samples_ns": samples})
            );
        }
    }
}
