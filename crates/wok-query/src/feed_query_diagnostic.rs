//! Opt-in full-query evidence for chronological author membership, not a planner.
//!
//! The control runs the current planner. The alternative constructs one current
//! CreatedAt cursor, then checks the original author filter on every candidate.
//! DbQuery still owns visibility, latest-ID cuts, deduplication, limits and its
//! ordinary budgeted completeness peek. Single-range batching is unchanged.
//! The original external two-arm harness below remains unbounded. Additional
//! private arms are used only by the separate bounded local prototype tests.
//! A distinct, feature-gated author-frontier entry below selects same-layout
//! Pubkey control versus AuthorHeads; it has its own marker, format and env.
//! The original CreatedAt entry keeps its existing output contract. Neither
//! experiment adds a production planner switch.
//!
//! The ignored harness reuses the exact range diagnostic's input parser and
//! selects only feed500 records, preserving original input indexes and hashes.
//! Required WOK_FEED_DIAGNOSTIC_DB must name a disposable RocksDB copy, never a
//! pristine seed; WOK_FEED_DIAGNOSTIC_FILTERS names the unchanged metadata file.
//! WOK_FEED_DIAGNOSTIC_PASSES is 1..=4 (default 4). Opening/closing native DBs
//! can affect auxiliary files and caches even through the read-only API. Copy
//! provenance, authorization and cleanup belong to the host, not this harness.
//!
//! Each arm uses a fresh transaction/cache. Named counters and instrumented
//! elapsed times include ordinary query work and decoded-body hashing, excluding
//! Env/transaction creation and stored-byte validation. Shared native/OS caches
//! are not reset. No bodies, filter keys or raw records are emitted. Primary pin
//! bytes include whole combined records and do not imply zero-copy or device I/O.

use super::range_seed_diagnostic::{digest, framed, read_inputs};
use super::*;
use crate::{NostrFilterGroup, SubId};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Instant;
use wok_db::read_diagnostics::{measure, ReadMeasurements};
use wok_db::{Env, EnvOptions};

const MAX_FEED_INPUTS: usize = 64;
const MAX_SLICES: usize = 64;

#[derive(Clone, Copy)]
enum DiagnosticComparison {
    CreatedAtMembership,

    AuthorFrontiers,
}

impl DiagnosticComparison {
    fn arms(self, pass: u32, original_index: usize) -> [Arm; 2] {
        let candidate = match self {
            Self::CreatedAtMembership => Arm::CreatedAtMembership,

            Self::AuthorFrontiers => Arm::AuthorHeads,
        };
        // The original external feed indexes are all odd: order alternates by
        // pass, not between adjacent selected feeds. Never renumber them.
        if (pass as usize + original_index) % 2 == 1 {
            [Arm::Pubkey, candidate]
        } else {
            [candidate, Arm::Pubkey]
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Arm {
    Pubkey,

    AuthorHeads,
    CreatedAtMembership,
    BoundedGlobalPeek,
    BoundedAuthorPeek,
}

impl Arm {
    fn name(self) -> &'static str {
        match self {
            Self::Pubkey => "pubkey_control",

            Self::AuthorHeads => "author_frontier_reader",
            Self::CreatedAtMembership => "created_at_membership",
            Self::BoundedGlobalPeek => "bounded_global_peek",
            Self::BoundedAuthorPeek => "bounded_author_peek",
        }
    }

    fn scan(self, filter: &NostrFilter, txn: &RoTxn<'_>) -> DbScan {
        match self {
            Self::Pubkey => {
                #[allow(unused_mut)]
                let mut scan = DbScan::new(filter, txn);

                {
                    // Keep the existing diagnostic's control causal when a
                    // separate frontier experiment is built into this binary.
                    scan.author_head_reads = false;
                }
                scan
            }

            Self::AuthorHeads => DbScan::new(filter, txn),
            Self::BoundedGlobalPeek => super::bounded_feed_diagnostic::configure(
                filter,
                txn,
                super::bounded_feed_diagnostic::PeekPolicy::GlobalUntilCap,
            ),
            Self::BoundedAuthorPeek => super::bounded_feed_diagnostic::configure(
                filter,
                txn,
                super::bounded_feed_diagnostic::PeekPolicy::AuthorOnPeek,
            ),
            Self::CreatedAtMembership => {
                // Only the constructor sees an unscoped seed. The unchanged
                // original filter remains the residual passed to DbQuery.
                // Clearing all selectors also permits focused residual tests;
                // the real-input parser accepts pure author feeds only.
                let mut seed = filter.clone();
                seed.ids = None;
                seed.authors = None;
                seed.kinds = None;
                seed.tags.clear();
                seed.and_tags.clear();
                seed.search = None;
                seed.index_only_scans = false;
                let mut scan = DbScan::new(&seed, txn);
                scan.index_only = false;
                assert_eq!(scan.desc, "CreatedAt");
                assert_eq!(scan.index_dbi, txn.env().dbis().event_created_at);
                scan
            }
        }
    }
}

#[derive(Clone)]
pub(super) struct QueryOptions {
    pub(super) visibility: ReadVisibility,
    pub(super) latest: u64,
    pub(super) max_total: u64,
    pub(super) time_budget_us: u64,
    pub(super) max_slices: usize,
}

impl Default for QueryOptions {
    fn default() -> Self {
        Self {
            visibility: ReadVisibility::default(),
            latest: u64::MAX,
            max_total: 0,
            time_budget_us: u64::MAX,
            max_slices: MAX_SLICES,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Delivery {
    pub(super) ids: Vec<u64>,
    pub(super) sent_count: u64,
    pub(super) body_sha256: String,
    pub(super) body_bytes: u64,
    pub(super) packed_sha256: String,
    pub(super) packed_bytes: u64,
    pub(super) payload_sha256: String,
    pub(super) payload_bytes: u64,
    pub(super) payload_failed: bool,
}

#[derive(Debug)]
pub(super) struct Plan {
    pub(super) desc: &'static str,
    pub(super) index_dbi: u32,
    pub(super) index_only: bool,
    pub(super) cursors: usize,
    pub(super) initial_depth: u64,
    pub(super) refill_depths: Vec<u64>,

    pub(super) author_head_reads: bool,
}

#[derive(Debug)]
pub(super) struct Sample {
    pub(super) delivery: Delivery,
    pub(super) completeness: Completeness,
    pub(super) completed: bool,
    pub(super) plan: Plan,
    pub(super) chronological_work: u64,
    pub(super) peek_work: u64,
    pub(super) peek_candidates: u32,
    // These are cumulative chronological work values, not elapsed-time shares.
    pub(super) slice_work: Vec<u64>,
    pub(super) measurements: ReadMeasurements,

    pub(super) author_frontier_initialization: super::author_head_scan::InitializationStats,
    pub(super) bounded: Option<super::bounded_feed_diagnostic::Stats>,
    pub(super) diagnostic_closure_elapsed_us: u64,
}

pub(super) fn subscription(group: NostrFilterGroup, latest: u64) -> Subscription {
    let mut sub = Subscription::new(
        1,
        SubId::new("feed-query-diagnostic").unwrap(),
        group,
        false,
    );
    sub.latest_event_id = latest;
    sub
}

pub(super) fn read_arm(
    env: &Env,
    group: &NostrFilterGroup,
    arm: Arm,
    options: &QueryOptions,
) -> Result<Sample, String> {
    if group.filters.is_empty() || group.filters.iter().any(|f| f.search.is_some()) {
        return Err("diagnostic requires chronological filters".into());
    }
    // All real inputs have one filter. The private frontier control below also
    // applies to later chronological scanners/peeks in a multi-filter fixture;
    // the original forced CreatedAt/bounded path still seeds only filter zero.
    let tx = env.begin_ro().map_err(|_| "cannot begin read snapshot")?;
    let mut query = DbQuery::new(
        subscription(group.clone(), options.latest),
        options.max_total,
        0,
    );
    query.track_completeness();
    query.set_visibility(options.visibility.clone());

    {
        query.diagnostic_author_head_reads = Some(matches!(arm, Arm::AuthorHeads));
    }
    let mut ids = Vec::new();
    let mut body_hash = Sha256::new();
    let mut body_bytes = 0u64;
    let mut payload_failed = false;
    let mut decompressor = Decompressor::new();
    let (run, measurements) = measure(|| {
        let start = Instant::now();
        let scan = arm.scan(&group.filters[0], &tx);
        let plan = Plan {
            desc: scan.desc,
            index_dbi: scan.index_dbi,
            index_only: scan.index_only,
            cursors: scan.cursor_count(),
            initial_depth: scan.initial_scan_depth,
            refill_depths: scan.refill_scan_depths.clone(),

            author_head_reads: scan.author_head_reads,
        };
        query.scanner = Some(QueryScanner::Chronological(scan));
        let mut completed = false;
        let mut slice_work = Vec::new();
        for _ in 0..options.max_slices {
            completed = query
                .process_with(
                    &tx,
                    |_, id| {
                        ids.push(id);
                        match wok_db::event_json_owned(&tx, &mut decompressor, id, 1 << 20) {
                            Ok(body) => {
                                framed(&mut body_hash, id, body.as_bytes());
                                body_bytes += body.len() as u64;
                            }
                            Err(_) => payload_failed = true,
                        }
                    },
                    options.time_budget_us,
                    &mut Decompressor::new(),
                )
                .map_err(|_| "query processing failed")?;
            if payload_failed {
                query.mark_incomplete();
            }
            slice_work.push(query.diagnostic_chronological_work);
            if completed || query.dead {
                break;
            }
        }
        if query.dead {
            return Err("chronological query died");
        }
        Ok((
            plan,
            completed,
            slice_work,
            u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX),
        ))
    })
    .map_err(|_| "nested diagnostic measurement")?;
    let (plan, completed, slice_work, elapsed) = run?;
    if ids.len() as u64 != query.sent_count() {
        return Err("query sent-count validation failed".into());
    }
    // Exact stored bytes are checked in the same immutable snapshot but outside
    // the measured scope, so validation does not add primary-cache hits.
    let mut packed_hash = Sha256::new();
    let mut payload_hash = Sha256::new();
    let (mut packed_bytes, mut payload_bytes) = (0u64, 0u64);
    for id in &ids {
        let packed = tx
            .get_u64(env.dbis().event, *id)
            .map_err(|_| "stored packed read failed")?
            .ok_or("stored packed bytes are absent")?;
        let payload = tx
            .get_u64(env.dbis().event_payload, *id)
            .map_err(|_| "stored payload read failed")?
            .ok_or("stored payload bytes are absent")?;
        framed(&mut packed_hash, *id, packed);
        framed(&mut payload_hash, *id, payload);
        packed_bytes += packed.len() as u64;
        payload_bytes += payload.len() as u64;
    }
    Ok(Sample {
        delivery: Delivery {
            ids,
            sent_count: query.sent_count(),
            body_sha256: hex::encode(body_hash.finalize()),
            body_bytes,
            packed_sha256: hex::encode(packed_hash.finalize()),
            packed_bytes,
            payload_sha256: hex::encode(payload_hash.finalize()),
            payload_bytes,
            payload_failed,
        },
        completeness: query.completeness(),
        completed,
        plan,
        chronological_work: query.diagnostic_chronological_work,
        peek_work: PEEK_WORK - query.peek_budget.work,
        peek_candidates: PEEK_CANDIDATES - query.peek_budget.candidates,
        slice_work,
        measurements,

        author_frontier_initialization: query.diagnostic_author_frontier_initialization,
        bounded: query.diagnostic_feed_stats,
        diagnostic_closure_elapsed_us: elapsed,
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn sample_json(
    sample: &Sample,
    input_index: usize,
    filter_sha256: &str,
    pass: u32,
    arm: Arm,
    ordinal: usize,
    delivery_equal: bool,
    completeness_equal: bool,
    pair_equivalent: bool,
) -> Value {
    let d = &sample.delivery;
    let p = &sample.plan;
    json!({
        "pass":pass,"input_index":input_index,"shape":"feed500","filter_sha256":filter_sha256,
        "arm":arm.name(),"arm_ordinal":ordinal,"completed":sample.completed,"completeness_final":sample.completed,
        "delivery_equal":delivery_equal,"completeness_equal":completeness_equal,"pair_equivalent":pair_equivalent,
        "ordered_local_ids":d.ids,"sent_count":d.sent_count,
        "body_sha256":d.body_sha256,"body_bytes":d.body_bytes,"payload_failed":d.payload_failed,
        "packed_sha256":d.packed_sha256,"packed_bytes":d.packed_bytes,
        "payload_sha256":d.payload_sha256,"payload_bytes":d.payload_bytes,
        "completeness":{"finish":sample.completeness.finish,"more":sample.completeness.more,"restricted":sample.completeness.restricted},
        "chronological_work":sample.chronological_work,"peek_work":sample.peek_work,"peek_candidates":sample.peek_candidates,
        "slice_work":sample.slice_work,"plan":{"desc":p.desc,"index_dbi":p.index_dbi,"index_only":p.index_only,"cursors":p.cursors,"initial_depth":p.initial_depth,"refill_depths":p.refill_depths},
        "measurements":sample.measurements,"diagnostic_closure_elapsed_us":sample.diagnostic_closure_elapsed_us
    })
}

fn diagnose(database: &Path, filters: &Path, passes: u32) -> Result<Value, String> {
    diagnose_with_options(
        database,
        filters,
        passes,
        &QueryOptions {
            time_budget_us: 0,
            ..QueryOptions::default()
        },
    )
}

fn diagnose_with_options(
    database: &Path,
    filters: &Path,
    passes: u32,
    options: &QueryOptions,
) -> Result<Value, String> {
    diagnose_comparison(
        database,
        filters,
        passes,
        options,
        DiagnosticComparison::CreatedAtMembership,
    )
}

fn read_comparison_arm(
    env: &Env,
    group: &NostrFilterGroup,
    arm: Arm,
    options: &QueryOptions,
    comparison: DiagnosticComparison,
) -> Result<Sample, String> {
    let sample = read_arm(env, group, arm, options)?;

    if matches!(comparison, DiagnosticComparison::AuthorFrontiers) {
        validate_frontier_sample(&sample, arm)?;
    }
    let _ = comparison;
    Ok(sample)
}

#[allow(clippy::too_many_arguments)]
fn comparison_sample_json(
    sample: &Sample,
    input_index: usize,
    filter_sha256: &str,
    pass: u32,
    arm: Arm,
    ordinal: usize,
    delivery_equal: bool,
    completeness_equal: bool,
    pair_equivalent: bool,
    comparison: DiagnosticComparison,
    logical_work_equal: Option<bool>,
) -> Value {
    #[allow(unused_mut)]
    let mut row = sample_json(
        sample,
        input_index,
        filter_sha256,
        pass,
        arm,
        ordinal,
        delivery_equal,
        completeness_equal,
        pair_equivalent,
    );

    if matches!(comparison, DiagnosticComparison::AuthorFrontiers) {
        let object = row.as_object_mut().expect("sample object");
        // Keep the old formatter/contract unchanged. The new result reports no
        // instrumented elapsed time and no 500-element refill-depth arrays.
        object.remove("diagnostic_closure_elapsed_us");
        let plan = object
            .get_mut("plan")
            .expect("plan")
            .as_object_mut()
            .expect("plan object");
        plan.remove("refill_depths");
        plan.insert(
            "initial_refill_depths_summary".into(),
            json!({
                "count":sample.plan.refill_depths.len(),
                "min":sample.plan.refill_depths.iter().min(),
                "max":sample.plan.refill_depths.iter().max()
            }),
        );
        let stats = sample.author_frontier_initialization;
        object.insert("author_frontier_initialization".into(),json!({
            "reader_enabled":sample.plan.author_head_reads,
            "eligible_range_count":sample.plan.cursors,
            "issued_keys":stats.issued_keys,"classified_keys":stats.classified_keys(),
            "seeded_heads":stats.seeded_heads,"fallback_missing":stats.fallback_missing,
            "fallback_below_since":stats.fallback_below_since,
            "fallback_above_until":stats.fallback_above_until,
            "fallback_unsupported_timestamp":stats.fallback_unsupported_timestamp,
            "fallback_postings_collected":stats.fallback_postings_collected,
            "failed_batch_keys":stats.failed_batch_keys,"failed_batch_calls":stats.failed_batch_calls,
            "unclassified_issued_keys":stats.issued_keys.saturating_sub(stats.classified_keys()),
            "header_keys_during_peek":stats.header_keys_during_peek,
            "scope":"Actual initialization outcomes only; no extra reads. An issued batch error need not be a decode error. Failed-arm in-flight observations are unavailable under the existing error-retention contract."
        }));
        object.insert("logical_work_equal".into(), json!(logical_work_equal));
    }
    let _ = (comparison, logical_work_equal);
    row
}

fn diagnose_comparison(
    database: &Path,
    filters: &Path,
    passes: u32,
    options: &QueryOptions,
    comparison: DiagnosticComparison,
) -> Result<Value, String> {
    if !(1..=4).contains(&passes) {
        return Err("passes must be1..=4".into());
    }
    let (inputs, filters_sha256) = read_inputs(filters)?;
    let feed_inputs: Vec<_> = inputs
        .iter()
        .enumerate()
        .filter(|(_, input)| input.shape == "feed500")
        .collect();
    if feed_inputs.is_empty() || feed_inputs.len() > MAX_FEED_INPUTS {
        return Err("metadata input must contain1..=64 feed500 records".into());
    }
    let database = database
        .canonicalize()
        .map_err(|_| "database path does not exist")?;
    if !database.is_dir() || !database.join("CURRENT").is_file() {
        return Err("database must be an existing disposable RocksDB copy".into());
    }
    let env = Env::open(
        &database,
        EnvOptions {
            read_only: true,
            create_dir: false,
            create_dbis: false,
            ..EnvOptions::default()
        },
    )
    .map_err(|_| "read-only disposable database open failed")?;
    let mut records = Vec::new();
    let mut differences = Vec::new();
    let mut limited = Vec::new();
    let mut errors = Vec::new();
    for pass in 1..=passes {
        for &(index, input) in &feed_inputs {
            let arms = comparison.arms(pass, index);
            let first = read_comparison_arm(&env, &input.group, arms[0], options, comparison);
            let second = read_comparison_arm(&env, &input.group, arms[1], options, comparison);
            let (first, second) = match (first, second) {
                (Ok(first), Ok(second)) => (first, second),
                results => {
                    // Preserve all earlier complete pairs and either available
                    // arm from this pair. A processing error is never equality.
                    for (ordinal, result) in [results.0, results.1].into_iter().enumerate() {
                        match result {
                            Ok(sample) => records.push(comparison_sample_json(&sample,index,&input.filter_sha256,pass,arms[ordinal],ordinal,false,false,false,comparison,None)),
                            Err(error) => errors.push(json!({"pass":pass,"input_index":index,"filter_sha256":input.filter_sha256,"arm":arms[ordinal].name(),"arm_ordinal":ordinal,"error":error})),
                        }
                    }
                    continue;
                }
            };
            let completed = first.completed && second.completed;
            let logical_work_equal = first.chronological_work == second.chronological_work;
            let delivery_equal = first.delivery == second.delivery;
            let completeness_equal = first.completeness == second.completeness;
            let equivalent = completed
                && delivery_equal
                && completeness_equal
                && !first.delivery.payload_failed
                && !second.delivery.payload_failed;
            if !completed {
                limited.push(
                    json!({"pass":pass,"input_index":index,"filter_sha256":input.filter_sha256}),
                );
            } else if !equivalent {
                differences.push(json!({"pass":pass,"input_index":index,"filter_sha256":input.filter_sha256,"delivery_equal":delivery_equal,"completeness_equal":completeness_equal}));
            }
            for (ordinal, (sample, arm)) in [(first, arms[0]), (second, arms[1])]
                .into_iter()
                .enumerate()
            {
                records.push(comparison_sample_json(
                    &sample,
                    index,
                    &input.filter_sha256,
                    pass,
                    arm,
                    ordinal,
                    delivery_equal,
                    completeness_equal,
                    equivalent,
                    comparison,
                    Some(logical_work_equal),
                ));
            }
        }
    }
    drop(env);
    let payload_failed = records.iter().any(|r| r["payload_failed"] == true);
    let status = if !errors.is_empty() {
        "processing_error"
    } else if payload_failed {
        "payload_error"
    } else if !limited.is_empty() {
        "processing_limit"
    } else if !differences.is_empty() {
        "completed_differences"
    } else {
        "passed"
    };
    #[allow(unused_mut)]
    let mut report = json!({
        "format":"wok-feed-query-diagnostic-v1","status":status,"database_closed":true,
        "database_path":database,"env_read_only":true,"env_create_dir":false,"env_create_dbis":false,
        "filters_path":filters,"filters_sha256":filters_sha256,"input_records":inputs.len(),"selected_feed_records":feed_inputs.len(),
        "passes":passes,"pairs_checked":feed_inputs.len()*passes as usize,"arm_query_executions":records.len(),
        "arm_query_attempts":feed_inputs.len()*passes as usize*2,"recorded_arm_results":records.len(),
        "execution_limits":{"time_budget_us":options.time_budget_us,"max_slices":options.max_slices,"work_check_interval":2000,"snapshot_refresh_between_slices":false},
        "records":records,"all_pairs_equivalent":errors.is_empty()&&differences.is_empty()&&limited.is_empty()&&!payload_failed,
        "different_pairs":differences,"processing_limited_pairs":limited,"processing_errors":errors,
        "harness_source_sha256":digest(include_bytes!("feed_query_diagnostic.rs")),
        "input_parser_source_sha256":digest(include_bytes!("range_seed_diagnostic.rs")),
        "storage_backend":wok_db::storage_backend_name(),"thin_author_feature":true,
        "digest_framing":"Ordered local-ID u64 big-endian, length u64 big-endian, exact component bytes; separate SHA-256 streams for packed, encoded payload and decoded body.",
        "scope":"One fresh transaction per arm, unchanged control planner versus forced CreatedAt with original authors residual and index_only=false. Normal DbQuery visibility, latest, dedup, limit50, completeness and payload callbacks. External harness uses zero-microsecond slices at normal >2000-work checks and at most64 slices per arm; exact limits recorded separately. Same snapshot retained across slices, unlike worker-pass refresh. Planning/query/body hashing measured; opening and exact stored-byte validation excluded. Native/OS caches shared; alternating order does not reset them.",
        "limits":"This is a full-query forced-plan diagnostic, not a bounded planner or network timing. Plan-specific work/counters are reported, not required equal. Higher residual work can exhaust the normal completeness peek sooner: such a hint difference makes strict pair_equivalent false even when conservative Unknown is truthful. Interrupted or payload-failed queries never pass; completeness on an interrupted result is not final. Exact valid-record equivalence does not promise identical malformed-primary detection between index-only and residual plans; full offline corruption auditing is separate. Returned primary-pin bytes can include combined payload bytes; named copies are partial, native block reads are not device I/O. Copy/input/build provenance belongs to host. No sparse/adverse15M input is authorized by this harness."
    });

    if matches!(comparison, DiagnosticComparison::AuthorFrontiers) {
        decorate_frontier_report(&mut report);
        report["selected_original_input_indexes"] = json!(feed_inputs
            .iter()
            .map(|(index, _)| *index)
            .collect::<Vec<_>>());
    }
    Ok(report)
}

fn explicit_path(name: &str) -> PathBuf {
    std::env::var_os(name)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("{name} must name an explicit disposable diagnostic input"))
}

#[test]
#[ignore = "requires separately authorized disposable database copy and retained dense feed metadata"]
fn diagnose_existing_seed_feeds() {
    let passes = match std::env::var("WOK_FEED_DIAGNOSTIC_PASSES") {
        Ok(s) => s.parse::<u32>().expect("passes must be1..=4"),
        Err(std::env::VarError::NotPresent) => 4,
        Err(_) => panic!("passes must be UTF-8"),
    };
    let report = diagnose(
        &explicit_path("WOK_FEED_DIAGNOSTIC_DB"),
        &explicit_path("WOK_FEED_DIAGNOSTIC_FILTERS"),
        passes,
    )
    .unwrap_or_else(|e| panic!("feed diagnostic processing_error: {e}"));
    println!("WOK_FEED_DIAGNOSTIC_RESULT={report}");
    assert_eq!(
        report["status"], "passed",
        "full strict pair comparison failed"
    );
}

use crate::visibility::ReadRestrictor;
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use wok_db::{write_events, EventToWrite, NoopNegentropy};
use wok_event::{PackedEventBuilder, PackedEventTagBuilder};

const BASE: u64 = 1_700_000_000;

pub(super) struct Fixture {
    pub(super) dir: tempfile::TempDir,
    pub(super) env: Env,
    pub(super) events: Vec<EventToWrite>,
}

pub(super) fn author(n: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&n.to_be_bytes());
    bytes
}

pub(super) fn event(n: u64, who: u64, created: u64, kind: u64, expiration: u64) -> EventToWrite {
    let mut id = [0u8; 32];
    id[..8].copy_from_slice(&n.to_be_bytes());
    let mut tags = PackedEventTagBuilder::default();
    tags.add('t', if n.is_multiple_of(2) { b"red" } else { b"blue" })
        .unwrap();
    tags.add('p', &author(9)).unwrap();
    let packed =
        PackedEventBuilder::build(&id, &author(who), created, kind, expiration, &tags).unwrap();
    EventToWrite::new(
        packed.into_bytes(),
        wok_event::json::to_tao_string(&json!({
            "content":format!("feed {n}: 🥘\u{7f} {}", "body".repeat(128))
        })),
    )
}

pub(super) fn store(mut events: Vec<EventToWrite>) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    // A single sorted write batch would make global chronology and primary-ID
    // locality almost identical. Randomize multiple independent write batches
    // so these correctness fixtures cannot rely on that allocation pattern.
    events.shuffle(&mut StdRng::seed_from_u64(0xC692_FEED));
    for batch in events.chunks_mut(191) {
        let mut txn = env.begin_rw().unwrap();
        write_events(&mut txn, &mut NoopNegentropy, batch, false).unwrap();
        txn.commit().unwrap();
    }
    Fixture { dir, env, events }
}

pub(super) fn group(value: &Value) -> NostrFilterGroup {
    NostrFilterGroup::from_value(value, 10_000, 8, 16).unwrap()
}

pub(super) fn feed(authors: impl Iterator<Item = u64>, limit: u64) -> Value {
    json!({"authors":authors.map(|n|hex::encode(author(n))).collect::<Vec<_>>(),"until":BASE+20000,"limit":limit})
}

pub(super) fn dense_events(authors: u64, depths: u64, hidden: bool) -> Vec<EventToWrite> {
    (0..authors * depths)
        .map(|n| {
            let kind = if hidden && n % 11 == 0 {
                22242
            } else if hidden && n % 7 == 0 {
                4
            } else if n % 3 == 0 {
                7
            } else {
                1
            };
            event(
                n + 1,
                n % authors,
                if n % 211 == 0 {
                    0
                } else {
                    BASE + (n * 7919 % 128)
                },
                kind,
                if hidden && n % 13 == 0 { 2 } else { 0 },
            )
        })
        .collect()
}

pub(super) fn expected(
    fixture: &Fixture,
    group: &NostrFilterGroup,
    options: &QueryOptions,
) -> Vec<u64> {
    let tx = fixture.env.begin_ro().unwrap();
    let snapshot = ReadSnapshot::for_stored(&tx);
    let mut seen = HashSet::new();
    let mut output = Vec::new();
    for filter in &group.filters {
        let mut matching: Vec<_> = fixture
            .events
            .iter()
            .filter_map(|event| {
                let packed = PackedEventView::new(&event.packed).unwrap();
                (event.lev_id <= options.latest
                    && filter.does_match(packed)
                    && options.visibility.allows(&snapshot, packed).unwrap())
                .then_some((packed.created_at(), event.lev_id))
            })
            .collect();
        matching.sort_unstable_by(|a, b| b.cmp(a));
        // Per-filter limits count prior-filter duplicates too, as DbQuery does.
        for (_, id) in matching.into_iter().take(filter.limit as usize) {
            if seen.insert(id) {
                output.push(id);
            }
            if options.max_total != 0 && output.len() as u64 >= options.max_total {
                return output;
            }
        }
    }
    output
}

pub(super) fn pair(
    fixture: &Fixture,
    group: &NostrFilterGroup,
    options: &QueryOptions,
) -> (Sample, Sample) {
    let control = read_arm(&fixture.env, group, Arm::Pubkey, options).unwrap();
    let global = read_arm(&fixture.env, group, Arm::CreatedAtMembership, options).unwrap();
    assert!(control.completed && global.completed);
    assert!(!control.delivery.payload_failed && !global.delivery.payload_failed);
    assert_eq!(control.delivery, global.delivery);
    assert_eq!(control.delivery.ids, expected(fixture, group, options));
    (control, global)
}

pub(super) fn fixture_evidence(
    label: &str,
    filter: &Value,
    control: &Sample,
    global: &Sample,
    budget: u64,
) {
    let filter_sha256 = digest(wok_event::json::to_tao_string(filter).as_bytes());
    let delivery_equal = control.delivery == global.delivery;
    let completeness_equal = control.completeness == global.completeness;
    let equivalent = control.completed
        && global.completed
        && delivery_equal
        && completeness_equal
        && !control.delivery.payload_failed
        && !global.delivery.payload_failed;
    let report = json!({
        "format":"wok-feed-fixture-operation-evidence-v1","label":label,"time_budget_us":budget,
        "harness_source_sha256":digest(include_bytes!("feed_query_diagnostic.rs")),
        "scope":"Deterministic small, multi-batch shuffled fixture; full DbQuery with fresh transaction per arm, body hashes and counters. Instrumented closure times are not clean timings or large-seed estimates.",
        "records":[
            sample_json(control,0,&filter_sha256,1,Arm::Pubkey,0,delivery_equal,completeness_equal,equivalent),
            sample_json(global,0,&filter_sha256,1,Arm::CreatedAtMembership,1,delivery_equal,completeness_equal,equivalent)
        ]
    });
    println!("WOK_FEED_LOCAL_OPERATION_RESULT={report}");
}

#[test]
fn full_dense_feeds_preserve_ties_cuts_payloads_and_charge_different_work() {
    let fixture = store(dense_events(2048, 3, false));
    // Confirm chronology does move backwards as IDs increase between batches.
    let mut by_id: Vec<_> = fixture.events.iter().collect();
    by_id.sort_unstable_by_key(|event| event.lev_id);
    assert!(by_id.windows(2).any(|pair| {
        PackedEventView::new(&pair[0].packed).unwrap().created_at()
            > PackedEventView::new(&pair[1].packed).unwrap().created_at()
    }));
    for (authors, since, until) in [
        (500, 0, BASE + 127),
        (500, BASE + 62, BASE + 62),
        (500, 0, 0),
        (500, BASE + 100, BASE + 20),
        (2047, BASE + 20, u64::MAX),
    ] {
        let mut value = feed(0..authors, 50);
        value["since"] = json!(since);
        value["until"] = json!(until);
        let group = group(&value);
        let (control, global) = pair(&fixture, &group, &QueryOptions::default());
        assert_eq!(control.completeness, global.completeness);
        assert_eq!(control.plan.desc, "Pubkey");
        assert_eq!(control.plan.cursors, authors as usize);
        assert_eq!(global.plan.cursors, 1);
        assert!(!global.plan.index_only);
        assert_eq!(global.plan.initial_depth, 50);
        assert_eq!(global.plan.refill_depths, vec![500]);
        if since == 0 && until == BASE + 127 {
            assert!(global.measurements.wrapper.seek < control.measurements.wrapper.seek);
            assert!(
                global.measurements.wrapper.primary_pin_lookups
                    > control.measurements.wrapper.primary_pin_lookups
            );
            assert!(global.chronological_work > control.chronological_work);
            assert!(
                global.measurements.wrapper.primary_pin_returned_bytes
                    > control.measurements.wrapper.primary_pin_returned_bytes
            );
            fixture_evidence("dense500_of2048", &value, &control, &global, u64::MAX);
        }
        assert_eq!(global.measurements.wrapper.generic_row_materializations, 0);
    }
}

#[test]
fn sparse_adverse_and_missing_feeds_exhaust_with_charged_primary_reads() {
    let mut events: Vec<_> = (0..1536)
        .map(|n| event(n + 1, 1000 + n % 1024, BASE + 1000 + n / 3, 1, 0))
        .collect();
    events.extend((0..20).map(|n| event(2000 + n, n % 5, BASE + n, 1, 0)));
    let fixture = store(events);
    let options = QueryOptions {
        time_budget_us: 0,
        ..QueryOptions::default()
    };
    for authors in [
        (0..5).chain(3000..3495).collect::<Vec<_>>(),
        (3000..3500).collect(),
    ] {
        let filter = feed(authors.into_iter(), 50);
        let group = group(&filter);
        let (control, global) = pair(&fixture, &group, &options);
        assert_eq!(control.completeness, global.completeness);
        assert!(global.completeness.finish && !global.completeness.more);
        assert!(global.slice_work.len() > 1);
        assert!(global.slice_work.windows(2).all(|w| w[1] > w[0]));
        assert!(global.measurements.wrapper.primary_pin_lookups >= fixture.events.len() as u64);
        assert!(global.chronological_work > 10 * fixture.events.len() as u64);
        assert!(global.chronological_work > control.chronological_work);
        fixture_evidence(
            if global.delivery.ids.is_empty() {
                "absent500"
            } else {
                "adverse_sparse500"
            },
            &filter,
            &control,
            &global,
            0,
        );
    }
    let incomplete = read_arm(
        &fixture.env,
        &group(&feed(3000..3500, 50)),
        Arm::CreatedAtMembership,
        &QueryOptions {
            time_budget_us: 0,
            max_slices: 1,
            ..QueryOptions::default()
        },
    )
    .unwrap();
    assert!(!incomplete.completed);
    assert!(incomplete.chronological_work > 2000);
    assert_eq!(incomplete.slice_work.len(), 1);
}

#[test]
fn visibility_residual_filters_latest_and_dictionary_bodies_use_normal_query_rules() {
    let fixture = store(dense_events(512, 5, true));
    let chosen = fixture
        .events
        .iter()
        .find(|event| {
            let p = PackedEventView::new(&event.packed).unwrap();
            p.pubkey() == author(0) && p.kind() == 1 && p.expiration() == 0
        })
        .unwrap();
    let dictionary = b"feed content body red blue".repeat(64);
    let mut tx = fixture.env.begin_rw().unwrap();
    let dict_id =
        u32::try_from(wok_db::insert_compression_dictionary(&mut tx, &dictionary).unwrap())
            .unwrap();
    let compressed = zstd::bulk::Compressor::with_dictionary(3, &dictionary)
        .unwrap()
        .compress(chosen.json.as_bytes())
        .unwrap();
    tx.put_u64(
        fixture.env.dbis().event_payload,
        chosen.lev_id,
        &wok_db::encode_zstd_payload(dict_id, &compressed),
        0,
    )
    .unwrap();
    tx.commit().unwrap();
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
            latest: fixture
                .events
                .iter()
                .map(|event| event.lev_id)
                .max()
                .unwrap()
                - 100,
            time_budget_us: 0,
            ..QueryOptions::default()
        };
        for residual in [false, true] {
            let mut value = feed(0..500, 1000);
            if residual {
                value["#t"] = json!(["red"]);
                value["kinds"] = json!([1, 4, 7]);
            }
            let (control, global) = pair(&fixture, &group(&value), &options);
            assert_eq!(control.completeness, global.completeness);
            assert_eq!(
                control.completeness.restricted,
                options.visibility.identities.is_empty()
            );
        }
    }
    // Include the dictionary-backed record and exhaust, not merely the limit's
    // newest rows; its exact encoded and decoded components must match too.
    let (control, global) = pair(
        &fixture,
        &group(&feed(0..500, 10000)),
        &QueryOptions::default(),
    );
    assert!(control.delivery.ids.contains(&chosen.lev_id));
    assert_eq!(control.completeness, global.completeness);
    assert!(global.completeness.finish);
}

#[test]
fn current_peek_budget_can_change_only_the_conservative_completeness_hint() {
    let mut events: Vec<_> = (0..50)
        .map(|n| event(n + 1, 0, BASE + 20000, 1, 0))
        .collect();
    events.extend((0..700).map(|n| event(1000 + n, 1000 + n % 512, BASE + 19000, 1, 0)));
    events.push(event(2000, 1, BASE + 18000, 1, 0));
    let fixture = store(events);
    let (control, global) = pair(
        &fixture,
        &group(&feed(0..500, 50)),
        &QueryOptions::default(),
    );
    assert!(control.completeness.more && !control.completeness.finish);
    assert_eq!(global.completeness, Completeness::default());
    assert_eq!(global.peek_work, PEEK_WORK);
    assert!(global.chronological_work > control.chronological_work);
    assert!(!global.completeness.more && !global.completeness.finish);
    // Strict semantic equality must reject this otherwise equal delivery pair.
    assert_ne!(control.completeness, global.completeness);
    fixture_evidence(
        "adverse_completeness_tail",
        &feed(0..500, 50),
        &control,
        &global,
        u64::MAX,
    );
}

#[test]
fn partial_filter_continuations_deduplicate_and_preserve_request_cap_peeks() {
    let fixture = store(dense_events(512, 4, false));
    let filters = json!([
        feed(0..500, 10),
        {"authors":(0..512).map(|n|hex::encode(author(n))).collect::<Vec<_>>(),"limit":100,"until":BASE+127}
    ]);
    for max_total in [0, 12] {
        let options = QueryOptions {
            max_total,
            time_budget_us: 0,
            ..QueryOptions::default()
        };
        let (control, global) = pair(&fixture, &group(&filters), &options);
        assert_eq!(control.completeness, global.completeness);
        assert!(global.completeness.more);
        assert!(control.slice_work.len() > 1 && global.slice_work.len() > 1);
        assert_eq!(
            global.delivery.ids.len(),
            global.delivery.ids.iter().collect::<HashSet<_>>().len()
        );
    }
}

#[test]
fn owned_resume_state_survives_snapshot_refresh_and_excludes_new_backdated_ids() {
    let fixture = store(dense_events(512, 6, false));
    let group = group(&feed(0..500, 10000));
    let latest = fixture
        .events
        .iter()
        .map(|event| event.lev_id)
        .max()
        .unwrap();
    let expected = expected(
        &fixture,
        &group,
        &QueryOptions {
            latest,
            ..QueryOptions::default()
        },
    );
    for (round, arm) in [Arm::Pubkey, Arm::CreatedAtMembership]
        .into_iter()
        .enumerate()
    {
        let mut query = DbQuery::new(subscription(group.clone(), latest), 0, 0);
        query.track_completeness();
        let mut ids = Vec::new();
        let mut bodies = 0;
        let mut prior_work = 0;
        let mut slices = 0;
        loop {
            let tx = fixture.env.begin_ro().unwrap();
            if slices == 0 {
                query.scanner = Some(QueryScanner::Chronological(
                    arm.scan(&group.filters[0], &tx),
                ));
            }
            let mut decompressor = Decompressor::new();
            let complete = query
                .process(
                    &tx,
                    |_, id| {
                        ids.push(id);
                        bodies += wok_db::event_json_owned(&tx, &mut decompressor, id, 1 << 20)
                            .unwrap()
                            .len();
                    },
                    0,
                )
                .unwrap();
            assert!(query.diagnostic_chronological_work > prior_work);
            prior_work = query.diagnostic_chronological_work;
            drop(tx); // no native iterator, transaction borrow or pin in query
            slices += 1;
            if slices == 1 {
                assert!(!complete);
                let mut inserted = (0..64)
                    .map(|n| event(100000 + round as u64 * 1000 + n, n, BASE + 64, 1, 0))
                    .collect::<Vec<_>>();
                let mut tx = fixture.env.begin_rw().unwrap();
                write_events(&mut tx, &mut NoopNegentropy, &mut inserted, false).unwrap();
                tx.commit().unwrap();
                assert!(inserted.iter().all(|event| event.lev_id > latest));
            }
            if complete {
                break;
            }
            assert!(slices < MAX_SLICES);
        }
        assert_eq!(ids, expected);
        assert!(bodies > ids.len() * 500);
        assert!(slices > 1);
        assert!(query.completeness().finish);
    }
}

#[test]
fn failed_body_delivery_keeps_completeness_conservative_in_both_plans() {
    let fixture = store(
        (0..30)
            .map(|n| event(n + 1, n % 5, BASE + n, 1, 0))
            .collect(),
    );
    let id = fixture.events[0].lev_id;
    let mut tx = fixture.env.begin_rw().unwrap();
    tx.put_u64(fixture.env.dbis().event_payload, id, &[0xFF], 0)
        .unwrap();
    tx.commit().unwrap();
    let group = group(&feed(0..500, 50));
    let control = read_arm(&fixture.env, &group, Arm::Pubkey, &QueryOptions::default()).unwrap();
    let global = read_arm(
        &fixture.env,
        &group,
        Arm::CreatedAtMembership,
        &QueryOptions::default(),
    )
    .unwrap();
    assert!(control.completed && global.completed);
    assert!(control.delivery.payload_failed && global.delivery.payload_failed);
    assert_eq!(control.delivery, global.delivery);
    assert_eq!(control.completeness, global.completeness);
    assert!(!global.completeness.finish);
}

#[test]
fn unchanged_metadata_parser_selection_pairing_and_readonly_closure_smoke() {
    let Fixture {
        dir,
        env,
        events: _,
    } = store(dense_events(512, 4, false));
    drop(env);
    let filters = dir.path().join("retained-metadata.json");
    let records = json!([
        {"shape":"tag","filter":{"#t":["red"],"limit":50,"until":BASE+127}},
        {"shape":"feed500","filter":feed(0..500,50)},
        {"shape":"author","filter":{"authors":[hex::encode(author(0))],"limit":50,"until":BASE+127}},
        {"shape":"feed500","filter":feed(12..512,50)}
    ]);
    let input_bytes = wok_event::json::to_tao_string(&records);
    std::fs::write(&filters, &input_bytes).unwrap();
    assert!(diagnose(dir.path(), &filters, 0).is_err());
    assert!(diagnose(dir.path(), &filters, 5).is_err());
    let report = diagnose(dir.path(), &filters, 2).unwrap();
    assert_eq!(report["status"], "passed");
    assert_eq!(report["database_closed"], true);
    assert_eq!(report["filters_sha256"], digest(input_bytes.as_bytes()));
    assert_eq!(report["input_records"], 4);
    assert_eq!(report["selected_feed_records"], 2);
    assert_eq!(report["pairs_checked"], 4);
    let rows = report["records"].as_array().unwrap();
    assert_eq!(rows.len(), 8);
    for pair in rows.as_chunks::<2>().0 {
        assert!(pair
            .iter()
            .all(|r| r["pair_equivalent"] == true && r["completed"] == true));
        assert_eq!(pair[0]["input_index"], pair[1]["input_index"]);
        assert_eq!(pair[0]["filter_sha256"], pair[1]["filter_sha256"]);
        assert!([json!(1), json!(3)].contains(&pair[0]["input_index"]));
        assert_ne!(pair[0]["arm"], pair[1]["arm"]);
        let global = pair
            .iter()
            .find(|r| r["arm"] == "created_at_membership")
            .unwrap();
        assert_eq!(global["plan"]["desc"], "CreatedAt");
        assert_eq!(global["plan"]["index_only"], false);
        assert!(global["measurements"]["wrapper"].is_object());
        assert!(global["measurements"]["native"].is_object());
    }
    // Reopening for writes proves all read-only handles were released.
    drop(
        Env::open(
            dir.path(),
            EnvOptions {
                create_dir: false,
                create_dbis: false,
                ..EnvOptions::for_tests()
            },
        )
        .unwrap(),
    );
    std::fs::write(
        &filters,
        wok_event::json::to_tao_string(&json!([records[0].clone()])),
    )
    .unwrap();
    assert!(diagnose(dir.path(), &filters, 1).is_err());
}

#[test]
fn report_retains_hint_differences_and_never_passes_limited_or_failed_payload_pairs() {
    let mut events: Vec<_> = (0..50)
        .map(|n| event(n + 1, 0, BASE + 20000, 1, 0))
        .collect();
    events.extend((0..700).map(|n| event(1000 + n, 1000 + n % 512, BASE + 19000, 1, 0)));
    events.push(event(2000, 1, BASE + 18000, 1, 0));
    let Fixture {
        dir,
        env,
        events: _,
    } = store(events);
    drop(env);
    let filters = dir.path().join("metadata.json");
    std::fs::write(
        &filters,
        wok_event::json::to_tao_string(&json!([
            {"shape":"feed500","filter":feed(0..500,50)}
        ])),
    )
    .unwrap();
    let report = diagnose(dir.path(), &filters, 1).unwrap();
    assert_eq!(report["status"], "completed_differences");
    assert_eq!(report["records"].as_array().unwrap().len(), 2);
    assert_eq!(report["different_pairs"].as_array().unwrap().len(), 1);
    assert_eq!(report["all_pairs_equivalent"], false);
    assert!(report["records"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["delivery_equal"] == true
            && r["completeness_equal"] == false
            && r["pair_equivalent"] == false));
    std::fs::write(
        &filters,
        wok_event::json::to_tao_string(&json!([
            {"shape":"feed500","filter":feed(3000..3500,50)}
        ])),
    )
    .unwrap();
    let report = diagnose_with_options(
        dir.path(),
        &filters,
        1,
        &QueryOptions {
            time_budget_us: 0,
            max_slices: 1,
            ..QueryOptions::default()
        },
    )
    .unwrap();
    assert_eq!(report["status"], "processing_limit");
    assert_eq!(report["records"].as_array().unwrap().len(), 2);
    assert_eq!(report["all_pairs_equivalent"], false);
    assert!(report["records"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["completed"] == false && r["completeness_final"] == false));
    // A payload failure in both equal arms is still ineligible for strict pass.
    let env = Env::open(
        dir.path(),
        EnvOptions {
            create_dir: false,
            create_dbis: false,
            ..EnvOptions::for_tests()
        },
    )
    .unwrap();
    let id = read_arm(
        &env,
        &group(&feed(0..500, 50)),
        Arm::Pubkey,
        &QueryOptions::default(),
    )
    .unwrap()
    .delivery
    .ids[0];
    let mut tx = env.begin_rw().unwrap();
    tx.put_u64(env.dbis().event_payload, id, &[0xFF], 0)
        .unwrap();
    tx.commit().unwrap();
    drop(env);
    std::fs::write(
        &filters,
        wok_event::json::to_tao_string(&json!([
            {"shape":"feed500","filter":feed(0..500,50)}
        ])),
    )
    .unwrap();
    let report = diagnose(dir.path(), &filters, 1).unwrap();
    assert_eq!(report["status"], "payload_error");
    assert_eq!(report["all_pairs_equivalent"], false);
    assert!(report["records"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["payload_failed"] == true && r["pair_equivalent"] == false));
}

// This entry is deliberately separate from diagnose_existing_seed_feeds. The
// parent/host owns source/binary/native/layout/copy/audit/resource provenance.

const FRONTIER_WRAPPER_FIELDS: &[&str] = &[
    "author_head_multiget_calls",
    "author_head_keys",
    "iterator_creations",
    "seek",
    "seek_for_prev",
    "seek_to_first",
    "seek_to_last",
    "next",
    "prev",
    "typed_index_entries",
    "fallback_index_entries",
    "logical_decode_calls",
    "ordered_key_encodes",
    "ordered_key_bytes",
    "resume_key_copies",
    "resume_key_bytes",
    "generic_row_materializations",
    "generic_key_copy_bytes",
    "generic_value_copy_bytes",
    "arena_copy_bytes",
    "primary_pin_lookups",
    "primary_pins_found",
    "primary_pins_missing",
    "primary_pin_returned_bytes",
    "primary_cached_pinned_hits",
    "primary_cached_owned_hits",
    "cover_records_copied",
    "cover_record_bytes_copied",
    "cover_cached_pinned_hits",
    "cover_cached_owned_hits",
];

const FRONTIER_NATIVE_FIELDS: &[&str] = &[
    "user_key_comparison_count",
    "seek_on_memtable_count",
    "seek_child_seek_count",
    "next_on_memtable_count",
    "prev_on_memtable_count",
    "block_cache_hit_count",
    "block_read_count",
    "block_read_bytes",
    "get_read_bytes",
    "iter_read_bytes",
    "internal_key_skipped_count",
    "internal_delete_skipped_count",
    "get_from_memtable_count",
];

fn validate_frontier_sample(sample: &Sample, arm: Arm) -> Result<(), String> {
    let measured =
        serde_json::to_value(sample.measurements).map_err(|_| "measurement encoding failed")?;
    for (group, expected) in [
        ("wrapper", FRONTIER_WRAPPER_FIELDS),
        ("native", FRONTIER_NATIVE_FIELDS),
    ] {
        let actual = measured[group]
            .as_object()
            .ok_or("measurement group missing")?;
        if actual.len() != expected.len() || expected.iter().any(|key| !actual.contains_key(*key)) {
            return Err(format!("unexpected {group} measurement schema"));
        }
    }
    let plan = &sample.plan;
    if plan.desc != "Pubkey"
        || !plan.index_only
        || plan.cursors != 500
        || plan.initial_depth != 1
        || plan.refill_depths.len() != 500
        || plan.refill_depths.iter().any(|depth| *depth != 2)
    {
        return Err(
            "frontier diagnostic requires ordinary depth-one pure500-author Pubkey plans".into(),
        );
    }
    let stats = sample.author_frontier_initialization;
    let wrapper = sample.measurements.wrapper;
    if stats.issued_keys != wrapper.author_head_keys
        || stats.classified_keys() != stats.issued_keys
        || stats.header_keys_during_peek != 0
        || stats.failed_batch_keys != 0
        || stats.failed_batch_calls != 0
    {
        return Err("frontier initialization observations do not match actual issued keys".into());
    }
    if matches!(arm, Arm::Pubkey)
        && (plan.author_head_reads
            || wrapper.author_head_multiget_calls != 0
            || stats != super::author_head_scan::InitializationStats::default())
    {
        return Err("Pubkey control unexpectedly used author frontiers".into());
    }
    if matches!(arm, Arm::AuthorHeads) && !plan.author_head_reads {
        return Err("author-frontier arm is not eligible for this scanner".into());
    }
    Ok(())
}

fn decorate_frontier_report(report: &mut Value) {
    use std::collections::BTreeMap;
    let rows = report["records"].as_array().expect("records");
    let mut pairs: BTreeMap<(u64, u64, String), Vec<&Value>> = BTreeMap::new();
    for row in rows {
        pairs
            .entry((
                row["pass"].as_u64().expect("pass"),
                row["input_index"].as_u64().expect("index"),
                row["filter_sha256"]
                    .as_str()
                    .expect("filter hash")
                    .to_owned(),
            ))
            .or_default()
            .push(row);
    }
    let recorded_pairs = pairs.values().filter(|rows| rows.len() == 2).count();
    let completed_pairs = pairs
        .values()
        .filter(|rows| rows.len() == 2 && rows.iter().all(|r| r["completed"] == true))
        .count();
    let strict_pairs = pairs
        .values()
        .filter(|rows| rows.len() == 2 && rows.iter().all(|r| r["pair_equivalent"] == true))
        .count();
    let completed_arms = rows.iter().filter(|r| r["completed"] == true).count();
    let mut indexes: Vec<_> = rows
        .iter()
        .filter_map(|r| r["input_index"].as_u64())
        .collect();
    // Even when an arm fails before producing a Sample, the selected indices
    // are reported separately by diagnose_comparison below, not inferred here.
    indexes.sort_unstable();
    indexes.dedup();
    let object = report.as_object_mut().expect("report");
    let planned_pairs = object.remove("pairs_checked").expect("planned pairs");
    object.remove("arm_query_executions");
    object.insert(
        "format".into(),
        json!("wok-author-frontier-query-diagnostic-v1"),
    );
    object.insert("experiment".into(),json!({"control":"pubkey_control","candidate":"author_frontier_reader","same_layout":true,"batch_keys":super::author_head_scan::DIAGNOSTIC_BATCH_KEYS}));
    object.insert("planned_pairs".into(), planned_pairs);
    object.insert("recorded_pairs".into(), json!(recorded_pairs));
    object.insert("completed_arm_results".into(), json!(completed_arms));
    object.insert("completed_pairs".into(), json!(completed_pairs));
    object.insert("strict_eligible_pairs".into(), json!(strict_pairs));
    object.insert("selected_indexes_with_sample".into(), json!(indexes));
    object.insert(
        "feature_flags".into(),
        json!({
            "rocksdb_author_heads":true,
            "rocksdb_author_head_reads":true,
            "rocksdb_coverless":true,
            "rocksdb_read_diagnostics":cfg!(feature="rocksdb-read-diagnostics")
        }),
    );
    object.insert("expected_native_layout".into(),json!({"format":"wok-rocks-v3:combined:thin-author-frontiers:reverse-order:sync-wal","frontier_cf":"wok_author_frontiers_v1","verification":"Env open requires this compiled layout; host binds complete physical-format and audit evidence separately."}));
    object.insert("measurement_schema".into(),json!({
        "wrapper_count":FRONTIER_WRAPPER_FIELDS.len(),"wrapper_fields":FRONTIER_WRAPPER_FIELDS,
        "native_count":FRONTIER_NATIVE_FIELDS.len(),"native_fields":FRONTIER_NATIVE_FIELDS,
        "wrapper_fields_sha256":digest(wok_event::json::to_tao_string(&json!(FRONTIER_WRAPPER_FIELDS)).as_bytes()),
        "native_fields_sha256":digest(wok_event::json::to_tao_string(&json!(FRONTIER_NATIVE_FIELDS)).as_bytes())
    }));
    object.insert(
        "initializer_source_sha256".into(),
        json!(digest(include_bytes!("author_head_scan.rs"))),
    );
    object.insert("scope".into(),json!("Same-v3-layout all-request Pubkey seek control versus optional32-key author-frontier initialization. Both use unchanged DbQuery visibility/latest/dedup/limits/body callbacks/complete hints. New transaction/cache per arm, retained across normal zero-us/max64 process slices. Transaction begin and marker/cache setup, Env opening, exact stored-byte validation, transaction/Env drops are outside the measured query scope; lazy read-option setup performed by an actual query call remains inside it. Shared native/OS caches are not reset. The harness neither measures nor claims transaction-lifecycle savings."));
    object.insert("limits".into(),json!("Named operations and actual query outcome classifications only. No timing/network/device-I/O/15M performance or matched cross-round claim. Work/counters are observations; a logical-work delta requires review before any paired-savings interpretation. Strict equality requires both completed Samples, exact ordered IDs and packed/encoded-payload/decoded-body hashes+lengths, equal final hints and no payload failure. Partial Samples retain available state and are ineligible; a failed read_arm loses its in-flight Sample/counters but retains error metadata, the available opposite Sample and prior pairs. Expected outcome lists and status precedence remain explicit. Valid-record parity does not promise identical incidental corruption detection outside a skipped lookahead boundary; full offline audit is separate. Host owns input/copy/binary/source/native/archive/layout/audit/resource/lifecycle provenance and authorization."));
}

fn diagnose_author_frontiers(
    database: &Path,
    filters: &Path,
    passes: u32,
) -> Result<Value, String> {
    diagnose_comparison(
        database,
        filters,
        passes,
        &QueryOptions {
            time_budget_us: 0,
            ..QueryOptions::default()
        },
        DiagnosticComparison::AuthorFrontiers,
    )
}

#[test]
#[ignore = "requires separately authorized same-v3 disposable database and exact retained feed metadata"]
fn diagnose_existing_seed_author_frontiers() {
    let passes = match std::env::var("WOK_AUTHOR_FRONTIER_DIAGNOSTIC_PASSES") {
        Ok(s) => s.parse::<u32>().expect("passes must be1..=4"),
        Err(std::env::VarError::NotPresent) => 4,
        Err(_) => panic!("passes must be UTF-8"),
    };
    let report = diagnose_author_frontiers(
        &explicit_path("WOK_AUTHOR_FRONTIER_DIAGNOSTIC_DB"),
        &explicit_path("WOK_AUTHOR_FRONTIER_DIAGNOSTIC_FILTERS"),
        passes,
    )
    .unwrap_or_else(|e| panic!("author-frontier diagnostic processing_error: {e}"));
    println!("WOK_AUTHOR_FRONTIER_DIAGNOSTIC_RESULT={report}");
    assert_eq!(
        report["status"], "passed",
        "full strict author-frontier pair comparison failed"
    );
}

#[path = "author_frontier_seed_tests.rs"]
mod author_frontier_seed_tests;
