//! Local operation diagnostic on an explicitly supplied disposable RocksDB copy.
//!
//! Required environment: WOK_RANGE_DIAGNOSTIC_DB is the existing disposable
//! database directory; WOK_RANGE_DIAGNOSTIC_FILTERS names a JSON array file of
//! {"shape":"author|feed500|tag|id","filter":{...}} records. Each filter has
//! explicit `until` and `limit:50`. WOK_RANGE_DIAGNOSTIC_PASSES is 1..=4 (default4).
//! The host owns copy provenance, input selection/transforms and cleanup; this
//! harness never infers a historical timed-pool identity from representative
//! inputs. In particular, a seed-max cutoff need not have any newer postings.
//!
//! Env uses its read-only API with creation disabled and closes before output.
//! Read-only opening is not a preservation guarantee or permission to open a
//! pristine seed: native opening may still affect auxiliary files/OS caches.
//! The caller must supply a disposable copy and preserve its identity externally.
//! No writes, imports, forced flushes or cache resets are performed here.
//!
//! Each arm gets a fresh transaction, while native/OS caches are shared by the
//! alternating runs. Measurements include unchanged planning probes, ordinary
//! DbQuery visibility/completeness and decoded-payload callbacks. Stored-byte
//! validation is outside the measured scope. Elapsed diagnostic closure time
//! includes instrumentation and body hashing; it is not network latency or a
//! clean-build performance estimate. No bodies, filters or raw events are output.

use super::*;
use crate::{NostrFilterGroup, SubId};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;
use wok_db::read_diagnostics::{measure, ReadMeasurements};
use wok_db::{Env, EnvOptions};

const MAX_INPUT_BYTES: usize = 2 * 1024 * 1024;
const MAX_RECORDS: usize = 256;
const MAX_LIMIT: u64 = 50;

struct Config {
    database: PathBuf,
    filters_path: PathBuf,
    passes: u32,
}

pub(super) struct Input {
    pub(super) shape: String,
    pub(super) filter_sha256: String,
    pub(super) group: NostrFilterGroup,
}

#[derive(Clone, Copy)]
enum Arm {
    LegacyMax,
    DirectUntil,
}

impl Arm {
    fn name(self) -> &'static str {
        match self {
            Self::LegacyMax => "legacy_max",
            Self::DirectUntil => "direct_until",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    ids: Vec<u64>,
    sent_count: u64,
    completeness: Completeness,
    chronological_work: u64,
    peek_work: u64,
    peek_candidates: u32,
    body_sha256: String,
    body_bytes: u64,
    packed_sha256: String,
    packed_bytes: u64,
    payload_sha256: String,
    payload_bytes: u64,
    plan: &'static str,
    index_dbi: u32,
    index_only: bool,
    cursors: usize,
}

struct Sample {
    outcome: Outcome,
    measurements: ReadMeasurements,
    diagnostic_closure_elapsed_us: u64,
}

pub(super) fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(super) fn framed(hash: &mut Sha256, id: u64, bytes: &[u8]) {
    hash.update(id.to_be_bytes());
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

fn config_from_env() -> Result<Config, String> {
    let required = |name| {
        std::env::var_os(name)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .ok_or_else(|| format!("{name} must name an explicit disposable-copy input"))
    };
    let passes = match std::env::var("WOK_RANGE_DIAGNOSTIC_PASSES") {
        Ok(value) => value
            .parse::<u32>()
            .map_err(|_| "WOK_RANGE_DIAGNOSTIC_PASSES must be1..=4")?,
        Err(std::env::VarError::NotPresent) => 4,
        Err(_) => return Err("WOK_RANGE_DIAGNOSTIC_PASSES must be UTF-8".into()),
    };
    if !(1..=4).contains(&passes) {
        return Err("WOK_RANGE_DIAGNOSTIC_PASSES must be1..=4".into());
    }
    Ok(Config {
        database: required("WOK_RANGE_DIAGNOSTIC_DB")?,
        filters_path: required("WOK_RANGE_DIAGNOSTIC_FILTERS")?,
        passes,
    })
}

pub(super) fn read_inputs(path: &Path) -> Result<(Vec<Input>, String), String> {
    let file = std::fs::File::open(path).map_err(|_| "cannot open explicit filters file")?;
    let mut bytes = Vec::new();
    file.take(MAX_INPUT_BYTES as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read explicit filters file")?;
    if bytes.len() >= MAX_INPUT_BYTES {
        return Err("filters file must be smaller than2MiB".into());
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| "filters file must be UTF-8")?;
    let value = wok_event::json::parse_strict(text).map_err(|_| "invalid filters JSON")?;
    let records = value.as_array().ok_or("filters input must be an array")?;
    if records.is_empty() || records.len() > MAX_RECORDS {
        return Err("filters input must contain1..=256 records".into());
    }
    let inputs = records
        .iter()
        .enumerate()
        .map(|(index, record)| parse_input(record).map_err(|e| format!("input_index={index}: {e}")))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((inputs, digest(&bytes)))
}

fn parse_input(record: &Value) -> Result<Input, String> {
    let record = record.as_object().ok_or("record must be an object")?;
    if record.len() != 2 || !record.contains_key("shape") || !record.contains_key("filter") {
        return Err("record must contain exactly shape and filter".into());
    }
    let shape = record["shape"].as_str().ok_or("shape must be a string")?;
    let selector = match shape {
        "author" | "feed500" => "authors",
        "tag" => "#t",
        "id" => "ids",
        _ => return Err("unsupported shape label".into()),
    };
    let value = &record["filter"];
    let object = value.as_object().ok_or("filter must be an object")?;
    if object.len() != 3
        || !object.contains_key(selector)
        || object.get("until").and_then(Value::as_u64).is_none()
        || object.get("limit").and_then(Value::as_u64) != Some(MAX_LIMIT)
    {
        return Err(
            "filter must contain only its selector, explicit unsigned until and limit50".into(),
        );
    }
    let selector_values = object[selector]
        .as_array()
        .ok_or("selector must be an array")?;
    let cardinality = if shape == "feed500" { 500 } else { 1 };
    if selector_values.len() != cardinality || selector_values.iter().any(|v| !v.is_string()) {
        return Err("selector has the wrong shape cardinality/type".into());
    }
    let group = NostrFilterGroup::from_value(value, MAX_LIMIT, 8, 16)
        .map_err(|_| "invalid chronological filter")?;
    if group.filters.len() != 1 || group.never_matching != 0 {
        return Err("filter must produce one chronological query".into());
    }
    let filter = &group.filters[0];
    if filter.search.is_some() || filter.limit != MAX_LIMIT || filter.never_match {
        return Err("search/zero-limit/never-matching filters are unsupported".into());
    }
    match shape {
        "author" | "feed500"
            if filter.authors.as_ref().map(FilterSetBytes::size) != Some(cardinality) =>
        {
            return Err("authors must remain distinct exact keys after parsing".into());
        }
        "id" if filter.ids.as_ref().map(FilterSetBytes::size) != Some(1) => {
            return Err("ID must be one exact key".into());
        }
        _ => {}
    }
    Ok(Input {
        shape: shape.to_owned(),
        filter_sha256: digest(wok_event::json::to_tao_string(value).as_bytes()),
        group,
    })
}

fn read_arm(env: &Env, input: &Input, arm: Arm) -> Result<Sample, String> {
    // Env opening, transaction creation and later stored-byte validation stay
    // outside this query/planner scope. Each arm starts with an empty View cache.
    let tx = env.begin_ro().map_err(|_| "cannot begin read snapshot")?;
    let sub = Subscription::new(
        1,
        SubId::new("range-seed-diagnostic").unwrap(),
        input.group.clone(),
        false,
    );
    let mut query = DbQuery::new(sub, 0, 0);
    query.track_completeness();
    query.set_visibility(ReadVisibility::default());
    let filter = &input.group.filters[0];
    let mut ids = Vec::new();
    let mut body_hash = Sha256::new();
    let mut body_bytes = 0u64;
    let mut decompressor = Decompressor::new();
    let (run, measurements) = measure(|| {
        let start = Instant::now();
        // Both paths execute the same untouched planner and unbounded probes.
        // Only selected initial execution endpoints differ; no public override.
        #[allow(unused_mut)]
        let mut scan = match arm {
            Arm::LegacyMax => DbScan::new_planned(filter, &tx),
            Arm::DirectUntil => DbScan::new(filter, &tx),
        };
        #[cfg(feature = "rocksdb-author-head-reads")]
        {
            // Preserve the original endpoint-only comparison in this harness.
            scan.author_head_reads = false;
        }
        let expected_plan = match input.shape.as_str() {
            "author" | "feed500" => "Pubkey",
            "tag" => "Tag",
            "id" => "ID",
            _ => unreachable!(),
        };
        if scan.desc != expected_plan {
            return Err("selected scanner does not match the declared shape");
        }
        let plan = (
            scan.desc,
            scan.index_dbi,
            scan.index_only,
            scan.cursor_count(),
        );
        query.scanner = Some(QueryScanner::Chronological(scan));
        let mut payload_failed = false;
        let complete = query
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
                // Disable wall-clock interruption while retaining the normal
                // query work/refill/limit/visibility/completeness behavior.
                u64::MAX,
                &mut Decompressor::new(),
            )
            .map_err(|_| "query processing failed")?;
        if payload_failed {
            query.mark_incomplete();
            return Err("stored payload decoding failed");
        }
        if !complete || query.dead {
            return Err("chronological query did not complete normally");
        }
        let elapsed = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
        Ok((plan, elapsed))
    })
    .map_err(|_| "nested diagnostic measurement")?;
    let ((plan, index_dbi, index_only, cursors), elapsed) = run?;
    if ids.len() as u64 != query.sent_count() || ids.len() > MAX_LIMIT as usize {
        return Err("query sent-count/limit validation failed".into());
    }
    // Validate exact stored components in the same immutable snapshot, without
    // adding validation-only primary-cache hits to the measured query counters.
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
        outcome: Outcome {
            ids,
            sent_count: query.sent_count(),
            completeness: query.completeness(),
            chronological_work: query.diagnostic_chronological_work,
            peek_work: PEEK_WORK - query.peek_budget.work,
            peek_candidates: PEEK_CANDIDATES - query.peek_budget.candidates,
            body_sha256: hex::encode(body_hash.finalize()),
            body_bytes,
            packed_sha256: hex::encode(packed_hash.finalize()),
            packed_bytes,
            payload_sha256: hex::encode(payload_hash.finalize()),
            payload_bytes,
            plan,
            index_dbi,
            index_only,
            cursors,
        },
        measurements,
        diagnostic_closure_elapsed_us: elapsed,
    })
}

fn sample_json(
    sample: Sample,
    input: &Input,
    input_index: usize,
    pass: u32,
    arm: Arm,
    ordinal: usize,
    pair_equivalent: bool,
) -> Value {
    let r = sample.outcome;
    json!({
        "pass": pass, "input_index": input_index, "shape": input.shape,
        "filter_sha256": input.filter_sha256, "arm": arm.name(), "arm_ordinal": ordinal,
        "pair_equivalent": pair_equivalent, "ordered_local_ids": r.ids, "sent_count": r.sent_count,
        "completeness": {"finish":r.completeness.finish,"more":r.completeness.more,"restricted":r.completeness.restricted},
        "chronological_work":r.chronological_work,"peek_work":r.peek_work,"peek_candidates":r.peek_candidates,
        "body_sha256":r.body_sha256,"body_bytes":r.body_bytes,
        "packed_sha256":r.packed_sha256,"packed_bytes":r.packed_bytes,
        "payload_sha256":r.payload_sha256,"payload_bytes":r.payload_bytes,
        "plan":{"desc":r.plan,"index_dbi":r.index_dbi,"index_only":r.index_only,"cursors":r.cursors},
        "diagnostic_closure_elapsed_us":sample.diagnostic_closure_elapsed_us,
        "measurements":sample.measurements
    })
}

fn diagnose(config: &Config) -> Result<Value, String> {
    if !(1..=4).contains(&config.passes) {
        return Err("passes must be1..=4".into());
    }
    let (inputs, filters_sha256) = read_inputs(&config.filters_path)?;
    let database = config
        .database
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
    let mut records = Vec::with_capacity(inputs.len() * config.passes as usize * 2);
    let mut mismatches = Vec::new();
    for pass in 1..=config.passes {
        for (index, input) in inputs.iter().enumerate() {
            let arms = if (pass as usize + index) % 2 == 1 {
                [Arm::LegacyMax, Arm::DirectUntil]
            } else {
                [Arm::DirectUntil, Arm::LegacyMax]
            };
            let first = read_arm(&env, input, arms[0])?;
            let second = read_arm(&env, input, arms[1])?;
            let pair_equivalent = first.outcome == second.outcome;
            if !pair_equivalent {
                mismatches.push(json!({"pass":pass,"input_index":index,"shape":input.shape,"filter_sha256":input.filter_sha256}));
            }
            records.push(sample_json(
                first,
                input,
                index,
                pass,
                arms[0],
                0,
                pair_equivalent,
            ));
            records.push(sample_json(
                second,
                input,
                index,
                pass,
                arms[1],
                1,
                pair_equivalent,
            ));
        }
    }
    drop(env); // Close the read-only native handle before returning/emitting output.
    Ok(json!({
        "format":"wok-range-seed-diagnostic-v1", "status":if mismatches.is_empty(){"passed"}else{"failed"}, "database_closed":true,
        "database_path":database,"env_read_only":true,"env_create_dir":false,"env_create_dbis":false,
        "filters_path":config.filters_path,"filters_sha256":filters_sha256,"input_records":inputs.len(),
        "passes":config.passes,"pairs_checked":inputs.len()*config.passes as usize,
        "arm_query_executions":records.len(),"records":records,
        "all_pairs_equivalent":mismatches.is_empty(),"mismatched_pairs":mismatches,
        "harness_source_sha256":digest(include_bytes!("range_seed_diagnostic.rs")),
        "storage_backend":wok_db::storage_backend_name(),"thin_author_feature":cfg!(feature="rocksdb-thin-author-reads"),
        "digest_framing":"For each ordered hit: unsigned local-ID u64 big-endian, byte length u64 big-endian, exact bytes. Separate SHA-256 streams for packed, encoded payload and decoded body; an empty stream has the standard empty SHA-256.",
        "scope":"Fresh read transaction per arm/query; unchanged planner then legacyMAX versus direct inclusive-until endpoints; normal default-visibility DbQuery, limit50, completeness and payload decoding. Wall-clock interruption disabled. Instrumented planner/query/body-callback scope excludes Env/txn opening, stored-byte verification and teardown. Native and OS caches remain shared; alternating arm order does not reset caches.",
        "provenance":"Explicit input file and disposable-copy provenance belong to the host manifest. Representative/unshifted/lower-cutoff inputs are not asserted to be an exact historical timed pool.",
        "limits":"Diagnostic closure elapsed time includes counter and body-hash overhead and is not network latency. Named wrapper copies are partial; primary returned pins need not be native zero-copy and native block reads need not be physical I/O. No cache isolation or maximum-capacity claim. No filters/bodies/raw events emitted."
    }))
}

#[test]
#[ignore = "requires explicit disposable database copy and bounded filter file"]
fn diagnose_existing_seed_ranges() {
    let config = config_from_env().unwrap_or_else(|e| panic!("range diagnostic input: {e}"));
    let report = diagnose(&config).unwrap_or_else(|e| panic!("range diagnostic failed: {e}"));
    println!("WOK_RANGE_DIAGNOSTIC_RESULT={report}");
    assert_eq!(
        report["status"], "passed",
        "completed arm pairs did not match"
    );
}

#[test]
fn disposable_seed_diagnostic_parser_and_full_query_smoke() {
    use wok_db::{write_events, EventToWrite, NoopNegentropy};
    use wok_event::{PackedEventBuilder, PackedEventTagBuilder};

    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("disposable-rocks-copy");
    let env = Env::open(&database, EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let author = |who: u64| {
        let mut pk = [0u8; 32];
        pk[..8].copy_from_slice(&who.to_be_bytes());
        pk
    };
    let mut events = Vec::new();
    let base = 1_700_000_000u64;
    // Interleaved local IDs, an inclusive older cutoff, sparse tags and two
    // hidden author rows exercise the full query path on a tiny fresh DB.
    for depth in 0..3u64 {
        for who in 0..512u64 {
            let number = depth * 512 + who + 1;
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&number.to_be_bytes());
            let mut tags = PackedEventTagBuilder::default();
            if who % 8 == 0 {
                tags.add('t', b"fixture").unwrap();
            }
            let kind = if who == 0 && depth == 1 { 22242 } else { 1 };
            // Expiration1 is Wok's ephemeral marker, whose TTL is configured
            // separately; use a real old timestamp to test default expiry.
            let expiration = if who == 0 && depth == 2 { 2 } else { 0 };
            let packed = PackedEventBuilder::build(
                &id,
                &author(who),
                base + depth * 120,
                kind,
                expiration,
                &tags,
            )
            .unwrap();
            events.push(EventToWrite::new(
                packed.into_bytes(),
                wok_event::json::to_tao_string(
                    &json!({"content":format!("fixture{number}: 🥘\u{7f}")}),
                ),
            ));
        }
    }
    let mut writer = env.begin_rw().unwrap();
    write_events(&mut writer, &mut NoopNegentropy, &mut events, false).unwrap();
    writer.commit().unwrap();
    drop(env);
    let id = {
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&2u64.to_be_bytes());
        hex::encode(id)
    };
    let mut records = Vec::new();
    for until in [base + 240, base + 120] {
        records.extend([
            json!({"shape":"author","filter":{"authors":[hex::encode(author(0))],"until":until,"limit":50}}),
            json!({"shape":"feed500","filter":{"authors":(0..500).map(|n|hex::encode(author(n))).collect::<Vec<_>>(),"until":until,"limit":50}}),
            json!({"shape":"tag","filter":{"#t":["fixture"],"until":until,"limit":50}}),
            json!({"shape":"id","filter":{"ids":[id.clone()],"until":until,"limit":50}}),
        ]);
    }
    for invalid in [
        json!({"shape":"feed500","filter":{"authors":[hex::encode(author(0))],"until":base,"limit":50}}),
        json!({"shape":"feed500","filter":{"authors":vec![hex::encode(author(0));500],"until":base,"limit":50}}),
        json!({"shape":"id","filter":{"ids":["aa"],"until":base,"limit":50}}),
        json!({"shape":"author","filter":{"authors":[hex::encode(author(0))],"limit":50}}),
        json!({"shape":"author","filter":{"authors":[hex::encode(author(0))],"until":base,"limit":0}}),
        json!({"shape":"tag","filter":{"#t":["fixture"],"until":base,"limit":50,"search":"fixture"}}),
        json!({"shape":"id","filter":[{"ids":[id.clone()],"until":base,"limit":50}]}),
    ] {
        assert!(parse_input(&invalid).is_err());
    }
    let filters_path = dir.path().join("explicit-filters.json");
    let input_bytes = wok_event::json::to_tao_string(&json!(records));
    std::fs::write(&filters_path, &input_bytes).unwrap();
    let rejected_path = dir.path().join("rejected-filters.json");
    let too_many = json!(vec![
        json!({"shape":"id","filter":{"ids":[id],"until":base,"limit":50}});
        MAX_RECORDS + 1
    ]);
    std::fs::write(&rejected_path, wok_event::json::to_tao_string(&too_many)).unwrap();
    assert!(read_inputs(&rejected_path).is_err());
    std::fs::write(&rejected_path, vec![b' '; MAX_INPUT_BYTES]).unwrap();
    assert!(read_inputs(&rejected_path).is_err());
    let report = diagnose(&Config {
        database: database.clone(),
        filters_path,
        passes: 1,
    })
    .unwrap();
    assert_eq!(report["arm_query_executions"], 16);
    assert_eq!(report["pairs_checked"], 8);
    assert_eq!(report["filters_sha256"], digest(input_bytes.as_bytes()));
    assert_eq!(report["database_closed"], true);
    let rows = report["records"].as_array().unwrap();
    assert!(rows.iter().all(|row| row["pair_equivalent"] == true));
    assert!(rows
        .iter()
        .filter(|row| row["shape"] == "author")
        .all(|row| row["sent_count"] == 1));
    assert!(rows
        .iter()
        .filter(|row| row["shape"] == "feed500")
        .all(|row| row["completeness"]["more"] == true));
    assert!(rows
        .iter()
        .all(|row| row["measurements"]["wrapper"].is_object()
            && row["measurements"]["native"].is_object()));
    // Returning the report released the read-only handle and its native lock.
    drop(
        Env::open(
            &database,
            EnvOptions {
                create_dir: false,
                create_dbis: false,
                ..EnvOptions::for_tests()
            },
        )
        .unwrap(),
    );
}
