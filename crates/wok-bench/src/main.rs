//! Comparative benchmark: C++ strfry vs wok.
//!
//! Principles:
//! - Never touches a user database; every trial uses a disposable temp dir.
//! - Identical deterministic corpus for both relays (same seed => same
//!   signed events).
//! - Warm-up before measurement; latency percentiles over hundreds of
//!   samples, not single runs.
//! - A trial with missing events, unexpected rejections, or dropped
//!   deliveries is recorded as `ok=false` (correctness before speed).

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use futures_util::{SinkExt, StreamExt};
use hdrhistogram::Histogram;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

#[derive(Parser, Debug)]
struct Args {
    /// C++ strfry binary
    #[arg(long, default_value = "/Users/jeff/code/strfry/strfry")]
    strfry: PathBuf,
    /// wok binary
    #[arg(long, default_value = "target/release/wok")]
    wok: PathBuf,
    /// Scenarios: smoke (quick) or full
    #[arg(long, default_value = "smoke")]
    profile: String,
    /// Run one scenario instead of the selected profile (for example nip50_search)
    #[arg(long)]
    scenario: Option<String>,
    /// Output directory for JSONL + markdown
    #[arg(long, default_value = "bench-results")]
    out: PathBuf,
    /// Fixed RNG seed
    #[arg(long, default_value_t = 1)]
    seed: u64,
    /// Events in bulk scenarios (smoke default 2000, full default 20000)
    #[arg(long)]
    events: Option<u64>,
    /// Reuse an existing signed JSONL corpus instead of generating one.
    #[arg(long)]
    corpus: Option<PathBuf>,
    /// Write the corpus and manifest, then exit without running a trial.
    #[arg(long)]
    generate_corpus_only: bool,
    /// Queries in query scenarios (default 400)
    #[arg(long)]
    queries: Option<u64>,
    /// Fixed event timestamp anchor. Defaults once at campaign start.
    #[arg(long)]
    base_timestamp: Option<u64>,
    /// Signed event distribution used by generated corpora.
    #[arg(long, value_enum, default_value_t = EventMix::Kind1)]
    event_mix: EventMix,
    /// Repetitions per relay/scenario. Relay order alternates each repetition.
    #[arg(long, default_value_t = 1)]
    repetitions: u32,
    /// Connections used by ws_publish_scaled.
    #[arg(long, default_value_t = 32)]
    publish_connections: usize,
    /// Subscribers used by live_fanout.
    #[arg(long, default_value_t = 32)]
    fanout_subscribers: usize,
    /// Events published during live_fanout.
    #[arg(long, default_value_t = 200)]
    fanout_events: u64,
    /// Connections opened by idle_connections.
    #[arg(long, default_value_t = 1_000)]
    connections: usize,
    /// Seconds idle_connections keeps every socket open.
    #[arg(long, default_value_t = 5)]
    hold_seconds: u64,
    /// Run network load against an already-running relay instead of spawning one.
    #[arg(long)]
    target_url: Option<String>,
    /// Run load over Wok's framed Unix socket instead of spawning a relay.
    #[arg(long, conflicts_with = "target_url")]
    target_unix: Option<PathBuf>,
    /// Result label used with --target-url or --target-unix.
    #[arg(long, default_value = "remote")]
    target_label: String,
}

impl Args {
    fn target_endpoint(&self) -> Option<String> {
        self.target_url.clone().or_else(|| {
            self.target_unix
                .as_ref()
                .map(|path| format!("unix://{}", path.display()))
        })
    }

    fn has_external_target(&self) -> bool {
        self.target_url.is_some() || self.target_unix.is_some()
    }
}

#[derive(Serialize, Clone)]
struct Trial {
    relay: String,
    scenario: String,
    repetition: u32,
    ok: bool,
    throughput_per_s: f64,
    latency_p50_ms: f64,
    latency_p90_ms: f64,
    latency_p99_ms: f64,
    latency_max_ms: f64,
    errors: u64,
    mismatches: u64,
    notes: String,
    host: String,
    os: String,
    arch: String,
    seed: u64,
    workload_seed: u64,
    event_mix: EventMix,
    base_timestamp: u64,
    corpus_sha256: String,
    binary_sha256: String,
    profile: String,
}

#[derive(Serialize)]
struct CorpusManifest {
    format: &'static str,
    events: u64,
    seed: u64,
    base_timestamp: u64,
    event_mix: EventMix,
    bytes: u64,
    sha256: String,
    path: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum EventMix {
    /// Kind 1 notes only, preserving the original focused workload.
    Kind1,
    /// Weighted notes plus metadata, contacts, reactions, zaps, relay lists,
    /// and long-form content.
    Realistic,
    /// Notes plus deletion requests and ephemeral events. Intended for live
    /// publication workloads, not retained-count comparisons.
    Lifecycle,
}

#[derive(Serialize)]
struct BinaryManifest {
    path: String,
    sha256: String,
}

#[derive(Serialize)]
struct CampaignManifest {
    generated_at: String,
    host: String,
    os: String,
    arch: String,
    profile: String,
    repetitions: u32,
    corpus: CorpusManifest,
    wok: Option<BinaryManifest>,
    strfry: Option<BinaryManifest>,
    target_url: Option<String>,
    target_label: Option<String>,
}

#[derive(Clone, Copy)]
struct EventWorkload {
    count: u64,
    seed: u64,
    base_timestamp: u64,
    mix: EventMix,
}

#[derive(Clone, Copy)]
struct RelayTarget<'a> {
    bin: Option<&'a Path>,
    url: Option<&'a str>,
    dbdir: &'a Path,
}

const RELAYS: [&str; 2] = ["wok", "strfry"];

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive("warn".parse()?),
        )
        .init();
    let mut args = Args::parse();
    if args.repetitions == 0 {
        anyhow::bail!("--repetitions must be at least 1");
    }
    if args.publish_connections == 0 || args.fanout_subscribers == 0 || args.connections == 0 {
        anyhow::bail!("connection counts must be at least 1");
    }
    if args.events == Some(0) || args.queries == Some(0) || args.fanout_events == 0 {
        anyhow::bail!("event and query counts must be at least 1");
    }
    let base_timestamp = args.base_timestamp.unwrap_or(unix_timestamp()?);
    args.base_timestamp = Some(base_timestamp);
    std::fs::create_dir_all(&args.out)?;
    let profile_scenarios: Vec<&str> = if args.profile == "load" {
        vec!["ws_publish_scaled", "live_fanout", "idle_connections"]
    } else if args.profile == "full" {
        vec![
            "import",
            "export",
            "negentropy_build",
            "ws_publish_1conn",
            "ws_publish_8conn",
            "ws_query_latency",
            "deep_history_pagination",
            "mixed_read_write",
            "nip50_search",
            "live_fanout",
            "ws_publish_scaled",
            "idle_connections",
            "duplicate_import",
            "cold_start",
        ]
    } else {
        vec![
            "import",
            "export",
            "ws_publish_1conn",
            "ws_query_latency",
            "nip50_search",
        ]
    };
    let known_scenarios = [
        "import",
        "export",
        "negentropy_build",
        "ws_publish_1conn",
        "ws_publish_8conn",
        "ws_query_latency",
        "deep_history_pagination",
        "mixed_read_write",
        "nip50_search",
        "live_fanout",
        "ws_publish_scaled",
        "idle_connections",
        "duplicate_import",
        "cold_start",
    ];
    let scenarios: Vec<&str> = if let Some(scenario) = args.scenario.as_deref() {
        if !known_scenarios.contains(&scenario) {
            anyhow::bail!("unknown benchmark scenario: {scenario}");
        }
        vec![scenario]
    } else {
        profile_scenarios
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(8)
        .build()?;

    if args.has_external_target()
        && scenarios.iter().any(|scenario| {
            !matches!(
                *scenario,
                "ws_publish_scaled"
                    | "ws_query_latency"
                    | "deep_history_pagination"
                    | "mixed_read_write"
                    | "live_fanout"
                    | "idle_connections"
            )
        })
    {
        anyhow::bail!(
            "external targets support scaled publication, query, mixed read/write, fanout, and idle-connection scenarios"
        );
    }

    if args.event_mix == EventMix::Lifecycle
        && scenarios.iter().any(|scenario| {
            !matches!(
                *scenario,
                "ws_publish_1conn"
                    | "ws_publish_8conn"
                    | "ws_publish_scaled"
                    | "live_fanout"
                    | "idle_connections"
            )
        })
    {
        anyhow::bail!("--event-mix lifecycle is only valid for live publication scenarios");
    }

    let default_event_count = if args.profile == "smoke" {
        2_000
    } else {
        20_000
    };
    let (corpus_path, event_count) = if let Some(path) = &args.corpus {
        let path = std::fs::canonicalize(path)
            .with_context(|| format!("open corpus {}", path.display()))?;
        let count = count_jsonl_events(&path)?;
        if let Some(expected) = args.events {
            if expected != count {
                anyhow::bail!(
                    "--events {expected} does not match {} records in {}",
                    count,
                    path.display()
                );
            }
        }
        (path, count)
    } else {
        let count = args.events.unwrap_or(default_event_count);
        let path = args.out.join("corpus.jsonl");
        generate_events(&path, count, args.seed, base_timestamp, args.event_mix)?;
        (path, count)
    };
    args.events = Some(event_count);
    let corpus = corpus_manifest(
        &corpus_path,
        event_count,
        args.seed,
        base_timestamp,
        args.event_mix,
    )?;
    let corpus_sha256 = corpus.sha256.clone();
    let wok_manifest = binary_manifest(&args.wok);
    let strfry_manifest = binary_manifest(&args.strfry);
    let campaign = CampaignManifest {
        generated_at: chrono::Utc::now().to_rfc3339(),
        host: hostname(),
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        profile: args.profile.clone(),
        repetitions: args.repetitions,
        corpus,
        wok: wok_manifest,
        strfry: strfry_manifest,
        target_url: args.target_endpoint(),
        target_label: args
            .has_external_target()
            .then(|| args.target_label.clone()),
    };
    std::fs::write(
        args.out.join("manifest.json"),
        serde_json::to_vec_pretty(&campaign)?,
    )?;
    if args.generate_corpus_only {
        println!(
            "wrote corpus manifest for {} events at {}",
            event_count,
            corpus_path.display()
        );
        return Ok(());
    }

    let mut trials = Vec::new();
    for repetition in 1..=args.repetitions {
        for scenario in &scenarios {
            let mut relays: Vec<&str> = if args.has_external_target() {
                vec![args.target_label.as_str()]
            } else if *scenario == "nip50_search" {
                vec!["wok"]
            } else {
                RELAYS.to_vec()
            };
            if repetition % 2 == 0 {
                relays.reverse();
            }
            for relay in relays {
                let t = run_trial(
                    &rt,
                    &args,
                    relay,
                    scenario,
                    repetition,
                    &corpus_path,
                    &corpus_sha256,
                );
                match t {
                    Ok(t) => trials.push(t),
                    Err(e) => {
                        eprintln!("trial {relay}/{scenario}/r{repetition} errored: {e}");
                        trials.push(failed_trial(
                            &args,
                            relay,
                            scenario,
                            repetition,
                            &corpus_sha256,
                            format!("{e}"),
                        ));
                    }
                }
            }
        }
    }

    let jsonl = args.out.join("results.jsonl");
    let mut f = std::fs::File::create(&jsonl)?;
    for t in &trials {
        writeln!(f, "{}", serde_json::to_string(t)?)?;
    }
    let md = render_markdown(&args, &trials);
    std::fs::write(args.out.join("summary.md"), &md)?;
    println!("wrote {} and summary.md", jsonl.display());
    print!("\n{md}");
    Ok(())
}

fn run_trial(
    rt: &tokio::runtime::Runtime,
    args: &Args,
    relay: &str,
    scenario: &str,
    repetition: u32,
    corpus_path: &Path,
    corpus_sha256: &str,
) -> Result<Trial> {
    let dir = TempDir::new()?;
    let mut hist = Histogram::<u64>::new(3)?;
    let mut ok = true;
    let mut errors = 0u64;
    let mut mismatches = 0u64;
    #[allow(unused_assignments)]
    let mut notes = String::new();
    let mut throughput = 0.0f64;

    let bin = if args.has_external_target() {
        None
    } else if relay == "wok" {
        Some(args.wok.as_path())
    } else {
        Some(args.strfry.as_path())
    };
    if let Some(path) = bin {
        if !path.is_file() {
            return Ok(failed_trial(
                args,
                relay,
                scenario,
                repetition,
                corpus_sha256,
                format!("binary missing: {}", path.display()),
            ));
        }
    }
    let bin = bin.map(std::fs::canonicalize).transpose()?;
    let bin = bin.as_deref();

    let n = args.events.unwrap_or(if args.profile == "smoke" {
        2_000
    } else {
        20_000
    });
    let n_queries = args.queries.unwrap_or(400);

    let base_timestamp = args.base_timestamp.expect("campaign timestamp set");
    let workload_seed = workload_seed(args.seed, scenario, repetition);
    let workload = EventWorkload {
        count: n,
        seed: workload_seed,
        base_timestamp,
        mix: args.event_mix,
    };
    let local_bin =
        || bin.ok_or_else(|| anyhow::anyhow!("{scenario} requires locally managed relay binaries"));
    let target_endpoint = args.target_endpoint();
    let target = RelayTarget {
        bin,
        url: target_endpoint.as_deref(),
        dbdir: dir.path(),
    };
    match scenario {
        "import" => {
            let bin = local_bin()?;
            let start = Instant::now();
            let good = import_with(bin, dir.path(), corpus_path, true);
            let elapsed = start.elapsed();
            if !good {
                ok = false;
                errors += 1;
                notes = "import process failed".into();
            } else {
                let exported = export_count(bin, dir.path());
                if exported != n {
                    mismatches += 1;
                    ok = false;
                    notes = format!("export count {exported} != imported {n}");
                } else {
                    throughput = n as f64 / elapsed.as_secs_f64();
                    hist.record(elapsed.as_micros().max(1) as u64)?;
                    notes = format!("imported+verified {n} events");
                }
            }
        }
        "export" => {
            let bin = local_bin()?;
            if !import_with(bin, dir.path(), corpus_path, false) {
                ok = false;
                errors += 1;
                notes = "pre-import failed".into();
            } else {
                let start = Instant::now();
                let exported = export_count(bin, dir.path());
                let elapsed = start.elapsed();
                if exported != n {
                    mismatches += 1;
                    ok = false;
                    notes = format!("export count {exported} != {n}");
                } else {
                    throughput = n as f64 / elapsed.as_secs_f64();
                    hist.record(elapsed.as_micros().max(1) as u64)?;
                    notes = format!("exported {n} events");
                }
            }
        }
        "duplicate_import" => {
            let bin = local_bin()?;
            let jsonl = generate_events(
                &dir.path().join("duplicate-events.jsonl"),
                n.min(5_000),
                workload_seed,
                base_timestamp,
                args.event_mix,
            )?;
            if !import_with(bin, dir.path(), &jsonl, false) {
                ok = false;
                errors += 1;
                notes = "pre-import failed".into();
            } else {
                let start = Instant::now();
                let good = import_with(bin, dir.path(), &jsonl, false);
                let elapsed = start.elapsed();
                ok = good;
                throughput = n.min(5_000) as f64 / elapsed.as_secs_f64();
                hist.record(elapsed.as_micros().max(1) as u64)?;
                notes = "re-import of identical events (dup detection)".into();
            }
        }
        "negentropy_build" => {
            let bin = local_bin()?;
            if !import_with(bin, dir.path(), corpus_path, false) {
                ok = false;
                errors += 1;
                notes = "pre-import failed".into();
            } else {
                let start = Instant::now();
                let good = negentropy_build(bin, dir.path());
                let elapsed = start.elapsed();
                ok = good;
                throughput = n as f64 / elapsed.as_secs_f64();
                hist.record(elapsed.as_micros().max(1) as u64)?;
                notes = "negentropy build 1 (default {} tree)".into();
            }
        }
        "ws_publish_1conn" | "ws_publish_8conn" => {
            let bin = local_bin()?;
            let conns = if scenario == "ws_publish_8conn" { 8 } else { 1 };
            match ws_publish_trial(rt, bin, dir.path(), workload, conns, &mut hist) {
                Ok((eps, nts, good, miss)) => {
                    throughput = eps;
                    notes = nts;
                    ok = good;
                    mismatches += miss;
                }
                Err(e) => {
                    ok = false;
                    errors += 1;
                    notes = format!("{e}");
                }
            }
        }
        "ws_query_latency" => match ws_query_trial(rt, target, corpus_path, n_queries, &mut hist) {
            Ok((qps, nts, good, miss)) => {
                throughput = qps;
                notes = nts;
                ok = good;
                mismatches += miss;
            }
            Err(e) => {
                ok = false;
                errors += 1;
                notes = format!("{e}");
            }
        },
        "deep_history_pagination" => {
            match deep_history_trial(rt, target, corpus_path, n_queries, &mut hist) {
                Ok((qps, nts, good, miss)) => {
                    throughput = qps;
                    notes = nts;
                    ok = good;
                    mismatches += miss;
                }
                Err(e) => {
                    ok = false;
                    errors += 1;
                    notes = format!("{e}");
                }
            }
        }
        "mixed_read_write" => {
            match mixed_read_write_trial(rt, target, corpus_path, workload, n_queries, &mut hist) {
                Ok((qps, nts, good, miss)) => {
                    throughput = qps;
                    notes = nts;
                    ok = good;
                    mismatches += miss;
                }
                Err(e) => {
                    ok = false;
                    errors += 1;
                    notes = format!("{e}");
                }
            }
        }
        "nip50_search" => {
            let bin = local_bin()?;
            match ws_search_trial(rt, bin, dir.path(), workload, n_queries, &mut hist) {
                Ok((qps, nts, good, miss)) => {
                    throughput = qps;
                    notes = nts;
                    ok = good;
                    mismatches += miss;
                }
                Err(e) => {
                    ok = false;
                    errors += 1;
                    notes = format!("{e}");
                }
            }
        }
        "live_fanout" => {
            let workload = EventWorkload {
                count: args.fanout_events,
                ..workload
            };
            match live_fanout_trial(rt, target, workload, args.fanout_subscribers, &mut hist) {
                Ok((eps, nts, good, miss)) => {
                    throughput = eps;
                    notes = nts;
                    ok = good;
                    mismatches += miss;
                }
                Err(e) => {
                    ok = false;
                    errors += 1;
                    notes = format!("{e}");
                }
            }
        }
        "ws_publish_scaled" => {
            match ws_publish_target_trial(rt, target, workload, args.publish_connections, &mut hist)
            {
                Ok((eps, nts, good, miss)) => {
                    throughput = eps;
                    notes = nts;
                    ok = good;
                    mismatches += miss;
                }
                Err(e) => {
                    ok = false;
                    errors += 1;
                    notes = format!("{e}");
                }
            }
        }
        "idle_connections" => {
            match idle_connections_trial(
                rt,
                bin,
                target_endpoint.as_deref(),
                dir.path(),
                args.connections,
                args.hold_seconds,
                &mut hist,
            ) {
                Ok((cps, nts, good, miss)) => {
                    throughput = cps;
                    notes = nts;
                    ok = good;
                    mismatches += miss;
                }
                Err(e) => {
                    ok = false;
                    errors += 1;
                    notes = format!("{e}");
                }
            }
        }
        "cold_start" => {
            let bin = local_bin()?;
            if !import_with(bin, dir.path(), corpus_path, false) {
                ok = false;
                errors += 1;
                notes = "pre-import failed".into();
            } else {
                match cold_start_trial(rt, bin, dir.path(), &mut hist) {
                    Ok(ms) => {
                        throughput = 1000.0 / ms as f64;
                        notes = format!("relay ready + first query answered in {ms} ms");
                    }
                    Err(e) => {
                        ok = false;
                        errors += 1;
                        notes = format!("{e}");
                    }
                }
            }
        }
        _ => {
            notes = "unrecognized scenario".into();
            ok = false;
        }
    }

    Ok(Trial {
        relay: relay.into(),
        scenario: scenario.into(),
        repetition,
        ok,
        throughput_per_s: throughput,
        latency_p50_ms: pct(&hist, 50.0) / 1000.0,
        latency_p90_ms: pct(&hist, 90.0) / 1000.0,
        latency_p99_ms: pct(&hist, 99.0) / 1000.0,
        latency_max_ms: hist.max() as f64 / 1000.0,
        errors,
        mismatches,
        notes,
        host: hostname(),
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        seed: args.seed,
        workload_seed,
        event_mix: args.event_mix,
        base_timestamp,
        corpus_sha256: corpus_sha256.into(),
        binary_sha256: bin
            .and_then(|path| sha256_file(path).ok())
            .unwrap_or_default(),
        profile: args.profile.clone(),
    })
}

fn failed_trial(
    args: &Args,
    relay: &str,
    scenario: &str,
    repetition: u32,
    corpus_sha256: &str,
    notes: String,
) -> Trial {
    Trial {
        relay: relay.into(),
        scenario: scenario.into(),
        repetition,
        ok: false,
        throughput_per_s: 0.0,
        latency_p50_ms: 0.0,
        latency_p90_ms: 0.0,
        latency_p99_ms: 0.0,
        latency_max_ms: 0.0,
        errors: 1,
        mismatches: 0,
        notes,
        host: hostname(),
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        seed: args.seed,
        workload_seed: workload_seed(args.seed, scenario, repetition),
        event_mix: args.event_mix,
        base_timestamp: args.base_timestamp.unwrap_or_default(),
        corpus_sha256: corpus_sha256.into(),
        binary_sha256: String::new(),
        profile: args.profile.clone(),
    }
}

fn pct(h: &Histogram<u64>, p: f64) -> f64 {
    h.value_at_percentile(p) as f64
}

fn workload_seed(seed: u64, scenario: &str, repetition: u32) -> u64 {
    // Stable FNV-1a rather than DefaultHasher, whose output is not a public
    // cross-version reproducibility contract.
    let mut hash = 0xcbf29ce484222325u64;
    for byte in scenario.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    seed ^ hash ^ (u64::from(repetition).wrapping_mul(0x9e3779b97f4a7c15))
}

// ---------------------------------------------------------------------------
// Corpus
// ---------------------------------------------------------------------------

struct EventFactory {
    rng: rand::rngs::StdRng,
    actors: Vec<secp256k1::Keypair>,
    actor_pubkeys: Vec<String>,
    last_note: Option<(String, String, usize)>,
}

impl EventFactory {
    fn new(seed: u64) -> Self {
        use rand::SeedableRng;
        use secp256k1::{Keypair, SECP256K1};

        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let actors: Vec<Keypair> = (0..32).map(|_| Keypair::new(SECP256K1, &mut rng)).collect();
        let actor_pubkeys = actors
            .iter()
            .map(|key| hex::encode(key.x_only_public_key().0.serialize()))
            .collect();
        Self {
            rng,
            actors,
            actor_pubkeys,
            last_note: None,
        }
    }

    fn event(&mut self, i: u64, total: u64, now: u64, mix: EventMix) -> Value {
        use secp256k1::{Keypair, SECP256K1};

        let kind = match mix {
            EventMix::Kind1 => 1,
            EventMix::Realistic => match i % 20 {
                0 => 0,
                1 => 3,
                2 => 7,
                3 => 9735,
                4 => 10002,
                5 => 30023,
                _ => 1,
            },
            EventMix::Lifecycle => match i % 10 {
                0 => 20_001,
                1 if self.last_note.is_some() => 5,
                _ => 1,
            },
        };
        let mut actor_index = (i as usize) % self.actors.len();
        if kind == 5 {
            actor_index = self
                .last_note
                .as_ref()
                .map(|(_, _, actor)| *actor)
                .unwrap_or(actor_index);
        }
        // Replaceable/addressable events get unique authors in the general
        // corpus so retained-count comparisons remain exact. Dedicated churn
        // scenarios can intentionally reuse authors later.
        let unique_author = matches!(kind, 0 | 3 | 10_002 | 30_023);
        let key = if unique_author {
            Keypair::new(SECP256K1, &mut self.rng)
        } else {
            self.actors[actor_index]
        };
        let pubkey = hex::encode(key.x_only_public_key().0.serialize());
        let mut tags = vec![json!(["t", format!("tag-{}", i % 64)])];
        match kind {
            1 if i.is_multiple_of(5) => {
                if let Some((event_id, parent_pubkey, _)) = &self.last_note {
                    tags.push(json!(["e", event_id, "", "reply"]));
                    tags.push(json!(["p", parent_pubkey]));
                }
            }
            3 => {
                for contact in self.actor_pubkeys.iter().take(3) {
                    tags.push(json!(["p", contact]));
                }
            }
            5 | 7 | 9735 => {
                if let Some((event_id, parent_pubkey, _)) = &self.last_note {
                    tags.push(json!(["e", event_id]));
                    tags.push(json!(["p", parent_pubkey]));
                }
                if kind == 9735 {
                    tags.push(json!(["amount", format!("{}000", (i % 100) + 1)]));
                }
            }
            10_002 => {
                tags.push(json!(["r", "wss://relay.example"]));
                tags.push(json!(["r", "wss://backup.example", "read"]));
            }
            30_023 => tags.push(json!(["d", format!("article-{i}")])),
            _ => {}
        }
        let content = match kind {
            0 => json!({
                "name": format!("benchmark-actor-{i}"),
                "about": format!("deterministic benchmark profile {i}")
            })
            .to_string(),
            3 | 5 | 9735 | 10_002 | 20_001 => String::new(),
            7 => "+".into(),
            _ => format!(
                "common benchmark event {i} needle{} category{} {}",
                i % 1024,
                i % 32,
                "x".repeat((i % 24) as usize)
            ),
        };
        let created_at = if kind == 20_001 {
            // Ephemerals are live-only and some relays enforce very short
            // acceptance windows. Keep the whole generated burst fresh.
            now
        } else {
            now.saturating_sub(total).saturating_add(i)
        };
        let mut event = json!({
            "created_at": created_at,
            "kind": kind,
            "tags": tags,
            "content": content,
            "pubkey": pubkey,
        });
        let id = wok_event::event_id_hash(&event).expect("generated event is valid JSON");
        let id_hex = hex::encode(id);
        event["id"] = json!(id_hex);
        let signature = SECP256K1.sign_schnorr_no_aux_rand(&id, &key);
        event["sig"] = json!(hex::encode(signature.as_ref()));
        if kind == 1 {
            self.last_note = Some((
                event["id"].as_str().unwrap_or_default().to_string(),
                pubkey,
                actor_index,
            ));
        }
        event
    }
}

fn unix_timestamp() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn count_jsonl_events(path: &Path) -> Result<u64> {
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    use std::io::BufRead;
    let mut count = 0u64;
    for line in reader.lines() {
        if !line?.trim().is_empty() {
            count += 1;
        }
    }
    Ok(count)
}

fn read_event_values(path: &Path) -> Result<Vec<Value>> {
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    use std::io::BufRead;
    reader
        .lines()
        .filter_map(|line| match line {
            Ok(line) if line.trim().is_empty() => None,
            other => Some(other),
        })
        .map(|line| Ok(serde_json::from_str(&line?)?))
        .collect()
}

fn binary_manifest(path: &Path) -> Option<BinaryManifest> {
    let path = std::fs::canonicalize(path).ok()?;
    Some(BinaryManifest {
        path: path.display().to_string(),
        sha256: sha256_file(&path).ok()?,
    })
}

fn corpus_manifest(
    path: &Path,
    events: u64,
    seed: u64,
    base_timestamp: u64,
    event_mix: EventMix,
) -> Result<CorpusManifest> {
    Ok(CorpusManifest {
        format: "nostr-event-jsonl-v1",
        events,
        seed,
        base_timestamp,
        event_mix,
        bytes: std::fs::metadata(path)?.len(),
        sha256: sha256_file(path)?,
        path: std::fs::canonicalize(path)?.display().to_string(),
    })
}

fn generate_events(
    path: &Path,
    n: u64,
    seed: u64,
    base_timestamp: u64,
    mix: EventMix,
) -> Result<PathBuf> {
    let mut factory = EventFactory::new(seed);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = std::fs::File::create(path)?;
    for i in 0..n {
        let ev = factory.event(i, n, base_timestamp, mix);
        writeln!(f, "{}", wok_event::json::to_tao_string(&ev))?;
    }
    Ok(path.to_path_buf())
}

fn generate_values(workload: EventWorkload) -> Result<Vec<Value>> {
    let mut factory = EventFactory::new(workload.seed);
    Ok((0..workload.count)
        .map(|i| factory.event(i, workload.count, workload.base_timestamp, workload.mix))
        .collect())
}

// ---------------------------------------------------------------------------
// CLI helpers
// ---------------------------------------------------------------------------

fn write_conf(bin: &Path, dbdir: &Path, port: u16) -> PathBuf {
    let conf = dbdir.join("strfry.conf");
    let is_wok = bin.file_name().and_then(|name| name.to_str()) == Some("wok");
    let rendered = if is_wok {
        format!(
            "[database]\npath = \"{}\"\n\n[relay]\nbind = \"127.0.0.1\"\nport = {port}\n\n[relay.auth]\nenabled = false\n\n[relay.abuse]\nenabled = false\n",
            dbdir.display()
        )
    } else {
        format!(
            "db = \"{}\"\nrelay {{\n    bind = \"127.0.0.1\"\n    port = {port}\n    auth {{ enabled = false }}\n}}\n",
            dbdir.display()
        )
    };
    let _ = std::fs::write(&conf, rendered);
    conf
}

fn import_with(bin: &Path, dbdir: &Path, jsonl: &Path, verify: bool) -> bool {
    let conf = write_conf(bin, dbdir, 0);
    let file = std::fs::File::open(jsonl).ok();
    let mut cmd = Command::new(bin);
    cmd.arg("--config").arg(&conf).arg("import");
    if !verify {
        cmd.arg("--no-verify");
    }
    cmd.current_dir(dbdir)
        .stdin(file.map(Stdio::from).unwrap_or(Stdio::null()))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn export_count(bin: &Path, dbdir: &Path) -> u64 {
    let conf = write_conf(bin, dbdir, 0);
    let out = Command::new(bin)
        .arg("--config")
        .arg(&conf)
        .arg("export")
        .current_dir(dbdir)
        .output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .lines()
            .filter(|l| !l.is_empty())
            .count() as u64,
        _ => 0,
    }
}

fn negentropy_build(bin: &Path, dbdir: &Path) -> bool {
    let conf = write_conf(bin, dbdir, 0);
    Command::new(bin)
        .arg("--config")
        .arg(&conf)
        .args(["negentropy", "build", "1"])
        .current_dir(dbdir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Live WS trials
// ---------------------------------------------------------------------------

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .ok()
        .and_then(|l| l.local_addr().ok())
        .map(|a| a.port())
        .unwrap_or(18080)
}

fn spawn_relay(bin: &Path, dbdir: &Path, port: u16) -> Result<Child> {
    let conf = write_conf(bin, dbdir, port);
    let child = Command::new(bin)
        .arg("--config")
        .arg(&conf)
        .arg("relay")
        .current_dir(dbdir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("spawn {}", bin.display()))?;
    Ok(child)
}

fn start_target(
    bin: Option<&Path>,
    target_url: Option<&str>,
    dbdir: &Path,
) -> Result<(String, Option<Child>)> {
    if let Some(url) = target_url {
        return Ok((url.trim_end_matches('/').to_string(), None));
    }
    let bin = bin.context("a relay binary is required without --target-url")?;
    let port = free_port();
    let child = spawn_relay(bin, dbdir, port)?;
    Ok((format!("ws://127.0.0.1:{port}"), Some(child)))
}

fn stop_target(child: &mut Option<Child>) {
    if let Some(child) = child {
        let _ = child.kill();
        let _ = child.wait();
    }
}

type WebSocketClient =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

enum ClientConnection {
    WebSocket(Box<WebSocketClient>),
    Unix(tokio::net::UnixStream),
}

impl ClientConnection {
    async fn send(&mut self, message: tokio_tungstenite::tungstenite::Message) -> Result<()> {
        match self {
            Self::WebSocket(stream) => stream.send(message).await.context("WebSocket send"),
            Self::Unix(stream) => {
                let text = message
                    .into_text()
                    .context("Unix transport accepts text frames only")?;
                wok_unix::write_frame(stream, text.as_bytes())
                    .await
                    .context("Unix frame send")
            }
        }
    }

    async fn next(&mut self) -> Option<Result<tokio_tungstenite::tungstenite::Message>> {
        match self {
            Self::WebSocket(stream) => stream
                .next()
                .await
                .map(|message| message.map_err(anyhow::Error::from)),
            Self::Unix(stream) => Some(
                wok_unix::read_frame(stream, 1_000_000)
                    .await
                    .context("Unix frame receive")
                    .map(|body| {
                        tokio_tungstenite::tungstenite::Message::Text(
                            String::from_utf8_lossy(&body).into_owned().into(),
                        )
                    }),
            ),
        }
    }

    async fn close(&mut self, _frame: Option<()>) -> Result<()> {
        match self {
            Self::WebSocket(stream) => stream.close(None).await.context("WebSocket close"),
            Self::Unix(stream) => {
                use tokio::io::AsyncWriteExt;
                stream.shutdown().await.context("Unix socket close")
            }
        }
    }
}

async fn connect_retry(endpoint: &str) -> Result<ClientConnection> {
    let mut last_err = None;
    for _ in 0..50 {
        let connected = if let Some(path) = endpoint.strip_prefix("unix://") {
            wok_unix::connect(path)
                .await
                .map(ClientConnection::Unix)
                .map_err(anyhow::Error::from)
        } else {
            tokio_tungstenite::connect_async(endpoint)
                .await
                .map(|(stream, _)| ClientConnection::WebSocket(Box::new(stream)))
                .map_err(anyhow::Error::from)
        };
        match connected {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                last_err = Some(e.to_string());
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    anyhow::bail!("connect failed: {last_err:?}")
}

/// Publish `n` events concurrently over `conns` connections, with one event
/// in flight per connection. Measures per-publish OK latency and aggregate
/// rate.
fn ws_publish_trial(
    rt: &tokio::runtime::Runtime,
    bin: &Path,
    dbdir: &Path,
    workload: EventWorkload,
    conns: usize,
    hist: &mut Histogram<u64>,
) -> Result<(f64, String, bool, u64)> {
    ws_publish_target_trial(
        rt,
        RelayTarget {
            bin: Some(bin),
            url: None,
            dbdir,
        },
        workload,
        conns,
        hist,
    )
}

fn ws_publish_target_trial(
    rt: &tokio::runtime::Runtime,
    target: RelayTarget<'_>,
    workload: EventWorkload,
    conns: usize,
    hist: &mut Histogram<u64>,
) -> Result<(f64, String, bool, u64)> {
    if conns == 0 {
        anyhow::bail!("publication requires at least one connection");
    }
    let warmup_events = conns.max(50);
    let events = generate_values(EventWorkload {
        count: workload.count.saturating_add(u64::try_from(warmup_events)?),
        ..workload
    })?;
    let (url, mut child) = start_target(target.bin, target.url, target.dbdir)?;
    let out = rt.block_on(async {
        use futures_util::future::join_all;
        use tokio_tungstenite::tungstenite::Message;
        let mut sockets = Vec::new();
        for _ in 0..conns {
            sockets.push(connect_retry(&url).await?);
        }
        // Warm-up (not measured).
        for (i, ev) in events.iter().take(warmup_events).enumerate() {
            let ws = &mut sockets[i % conns];
            ws.send(Message::Text(json!(["EVENT", ev]).to_string().into()))
                .await?;
            let _ = tokio::time::timeout(Duration::from_secs(5), ws.next()).await;
        }
        let mut batches = vec![Vec::new(); conns];
        for (i, event) in events.into_iter().skip(warmup_events).enumerate() {
            let connection = if workload.mix == EventMix::Lifecycle {
                // Deletions must follow the referenced event from the same
                // author. Actor-sticky batches retain that ordering while
                // still exercising concurrent publisher connections.
                event
                    .get("pubkey")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .bytes()
                    .fold(0usize, |hash, byte| {
                        hash.wrapping_mul(16777619) ^ usize::from(byte)
                    })
                    % conns
            } else {
                i % conns
            };
            batches[connection].push(event);
        }
        let mut accepted = 0u64;
        let mut rejected = 0u64;
        let mut latencies = Vec::with_capacity(workload.count as usize);
        let start = Instant::now();
        let publishers = sockets
            .into_iter()
            .zip(batches)
            .map(|(mut socket, batch)| async move {
                let mut accepted = 0u64;
                let mut rejected = 0u64;
                let mut latencies = Vec::with_capacity(batch.len());
                for event in batch {
                    let event_started = Instant::now();
                    socket
                        .send(Message::Text(json!(["EVENT", event]).to_string().into()))
                        .await?;
                    let ok_reply = loop {
                        match tokio::time::timeout(Duration::from_secs(10), socket.next()).await {
                            Ok(Some(Ok(message))) => {
                                let text = message.to_text().unwrap_or("").to_string();
                                if text.contains("\"OK\"") {
                                    break text;
                                }
                            }
                            _ => break String::new(),
                        }
                    };
                    latencies.push(event_started.elapsed().as_micros().max(1) as u64);
                    if ok_reply.contains("true") {
                        accepted += 1;
                    } else {
                        rejected += 1;
                    }
                }
                let _ = socket.close(None).await;
                Ok::<_, anyhow::Error>((accepted, rejected, latencies))
            });
        for publisher in join_all(publishers).await {
            let (publisher_accepted, publisher_rejected, publisher_latencies) = publisher?;
            accepted += publisher_accepted;
            rejected += publisher_rejected;
            latencies.extend(publisher_latencies);
        }
        let elapsed = start.elapsed();
        Ok::<_, anyhow::Error>((accepted, rejected, elapsed, latencies))
    });
    stop_target(&mut child);
    let (accepted, rejected, elapsed, latencies) = out?;
    for latency in latencies {
        hist.record(latency)
            .map_err(|error| anyhow::anyhow!("{error}"))?;
    }
    let eps = accepted as f64 / elapsed.as_secs_f64();
    let miss = u64::from(rejected > 0 || accepted != workload.count);
    let notes = format!(
        "{conns} concurrent connection(s): accepted {accepted}/{}, rejected {rejected}",
        workload.count
    );
    Ok((
        eps,
        notes,
        rejected == 0 && accepted == workload.count,
        miss,
    ))
}

/// Run `queries` REQs of mixed shapes against an exact corpus. Local targets
/// are preloaded automatically; remote targets must already contain the
/// supplied `--corpus`.
fn ws_query_trial(
    rt: &tokio::runtime::Runtime,
    target: RelayTarget<'_>,
    corpus_path: &Path,
    queries: u64,
    hist: &mut Histogram<u64>,
) -> Result<(f64, String, bool, u64)> {
    let events = read_event_values(corpus_path)?;
    if events.is_empty() {
        anyhow::bail!("query corpus is empty");
    }
    let note_events: Vec<&Value> = events
        .iter()
        .filter(|event| event.get("kind").and_then(Value::as_u64) == Some(1))
        .collect();
    if note_events.is_empty() {
        anyhow::bail!("query corpus has no kind 1 events");
    }
    let measured_queries = queries.max(1);
    let total_queries = measured_queries.saturating_add(20);
    if let Some(bin) = target.bin {
        if !import_with(bin, target.dbdir, corpus_path, false) {
            anyhow::bail!("pre-import failed");
        }
        let retained = export_count(bin, target.dbdir);
        if retained != events.len() as u64 {
            anyhow::bail!(
                "pre-import retained {retained}/{} corpus events",
                events.len()
            );
        }
    }
    let (url, mut child) = start_target(target.bin, target.url, target.dbdir)?;
    let out = rt.block_on(async {
        use tokio_tungstenite::tungstenite::Message;
        let mut sockets = Vec::new();
        for _ in 0..4 {
            sockets.push(connect_retry(&url).await?);
        }
        let filters: Vec<Value> = (0..total_queries)
            .map(|q| {
                let ev = &events[(q as usize * 7) % events.len()];
                let note = note_events[(q as usize * 11) % note_events.len()];
                let id = ev["id"].as_str().unwrap_or("");
                let pk = note["pubkey"].as_str().unwrap_or("");
                match q % 4 {
                    0 => json!({"ids":[id]}),
                    1 => json!({"authors":[pk],"kinds":[1],"limit":50}),
                    2 => json!({"kinds":[1],"since":note["created_at"].as_u64().unwrap_or(0),"limit":20}),
                    _ => json!({"#t":[format!("tag-{}", q % 64)],"limit":50}),
                }
            })
            .collect();
        // Warm-up.
        for (i, f) in filters.iter().take(20).enumerate() {
            let ws = &mut sockets[i % 4];
            let subscription = format!("warm-{i}");
            ws.send(Message::Text(
                json!(["REQ", subscription, f]).to_string().into(),
            ))
            .await?;
            while let Ok(Some(Ok(m))) = tokio::time::timeout(Duration::from_secs(5), ws.next()).await
            {
                if m.to_text().unwrap_or("").contains("EOSE") {
                    break;
                }
            }
            ws.send(Message::Text(
                json!(["CLOSE", subscription]).to_string().into(),
            ))
            .await?;
        }
        let start = Instant::now();
        let mut done = 0u64;
        let mut results = 0u64;
        let mut mismatches = 0u64;
        for (i, f) in filters.iter().skip(20).enumerate() {
            let ws = &mut sockets[i % 4];
            let subscription = format!("query-{i}");
            let t0 = Instant::now();
            ws.send(Message::Text(
                json!(["REQ", subscription, f]).to_string().into(),
            ))
            .await?;
            let mut query_results = 0u64;
            let mut saw_eose = false;
            while let Ok(Some(Ok(m))) =
                tokio::time::timeout(Duration::from_secs(10), ws.next()).await
            {
                let t = m.to_text().unwrap_or("");
                if t.contains("\"EVENT\"") {
                    results += 1;
                    query_results += 1;
                }
                if t.contains("EOSE") {
                    saw_eose = true;
                    break;
                }
            }
            ws.send(Message::Text(
                json!(["CLOSE", subscription]).to_string().into(),
            ))
            .await?;
            hist.record(t0.elapsed().as_micros().max(1) as u64)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            if !saw_eose || query_results == 0 {
                mismatches += 1;
            }
            done += 1;
        }
        let elapsed = start.elapsed();
        for ws in &mut sockets {
            let _ = ws.close(None).await;
        }
        Ok::<_, anyhow::Error>((done, results, mismatches, elapsed))
    });
    stop_target(&mut child);
    let (done, results, mismatches, elapsed) = out?;
    let qps = done as f64 / elapsed.as_secs_f64();
    let notes = format!("{done} mixed REQs, {results} events returned");
    Ok((qps, notes, mismatches == 0, mismatches))
}

/// Repeated author+kind+until pagination into progressively older history.
/// This is the workload from strfry issue #157, where later pages can degrade
/// from sub-second to tens of seconds on fragmented, production-sized stores.
fn deep_history_trial(
    rt: &tokio::runtime::Runtime,
    target: RelayTarget<'_>,
    corpus_path: &Path,
    queries: u64,
    hist: &mut Histogram<u64>,
) -> Result<(f64, String, bool, u64)> {
    use std::collections::HashMap;

    let events = read_event_values(corpus_path)?;
    let mut authors = HashMap::<String, u64>::new();
    for event in &events {
        if event.get("kind").and_then(Value::as_u64) == Some(1) {
            if let Some(author) = event.get("pubkey").and_then(Value::as_str) {
                *authors.entry(author.to_string()).or_default() += 1;
            }
        }
    }
    let (author, n) = authors
        .into_iter()
        .max_by_key(|(_, count)| *count)
        .context("deep-history corpus has no kind 1 author")?;
    if let Some(bin) = target.bin {
        if !import_with(bin, target.dbdir, corpus_path, false) {
            anyhow::bail!("deep-history import failed");
        }
        let imported = export_count(bin, target.dbdir);
        if imported != events.len() as u64 {
            anyhow::bail!(
                "deep-history import retained {imported}/{} events",
                events.len()
            );
        }
    }
    let page_size = 500u64;
    let available_pages = n.div_ceil(page_size);
    let pages = queries.max(1).min(available_pages);
    let (url, mut child) = start_target(target.bin, target.url, target.dbdir)?;
    let out = rt.block_on(async {
        use std::collections::HashSet;
        use tokio_tungstenite::tungstenite::Message;

        let mut socket = connect_retry(&url).await?;
        let mut until = u64::MAX;
        let mut seen = HashSet::new();
        let mut mismatches = 0u64;
        let mut latencies = Vec::new();
        let started_all = Instant::now();
        for page in 0..pages {
            let started = Instant::now();
            socket
                .send(Message::Text(
                    json!(["REQ", "deep", {
                        "authors":[author],
                        "kinds":[1],
                        "until":until,
                        "limit":page_size
                    }])
                    .to_string()
                    .into(),
                ))
                .await?;
            let mut page_events = 0u64;
            let mut oldest = until;
            let mut saw_eose = false;
            while let Ok(Some(Ok(message))) =
                tokio::time::timeout(Duration::from_secs(60), socket.next()).await
            {
                let text = message.to_text().unwrap_or("");
                let parsed: Value = match serde_json::from_str(text) {
                    Ok(value) => value,
                    Err(_) => {
                        mismatches += 1;
                        continue;
                    }
                };
                match parsed.get(0).and_then(Value::as_str) {
                    Some("EVENT") => {
                        page_events += 1;
                        if let Some(event) = parsed.get(2) {
                            let created = event
                                .get("created_at")
                                .and_then(Value::as_u64)
                                .unwrap_or(u64::MAX);
                            oldest = oldest.min(created);
                            if let Some(id) = event.get("id").and_then(Value::as_str) {
                                if !seen.insert(id.to_string()) {
                                    mismatches += 1;
                                }
                            } else {
                                mismatches += 1;
                            }
                        }
                    }
                    Some("EOSE") => {
                        saw_eose = true;
                        break;
                    }
                    Some("CLOSED") => {
                        mismatches += 1;
                        break;
                    }
                    _ => {}
                }
            }
            latencies.push(started.elapsed().as_micros().max(1) as u64);
            let expected_page = page_size.min(n.saturating_sub(page * page_size));
            if !saw_eose || page_events != expected_page || oldest == u64::MAX {
                mismatches += 1;
                break;
            }
            until = oldest.saturating_sub(1);
        }
        let elapsed = started_all.elapsed();
        let _ = socket.close(None).await;
        Ok::<_, anyhow::Error>((seen.len() as u64, mismatches, elapsed, latencies))
    });
    stop_target(&mut child);
    let (seen, mut mismatches, elapsed, latencies) = out?;
    for latency in latencies {
        hist.record(latency)
            .map_err(|error| anyhow::anyhow!("{error}"))?;
    }
    let expected = n.min(pages * page_size);
    if seen != expected {
        mismatches += 1;
    }
    let qps = pages as f64 / elapsed.as_secs_f64();
    let notes = format!(
        "{pages} progressive 500-event pages over {n} events from the corpus's busiest author; {seen} unique events"
    );
    Ok((qps, notes, mismatches == 0, mismatches))
}

/// Measure historical REQ latency while a second connection continuously
/// publishes accepted events. This catches cursor/refill regressions that are
/// invisible in a read-only corpus.
fn mixed_read_write_trial(
    rt: &tokio::runtime::Runtime,
    target: RelayTarget<'_>,
    corpus_path: &Path,
    workload: EventWorkload,
    queries: u64,
    hist: &mut Histogram<u64>,
) -> Result<(f64, String, bool, u64)> {
    let base_events = read_event_values(corpus_path)?;
    let n = base_events.len() as u64;
    if n == 0 {
        anyhow::bail!("mixed-load corpus is empty");
    }
    if let Some(bin) = target.bin {
        if !import_with(bin, target.dbdir, corpus_path, false) {
            anyhow::bail!("mixed-load import failed");
        }
        let imported = export_count(bin, target.dbdir);
        if imported != n {
            anyhow::bail!("mixed-load import retained {imported}/{n} events");
        }
    }
    let query_count = queries.max(1);
    let write_count = query_count.max(50).min(n);
    let new_events = generate_values(EventWorkload {
        count: write_count,
        seed: workload.seed.wrapping_add(10_000),
        // Keep concurrent writes recent but never push them into the future.
        // The distinct workload seed is sufficient to avoid corpus IDs.
        base_timestamp: workload.base_timestamp,
        ..workload
    })?;
    let (url, mut child) = start_target(target.bin, target.url, target.dbdir)?;
    let out = rt.block_on(async {
        use tokio_tungstenite::tungstenite::Message;

        let mut query_socket = connect_retry(&url).await?;
        let mut write_socket = connect_retry(&url).await?;
        let query_future = async {
            let started_all = Instant::now();
            let mut completed = 0u64;
            let mut results = 0u64;
            let mut mismatches = 0u64;
            let mut latencies = Vec::new();
            for query_number in 0..query_count {
                let started = Instant::now();
                let subscription_id = format!("mixed-{query_number}");
                query_socket
                    .send(Message::Text(
                        json!(["REQ", subscription_id, {
                            "kinds":[1],
                            "limit":100,
                            "until":u64::MAX.saturating_sub(query_number)
                        }])
                        .to_string()
                        .into(),
                    ))
                    .await?;
                let mut query_results = 0u64;
                let mut saw_eose = false;
                while let Ok(Some(Ok(message))) =
                    tokio::time::timeout(Duration::from_secs(30), query_socket.next()).await
                {
                    let text = message.to_text().unwrap_or("");
                    if let Ok(frame) = serde_json::from_str::<Value>(text) {
                        let command = frame.get(0).and_then(Value::as_str);
                        let frame_sub = frame.get(1).and_then(Value::as_str);
                        if frame_sub != Some(subscription_id.as_str()) {
                            continue;
                        }
                        match command {
                            Some("EVENT") => query_results += 1,
                            Some("CLOSED") => {
                                mismatches += 1;
                                break;
                            }
                            Some("EOSE") => {
                                saw_eose = true;
                                break;
                            }
                            _ => {}
                        }
                    }
                }
                query_socket
                    .send(Message::Text(
                        json!(["CLOSE", subscription_id]).to_string().into(),
                    ))
                    .await?;
                latencies.push(started.elapsed().as_micros().max(1) as u64);
                // Up to `limit` records come from the historical snapshot.
                // Events committed after that snapshot are deliberately
                // caught up before EOSE, so concurrent writes may add to it.
                if !saw_eose || query_results == 0 || query_results > 100 + write_count {
                    mismatches += 1;
                }
                results += query_results;
                completed += 1;
            }
            let elapsed = started_all.elapsed();
            let _ = query_socket.close(None).await;
            Ok::<_, anyhow::Error>((completed, results, mismatches, elapsed, latencies))
        };
        let write_future = async {
            let mut accepted = 0u64;
            for event in &new_events {
                write_socket
                    .send(Message::Text(json!(["EVENT", event]).to_string().into()))
                    .await?;
                while let Ok(Some(Ok(message))) =
                    tokio::time::timeout(Duration::from_secs(30), write_socket.next()).await
                {
                    let text = message.to_text().unwrap_or("");
                    if text.contains("\"OK\"") {
                        if text.contains("true") {
                            accepted += 1;
                        }
                        break;
                    }
                }
            }
            let _ = write_socket.close(None).await;
            Ok::<_, anyhow::Error>(accepted)
        };
        let (query_result, write_result) = tokio::join!(query_future, write_future);
        Ok::<_, anyhow::Error>((query_result?, write_result?))
    });
    stop_target(&mut child);
    let ((completed, results, mut mismatches, elapsed, latencies), accepted) = out?;
    for latency in latencies {
        hist.record(latency)
            .map_err(|error| anyhow::anyhow!("{error}"))?;
    }
    if accepted != write_count || completed != query_count {
        mismatches += 1;
    }
    let qps = completed as f64 / elapsed.as_secs_f64();
    let notes = format!(
        "{completed} historical REQs returned {results} events while {accepted}/{write_count} writes succeeded"
    );
    Ok((qps, notes, mismatches == 0, mismatches))
}

/// Preload a deterministic vocabulary, then exercise rare and common+rare
/// NIP-50 queries. Every returned event is checked for the requested term and
/// every response must honor the post-ranking limit.
fn ws_search_trial(
    rt: &tokio::runtime::Runtime,
    bin: &Path,
    dbdir: &Path,
    workload: EventWorkload,
    queries: u64,
    hist: &mut Histogram<u64>,
) -> Result<(f64, String, bool, u64)> {
    let n = workload.count;
    let events = generate_values(EventWorkload {
        count: n.max(1),
        ..workload
    })?;
    let jsonl = dbdir.join("events.jsonl");
    {
        let mut file = std::fs::File::create(&jsonl)?;
        for event in &events {
            writeln!(file, "{}", wok_event::json::to_tao_string(event))?;
        }
    }
    if !import_with(bin, dbdir, &jsonl, false) {
        anyhow::bail!("search corpus import failed");
    }

    let port = free_port();
    let mut child = spawn_relay(bin, dbdir, port)?;
    let out = rt.block_on(async {
        use tokio_tungstenite::tungstenite::Message;

        let url = format!("ws://127.0.0.1:{port}/");
        let mut sockets = Vec::new();
        for _ in 0..4 {
            sockets.push(connect_retry(&url).await?);
        }
        let queries = queries.max(1);
        let warmup = (queries / 10).clamp(1, 20);
        let total = queries + warmup;
        let mut done = 0u64;
        let mut returned = 0u64;
        let mut mismatches = 0u64;
        let measured_start = Instant::now();

        for query_number in 0..total {
            let needle = format!("needle{}", (query_number * 17) % 1024);
            let (search, required_term) = match query_number % 3 {
                0 => (needle.clone(), needle.as_str()),
                1 => (format!("common {needle}"), needle.as_str()),
                _ => ("common".to_string(), "common"),
            };
            let socket_index = query_number as usize % sockets.len();
            let socket = &mut sockets[socket_index];
            let started = Instant::now();
            socket
                .send(Message::Text(
                    json!(["REQ", "nip50-bench", {"search":search, "kinds":[1], "limit":20}])
                        .to_string()
                        .into(),
                ))
                .await?;
            let mut query_results = 0u64;
            let mut saw_eose = false;
            while let Ok(Some(Ok(message))) =
                tokio::time::timeout(Duration::from_secs(10), socket.next()).await
            {
                let text = message.to_text().unwrap_or("");
                if text.contains("\"EVENT\"") {
                    query_results += 1;
                    if !text.contains(required_term) {
                        mismatches += 1;
                    }
                }
                if text.contains("\"CLOSED\"") {
                    mismatches += 1;
                    break;
                }
                if text.contains("EOSE") {
                    saw_eose = true;
                    break;
                }
            }
            if !saw_eose || query_results > 20 {
                mismatches += 1;
            }
            if query_number >= warmup {
                hist.record(started.elapsed().as_micros().max(1) as u64)
                    .map_err(|error| anyhow::anyhow!("{error}"))?;
                done += 1;
                returned += query_results;
            }
        }
        let elapsed = measured_start.elapsed();
        for socket in &mut sockets {
            let _ = socket.close(None).await;
        }
        Ok::<_, anyhow::Error>((done, returned, mismatches, elapsed))
    });
    let _ = child.kill();
    let _ = child.wait();
    let (done, returned, mismatches, elapsed) = out?;
    let qps = done as f64 / elapsed.as_secs_f64();
    let notes = format!("{done} ranked NIP-50 REQs over {n} events, {returned} verified results");
    Ok((qps, notes, mismatches == 0, mismatches))
}

/// 1 publisher, `subs` subscribers; measures per-event delivery latency and
/// verifies every subscriber receives every event.
fn live_fanout_trial(
    rt: &tokio::runtime::Runtime,
    target: RelayTarget<'_>,
    workload: EventWorkload,
    subs: usize,
    hist: &mut Histogram<u64>,
) -> Result<(f64, String, bool, u64)> {
    let n = workload.count;
    let events = generate_values(workload)?;
    let (url, mut child) = start_target(target.bin, target.url, target.dbdir)?;
    let out = rt.block_on(async {
        use tokio_tungstenite::tungstenite::Message;
        let mut subscribers = Vec::new();
        for i in 0..subs {
            let mut ws = connect_retry(&url).await?;
            let filter = match workload.mix {
                EventMix::Kind1 => json!({"kinds":[1]}),
                EventMix::Realistic | EventMix::Lifecycle => json!({}),
            };
            ws.send(Message::Text(
                json!(["REQ", format!("s{i}"), filter]).to_string().into(),
            ))
            .await?;
            subscribers.push(ws);
        }
        // Wait for all EOSEs.
        for ws in &mut subscribers {
            while let Ok(Some(Ok(m))) =
                tokio::time::timeout(Duration::from_secs(5), ws.next()).await
            {
                if m.to_text().unwrap_or("").contains("EOSE") {
                    break;
                }
            }
        }
        let mut publisher = connect_retry(&url).await?;
        let start = Instant::now();
        for ev in &events {
            publisher
                .send(Message::Text(json!(["EVENT", ev]).to_string().into()))
                .await?;
            // Read our own OK to serialize the flow.
            let _ = tokio::time::timeout(Duration::from_secs(5), publisher.next()).await;
        }
        // Collect deliveries.
        let mut delivered = 0u64;
        let t_collect = Instant::now();
        'collect: for ws in &mut subscribers {
            let mut got = 0u64;
            while got < n {
                match tokio::time::timeout(Duration::from_secs(10), ws.next()).await {
                    Ok(Some(Ok(m))) => {
                        if m.to_text().unwrap_or("").contains("\"EVENT\"") {
                            got += 1;
                            delivered += 1;
                        }
                    }
                    _ => break 'collect,
                }
            }
        }
        let collect_elapsed = t_collect.elapsed();
        hist.record(collect_elapsed.as_micros().max(1) as u64)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let elapsed = start.elapsed();
        let _ = publisher.close(None).await;
        for subscriber in &mut subscribers {
            let _ = subscriber.close(None).await;
        }
        Ok::<_, anyhow::Error>((delivered, elapsed, collect_elapsed))
    });
    stop_target(&mut child);
    let (delivered, elapsed, _collect) = out?;
    let expected = n * subs as u64;
    let eps = delivered as f64 / elapsed.as_secs_f64();
    let miss = if delivered != expected { 1 } else { 0 };
    let notes = format!("{subs} subscribers x {n} events: delivered {delivered}/{expected}");
    Ok((eps, notes, miss == 0, miss))
}

/// Open and hold a large number of quiet WebSocket connections. Connection
/// setup latency is recorded individually and all sockets must remain usable
/// until the hold period finishes.
fn idle_connections_trial(
    rt: &tokio::runtime::Runtime,
    bin: Option<&Path>,
    target_url: Option<&str>,
    dbdir: &Path,
    connections: usize,
    hold_seconds: u64,
    hist: &mut Histogram<u64>,
) -> Result<(f64, String, bool, u64)> {
    let (url, mut child) = start_target(bin, target_url, dbdir)?;
    let out = rt.block_on(async {
        let started = Instant::now();
        let mut sockets = Vec::with_capacity(connections);
        for _ in 0..connections {
            let connection_started = Instant::now();
            match connect_retry(&url).await {
                Ok(socket) => {
                    hist.record(connection_started.elapsed().as_micros().max(1) as u64)
                        .map_err(|error| anyhow::anyhow!("{error}"))?;
                    sockets.push(socket);
                }
                Err(_) => break,
            }
        }
        let open_elapsed = started.elapsed();
        tokio::time::sleep(Duration::from_secs(hold_seconds)).await;
        for socket in &mut sockets {
            let _ = socket.close(None).await;
        }
        Ok::<_, anyhow::Error>((sockets.len(), open_elapsed))
    });
    stop_target(&mut child);
    let (opened, elapsed) = out?;
    let mismatches = u64::from(opened != connections);
    let rate = opened as f64 / elapsed.as_secs_f64().max(f64::EPSILON);
    let notes =
        format!("opened {opened}/{connections} connections and held them for {hold_seconds}s");
    Ok((rate, notes, mismatches == 0, mismatches))
}

/// Time from relay spawn to first answered query on a prebuilt DB.
fn cold_start_trial(
    rt: &tokio::runtime::Runtime,
    bin: &Path,
    dbdir: &Path,
    hist: &mut Histogram<u64>,
) -> Result<u64> {
    let port = free_port();
    let start = Instant::now();
    let mut child = spawn_relay(bin, dbdir, port)?;
    let out = rt.block_on(async {
        use tokio_tungstenite::tungstenite::Message;
        let url = format!("ws://127.0.0.1:{port}/");
        let mut ws = connect_retry(&url).await?;
        ws.send(Message::Text(
            r#"["REQ","s",{"kinds":[1],"limit":1}]"#.into(),
        ))
        .await?;
        while let Ok(Some(Ok(m))) = tokio::time::timeout(Duration::from_secs(10), ws.next()).await {
            if m.to_text().unwrap_or("").contains("EOSE") {
                break;
            }
        }
        Ok::<_, anyhow::Error>(())
    });
    let ms = start.elapsed().as_micros().max(1) as u64 / 1000;
    let _ = child.kill();
    let _ = child.wait();
    out?;
    hist.record(ms)?;
    Ok(ms)
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

fn render_markdown(args: &Args, trials: &[Trial]) -> String {
    let mut s = String::from("# wok vs strfry benchmark summary\n\n");
    s.push_str(&format!(
        "profile={} seed={} base_timestamp={} event_mix={:?} repetitions={} host={} os={} arch={}\n\n",
        args.profile,
        args.seed,
        args.base_timestamp.unwrap_or_default(),
        args.event_mix,
        args.repetitions,
        hostname(),
        std::env::consts::OS,
        std::env::consts::ARCH
    ));
    if let Some(target_url) = args.target_endpoint() {
        s.push_str(&format!(
            "external_target={} ({})\n\n",
            args.target_label, target_url
        ));
    }
    s.push_str("The campaign manifest records the corpus and binary SHA-256 values. Each local comparison uses the same deterministic workload for both relays; remote repetitions use deterministic per-scenario seeds so a persistent target does not see duplicate events. `ok=false` means a correctness failure, not slowness. Do not rank relays from a single noisy run.\n\n");
    s.push_str("| relay | scenario | rep | ok | throughput/s | p50 ms | p90 ms | p99 ms | max ms | errors | mismatches | notes |\n|---|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---|\n");
    for t in trials {
        s.push_str(&format!(
            "| {} | {} | {} | {} | {:.1} | {:.2} | {:.2} | {:.2} | {:.1} | {} | {} | {} |\n",
            t.relay,
            t.scenario,
            t.repetition,
            t.ok,
            t.throughput_per_s,
            t.latency_p50_ms,
            t.latency_p90_ms,
            t.latency_p99_ms,
            t.latency_max_ms,
            t.errors,
            t.mismatches,
            t.notes
        ));
    }
    let selection = args.scenario.as_ref().map_or_else(
        || format!("--profile {}", args.profile),
        |scenario| format!("--scenario {scenario}"),
    );
    let target = if let Some(path) = &args.target_unix {
        format!(
            " --target-unix \"{}\" --target-label {}",
            path.display(),
            args.target_label
        )
    } else if let Some(url) = &args.target_url {
        format!(
            " --target-url \"{url}\" --target-label {}",
            args.target_label
        )
    } else {
        " --strfry /path/to/strfry --wok ./target/release/wok".into()
    };
    s.push_str(&format!(
        "\nReproduction:\n\n```bash\ncargo build --release -p wok-cli -p wok-bench\n./target/release/wok-bench {selection} --out bench-results{target} --seed {} --base-timestamp {} --event-mix {} --repetitions {}\n```\n",
        args.seed,
        args.base_timestamp.unwrap_or_default(),
        args.event_mix.to_possible_value().expect("value enum").get_name(),
        args.repetitions
    ));
    s
}

fn hostname() -> String {
    if let Ok(h) = std::env::var("HOSTNAME").or_else(|_| std::env::var("HOST")) {
        if !h.is_empty() {
            return h;
        }
    }
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpus_is_byte_reproducible() {
        let first_dir = TempDir::new().unwrap();
        let second_dir = TempDir::new().unwrap();
        let first = generate_events(
            &first_dir.path().join("corpus.jsonl"),
            32,
            7,
            1_700_000_000,
            EventMix::Realistic,
        )
        .unwrap();
        let second = generate_events(
            &second_dir.path().join("corpus.jsonl"),
            32,
            7,
            1_700_000_000,
            EventMix::Realistic,
        )
        .unwrap();
        assert_eq!(sha256_file(&first).unwrap(), sha256_file(&second).unwrap());
        assert_eq!(
            std::fs::read(first).unwrap(),
            std::fs::read(second).unwrap()
        );
    }

    #[test]
    fn workload_seeds_are_stable_and_distinct() {
        assert_eq!(
            workload_seed(1, "live_fanout", 2),
            workload_seed(1, "live_fanout", 2)
        );
        assert_ne!(
            workload_seed(1, "live_fanout", 1),
            workload_seed(1, "live_fanout", 2)
        );
        assert_ne!(
            workload_seed(1, "live_fanout", 1),
            workload_seed(1, "ws_publish_scaled", 1)
        );
    }

    #[test]
    fn realistic_corpus_has_reused_actors_and_relational_tags() {
        let events = generate_values(EventWorkload {
            count: 1_000,
            seed: 9,
            base_timestamp: 1_700_000_000,
            mix: EventMix::Realistic,
        })
        .unwrap();
        let note_authors: std::collections::HashSet<&str> = events
            .iter()
            .filter(|event| event["kind"] == 1)
            .filter_map(|event| event["pubkey"].as_str())
            .collect();
        assert_eq!(note_authors.len(), 32);
        assert!(events.iter().any(|event| {
            event["kind"] == 7
                && event["tags"]
                    .as_array()
                    .is_some_and(|tags| tags.iter().any(|tag| tag[0] == "e"))
        }));
        assert!(events.iter().any(|event| {
            event["kind"] == 1
                && event["tags"]
                    .as_array()
                    .is_some_and(|tags| tags.iter().any(|tag| tag[0] == "e"))
        }));
    }

    #[test]
    fn lifecycle_corpus_contains_fresh_ephemeral_and_deletion_events() {
        let base_timestamp = 1_800_000_000;
        let events = generate_values(EventWorkload {
            count: 100,
            seed: 11,
            base_timestamp,
            mix: EventMix::Lifecycle,
        })
        .unwrap();
        assert!(events.iter().any(|event| {
            event["kind"] == 20_001
                && event["created_at"].as_u64().unwrap_or_default() + 30 >= base_timestamp
        }));
        assert!(events.iter().any(|event| {
            event["kind"] == 5
                && event["tags"]
                    .as_array()
                    .is_some_and(|tags| tags.iter().any(|tag| tag[0] == "e"))
        }));
    }

    #[test]
    fn unix_target_is_an_external_endpoint_and_conflicts_with_url() {
        let args = Args::try_parse_from([
            "wok-bench",
            "--target-unix",
            "/tmp/wok-bench.sock",
            "--target-label",
            "wok-unix",
        ])
        .unwrap();
        assert!(args.has_external_target());
        assert_eq!(
            args.target_endpoint().as_deref(),
            Some("unix:///tmp/wok-bench.sock")
        );
        assert!(Args::try_parse_from([
            "wok-bench",
            "--target-unix",
            "/tmp/wok-bench.sock",
            "--target-url",
            "ws://127.0.0.1:7777",
        ])
        .is_err());
    }

    #[tokio::test]
    async fn client_connection_uses_length_prefixed_unix_frames() {
        use tokio_tungstenite::tungstenite::Message;

        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("bench.sock");
        let listener = wok_unix::bind_unix(&socket, 0o600, "", "").unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = wok_unix::read_frame(&mut stream, 1024).await.unwrap();
            assert_eq!(request, br#"["REQ","test",{}]"#);
            wok_unix::write_frame(&mut stream, br#"["EOSE","test"]"#)
                .await
                .unwrap();
        });

        let mut client = connect_retry(&format!("unix://{}", socket.display()))
            .await
            .unwrap();
        client
            .send(Message::Text(r#"["REQ","test",{}]"#.into()))
            .await
            .unwrap();
        let response = client.next().await.unwrap().unwrap();
        assert_eq!(response.to_text().unwrap(), r#"["EOSE","test"]"#);
        let _ = client.close(None).await;
        server.await.unwrap();
    }
}
