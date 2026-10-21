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

#![forbid(unsafe_code)]

mod author_kinds;
mod clients;
mod live;
mod transport;

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

static CLIENT_NODELAY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

#[derive(Parser, Debug)]
struct Args {
    /// Disable client Nagle; explicit false permits controlled transport comparisons.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    tcp_nodelay: bool,
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
    /// Wok TOML that --scenario clients runs against (default: built-in
    /// defaults). Abuse controls and AUTH stay as the file sets them; only the
    /// database path, listen address and port, Unix socket, real-IP header and
    /// an empty AUTH service URL are replaced for the disposable trial.
    #[arg(long)]
    relay_config: Option<PathBuf>,
    /// Outbox clients simulated by --scenario clients (about 30 subscriptions each).
    #[arg(long, default_value_t = 20)]
    clients: usize,
    /// Marmot (MDK-shaped) clients simulated by --scenario clients.
    #[arg(long, default_value_t = 4)]
    marmot_clients: usize,
    /// Groups per Marmot client: one live 445 #h subscription and one NIP-77 pass each.
    #[arg(long, default_value_t = 10)]
    marmot_groups: usize,
    /// Gift wraps in each Marmot add-member burst (one commit plus N Welcomes).
    #[arg(long, default_value_t = 10)]
    marmot_invitees: usize,
    /// Largest outbox follow list; sizes are log-uniform from 100 up to this.
    #[arg(long, default_value_t = 2_000)]
    max_follows: usize,
    /// Seconds of activity in --scenario clients, before a 2 s delivery drain.
    #[arg(long, default_value_t = 15)]
    clients_duration_secs: u64,
    /// Milliseconds between re-REQs of each replaced subscription.
    #[arg(long, default_value_t = 3_000)]
    replace_interval_ms: u64,
    /// Background publications per second in --scenario clients (0 disables).
    #[arg(long, default_value_t = 20.0)]
    publish_rate: f64,
    /// Simulated clients per source address; 0 sends every client from the
    /// bench host's own address.
    #[arg(long, default_value_t = 1)]
    clients_per_address: usize,
    /// Offer permessage-deflate from --scenario clients connections.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    client_deflate: bool,
    /// Fail --scenario clients when any request is refused.
    #[arg(long)]
    expect_no_refusals: bool,
    /// Events per history burst in --scenario ws_transport.
    #[arg(long, default_value_t = 500)]
    burst_events: u64,
    /// History bursts per deflate mode in --scenario ws_transport.
    #[arg(long, default_value_t = 40)]
    bursts: usize,
    /// Connect, fetch, close cycles per deflate mode in --scenario ws_transport.
    #[arg(long, default_value_t = 1_000)]
    churn_connections: usize,
    /// Seconds --scenario ws_transport holds its connections silent before a
    /// last memory sample (0 skips it).
    #[arg(long, default_value_t = 0)]
    transport_idle_secs: u64,
    /// Authors that monitor_index and live_subscriptions follow lists, posts
    /// and mentions draw from, by a Zipf law.
    #[arg(long, default_value_t = 20_000)]
    live_authors: usize,
    /// Connections in --scenario monitor_index and live_subscriptions.
    #[arg(long, default_value_t = 1_000)]
    live_conns: usize,
    /// Subscriptions per connection. Of every ten, six are author feeds, then
    /// a `#p` mention, a `#p` zap receipt and two `#e` thread subscriptions.
    #[arg(long, default_value_t = 10)]
    live_subs_per_conn: usize,
    /// Smallest feed author list.
    #[arg(long, default_value_t = 50)]
    live_min_authors: usize,
    /// Largest feed author list, also the size churn REQs use.
    #[arg(long, default_value_t = 500)]
    live_max_authors: usize,
    /// Events --scenario monitor_index matches before its churn.
    #[arg(long, default_value_t = 20_000)]
    live_events: usize,
    /// Publications per second in --scenario live_subscriptions.
    #[arg(long, default_value_t = 50.0)]
    live_rate: f64,
    /// Seconds of the steady, churn and recovered live_subscriptions phases.
    #[arg(long, default_value_t = 10)]
    live_phase_secs: u64,
    /// Extra connections that churn subscriptions in live_subscriptions.
    #[arg(long, default_value_t = 50)]
    live_churners: usize,
    /// REQs per second the live_subscriptions churners send in total.
    #[arg(long, default_value_t = 200.0)]
    live_churn_rate: f64,
    /// Second wok binary that --scenario author_kinds measures on the same
    /// dataset, for a before/after comparison (for example a build of master).
    #[arg(long)]
    wok_baseline: Option<PathBuf>,
    /// Authors in the --scenario author_kinds dataset.
    #[arg(long, default_value_t = 5_000)]
    authors: usize,
    /// Directory that keeps --scenario author_kinds datasets, so later runs
    /// and other binaries reuse the same database files.
    #[arg(long, default_value = "bench-results/datasets")]
    dataset_dir: PathBuf,
    /// Warm runs per --scenario author_kinds query shape, after one cold run.
    #[arg(long, default_value_t = 15)]
    warm_runs: usize,
    /// Seconds after which a shape stops its warm runs (it keeps at least 3).
    #[arg(long, default_value_t = 30)]
    shape_secs: u64,
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
    client_tcp_nodelay: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    clients: Option<clients::ClientsReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transport: Option<transport::TransportReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    monitor_index: Option<live::IndexReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    live_subscriptions: Option<live::LiveReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    author_kinds: Option<author_kinds::Report>,
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
    CLIENT_NODELAY.store(args.tcp_nodelay, std::sync::atomic::Ordering::Relaxed);
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
        "clients",
        "ws_transport",
        "monitor_index",
        "live_subscriptions",
        "author_kinds",
    ];
    let scenarios: Vec<&str> = if let Some(scenario) = args.scenario.as_deref() {
        if !known_scenarios.contains(&scenario) {
            anyhow::bail!("unknown benchmark scenario: {scenario}");
        }
        vec![scenario]
    } else {
        profile_scenarios
    };
    if args.relay_config.is_some() && !scenarios.contains(&"clients") {
        anyhow::bail!("--relay-config is used only by --scenario clients");
    }
    if args.clients_per_address > 0
        && (args.clients + args.marmot_clients).div_ceil(args.clients_per_address) > 1 << 22
    {
        anyhow::bail!(
            "--clients-per-address leaves more addresses than the 10.64.0.0/10 range holds"
        );
    }

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
    let (corpus_path, event_count) = if args.scenario.as_deref() == Some("author_kinds") {
        anyhow::ensure!(
            args.corpus.is_none() && !args.has_external_target(),
            "--scenario author_kinds generates its own dataset and starts its own relays"
        );
        let opts = author_kinds_options(&args)?;
        author_kinds::ensure_dataset(&opts)?;
        (author_kinds::Dataset::corpus_path(&opts), opts.events)
    } else if let Some(path) = &args.corpus {
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
            } else if matches!(
                *scenario,
                "nip50_search"
                    | "clients"
                    | "ws_transport"
                    | "author_kinds"
                    | "monitor_index"
                    | "live_subscriptions"
            ) {
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
    anyhow::ensure!(
        trials
            .iter()
            .all(|t| t.ok && t.errors == 0 && t.mismatches == 0),
        "benchmark trials failed; see {}",
        jsonl.display()
    );
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
    let mut clients_report = None;
    let mut transport_report = None;
    let mut monitor_index_report = None;
    let mut live_report = None;
    let mut author_kinds_report = None;

    let bin = if args.has_external_target() || scenario == "monitor_index" {
        // monitor_index runs the index compiled into this binary.
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
        "clients" => {
            let bin = local_bin()?;
            match clients_trial(
                rt,
                args,
                bin,
                dir.path(),
                corpus_path,
                workload_seed,
                &mut hist,
            ) {
                Ok((rate, nts, report)) => {
                    throughput = rate;
                    notes = nts;
                    ok = report.ok();
                    mismatches += report.mismatches;
                    errors += report.errors;
                    clients_report = Some(report);
                }
                Err(e) => {
                    ok = false;
                    errors += 1;
                    notes = format!("{e}");
                }
            }
        }
        "ws_transport" => {
            let bin = local_bin()?;
            match transport_trial(rt, args, bin, dir.path(), corpus_path) {
                Ok((nts, report)) => {
                    notes = nts;
                    ok = report.ok();
                    errors += report.errors();
                    transport_report = Some(report);
                }
                Err(e) => {
                    ok = false;
                    errors += 1;
                    notes = format!("{e}");
                }
            }
        }
        "monitor_index" => match live::run_index(&live_options(args)) {
            Ok(report) => {
                throughput = 1e9 / report.matched.mean().max(f64::MIN_POSITIVE);
                // The latency columns hold per-event match time in µs, not ms.
                for v in report.matched.iter_recorded() {
                    hist.record_n(v.value_iterated_to(), v.count_at_value())?;
                }
                mismatches += report.mismatches;
                ok = report.mismatches == 0;
                notes = format!(
                    "in-process ActiveMonitors: {} subscriptions, {} events matched per second of monitor CPU; latency columns are per-event match time in µs, not ms; see the monitor_index table",
                    report.subscriptions, report.events
                );
                monitor_index_report = Some(report);
            }
            Err(e) => {
                ok = false;
                errors += 1;
                notes = format!("{e:#}");
            }
        },
        "author_kinds" => match author_kinds::run(rt, &author_kinds_options(args)?) {
            Ok(report) => {
                mismatches += report.mismatches.len() as u64;
                notes = format!(
                    "{} measurements; time to EOSE per shape in the author_kinds table",
                    report.rows.len()
                );
                author_kinds_report = Some(report);
            }
            Err(e) => {
                ok = false;
                errors += 1;
                notes = format!("{e:#}");
            }
        },
        "live_subscriptions" => {
            let bin = local_bin()?;
            match live_subscriptions_trial(rt, args, bin, dir.path(), &mut hist) {
                Ok(report) => {
                    let steady = report.steady();
                    throughput = steady.deliveries as f64 / steady.secs.max(f64::MIN_POSITIVE);
                    mismatches += report.mismatches();
                    ok = report.mismatches() == 0;
                    notes = format!(
                        "{} subscriptions on {} connections; latency is steady-phase fan-out, see the live_subscriptions table",
                        report.subscriptions, report.conns
                    );
                    live_report = Some(report);
                }
                Err(e) => {
                    ok = false;
                    errors += 1;
                    notes = format!("{e:#}");
                }
            }
        }
        _ => {
            notes = "unrecognized scenario".into();
            ok = false;
        }
    }

    Ok(Trial {
        clients: clients_report,
        transport: transport_report,
        monitor_index: monitor_index_report,
        live_subscriptions: live_report,
        author_kinds: author_kinds_report,
        client_tcp_nodelay: args.tcp_nodelay,
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
        clients: None,
        transport: None,
        monitor_index: None,
        live_subscriptions: None,
        author_kinds: None,
        client_tcp_nodelay: args.tcp_nodelay,
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
            1 if i % 5 == 0 => {
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

fn export_values(bin: &Path, dbdir: &Path) -> Result<Vec<Value>> {
    let conf = write_conf(bin, dbdir, 0);
    let output = Command::new(bin)
        .arg("--config")
        .arg(conf)
        .arg("export")
        .current_dir(dbdir)
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "storage verification export failed"
    );
    String::from_utf8(output.stdout)?
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str(line).map_err(anyhow::Error::from))
        .collect()
}

/// Independent final-state oracle for generated publication mixes. Ephemerals
/// are live-only; replacements retain the latest address; kind-5 e tags delete
/// only the same author's target. The generator uses only these lifecycle forms.
fn retained_events(events: &[Value]) -> Vec<Value> {
    let mut retained: Vec<Value> = Vec::new();
    let mut ordered = events.to_vec();
    ordered.sort_by_key(|e| e["created_at"].as_u64().unwrap());
    for event in ordered {
        let kind = event["kind"].as_u64().unwrap();
        if (20_000..30_000).contains(&kind) {
            continue;
        }
        if kind == 5 {
            for tag in event["tags"].as_array().unwrap() {
                if tag[0] == "e" {
                    retained.retain(|old| old["id"] != tag[1] || old["pubkey"] != event["pubkey"]);
                }
            }
        }
        if kind == 0
            || kind == 3
            || (10_000..20_000).contains(&kind)
            || (30_000..40_000).contains(&kind)
        {
            let address = |e: &Value| {
                e["tags"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|t| t[0] == "d")
                    .and_then(|t| t[1].as_str())
                    .unwrap_or("")
                    .to_owned()
            };
            retained.retain(|old| {
                old["pubkey"] != event["pubkey"]
                    || old["kind"] != event["kind"]
                    || (kind >= 30_000 && address(old) != address(&event))
            });
        }
        retained.push(event);
    }
    retained
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

fn stop_target(child: &mut Option<Child>, url: &str) {
    if let Some(child) = child {
        stop_relay(child, url);
    }
}

/// Graceful stop first so the relay closes LMDB. On macOS a SIGKILLed relay
/// leaks its two POSIX semaphores once the trial's temp database is deleted;
/// enough trials exhaust kern.posix.sem.max (docs/production-deployment.md).
/// SIGUSR1 is the graceful shutdown signal of both Wok and strfry, but strfry
/// exits only when a connection closes during shutdown, never when already
/// idle. A control WebSocket held across the signal supplies that close.
fn stop_relay(child: &mut Child, url: &str) {
    let control = tokio_tungstenite::tungstenite::connect(url).ok();
    let signalled = Command::new("kill")
        .args(["-USR1", &child.id().to_string()])
        .status()
        .is_ok_and(|status| status.success());
    if let Some((mut socket, _)) = control {
        // Let the relay enter graceful shutdown before the disconnect.
        std::thread::sleep(Duration::from_millis(200));
        let _ = socket.close(None);
        let _ = socket.flush();
    }
    if signalled {
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if matches!(child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    let _ = child.kill();
    let _ = child.wait();
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
            Self::WebSocket(stream) => {
                tokio_tungstenite::WebSocketStream::close(stream.as_mut(), None)
                    .await
                    .context("WebSocket close")
            }
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
            tokio_tungstenite::connect_async_with_config(
                endpoint,
                None,
                CLIENT_NODELAY.load(std::sync::atomic::Ordering::Relaxed),
            )
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

fn parse_receipt(reply: &Value, event: &Value) -> Result<bool> {
    anyhow::ensure!(
        reply.as_array().is_some_and(|a| a.len() == 4)
            && reply[0] == "OK"
            && reply[1] == event["id"]
            && reply[3].is_string(),
        "invalid or misrouted publication receipt: {reply}"
    );
    reply[2].as_bool().context("OK acceptance is not boolean")
}

async fn read_ack(socket: &mut ClientConnection, event: &Value) -> Result<bool> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let message = socket.next().await.context("closed before OK")??;
            if !message.is_text() {
                continue;
            }
            let reply: Value = serde_json::from_str(message.to_text()?)?;
            if reply[0] == "AUTH" {
                continue;
            }
            return parse_receipt(&reply, event);
        }
    })
    .await
    .context("publication acknowledgement deadline")?
}

/// Independent NIP-01 oracle for this harness's historical filter workloads.
fn expected_history(events: &[Value], filter: &Value) -> Vec<Value> {
    let mut matches: Vec<Value> = events
        .iter()
        .filter(|event| {
            for (key, condition) in filter.as_object().unwrap() {
                match key.as_str() {
                    "limit" => {}
                    "since" => {
                        if event["created_at"].as_u64().unwrap() < condition.as_u64().unwrap() {
                            return false;
                        }
                    }
                    "until" => {
                        if event["created_at"].as_u64().unwrap() > condition.as_u64().unwrap() {
                            return false;
                        }
                    }
                    "ids" | "authors" | "kinds" => {
                        let field = match key.as_str() {
                            "ids" => "id",
                            "authors" => "pubkey",
                            _ => "kind",
                        };
                        if !condition.as_array().unwrap().contains(&event[field]) {
                            return false;
                        }
                    }
                    tag if tag.starts_with('#') => {
                        if !event["tags"].as_array().unwrap().iter().any(|t| {
                            t[0].as_str() == Some(&tag[1..])
                                && condition.as_array().unwrap().contains(&t[1])
                        }) {
                            return false;
                        }
                    }
                    _ => panic!("unsupported benchmark oracle filter: {key}"),
                }
            }
            true
        })
        .cloned()
        .collect();
    matches.sort_by(|a, b| {
        b["created_at"]
            .as_u64()
            .cmp(&a["created_at"].as_u64())
            .then_with(|| a["id"].as_str().cmp(&b["id"].as_str()))
    });
    matches.truncate(
        filter["limit"]
            .as_u64()
            .unwrap_or(u64::MAX)
            .min(usize::MAX as u64) as usize,
    );
    matches
}

async fn read_history(socket: &mut ClientConnection, sid: &str) -> Result<Vec<Value>> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut events = Vec::new();
        loop {
            let message = socket.next().await.context("closed before EOSE")??;
            if !message.is_text() {
                continue;
            }
            let reply: Value = serde_json::from_str(message.to_text()?)?;
            if reply[0] == "AUTH" {
                continue;
            }
            anyhow::ensure!(reply[1] == sid, "wrong subscription in reply: {reply}");
            match reply[0].as_str() {
                Some("EVENT") => {
                    anyhow::ensure!(
                        reply.as_array().is_some_and(|a| a.len() == 3),
                        "invalid EVENT"
                    );
                    events.push(reply[2].clone());
                }
                Some("EOSE") => {
                    anyhow::ensure!(
                        reply.as_array().is_some_and(|a| a.len() == 2),
                        "invalid EOSE"
                    );
                    return Ok(events);
                }
                _ => anyhow::bail!("unexpected query reply: {reply}"),
            }
        }
    })
    .await
    .context("historical query deadline")?
}

fn same_event_set(actual: &[Value], expected: &[Value]) -> bool {
    if actual.len() != expected.len() {
        return false;
    }
    let mut seen = std::collections::HashSet::new();
    let expected: std::collections::HashMap<_, _> = expected
        .iter()
        .map(|e| (e["id"].as_str().unwrap(), e))
        .collect();
    actual.iter().all(|e| {
        e["id"]
            .as_str()
            .is_some_and(|id| seen.insert(id) && expected.get(id).is_some_and(|want| *want == e))
    })
}

// strfry retains ephemeral events temporarily; Wok defaults to live-only.
// Verify the exact durable set for both and, for strfry, permit only an
// unmodified, duplicate-free subset of the submitted ephemeral events.
fn verify_stored_events(actual: &[Value], submitted: &[Value], live_only: bool) -> bool {
    let ephemeral = |e: &Value| {
        e["kind"]
            .as_u64()
            .is_some_and(|k| (20_000..30_000).contains(&k))
    };
    let (transient, durable): (Vec<_>, Vec<_>) = actual.iter().cloned().partition(ephemeral);
    if live_only && !transient.is_empty() {
        return false;
    }
    let allowed: std::collections::HashMap<_, _> = submitted
        .iter()
        .filter(|e| ephemeral(e))
        .map(|e| (e["id"].as_str().unwrap(), e))
        .collect();
    let mut seen = std::collections::HashSet::new();
    transient.iter().all(|e| {
        e["id"]
            .as_str()
            .is_some_and(|id| seen.insert(id) && allowed.get(id).is_some_and(|want| *want == e))
    }) && same_event_set(&durable, &retained_events(submitted))
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
            anyhow::ensure!(read_ack(ws, ev).await?, "warmup publication rejected");
        }
        let mut batches = vec![Vec::new(); conns];
        for (i, event) in events.iter().skip(warmup_events).cloned().enumerate() {
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
                    let accepted_reply = read_ack(&mut socket, &event).await?;
                    latencies.push(event_started.elapsed().as_micros().max(1) as u64);
                    if accepted_reply {
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
    stop_target(&mut child, &url);
    let (accepted, rejected, elapsed, latencies) = out?;
    for latency in latencies {
        hist.record(latency)
            .map_err(|error| anyhow::anyhow!("{error}"))?;
    }
    let eps = accepted as f64 / elapsed.as_secs_f64();
    let stored_ok = if let Some(bin) = target.bin {
        let actual = export_values(bin, target.dbdir)?;
        verify_stored_events(
            &actual,
            &events,
            bin.file_name().and_then(|n| n.to_str()) == Some("wok"),
        )
    } else {
        true
    };
    let miss = u64::from(rejected > 0 || accepted != workload.count || !stored_ok);
    let notes = format!(
        "{conns} concurrent connection(s): accepted {accepted}/{}, rejected {rejected}; storage {}",
        workload.count,
        if target.bin.is_none() {
            "not inspected (remote target)"
        } else if stored_ok {
            "verified"
        } else {
            "MISMATCH"
        }
    );
    Ok((eps, notes, miss == 0, miss))
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
            let actual = read_history(ws, &subscription).await?;
            anyhow::ensure!(same_event_set(&actual, &expected_history(&events,f)), "warmup returned wrong events");
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
            let actual = read_history(ws,&subscription).await?;
            results += actual.len() as u64;
            let correct = same_event_set(&actual,&expected_history(&events,f));
            ws.send(Message::Text(
                json!(["CLOSE", subscription]).to_string().into(),
            ))
            .await?;
            hist.record(t0.elapsed().as_micros().max(1) as u64)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            if !correct {
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
    stop_target(&mut child, &url);
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
        for _page in 0..pages {
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
            let actual = read_history(&mut socket, "deep").await?;
            let expected = expected_history(
                &events,
                &json!({"authors":[author],"kinds":[1],"until":until,"limit":page_size}),
            );
            let oldest = actual
                .iter()
                .filter_map(|e| e["created_at"].as_u64())
                .min()
                .unwrap_or(u64::MAX);
            if !same_event_set(&actual, &expected) || oldest == u64::MAX {
                mismatches += 1;
                break;
            }
            for event in &actual {
                if !seen.insert(event["id"].as_str().unwrap().to_owned()) {
                    mismatches += 1;
                }
            }
            latencies.push(started.elapsed().as_micros().max(1) as u64);
            until = oldest.saturating_sub(1);
        }
        let elapsed = started_all.elapsed();
        let _ = socket.close(None).await;
        Ok::<_, anyhow::Error>((seen.len() as u64, mismatches, elapsed, latencies))
    });
    stop_target(&mut child, &url);
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
    let query_author = base_events
        .iter()
        .find(|e| e["kind"] == 1)
        .context("mixed corpus has no kind 1")?["pubkey"]
        .clone();
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
                            "kinds":[1], "authors":[query_author],
                            "limit":100,
                            "until":u64::MAX.saturating_sub(query_number)
                        }])
                        .to_string()
                        .into(),
                    ))
                    .await?;
                let actual = read_history(&mut query_socket, &subscription_id).await?;
                let expected = expected_history(&base_events, &json!({"kinds":[1], "authors":[query_author], "limit":100, "until":u64::MAX.saturating_sub(query_number)}));
                let query_results = actual.len() as u64;
                if !same_event_set(&actual, &expected) { mismatches += 1; }
                query_socket
                    .send(Message::Text(
                        json!(["CLOSE", subscription_id]).to_string().into(),
                    ))
                    .await?;
                latencies.push(started.elapsed().as_micros().max(1) as u64);
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
                if read_ack(&mut write_socket, event).await? {
                    accepted += 1;
                }
            }
            let _ = write_socket.close(None).await;
            Ok::<_, anyhow::Error>(accepted)
        };
        let (query_result, write_result) = tokio::join!(query_future, write_future);
        Ok::<_, anyhow::Error>((query_result?, write_result?))
    });
    stop_target(&mut child, &url);
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
    let url = format!("ws://127.0.0.1:{port}/");
    let out = rt.block_on(async {
        use tokio_tungstenite::tungstenite::Message;

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
        let mut measured_start = Instant::now();

        for query_number in 0..total {
            if query_number == warmup {
                measured_start = Instant::now();
            }
            let needle = format!("needle{}", (query_number * 17) % 1024);
            let search = match query_number % 3 {
                0 => needle.clone(),
                1 => format!("common {needle}"),
                _ => "common".to_string(),
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
            let actual = read_history(socket, "nip50-bench").await?;
            let candidates: Vec<Value> = events
                .iter()
                .filter(|event| {
                    let content = event["content"].as_str().unwrap();
                    search
                        .split_whitespace()
                        .all(|term| content.split_whitespace().any(|word| word == term))
                })
                .cloned()
                .collect();
            let expected = expected_history(&candidates, &json!({"kinds":[1], "limit":20}));
            let query_results = actual.len() as u64;
            if !same_event_set(&actual, &expected) {
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
    stop_relay(&mut child, &url);
    let (done, returned, mismatches, elapsed) = out?;
    let qps = done as f64 / elapsed.as_secs_f64();
    let notes = format!("{done} ranked NIP-50 REQs over {n} events, {returned} verified results");
    Ok((qps, notes, mismatches == 0, mismatches))
}

fn check_fanout_event(
    frame: &Value,
    sid: &str,
    expected: &std::collections::BTreeMap<&str, (usize, &Value)>,
    seen: &mut [bool],
) -> Result<()> {
    anyhow::ensure!(
        frame.as_array().is_some_and(|a| a.len() == 3) && frame[0] == "EVENT" && frame[1] == sid,
        "invalid fanout envelope"
    );
    let id = frame[2]["id"].as_str().context("missing fanout event ID")?;
    let &(index, event) = expected.get(id).context("unexpected fanout ID")?;
    anyhow::ensure!(
        !seen[index] && &frame[2] == event,
        "duplicate or altered fanout event {id}"
    );
    seen[index] = true;
    Ok(())
}

/// 1 publisher, `subs` subscribers; measures aggregate delivery/drain time and
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
                EventMix::Kind1 => json!({"kinds":[1], "limit":0}),
                EventMix::Realistic | EventMix::Lifecycle => json!({"limit":0}),
            };
            ws.send(Message::Text(
                json!(["REQ", format!("s{i}"), filter]).to_string().into(),
            ))
            .await?;
            subscribers.push(ws);
        }
        for (i, ws) in subscribers.iter_mut().enumerate() {
            read_history(ws, &format!("s{i}")).await?;
        }
        let mut publisher = connect_retry(&url).await?;
        // Share the expected payloads; each subscriber retains only a seen bitmap.
        let expected: std::collections::BTreeMap<_, _> = events
            .iter()
            .enumerate()
            .map(|(i, e)| (e["id"].as_str().unwrap(), (i, e)))
            .collect();
        anyhow::ensure!(
            expected.len() == events.len(),
            "duplicate generated fanout IDs"
        );
        let start = Instant::now();
        let publish = async {
            for ev in &events {
                publisher
                    .send(Message::Text(json!(["EVENT", ev]).to_string().into()))
                    .await?;
                anyhow::ensure!(
                    read_ack(&mut publisher, ev).await?,
                    "fanout publication rejected"
                );
            }
            Ok::<_, anyhow::Error>(())
        };
        let readers = subscribers.iter_mut().enumerate().map(|(i, ws)| {
            let expected = &expected;
            async move {
                let sid = format!("s{i}");
                let mut seen = vec![false; expected.len()];
                for _ in 0..expected.len() {
                    // An inactivity deadline, not a fixed lifetime: large active
                    // fanout workloads can legitimately take more than 30s.
                    tokio::time::timeout(Duration::from_secs(30), async {
                        loop {
                            let message = ws.next().await.context("closed during fanout")??;
                            if !message.is_text() {
                                continue;
                            }
                            let frame: Value = serde_json::from_str(message.to_text()?)?;
                            check_fanout_event(&frame, &sid, expected, &mut seen)?;
                            return Ok::<_, anyhow::Error>(());
                        }
                    })
                    .await
                    .context("fanout inactivity deadline")??;
                }
                Ok::<_, anyhow::Error>(expected.len() as u64)
            }
        });
        let (_, deliveries) =
            tokio::try_join!(publish, futures_util::future::try_join_all(readers))?;
        let delivered: u64 = deliveries.into_iter().sum();
        let elapsed = start.elapsed();
        hist.record(elapsed.as_micros().max(1) as u64)?;
        let _ = publisher.close(None).await;
        for subscriber in &mut subscribers {
            let _ = subscriber.close(None).await;
        }
        Ok::<_, anyhow::Error>((delivered, elapsed))
    });
    stop_target(&mut child, &url);
    let (delivered, elapsed) = out?;
    let expected = n * subs as u64;
    let eps = delivered as f64 / elapsed.as_secs_f64();
    let miss = if delivered != expected { 1 } else { 0 };
    let notes = format!("{subs} subscribers x {n} events: delivered {delivered}/{expected}; concurrent readers; latency is aggregate trial duration");
    Ok((eps, notes, miss == 0, miss))
}

// Every WebSocket is polled from the moment it opens, including while other
// clients connect. Application-idle clients still owe transport-level pongs.
async fn idle_client(
    mut socket: ClientConnection,
    mut finish: tokio::sync::oneshot::Receiver<()>,
) -> Result<()> {
    use tokio_tungstenite::tungstenite::Message;
    if matches!(&socket, ClientConnection::WebSocket(_)) {
        loop {
            tokio::select! {
                _ = &mut finish => break,
                message = socket.next() => {
                    match message.context("idle connection closed")?? {
                        Message::Ping(payload) => socket.send(Message::Pong(payload)).await?,
                        Message::Pong(_) => {},
                        Message::Text(text) => {
                            let message: Value = serde_json::from_str(&text)?;
                            anyhow::ensure!(message[0] == "AUTH" || message[0] == "NOTICE",
                                "unexpected application message on idle connection: {message}");
                        }
                        other => anyhow::bail!("unexpected idle frame: {other:?}"),
                    }
                }
            }
        }
    } else {
        // Unix has no transport heartbeat. Avoid cancelling a partial framed
        // read just to begin the final usability probe.
        let _ = finish.await;
    }
    socket
        .send(Message::Text(
            json!(["REQ", "idle-check", {"limit":0}]).to_string().into(),
        ))
        .await?;
    anyhow::ensure!(
        read_history(&mut socket, "idle-check").await?.is_empty(),
        "unexpected idle history"
    );
    let _ = socket.close(None).await;
    Ok(())
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
        let mut clients = tokio::task::JoinSet::new();
        let mut finish = Vec::with_capacity(connections);
        for _ in 0..connections {
            let connection_started = Instant::now();
            match connect_retry(&url).await {
                Ok(socket) => {
                    hist.record(connection_started.elapsed().as_micros().max(1) as u64)
                        .map_err(|error| anyhow::anyhow!("{error}"))?;
                    let (done, receiver) = tokio::sync::oneshot::channel();
                    finish.push(done);
                    clients.spawn(idle_client(socket, receiver));
                }
                Err(_) => break,
            }
        }
        let open_elapsed = started.elapsed();
        tokio::time::sleep(Duration::from_secs(hold_seconds)).await;
        let opened = finish.len();
        // Probe one client at a time, preserving the workload instead of
        // turning the end of the hold into a synchronized REQ burst.
        for done in finish {
            let _ = done.send(());
            clients
                .join_next()
                .await
                .context("missing idle client")???;
        }
        Ok::<_, anyhow::Error>((opened, open_elapsed))
    });
    stop_target(&mut child, &url);
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
    let url = format!("ws://127.0.0.1:{port}/");
    let out = rt.block_on(async {
        use tokio_tungstenite::tungstenite::Message;
        let mut ws = connect_retry(&url).await?;
        ws.send(Message::Text(
            r#"["REQ","s",{"kinds":[1],"limit":1}]"#.into(),
        ))
        .await?;
        read_history(&mut ws, "s").await?;
        Ok::<_, anyhow::Error>(())
    });
    let ms = start.elapsed().as_micros().max(1) as u64 / 1000;
    stop_relay(&mut child, &url);
    out?;
    hist.record(ms.saturating_mul(1000))?;
    Ok(ms)
}

fn live_options(args: &Args) -> live::Options {
    live::Options {
        authors: args.live_authors.max(2 * args.live_max_authors).max(2),
        conns: args.live_conns,
        subs_per_conn: args.live_subs_per_conn,
        min_authors: args.live_min_authors.min(args.live_max_authors),
        max_authors: args.live_max_authors,
        events: args.live_events,
        rate: args.live_rate,
        phase_secs: args.live_phase_secs,
        churners: args.live_churners,
        churn_rate: args.live_churn_rate,
        seed: args.seed,
    }
}

/// Spawn the relay, run the live_subscriptions phases against it, and record
/// steady-phase fan-out latency in `hist` (µs).
fn live_subscriptions_trial(
    rt: &tokio::runtime::Runtime,
    args: &Args,
    bin: &Path,
    dbdir: &Path,
    hist: &mut Histogram<u64>,
) -> Result<live::LiveReport> {
    let (url, mut child) = start_target(Some(bin), None, dbdir)?;
    let pid = child.as_ref().map(Child::id);
    let report = rt.block_on(live::run_live(&url, pid, &live_options(args)));
    stop_target(&mut child, &url);
    let report = report?;
    hist.add(&report.steady_fanout)?;
    Ok(report)
}

fn author_kinds_options(args: &Args) -> Result<author_kinds::Options> {
    // `write_conf` writes Wok TOML only for a binary named `wok`.
    let canonical = |path: &Path| {
        anyhow::ensure!(
            path.file_name().and_then(|name| name.to_str()) == Some("wok"),
            "{} must be named wok",
            path.display()
        );
        std::fs::canonicalize(path).with_context(|| format!("wok binary {}", path.display()))
    };
    Ok(author_kinds::Options {
        wok: canonical(&args.wok)?,
        baseline: args.wok_baseline.as_deref().map(canonical).transpose()?,
        // The importer runs in the database directory, so a relative path
        // would resolve under it.
        dataset_dir: std::path::absolute(&args.dataset_dir)
            .with_context(|| format!("dataset directory {}", args.dataset_dir.display()))?,
        authors: args.authors,
        events: args.events.unwrap_or(1_000_000),
        seed: args.seed,
        warm_runs: args.warm_runs.max(1),
        shape_secs: args.shape_secs,
    })
}

fn clients_options(args: &Args) -> clients::ClientsOptions {
    clients::ClientsOptions {
        outbox_clients: args.clients,
        marmot_clients: args.marmot_clients,
        marmot_groups: args.marmot_groups,
        marmot_invitees: args.marmot_invitees,
        max_follows: args.max_follows,
        duration_secs: args.clients_duration_secs,
        replace_interval_ms: args.replace_interval_ms,
        publish_rate: args.publish_rate,
        publishers: 4,
        clients_per_address: args.clients_per_address,
        deflate: args.client_deflate,
        expect_no_refusals: args.expect_no_refusals,
    }
}

fn import_with_config(bin: &Path, conf: &Path, dbdir: &Path, jsonl: &Path) -> Result<()> {
    let status = Command::new(bin)
        .arg("--config")
        .arg(conf)
        .args(["import", "--no-verify"])
        .current_dir(dbdir)
        .stdin(Stdio::from(std::fs::File::open(jsonl)?))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    anyhow::ensure!(status.success(), "import of {} failed", jsonl.display());
    Ok(())
}

fn log_tail(path: &Path) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(5)..].join(" | ")
}

/// The kind-1 events a relay serves after importing `corpus`: deletions
/// applied as `retained_events` models them, each id once, and none past a
/// NIP-40 expiration.
fn served_notes(corpus: &[Value], now: u64) -> Vec<Value> {
    let expired = |event: &Value| {
        event["tags"].as_array().is_some_and(|tags| {
            tags.iter().any(|tag| {
                tag[0] == "expiration"
                    && tag[1]
                        .as_str()
                        .and_then(|at| at.parse::<u64>().ok())
                        .is_some_and(|at| at <= now)
            })
        })
    };
    let mut seen = std::collections::HashSet::new();
    retained_events(corpus)
        .into_iter()
        .filter(|event| event["kind"] == 1 && !expired(event))
        .filter(|event| seen.insert(event["id"].as_str().unwrap_or_default().to_owned()))
        .collect()
}

/// Per-connection transport costs with and without deflate (see
/// transport.rs). Fan-out publications are fresh notes, newer than the corpus.
fn transport_trial(
    rt: &tokio::runtime::Runtime,
    args: &Args,
    bin: &Path,
    dbdir: &Path,
    corpus_path: &Path,
) -> Result<(String, transport::TransportReport)> {
    let opts = transport::TransportOptions {
        connections: args.connections,
        idle_secs: args.transport_idle_secs,
        burst_events: args.burst_events,
        bursts: args.bursts,
        fanout_subscribers: args.fanout_subscribers,
        fanout_events: args.fanout_events,
        churn_connections: args.churn_connections,
    };
    // The spawned relay keeps its default filter limit, which would quietly
    // shorten larger bursts.
    let max_limit = wok_relay::Config::default().relay.max_filter_limit;
    anyhow::ensure!(
        args.burst_events <= max_limit,
        "--burst-events {} is above the relay's max_filter_limit ({max_limit})",
        args.burst_events
    );
    let corpus = read_event_values(corpus_path)?;
    let newest = corpus
        .iter()
        .filter_map(|event| event["created_at"].as_u64())
        .max()
        .unwrap_or_default();
    let now = unix_timestamp()?;
    let kind1 = served_notes(&corpus, now);
    // Every fan-out note takes one second after the corpus (or now), so no
    // history fetch returns them, however many there are, and the relay's
    // created_at window still accepts them.
    let fanout_at = now.max(newest + 1);
    let window = wok_relay::Config::default().events.reject_newer_than_secs;
    anyhow::ensure!(
        window == 0 || fanout_at < now + window,
        "the corpus is dated too far in the future for live publications"
    );
    let key = {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(args.seed ^ 0x7472_616e_7370_6f72);
        secp256k1::Keypair::new(secp256k1::SECP256K1, &mut rng)
    };
    let fanout = (0..args.fanout_events * 2)
        .map(|n| {
            clients::signed(
                &key,
                fanout_at,
                1,
                Vec::new(),
                format!("ws_transport fan-out note {n}"),
            )
        })
        .collect();
    let report = transport::run(
        rt,
        transport::RunInput {
            bin,
            dbdir,
            corpus: corpus_path,
            kind1,
            newest,
            fanout,
            opts,
        },
    )?;
    let summary: Vec<String> = report
        .modes
        .iter()
        .map(|mode| {
            format!(
                "deflate {}: {:.0} KB/conn warm, burst {:.2} ms / {:.1} CPU ms",
                if mode.offer_deflate { "on" } else { "off" },
                mode.warm_kb_per_conn,
                mode.burst_p50_ms,
                mode.burst_cpu_ms,
            )
        })
        .collect();
    Ok((summary.join("; "), report))
}

/// Client-realistic load with abuse controls and AUTH on (see clients.rs).
/// The relay gets the background corpus plus the scenario's own corpus, both
/// imported with the trial's config before it starts.
fn clients_trial(
    rt: &tokio::runtime::Runtime,
    args: &Args,
    bin: &Path,
    dbdir: &Path,
    corpus_path: &Path,
    workload_seed: u64,
    hist: &mut Histogram<u64>,
) -> Result<(f64, String, clients::ClientsReport)> {
    let anchor = args.base_timestamp.expect("campaign timestamp set");
    anyhow::ensure!(
        anchor <= unix_timestamp()?,
        "--scenario clients publishes live events, so --base-timestamp cannot be in the future"
    );
    let opts = clients_options(args);
    let port = free_port();
    let prepared = clients::prepare_config(
        dbdir,
        port,
        args.relay_config.as_deref(),
        opts.clients_per_address > 0,
    )?;
    let plan = clients::Plan::generate(&opts, workload_seed, anchor);
    let scenario_corpus = dbdir.join("clients-corpus.jsonl");
    {
        let mut file = std::io::BufWriter::new(std::fs::File::create(&scenario_corpus)?);
        for event in &plan.events {
            writeln!(file, "{}", wok_event::json::to_tao_string(event))?;
        }
    }
    import_with_config(bin, &prepared.path, dbdir, corpus_path)?;
    import_with_config(bin, &prepared.path, dbdir, &scenario_corpus)?;
    let background = read_event_values(corpus_path)?;
    let log = dbdir.join("relay.log");
    let mut child = Command::new(bin)
        .arg("--config")
        .arg(&prepared.path)
        .arg("relay")
        .current_dir(dbdir)
        .stdout(Stdio::null())
        .stderr(Stdio::from(std::fs::File::create(&log)?))
        .spawn()
        .with_context(|| format!("spawn {}", bin.display()))?;
    let url = format!("ws://127.0.0.1:{port}");
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            anyhow::bail!("relay exited during startup ({status}): {}", log_tail(&log));
        }
        if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
            break;
        }
        if Instant::now() > deadline {
            stop_relay(&mut child, &url);
            anyhow::bail!("relay did not listen within 30 s: {}", log_tail(&log));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let outcome = rt.block_on(clients::run(clients::RunInput {
        addr,
        plan,
        background,
        config: &prepared.effective,
        relay_config: prepared.source.clone(),
        config_overrides: prepared.overrides.clone(),
        opts,
        nodelay: CLIENT_NODELAY.load(std::sync::atomic::Ordering::Relaxed),
    }));
    stop_relay(&mut child, &url);
    let (report, eose) = outcome?;
    hist.add(&eose).map_err(|e| anyhow::anyhow!("{e}"))?;
    let top: Vec<String> = report
        .refusals
        .iter()
        .take(3)
        .map(|row| format!("{} x{}", row.reason, row.count))
        .collect();
    let notes = format!(
        "{} outbox + {} Marmot clients ({} groups, {} invitees): {} subscriptions, {} refusals [{}], {} truncated, {} missed deliveries; deflate {}/{} connections; latency is time to EOSE",
        report.options.outbox_clients,
        report.options.marmot_clients,
        report.options.marmot_groups,
        report.options.marmot_invitees,
        report.subscriptions,
        report.refusals_total,
        top.join("; "),
        report.truncated_total,
        report.missed_deliveries,
        report.deflate_negotiated,
        report.connections,
    );
    let rate = report.eose_count() as f64 / report.elapsed_secs.max(f64::EPSILON);
    Ok((rate, notes, report))
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
    for t in trials {
        if let Some(report) = &t.clients {
            s.push_str(&clients::render_markdown(report, &t.relay, t.repetition));
        }
        if let Some(report) = &t.transport {
            s.push_str(&transport::render_markdown(report, &t.relay, t.repetition));
        }
        if let Some(report) = &t.monitor_index {
            s.push_str(&live::render_index_markdown(report));
        }
        if let Some(report) = &t.live_subscriptions {
            s.push_str(&live::render_live_markdown(report));
        }
        if let Some(report) = &t.author_kinds {
            s.push_str(&author_kinds::render_markdown(report));
        }
    }
    let mut selection = args.scenario.as_ref().map_or_else(
        || format!("--profile {}", args.profile),
        |scenario| format!("--scenario {scenario}"),
    );
    if args.scenario.as_deref() == Some("clients") {
        if let Some(path) = &args.relay_config {
            selection.push_str(&format!(" --relay-config \"{}\"", path.display()));
        }
        selection.push_str(&format!(
            " --clients {} --marmot-clients {} --marmot-groups {} --marmot-invitees {} --max-follows {} --clients-duration-secs {} --replace-interval-ms {} --publish-rate {} --clients-per-address {} --client-deflate {} --events {}",
            args.clients,
            args.marmot_clients,
            args.marmot_groups,
            args.marmot_invitees,
            args.max_follows,
            args.clients_duration_secs,
            args.replace_interval_ms,
            args.publish_rate,
            args.clients_per_address,
            args.client_deflate,
            args.events.unwrap_or_default(),
        ));
        if args.expect_no_refusals {
            selection.push_str(" --expect-no-refusals");
        }
    }
    if args.scenario.as_deref() == Some("ws_transport") {
        selection.push_str(&format!(
            " --connections {} --transport-idle-secs {} --burst-events {} --bursts {} --fanout-subscribers {} --fanout-events {} --churn-connections {} --events {}",
            args.connections,
            args.transport_idle_secs,
            args.burst_events,
            args.bursts,
            args.fanout_subscribers,
            args.fanout_events,
            args.churn_connections,
            args.events.unwrap_or_default(),
        ));
    }
    if matches!(
        args.scenario.as_deref(),
        Some("monitor_index" | "live_subscriptions")
    ) {
        selection.push_str(&format!(
            " --live-authors {} --live-conns {} --live-subs-per-conn {} --live-min-authors {} --live-max-authors {} --live-events {} --live-rate {} --live-phase-secs {} --live-churners {} --live-churn-rate {}",
            args.live_authors,
            args.live_conns,
            args.live_subs_per_conn,
            args.live_min_authors,
            args.live_max_authors,
            args.live_events,
            args.live_rate,
            args.live_phase_secs,
            args.live_churners,
            args.live_churn_rate,
        ));
    }
    if args.scenario.as_deref() == Some("author_kinds") {
        selection.push_str(&format!(
            " --events {} --authors {} --warm-runs {} --shape-secs {} --dataset-dir \"{}\"",
            args.events.unwrap_or_default(),
            args.authors,
            args.warm_runs,
            args.shape_secs,
            args.dataset_dir.display(),
        ));
        if let Some(path) = &args.wok_baseline {
            selection.push_str(&format!(" --wok-baseline \"{}\"", path.display()));
        }
    }
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
    fn fanout_bitmap_rejects_duplicate_altered_and_unexpected_events() {
        let event = json!({"id":"expected", "content":"original"});
        let expected = std::collections::BTreeMap::from([("expected", (0, &event))]);
        let good = json!(["EVENT", "s", event]);
        let mut seen = [false];
        check_fanout_event(&good, "s", &expected, &mut seen).unwrap();
        assert!(check_fanout_event(&good, "s", &expected, &mut seen).is_err());
        for bad in [
            json!(["EVENT", "other", event]),
            json!(["EVENT", "s", {"id":"expected", "content":"altered"}]),
            json!(["EVENT", "s", {"id":"unknown", "content":"original"}]),
        ] {
            assert!(check_fanout_event(&bad, "s", &expected, &mut [false]).is_err());
        }
    }

    #[test]
    fn fanout_reads_subscribers_while_publishing() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(async move {
                    use tokio_tungstenite::tungstenite::Message;
                    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                    let (stream, _) = listener.accept().await?;
                    let mut subscriber = tokio_tungstenite::accept_async(stream).await?;
                    let _req = subscriber.next().await.context("subscription closed")??;
                    subscriber
                        .send(Message::Text(json!(["EOSE", "s0"]).to_string().into()))
                        .await?;
                    let (stream, _) = listener.accept().await?;
                    let mut publisher = tokio_tungstenite::accept_async(stream).await?;
                    let message = publisher.next().await.context("publisher closed")??;
                    let event: Value = serde_json::from_str(message.to_text()?)?;
                    subscriber.send(Message::Ping(vec![1].into())).await?;
                    let pong =
                        tokio::time::timeout(Duration::from_millis(300), subscriber.next()).await;
                    anyhow::ensure!(
                        matches!(pong, Ok(Some(Ok(Message::Pong(_))))),
                        "subscriber was not being polled: {pong:?}"
                    );
                    subscriber
                        .send(Message::Text(
                            json!(["EVENT", "s0", event[1]]).to_string().into(),
                        ))
                        .await?;
                    publisher
                        .send(Message::Text(
                            json!(["OK", event[1]["id"], true, ""]).to_string().into(),
                        ))
                        .await?;
                    Ok::<_, anyhow::Error>(())
                })
        });
        let rt = tokio::runtime::Runtime::new().unwrap();
        let temp = TempDir::new().unwrap();
        let url = format!("ws://{addr}");
        let result = live_fanout_trial(
            &rt,
            RelayTarget {
                bin: None,
                url: Some(&url),
                dbdir: temp.path(),
            },
            EventWorkload {
                count: 1,
                seed: 1,
                base_timestamp: 1_800_000_000,
                mix: EventMix::Kind1,
            },
            1,
            &mut Histogram::new(3).unwrap(),
        );
        let peer_result = server.join().unwrap();
        assert!(peer_result.is_ok(), "{peer_result:?}");
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn idle_clients_answer_relay_pings_during_hold() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            tokio::runtime::Runtime::new().unwrap().block_on(async move {
                use tokio_tungstenite::tungstenite::Message;
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                let (stream, _) = listener.accept().await.unwrap();
                let mut peer = tokio_tungstenite::accept_async(stream).await.unwrap();
                for _ in 0..3 {
                    peer.send(Message::Ping(vec![4, 2].into())).await.unwrap();
                    let reply = tokio::time::timeout(Duration::from_millis(300), peer.next()).await;
                    anyhow::ensure!(matches!(reply, Ok(Some(Ok(Message::Pong(ref p)))) if p.as_ref() == [4, 2]),
                        "idle client failed to answer relay ping: {reply:?}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                let req = tokio::time::timeout(Duration::from_secs(3), peer.next()).await?.context("client closed before final probe")??;
                anyhow::ensure!(req.is_text(), "expected final usability probe");
                peer.send(Message::Text(json!(["EOSE", "idle-check"]).to_string().into())).await?;
                Ok::<_, anyhow::Error>(())
            })
        });
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut hist = Histogram::new(3).unwrap();
        let temp = TempDir::new().unwrap();
        let result = idle_connections_trial(
            &rt,
            None,
            Some(&format!("ws://{addr}")),
            temp.path(),
            1,
            1,
            &mut hist,
        );
        let peer_result = server.join().unwrap();
        assert!(peer_result.is_ok(), "{peer_result:?}");
        assert!(result.is_ok(), "{result:?}");
    }

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
    fn ws_transport_expects_only_notes_the_relay_serves() {
        let now = 1_800_000_000;
        let mut events = generate_values(EventWorkload {
            count: 1000,
            seed: 11,
            base_timestamp: now,
            mix: EventMix::Lifecycle,
        })
        .unwrap();
        let deleted: Vec<String> = events
            .iter()
            .filter(|event| event["kind"] == 5)
            .flat_map(|event| event["tags"].as_array().cloned().unwrap_or_default())
            .filter(|tag| tag[0] == "e")
            .filter_map(|tag| tag[1].as_str().map(str::to_owned))
            .collect();
        let kept = events
            .iter()
            .find(|event| {
                event["kind"] == 1 && !deleted.iter().any(|id| event["id"] == id.as_str())
            })
            .cloned()
            .unwrap();
        events.push(kept.clone());
        let key = secp256k1::Keypair::new(secp256k1::SECP256K1, &mut rand::thread_rng());
        let expired = clients::signed(
            &key,
            now - 10,
            1,
            vec![json!(["expiration", (now - 5).to_string()])],
            "expired".into(),
        );
        events.push(expired.clone());

        let served = served_notes(&events, now);
        let ids: Vec<&str> = served.iter().filter_map(|e| e["id"].as_str()).collect();
        assert!(!deleted.is_empty());
        assert!(served.iter().all(|event| event["kind"] == 1));
        assert!(deleted.iter().all(|id| !ids.contains(&id.as_str())));
        assert_eq!(ids.iter().filter(|&&id| kept["id"] == id).count(), 1);
        assert!(!ids.contains(&expired["id"].as_str().unwrap()));
    }

    #[test]
    fn author_kinds_datasets_resolve_to_an_absolute_directory() {
        let bin = TempDir::new().unwrap();
        let wok = bin.path().join("wok");
        std::fs::write(&wok, b"").unwrap();
        let args = Args::try_parse_from([
            "wok-bench".as_ref(),
            "--scenario".as_ref(),
            "author_kinds".as_ref(),
            "--wok".as_ref(),
            wok.as_os_str(),
        ])
        .unwrap();
        let opts = author_kinds_options(&args).unwrap();
        assert!(opts.dataset_dir.is_absolute());
        assert!(opts.dataset_dir.ends_with("bench-results/datasets"));
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

#[cfg(test)]
mod correctness_tests {
    use super::*;
    #[test]
    fn receipts_require_exact_id_and_boolean() {
        let event = json!({"id":"alice"});
        assert!(parse_receipt(&json!(["OK", "bob", true, ""]), &event).is_err());
        assert!(parse_receipt(&json!(["OK", "alice", "true", ""]), &event).is_err());
        assert!(!parse_receipt(
            &json!(["OK", "alice", false, "true appears in reason"]),
            &event
        )
        .unwrap());
        assert!(parse_receipt(&json!(["OK", "alice", true, ""]), &event).unwrap());
    }
    #[test]
    fn storage_oracle_respects_live_only_and_ttl_transport_policies() {
        let event =
            json!({"id":"e","kind":20001,"created_at":1,"pubkey":"p","tags":[],"content":"body"});
        let events = vec![event.clone()];
        assert!(verify_stored_events(&[], &events, true));
        assert!(!verify_stored_events(&events, &events, true));
        assert!(verify_stored_events(&events, &events, false));
        assert!(!verify_stored_events(
            &[event.clone(), event.clone()],
            &events,
            false
        ));
        let mut bad = event;
        bad["content"] = json!("corrupt");
        assert!(!verify_stored_events(&[bad], &events, false));
    }
    #[test]
    fn oracle_rejects_duplicates_wrong_payload_and_wrong_set() {
        let a = json!({"id":"a","pubkey":"p","kind":1,"created_at":1,"tags":[["t","rust"]],"content":"EOSE"});
        let b = json!({"id":"b","pubkey":"p","kind":1,"created_at":2,"tags":[],"content":"EVENT"});
        let corpus = vec![a.clone(), b.clone()];
        assert_eq!(
            expected_history(&corpus, &json!({"#t":["rust"],"limit":1})),
            vec![a.clone()]
        );
        assert_eq!(
            expected_history(&corpus, &json!({"limit":1})),
            vec![b.clone()]
        );
        assert!(!same_event_set(&[a.clone(), a.clone()], &corpus));
        let mut changed = a.clone();
        changed["content"] = json!("altered");
        assert!(!same_event_set(&[changed], &[a]));
        assert!(same_event_set(
            std::slice::from_ref(&b),
            std::slice::from_ref(&b)
        ));
    }
}
