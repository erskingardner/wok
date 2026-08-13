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
use clap::Parser;
use hdrhistogram::Histogram;
use serde::Serialize;
use serde_json::{json, Value};
use std::io::Write;
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
    /// Queries in query scenarios (default 400)
    #[arg(long)]
    queries: Option<u64>,
}

#[derive(Serialize, Clone)]
struct Trial {
    relay: String,
    scenario: String,
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
    seed: u64,
    profile: String,
}

const RELAYS: [&str; 2] = ["wok", "strfry"];

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive("warn".parse()?),
        )
        .init();
    let args = Args::parse();
    std::fs::create_dir_all(&args.out)?;
    let profile_scenarios: Vec<&str> = if args.profile == "full" {
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

    let mut trials = Vec::new();
    for scenario in &scenarios {
        let relays: &[&str] = if *scenario == "nip50_search" {
            &["wok"]
        } else {
            &RELAYS
        };
        for relay in relays {
            let t = run_trial(&rt, &args, relay, scenario);
            match t {
                Ok(t) => trials.push(t),
                Err(e) => {
                    eprintln!("trial {relay}/{scenario} errored: {e}");
                    trials.push(failed_trial(&args, relay, scenario, format!("{e}")));
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
) -> Result<Trial> {
    let dir = TempDir::new()?;
    let mut hist = Histogram::<u64>::new(3)?;
    let mut ok = true;
    let mut errors = 0u64;
    let mut mismatches = 0u64;
    #[allow(unused_assignments)]
    let mut notes = String::new();
    let mut throughput = 0.0f64;

    let bin = if relay == "wok" {
        args.wok.as_path()
    } else {
        args.strfry.as_path()
    };
    if !bin.is_file() {
        return Ok(failed_trial(
            args,
            relay,
            scenario,
            format!("binary missing: {}", bin.display()),
        ));
    }
    let bin = std::fs::canonicalize(bin)?;
    let bin = bin.as_path();

    let n = args.events.unwrap_or(if args.profile == "smoke" {
        2_000
    } else {
        20_000
    });
    let n_queries = args.queries.unwrap_or(400);

    match scenario {
        "import" => {
            let jsonl = generate_events(dir.path(), n, args.seed)?;
            let start = Instant::now();
            let good = import_with(bin, dir.path(), &jsonl, true);
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
            let jsonl = generate_events(dir.path(), n, args.seed)?;
            if !import_with(bin, dir.path(), &jsonl, false) {
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
            let jsonl = generate_events(dir.path(), n.min(5_000), args.seed)?;
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
            let jsonl = generate_events(dir.path(), n, args.seed)?;
            if !import_with(bin, dir.path(), &jsonl, false) {
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
            let conns = if scenario == "ws_publish_8conn" { 8 } else { 1 };
            match ws_publish_trial(rt, bin, dir.path(), n, args.seed, conns, &mut hist) {
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
        "ws_query_latency" => {
            match ws_query_trial(rt, bin, dir.path(), n, n_queries, args.seed, &mut hist) {
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
        "deep_history_pagination" => {
            match deep_history_trial(rt, bin, dir.path(), n, n_queries, args.seed, &mut hist) {
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
            match mixed_read_write_trial(rt, bin, dir.path(), n, n_queries, args.seed, &mut hist) {
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
            match ws_search_trial(rt, bin, dir.path(), n, n_queries, args.seed, &mut hist) {
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
            match live_fanout_trial(rt, bin, dir.path(), 200, 32, args.seed, &mut hist) {
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
        "cold_start" => {
            let jsonl = generate_events(dir.path(), n, args.seed)?;
            if !import_with(bin, dir.path(), &jsonl, false) {
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
        seed: args.seed,
        profile: args.profile.clone(),
    })
}

fn failed_trial(args: &Args, relay: &str, scenario: &str, notes: String) -> Trial {
    Trial {
        relay: relay.into(),
        scenario: scenario.into(),
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
        seed: args.seed,
        profile: args.profile.clone(),
    }
}

fn pct(h: &Histogram<u64>, p: f64) -> f64 {
    h.value_at_percentile(p) as f64
}

// ---------------------------------------------------------------------------
// Corpus
// ---------------------------------------------------------------------------

fn event_at(i: u64, now: u64, rng: &mut rand::rngs::StdRng) -> Value {
    use rand::Rng;
    use secp256k1::{Keypair, SECP256K1};
    let kp = Keypair::new(SECP256K1, rng);
    let (xonly, _) = kp.x_only_public_key();
    let mut ev = json!({
        "created_at": now.saturating_sub(100_000) + i,
        "kind": 1,
        "tags": [["t", format!("tag-{}", i % 64)]],
        "content": format!(
            "common benchmark event {i} needle{} category{} {}",
            i % 1024,
            i % 32,
            "x".repeat((i % 24) as usize)
        ),
        "pubkey": hex::encode(xonly.serialize()),
    });
    let id = wok_event::event_id_hash(&ev).unwrap();
    ev["id"] = json!(hex::encode(id));
    let sig = SECP256K1.sign_schnorr(&id, &kp);
    ev["sig"] = json!(hex::encode(sig.as_ref()));
    let _ = rng.gen::<u32>();
    ev
}

fn generate_events(dir: &Path, n: u64, seed: u64) -> Result<PathBuf> {
    use rand::SeedableRng;
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let path = dir.join("events.jsonl");
    let mut f = std::fs::File::create(&path)?;
    for i in 0..n {
        let ev = event_at(i, now, &mut rng);
        writeln!(f, "{}", wok_event::json::to_tao_string(&ev))?;
    }
    Ok(path)
}

fn generate_values(n: u64, seed: u64) -> Result<Vec<Value>> {
    use rand::SeedableRng;
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    Ok((0..n).map(|i| event_at(i, now, &mut rng)).collect())
}

/// Build a dense single-author history so pagination exercises the same
/// author+kind+until cursor shape reported by large relay operators.
fn generate_author_history(dir: &Path, n: u64, seed: u64) -> Result<(PathBuf, String)> {
    use rand::SeedableRng;
    use secp256k1::{Keypair, SECP256K1};
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let key = Keypair::new(SECP256K1, &mut rng);
    let (pubkey, _) = key.x_only_public_key();
    let pubkey = hex::encode(pubkey.serialize());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let path = dir.join("author-history.jsonl");
    let mut file = std::fs::File::create(&path)?;
    for i in 0..n {
        let mut event = json!({
            "created_at": now.saturating_sub(n).saturating_add(i),
            "kind": 1,
            "tags": [],
            "content": format!("historical page event {i}"),
            "pubkey": pubkey.clone(),
        });
        let id = wok_event::event_id_hash(&event)?;
        event["id"] = json!(hex::encode(id));
        let signature = SECP256K1.sign_schnorr(&id, &key);
        event["sig"] = json!(hex::encode(signature.as_ref()));
        writeln!(file, "{}", wok_event::json::to_tao_string(&event))?;
    }
    Ok((path, pubkey))
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

async fn connect_retry(
    url: &str,
) -> Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
> {
    let mut last_err = None;
    for _ in 0..50 {
        match tokio_tungstenite::connect_async(url).await {
            Ok((s, _)) => return Ok(s),
            Err(e) => {
                last_err = Some(e.to_string());
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    anyhow::bail!("connect failed: {last_err:?}")
}

/// Publish `n` events over `conns` connections (round-robin), one in flight
/// per connection. Measures per-publish OK latency and aggregate rate.
fn ws_publish_trial(
    rt: &tokio::runtime::Runtime,
    bin: &Path,
    dbdir: &Path,
    n: u64,
    seed: u64,
    conns: usize,
    hist: &mut Histogram<u64>,
) -> Result<(f64, String, bool, u64)> {
    let events = generate_values(n, seed)?;
    let port = free_port();
    let mut child = spawn_relay(bin, dbdir, port)?;
    let out = rt.block_on(async {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;
        let url = format!("ws://127.0.0.1:{port}/");
        let mut sockets = Vec::new();
        for _ in 0..conns {
            sockets.push(connect_retry(&url).await?);
        }
        // Warm-up (not measured).
        for (i, ev) in events.iter().take(50).enumerate() {
            let ws = &mut sockets[i % conns];
            ws.send(Message::Text(json!(["EVENT", ev]).to_string().into()))
                .await?;
            let _ = tokio::time::timeout(Duration::from_secs(5), ws.next()).await;
        }
        let start = Instant::now();
        let mut accepted = 0u64;
        let mut rejected = 0u64;
        for (i, ev) in events.iter().skip(50).enumerate() {
            let ws = &mut sockets[i % conns];
            let t0 = Instant::now();
            ws.send(Message::Text(json!(["EVENT", ev]).to_string().into()))
                .await?;
            let ok_reply = loop {
                match tokio::time::timeout(Duration::from_secs(10), ws.next()).await {
                    Ok(Some(Ok(m))) => {
                        let t = m.to_text().unwrap_or("").to_string();
                        if t.contains("\"OK\"") {
                            break t;
                        }
                    }
                    _ => break String::new(),
                }
            };
            hist.record(t0.elapsed().as_micros().max(1) as u64)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            if ok_reply.contains("true") {
                accepted += 1;
            } else {
                rejected += 1;
            }
        }
        let elapsed = start.elapsed();
        for ws in &mut sockets {
            let _ = ws.close(None).await;
        }
        Ok::<_, anyhow::Error>((accepted, rejected, elapsed))
    });
    let _ = child.kill();
    let _ = child.wait();
    let (accepted, rejected, elapsed) = out?;
    let eps = accepted as f64 / elapsed.as_secs_f64();
    let miss = if rejected > 0 { 1 } else { 0 };
    let notes = format!("{conns} conn(s): accepted {accepted}, rejected {rejected}");
    Ok((eps, notes, rejected == 0, miss))
}

/// Preload n events, then run `queries` REQs of mixed shapes; measures
/// time-to-EOSE per query and aggregate QPS over 4 connections.
fn ws_query_trial(
    rt: &tokio::runtime::Runtime,
    bin: &Path,
    dbdir: &Path,
    n: u64,
    queries: u64,
    seed: u64,
    hist: &mut Histogram<u64>,
) -> Result<(f64, String, bool, u64)> {
    let events = generate_values(n, seed)?;
    let jsonl = dbdir.join("events.jsonl");
    {
        let mut f = std::fs::File::create(&jsonl)?;
        for ev in &events {
            writeln!(f, "{}", wok_event::json::to_tao_string(ev))?;
        }
    }
    if !import_with(bin, dbdir, &jsonl, false) {
        anyhow::bail!("pre-import failed");
    }
    let port = free_port();
    let mut child = spawn_relay(bin, dbdir, port)?;
    let out = rt.block_on(async {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;
        let url = format!("ws://127.0.0.1:{port}/");
        let mut sockets = Vec::new();
        for _ in 0..4 {
            sockets.push(connect_retry(&url).await?);
        }
        let filters: Vec<Value> = (0..queries)
            .map(|q| {
                let ev = &events[(q as usize * 7) % events.len()];
                let id = ev["id"].as_str().unwrap_or("");
                let pk = ev["pubkey"].as_str().unwrap_or("");
                match q % 4 {
                    0 => json!({"ids":[id]}),
                    1 => json!({"authors":[pk],"kinds":[1],"limit":50}),
                    2 => json!({"kinds":[1],"since":ev["created_at"].as_u64().unwrap_or(0),"limit":20}),
                    _ => json!({"#t":[format!("tag-{}", q % 64)],"limit":50}),
                }
            })
            .collect();
        // Warm-up.
        for (i, f) in filters.iter().take(20).enumerate() {
            let ws = &mut sockets[i % 4];
            ws.send(Message::Text(json!(["REQ", "w", f]).to_string().into()))
                .await?;
            while let Ok(Some(Ok(m))) = tokio::time::timeout(Duration::from_secs(5), ws.next()).await
            {
                if m.to_text().unwrap_or("").contains("EOSE") {
                    break;
                }
            }
        }
        let start = Instant::now();
        let mut done = 0u64;
        let mut results = 0u64;
        for (i, f) in filters.iter().skip(20).enumerate() {
            let ws = &mut sockets[i % 4];
            let t0 = Instant::now();
            ws.send(Message::Text(json!(["REQ", "q", f]).to_string().into()))
                .await?;
            while let Ok(Some(Ok(m))) =
                tokio::time::timeout(Duration::from_secs(10), ws.next()).await
            {
                let t = m.to_text().unwrap_or("");
                if t.contains("\"EVENT\"") {
                    results += 1;
                }
                if t.contains("EOSE") {
                    break;
                }
            }
            hist.record(t0.elapsed().as_micros().max(1) as u64)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            done += 1;
        }
        let elapsed = start.elapsed();
        for ws in &mut sockets {
            let _ = ws.close(None).await;
        }
        Ok::<_, anyhow::Error>((done, results, elapsed))
    });
    let _ = child.kill();
    let _ = child.wait();
    let (done, results, elapsed) = out?;
    let qps = done as f64 / elapsed.as_secs_f64();
    let miss = if done == 0 || results == 0 { 1 } else { 0 };
    let notes = format!("{done} mixed REQs, {results} events returned");
    Ok((qps, notes, miss == 0, miss))
}

/// Repeated author+kind+until pagination into progressively older history.
/// This is the workload from strfry issue #157, where later pages can degrade
/// from sub-second to tens of seconds on fragmented, production-sized stores.
fn deep_history_trial(
    rt: &tokio::runtime::Runtime,
    bin: &Path,
    dbdir: &Path,
    n: u64,
    queries: u64,
    seed: u64,
    hist: &mut Histogram<u64>,
) -> Result<(f64, String, bool, u64)> {
    let n = n.max(1);
    let (jsonl, author) = generate_author_history(dbdir, n, seed)?;
    if !import_with(bin, dbdir, &jsonl, false) {
        anyhow::bail!("deep-history import failed");
    }
    let imported = export_count(bin, dbdir);
    if imported != n {
        anyhow::bail!("deep-history import retained {imported}/{n} events");
    }
    let page_size = 500u64;
    let available_pages = n.div_ceil(page_size);
    let pages = queries.max(1).min(available_pages);
    let port = free_port();
    let mut child = spawn_relay(bin, dbdir, port)?;
    let out = rt.block_on(async {
        use futures_util::{SinkExt, StreamExt};
        use std::collections::HashSet;
        use tokio_tungstenite::tungstenite::Message;

        let url = format!("ws://127.0.0.1:{port}/");
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
    let _ = child.kill();
    let _ = child.wait();
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
        "{pages} progressive 500-event pages over {n} single-author events; {seen} unique events"
    );
    Ok((qps, notes, mismatches == 0, mismatches))
}

/// Measure historical REQ latency while a second connection continuously
/// publishes accepted events. This catches cursor/refill regressions that are
/// invisible in a read-only corpus.
fn mixed_read_write_trial(
    rt: &tokio::runtime::Runtime,
    bin: &Path,
    dbdir: &Path,
    n: u64,
    queries: u64,
    seed: u64,
    hist: &mut Histogram<u64>,
) -> Result<(f64, String, bool, u64)> {
    let n = n.max(1);
    let base_events = generate_values(n, seed)?;
    let jsonl = dbdir.join("mixed-base.jsonl");
    {
        let mut file = std::fs::File::create(&jsonl)?;
        for event in &base_events {
            writeln!(file, "{}", wok_event::json::to_tao_string(event))?;
        }
    }
    if !import_with(bin, dbdir, &jsonl, false) {
        anyhow::bail!("mixed-load import failed");
    }
    let imported = export_count(bin, dbdir);
    if imported != n {
        anyhow::bail!("mixed-load import retained {imported}/{n} events");
    }
    let query_count = queries.max(1);
    let write_count = query_count.max(50).min(n);
    let new_events = generate_values(write_count, seed.wrapping_add(10_000))?;
    let port = free_port();
    let mut child = spawn_relay(bin, dbdir, port)?;
    let out = rt.block_on(async {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;

        let url = format!("ws://127.0.0.1:{port}/");
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
    let _ = child.kill();
    let _ = child.wait();
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
    n: u64,
    queries: u64,
    seed: u64,
    hist: &mut Histogram<u64>,
) -> Result<(f64, String, bool, u64)> {
    let events = generate_values(n.max(1), seed)?;
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
        use futures_util::{SinkExt, StreamExt};
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
    bin: &Path,
    dbdir: &Path,
    n: u64,
    subs: usize,
    seed: u64,
    hist: &mut Histogram<u64>,
) -> Result<(f64, String, bool, u64)> {
    let events = generate_values(n, seed)?;
    let port = free_port();
    let mut child = spawn_relay(bin, dbdir, port)?;
    let out = rt.block_on(async {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;
        let url = format!("ws://127.0.0.1:{port}/");
        let mut subscribers = Vec::new();
        for i in 0..subs {
            let mut ws = connect_retry(&url).await?;
            ws.send(Message::Text(
                json!(["REQ", format!("s{i}"), {"kinds":[1]}])
                    .to_string()
                    .into(),
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
        Ok::<_, anyhow::Error>((delivered, elapsed, collect_elapsed))
    });
    let _ = child.kill();
    let _ = child.wait();
    let (delivered, elapsed, _collect) = out?;
    let expected = n * subs as u64;
    let eps = delivered as f64 / elapsed.as_secs_f64();
    let miss = if delivered != expected { 1 } else { 0 };
    let notes = format!("{subs} subscribers x {n} events: delivered {delivered}/{expected}");
    Ok((eps, notes, miss == 0, miss))
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
        use futures_util::{SinkExt, StreamExt};
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
        "profile={} seed={} host={} os={} arch={}\n\n",
        args.profile,
        args.seed,
        hostname(),
        std::env::consts::OS,
        std::env::consts::ARCH
    ));
    s.push_str("Each trial uses an identical deterministic corpus for both relays. `ok=false` means a correctness failure, not slowness. Do not rank relays from a single noisy run.\n\n");
    s.push_str("| relay | scenario | ok | throughput/s | p50 ms | p90 ms | p99 ms | max ms | errors | mismatches | notes |\n|---|---|---|---|---|---|---|---|---|---|---|\n");
    for t in trials {
        s.push_str(&format!(
            "| {} | {} | {} | {:.1} | {:.2} | {:.2} | {:.2} | {:.1} | {} | {} | {} |\n",
            t.relay,
            t.scenario,
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
    s.push_str("\nReproduction:\n\n```bash\ncargo build --release -p wok-cli -p wok-bench\n./target/release/wok-bench --profile full --out bench-results --strfry /Users/jeff/code/strfry/strfry --wok ./target/release/wok --seed 1\n```\n");
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
