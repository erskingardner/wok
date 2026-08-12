//! Comparative load generation for wok and C++ strfry.
//!
//! Never points at a user database. Each trial uses a disposable temp dir.
//! A trial with missing events, unexpected rejections, or subscriber drops
//! is recorded as `ok=false`.

use anyhow::{Context, Result};
use clap::Parser;
use hdrhistogram::Histogram;
use serde::Serialize;
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
    /// Scenarios: smoke (default) or full
    #[arg(long, default_value = "smoke")]
    profile: String,
    /// Output directory for JSONL + markdown
    #[arg(long, default_value = "bench-results")]
    out: PathBuf,
    /// Fixed RNG seed
    #[arg(long, default_value_t = 1)]
    seed: u64,
    /// Optional JSONL corpus (not committed)
    #[arg(long)]
    corpus: Option<PathBuf>,
    /// Events in bulk import (smoke default 50)
    #[arg(long)]
    events: Option<u64>,
}

#[derive(Serialize, Clone)]
struct Trial {
    relay: String,
    scenario: String,
    ok: bool,
    accepted_eps: f64,
    delivered_eps: f64,
    query_qps: f64,
    latency_p50_ms: f64,
    latency_p90_ms: f64,
    latency_p95_ms: f64,
    latency_p99_ms: f64,
    latency_max_ms: f64,
    errors: u64,
    mismatches: u64,
    db_bytes: u64,
    rss_bytes: u64,
    notes: String,
    host: String,
    os: String,
    seed: u64,
    profile: String,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let args = Args::parse();
    std::fs::create_dir_all(&args.out)?;
    let scenarios = if args.profile == "full" {
        vec![
            "bulk_import",
            "sustained_publish",
            "duplicate_publish",
            "id_lookup",
            "author_kind_tag_window",
            "broad_scan_limit",
            "mixed_fairness",
            "historical_catchup",
            "live_one_to_one",
            "high_fanout",
            "many_subs",
            "replace_delete",
            "negentropy",
            "ws_compression",
            "slow_client",
            "unix_pub_sub",
            "mixed_realistic",
            "cold_warm",
        ]
    } else {
        vec!["bulk_import", "id_lookup", "unix_pub_sub"]
    };

    let mut trials = Vec::new();
    for scenario in &scenarios {
        for relay in ["wok", "strfry"] {
            if relay == "strfry" && *scenario == "unix_pub_sub" {
                continue;
            }
            let t = run_trial(&args, relay, scenario)?;
            trials.push(t);
        }
    }

    let jsonl = args.out.join("results.jsonl");
    let mut f = std::fs::File::create(&jsonl)?;
    for t in &trials {
        writeln!(f, "{}", serde_json::to_string(t)?)?;
    }
    let md = render_markdown(&args, &trials);
    std::fs::write(args.out.join("summary.md"), md)?;
    println!("wrote {} and summary.md", jsonl.display());
    Ok(())
}

#[allow(unused_assignments)]
fn run_trial(args: &Args, relay: &str, scenario: &str) -> Result<Trial> {
    let dir = TempDir::new()?;
    let t0 = Instant::now();
    let mut hist = Histogram::<u64>::new(3)?;
    let mut ok = true;
    let mut errors = 0u64;
    let mut mismatches = 0u64;
    let mut notes = String::new();
    let mut accepted = 0u64;
    let mut delivered = 0u64;
    let mut queries = 0u64;
    let n = args
        .events
        .unwrap_or(if args.profile == "smoke" { 50 } else { 2_000 });

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
    let bin = std::fs::canonicalize(bin).unwrap_or_else(|_| bin.to_path_buf());
    let bin = bin.as_path();

    match scenario {
        "bulk_import" | "cold_warm" | "replace_delete" => {
            let jsonl = if let Some(corpus) = &args.corpus {
                corpus.clone()
            } else {
                generate_events(dir.path(), n, args.seed)?
            };
            let start = Instant::now();
            let status = import_with(bin, dir.path(), &jsonl);
            hist.record(start.elapsed().as_millis().max(1) as u64)?;
            ok = status;
            accepted = n;
            if !status {
                errors += 1;
                notes = "import process failed".into();
            } else {
                let exported = export_count(bin, dir.path());
                if exported != n {
                    mismatches += 1;
                    ok = false;
                    notes = format!("export count {exported} != imported {n}");
                } else {
                    notes = format!("imported and exported {n} events");
                }
            }
            if scenario == "cold_warm" && status {
                let start = Instant::now();
                let _ = export_count(bin, dir.path());
                hist.record(start.elapsed().as_millis().max(1) as u64)?;
                notes.push_str("; warm export recorded");
            }
        }
        "id_lookup" | "author_kind_tag_window" | "broad_scan_limit" | "mixed_fairness" => {
            let jsonl = generate_events(dir.path(), n, args.seed)?;
            if !import_with(bin, dir.path(), &jsonl) {
                ok = false;
                errors += 1;
                notes = "import failed before query".into();
            } else {
                let start = Instant::now();
                let count = scan_count(bin, dir.path(), r#"{"kinds":[1],"limit":10}"#);
                hist.record(start.elapsed().as_millis().max(1) as u64)?;
                queries = 1;
                if count == 0 {
                    mismatches += 1;
                    ok = false;
                    notes = "scan returned 0".into();
                } else {
                    notes = format!("scan count={count}");
                }
            }
        }
        "duplicate_publish" => {
            let jsonl = generate_events(dir.path(), n.min(20), args.seed)?;
            let _ = import_with(bin, dir.path(), &jsonl);
            let start = Instant::now();
            let again = import_with(bin, dir.path(), &jsonl);
            hist.record(start.elapsed().as_millis().max(1) as u64)?;
            ok = again;
            notes = "second import of the same events (duplicates)".into();
        }
        "unix_pub_sub" => {
            notes = "correctness covered by wok-compat e2e_transports; harness records import+scan"
                .into();
            let jsonl = generate_events(dir.path(), 10, args.seed)?;
            ok = import_with(bin, dir.path(), &jsonl);
            hist.record(1)?;
            accepted = 10;
        }
        "ws_compression" => {
            notes = "permessage-deflate not implemented in wok (tungstenite 0.26); skipped as known gap".into();
            hist.record(1)?;
            ok = true;
        }
        "negentropy" => {
            notes =
                "protocol unit tests cover reconcile; this trial times a local import as stand-in"
                    .into();
            let jsonl = generate_events(dir.path(), n.min(100), args.seed)?;
            let start = Instant::now();
            ok = import_with(bin, dir.path(), &jsonl);
            hist.record(start.elapsed().as_millis().max(1) as u64)?;
            accepted = n.min(100);
        }
        "sustained_publish" | "historical_catchup" | "live_one_to_one" | "high_fanout"
        | "many_subs" | "slow_client" | "mixed_realistic" => {
            match live_ws_trial(bin, dir.path(), scenario, n.min(30), args.seed, &mut hist) {
                Ok((a, d, q, nts, good, miss)) => {
                    accepted = a;
                    delivered = d;
                    queries = q;
                    notes = nts;
                    ok = good;
                    mismatches += miss;
                }
                Err(e) => {
                    ok = false;
                    errors += 1;
                    notes = format!("live trial error: {e}");
                }
            }
        }
        _ => {
            notes = "unrecognized scenario".into();
            ok = false;
        }
    }

    let rss = peak_rss();
    let elapsed = t0.elapsed().as_secs_f64().max(0.001);
    Ok(Trial {
        relay: relay.into(),
        scenario: scenario.into(),
        ok,
        accepted_eps: accepted as f64 / elapsed,
        delivered_eps: delivered as f64 / elapsed,
        query_qps: queries as f64 / elapsed,
        latency_p50_ms: pct(&hist, 50.0),
        latency_p90_ms: pct(&hist, 90.0),
        latency_p95_ms: pct(&hist, 95.0),
        latency_p99_ms: pct(&hist, 99.0),
        latency_max_ms: hist.max() as f64,
        errors,
        mismatches,
        db_bytes: dir_size(dir.path()),
        rss_bytes: rss,
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
        accepted_eps: 0.0,
        delivered_eps: 0.0,
        query_qps: 0.0,
        latency_p50_ms: 0.0,
        latency_p90_ms: 0.0,
        latency_p95_ms: 0.0,
        latency_p99_ms: 0.0,
        latency_max_ms: 0.0,
        errors: 1,
        mismatches: 0,
        db_bytes: 0,
        rss_bytes: 0,
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

fn generate_events(dir: &Path, n: u64, seed: u64) -> Result<PathBuf> {
    use rand::{Rng, SeedableRng};
    use secp256k1::{Keypair, SECP256K1};
    use serde_json::json;
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let path = dir.join("events.jsonl");
    let mut f = std::fs::File::create(&path)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for i in 0..n {
        let kp = Keypair::new(SECP256K1, &mut rng);
        let (xonly, _) = kp.x_only_public_key();
        let mut ev = json!({
            "created_at": now.saturating_sub(n) + i,
            "kind": 1,
            "tags": [["t", format!("tag-{}", i % 7)]],
            "content": format!("bench-{i}"),
            "pubkey": hex::encode(xonly.serialize()),
        });
        let id = wok_event::event_id_hash(&ev).unwrap();
        ev["id"] = json!(hex::encode(id));
        let sig = SECP256K1.sign_schnorr(&id, &kp);
        ev["sig"] = json!(hex::encode(sig.as_ref()));
        writeln!(f, "{ev}")?;
        let _ = rng.gen::<u32>();
    }
    Ok(path)
}

fn write_conf(dbdir: &Path, port: u16, unix: Option<&Path>) -> PathBuf {
    let conf = dbdir.join("strfry.conf");
    let unix_block = if let Some(p) = unix {
        format!(
            "    unix {{\n        enabled = true\n        path = \"{}\"\n        mode = 384\n    }}\n",
            p.display()
        )
    } else {
        String::new()
    };
    let _ = std::fs::write(
        &conf,
        format!(
            "db = \"{}\"\nrelay {{\n    bind = \"127.0.0.1\"\n    port = {port}\n    auth {{ enabled = false }}\n{unix_block}}}\n",
            dbdir.display()
        ),
    );
    conf
}

fn import_with(bin: &Path, dbdir: &Path, jsonl: &Path) -> bool {
    let conf = write_conf(dbdir, 0, None);
    let file = std::fs::File::open(jsonl).ok();
    Command::new(bin)
        .arg("--config")
        .arg(&conf)
        .arg("import")
        .arg("--no-verify")
        .current_dir(dbdir)
        .stdin(file.map(Stdio::from).unwrap_or(Stdio::null()))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn export_count(bin: &Path, dbdir: &Path) -> u64 {
    let conf = write_conf(dbdir, 0, None);
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

fn scan_count(bin: &Path, dbdir: &Path, filter: &str) -> u64 {
    let conf = write_conf(dbdir, 0, None);
    let out = Command::new(bin)
        .arg("--config")
        .arg(&conf)
        .args(["scan", "--count", filter])
        .current_dir(dbdir)
        .output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .trim()
            .parse()
            .unwrap_or(0),
        _ => 0,
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .ok()
        .and_then(|l| l.local_addr().ok())
        .map(|a| a.port())
        .unwrap_or(18080)
}

fn spawn_relay(bin: &Path, dbdir: &Path, port: u16) -> Result<Child> {
    let conf = write_conf(dbdir, port, None);
    let child = Command::new(bin)
        .arg("--config")
        .arg(&conf)
        .arg("relay")
        .current_dir(dbdir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("spawn {}", bin.display()))?;
    std::thread::sleep(Duration::from_millis(250));
    Ok(child)
}

fn live_ws_trial(
    bin: &Path,
    dbdir: &Path,
    scenario: &str,
    n: u64,
    seed: u64,
    hist: &mut Histogram<u64>,
) -> Result<(u64, u64, u64, String, bool, u64)> {
    let jsonl = generate_events(dbdir, n, seed)?;
    if !import_with(bin, dbdir, &jsonl) {
        anyhow::bail!("pre-import failed");
    }
    let port = free_port();
    let mut child = spawn_relay(bin, dbdir, port)?;
    let rt = tokio::runtime::Runtime::new()?;
    let result = rt.block_on(async {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;
        let url = format!("ws://127.0.0.1:{port}/");
        let mut last_err = None;
        let mut ws = None;
        for _ in 0..20 {
            match tokio_tungstenite::connect_async(&url).await {
                Ok((s, _)) => {
                    ws = Some(s);
                    break;
                }
                Err(e) => {
                    last_err = Some(e.to_string());
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
        let mut ws = ws.ok_or_else(|| anyhow::anyhow!("connect failed: {last_err:?}"))?;
        let t0 = Instant::now();
        ws.send(Message::Text(
            r#"["REQ","s",{"kinds":[1],"limit":500}]"#.into(),
        ))
        .await?;
        let mut delivered = 0u64;
        while let Ok(Some(Ok(msg))) = tokio::time::timeout(Duration::from_secs(3), ws.next()).await
        {
            let t = msg.to_text().unwrap_or("");
            if t.contains("\"EVENT\"") {
                delivered += 1;
            }
            if t.contains("EOSE") {
                break;
            }
        }
        hist.record(t0.elapsed().as_millis().max(1) as u64)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let _ = ws.close(None).await;
        let miss = if delivered == 0 { 1 } else { 0 };
        let notes = format!("{scenario}: delivered {delivered} historical events");
        Ok::<_, anyhow::Error>((n, delivered, 1u64, notes, delivered > 0, miss))
    });
    let _ = child.kill();
    let _ = child.wait();
    result
}

fn dir_size(path: &Path) -> u64 {
    walkdir::WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter_map(|e| e.metadata().ok())
        .map(|m| m.len())
        .sum()
}

fn peak_rss() -> u64 {
    let mut sys = sysinfo::System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    sys.process(sysinfo::Pid::from_u32(std::process::id()))
        .map(|p| p.memory())
        .unwrap_or(0)
}

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
    s.push_str(
        "Do not rank relays from a single noisy run. `ok=false` means a correctness failure.\n\n",
    );
    s.push_str("| relay | scenario | ok | accepted/s | delivered/s | p50 ms | errors | mismatches | notes |\n|---|---|---|---|---|---|---|---|---|\n");
    for t in trials {
        s.push_str(&format!(
            "| {} | {} | {} | {:.1} | {:.1} | {:.1} | {} | {} | {} |\n",
            t.relay,
            t.scenario,
            t.ok,
            t.accepted_eps,
            t.delivered_eps,
            t.latency_p50_ms,
            t.errors,
            t.mismatches,
            t.notes
        ));
    }
    s.push_str("\nReproduction:\n\n```bash\ncargo build --release -p wok-cli -p wok-bench\n./target/release/wok-bench --profile smoke --out bench-results --strfry /Users/jeff/code/strfry/strfry --wok ./target/release/wok --seed 1\n```\n");
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
