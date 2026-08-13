use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::io::BufRead;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use wok_db::{
    check_integrity, delete_events, event_json_owned, write_events, Decompressor, Env, EnvOptions,
    EventToWrite, NoopNegentropy,
};
use wok_event::{parse_and_verify_event, EventLimits, PackedEventView};
use wok_negentropy::Storage;
mod doctor;
mod migrate;
mod reindex;
mod router;

use wok_relay::Config;

fn foreach_by_filter_scan(
    txn: &wok_db::RoTxn<'_>,
    filter: &serde_json::Value,
    max_limit: u64,
    max_tags: usize,
    cb: impl FnMut(u64),
) -> Result<(), wok_query::QueryError> {
    wok_query::foreach_by_filter(txn, filter, max_limit, max_tags, cb)
}

#[derive(Parser)]
#[command(
    name = "wok",
    version,
    about = "Nostr relay with verified migration from strfry"
)]
struct Cli {
    /// Wok config, or source strfry config during migration
    #[arg(long, short, global = true, default_value = "wok.toml")]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a verified Wok-owned database from another relay
    Migrate {
        #[command(subcommand)]
        cmd: MigrateCmd,
    },
    Relay,
    Info,
    /// Diagnose configuration, storage, indexes, payloads, and runtime paths
    Doctor {
        /// Emit the complete machine-readable report
        #[arg(long)]
        json: bool,
    },
    /// Rebuild all derived indexes into a staged database and promote it
    Reindex {
        /// Required acknowledgement that no relay or DB utility is using the database
        #[arg(long)]
        confirm_relay_stopped: bool,
        /// Sibling directory that will retain the original database
        #[arg(long)]
        backup: Option<PathBuf>,
        /// Emit the machine-readable outcome
        #[arg(long)]
        json: bool,
    },
    Import {
        #[arg(long)]
        show_rejected: bool,
        #[arg(long)]
        no_verify: bool,
        #[arg(long)]
        fried: bool,
        #[arg(long, default_value_t = 1000)]
        debounce_millis: u64,
        #[arg(long)]
        write_batch: Option<u64>,
    },
    Export {
        #[arg(long, default_value_t = 0)]
        since: u64,
        #[arg(long)]
        until: Option<u64>,
        #[arg(long)]
        reverse: bool,
        #[arg(long)]
        fried: bool,
    },
    Scan {
        filter: String,
        #[arg(long)]
        count: bool,
    },
    /// Print one event by its local event ID (levId)
    Event {
        lev_id: u64,
        #[arg(long)]
        fried: bool,
    },
    Delete {
        #[arg(long)]
        age: Option<u64>,
        #[arg(long)]
        filter: Option<String>,
        #[arg(long)]
        dry_run: bool,
    },
    Compact {
        output_file: PathBuf,
    },
    Monitor,
    Dict {
        #[command(subcommand)]
        cmd: DictCmd,
    },
    Negentropy {
        #[command(subcommand)]
        cmd: NegCmd,
    },
    Integrity,
    Sync {
        url: String,
        #[arg(long, default_value = "both")]
        dir: String,
        #[arg(long)]
        filter: Option<String>,
        /// Add since/until to the filter. Format: START-END, e.g. 2M- or 1Y-3w
        #[arg(long)]
        range: Option<String>,
        /// Only print missing record IDs (implies --dir=none)
        #[arg(long)]
        print_missing: bool,
        #[arg(long, default_value_t = 60_000)]
        frame_size_limit: u64,
        /// Abort if no activity for this many seconds (0 = no timeout)
        #[arg(long, default_value_t = 0)]
        timeout: u64,
    },
    Stream {
        url: String,
        #[arg(long, default_value = "down")]
        dir: String,
    },
    Upload {
        url: String,
        #[arg(long, default_value_t = 50)]
        pipeline: u64,
    },
    Download {
        url: String,
        #[arg(long)]
        filter: Option<String>,
    },
    Router {
        /// Router config file (taocpp::config format)
        router_config_file: PathBuf,
    },
}

#[derive(Subcommand)]
enum MigrateCmd {
    /// Import a strfry LMDB v3 database and config without modifying either
    Strfry {
        /// strfry LMDB environment directory
        #[arg(long)]
        db: PathBuf,
        /// New directory to create with db/, wok.toml, and a manifest
        #[arg(long)]
        output: PathBuf,
        /// Inspect source, translation, capacity, and runtime use without copying
        #[arg(long)]
        check: bool,
        /// Emit a machine-readable preflight report (requires --check)
        #[arg(long, requires = "check")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum DictCmd {
    Stats {
        #[arg(long)]
        filter: Option<String>,
    },
    Train {
        #[arg(long)]
        filter: Option<String>,
        #[arg(long)]
        limit: Option<u64>,
        #[arg(long, default_value_t = 100_000)]
        dict_size: u64,
    },
    Compress {
        #[arg(long)]
        filter: Option<String>,
        #[arg(long)]
        dict_id: Option<u64>,
        #[arg(long, default_value_t = 3)]
        level: i32,
    },
    Decompress {
        #[arg(long)]
        filter: Option<String>,
    },
}

#[derive(Subcommand)]
enum NegCmd {
    List,
    Add { filter: String },
    Build { tree_id: u64 },
}

fn open_env(cfg: &Config) -> Result<Env> {
    let env = Env::open(
        &cfg.db,
        EnvOptions {
            max_readers: cfg.db_maxreaders,
            map_size: cfg.db_mapsize,
            no_read_ahead: cfg.db_no_read_ahead,
            ..EnvOptions::default()
        },
    )?;
    env.ensure_initialized()?;
    Ok(env)
}

fn load_cfg(path: &Path) -> Result<Config> {
    if path.exists() {
        Config::load(path).map_err(|e| anyhow::anyhow!(e))
    } else {
        tracing::warn!("config {} not found, using defaults", path.display());
        Ok(Config::default())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("wok=info".parse().unwrap()),
        )
        .init();
    let Cli { config, cmd } = Cli::parse();
    let cmd = match cmd {
        Command::Migrate { cmd } => {
            return match cmd {
                MigrateCmd::Strfry {
                    db,
                    output,
                    check,
                    json,
                } => {
                    if check {
                        migrate::check_strfry(&db, &config, &output, json)
                    } else {
                        migrate::migrate_strfry(&db, &config, &output)
                    }
                }
            };
        }
        cmd => cmd,
    };
    let cfg = load_cfg(&config)?;
    match cmd {
        Command::Migrate { .. } => unreachable!("migration was dispatched before config load"),
        Command::Relay => cmd_relay(cfg, config).await,
        Command::Info => cmd_info(&cfg),
        Command::Doctor { json } => cmd_doctor(&cfg, &config, json),
        Command::Reindex {
            confirm_relay_stopped,
            backup,
            json,
        } => cmd_reindex(&cfg, backup.as_deref(), confirm_relay_stopped, json),
        Command::Import {
            show_rejected,
            no_verify,
            fried,
            debounce_millis: _,
            write_batch,
        } => cmd_import(&cfg, show_rejected, no_verify, fried, write_batch),
        Command::Export {
            since,
            until,
            reverse,
            fried,
        } => cmd_export(&cfg, since, until.unwrap_or(u64::MAX), reverse, fried),
        Command::Scan { filter, count } => cmd_scan(&cfg, &filter, count),
        Command::Event { lev_id, fried } => cmd_event(&cfg, lev_id, fried),
        Command::Delete {
            age,
            filter,
            dry_run,
        } => cmd_delete(&cfg, age, filter, dry_run),
        Command::Compact { output_file } => cmd_compact(&cfg, &output_file),
        Command::Monitor => cmd_monitor(&cfg),
        Command::Dict { cmd } => cmd_dict(&cfg, cmd),
        Command::Negentropy { cmd } => cmd_neg(&cfg, cmd),
        Command::Integrity => cmd_integrity(&cfg),
        Command::Sync {
            url,
            dir,
            filter,
            range,
            print_missing,
            frame_size_limit,
            timeout,
        } => {
            cmd_sync(
                &cfg,
                url,
                dir,
                filter,
                range,
                print_missing,
                frame_size_limit,
                timeout,
            )
            .await
        }
        Command::Stream { url, dir } => cmd_stream(&cfg, url, dir).await,
        Command::Upload { url, pipeline } => cmd_upload(url, pipeline).await,
        Command::Download { url, filter } => cmd_download(url, filter).await,
        Command::Router { router_config_file } => router::run_router(cfg, router_config_file).await,
    }
}

/// Watch the config file and live-reload the reloadable subset, like golpe
/// (which watches the config file and applies non-`noReload` keys). Parse
/// errors keep the old config.
fn spawn_config_reload(path: PathBuf, handle: wok_relay::RelayHandle) {
    tokio::spawn(async move {
        let mut last = std::fs::metadata(&path)
            .ok()
            .and_then(|m| m.modified().ok());
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            if handle.is_shutdown() {
                break;
            }
            let cur = std::fs::metadata(&path)
                .ok()
                .and_then(|m| m.modified().ok());
            if cur.is_none() || cur == last {
                continue;
            }
            last = cur;
            match Config::load(&path) {
                Ok(new) => {
                    tracing::info!("config {} changed, reloading", path.display());
                    handle.config.write().apply_reload(new);
                }
                Err(e) => {
                    tracing::error!("config reload failed, keeping old config: {e}");
                }
            }
        }
    });
}

async fn cmd_relay(cfg: Config, config_path: PathBuf) -> Result<()> {
    wok_relay::apply_nofiles_limit(cfg.relay.nofiles).map_err(anyhow::Error::msg)?;
    let env = open_env(&cfg)?;
    let bind: SocketAddr = format!("{}:{}", cfg.relay.bind, cfg.relay.port).parse()?;
    let unix_cfg = cfg.clone();
    let handle = wok_relay::start(env, cfg).map_err(|e| anyhow::anyhow!(e))?;
    if config_path.exists() {
        spawn_config_reload(config_path, handle.clone());
    }
    let h2 = handle.clone();
    let h3 = handle.clone();
    let ws = tokio::spawn(async move {
        if let Err(e) = wok_ws::serve(h3, bind).await {
            tracing::error!("ws server: {e}");
        }
    });
    let unix = tokio::spawn(async move {
        if let Err(e) = wok_unix::serve(h2, unix_cfg).await {
            tracing::error!("unix server: {e}");
        }
    });
    // C++ graceful shutdown is SIGUSR1; wok also treats SIGINT the same way.
    let mut sigusr1 =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => tracing::info!("SIGINT: initiating graceful shutdown"),
        _ = sigusr1.recv() => tracing::info!("SIGUSR1: initiating graceful shutdown"),
    }
    handle.request_shutdown();
    // Listeners stop accepting and return (the unix server unlinks its
    // socket); existing connections drain naturally like C++.
    let _ = ws.await;
    let _ = unix.await;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let n = handle
            .metrics
            .active_connections
            .load(std::sync::atomic::Ordering::Relaxed);
        if n == 0 {
            tracing::info!("All connections closed, shutting down");
            break;
        }
        if std::time::Instant::now() > deadline {
            tracing::warn!("Shutdown deadline reached with {n} connections remaining");
            break;
        }
        tracing::info!("Graceful shutdown in progress: {n} connections remaining");
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    Ok(())
}

fn cmd_info(cfg: &Config) -> Result<()> {
    let env = open_env(cfg)?;
    println!("DB version: {}", env.db_version()?);
    Ok(())
}

fn cmd_doctor(cfg: &Config, config_path: &Path, json: bool) -> Result<()> {
    let report = doctor::run(cfg, config_path);
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", report.render_human());
    }
    if !report.ok {
        std::process::exit(1);
    }
    Ok(())
}

fn cmd_reindex(
    cfg: &Config,
    backup: Option<&Path>,
    confirmed_stopped: bool,
    json: bool,
) -> Result<()> {
    let outcome = reindex::run(cfg, backup, confirmed_stopped)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&outcome)?);
    } else {
        println!("Reindexed {} events.", outcome.events);
        println!("Database: {}", outcome.database.display());
        println!("Original backup: {}", outcome.backup.display());
        println!("Fingerprint: {}", outcome.event_fingerprint_sha256);
    }
    Ok(())
}

fn cmd_import(
    cfg: &Config,
    show_rejected: bool,
    no_verify: bool,
    fried: bool,
    write_batch: Option<u64>,
) -> Result<()> {
    if no_verify {
        tracing::warn!("not verifying event IDs or signatures!");
    }
    if fried && cfg!(target_endian = "big") {
        // Matches the C++ cmd_import guard.
        bail!("--fried currently only supported on little-endian CPUs");
    }
    let env = open_env(cfg)?;
    let batch_size = write_batch.unwrap_or(if fried { 100_000 } else { 10_000 }) as usize;
    let stdin = std::io::stdin();
    let mut batch = Vec::new();
    let mut total_processed = 0u64;
    let mut total_written = 0u64;
    let mut total_rejected = 0u64;
    let mut total_dups = 0u64;
    let limits = cfg.event_limits();
    for (i, line) in stdin.lock().lines().enumerate() {
        let line = line?;
        total_processed += 1;
        // C++ counts the newline in its getline length check, so a line of
        // exactly maxEventSize chars is rejected there.
        if line.len() + 1 > cfg.events.max_event_size {
            bail!("Line larger than configured maxEventSize on line {}", i + 1);
        }
        match parse_import_line(&line, fried, no_verify, &limits) {
            Ok(ev) => batch.push(ev),
            Err(e) => {
                tracing::warn!("Unable to parse JSON on line {}: {e}", i + 1);
                continue;
            }
        }
        if batch.len() >= batch_size {
            commit_import(
                &env,
                &mut batch,
                &mut total_written,
                &mut total_rejected,
                &mut total_dups,
                show_rejected,
            )?;
        }
    }
    if !batch.is_empty() {
        commit_import(
            &env,
            &mut batch,
            &mut total_written,
            &mut total_rejected,
            &mut total_dups,
            show_rejected,
        )?;
    }
    tracing::info!(
        "Done. Processed {total_processed} lines. {total_written} added, {total_rejected} rejected, {total_dups} dups"
    );
    Ok(())
}

fn parse_import_line(
    line: &str,
    fried: bool,
    no_verify: bool,
    limits: &EventLimits,
) -> Result<EventToWrite> {
    if fried {
        let (packed, json) = parse_fried(line)?;
        return Ok(EventToWrite::new(packed, json));
    }
    let v: serde_json::Value = wok_event::json::parse_strict(line)?;
    let parsed = parse_and_verify_event(&v, limits, None, !no_verify, false)?;
    Ok(EventToWrite::new(parsed.packed.into_bytes(), parsed.json))
}

fn parse_fried(line: &str) -> Result<(Vec<u8>, String)> {
    if line.len() < 64 || !line.ends_with("\"}") {
        bail!("fried parse error");
    }
    let bytes = line.as_bytes();
    let mut i = line.len() - 3;
    while i > 0 && bytes[i] != b'"' {
        i -= 1;
    }
    if !line[..i + 1].ends_with(",\"fried\":\"") {
        bail!("fried parse error");
    }
    let packed = wok_event::from_hex(&line[i + 1..line.len() - 2])?;
    let mut json = line[..i - 9].to_string();
    json.push('}');
    Ok((packed, json))
}

fn commit_import(
    env: &Env,
    batch: &mut Vec<EventToWrite>,
    written: &mut u64,
    rejected: &mut u64,
    dups: &mut u64,
    show_rejected: bool,
) -> Result<()> {
    let mut txn = env.begin_rw()?;
    let mut sink = NoopNegentropy;
    write_events(&mut txn, &mut sink, batch, false)?;
    txn.commit()?;
    for ev in batch.drain(..) {
        match ev.status {
            wok_db::EventWriteStatus::Written => *written += 1,
            wok_db::EventWriteStatus::Duplicate => *dups += 1,
            other => {
                *rejected += 1;
                if show_rejected {
                    tracing::info!("rejected {:?}: {}", other, ev.json);
                }
            }
        }
    }
    Ok(())
}

fn cmd_export(cfg: &Config, since: u64, until: u64, reverse: bool, fried: bool) -> Result<()> {
    let env = open_env(cfg)?;
    let txn = env.begin_ro()?;
    if fried && cfg!(target_endian = "big") {
        bail!("--fried currently only supported on little-endian CPUs");
    }
    let mut decomp = Decompressor::new();
    let start = if reverse { until } else { since };
    let start_dup = if reverse { u64::MAX } else { 0 };
    let mut export_err: Option<anyhow::Error> = None;
    wok_db::foreach_created_at(&txn, start, start_dup, reverse, |created, lev| {
        if reverse {
            if created < since {
                return false;
            }
        } else if created > until {
            return false;
        }
        // C++ getEventJson/lookupEventByLevId abort the export on a missing
        // or undecodable record; do the same instead of silently skipping.
        match event_json_owned(&txn, &mut decomp, lev, cfg.events.max_event_size) {
            Ok(json) => {
                if fried {
                    match wok_db::get_packed_ro(&txn, lev) {
                        Ok(Some(packed)) => {
                            let mut o = json;
                            o.pop();
                            o.push_str(",\"fried\":\"");
                            o.push_str(&hex::encode(packed));
                            o.push_str("\"}");
                            println!("{o}");
                        }
                        Ok(None) => {
                            export_err = Some(anyhow::anyhow!("unable to lookup event by levId"));
                            return false;
                        }
                        Err(e) => {
                            export_err = Some(e.into());
                            return false;
                        }
                    }
                } else {
                    println!("{json}");
                }
            }
            Err(e) => {
                export_err = Some(e.into());
                return false;
            }
        }
        true
    })?;
    if let Some(e) = export_err {
        return Err(e);
    }
    Ok(())
}

fn cmd_scan(cfg: &Config, filter: &str, count: bool) -> Result<()> {
    let env = open_env(cfg)?;
    let txn = env.begin_ro()?;
    let filter: serde_json::Value = serde_json::from_str(filter)?;
    let mut n = 0u64;
    let mut decomp = Decompressor::new();
    foreach_by_filter_scan(
        &txn,
        &filter,
        cfg.relay.max_filter_limit,
        cfg.relay.max_tags_per_filter,
        |lev| {
            n += 1;
            if !count {
                if let Ok(json) =
                    event_json_owned(&txn, &mut decomp, lev, cfg.events.max_event_size)
                {
                    println!("{json}");
                }
            }
        },
    )?;
    if count {
        println!("{n}");
    }
    Ok(())
}

fn cmd_event(cfg: &Config, lev_id: u64, fried: bool) -> Result<()> {
    let env = open_env(cfg)?;
    let txn = env.begin_ro()?;
    let mut decomp = Decompressor::new();
    let json = event_json_owned(&txn, &mut decomp, lev_id, cfg.events.max_event_size)
        .with_context(|| format!("couldn't find event in EventPayload (levId {lev_id})"))?;
    if fried {
        if cfg!(target_endian = "big") {
            bail!("--fried currently only supported on little-endian CPUs");
        }
        let packed = wok_db::get_packed_ro(&txn, lev_id)?
            .with_context(|| format!("unable to lookup event by levId {lev_id}"))?;
        let mut o = json;
        o.pop();
        o.push_str(",\"fried\":\"");
        o.push_str(&hex::encode(packed));
        o.push_str("\"}");
        println!("{o}");
    } else {
        println!("{json}");
    }
    Ok(())
}

fn cmd_delete(cfg: &Config, age: Option<u64>, filter: Option<String>, dry_run: bool) -> Result<()> {
    if age.is_none() && filter.is_none() {
        bail!("must specify --age and/or --filter");
    }
    let mut filter: serde_json::Value = serde_json::from_str(filter.as_deref().unwrap_or("{}"))?;
    if let Some(age) = age {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        if filter.get("until").is_some() {
            bail!("--age is not compatible with filter containing 'until'");
        }
        filter["until"] = serde_json::json!(now.saturating_sub(age.min(now)));
    }
    let env = open_env(cfg)?;
    let mut levs = Vec::new();
    {
        let txn = env.begin_ro()?;
        foreach_by_filter_scan(
            &txn,
            &filter,
            u64::MAX,
            cfg.relay.max_tags_per_filter,
            |lev| levs.push(lev),
        )?;
    }
    if dry_run {
        tracing::info!("Would delete {} events", levs.len());
        return Ok(());
    }
    tracing::info!("Deleting {} events", levs.len());
    let mut txn = env.begin_rw()?;
    let mut sink = NoopNegentropy;
    delete_events(&mut txn, &mut sink, levs)?;
    txn.commit()?;
    Ok(())
}

fn cmd_compact(cfg: &Config, output: &Path) -> Result<()> {
    let env = open_env(cfg)?;
    if output.as_os_str() == "-" {
        env.compact_to_fd(1)?;
    } else {
        env.compact_to_path(output)?;
    }
    Ok(())
}

fn cmd_monitor(cfg: &Config) -> Result<()> {
    let env = open_env(cfg)?;
    let txn = env.begin_ro()?;
    let mut monitors = wok_query::ActiveMonitors::new(cfg.relay.max_subs_per_connection);
    let stdin = std::io::stdin();
    let mut interest: Option<(u64, String)> = None;
    for line in stdin.lock().lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        let msg: serde_json::Value = serde_json::from_str(&line)?;
        let arr = msg.as_array().context("not array")?;
        let cmd = arr[0].as_str().unwrap_or("");
        match cmd {
            "sub" => {
                let conn = arr[1].as_u64().unwrap_or(0);
                let sub = arr[2].as_str().unwrap_or("x");
                let fg = wok_query::NostrFilterGroup::from_value(
                    &arr[3],
                    cfg.relay.max_filter_limit,
                    cfg.relay.max_tags_per_filter,
                )?;
                let mut s =
                    wok_query::Subscription::new(conn, wok_query::SubId::new(sub)?, fg, false);
                s.latest_event_id = 0;
                monitors.add_sub(s, 0);
            }
            "removeSub" => {
                monitors.remove_sub(
                    arr[1].as_u64().unwrap_or(0),
                    &wok_query::SubId::new(arr[2].as_str().unwrap_or(""))?,
                );
            }
            "closeConn" => monitors.close_conn(arr[1].as_u64().unwrap_or(0)),
            "interest" => {
                interest = Some((
                    arr[1].as_u64().unwrap_or(0),
                    arr[2].as_str().unwrap_or("").to_string(),
                ));
            }
            _ => bail!("unknown cmd"),
        }
    }
    let mut decomp = Decompressor::new();
    wok_db::foreach_event_from(&txn, 0, |lev, packed| {
        if let Ok(p) = wok_event::PackedEventView::new(packed) {
            if let Ok(json) = event_json_owned(&txn, &mut decomp, lev, cfg.events.max_event_size) {
                let search_terms = if monitors.requires_content() {
                    Some(wok_db::event_search_terms(&json).unwrap_or_default())
                } else {
                    None
                };
                let recips = monitors.process(lev, p, search_terms.as_ref());
                if let Some((cid, sid)) = &interest {
                    if recips
                        .iter()
                        .any(|r| r.conn_id == *cid && r.sub_id.as_str() == sid)
                    {
                        println!("{json}");
                    }
                }
            }
        }
        true
    })?;
    Ok(())
}

fn cmd_dict(cfg: &Config, cmd: DictCmd) -> Result<()> {
    let env = open_env(cfg)?;
    let (filter, limit, dict_size, dict_id, level) = match &cmd {
        DictCmd::Stats { filter } => (filter.clone(), None, 0, None, 0),
        DictCmd::Train {
            filter,
            limit,
            dict_size,
        } => (filter.clone(), *limit, *dict_size, None, 0),
        DictCmd::Compress {
            filter,
            dict_id,
            level,
        } => (filter.clone(), None, 0, *dict_id, *level),
        DictCmd::Decompress { filter } => (filter.clone(), None, 0, None, 0),
    };
    let filter = filter.unwrap_or_else(|| "{}".into());
    let mut levs = Vec::new();
    {
        let txn = env.begin_ro()?;
        let filter: serde_json::Value = wok_event::json::parse_strict(&filter)?;
        foreach_by_filter_scan(
            &txn,
            &filter,
            u64::MAX,
            cfg.relay.max_tags_per_filter,
            |lev| levs.push(lev),
        )?;
    }
    tracing::info!("Filter matched {} records", levs.len());
    match cmd {
        DictCmd::Stats { .. } => {
            let txn = env.begin_ro()?;
            let mut total = 0usize;
            let mut compressed = 0usize;
            let mut n_comp = 0u64;
            for lev in &levs {
                if let Ok(Some(raw)) = wok_db::get_payload_ro(&txn, *lev) {
                    total += raw.len();
                    if raw.first() == Some(&wok_db::PAYLOAD_ZSTD) {
                        compressed += raw.len();
                        n_comp += 1;
                    }
                }
            }
            println!(
                "records={} bytes={} compressed_records={n_comp} compressed_bytes={compressed}",
                levs.len(),
                total
            );
        }
        DictCmd::Train { .. } => {
            use rand::seq::SliceRandom;
            let mut levs = levs;
            if let Some(limit) = limit {
                if levs.len() as u64 > limit {
                    tracing::info!("Randomly selecting {limit} records");
                    let mut rng = rand::thread_rng();
                    levs.shuffle(&mut rng);
                    levs.truncate(limit as usize);
                }
            }
            let txn = env.begin_ro()?;
            let mut decomp = Decompressor::new();
            let mut training_buf = Vec::new();
            let mut training_sizes = Vec::new();
            for lev in &levs {
                let json = event_json_owned(&txn, &mut decomp, *lev, cfg.events.max_event_size)?;
                training_sizes.push(json.len());
                training_buf.extend_from_slice(json.as_bytes());
            }
            drop(txn);
            tracing::info!("Performing zstd training...");
            let dict =
                zstd::dict::from_continuous(&training_buf, &training_sizes, dict_size as usize)
                    .map_err(|e| anyhow::anyhow!("zstd training failed: {e}"))?;
            let mut txn = env.begin_rw()?;
            let new_id = wok_db::insert_compression_dictionary(&mut txn, &dict)?;
            txn.commit()?;
            println!("Saved new dictionary, dictId = {new_id}");
        }
        DictCmd::Compress { .. } => {
            let dict_id = dict_id.context("specify --dict-id")?;
            let dict = {
                let txn = env.begin_ro()?;
                wok_db::get_compression_dictionary_ro(&txn, dict_id)?
                    .with_context(|| format!("couldn't find dictId {dict_id}"))?
            };
            let dict = zstd::dict::EncoderDictionary::copy(&dict, level);
            let mut orig_sizes = 0u64;
            let mut compressed_sizes = 0u64;
            let mut processed = 0u64;
            let mut txn = env.begin_rw()?;
            let mut decomp = Decompressor::new();
            let mut pending_flush = 0u64;
            for lev in &levs {
                // C++ skips records that fail to decode.
                let json = {
                    let ro = env.begin_ro()?;
                    match event_json_owned(&ro, &mut decomp, *lev, cfg.events.max_event_size) {
                        Ok(j) => j,
                        Err(_) => continue,
                    }
                };
                let mut compressor = zstd::bulk::Compressor::with_prepared_dictionary(&dict)
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                let compressed = compressor
                    .compress(json.as_bytes())
                    .map_err(|e| anyhow::anyhow!("zstd compression failed: {e}"))?;
                orig_sizes += json.len() as u64;
                compressed_sizes += compressed.len() as u64;
                let new_val = if compressed.len() + 4 < json.len() {
                    wok_db::encode_zstd_payload(dict_id as u32, &compressed)
                } else {
                    wok_db::encode_raw_payload(&json)
                };
                txn.put_u64(env.dbis().event_payload, *lev, &new_val, 0)?;
                pending_flush += 1;
                processed += 1;
                if pending_flush > 10_000 {
                    txn.commit()?;
                    tracing::info!("Progress: {processed}/{}", levs.len());
                    pending_flush = 0;
                    txn = env.begin_rw()?;
                }
            }
            txn.commit()?;
            tracing::info!("Original event sizes: {orig_sizes}");
            tracing::info!("New event sizes:      {compressed_sizes}");
        }
        DictCmd::Decompress { .. } => {
            let mut processed = 0u64;
            let mut txn = env.begin_rw()?;
            let mut decomp = Decompressor::new();
            let mut pending_flush = 0u64;
            for lev in &levs {
                let json = {
                    let ro = env.begin_ro()?;
                    match event_json_owned(&ro, &mut decomp, *lev, cfg.events.max_event_size) {
                        Ok(j) => j,
                        Err(_) => continue,
                    }
                };
                let new_val = wok_db::encode_raw_payload(&json);
                txn.put_u64(env.dbis().event_payload, *lev, &new_val, 0)?;
                pending_flush += 1;
                processed += 1;
                if pending_flush > 10_000 {
                    txn.commit()?;
                    tracing::info!("Progress: {processed}/{}", levs.len());
                    pending_flush = 0;
                    txn = env.begin_rw()?;
                }
            }
            txn.commit()?;
        }
    }
    Ok(())
}

fn cmd_neg(cfg: &Config, cmd: NegCmd) -> Result<()> {
    let env = open_env(cfg)?;
    match cmd {
        NegCmd::List => {
            let txn = env.begin_ro()?;
            wok_db::foreach_negentropy_filter(&txn, |id, filter| {
                println!("tree {id}");
                println!("  filter: {filter}");
                if let Ok(mut tree) = wok_negentropy::open_ro(&txn, id) {
                    let size = tree.size();
                    let fp = tree.fingerprint(0, size as usize);
                    println!("  size: {size}");
                    println!("  fingerprint: {}", hex::encode(fp));
                }
                true
            })?;
        }
        NegCmd::Add { filter } => {
            let v: serde_json::Value = serde_json::from_str(&filter)?;
            let compiled = wok_query::NostrFilterGroup::from_value(&v, u64::MAX, 64)?;
            if compiled.filters.is_empty() {
                bail!("filter will never match");
            }
            if compiled.filters.len() == 1
                && (compiled.filters[0].since != 0 || compiled.filters[0].until != u64::MAX)
            {
                bail!("single filters should not have since/until");
            }
            let filter_str = v.to_string();
            let mut txn = env.begin_rw()?;
            wok_db::bump_negentropy_mod_counter(&mut txn)?;
            let mut exists = false;
            wok_db::foreach_negentropy_filter_rw(&txn, |id, f| {
                if f == filter_str {
                    exists = true;
                    tracing::error!("filter already exists as tree: {id}");
                    false
                } else {
                    true
                }
            })?;
            if exists {
                bail!("filter already exists");
            }
            let id = wok_db::insert_negentropy_filter(&mut txn, &filter_str)?;
            txn.commit()?;
            println!("created tree {id}");
            println!("  to populate, run: wok negentropy build {id}");
        }
        NegCmd::Build { tree_id } => {
            let mut recs = Vec::new();
            {
                let txn = env.begin_ro()?;
                let mut filter_str = None;
                wok_db::foreach_negentropy_filter(&txn, |id, f| {
                    if id == tree_id {
                        filter_str = Some(f.to_string());
                        false
                    } else {
                        true
                    }
                })?;
                let filter_str = filter_str.context("couldn't find treeId")?;
                let filter: serde_json::Value = serde_json::from_str(&filter_str)?;
                foreach_by_filter_scan(&txn, &filter, u64::MAX, 64, |lev| {
                    if let Ok(Some(buf)) = wok_db::get_packed_ro(&txn, lev) {
                        if let Ok(p) = wok_event::PackedEventView::new(&buf) {
                            recs.push((p.created_at(), p.id().to_vec()));
                        }
                    }
                })?;
            }
            let mut txn = env.begin_rw()?;
            wok_db::bump_negentropy_mod_counter(&mut txn)?;
            {
                let mut tree = wok_negentropy::open_rw(&mut txn, tree_id)?;
                for (ts, id) in recs {
                    let _ = tree.insert(ts, &id);
                }
                tree.backend.flush()?;
            }
            txn.commit()?;
        }
    }
    Ok(())
}

fn cmd_integrity(cfg: &Config) -> Result<()> {
    let env = open_env(cfg)?;
    let txn = env.begin_ro()?;
    let report = check_integrity(&txn)?;
    println!("{report:?}");
    if !report.ok() {
        std::process::exit(1);
    }
    Ok(())
}

/// Parse C++ MeshUtils time specs: `<number><unit>` with units
/// s/m/h/d/w/M(30.5d)/Y(365.2425d).
fn parse_mesh_time(s: &str) -> Result<u64> {
    if s.is_empty() {
        bail!("invalid time");
    }
    let (num, unit) = s.split_at(s.len() - 1);
    let scale = match unit {
        "s" => 1.0,
        "m" => 60.0,
        "h" => 60.0 * 60.0,
        "d" => 86400.0,
        "w" => 86400.0 * 7.0,
        "M" => 86400.0 * 30.5,
        "Y" => 86400.0 * 365.2425,
        _ => bail!("unknown time unit: {unit}"),
    };
    let v: f64 = num
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid time: {s}"))?;
    Ok((v * scale) as u64)
}

fn process_range_option(range: &str, filter: &mut serde_json::Value) -> Result<()> {
    if filter.get("since").is_some() || filter.get("until").is_some() {
        bail!("can't specify a --range AND since/until in filter");
    }
    let Some(dash) = range.find('-') else {
        bail!("range param is missing -");
    };
    let (since_str, until_str) = (&range[..dash], &range[dash + 1..]);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    if !since_str.is_empty() {
        filter["since"] = serde_json::json!(now.saturating_sub(parse_mesh_time(since_str)?));
    }
    if !until_str.is_empty() {
        filter["until"] = serde_json::json!(now.saturating_sub(parse_mesh_time(until_str)?));
    }
    if !since_str.is_empty() && !until_str.is_empty() {
        let s = filter["since"].as_u64().unwrap_or(0);
        let u = filter["until"].as_u64().unwrap_or(0);
        if s > u {
            bail!("since can't be after until");
        }
    }
    Ok(())
}

/// Verify and write a batch of downloaded events, updating negentropy trees
/// like C++ WriterPipeline (verifyMsg + verifyTime).
fn write_downloaded(
    env: &Env,
    cfg: &Config,
    batch: &mut Vec<serde_json::Value>,
    written: &mut u64,
) -> Result<()> {
    if batch.is_empty() {
        return Ok(());
    }
    let limits = cfg.event_limits();
    let policy = wok_event::TimestampPolicy::from_now(
        cfg.events.reject_newer_than_secs,
        cfg.events.reject_older_than_secs,
        cfg.events.reject_ephemeral_older_than_secs,
    );
    let mut evs = Vec::with_capacity(batch.len());
    for v in batch.drain(..) {
        match parse_and_verify_event(&v, &limits, Some(&policy), true, true) {
            Ok(p) => evs.push(EventToWrite::new(p.packed.into_bytes(), p.json)),
            Err(e) => tracing::warn!("downloaded event rejected: {e}"),
        }
    }
    if evs.is_empty() {
        return Ok(());
    }
    let mut txn = env.begin_rw()?;
    let mut sink = wok_negentropy::DeferredSink::default();
    write_events(&mut txn, &mut sink, &mut evs, false)?;
    let mut cache = wok_negentropy::NegentropyFilterCache::new(cfg.relay.max_tags_per_filter);
    sink.apply(&mut cache, &mut txn)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    txn.commit()?;
    *written += evs
        .iter()
        .filter(|e| e.status == wok_db::EventWriteStatus::Written)
        .count() as u64;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn cmd_sync(
    cfg: &Config,
    url: String,
    dir: String,
    filter: Option<String>,
    range: Option<String>,
    print_missing: bool,
    frame_size_limit: u64,
    timeout: u64,
) -> Result<()> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    if !["both", "up", "down", "none"].contains(&dir.as_str()) {
        bail!("invalid direction: {dir}. Should be one of both/up/down/none");
    }
    if print_missing && dir != "none" {
        bail!("--print-missing requires --dir=none");
    }
    let dir = if print_missing {
        "none".to_string()
    } else {
        dir
    };
    let do_up = dir == "both" || dir == "up";
    let do_down = dir == "both" || dir == "down";

    let mut filter_json: serde_json::Value =
        wok_event::json::parse_strict(filter.as_deref().unwrap_or("{}"))?;
    if let Some(range) = &range {
        process_range_option(range, &mut filter_json)?;
    }
    let filter_group = wok_query::NostrFilterGroup::from_value(
        &filter_json,
        u64::MAX,
        cfg.relay.max_tags_per_filter,
    )?;

    let env = open_env(cfg)?;

    // Prefer a precomputed tree whose canonical (time-stripped) filter
    // matches, like C++.
    enum SyncStorage {
        Tree(u64),
        Vector(wok_negentropy::Vector),
    }
    let storage = {
        let mut canonical = filter_json.clone();
        if let Some(obj) = canonical.as_object_mut() {
            obj.remove("since");
            obj.remove("until");
        }
        let canonical = wok_event::json::to_tao_string(&canonical);
        let txn = env.begin_ro()?;
        let mut tree_id = None;
        wok_db::foreach_negentropy_filter(&txn, |id, f| {
            if f == canonical {
                tree_id = Some(id);
                false
            } else {
                true
            }
        })?;
        match tree_id {
            Some(id) => SyncStorage::Tree(id),
            None => {
                let mut levs = Vec::new();
                foreach_by_filter_scan(
                    &txn,
                    &filter_json,
                    u64::MAX,
                    cfg.relay.max_tags_per_filter,
                    |lev| levs.push(lev),
                )?;
                levs.sort_unstable();
                let mut v = wok_negentropy::Vector::new();
                for lev in levs {
                    if let Some(buf) = wok_db::get_packed_ro(&txn, lev)? {
                        let p = PackedEventView::new(&buf)
                            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                        v.insert(p.created_at(), p.id())
                            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                    }
                }
                v.seal().map_err(|e| anyhow::anyhow!(e.to_string()))?;
                tracing::info!("Filter matches {} events", v.size_checked().unwrap_or(0));
                SyncStorage::Vector(v)
            }
        }
    };

    let initiate = |env: &Env| -> Result<Vec<u8>> {
        let txn = env.begin_ro()?;
        match &storage {
            SyncStorage::Tree(tid) => {
                let mut tree = wok_negentropy::open_ro(&txn, *tid)
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                let f = filter_group.filters.first();
                let since = f.map(|f| f.since).unwrap_or(0);
                let until = f.map(|f| f.until).unwrap_or(u64::MAX);
                let lower = wok_negentropy::Bound::timestamp(since);
                let upper = wok_negentropy::Bound::timestamp(if until == u64::MAX {
                    u64::MAX
                } else {
                    until.saturating_add(1)
                });
                let sub = wok_negentropy::SubRange::new(&mut tree, &lower, &upper);
                let mut ne = wok_negentropy::Negentropy::new(sub, frame_size_limit)
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                ne.initiate().map_err(|e| anyhow::anyhow!(e.to_string()))
            }
            SyncStorage::Vector(v) => {
                let mut ne = wok_negentropy::Negentropy::new(v.clone(), frame_size_limit)
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                ne.initiate().map_err(|e| anyhow::anyhow!(e.to_string()))
            }
        }
    };
    let reconcile = |env: &Env,
                     payload: &[u8],
                     have: &mut Vec<Vec<u8>>,
                     need: &mut Vec<Vec<u8>>|
     -> Result<Option<Vec<u8>>> {
        let txn = env.begin_ro()?;
        match &storage {
            SyncStorage::Tree(tid) => {
                let mut tree = wok_negentropy::open_ro(&txn, *tid)
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                let f = filter_group.filters.first();
                let since = f.map(|f| f.since).unwrap_or(0);
                let until = f.map(|f| f.until).unwrap_or(u64::MAX);
                let lower = wok_negentropy::Bound::timestamp(since);
                let upper = wok_negentropy::Bound::timestamp(if until == u64::MAX {
                    u64::MAX
                } else {
                    until.saturating_add(1)
                });
                let sub = wok_negentropy::SubRange::new(&mut tree, &lower, &upper);
                let mut ne = wok_negentropy::Negentropy::new(sub, frame_size_limit)
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                ne.set_initiator();
                ne.reconcile_with_ids(payload, have, need)
                    .map_err(|e| anyhow::anyhow!(e.to_string()))
            }
            SyncStorage::Vector(v) => {
                let mut ne = wok_negentropy::Negentropy::new(v.clone(), frame_size_limit)
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                ne.set_initiator();
                ne.reconcile_with_ids(payload, have, need)
                    .map_err(|e| anyhow::anyhow!(e.to_string()))
            }
        }
    };

    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await?;
    let init = initiate(&env)?;
    let open = serde_json::json!(["NEG-OPEN", "N", filter_json, hex::encode(init)]);
    ws.send(Message::Text(open.to_string().into())).await?;

    const HIGH_WATER_UP: usize = 100;
    const LOW_WATER_UP: usize = 50;
    const BATCH_DOWN: usize = 50;

    let mut have: std::collections::VecDeque<Vec<u8>> = Default::default();
    let mut need: std::collections::VecDeque<Vec<u8>> = Default::default();
    let mut seen_have: std::collections::HashSet<Vec<u8>> = Default::default();
    let mut seen_need: std::collections::HashSet<Vec<u8>> = Default::default();
    let mut sync_done = false;
    let mut received_neg_msg = false;
    let mut in_flight_up = 0usize;
    let mut in_flight_down = false;
    // Assigned on every NEG-MSG before any read.
    let mut total_haves: usize;
    let mut total_needs: usize;
    let mut batch: Vec<serde_json::Value> = Vec::new();
    let mut written = 0u64;
    let mut last_activity = std::time::Instant::now();

    loop {
        if timeout > 0 && last_activity.elapsed().as_secs() >= timeout {
            write_downloaded(&env, cfg, &mut batch, &mut written)?;
            bail!("Sync timed out: no activity for {timeout} seconds");
        }
        let msg = match tokio::time::timeout(std::time::Duration::from_secs(1), ws.next()).await {
            Ok(Some(m)) => m?,
            Ok(None) => bail!("connection closed"),
            Err(_) => {
                // 1s idle tick: flush pending writes / pump queues.
                write_downloaded(&env, cfg, &mut batch, &mut written)?;
                if sync_done
                    && have.is_empty()
                    && need.is_empty()
                    && in_flight_up == 0
                    && !in_flight_down
                {
                    break;
                }
                continue;
            }
        };
        last_activity = std::time::Instant::now();
        let txt = match msg {
            Message::Text(t) => t.to_string(),
            Message::Binary(b) => String::from_utf8_lossy(&b).into_owned(),
            Message::Close(_) => bail!("connection closed"),
            _ => continue,
        };
        let v: serde_json::Value = match serde_json::from_str(&txt) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let cmd = v[0].as_str().unwrap_or("");
        match cmd {
            "NEG-MSG" => {
                received_neg_msg = true;
                let payload = wok_event::from_hex_strict(v[2].as_str().unwrap_or(""))?;
                let mut curr_have = Vec::new();
                let mut curr_need = Vec::new();
                let next = match reconcile(&env, &payload, &mut curr_have, &mut curr_need) {
                    Ok(n) => n,
                    Err(e) => {
                        write_downloaded(&env, cfg, &mut batch, &mut written)?;
                        return Err(e.context("Unable to parse negentropy message from relay"));
                    }
                };
                for id in curr_have {
                    if seen_have.insert(id.clone()) {
                        have.push_back(id);
                    }
                }
                for id in curr_need {
                    if seen_need.insert(id.clone()) {
                        need.push_back(id);
                    }
                }
                total_haves = seen_have.len();
                total_needs = seen_need.len();
                if !do_up {
                    have.clear();
                }
                if !do_down {
                    need.clear();
                }
                match next {
                    Some(next) => {
                        let m = serde_json::json!(["NEG-MSG", "N", hex::encode(next)]);
                        ws.send(Message::Text(m.to_string().into())).await?;
                    }
                    None => {
                        sync_done = true;
                        tracing::info!(
                            "Set reconcile complete. Have {total_haves} need {total_needs}"
                        );
                        ws.send(Message::Text(r#"["NEG-CLOSE","N"]"#.into()))
                            .await?;
                    }
                }
            }
            "OK" => {
                in_flight_up = in_flight_up.saturating_sub(1);
                if v[2].as_bool() == Some(false) {
                    tracing::warn!("Unable to upload event {}: {}", v[1], v[3]);
                }
            }
            "EVENT" => {
                if let Some(ev) = v.get(2) {
                    batch.push(ev.clone());
                    if batch.len() >= 1000 {
                        write_downloaded(&env, cfg, &mut batch, &mut written)?;
                    }
                }
            }
            "EOSE" => {
                in_flight_down = false;
                write_downloaded(&env, cfg, &mut batch, &mut written)?;
            }
            "NEG-ERR" => {
                write_downloaded(&env, cfg, &mut batch, &mut written)?;
                bail!("Got NEG-ERR response from relay: {v}");
            }
            "NOTICE" => {
                let notice = v[1].as_str().unwrap_or("");
                tracing::warn!("NOTICE from relay: {notice}");
                if !received_neg_msg {
                    let lower = notice.to_ascii_lowercase();
                    for kw in [
                        "error",
                        "invalid",
                        "unrecognized",
                        "bad msg",
                        "bad message",
                        "could not parse",
                        "disabled",
                        "unsupported",
                        "unknown",
                    ] {
                        if lower.contains(kw) {
                            write_downloaded(&env, cfg, &mut batch, &mut written)?;
                            bail!("Received error NOTICE before any negentropy response, relay likely does not support negentropy syncing");
                        }
                    }
                }
            }
            _ => tracing::warn!("Unexpected message from relay: {txt:.512}"),
        }

        // Pump uploads (haves) with the C++ water marks.
        if do_up && !have.is_empty() && in_flight_up <= LOW_WATER_UP {
            let mut num_sent = 0usize;
            let txn = env.begin_ro()?;
            let mut decomp = Decompressor::new();
            let mut to_send = Vec::new();
            while let Some(id) = have.back().cloned() {
                if in_flight_up + to_send.len() >= HIGH_WATER_UP {
                    break;
                }
                have.pop_back();
                match wok_db::lookup_event_by_id_ro(&txn, &id)? {
                    Some((lev, _)) => {
                        let json =
                            event_json_owned(&txn, &mut decomp, lev, cfg.events.max_event_size)?;
                        to_send.push(format!("[\"EVENT\",{json}]"));
                    }
                    None => {
                        tracing::warn!("Couldn't upload event because not found (deleted?)");
                    }
                }
                num_sent += 1;
            }
            drop(txn);
            for m in to_send {
                ws.send(Message::Text(m.into())).await?;
                in_flight_up += 1;
            }
            if num_sent > 0 {
                tracing::info!("UP: {num_sent} events ({} remaining)", have.len());
            }
        }

        // Pump downloads (needs) one REQ batch at a time.
        if do_down && !need.is_empty() && !in_flight_down {
            let mut ids = Vec::new();
            while let Some(id) = need.back().cloned() {
                if ids.len() >= BATCH_DOWN {
                    break;
                }
                need.pop_back();
                ids.push(hex::encode(id));
            }
            tracing::info!("DOWN: {} events ({} remaining)", ids.len(), need.len());
            let req = serde_json::json!(["REQ", "R", { "ids": ids }]);
            ws.send(Message::Text(req.to_string().into())).await?;
            in_flight_down = true;
        }

        if sync_done && have.is_empty() && need.is_empty() && in_flight_up == 0 && !in_flight_down {
            write_downloaded(&env, cfg, &mut batch, &mut written)?;
            if print_missing {
                for id in &seen_have {
                    println!("have,{}", hex::encode(id));
                }
                for id in &seen_need {
                    println!("need,{}", hex::encode(id));
                }
            }
            break;
        }
    }
    tracing::info!("Sync done; {written} events written");
    Ok(())
}

async fn cmd_stream(cfg: &Config, url: String, dir: String) -> Result<()> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    if !["up", "down", "both"].contains(&dir.as_str()) {
        bail!("invalid direction: {dir}. Should be one of up/down/both");
    }
    tracing::warn!("'wok stream' is deprecated. Please use 'wok router' instead.");

    let env = open_env(cfg)?;
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await?;
    if dir == "down" || dir == "both" {
        ws.send(Message::Text(r#"["REQ","sub",{"limit":0}]"#.into()))
            .await?;
    }

    let mut downloaded: std::collections::HashSet<Vec<u8>> = Default::default();
    let mut curr_event_id = {
        let txn = env.begin_ro()?;
        most_recent_levid_ro_quiet(&txn)
    };
    let mut batch: Vec<serde_json::Value> = Vec::new();
    let mut written = 0u64;

    loop {
        tokio::select! {
            msg = ws.next() => {
                let Some(msg) = msg else { break };
                let msg = msg?;
                let txt = match msg {
                    Message::Text(t) => t.to_string(),
                    Message::Binary(b) => String::from_utf8_lossy(&b).into_owned(),
                    _ => continue,
                };
                let v: serde_json::Value = match serde_json::from_str(&txt) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                match v[0].as_str().unwrap_or("") {
                    "EOSE" => {
                        write_downloaded(&env, cfg, &mut batch, &mut written)?;
                    }
                    "NOTICE" => tracing::warn!("NOTICE message: {v}"),
                    "OK" => {
                        if v[2].as_bool() == Some(false) {
                            tracing::warn!("Event not written: {v}");
                        }
                    }
                    "EVENT" => {
                        if dir == "down" || dir == "both" {
                            if let Some(ev) = v.get(2) {
                                if let Some(id) = ev.get("id").and_then(|i| i.as_str()) {
                                    if let Ok(raw) = wok_event::from_lower_hex_exact(id) {
                                        downloaded.insert(raw);
                                    }
                                }
                                batch.push(ev.clone());
                                if batch.len() >= 1000 {
                                    write_downloaded(&env, cfg, &mut batch, &mut written)?;
                                }
                            }
                        } else {
                            tracing::warn!("Unexpected EVENT");
                        }
                    }
                    other => bail!("unexpected first element: {other}"),
                }
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {
                // WriterPipeline debounce: flush partial batches periodically.
                write_downloaded(&env, cfg, &mut batch, &mut written)?;
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)), if dir != "down" => {
                // Up direction: stream new local events to the remote, like
                // C++'s file-change-triggered foreach_Event from currEventId+1.
                let mut to_send = Vec::new();
                {
                    let txn = env.begin_ro()?;
                    let mut decomp = Decompressor::new();
                    let mut latest = curr_event_id;
                    let res = wok_db::foreach_event_from(&txn, curr_event_id.saturating_add(1), |lev, packed_bytes| {
                        latest = lev;
                        if let Ok(p) = PackedEventView::new(packed_bytes) {
                            let id = p.id().to_vec();
                            if downloaded.remove(&id) {
                                return true;
                            }
                            if let Ok(json) = event_json_owned(&txn, &mut decomp, lev, cfg.events.max_event_size) {
                                to_send.push(format!("[\"EVENT\",{json}]"));
                            }
                        }
                        true
                    });
                    if let Err(e) = res {
                        tracing::error!("stream up scan: {e}");
                    }
                    curr_event_id = latest;
                }
                for m in to_send {
                    ws.send(Message::Text(m.into())).await?;
                }
            }
        }
    }
    write_downloaded(&env, cfg, &mut batch, &mut written)?;
    tracing::info!("stream ended; {written} events written");
    Ok(())
}

fn most_recent_levid_ro_quiet(txn: &wok_db::RoTxn<'_>) -> u64 {
    wok_db::most_recent_levid_ro(txn).unwrap_or(0)
}

async fn cmd_upload(url: String, pipeline: u64) -> Result<()> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await?;
    let stdin = std::io::stdin();
    let mut inflight = 0u64;
    let mut lines = stdin.lock().lines();
    loop {
        while inflight < pipeline {
            match lines.next() {
                Some(Ok(line)) => {
                    let msg = format!("[\"EVENT\",{line}]");
                    ws.send(Message::Text(msg.into())).await?;
                    inflight += 1;
                }
                _ => break,
            }
        }
        if inflight == 0 {
            break;
        }
        if let Some(Ok(msg)) = ws.next().await {
            if msg.to_text()?.contains("\"OK\"") {
                inflight = inflight.saturating_sub(1);
            }
        } else {
            break;
        }
    }
    Ok(())
}

async fn cmd_download(url: String, filter: Option<String>) -> Result<()> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await?;
    let filter = filter.unwrap_or_else(|| "{}".into());
    let req = format!(r#"["REQ","_",{filter}]"#);
    ws.send(Message::Text(req.into())).await?;
    while let Some(msg) = ws.next().await {
        let txt = msg?.to_text()?.to_string();
        let v: serde_json::Value = serde_json::from_str(&txt)?;
        if v[0] == "EOSE" {
            break;
        }
        if v[0] == "EVENT" {
            println!("{}", v[2]);
        }
    }
    Ok(())
}
