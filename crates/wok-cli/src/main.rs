#![deny(unsafe_code, unsafe_op_in_unsafe_fn)]

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::io::BufRead;
use std::io::Read as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use wok_db::{
    check_integrity, delete_events, event_json_owned, write_events_with_policy, Decompressor, Env,
    EnvOptions, EventToWrite, NoopNegentropy,
};
use wok_event::{parse_and_verify_event, EventLimits, PackedEventView};
use wok_negentropy::Storage;
mod doctor;
mod mesh;
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

/// Read one line from `reader` into `buf` (newline stripped, like
/// `BufRead::lines`), buffering at most `max_len + 1` bytes so a newline-free
/// multi-GB line can't OOM the process before the caller's size check runs.
/// An oversize line comes back `max_len + 1` bytes long (possibly without a
/// newline); the caller must reject it. Returns Ok(false) on EOF.
fn read_line_bounded(
    reader: &mut impl BufRead,
    buf: &mut String,
    max_len: usize,
) -> std::io::Result<bool> {
    buf.clear();
    let n = reader.by_ref().take(max_len as u64 + 1).read_line(buf)?;
    if n == 0 {
        return Ok(false);
    }
    if buf.ends_with('\n') {
        buf.pop();
        if buf.ends_with('\r') {
            buf.pop();
        }
    }
    Ok(true)
}

/// Hard ceiling for a single stdin line in `wok upload`, which has no relay
/// config in scope. Matches the 16 MiB decompression hard cap in wok-db.
const MAX_UPLOAD_LINE_BYTES: usize = 16 * 1024 * 1024;

/// `cli_println!` panics when the stdout write fails, so `wok export | head -1`
/// (or any downstream consumer closing the pipe) aborts the process with
/// SIGABRT under panic=abort. These macros treat a broken pipe as a clean
/// early exit, matching standard CLI behavior.
macro_rules! cli_println {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        if writeln!(lock, $($arg)*).is_err() {
            std::process::exit(0);
        }
    }};
}

macro_rules! cli_print {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        if write!(lock, $($arg)*).and_then(|_| lock.flush()).is_err() {
            std::process::exit(0);
        }
    }};
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
        /// Initial non-blocking reconnect delay in seconds
        #[arg(long, default_value_t = 1)]
        reconnect_delay: u64,
        /// Maximum exponential reconnect delay in seconds
        #[arg(long, default_value_t = 30)]
        max_reconnect_delay: u64,
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
    Add {
        filter: String,
    },
    Build {
        tree_id: u64,
        /// Number of primary event records scanned per read/write cycle
        #[arg(long, default_value_t = 10_000)]
        batch_size: usize,
    },
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
    let Cli { config, cmd } = Cli::parse();
    let startup_cfg = if config.exists() {
        Config::load(&config).ok()
    } else {
        None
    };
    init_tracing(startup_cfg.as_ref())?;
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
        Command::Stream {
            url,
            dir,
            reconnect_delay,
            max_reconnect_delay,
        } => cmd_stream(&cfg, url, dir, reconnect_delay, max_reconnect_delay).await,
        Command::Upload { url, pipeline } => cmd_upload(url, pipeline).await,
        Command::Download { url, filter } => cmd_download(url, filter).await,
        Command::Router { router_config_file } => router::run_router(cfg, router_config_file).await,
    }
}

fn init_tracing(config: Option<&Config>) -> Result<()> {
    use tracing_subscriber::EnvFilter;

    let configured_filter = config
        .map(|cfg| cfg.observability.log_filter.as_str())
        .filter(|filter| !filter.trim().is_empty())
        .unwrap_or("wok=info");
    let filter = match std::env::var(EnvFilter::DEFAULT_ENV) {
        Ok(value) => EnvFilter::try_new(value)?,
        Err(std::env::VarError::NotPresent) => EnvFilter::try_new(configured_filter)?,
        Err(error) => return Err(error.into()),
    };
    let format = config
        .map(|cfg| cfg.observability.log_format)
        .unwrap_or(wok_relay::config::LogFormat::Pretty);
    match format {
        wok_relay::config::LogFormat::Pretty => {
            tracing_subscriber::fmt().with_env_filter(filter).init();
        }
        wok_relay::config::LogFormat::Json => {
            tracing_subscriber::fmt()
                .json()
                .flatten_event(true)
                .with_current_span(true)
                .with_span_list(true)
                .with_env_filter(filter)
                .init();
        }
    }
    Ok(())
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
    if let Some(warning) = cfg.auth_configuration_warning() {
        tracing::warn!("{warning}; restricted reads fail closed");
    }
    wok_relay::apply_nofiles_limit(cfg.relay.nofiles).map_err(anyhow::Error::msg)?;
    let env = open_env(&cfg)?;
    let bind: SocketAddr = format!("{}:{}", cfg.relay.bind, cfg.relay.port).parse()?;
    let unix_cfg = cfg.clone();
    let handle = wok_relay::start(env, cfg).map_err(|e| anyhow::anyhow!(e))?;
    if config_path.exists() {
        handle.set_config_path(config_path.clone());
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
    cli_println!("DB version: {}", env.db_version()?);
    Ok(())
}

fn cmd_doctor(cfg: &Config, config_path: &Path, json: bool) -> Result<()> {
    let report = doctor::run(cfg, config_path);
    if json {
        cli_println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        cli_print!("{}", report.render_human());
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
        cli_println!("{}", serde_json::to_string_pretty(&outcome)?);
    } else {
        cli_println!("Reindexed {} events.", outcome.events);
        cli_println!("Database: {}", outcome.database.display());
        cli_println!("Original backup: {}", outcome.backup.display());
        cli_println!("Fingerprint: {}", outcome.event_fingerprint_sha256);
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
    let mut stdin = stdin.lock();
    let mut line = String::new();
    let mut i = 0u64;
    while read_line_bounded(&mut stdin, &mut line, cfg.events.max_event_size)? {
        i += 1;
        total_processed += 1;
        // C++ counts the newline in its getline length check, so a line of
        // exactly maxEventSize chars is rejected there.
        if line.len() + 1 > cfg.events.max_event_size {
            bail!("Line larger than configured maxEventSize on line {i}");
        }
        match parse_import_line(&line, fried, no_verify, &limits) {
            Ok(ev) => batch.push(ev),
            Err(e) => {
                tracing::warn!("Unable to parse JSON on line {i}: {e}");
                continue;
            }
        }
        if batch.len() >= batch_size {
            commit_import(
                cfg,
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
            cfg,
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
    cfg: &Config,
    env: &Env,
    batch: &mut Vec<EventToWrite>,
    written: &mut u64,
    rejected: &mut u64,
    dups: &mut u64,
    show_rejected: bool,
) -> Result<()> {
    let mut txn = env.begin_rw()?;
    let mut sink = NoopNegentropy;
    write_events_with_policy(&mut txn, &mut sink, batch, false, &cfg.vanish_policy())?;
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
                            cli_println!("{o}");
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
                    cli_println!("{json}");
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
                    cli_println!("{json}");
                }
            }
        },
    )?;
    if count {
        cli_println!("{n}");
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
        cli_println!("{o}");
    } else {
        cli_println!("{json}");
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
    let mut stdin = stdin.lock();
    let mut line = String::new();
    while read_line_bounded(&mut stdin, &mut line, cfg.events.max_event_size)? {
        if line.len() + 1 > cfg.events.max_event_size {
            bail!("monitor: stdin line larger than configured maxEventSize");
        }
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
                        cli_println!("{json}");
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
            cli_println!(
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
            cli_println!("Saved new dictionary, dictId = {new_id}");
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
                cli_println!("tree {id}");
                cli_println!("  filter: {filter}");
                if let Ok(mut tree) = wok_negentropy::open_ro(&txn, id) {
                    let size = tree.size();
                    let fp = tree.fingerprint(0, size as usize);
                    cli_println!("  size: {size}");
                    cli_println!("  fingerprint: {}", hex::encode(fp));
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
            if compiled.requires_content() {
                bail!("negentropy filters do not support content search");
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
            cli_println!("created tree {id}");
            cli_println!("  to populate, run: wok negentropy build {id}");
        }
        NegCmd::Build {
            tree_id,
            batch_size,
        } => build_negentropy_tree(&env, tree_id, batch_size)?,
    }
    Ok(())
}

/// Populate a tree through bounded primary-table scans and short write
/// transactions. Inserts are idempotent, so rerunning this after interruption
/// safely resumes the outcome without requiring a separate progress file.
fn build_negentropy_tree(env: &Env, tree_id: u64, batch_size: usize) -> Result<()> {
    if batch_size == 0 {
        bail!("--batch-size must be at least 1");
    }
    let (compiled, target_lev) = {
        let txn = env.begin_ro()?;
        let mut filter_str = None;
        wok_db::foreach_negentropy_filter(&txn, |id, filter| {
            if id == tree_id {
                filter_str = Some(filter.to_string());
                false
            } else {
                true
            }
        })?;
        let filter: serde_json::Value =
            serde_json::from_str(&filter_str.context("couldn't find treeId")?)?;
        let compiled = wok_query::NostrFilterGroup::from_value(&filter, u64::MAX, 64)?;
        if compiled.requires_content() {
            bail!("negentropy filters do not support content search");
        }
        (compiled, most_recent_levid_ro_quiet(&txn))
    };

    let mut next_lev = 1u64;
    let mut scanned = 0u64;
    let mut inserted = 0u64;
    let mut first_batch = true;
    while first_batch || next_lev <= target_lev {
        let NegentropyScanBatch {
            last_scanned,
            rows,
            records,
        } = scan_negentropy_batch(env, &compiled, next_lev, target_lev, batch_size)?;
        let Some(last_scanned) = last_scanned else {
            if first_batch {
                let mut txn = env.begin_rw()?;
                wok_db::bump_negentropy_mod_counter(&mut txn)?;
                let mut tree = wok_negentropy::open_rw(&mut txn, tree_id)?;
                tree.backend.flush()?;
                drop(tree);
                txn.commit()?;
            }
            break;
        };
        let record_count = records.len() as u64;
        let mut txn = env.begin_rw()?;
        if first_batch {
            wok_db::bump_negentropy_mod_counter(&mut txn)?;
        }
        {
            let mut tree = wok_negentropy::open_rw(&mut txn, tree_id)?;
            for (created_at, id) in records {
                if tree.insert(created_at, &id)? {
                    inserted += 1;
                }
            }
            tree.backend.flush()?;
        }
        txn.commit()?;
        scanned += rows as u64;
        tracing::info!(
            tree_id,
            scanned,
            target_lev,
            matched = record_count,
            inserted,
            "negentropy build checkpoint"
        );
        next_lev = last_scanned.saturating_add(1);
        first_batch = false;
    }
    tracing::info!(tree_id, scanned, inserted, "negentropy build complete");
    Ok(())
}

struct NegentropyScanBatch {
    last_scanned: Option<u64>,
    rows: usize,
    records: Vec<(u64, Vec<u8>)>,
}

fn scan_negentropy_batch(
    env: &Env,
    compiled: &wok_query::NostrFilterGroup,
    start_lev: u64,
    target_lev: u64,
    batch_size: usize,
) -> Result<NegentropyScanBatch> {
    let txn = env.begin_ro()?;
    let mut rows = 0usize;
    let mut last = None;
    let mut records = Vec::new();
    wok_db::foreach_event_from(&txn, start_lev, |lev, packed_bytes| {
        if lev > target_lev || rows >= batch_size {
            return false;
        }
        rows += 1;
        last = Some(lev);
        if let Ok(packed) = PackedEventView::new(packed_bytes) {
            if compiled.does_match(packed) {
                records.push((packed.created_at(), packed.id().to_vec()));
            }
        }
        true
    })?;
    Ok(NegentropyScanBatch {
        last_scanned: last,
        rows,
        records,
    })
}

fn cmd_integrity(cfg: &Config) -> Result<()> {
    let env = open_env(cfg)?;
    let txn = env.begin_ro()?;
    let report = check_integrity(&txn)?;
    cli_println!("{report:?}");
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
    // Split on the last char boundary: byte-indexing s.len()-1 panics when
    // the unit is a multi-byte char.
    let Some((unit_idx, unit)) = s.char_indices().next_back() else {
        bail!("invalid time");
    };
    let num = &s[..unit_idx];
    let scale = match unit {
        's' => 1.0,
        'm' => 60.0,
        'h' => 60.0 * 60.0,
        'd' => 86400.0,
        'w' => 86400.0 * 7.0,
        'M' => 86400.0 * 30.5,
        'Y' => 86400.0 * 365.2425,
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
    let mut evs = Vec::with_capacity(batch.len());
    for v in batch.drain(..) {
        let policy = cfg.timestamp_policy_for_kind(
            v.get("kind")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(u64::MAX),
        );
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
    write_events_with_policy(&mut txn, &mut sink, &mut evs, false, &cfg.vanish_policy())?;
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

    let mut ws = mesh::connect_mesh(&url, cfg.events.max_event_size).await?;
    let init = initiate(&env)?;
    let open = serde_json::json!(["NEG-OPEN", "N", filter_json, hex::encode(init)]);
    ws.send(Message::Text(open.to_string().into())).await?;

    const HIGH_WATER_UP: usize = 100;
    const LOW_WATER_UP: usize = 50;
    const BATCH_DOWN: usize = 50;
    /// A malicious or buggy peer can keep supplying fresh 32-byte IDs forever,
    /// growing RAM ~3x network speed; cap the tracked have/need ID sets.
    const MAX_SYNC_IDS: usize = 5_000_000;

    let mut have: std::collections::VecDeque<Vec<u8>> = Default::default();
    let mut need: std::collections::VecDeque<Vec<u8>> = Default::default();
    let mut seen_have: std::collections::HashSet<Vec<u8>> = Default::default();
    let mut seen_need: std::collections::HashSet<Vec<u8>> = Default::default();
    // Only track IDs for directions we actually act on (print-missing needs both).
    let track_have = do_up || print_missing;
    let track_need = do_down || print_missing;
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
                    if track_have && seen_have.insert(id.clone()) {
                        have.push_back(id);
                    }
                }
                for id in curr_need {
                    if track_need && seen_need.insert(id.clone()) {
                        need.push_back(id);
                    }
                }
                if seen_have.len() + seen_need.len() > MAX_SYNC_IDS {
                    write_downloaded(&env, cfg, &mut batch, &mut written)?;
                    bail!("Sync aborted: peer supplied more than {MAX_SYNC_IDS} unique ids");
                }
                total_haves = seen_have.len();
                total_needs = seen_need.len();
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
                tracing::warn!(message = ?notice, "NOTICE from relay");
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
            _ => {
                let preview: String = txt.chars().take(512).collect();
                tracing::warn!(message = ?preview, "unexpected message from relay");
            }
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

        // Once a direction is fully done, drop its dedup state so a long
        // remaining transfer in the other direction doesn't keep it resident.
        if !print_missing && sync_done && have.is_empty() && in_flight_up == 0 {
            seen_have = Default::default();
        }
        if !print_missing && sync_done && need.is_empty() && !in_flight_down {
            seen_need = Default::default();
        }

        if sync_done && have.is_empty() && need.is_empty() && in_flight_up == 0 && !in_flight_down {
            write_downloaded(&env, cfg, &mut batch, &mut written)?;
            if print_missing {
                for id in &seen_have {
                    cli_println!("have,{}", hex::encode(id));
                }
                for id in &seen_need {
                    cli_println!("need,{}", hex::encode(id));
                }
            }
            break;
        }
    }
    tracing::info!("Sync done; {written} events written");
    Ok(())
}

async fn cmd_stream(
    cfg: &Config,
    url: String,
    dir: String,
    reconnect_delay: u64,
    max_reconnect_delay: u64,
) -> Result<()> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    if !["up", "down", "both"].contains(&dir.as_str()) {
        bail!("invalid direction: {dir}. Should be one of up/down/both");
    }
    if reconnect_delay == 0 || max_reconnect_delay < reconnect_delay {
        bail!("reconnect delays require 1 <= reconnect-delay <= max-reconnect-delay");
    }
    tracing::warn!("'wok stream' is deprecated. Please use 'wok router' instead.");

    let env = open_env(cfg)?;
    // Dedup set of remote event IDs we've already downloaded; capped so a
    // peer feeding invented IDs can't grow RAM without bound. At the cap the
    // dedup degrades to possible duplicate uploads (harmless).
    const MAX_DOWNLOADED_IDS: usize = 1_000_000;
    /// Flush the write batch at this many queued bytes even below the
    /// per-flush event count.
    const MAX_BATCH_BYTES: usize = 8 * 1024 * 1024;
    let mut downloaded: std::collections::HashSet<Vec<u8>> = Default::default();
    let mut curr_event_id = {
        let txn = env.begin_ro()?;
        most_recent_levid_ro_quiet(&txn)
    };
    let mut batch: Vec<serde_json::Value> = Vec::new();
    let mut batch_bytes = 0usize;
    let mut written = 0u64;
    let initial_delay = std::time::Duration::from_secs(reconnect_delay);
    let maximum_delay = std::time::Duration::from_secs(max_reconnect_delay);
    let mut delay = initial_delay;

    loop {
        tracing::info!(url = %url, "stream connecting");
        match mesh::connect_mesh(&url, cfg.events.max_event_size).await {
            Ok(mut ws) => {
                tracing::info!(url = %url, "stream connected");
                delay = initial_delay;
                let subscription = if dir == "down" || dir == "both" {
                    Some(
                        ws.send(Message::Text(r#"["REQ","sub",{"limit":0}]"#.into()))
                            .await,
                    )
                } else {
                    None
                };
                let disconnect = if let Some(Err(error)) = subscription {
                    error.to_string()
                } else {
                    let mut flush_tick = tokio::time::interval(std::time::Duration::from_secs(1));
                    let mut upload_tick =
                        tokio::time::interval(std::time::Duration::from_millis(100));
                    'connected: loop {
                        tokio::select! {
                            msg = ws.next() => {
                                let Some(msg) = msg else {
                                    break "remote closed the websocket".to_string();
                                };
                                let msg = match msg {
                                    Ok(message) => message,
                                    Err(error) => break error.to_string(),
                                };
                                let txt = match msg {
                                    Message::Text(t) => t.to_string(),
                                    Message::Binary(b) => String::from_utf8_lossy(&b).into_owned(),
                                    Message::Ping(payload) => {
                                        if let Err(error) = ws.send(Message::Pong(payload)).await {
                                            break error.to_string();
                                        }
                                        continue;
                                    }
                                    Message::Close(frame) => break format!("remote close: {frame:?}"),
                                    _ => continue,
                                };
                                let v: serde_json::Value = match serde_json::from_str(&txt) {
                                    Ok(v) => v,
                                    Err(error) => {
                                        tracing::warn!(url = %url, %error, "stream ignored invalid JSON");
                                        continue;
                                    }
                                };
                                match v[0].as_str().unwrap_or("") {
                                    "EOSE" => write_downloaded(&env, cfg, &mut batch, &mut written)?,
                                    "NOTICE" => tracing::warn!(url = %url, "NOTICE message: {v}"),
                                    "OK" if v[2].as_bool() == Some(false) => {
                                        tracing::warn!(url = %url, "event not written: {v}");
                                    }
                                    "EVENT" if dir == "down" || dir == "both" => {
                                        // Drop frames that could never hold a valid
                                        // event before queueing them unverified.
                                        if txt.len() > cfg.events.max_event_size + 64 {
                                            tracing::warn!(url = %url, "stream dropped oversize frame");
                                            continue;
                                        }
                                        if let Some(ev) = v.get(2) {
                                            if dir == "both" {
                                                if let Some(id) = ev.get("id").and_then(|id| id.as_str()) {
                                                    // Event IDs are 32 bytes hex; longer
                                                    // "ids" are attacker-controlled padding.
                                                    if id.len() == 64 && downloaded.len() < MAX_DOWNLOADED_IDS {
                                                        if let Ok(raw) = wok_event::from_lower_hex_exact(id) {
                                                            downloaded.insert(raw);
                                                        }
                                                    }
                                                }
                                            }
                                            batch_bytes += txt.len();
                                            batch.push(ev.clone());
                                            if batch.len() >= 1000 || batch_bytes >= MAX_BATCH_BYTES {
                                                write_downloaded(&env, cfg, &mut batch, &mut written)?;
                                                batch_bytes = 0;
                                            }
                                        }
                                    }
                                    other => tracing::warn!(url = %url, command = other, "stream ignored unexpected relay message"),
                                }
                            }
                            _ = flush_tick.tick() => {
                                write_downloaded(&env, cfg, &mut batch, &mut written)?;
                                batch_bytes = 0;
                            }
                            _ = upload_tick.tick(), if dir != "down" => {
                                let mut outbound = Vec::new();
                                {
                                    let txn = env.begin_ro()?;
                                    let mut decomp = Decompressor::new();
                                    let mut rows = 0usize;
                                    wok_db::foreach_event_from(&txn, curr_event_id.saturating_add(1), |lev, packed_bytes| {
                                        if rows >= 1_000 {
                                            return false;
                                        }
                                        rows += 1;
                                        let message = if let Ok(p) = PackedEventView::new(packed_bytes) {
                                            if downloaded.remove(p.id()) {
                                                None
                                            } else {
                                                event_json_owned(&txn, &mut decomp, lev, cfg.events.max_event_size)
                                                    .ok()
                                                    .map(|json| format!("[\"EVENT\",{json}]"))
                                            }
                                        } else {
                                            None
                                        };
                                        outbound.push((lev, message));
                                        true
                                    })?;
                                }
                                for (lev, message) in outbound {
                                    if let Some(message) = message {
                                        if let Err(error) = ws.send(Message::Text(message.into())).await {
                                            break 'connected error.to_string();
                                        }
                                    }
                                    // Advance only after the corresponding send succeeds,
                                    // so a reconnect retries the first unsent local event.
                                    curr_event_id = lev;
                                }
                            }
                        }
                    }
                };
                write_downloaded(&env, cfg, &mut batch, &mut written)?;
                tracing::warn!(url = %url, reason = %disconnect, written, "stream disconnected");
            }
            Err(error) => {
                tracing::warn!(url = %url, %error, "stream connection failed");
            }
        }
        tracing::info!(url = %url, delay_secs = delay.as_secs(), "stream reconnect scheduled");
        tokio::time::sleep(delay).await;
        delay = next_reconnect_delay(delay, maximum_delay);
    }
}

fn next_reconnect_delay(
    current: std::time::Duration,
    maximum: std::time::Duration,
) -> std::time::Duration {
    current.saturating_mul(2).min(maximum)
}

fn most_recent_levid_ro_quiet(txn: &wok_db::RoTxn<'_>) -> u64 {
    wok_db::most_recent_levid_ro(txn).unwrap_or(0)
}

async fn cmd_upload(url: String, pipeline: u64) -> Result<()> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await?;
    let stdin = std::io::stdin();
    let mut stdin = stdin.lock();
    let mut inflight = 0u64;
    let mut line = String::new();
    let mut eof = false;
    loop {
        while inflight < pipeline && !eof {
            if !read_line_bounded(&mut stdin, &mut line, MAX_UPLOAD_LINE_BYTES)? {
                eof = true;
                break;
            }
            if line.len() + 1 > MAX_UPLOAD_LINE_BYTES {
                bail!("upload: stdin line exceeds {MAX_UPLOAD_LINE_BYTES} bytes");
            }
            let msg = format!("[\"EVENT\",{line}]");
            ws.send(Message::Text(msg.into())).await?;
            inflight += 1;
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
            cli_println!("{}", v[2]);
        }
    }
    Ok(())
}

#[cfg(test)]
mod main_tests {
    use super::*;
    use secp256k1::{Keypair, SECP256K1};
    use serde_json::json;
    use wok_db::{write_events, EventToWrite, NoopNegentropy};
    use wok_event::{parse_and_verify_event, EventLimits};
    use wok_negentropy::Storage;

    #[test]
    fn parse_mesh_time_rejects_multibyte_units_without_panicking() {
        assert_eq!(parse_mesh_time("1h").unwrap(), 3600);
        assert_eq!(parse_mesh_time("2d").unwrap(), 2 * 86400);
        assert!(parse_mesh_time("1€").is_err());
        assert!(parse_mesh_time("€").is_err());
        assert!(parse_mesh_time("").is_err());
        assert!(parse_mesh_time("xh").is_err());
    }

    fn signed_event(created_at: u64) -> EventToWrite {
        let mut rng = rand::thread_rng();
        let key = Keypair::new(SECP256K1, &mut rng);
        let (pubkey, _) = key.x_only_public_key();
        let mut event = json!({
            "created_at": created_at,
            "kind": 1,
            "tags": [],
            "content": format!("event {created_at}"),
            "pubkey": hex::encode(pubkey.serialize()),
        });
        let id = wok_event::event_id_hash(&event).unwrap();
        event["id"] = json!(hex::encode(id));
        event["sig"] = json!(hex::encode(SECP256K1.sign_schnorr(&id, &key).as_ref()));
        let parsed =
            parse_and_verify_event(&event, &EventLimits::default(), None, true, false).unwrap();
        EventToWrite::new(parsed.packed.into_bytes(), parsed.json)
    }

    #[test]
    fn negentropy_build_batches_are_idempotent_and_reject_zero_size() {
        let directory = tempfile::tempdir().unwrap();
        let env = Env::open(directory.path(), EnvOptions::default()).unwrap();
        env.ensure_initialized().unwrap();
        let mut events: Vec<_> = (0..5)
            .map(|offset| signed_event(1_700_000_000 + offset))
            .collect();
        let mut txn = env.begin_rw().unwrap();
        write_events(&mut txn, &mut NoopNegentropy, &mut events, false).unwrap();
        txn.commit().unwrap();

        let tree_id = {
            let txn = env.begin_ro().unwrap();
            let mut tree_id = None;
            wok_db::foreach_negentropy_filter(&txn, |id, _| {
                tree_id = Some(id);
                false
            })
            .unwrap();
            tree_id.unwrap()
        };
        build_negentropy_tree(&env, tree_id, 2).unwrap();
        build_negentropy_tree(&env, tree_id, 1).unwrap();
        let txn = env.begin_ro().unwrap();
        let mut tree = wok_negentropy::open_ro(&txn, tree_id).unwrap();
        assert_eq!(tree.size(), 5);
        assert!(build_negentropy_tree(&env, tree_id, 0)
            .unwrap_err()
            .to_string()
            .contains("at least 1"));
    }

    #[test]
    fn reconnect_backoff_is_exponential_and_capped() {
        let maximum = std::time::Duration::from_secs(5);
        assert_eq!(
            next_reconnect_delay(std::time::Duration::from_secs(1), maximum),
            std::time::Duration::from_secs(2)
        );
        assert_eq!(
            next_reconnect_delay(std::time::Duration::from_secs(4), maximum),
            maximum
        );
        assert_eq!(next_reconnect_delay(maximum, maximum), maximum);
    }

    #[tokio::test]
    async fn stream_reconnects_after_remote_close_without_blocking_runtime() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (socket, _) = listener.accept().await.unwrap();
                let mut websocket = tokio_tungstenite::accept_async(socket).await.unwrap();
                websocket.close(None).await.unwrap();
            }
        });

        let directory = tempfile::tempdir().unwrap();
        let cfg = Config {
            db: directory.path().join("db"),
            ..Config::default()
        };
        let client = tokio::spawn(async move {
            cmd_stream(&cfg, format!("ws://{address}"), "down".into(), 1, 1).await
        });

        tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .expect("stream did not reconnect")
            .unwrap();
        client.abort();
        assert!(client.await.unwrap_err().is_cancelled());
    }
}
