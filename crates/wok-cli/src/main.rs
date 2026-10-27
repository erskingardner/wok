#![deny(unsafe_code, unsafe_op_in_unsafe_fn)]

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::io::BufRead;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use wok_db::{
    check_integrity, delete_events, event_json_owned, write_events_with_policy, Decompressor, Env,
    EnvOptions, EventToWrite,
};
use wok_event::{
    parse_and_verify_event_with, EventLimits, IdPreimage, PackedEventView, AUTH_KIND, DELETION_KIND,
};
use wok_negentropy::Storage;
mod config_minimize;
mod config_show;
mod doctor;
mod mesh;
mod migrate;
mod reindex;
mod router;
mod sync;

use wok_relay::Config;

fn foreach_by_filter_scan(
    txn: &wok_db::RoTxn<'_>,
    filter: &serde_json::Value,
    max_limit: u64,
    max_tags: usize,
    max_and_entries: usize,
    cb: impl FnMut(u64),
) -> Result<(), wok_query::QueryError> {
    wok_query::foreach_by_filter(txn, filter, max_limit, max_tags, max_and_entries, cb)
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
    /// Inspect the configuration file
    Config {
        #[command(subcommand)]
        cmd: ConfigCmd,
    },
    /// Diagnose configuration, storage, indexes, payloads, and runtime paths
    Doctor {
        /// Emit the complete machine-readable report
        #[arg(long)]
        json: bool,
    },
    /// Rebuild all derived indexes into a staged database and promote it,
    /// repacking records that dropped long tag values
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
    /// Delete replaceable versions superseded by a newer one at the same address
    PurgeSuperseded {
        /// Report what would be deleted without changing the database
        #[arg(long)]
        dry_run: bool,
        /// Emit the machine-readable outcome
        #[arg(long)]
        json: bool,
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
    Sync(sync::Options),
    Upload {
        url: String,
        /// Events sent ahead of the relay's acknowledgments
        #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u64).range(1..))]
        pipeline: u64,
    },
    Download {
        url: String,
        #[arg(long)]
        filter: Option<String>,
        #[arg(long)]
        no_verify: bool,
        /// Abort after this many seconds without the handshake, an event or
        /// EOSE (0 disables).
        #[arg(long, default_value_t = 60)]
        timeout: u64,
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
enum ConfigCmd {
    /// Print the effective configuration and where each value comes from
    Show {
        /// Print only keys the file sets to a value other than its preset's
        #[arg(long, conflicts_with = "defaults")]
        overrides: bool,
        /// Print every setting with the value of the file's preset, ignoring
        /// the rest of the file
        #[arg(long)]
        defaults: bool,
    },
    /// Remove the keys that repeat the preset's values, keeping comments, and
    /// keep the original as <config>.bak
    Minimize {
        /// Print the change as a unified diff and leave the file unchanged
        #[arg(long)]
        dry_run: bool,
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
        Command::Config { cmd } => {
            let shown = match cmd {
                ConfigCmd::Show {
                    overrides,
                    defaults,
                } => config_show::run(
                    &config,
                    if defaults {
                        config_show::View::Defaults
                    } else if overrides {
                        config_show::View::Overrides
                    } else {
                        config_show::View::Effective
                    },
                )?,
                ConfigCmd::Minimize { dry_run } => config_minimize::run(&config, dry_run)?,
            };
            cli_print!("{shown}");
            return Ok(());
        }
        cmd => cmd,
    };
    let cfg = load_cfg(&config)?;
    match cmd {
        Command::Migrate { .. } => unreachable!("migration was dispatched before config load"),
        Command::Config { .. } => unreachable!("config was dispatched before config load"),
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
        Command::PurgeSuperseded { dry_run, json } => cmd_purge_superseded(&cfg, dry_run, json),
        Command::Compact { output_file } => cmd_compact(&cfg, &output_file),
        Command::Monitor => cmd_monitor(&cfg),
        Command::Dict { cmd } => cmd_dict(&cfg, cmd),
        Command::Negentropy { cmd } => cmd_neg(&cfg, cmd),
        Command::Integrity => cmd_integrity(&cfg),
        Command::Sync(options) => sync::run(&cfg, options).await,
        Command::Upload { url, pipeline } => cmd_upload(url, pipeline).await,
        Command::Download {
            url,
            filter,
            no_verify,
            timeout,
        } => cmd_download(&cfg, url, filter, no_verify, timeout).await,
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
            tracing_subscriber::fmt()
                .with_writer(std::io::stderr)
                .with_env_filter(filter)
                .init();
        }
        wok_relay::config::LogFormat::Json => {
            tracing_subscriber::fmt()
                .json()
                .flatten_event(true)
                .with_current_span(true)
                .with_span_list(true)
                .with_writer(std::io::stderr)
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
                    if let Err(error) = handle.reload_config(new) {
                        tracing::error!("config reload refused, keeping old config: {error}");
                    }
                }
                Err(e) => {
                    tracing::error!("config reload failed, keeping old config: {e}");
                }
            }
        }
    });
}

async fn cmd_relay(cfg: Config, config_path: PathBuf) -> Result<()> {
    tracing::info!(
        preset = %cfg.preset,
        wok = env!("CARGO_PKG_VERSION"),
        "starting relay"
    );
    let warnings = [
        cfg.auth_configuration_warning(),
        cfg.read_class_warning(),
        cfg.inbox_kinds_warning(),
        cfg.unix_socket_warning(),
        cfg.pow_warning(),
        cfg.nodeinfo_warning(),
        cfg.admin_pubkeys_warning(),
    ];
    for warning in warnings
        .into_iter()
        .flatten()
        .chain(cfg.zero_guard_warnings())
        .chain(cfg.message_cap_warnings())
    {
        tracing::warn!("{warning}");
    }
    for deprecation in &cfg.deprecations {
        tracing::warn!("{deprecation}");
    }
    wok_relay::apply_nofiles_limit(cfg.relay.nofiles).map_err(anyhow::Error::msg)?;
    let env = open_env(&cfg)?;
    let listeners = wok_ws::bind_listeners(&cfg.relay.bind, cfg.relay.port).await?;
    let listening: Vec<std::net::SocketAddr> = listeners
        .iter()
        .filter_map(|listener| listener.local_addr().ok())
        .collect();
    if let Some(warning) = cfg.real_ip_header_warning(&listening) {
        tracing::warn!("{warning}");
    }
    // Bound whenever an address is set, so turning metrics on or off is a
    // live reload; the listener answers 404 while they are off.
    let metrics_listener = match cfg.observability.metrics_listen.as_str() {
        "" => None,
        listen => Some(
            tokio::net::TcpListener::bind(listen)
                .await
                .with_context(|| format!("bind observability.metrics_listen {listen}"))?,
        ),
    };
    let bound = wok_relay::BoundAddresses {
        relay: listening.clone(),
        metrics: metrics_listener
            .as_ref()
            .and_then(|listener| listener.local_addr().ok()),
    };
    if let Some(warning) = cfg.metrics_warning(&bound.relay, bound.metrics) {
        tracing::warn!("{warning}");
    }
    let unix_cfg = cfg.clone();
    let handle = wok_relay::start(env, cfg).map_err(|e| anyhow::anyhow!(e))?;
    handle.set_bound_addresses(bound);
    if config_path.exists() {
        handle.set_config_path(config_path.clone());
        spawn_config_reload(config_path, handle.clone());
    }
    let h2 = handle.clone();
    let h3 = handle.clone();
    let ws = tokio::spawn(async move {
        if let Err(e) = wok_ws::serve(h3, listeners).await {
            tracing::error!("ws server: {e}");
        }
    });
    let unix = tokio::spawn(async move {
        if let Err(e) = wok_unix::serve(h2, unix_cfg).await {
            tracing::error!("unix server: {e}");
        }
    });
    let metrics = metrics_listener.map(|listener| {
        let handle = handle.clone();
        tokio::spawn(async move {
            if let Err(e) = wok_ws::serve_metrics(handle, listener).await {
                tracing::error!("metrics server: {e}");
            }
        })
    });
    // Service managers use SIGTERM; preserve the interactive SIGINT and
    // historical strfry SIGUSR1 paths as equivalent graceful shutdowns.
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut sigusr1 =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => tracing::info!("SIGINT: initiating graceful shutdown"),
        _ = sigterm.recv() => tracing::info!("SIGTERM: initiating graceful shutdown"),
        _ = sigusr1.recv() => tracing::info!("SIGUSR1: initiating graceful shutdown"),
    }
    handle.request_shutdown();
    // Listeners stop accepting and return (the unix server unlinks its
    // socket); existing connections drain naturally like C++.
    let _ = ws.await;
    let _ = unix.await;
    if let Some(metrics) = metrics {
        let _ = metrics.await;
    }
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
    // Join the relay threads so their Env clones drop and LMDB closes the
    // environment before exit; on macOS an unclosed env leaks its POSIX
    // semaphores until reboot.
    let joined = tokio::task::spawn_blocking(move || {
        handle.shutdown_and_join(std::time::Duration::from_secs(10))
    })
    .await?;
    if let Err(e) = joined {
        tracing::warn!("{e}");
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
        if outcome.repacked_long_tag_records != 0 || outcome.skipped_long_tag_records != 0 {
            cli_println!(
                "Repacked {} records with their long tag values; kept {} whose payload packs differently.",
                outcome.repacked_long_tag_records,
                outcome.skipped_long_tag_records
            );
        }
        if outcome.deleted_under_repaired_deletions != 0 {
            cli_println!(
                "Deleted {} versions under repaired deletion requests; the backup keeps them.",
                outcome.deleted_under_repaired_deletions
            );
        }
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
    let limits = cfg.event_limits();
    let max_event_size = cfg.events.max_event_size;
    // A reader thread parses and verifies lines while this one writes the
    // batch before, as strfry verifies on a thread of its own. At most two
    // batches are held. A reader left blocked on stdin when a write fails
    // ends with the process.
    let (sender, batches) = std::sync::mpsc::sync_channel(0);
    let reader = std::thread::Builder::new()
        .name("import-reader".into())
        .spawn(move || {
            read_import_batches(
                std::io::stdin().lock(),
                batch_size,
                max_event_size,
                |line| parse_import_line(line, fried, no_verify, &limits),
                |batch| sender.send(batch).is_ok(),
            )
        })
        .context("start the import reader")?;
    let mut total_processed = 0u64;
    let mut total_written = 0u64;
    let mut total_rejected = 0u64;
    let mut total_dups = 0u64;
    let mut deferred_tag_kind = false;
    for batch in batches {
        let mut batch = batch?;
        total_processed += batch.lines;
        total_rejected += batch.rejected;
        if !batch.events.is_empty() {
            deferred_tag_kind |= commit_import(
                cfg,
                &env,
                &mut batch.events,
                &mut total_written,
                &mut total_rejected,
                &mut total_dups,
                show_rejected,
            )?;
        }
    }
    // The channel also closes if the reader panicked; don't report that as
    // the end of the input.
    reader
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    if deferred_tag_kind {
        build_tag_kind_index(&env)?;
    }
    build_search_index(&env)?;
    tracing::info!(
        "Done. Processed {total_processed} lines. {total_written} added, {total_rejected} rejected, {total_dups} dups"
    );
    if total_rejected > 0 {
        bail!("import incomplete: {total_rejected} records rejected; {total_written} written, {total_dups} duplicates");
    }
    Ok(())
}

/// Events read from `wok import`'s input to write in one transaction.
#[derive(Default)]
struct ImportBatch {
    events: Vec<EventToWrite>,
    /// Lines read for the batch, rejected ones included.
    lines: u64,
    rejected: u64,
}

/// Read `input` into batches of `batch_size` parsed events and `send` each,
/// until the input ends, a line fails to read or is too long, or `send`
/// returns false. A line that fails ends the import without the events read
/// since the last batch.
fn read_import_batches(
    mut input: impl BufRead,
    batch_size: usize,
    max_event_size: usize,
    parse: impl Fn(&str) -> Result<EventToWrite>,
    mut send: impl FnMut(Result<ImportBatch>) -> bool,
) {
    let mut batch = ImportBatch::default();
    let mut line = String::new();
    let mut i = 0u64;
    loop {
        match read_line_bounded(&mut input, &mut line, max_event_size) {
            Ok(true) => {}
            Ok(false) => break,
            Err(error) => {
                send(Err(error.into()));
                return;
            }
        }
        i += 1;
        batch.lines += 1;
        // C++ counts the newline in its getline length check, so a line of
        // exactly maxEventSize chars is rejected there.
        if line.len() + 1 > max_event_size {
            send(Err(anyhow::anyhow!(
                "Line larger than configured maxEventSize on line {i}"
            )));
            return;
        }
        match parse(&line) {
            Ok(ev) => batch.events.push(ev),
            Err(e) => {
                batch.rejected += 1;
                tracing::warn!("Unable to parse JSON on line {i}: {e}");
                continue;
            }
        }
        if batch.events.len() >= batch_size && !send(Ok(std::mem::take(&mut batch))) {
            return;
        }
    }
    if batch.lines != 0 {
        send(Ok(batch));
    }
}

/// NIP-42 forbids broadcasting kind 22242. The relay refuses it as EVENT, and
/// imports and downloads refuse it with this reason, so no ingest path stores
/// one.
const AUTH_EVENT_REFUSAL: &str = "kind 22242 AUTH events are never stored";

fn parse_import_line(
    line: &str,
    fried: bool,
    no_verify: bool,
    limits: &EventLimits,
) -> Result<EventToWrite> {
    let event = if fried {
        let (packed, json) = parse_fried(line)?;
        EventToWrite::new(packed, json)
    } else {
        let v: serde_json::Value = wok_event::json::parse_strict(line)?;
        // Imported lines are stored events, possibly hashed with the legacy
        // preimage by strfry or an earlier Wok release.
        let parsed = parse_and_verify_event_with(
            &v,
            limits,
            None,
            !no_verify,
            false,
            IdPreimage::Nip01OrLegacy,
        )?;
        EventToWrite::new(parsed.packed.into_bytes(), parsed.json)
    };
    let kind = PackedEventView::new(&event.packed)?.kind();
    if kind == AUTH_KIND {
        bail!(AUTH_EVENT_REFUSAL);
    }
    // parse_and_verify_event_with already refused a JSON line's padded kinds.
    if fried && kind == DELETION_KIND {
        wok_event::require_canonical_addresses(&wok_event::json::parse_strict(&event.json)?)?;
    }
    Ok(event)
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

/// Write `batch` in one transaction. Returns whether it left its events'
/// `(tag, kind, created_at)` postings to a key-ordered pass: it does while
/// the index is unbuilt, a new database's included, and no pass runs.
fn commit_import(
    cfg: &Config,
    env: &Env,
    batch: &mut Vec<EventToWrite>,
    written: &mut u64,
    rejected: &mut u64,
    dups: &mut u64,
    show_rejected: bool,
) -> Result<bool> {
    let mut txn = env.begin_rw()?;
    let deferred_tag_kind = wok_db::defer_tag_kind_postings(&mut txn)?;
    let mut sink = wok_negentropy::NegentropyFilterCache::default();
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
    Ok(deferred_tag_kind)
}

/// Index the imported events for NIP-50 search, which publishing leaves to
/// later steps, so that a relay started on the database can search it at
/// once. Like the tag-kind build, it leaves the rest to the relay's writer
/// once another process has the database open.
fn build_search_index(env: &Env) -> Result<()> {
    let started = std::time::Instant::now();
    let mut last_log = started;
    let mut events = 0u64;
    loop {
        if env.open_in_another_process()? {
            tracing::info!(
                "Another process has the database open; a relay on it builds the rest of the search index in the background"
            );
            return Ok(());
        }
        let mut txn = env.begin_rw()?;
        let step = wok_db::build_search_index(
            &mut txn,
            wok_db::SEARCH_BUILD_STEP_EVENTS,
            std::time::Duration::MAX,
        )?;
        txn.commit()?;
        let Some(step) = step else {
            return Ok(());
        };
        events += step.events;
        if step.state.lag() == 0 {
            break;
        }
        if last_log.elapsed() >= std::time::Duration::from_secs(10) {
            last_log = std::time::Instant::now();
            tracing::info!(
                "Search index: indexed through {} of {}",
                step.state.indexed_through,
                step.state.high_water
            );
        }
    }
    if events > 0 {
        tracing::info!(
            "Built the search index for {events} events in {:.1}s",
            started.elapsed().as_secs_f64()
        );
    }
    Ok(())
}

/// Build the `(tag, kind, created_at)` index that import batches left to a
/// key-ordered pass, so that the database is complete when the import
/// exits. Built after the load, it writes a fraction of the pages that
/// postings in arrival order rewrite. Its steps are the relay's, and it
/// leaves the rest to the relay's writer once another process has the
/// database open, so a relay on it acknowledges publications as fast as
/// during its own build. An import stopped before it ends leaves the index
/// incomplete, and the relay's writer finishes it.
fn build_tag_kind_index(env: &Env) -> Result<()> {
    let started = std::time::Instant::now();
    let mut last_log = started;
    let mut entries = 0u64;
    tracing::info!("Building the (tag, kind, created_at) index");
    loop {
        if env.open_in_another_process()? {
            tracing::info!(
                "Another process has the database open; a relay on it builds the rest of the (tag, kind, created_at) index in the background"
            );
            return Ok(());
        }
        let mut txn = env.begin_rw()?;
        let step = wok_db::backfill_tag_kind_index(
            &mut txn,
            wok_db::TAG_KIND_STEP_ENTRIES,
            wok_db::TAG_KIND_STEP_BUDGET,
        )?;
        txn.commit()?;
        let Some(step) = step else {
            return Ok(());
        };
        entries += step.entries;
        if step.state.complete() {
            break;
        }
        if last_log.elapsed() >= std::time::Duration::from_secs(10) {
            last_log = std::time::Instant::now();
            match step.state.bulk_pass {
                Some(pass) => tracing::info!(
                    "(tag, kind, created_at) index: {} of {} tag entries visited",
                    pass.visited,
                    step.tag_entries
                ),
                None => tracing::info!(
                    "(tag, kind, created_at) index: indexed through {} of {}",
                    step.state.indexed_through,
                    step.state.high_water
                ),
            }
        }
    }
    tracing::info!(
        "Built the (tag, kind, created_at) index: {entries} entries in {:.1}s",
        started.elapsed().as_secs_f64()
    );
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
    // relay.max_filter_limit bounds client REQs; an operator scan covers the
    // whole database unless the filter sets its own limit.
    foreach_by_filter_scan(
        &txn,
        &filter,
        u64::MAX,
        cfg.relay.max_tags_per_filter,
        cfg.relay.max_and_entries,
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
            cfg.relay.max_and_entries,
            |lev| levs.push(lev),
        )?;
    }
    if dry_run {
        tracing::info!("Would delete {} events", levs.len());
        return Ok(());
    }
    tracing::info!("Deleting {} events", levs.len());
    let mut txn = env.begin_rw()?;
    let mut sink = wok_negentropy::NegentropyFilterCache::default();
    delete_events(&mut txn, &mut sink, levs)?;
    txn.commit()?;
    Ok(())
}

/// Replacement-index entries scanned per write transaction, so the relay's
/// writer interleaves.
const PURGE_SUPERSEDED_BATCH: u64 = 10_000;

fn cmd_purge_superseded(cfg: &Config, dry_run: bool, json: bool) -> Result<()> {
    let history = if dry_run {
        // Like doctor: no directory creation, initialization, or marker upgrade.
        let env = Env::open(
            &cfg.db,
            EnvOptions {
                max_readers: cfg.db_maxreaders,
                map_size: cfg.db_mapsize,
                no_read_ahead: cfg.db_no_read_ahead,
                create_dir: false,
                create_dbis: false,
                read_only: true,
                ..EnvOptions::default()
            },
        )?;
        let txn = env.begin_ro()?;
        wok_db::count_superseded_ro(&txn)?
    } else {
        wok_db::purge_superseded(
            &open_env(cfg)?,
            wok_negentropy::NegentropyFilterCache::default,
            PURGE_SUPERSEDED_BATCH,
        )?
    };
    if json {
        let outcome = serde_json::json!({
            "dry_run": dry_run,
            "superseded_groups": history.groups,
            "superseded_events": history.events,
        });
        cli_println!("{}", serde_json::to_string_pretty(&outcome)?);
    } else {
        let verb = if dry_run { "Would delete" } else { "Deleted" };
        cli_println!(
            "{verb} {} superseded events in {} replacement groups.",
            history.events,
            history.groups
        );
    }
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
                    cfg.relay.max_and_entries,
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
                    Some(wok_db::event_search_terms(p.kind(), &json).unwrap_or_default())
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
            cfg.relay.max_and_entries,
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
                let details = wok_negentropy::open_ro(&txn, id).and_then(|mut tree| {
                    let size = tree.size()?;
                    let fp = tree.fingerprint(0, size as usize)?;
                    Ok((size, fp))
                });
                match details {
                    Ok((size, fp)) => {
                        cli_println!("  size: {size}");
                        cli_println!("  fingerprint: {}", hex::encode(fp));
                    }
                    Err(e) => cli_println!("  error: {e}"),
                }
                true
            })?;
        }
        NegCmd::Add { filter } => {
            let v: serde_json::Value = serde_json::from_str(&filter)?;
            let filter_str = v.to_string();
            // Check the stored text with the parser every tree writer uses,
            // so no setting can make a write fail on it (#243).
            let compiled = wok_negentropy::parse_negentropy_filter(&filter_str)?;
            if compiled.never_match {
                bail!("filter will never match");
            }
            if compiled.since != 0 || compiled.until != u64::MAX {
                bail!("negentropy filters should not have since/until");
            }
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
        } => {
            build_negentropy_tree(&env, tree_id, batch_size)?;
        }
    }
    Ok(())
}

/// Populate a tree through bounded primary-table scans and short write
/// transactions. Inserts are idempotent, so rerunning this after interruption
/// safely resumes the outcome without requiring a separate progress file.
/// Returns how many items were newly inserted.
fn build_negentropy_tree(env: &Env, tree_id: u64, batch_size: usize) -> Result<u64> {
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
        let compiled =
            wok_query::NostrFilterGroup::from_value(&filter, u64::MAX, usize::MAX, usize::MAX)?;
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
    Ok(inserted)
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
        // process::exit skips destructors; close the env first.
        drop(txn);
        drop(env);
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

fn downloaded_event_matches(
    filter_group: &wok_query::NostrFilterGroup,
    event: &serde_json::Value,
    limits: &EventLimits,
) -> bool {
    wok_event::nostr_json_to_packed_event(event, limits)
        .map(|packed| {
            if filter_group.requires_content() {
                let view = packed.view();
                wok_db::event_search_terms(view.kind(), &event.to_string()).is_ok_and(|terms| {
                    filter_group.does_match_with_search_terms(view, Some(&terms))
                })
            } else {
                filter_group.does_match(packed.view())
            }
        })
        .unwrap_or(false)
}

/// Normalized JSON of an event a relay sent `wok download`. Relays serve
/// stored events, which strfry and earlier Wok releases hashed with the legacy
/// id preimage.
fn downloaded_event_json(
    event: &serde_json::Value,
    no_verify: bool,
    limits: &EventLimits,
) -> Result<String> {
    let parsed = parse_and_verify_event_with(
        event,
        limits,
        None,
        !no_verify,
        false,
        IdPreimage::Nip01OrLegacy,
    )?;
    Ok(parsed.json)
}

fn most_recent_levid_ro_quiet(txn: &wok_db::RoTxn<'_>) -> u64 {
    wok_db::most_recent_levid_ro(txn).unwrap_or(0)
}

/// What `wok upload` sent and how the relay answered, printed on stderr
/// whether or not it succeeds.
#[derive(Default)]
struct UploadReport {
    /// Lines read from standard input.
    lines: u64,
    sent: u64,
    accepted: u64,
    duplicates: u64,
    /// Refused because the relay stores a newer version, as `wok sync` counts
    /// them: not a failure.
    superseded: u64,
    refused: u64,
    /// Lines not sent because they are not event JSON.
    invalid: u64,
    /// Events sent that the relay has not acknowledged.
    unacknowledged: u64,
}

async fn cmd_upload(url: String, pipeline: u64) -> Result<()> {
    let mut report = UploadReport::default();
    let result = upload(&url, pipeline, &mut report).await;
    eprintln!(
        "Upload {}: lines={} sent={} accepted={} duplicates={} superseded={} refused={} invalid={} unacknowledged={}",
        if result.is_ok() { "complete" } else { "failed" },
        report.lines,
        report.sent,
        report.accepted,
        report.duplicates,
        report.superseded,
        report.refused,
        report.invalid,
        report.unacknowledged
    );
    result
}

/// Send each line of standard input as an EVENT, at most `pipeline` ahead of
/// the relay's OKs, and count the OKs by event id.
async fn upload(url: &str, pipeline: u64, report: &mut UploadReport) -> Result<()> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    let (mut ws, _) = tokio_tungstenite::connect_async(url).await?;
    let stdin = std::io::stdin();
    let mut stdin = stdin.lock();
    // The relay answers each copy of an event the input repeats.
    let mut pending = std::collections::HashMap::<String, u64>::new();
    let mut line = String::new();
    let mut eof = false;
    let incomplete = |report: &UploadReport, eof: bool| {
        format!(
            "upload incomplete: connection lost with {} acknowledgments outstanding{}",
            report.unacknowledged,
            if eof { "" } else { " and input left unsent" }
        )
    };
    loop {
        while report.unacknowledged < pipeline && !eof {
            if !read_line_bounded(&mut stdin, &mut line, MAX_UPLOAD_LINE_BYTES)? {
                eof = true;
                break;
            }
            report.lines += 1;
            if line.len() + 1 > MAX_UPLOAD_LINE_BYTES {
                bail!("upload: stdin line exceeds {MAX_UPLOAD_LINE_BYTES} bytes");
            }
            let id = match upload_line_id(&line) {
                Ok(id) => id,
                Err(error) => {
                    report.invalid += 1;
                    tracing::warn!("Not uploading line {}: {error}", report.lines);
                    continue;
                }
            };
            let msg = format!("[\"EVENT\",{line}]");
            if let Err(error) = ws.send(Message::Text(msg.into())).await {
                return Err(error).context(incomplete(report, eof));
            }
            report.sent += 1;
            report.unacknowledged += 1;
            *pending.entry(id).or_default() += 1;
        }
        if report.unacknowledged == 0 {
            break;
        }
        let text = match ws.next().await {
            Some(Ok(Message::Text(text))) => text,
            Some(Ok(Message::Close(_))) | None => bail!(incomplete(report, eof)),
            Some(Err(error)) => return Err(error).context(incomplete(report, eof)),
            // Reading on past a ping flushes tungstenite's queued pong.
            Some(Ok(_)) => continue,
        };
        let message = match wok_event::json::parse_strict(&text) {
            Ok(message) => message,
            Err(error) => {
                tracing::warn!(%error, "upload ignored an unreadable relay message");
                continue;
            }
        };
        match message[0].as_str().unwrap_or_default() {
            "OK" => {
                let (Some(id), Some(accepted)) = (message[1].as_str(), message[2].as_bool()) else {
                    bail!("upload incomplete: malformed OK from the relay");
                };
                let reason = message[3].as_str().unwrap_or_default();
                let Some(copies) = pending.get_mut(id) else {
                    tracing::warn!(id, "upload ignored an OK for an event not awaiting one");
                    continue;
                };
                *copies -= 1;
                if *copies == 0 {
                    pending.remove(id);
                }
                report.unacknowledged -= 1;
                if accepted && reason.starts_with("duplicate:") {
                    report.duplicates += 1;
                } else if accepted {
                    report.accepted += 1;
                } else if sync::upload_superseded(reason) {
                    report.superseded += 1;
                } else {
                    report.refused += 1;
                    tracing::warn!(id, reason, "relay refused event");
                }
            }
            "NOTICE" => tracing::warn!(notice = %message[1], "relay NOTICE"),
            "CLOSED" => {
                tracing::warn!(subscription = %message[1], reason = %message[2], "relay CLOSED")
            }
            "AUTH" => tracing::debug!("relay advertises AUTH; wok upload has no signing identity"),
            _ => {}
        }
    }
    let _ = ws.close(None).await;
    if report.refused + report.invalid > 0 {
        bail!(
            "upload incomplete: {} events refused, {} lines not events",
            report.refused,
            report.invalid
        );
    }
    Ok(())
}

/// The id of the event on a `wok upload` input line. Like `wok import`, the
/// command skips a line that is not event JSON; the relay checks the rest.
fn upload_line_id(line: &str) -> Result<String> {
    let event = wok_event::json::parse_strict(line)?;
    let id = event
        .get("id")
        .and_then(serde_json::Value::as_str)
        .context("not an event: no id")?;
    if wok_event::from_lower_hex_exact(id)?.len() != 32 {
        bail!("not an event: id is not 32 bytes");
    }
    Ok(id.to_owned())
}

/// NIP-01's machine-readable refusal prefixes, and the `ERROR:` strfry and Wok
/// put on a REQ they cannot parse. A NOTICE without one, such as a greeting,
/// does not stop `wok download`.
const REFUSAL_PREFIXES: [&str; 7] = [
    "error",
    "auth-required",
    "restricted",
    "invalid",
    "blocked",
    "rate-limited",
    "unsupported",
];

fn notice_refuses(notice: &str) -> bool {
    REFUSAL_PREFIXES.iter().any(|prefix| {
        notice
            .get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
            && notice[prefix.len()..].starts_with(':')
    })
}

/// Awaits `future` until `deadline`, or for as long as it takes without one.
async fn until<T>(
    deadline: Option<tokio::time::Instant>,
    future: impl std::future::Future<Output = T>,
) -> Option<T> {
    match deadline {
        Some(deadline) => tokio::time::timeout_at(deadline, future).await.ok(),
        None => Some(future.await),
    }
}

async fn cmd_download(
    cfg: &Config,
    url: String,
    filter: Option<String>,
    no_verify: bool,
    timeout: u64,
) -> Result<()> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    if no_verify {
        tracing::warn!("not verifying event IDs or signatures!");
    }
    let limits = cfg.event_limits();
    // A relay that stalls holds the socket open as long as tungstenite answers
    // its pings, so only a deadline ends the wait.
    let idle = (timeout > 0).then(|| std::time::Duration::from_secs(timeout));
    let next_deadline = || idle.and_then(|idle| tokio::time::Instant::now().checked_add(idle));
    let Some(connected) = until(next_deadline(), tokio_tungstenite::connect_async(&url)).await
    else {
        bail!("download failed: no WebSocket handshake within {timeout}s");
    };
    let (mut ws, _) = connected?;
    let filter = filter.unwrap_or_else(|| "{}".into());
    let req = format!(r#"["REQ","_",{filter}]"#);
    ws.send(Message::Text(req.into())).await?;
    let (mut printed, mut rejected, mut eose) = (0u64, 0u64, false);
    let mut answered = false;
    let mut deadline = next_deadline();
    loop {
        let Some(msg) = until(deadline, ws.next()).await else {
            bail!("download incomplete: no event or EOSE for {timeout}s; {printed} printed, {rejected} rejected");
        };
        let Some(msg) = msg else { break };
        // Reading on past a ping flushes tungstenite's queued pong.
        let text = match msg? {
            Message::Text(text) => text,
            Message::Close(_) => break,
            _ => continue,
        };
        let v = match wok_event::json::parse_strict(&text) {
            Ok(v) => v,
            Err(error) => {
                rejected += 1;
                tracing::warn!(%error, "download rejected unreadable message");
                continue;
            }
        };
        match v[0].as_str().unwrap_or_default() {
            "EOSE" => {
                eose = true;
                break;
            }
            "EVENT" => {
                match downloaded_event_json(&v[2], no_verify, &limits) {
                    Ok(json) => {
                        cli_println!("{json}");
                        printed += 1;
                    }
                    Err(error) => {
                        rejected += 1;
                        let id = v[2]["id"].as_str().unwrap_or_default();
                        tracing::warn!(id, %error, "download rejected event");
                    }
                }
                answered = true;
                deadline = next_deadline();
            }
            "CLOSED" if v[1] == "_" => bail!(
                "download refused: relay closed the subscription: {}; {printed} printed, {rejected} rejected",
                v[2]
            ),
            "NOTICE" => {
                tracing::warn!(notice = %v[1], "download relay NOTICE");
                // Once events flow, a NOTICE concerns something else.
                if !answered && v[1].as_str().is_some_and(notice_refuses) {
                    bail!(
                        "download refused: relay NOTICE {}; {printed} printed, {rejected} rejected",
                        v[1]
                    );
                }
            }
            _ => {}
        }
    }
    if !eose {
        bail!("download incomplete: connection closed before EOSE; {printed} printed, {rejected} rejected");
    }
    if rejected > 0 {
        bail!("download incomplete: {printed} printed, {rejected} rejected");
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
    fn every_command_is_in_the_attack_surface_inventory() {
        use clap::CommandFactory;
        use std::collections::BTreeSet;

        fn leaves(command: &clap::Command, path: String, out: &mut BTreeSet<String>) {
            let mut children = command
                .get_subcommands()
                .filter(|child| child.get_name() != "help")
                .peekable();
            if children.peek().is_none() {
                out.insert(path);
                return;
            }
            for child in children {
                leaves(child, format!("{path} {}", child.get_name()), out);
            }
        }
        let mut commands = BTreeSet::new();
        leaves(&Cli::command(), "wok".into(), &mut commands);
        let documented: BTreeSet<String> = include_str!("../../../docs/attack-surface.md")
            .lines()
            .filter_map(|line| line.strip_prefix("| `wok "))
            .filter_map(|rest| rest.split_once('`'))
            .map(|(command, _)| format!("wok {command}"))
            .collect();
        assert_eq!(
            commands, documented,
            "the wok commands and the Commands table of docs/attack-surface.md differ"
        );
    }

    #[test]
    fn negentropy_add_stores_only_filters_every_write_can_parse() {
        // #243: add checked filters with its own limits, so it stored trees
        // every later write failed on.
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config {
            db: dir.path().join("db"),
            ..Config::default()
        };
        cfg.relay.max_tags_per_filter = 0;
        let add = |filter: &str| {
            cmd_neg(
                &cfg,
                NegCmd::Add {
                    filter: filter.into(),
                },
            )
        };
        // The cache parses one filter object; a stored array failed every write.
        let refused = add(r#"[{"kinds":[1]},{"kinds":[7]}]"#).unwrap_err();
        assert!(refused.to_string().contains("not an object"), "{refused}");
        // Ten tag letters, past the default of 8 and the setting of 0.
        let filter: serde_json::Map<_, _> = "abcdfghijk"
            .chars()
            .map(|letter| (format!("#{letter}"), json!(["x"])))
            .collect();
        let filter = serde_json::Value::Object(filter).to_string();
        add(&filter).unwrap();

        let env = open_env(&cfg).unwrap();
        let mut events = vec![signed_event(1)];
        let (mut written, mut rejected, mut duplicates) = (0, 0, 0);
        commit_import(
            &cfg,
            &env,
            &mut events,
            &mut written,
            &mut rejected,
            &mut duplicates,
            false,
        )
        .unwrap();
        assert_eq!((written, rejected, duplicates), (1, 0, 0));
        let txn = env.begin_ro().unwrap();
        assert_eq!(wok_negentropy::verify_tree(&txn, 1, "{}").unwrap(), 1);
        assert_eq!(wok_negentropy::verify_tree(&txn, 2, &filter).unwrap(), 0);
    }

    #[test]
    fn imported_events_update_legacy_zero_counter_trees() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config {
            db: dir.path().join("db"),
            ..Config::default()
        };
        let env = open_env(&cfg).unwrap();
        {
            let mut txn = env.begin_rw().unwrap();
            let mut meta =
                wok_db::decode_meta(txn.get_u64(env.dbis().meta, 1).unwrap().unwrap()).unwrap();
            meta.negentropy_modification_counter = 0;
            txn.put_u64(env.dbis().meta, 1, &wok_db::encode_meta(&meta), 0)
                .unwrap();
            txn.commit().unwrap();
        }
        let mut events = vec![signed_event(1)];
        let (mut written, mut rejected, mut duplicates) = (0, 0, 0);
        commit_import(
            &cfg,
            &env,
            &mut events,
            &mut written,
            &mut rejected,
            &mut duplicates,
            false,
        )
        .unwrap();
        assert_eq!((written, rejected, duplicates), (1, 0, 0));
        assert_eq!(
            wok_negentropy::verify_tree(&env.begin_ro().unwrap(), 1, "{}").unwrap(),
            1
        );
    }

    #[test]
    fn import_batches_hold_their_events_and_the_lines_read_for_them() {
        // Lines starting with x are rejected. Each batch holds two events
        // and the lines read to find them, sent here as
        // "events/lines/rejected".
        fn batches(input: &str) -> Vec<String> {
            let parse = |line: &str| {
                if line.starts_with('x') {
                    bail!("rejected");
                }
                Ok(EventToWrite::new(Vec::new(), line.to_owned()))
            };
            let mut sent = Vec::new();
            read_import_batches(input.as_bytes(), 2, 8, parse, |batch| {
                sent.push(match batch {
                    Ok(batch) => {
                        let events: Vec<_> = batch.events.into_iter().map(|e| e.json).collect();
                        format!("{}/{}/{}", events.join(","), batch.lines, batch.rejected)
                    }
                    Err(error) => error.to_string(),
                });
                true
            });
            sent
        }
        assert_eq!(
            batches("a\nx\nb\nc\nx\nx\nd\ne\n"),
            ["a,b/3/1", "c,d/4/2", "e/1/0"]
        );
        assert_eq!(batches("a\nb\n"), ["a,b/2/0"]);
        assert_eq!(batches("x\n"), ["/1/1"]);
        assert!(batches("").is_empty());
        // A line too long ends the import; the events read since the last
        // batch are not written.
        assert_eq!(
            batches("a\nb\nc\ntoo-long\nd\n"),
            [
                "a,b/2/0",
                "Line larger than configured maxEventSize on line 4"
            ]
        );
    }

    #[test]
    fn import_accepts_legacy_ids_from_stored_events() {
        // strfry and earlier Wok releases hashed U+007F as \u007f. Their
        // exports still verify on import; the NIP-01 form does too.
        let key = Keypair::new(SECP256K1, &mut rand::thread_rng());
        let mut event = json!({
            "created_at": 1_700_000_000u64,
            "kind": 1,
            "tags": [],
            "content": "del \u{7f}",
            "pubkey": hex::encode(key.x_only_public_key().0.serialize()),
        });
        let limits = EventLimits::default();
        for hash in [wok_event::legacy_event_id_hash, wok_event::event_id_hash] {
            let id = hash(&event).unwrap();
            event["id"] = json!(hex::encode(id));
            event["sig"] = json!(hex::encode(SECP256K1.sign_schnorr(&id, &key).as_ref()));
            let line = wok_event::json::to_tao_string(&event);
            assert!(line.contains("\\u007f"));
            assert!(parse_import_line(&line, false, false, &limits).is_ok());
        }
        event["id"] = json!("00".repeat(32));
        let line = wok_event::json::to_tao_string(&event);
        assert!(parse_import_line(&line, false, false, &limits).is_err());
    }

    #[test]
    fn import_refuses_deletion_a_tags_that_pad_the_kind() {
        // However a line arrives: JSON, verified or not, or fried, whose
        // packed record is taken as it is.
        let key = Keypair::new(SECP256K1, &mut rand::thread_rng());
        let pubkey = hex::encode(key.x_only_public_key().0.serialize());
        let limits = EventLimits::default();
        for (address, accepted) in [
            (format!("30000:{pubkey}:x"), true),
            (format!("030000:{pubkey}:x"), false),
        ] {
            let mut event = json!({
                "created_at": 1_700_000_000u64,
                "kind": 5,
                "tags": [["a", address]],
                "content": "",
                "pubkey": pubkey,
            });
            let id = wok_event::event_id_hash(&event).unwrap();
            event["id"] = json!(hex::encode(id));
            event["sig"] = json!(hex::encode(SECP256K1.sign_schnorr(&id, &key).as_ref()));
            let line = wok_event::json::to_tao_string(&event);
            let packed = wok_event::nostr_json_to_packed_event(&event, &limits).unwrap();
            let fried = format!(
                "{},\"fried\":\"{}\"}}",
                &line[..line.len() - 1],
                hex::encode(packed.as_bytes())
            );
            for (line, fried, no_verify) in [
                (&line, false, false),
                (&line, false, true),
                (&fried, true, false),
            ] {
                let result = parse_import_line(line, fried, no_verify, &limits);
                let context = format!("{address} fried={fried} no_verify={no_verify}");
                match result {
                    Ok(_) => assert!(accepted, "{context}"),
                    Err(error) => {
                        assert!(!accepted, "{context}: {error:#}");
                        assert!(format!("{error:#}").contains("leading zeros"), "{error:#}");
                    }
                }
            }
        }
    }

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
    fn import_builds_the_tag_kind_index_its_batches_left_out() {
        // One author's notes, reactions and follow lists, each list
        // replacing the one before, so that batches delete postings too.
        let key = Keypair::new(SECP256K1, &mut rand::thread_rng());
        let events: Vec<_> = (0..40u64)
            .map(|i| {
                let kind = [1u64, 7, 3][i as usize % 3];
                let mut event = json!({
                    "created_at": 1_700_000_000 + i,
                    "kind": kind,
                    "tags": [["p", format!("{:064x}", i % 5)], ["e", format!("{:064x}", i % 4)]],
                    "content": "",
                    "pubkey": hex::encode(key.x_only_public_key().0.serialize()),
                });
                let id = wok_event::event_id_hash(&event).unwrap();
                event["id"] = json!(hex::encode(id));
                event["sig"] = json!(hex::encode(SECP256K1.sign_schnorr(&id, &key).as_ref()));
                let parsed =
                    parse_and_verify_event(&event, &EventLimits::default(), None, true, false)
                        .unwrap();
                EventToWrite::new(parsed.packed.into_bytes(), parsed.json)
            })
            .collect();
        let postings = |env: &Env| {
            let txn = env.begin_ro().unwrap();
            let mut postings = Vec::new();
            txn.foreach_full(
                env.dbis().event_tag_kind.unwrap(),
                &[],
                &[],
                false,
                |key, value| {
                    postings.push((key.to_vec(), value.to_vec()));
                    true
                },
            )
            .unwrap();
            postings
        };

        let dir = tempfile::tempdir().unwrap();
        let cfg = Config {
            db: dir.path().join("db"),
            ..Config::default()
        };
        let env = open_env(&cfg).unwrap();
        let (mut written, mut rejected, mut duplicates) = (0, 0, 0);
        for chunk in events.chunks(16) {
            let deferred = commit_import(
                &cfg,
                &env,
                &mut chunk.to_vec(),
                &mut written,
                &mut rejected,
                &mut duplicates,
                false,
            )
            .unwrap();
            assert!(deferred);
        }
        assert_eq!((written, rejected, duplicates), (40, 0, 0));
        // Stopped here, the index is incomplete and the relay finishes it.
        let unbuilt = wok_db::tag_kind_index_state_ro(&env.begin_ro().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!((unbuilt.indexed_through, unbuilt.high_water), (0, 40));
        build_tag_kind_index(&env).unwrap();
        let report = check_integrity(&env.begin_ro().unwrap()).unwrap();
        assert!(report.ok(), "{:#?}", report.issues);
        let tag_kind = report.tag_kind_index.unwrap();
        assert!(tag_kind.complete && tag_kind.stale_entries == 0);

        // The same batches written as the relay writes them, posting each
        // event's entries, give the same table, markers included.
        let posted_dir = tempfile::tempdir().unwrap();
        let posted = Env::open(posted_dir.path(), EnvOptions::for_tests()).unwrap();
        posted.ensure_initialized().unwrap();
        for chunk in events.chunks(16) {
            let mut txn = posted.begin_rw().unwrap();
            write_events(&mut txn, &mut NoopNegentropy, &mut chunk.to_vec(), false).unwrap();
            txn.commit().unwrap();
        }
        assert_eq!(postings(&env), postings(&posted));
        // A later import into the built index posts as it writes.
        let mut later = vec![signed_event(1_800_000_000)];
        let deferred = commit_import(
            &cfg,
            &env,
            &mut later,
            &mut written,
            &mut rejected,
            &mut duplicates,
            false,
        )
        .unwrap();
        assert!(!deferred);
        assert!(wok_db::tag_kind_index_complete_ro(&env.begin_ro().unwrap()).unwrap());
    }

    #[test]
    fn negentropy_build_batches_are_idempotent_and_reject_zero_size() {
        let directory = tempfile::tempdir().unwrap();
        let env = Env::open(directory.path(), EnvOptions::for_tests()).unwrap();
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
        assert_eq!(tree.size().unwrap(), 5);
        assert!(build_negentropy_tree(&env, tree_id, 0)
            .unwrap_err()
            .to_string()
            .contains("at least 1"));
    }

    #[test]
    fn nip91_sync_post_filters_legacy_relay_results() {
        let filter = wok_query::NostrFilterGroup::from_value(
            &json!({"&t":["meme", "cat"], "#t":["meme", "cat", "black"]}),
            500,
            3,
            16,
        )
        .unwrap();
        let event = |tags: Vec<serde_json::Value>| {
            json!({
                "id":"11".repeat(32),
                "pubkey":"22".repeat(32),
                "created_at":1,
                "kind":1,
                "tags":tags,
                "content":"",
                "sig":"33".repeat(64)
            })
        };
        assert!(downloaded_event_matches(
            &filter,
            &event(vec![
                json!(["t", "meme"]),
                json!(["t", "cat"]),
                json!(["t", "black"])
            ]),
            &EventLimits::default(),
        ));
        assert!(!downloaded_event_matches(
            &filter,
            &event(vec![json!(["t", "meme"]), json!(["t", "cat"])]),
            &EventLimits::default(),
        ));

        let search = wok_query::NostrFilterGroup::from_value(
            &json!({"search":"needle", "&t":["meme", "cat"]}),
            500,
            3,
            16,
        )
        .unwrap();
        let mut searchable = event(vec![json!(["t", "meme"]), json!(["t", "cat"])]);
        searchable["content"] = json!("a sync needle");
        assert!(downloaded_event_matches(
            &search,
            &searchable,
            &EventLimits::default(),
        ));
    }

    #[test]
    fn download_prints_verified_events_including_legacy_ids() {
        let key = Keypair::new(SECP256K1, &mut rand::thread_rng());
        let mut event = json!({
            "created_at": 1_700_000_000u64,
            "kind": 1,
            "tags": [],
            "content": "del \u{7f}",
            "pubkey": hex::encode(key.x_only_public_key().0.serialize()),
        });
        let limits = EventLimits::default();
        for hash in [wok_event::legacy_event_id_hash, wok_event::event_id_hash] {
            let id = hash(&event).unwrap();
            event["id"] = json!(hex::encode(id));
            event["sig"] = json!(hex::encode(SECP256K1.sign_schnorr(&id, &key).as_ref()));
            assert_eq!(
                downloaded_event_json(&event, false, &limits).unwrap(),
                wok_event::json::to_tao_string(&event)
            );
        }
    }

    #[test]
    fn download_rejects_forged_events_unless_verification_is_off() {
        let event = signed_event(1_700_000_000);
        let event = wok_event::json::parse_strict(&event.json).unwrap();
        let limits = EventLimits::default();
        let mut forged_content = event.clone();
        forged_content["content"] = json!("forged");
        let mut forged_sig = event.clone();
        forged_sig["sig"] = json!("33".repeat(64));
        for forged in [&forged_content, &forged_sig] {
            assert!(downloaded_event_json(forged, false, &limits).is_err());
            assert_eq!(
                downloaded_event_json(forged, true, &limits).unwrap(),
                wok_event::json::to_tao_string(forged)
            );
        }
        // Verification off still refuses what is not an event.
        assert!(downloaded_event_json(&json!(null), true, &limits).is_err());
        assert!(downloaded_event_json(&json!({"kind": 1}), true, &limits).is_err());
    }

    #[test]
    fn download_treats_only_prefixed_notices_as_refusals() {
        for refusal in [
            "ERROR: bad msg: invalid filter",
            "auth-required: sign in first",
            "Restricted: members only",
            "rate-limited:",
        ] {
            assert!(notice_refuses(refusal), "{refusal}");
        }
        for other in [
            "",
            "Welcome to the relay",
            "errors are logged",
            "error",
            "é error: not a prefix",
        ] {
            assert!(!notice_refuses(other), "{other}");
        }
    }
}
