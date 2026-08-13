use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::io::BufRead;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use wok_db::{
    check_integrity, delete_events, event_json_owned, write_events, Decompressor, Env, EnvOptions,
    EventToWrite, NoopNegentropy,
};
use wok_event::{parse_and_verify_event, EventLimits};
use wok_negentropy::Storage;
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
    about = "Rust reimplementation of the strfry Nostr relay"
)]
struct Cli {
    /// Config file (HOCON subset, strfry.conf compatible)
    #[arg(long, short, global = true, default_value = "strfry.conf")]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    Relay,
    Info,
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
        #[arg(long)]
        config: Option<PathBuf>,
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
    let cli = Cli::parse();
    let cfg = load_cfg(&cli.config)?;
    match cli.cmd {
        Command::Relay => cmd_relay(cfg, cli.config.clone()).await,
        Command::Info => cmd_info(&cfg),
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
        Command::Sync { url, dir, filter } => cmd_sync(url, dir, filter).await,
        Command::Stream { url, dir } => cmd_stream(url, dir).await,
        Command::Upload { url, pipeline } => cmd_upload(url, pipeline).await,
        Command::Download { url, filter } => cmd_download(url, filter).await,
        Command::Router { .. } => {
            tracing::warn!("router is a compatibility stub; use stream/sync for mesh");
            Ok(())
        }
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
            let recips = monitors.process(lev, p);
            if let Some((cid, sid)) = &interest {
                if recips
                    .iter()
                    .any(|r| r.conn_id == *cid && r.sub_id.as_str() == sid)
                {
                    if let Ok(json) =
                        event_json_owned(&txn, &mut decomp, lev, cfg.events.max_event_size)
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

async fn cmd_sync(url: String, dir: String, filter: Option<String>) -> Result<()> {
    tracing::info!("sync {url} dir={dir} filter={filter:?} (initiator; uses NIP-77)");
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await?;
    let filter = filter.unwrap_or_else(|| "{}".into());
    let mut store = wok_negentropy::Vector::new();
    store.seal()?;
    let mut ne = wok_negentropy::Negentropy::new(store, 60_000)?;
    let init = ne.initiate()?;
    let open = serde_json::json!([
        "NEG-OPEN",
        "sync",
        serde_json::from_str::<serde_json::Value>(&filter)?,
        hex::encode(init)
    ]);
    ws.send(Message::Text(open.to_string().into())).await?;
    while let Some(msg) = ws.next().await {
        let msg = msg?;
        let txt = msg.to_text()?.to_string();
        let v: serde_json::Value = serde_json::from_str(&txt)?;
        if v[0] == "NEG-MSG" {
            let payload = wok_event::from_hex(v[2].as_str().unwrap_or(""))?;
            let mut have = Vec::new();
            let mut need = Vec::new();
            match ne.reconcile_with_ids(&payload, &mut have, &mut need)? {
                None => break,
                Some(next) => {
                    let m = serde_json::json!(["NEG-MSG", "sync", hex::encode(next)]);
                    ws.send(Message::Text(m.to_string().into())).await?;
                }
            }
            if dir == "none" {
                for id in &need {
                    println!("{}", hex::encode(id));
                }
            }
        } else if v[0] == "NEG-ERR" {
            bail!("negentropy error: {v}");
        }
    }
    Ok(())
}

async fn cmd_stream(url: String, dir: String) -> Result<()> {
    tracing::warn!("'wok stream' is deprecated. Please use 'wok router' instead.");
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await?;
    if dir == "down" || dir == "both" {
        ws.send(Message::Text(r#"["REQ","sub",{"limit":0}]"#.into()))
            .await?;
    }
    while let Some(msg) = ws.next().await {
        let txt = msg?.to_text()?.to_string();
        println!("{txt}");
    }
    Ok(())
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
