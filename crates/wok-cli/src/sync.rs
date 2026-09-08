//! Operator-initiated NIP-77 reconciliation with explicit transfer outcomes.
use super::*;
use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{HashSet, VecDeque};
use std::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::Message;

#[derive(clap::Args)]
pub struct Options {
    pub url: String,
    #[arg(long, default_value = "both", value_parser = ["both", "up", "down", "none"])]
    pub dir: String,
    #[arg(long)]
    pub filter: Option<String>,
    /// Add since/until: START-END, e.g. 2M- or 1Y-3w.
    #[arg(long)]
    pub range: Option<String>,
    /// Print have/need IDs without transferring events (implies --dir=none).
    #[arg(long, conflicts_with = "json")]
    pub print_missing: bool,
    /// Compare without transfers and exit nonzero if either side has missing IDs.
    #[arg(long)]
    pub check: bool,
    /// Emit a JSON summary on stdout, including on transfer/protocol failure.
    #[arg(long)]
    pub json: bool,
    #[arg(long, default_value_t = 60_000)]
    pub frame_size_limit: u64,
    /// Abort after this many seconds without protocol progress (0 disables).
    #[arg(long, default_value_t = 60)]
    pub timeout: u64,
}

#[derive(Default, Serialize)]
struct Report {
    ok: bool,
    reconciled: bool,
    have: u64,
    need: u64,
    downloaded: u64,
    written: u64,
    duplicates: u64,
    superseded: u64,
    rejected: u64,
    unavailable: u64,
    uploaded: u64,
    upload_rejected: u64,
    upload_superseded: u64,
    error: Option<String>,
}

pub async fn run(cfg: &Config, options: Options) -> Result<()> {
    let mut report = Report::default();
    let result = transfer(cfg, &options, &mut report).await;
    report.ok = result.is_ok();
    report.error = result.as_ref().err().map(|e| format!("{e:#}"));
    if options.json {
        // Do not turn a failed sync into success when its consumer closes stdout.
        use std::io::Write;
        writeln!(
            std::io::stdout().lock(),
            "{}",
            serde_json::to_string(&report)?
        )?;
    } else {
        eprintln!("Sync {}: reconciled={} have={} need={} downloaded={} written={} duplicates={} superseded={} rejected={} unavailable={} uploaded={} upload_rejected={} upload_superseded={}",
            if report.ok { "complete" } else { "failed" }, report.reconciled,
            report.have, report.need, report.downloaded, report.written, report.duplicates, report.superseded,
            report.rejected, report.unavailable, report.uploaded, report.upload_rejected, report.upload_superseded);
    }
    result
}

fn store_downloads(
    env: &Env,
    cfg: &Config,
    events: &mut Vec<Value>,
    report: &mut Report,
) -> Result<()> {
    let mut writes = Vec::with_capacity(events.len());
    for event in events.drain(..) {
        let policy = cfg.timestamp_policy_for_kind(event["kind"].as_u64().unwrap_or(u64::MAX));
        match parse_and_verify_event(&event, &cfg.event_limits(), Some(&policy), true, true) {
            Ok(parsed) => writes.push(EventToWrite::new(parsed.packed.into_bytes(), parsed.json)),
            Err(error) => {
                report.rejected += 1;
                tracing::warn!(%error, "sync download rejected");
            }
        }
    }
    if writes.is_empty() {
        return Ok(());
    }
    let mut txn = env.begin_rw()?;
    let mut cache = wok_negentropy::NegentropyFilterCache::new(cfg.relay.max_tags_per_filter);
    let mut sink = cache.batch();
    write_events_with_policy(
        &mut txn,
        &mut sink,
        &mut writes,
        false,
        &cfg.vanish_policy(),
    )?;
    sink.flush(&mut txn)?;
    txn.commit()?;
    for event in writes {
        match event.status {
            wok_db::EventWriteStatus::Written => report.written += 1,
            wok_db::EventWriteStatus::Duplicate => report.duplicates += 1,
            wok_db::EventWriteStatus::Replaced => report.superseded += 1,
            status => {
                report.rejected += 1;
                tracing::warn!(?status, "sync download not stored");
            }
        }
    }
    Ok(())
}

async fn transfer(cfg: &Config, options: &Options, report: &mut Report) -> Result<()> {
    let compare = options.print_missing || options.check || options.dir == "none";
    let do_up = !compare && (options.dir == "both" || options.dir == "up");
    let do_down = !compare && (options.dir == "both" || options.dir == "down");
    let url = &options.url;
    let frame_size_limit = options.frame_size_limit;
    let mut filter_json = wok_event::json::parse_strict(options.filter.as_deref().unwrap_or("{}"))?;
    if let Some(range) = &options.range {
        process_range_option(range, &mut filter_json)?;
    }
    let filter_group = wok_query::NostrFilterGroup::from_value(
        &filter_json,
        u64::MAX,
        cfg.relay.max_tags_per_filter,
        cfg.relay.max_and_entries,
    )?;
    let env = open_env(cfg)?;
    // Prefer a precomputed tree whose canonical (time-stripped) filter
    // matches, like C++.
    enum SyncStorage {
        Tree(u64),
        Vector(wok_negentropy::Vector),
    }
    let mut storage = {
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
        let tree_visible = wok_query::visibility::physical_tree_is_globally_visible(
            &txn,
            &filter_group.filters[0],
        )?;
        match tree_id.filter(|_| tree_visible) {
            Some(id) => {
                wok_negentropy::verify_tree(&txn, id, &canonical)?;
                SyncStorage::Tree(id)
            }
            None => {
                // Match the relay's conservative construction budget. Falling
                // back from a physical tree must not allocate an unbounded view.
                let per_item =
                    wok_negentropy::memory_view_item_bytes(filter_group.requires_content());
                let memory_budget = cfg
                    .relay
                    .sync_memory_per_connection
                    .min(cfg.relay.sync_memory_total);
                let view_budget = memory_budget.checked_sub(wok_negentropy::ROUND_MEMORY_BYTES)
                    .ok_or_else(|| anyhow::anyhow!("filtered sync requires at least {} bytes of sync_memory_per_connection and sync_memory_total for protocol rounds", wok_negentropy::ROUND_MEMORY_BYTES))?;
                // The overflow sentinel is also stored during construction.
                let memory_cap = (view_budget / per_item).saturating_sub(1);
                let cap = cfg.relay.max_sync_events.min(memory_cap);
                let mut levs = Vec::new();
                foreach_by_filter_scan(
                    &txn,
                    &filter_json,
                    cap.saturating_add(1),
                    cfg.relay.max_tags_per_filter,
                    cfg.relay.max_and_entries,
                    |lev| levs.push(lev),
                )?;
                if levs.len() as u64 > cap {
                    bail!("filtered sync view exceeds event/memory budget ({cap} events); narrow the filter or review relay.max_sync_events and sync_memory settings");
                }
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

    let initiate = |env: &Env, storage: &mut SyncStorage| -> Result<Vec<u8>> {
        let txn = env.begin_ro()?;
        match storage {
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
                let sub = wok_negentropy::SubRange::new(&mut tree, &lower, &upper)
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                let mut ne = wok_negentropy::Negentropy::new(sub, frame_size_limit)
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                ne.initiate().map_err(|e| anyhow::anyhow!(e.to_string()))
            }
            SyncStorage::Vector(v) => {
                let mut ne = wok_negentropy::Negentropy::new(v, frame_size_limit)
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                ne.initiate().map_err(|e| anyhow::anyhow!(e.to_string()))
            }
        }
    };
    let reconcile = |env: &Env,
                     storage: &mut SyncStorage,
                     payload: &[u8],
                     have: &mut Vec<Vec<u8>>,
                     need: &mut Vec<Vec<u8>>|
     -> Result<Option<Vec<u8>>> {
        let txn = env.begin_ro()?;
        match storage {
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
                let sub = wok_negentropy::SubRange::new(&mut tree, &lower, &upper)
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                let mut ne = wok_negentropy::Negentropy::new(sub, frame_size_limit)
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                ne.set_initiator();
                ne.reconcile_with_ids(payload, have, need)
                    .map_err(|e| anyhow::anyhow!(e.to_string()))
            }
            SyncStorage::Vector(v) => {
                let mut ne = wok_negentropy::Negentropy::new(v, frame_size_limit)
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                ne.set_initiator();
                ne.reconcile_with_ids(payload, have, need)
                    .map_err(|e| anyhow::anyhow!(e.to_string()))
            }
        }
    };

    let connect = mesh::connect_mesh(url, cfg.events.max_event_size);
    let capability_filter = mesh::outbound_filter_for_relay(url, &filter_json);
    let (ws, remote_filter) = tokio::join!(connect, capability_filter);
    let mut ws = ws?;
    let remote_filter = remote_filter?;
    let init = initiate(&env, &mut storage)?;
    let open = serde_json::json!(["NEG-OPEN", "N", remote_filter, hex::encode(init)]);
    ws.send(Message::Text(open.to_string().into())).await?;

    // Deduplication spans the whole reconciliation, including already-transferred IDs.
    const MAX_SYNC_IDS: usize = 5_000_000;
    let mut have = VecDeque::new();
    let mut need = VecDeque::new();
    let mut seen_have = HashSet::new();
    let mut seen_need = HashSet::new();
    let mut pending_up = HashSet::<String>::new();
    let mut pending_down = HashSet::<String>::new();
    let mut down_active = false;
    let mut batch = Vec::new();
    let mut last_progress = Instant::now();
    loop {
        if options.timeout > 0 && last_progress.elapsed().as_secs() >= options.timeout {
            store_downloads(&env, cfg, &mut batch, report)?;
            bail!(
                "Sync timed out: no protocol progress for {} seconds",
                options.timeout
            );
        }
        let message = match tokio::time::timeout(Duration::from_secs(1), ws.next()).await {
            Ok(Some(message)) => message?,
            Ok(None) => bail!("sync connection closed before completion"),
            Err(_) => continue,
        };
        let text = match message {
            Message::Text(text) => text.to_string(),
            Message::Ping(payload) => {
                ws.send(Message::Pong(payload)).await?;
                continue;
            }
            Message::Close(_) => bail!("sync connection closed before completion"),
            _ => continue,
        };
        let reply: Value = wok_event::json::parse_strict(&text)?;
        match reply[0].as_str().unwrap_or("") {
            "NEG-MSG" if reply[1] == "N" && !report.reconciled => {
                let payload = wok_event::from_hex_strict(
                    reply[2].as_str().context("missing NEG-MSG payload")?,
                )?;
                let (mut current_have, mut current_need) = (Vec::new(), Vec::new());
                let next = reconcile(
                    &env,
                    &mut storage,
                    &payload,
                    &mut current_have,
                    &mut current_need,
                )?;
                for id in current_have {
                    if seen_have.insert(id.clone()) && do_up {
                        have.push_back(id);
                    }
                }
                for id in current_need {
                    if seen_need.insert(id.clone()) && do_down {
                        need.push_back(id);
                    }
                }
                report.have = seen_have.len() as u64;
                report.need = seen_need.len() as u64;
                if seen_have.len() + seen_need.len() > MAX_SYNC_IDS {
                    bail!("sync peer exceeded {MAX_SYNC_IDS} unique differences; use narrower filters");
                }
                match next {
                    Some(next) => {
                        ws.send(Message::Text(
                            json!(["NEG-MSG", "N", hex::encode(next)])
                                .to_string()
                                .into(),
                        ))
                        .await?
                    }
                    None => {
                        report.reconciled = true;
                        ws.send(Message::Text(json!(["NEG-CLOSE", "N"]).to_string().into()))
                            .await?;
                    }
                }
                last_progress = Instant::now();
            }
            "OK" => {
                let id = reply[1].as_str().unwrap_or("");
                let accepted = reply[2]
                    .as_bool()
                    .context("malformed sync upload acknowledgment")?;
                if pending_up.remove(id) {
                    if accepted {
                        report.uploaded += 1;
                    } else if reply[3]
                        .as_str()
                        .is_some_and(|message| message.starts_with("replaced:"))
                    {
                        report.upload_superseded += 1;
                    } else {
                        report.upload_rejected += 1;
                    }
                    last_progress = Instant::now();
                }
            }
            "EVENT" if reply[1] == "R" && down_active => {
                let event = reply.get(2).context("missing sync event")?;
                let id = event["id"].as_str().unwrap_or("");
                if pending_down.remove(id) {
                    report.downloaded += 1;
                    if downloaded_event_matches(&filter_group, event, &cfg.event_limits()) {
                        batch.push(event.clone());
                    } else {
                        report.rejected += 1;
                    }
                    last_progress = Instant::now();
                }
            }
            "EOSE" if reply[1] == "R" && down_active => {
                report.unavailable += pending_down.len() as u64;
                pending_down.clear();
                down_active = false;
                store_downloads(&env, cfg, &mut batch, report)?;
                ws.send(Message::Text(json!(["CLOSE", "R"]).to_string().into()))
                    .await?;
                last_progress = Instant::now();
            }
            "CLOSED" if reply[1] == "R" => bail!("sync download subscription closed: {}", reply[2]),
            "NEG-ERR" if reply[1] == "N" => bail!("sync reconciliation rejected: {}", reply[2]),
            "NOTICE" => bail!("sync peer NOTICE: {}", reply[1]),
            "AUTH" => {
                // A challenge alone is not a rejection: public kinds may still be readable.
                tracing::debug!(
                    "sync peer advertises AUTH; this operator client has no signing identity"
                );
            }
            _ => {}
        }
        if do_up && pending_up.len() <= 50 && !have.is_empty() {
            let mut outgoing = Vec::new();
            {
                let txn = env.begin_ro()?;
                let mut decompressor = Decompressor::new();
                while pending_up.len() + outgoing.len() < 100 {
                    let Some(id) = have.pop_front() else { break };
                    if let Some((lev, raw)) = wok_db::lookup_event_by_id_ro(&txn, &id)? {
                        let packed = PackedEventView::new(&raw)?;
                        if !wok_query::visibility::ReadVisibility::default()
                            .globally_visible(&txn, packed)?
                        {
                            // Classify only a hidden event: visible uploads need
                            // one replacement lookup. Other visibility changes
                            // mean the negotiated transfer is incomplete, and
                            // retain the existing non-success outcome.
                            if wok_db::is_event_superseded_ro(&txn, packed)? {
                                report.upload_superseded += 1;
                            } else {
                                report.unavailable += 1;
                            }
                            continue;
                        }
                        let event = event_json_owned(
                            &txn,
                            &mut decompressor,
                            lev,
                            cfg.events.max_event_size,
                        )?;
                        outgoing.push((hex::encode(id), format!("[\"EVENT\",{event}]")));
                    } else {
                        report.unavailable += 1;
                    }
                }
            }
            for (id, event) in outgoing {
                ws.send(Message::Text(event.into())).await?;
                pending_up.insert(id);
            }
        }
        if do_down && !down_active && !need.is_empty() {
            let ids: Vec<_> = need.drain(..need.len().min(50)).map(hex::encode).collect();
            pending_down.extend(ids.iter().cloned());
            ws.send(Message::Text(
                json!(["REQ", "R", {"ids":ids}]).to_string().into(),
            ))
            .await?;
            down_active = true;
        }
        if report.reconciled
            && have.is_empty()
            && need.is_empty()
            && pending_up.is_empty()
            && !down_active
        {
            if options.print_missing {
                use std::io::Write;
                let stdout = std::io::stdout();
                let mut output = stdout.lock();
                for (label, ids) in [("have", &seen_have), ("need", &seen_need)] {
                    let mut ids: Vec<_> = ids.iter().collect();
                    ids.sort();
                    for id in ids {
                        writeln!(output, "{label},{}", hex::encode(id))?;
                    }
                }
            }
            if report.rejected + report.unavailable + report.upload_rejected > 0 {
                bail!("sync incomplete: rejected/unavailable events remain; inspect summary and retry after resolving policy or source changes");
            }
            if options.check && report.have + report.need > 0 {
                bail!(
                    "sync sets differ: have {} need {}",
                    report.have,
                    report.need
                );
            }
            return Ok(());
        }
    }
}
