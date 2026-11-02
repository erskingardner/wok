//! Single-writer mutation, publication receipts and maintenance.
use super::*;
use crate::protocol::SUPERSEDED_OK_REASON;
use std::time::Instant;
use wok_db::SEARCH_BUILD_BUSY_LAG;

/// Bounds on one `(tag, kind, created_at)` backfill transaction. The writer
/// runs one before each batch of messages it takes, so a publication waits
/// behind at most one.
#[derive(Clone, Copy)]
pub(super) struct TagKindStep {
    pub(super) max_entries: usize,
    pub(super) budget: Duration,
}

/// A step stops after 10 ms of indexing, plus its commit, so publications
/// during a backfill are acknowledged about as fast as without one.
pub(super) const TAG_KIND_STEP: TagKindStep = TagKindStep {
    max_entries: wok_db::TAG_KIND_STEP_ENTRIES,
    budget: wok_db::TAG_KIND_STEP_BUDGET,
};
/// How often a running backfill logs its progress.
const TAG_KIND_PROGRESS_INTERVAL: Duration = Duration::from_secs(10);

/// A writer that receives no message for this long is idle, and builds.
const SEARCH_BUILD_IDLE: Duration = Duration::from_millis(20);
/// A build that starts this far behind logs its start, progress and end.
const SEARCH_BUILD_LOG_LAG: u64 = 10_000;

pub(super) fn run_writer(
    env: Env,
    cfg: Arc<parking_lot::RwLock<Config>>,
    conns: Arc<ConnTable>,
    metrics: Arc<Metrics>,
    rx: Receiver<WriterMsg>,
    mon_txs: Vec<Sender<MonitorData>>,
    moderation: Arc<parking_lot::RwLock<ModerationSnapshot>>,
    tag_kind_step: TagKindStep,
) {
    let mut plugin = PluginEventSifter::new(cfg.read().relay.write_policy_timeout_secs);
    let mut negentropy_cache = NegentropyFilterCache::default();
    let mut batch = Vec::with_capacity(WRITER_BATCH_MAX);
    let mut event_batch = Vec::with_capacity(WRITER_BATCH_MAX);
    let mut maintenance_cursor = wok_db::VanishSweepCursor::default();
    let mut batch_vanish: HashMap<[u8; 32], u64> = HashMap::new();
    let mut events: Vec<EventToWrite<u64>> = Vec::with_capacity(256);
    // Bytes of committed events the req monitors still hold.
    let stored_in_flight = Arc::new(AtomicUsize::new(0));
    let mut tag_kind = TagKindBackfill::new(tag_kind_step);
    tag_kind.recheck(&env, &metrics, cfg.read().relay.tag_kind_index_enabled);
    let mut search = SearchBuild::new();
    search.recheck(&env, &metrics, cfg.read().relay.search_enabled);
    let mut storage_writes = ThreadStorageWrites::open();
    let mut stop = false;
    while !stop {
        // While the index is behind, each pass indexes one bounded batch
        // first, and an idle writer keeps going until it is complete.
        let msg = if tag_kind.pending() {
            let reserve = cfg.read().db_min_free_disk_bytes;
            tag_kind.step(&env, &metrics, reserve);
            match rx.try_recv() {
                Ok(msg) => msg,
                Err(crossbeam_channel::TryRecvError::Empty) => continue,
                Err(crossbeam_channel::TryRecvError::Disconnected) => break,
            }
        } else if search.lag() >= SEARCH_BUILD_BUSY_LAG && search.pending() {
            // Far enough behind: one step before each batch, as for the
            // tag-kind index.
            let reserve = cfg.read().db_min_free_disk_bytes;
            search.step(&env, &metrics, reserve);
            match rx.try_recv() {
                Ok(msg) => msg,
                Err(crossbeam_channel::TryRecvError::Empty) => continue,
                Err(crossbeam_channel::TryRecvError::Disconnected) => break,
            }
        } else if search.pending() {
            // Behind by a little: build once the writer is idle.
            match rx.recv_timeout(SEARCH_BUILD_IDLE) {
                Ok(msg) => msg,
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                    let reserve = cfg.read().db_min_free_disk_bytes;
                    search.step(&env, &metrics, reserve);
                    continue;
                }
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
            }
        } else {
            let Ok(msg) = rx.recv() else { break };
            msg
        };
        let batch_started = Instant::now();
        let queued = rx.len() as u64 + 1;
        batch.clear();
        event_batch.clear();
        batch_vanish.clear();
        events.clear();
        batch.push(msg);
        while batch.len() < WRITER_BATCH_MAX {
            match rx.try_recv() {
                Ok(more) => batch.push(more),
                Err(_) => break,
            }
        }
        // Management mutations take priority over every event in the drained
        // batch. This closes the same-batch race where an event queued just
        // before a ban/revocation could otherwise pass its stored-state
        // recheck and be committed after the management command returned.
        let mut maintenance_requested = false;
        for m in batch.drain(..) {
            if let WriterMsg::Management(msg) = m {
                let blocks = matches!(msg.cmd, ManagementCmd::BlockIp { .. });
                let result = apply_management(&env, &moderation, msg.cmd);
                // Before the reply, so the manager hears of the block once its
                // address's connections are told to close.
                if blocks && result.is_ok() {
                    let closed = conns.kill_blocked(&moderation.read().blocked_ips);
                    if closed > 0 {
                        tracing::info!(closed, "closed connections from a blocked IP address");
                    }
                }
                let _ = msg.reply.send(result);
            } else if matches!(m, WriterMsg::Maintenance) {
                maintenance_requested = true;
            } else if matches!(m, WriterMsg::Stop) {
                // Finish this batch; anything queued behind Stop is dropped.
                stop = true;
            } else {
                event_batch.push(m);
            }
        }
        let cfg_snap = cfg.read().clone();
        plugin.set_timeout(cfg_snap.relay.write_policy_timeout_secs);
        search.set_enabled(cfg_snap.relay.search_enabled);
        tag_kind.set_enabled(cfg_snap.relay.tag_kind_index_enabled);
        if maintenance_requested {
            run_maintenance(&env, &cfg_snap, &mut maintenance_cursor);
            tag_kind.recheck(&env, &metrics, cfg_snap.relay.tag_kind_index_enabled);
            search.recheck(&env, &metrics, cfg_snap.relay.search_enabled);
        }
        let vanish_policy = cfg_snap.vanish_policy();
        // A valid vanish request and an ephemeral gift wrap can arrive in the
        // same drained writer batch. Compute the batch markers up front so a
        // live-only event cannot be broadcast immediately before its request
        // is persisted later in that batch.
        for m in &event_batch {
            let WriterMsg::AddEvent { packed, json, .. } = m else {
                continue;
            };
            let Ok(event) = PackedEventView::new(packed) else {
                continue;
            };
            // Exact JSON tag-name inspection is only needed for kind 62.
            // Parsing every ordinary event again made publication pay for a
            // feature-specific slow path before the kind was even checked.
            if event.kind() != VANISH_KIND || !vanish_policy.targets_this_relay_json(json) {
                continue;
            }
            let mut pubkey = [0u8; 32];
            pubkey.copy_from_slice(event.pubkey());
            batch_vanish
                .entry(pubkey)
                .and_modify(|timestamp| *timestamp = (*timestamp).max(event.created_at()))
                .or_insert(event.created_at());
        }
        // A validated event is committed even when its connection closed in
        // the same batch; only its OK goes nowhere. C++ RelayWriter drops
        // such events, losing posts from clients that disconnect right after
        // publishing. `Close` therefore needs no writer state.
        for m in event_batch.drain(..) {
            if let WriterMsg::AddEvent {
                conn_id,
                source,
                packed,
                json,
                authed,
                grant,
            } = m
            {
                let mut ok_msg = String::new();
                let is_vanish_request =
                    PackedEventView::new(&packed).is_ok_and(|event| event.kind() == VANISH_KIND);
                // NIP-62: relays that restrict who can post MUST honor vanish
                // regardless of the user's status, so the plugin cannot veto it.
                let res = if is_vanish_request || cfg_snap.relay.write_policy_plugin.is_empty() {
                    PluginResult::Accept
                } else {
                    // Transport metadata remains separate from NIP-42 auth.
                    // Event JSON is parsed only when a plugin will consume it;
                    // the normal empty-plugin path remains packed.
                    let source_type = source.plugin_type();
                    let source_info = source.plugin_info();
                    let ev_json: Value = serde_json::from_str(&json).unwrap_or(json!({}));
                    plugin.accept_event(
                        &cfg_snap.relay.write_policy_plugin,
                        &ev_json,
                        source_type,
                        &source_info,
                        authed.as_ref().map(|a| a.as_slice()),
                        &mut ok_msg,
                    )
                };
                if res == PluginResult::Accept {
                    {
                        let packed_view = match PackedEventView::new(&packed) {
                            Ok(event) => event,
                            Err(error) => {
                                conns.send(
                                    conn_id,
                                    RelayMessage::Ok {
                                        event_id: "?".into(),
                                        accepted: false,
                                        message: format!("invalid: {error}"),
                                    },
                                    &metrics,
                                );
                                continue;
                            }
                        };
                        let stored_checks = env.begin_ro().and_then(|txn| {
                            // Recheck moderation and the write policy's
                            // member against committed state: a ban or
                            // revocation may have landed after the
                            // ingester's snapshot check. Vanish requests
                            // bypass their own markers, the author ban and
                            // write restrictions (NIP-62: honored regardless
                            // of the user's status), but not event-id bans or
                            // the kind policy.
                            Ok::<_, wok_db::DbError>(if is_vanish_request {
                                (
                                    false,
                                    moderation_reason_ignoring_author_ro(&txn, packed_view)?,
                                    true,
                                )
                            } else {
                                (
                                    wok_db::is_event_vanished_ro_with_json(
                                        &txn,
                                        packed_view,
                                        &json,
                                    )?,
                                    moderation_reason_ro(&txn, packed_view)?,
                                    grant.stored_admits(&txn, &cfg_snap, packed_view.kind())?,
                                )
                            })
                        });
                        let (vanished, moderated, write_allowed) = match stored_checks {
                            // `accepted_kinds` as the writer's configuration
                            // has it, like the stored kind policy. Only the
                            // first is a setting.
                            Ok((vanished, moderated, write_allowed)) => (
                                vanished
                                    || event_matches_vanish_markers(
                                        packed_view,
                                        &batch_vanish,
                                        &json,
                                    ),
                                moderated.map(|reason| (reason, None)).or((!cfg_snap
                                    .accepts_kind(packed_view.kind()))
                                .then_some((
                                    wok_db::ModerationReason::KindNotAllowed,
                                    Some(Setting::AcceptedKinds),
                                ))),
                                write_allowed,
                            ),
                            Err(error) => {
                                conns.send(
                                    conn_id,
                                    RelayMessage::Ok {
                                        event_id: to_hex(packed_view.id()),
                                        accepted: false,
                                        message: format!("error: {error}"),
                                    },
                                    &metrics,
                                );
                                continue;
                            }
                        };
                        if vanished {
                            let id_hex = PackedEventView::new(&packed)
                                .map(|event| to_hex(event.id()))
                                .unwrap_or_else(|_| "?".into());
                            conns.send(
                                conn_id,
                                RelayMessage::Ok {
                                    event_id: id_hex,
                                    accepted: false,
                                    message: "blocked: author or recipient requested vanish".into(),
                                },
                                &metrics,
                            );
                            continue;
                        }
                        if let Some((reason, setting)) = moderated {
                            if let Some(setting) = setting {
                                metrics.refused(setting);
                            }
                            let (counter, message) = match reason {
                                wok_db::ModerationReason::BannedEvent => (
                                    &metrics.moderation_banned_event_rejections,
                                    "restricted: event is banned by the relay operator".to_string(),
                                ),
                                wok_db::ModerationReason::BannedAuthor => (
                                    &metrics.moderation_banned_author_rejections,
                                    "restricted: author is banned by the relay operator"
                                        .to_string(),
                                ),
                                wok_db::ModerationReason::KindNotAllowed => (
                                    &metrics.moderation_kind_rejections,
                                    format!(
                                        "restricted: kind {} is not allowed by this relay",
                                        packed_view.kind()
                                    ),
                                ),
                            };
                            counter.fetch_add(1, Ordering::Relaxed);
                            let id_hex = PackedEventView::new(&packed)
                                .map(|event| to_hex(event.id()))
                                .unwrap_or_else(|_| "?".into());
                            conns.send(
                                conn_id,
                                RelayMessage::Ok {
                                    event_id: id_hex,
                                    accepted: false,
                                    message,
                                },
                                &metrics,
                            );
                            continue;
                        }
                        if !write_allowed {
                            metrics
                                .moderation_restricted_write_rejections
                                .fetch_add(1, Ordering::Relaxed);
                            metrics.refused(Setting::WritePolicy);
                            let id_hex = PackedEventView::new(&packed)
                                .map(|event| to_hex(event.id()))
                                .unwrap_or_else(|_| "?".into());
                            conns.send(
                                conn_id,
                                RelayMessage::Ok {
                                    event_id: id_hex,
                                    accepted: false,
                                    message: grant.refusal(&cfg_snap),
                                },
                                &metrics,
                            );
                            continue;
                        }
                        // What nobody could read, as the writer's
                        // configuration has it: a reload may have made AUTH
                        // unusable since the ingester's check.
                        if let Some(class) = cfg_snap.unreadable_class(packed_view.kind()) {
                            if let Some(setting) = Setting::of_read_class(class) {
                                metrics.refused(setting);
                            }
                            conns.send(
                                conn_id,
                                RelayMessage::Ok {
                                    event_id: to_hex(packed_view.id()),
                                    accepted: false,
                                    message: format!(
                                        "restricted: kind {} is read only after AUTH, which \
                                         this relay does not offer",
                                        packed_view.kind()
                                    ),
                                },
                                &metrics,
                            );
                            continue;
                        }
                        // The author's AUTH, as the writer's configuration
                        // requires it: a reload may have made AUTH unusable,
                        // or moved the kind into `owner_only_kinds`, since
                        // the ingester's check.
                        if let Err(message) = check_author_auth(
                            &cfg_snap,
                            &metrics,
                            packed_view,
                            &grant,
                            grant.challenged,
                        ) {
                            conns.send(
                                conn_id,
                                RelayMessage::Ok {
                                    event_id: to_hex(packed_view.id()),
                                    accepted: false,
                                    message,
                                },
                                &metrics,
                            );
                            continue;
                        }
                    }
                    let is_live_only = cfg_snap.events.ephemeral_persistence
                        == EphemeralPersistence::LiveOnly
                        && PackedEventView::new(&packed)
                            .map(|event| event.expiration() == 1)
                            .unwrap_or(false);
                    if is_live_only {
                        let id_hex = PackedEventView::new(&packed)
                            .map(|event| to_hex(event.id()))
                            .unwrap_or_else(|_| "?".into());
                        broadcast_ephemeral(&mon_txs, HeldEvent { packed, json });
                        metrics
                            .ephemeral_events_total
                            .fetch_add(1, Ordering::Relaxed);
                        conns.send(
                            conn_id,
                            RelayMessage::Ok {
                                event_id: id_hex,
                                accepted: true,
                                message: String::new(),
                            },
                            &metrics,
                        );
                    } else {
                        events.push(EventToWrite::new(packed, json).with_context(conn_id));
                    }
                } else {
                    metrics.refused(Setting::WritePolicyPlugin);
                    let id_hex = PackedEventView::new(&packed)
                        .map(|p| to_hex(p.id()))
                        .unwrap_or_else(|_| "?".into());
                    conns.send(
                        conn_id,
                        RelayMessage::Ok {
                            event_id: id_hex,
                            accepted: res == PluginResult::ShadowReject,
                            message: ok_msg,
                        },
                        &metrics,
                    );
                }
            }
        }
        if events.is_empty() {
            continue;
        }
        if cfg_snap.db_min_free_disk_bytes != 0 {
            match env.available_disk_bytes() {
                Ok(available) if available < cfg_snap.db_min_free_disk_bytes => {
                    metrics
                        .abuse_disk_reserve_rejections
                        .fetch_add(events.len() as u64, Ordering::Relaxed);
                    metrics
                        .refusals
                        .add(Setting::MinFreeDiskBytes, events.len() as u64);
                    for event in &events {
                        let conn_id = &event.context;
                        let id_hex = PackedEventView::new(&event.packed)
                            .map(|event| to_hex(event.id()))
                            .unwrap_or_else(|_| "?".into());
                        conns.send(
                            *conn_id,
                            RelayMessage::Ok {
                                event_id: id_hex,
                                accepted: false,
                                message: format!(
                                    "error: disk reserve requires {} free bytes",
                                    cfg_snap.db_min_free_disk_bytes
                                ),
                            },
                            &metrics,
                        );
                    }
                    continue;
                }
                Err(error) => {
                    for event in &events {
                        let conn_id = &event.context;
                        let id_hex = PackedEventView::new(&event.packed)
                            .map(|event| to_hex(event.id()))
                            .unwrap_or_else(|_| "?".into());
                        conns.send(
                            *conn_id,
                            RelayMessage::Ok {
                                event_id: id_hex,
                                accepted: false,
                                message: format!("error: disk space check failed: {error}"),
                            },
                            &metrics,
                        );
                    }
                    continue;
                }
                _ => {}
            }
        }
        let report_capacity =
            MAX_MODERATION_RECORDS.saturating_sub(moderation.read().reported_events.len());
        let global_quota = if cfg_snap.relay.abuse.enabled {
            cfg_snap.relay.abuse.max_stored_events
        } else {
            0
        };
        // NIP-62 requires a vanish request that targets this relay to be
        // honored whatever the user's status, so the global quota does not
        // count the ones a batch records and never refuses a batch for them.
        let honors_vanish = |event: &EventToWrite<u64>| {
            vanish_policy.enabled
                && PackedEventView::new(&event.packed).is_ok_and(|e| e.kind() == VANISH_KIND)
        };
        let records_vanish = |event: &EventToWrite<u64>| {
            event.status == EventWriteStatus::Written && honors_vanish(event)
        };
        // A copy of a request the batch recorded, or of one already stored,
        // is answered `duplicate:`, as the batch without the quota would.
        let keeps_vanish = |event: &EventToWrite<u64>| {
            matches!(
                event.status,
                EventWriteStatus::Written | EventWriteStatus::Duplicate
            ) && honors_vanish(event)
        };
        let write_started = Instant::now();
        let storage_before = storage_writes.bytes();
        let mut commit_started = None;
        // `None` when the global quota refuses the batch.
        let mut write_batch = |events: &mut Vec<EventToWrite<u64>>| {
            let mut txn = env.begin_rw()?;
            if !cfg_snap.relay.tag_kind_index_enabled {
                wok_db::skip_tag_kind_postings(&mut txn);
            }
            let mut tree_batch = negentropy_cache.batch();
            wok_db::write::write_events_with_quota(
                &mut txn,
                &mut tree_batch,
                events,
                &vanish_policy,
                if cfg_snap.relay.abuse.enabled {
                    cfg_snap.relay.abuse.max_stored_events_per_pubkey
                } else {
                    0
                },
            )?;
            tree_batch
                .flush(&mut txn)
                .map_err(|e| wok_db::DbError::msg(e.to_string()))?;
            let report_updates = record_reports(&mut txn, events, report_capacity);
            if global_quota != 0 {
                let vanishing = events.iter().filter(|e| records_vanish(e)).count();
                let written = events
                    .iter()
                    .filter(|e| e.status == EventWriteStatus::Written)
                    .count();
                let stored = txn
                    .entries(txn.env().dbis().event)?
                    .saturating_sub(vanishing);
                if written > vanishing && stored as u64 > global_quota {
                    return Ok(None);
                }
            }
            commit_started = Some(Instant::now());
            txn.commit()?;
            Ok::<_, wok_db::DbError>(Some(report_updates))
        };
        let mut write_res = write_batch(&mut events);
        if matches!(write_res, Ok(None)) {
            // The quota refuses everything else in the batch, and the
            // vanish requests it held are written on their own.
            let (vanishing, refused): (Vec<_>, Vec<_>) = events.drain(..).partition(keeps_vanish);
            metrics
                .abuse_global_quota_rejections
                .fetch_add(refused.len() as u64, Ordering::Relaxed);
            metrics
                .refusals
                .add(Setting::MaxStoredEvents, refused.len() as u64);
            for event in &refused {
                let id_hex = PackedEventView::new(&event.packed)
                    .map(|p| to_hex(p.id()))
                    .unwrap_or_else(|_| "?".into());
                conns.send(
                    event.context,
                    RelayMessage::Ok {
                        event_id: id_hex,
                        accepted: false,
                        message: format!(
                            "error: global storage quota of {global_quota} events exceeded"
                        ),
                    },
                    &metrics,
                );
            }
            events.extend(vanishing.into_iter().map(|mut event| {
                event.status = EventWriteStatus::Pending;
                event.lev_id = 0;
                event
            }));
            if !events.is_empty() {
                write_res = write_batch(&mut events);
            }
        }
        let committed = Instant::now();
        let report_updates = match write_res {
            Ok(Some(report_updates)) => report_updates,
            // Nothing in the batch was left to write.
            Ok(None) => continue,
            Err(error) => {
                // The transaction aborted; nothing was written this batch.
                for event in &events {
                    let conn_id = &event.context;
                    let id_hex = PackedEventView::new(&event.packed)
                        .map(|p| to_hex(p.id()))
                        .unwrap_or_else(|_| "?".into());
                    conns.send(
                        *conn_id,
                        RelayMessage::Ok {
                            event_id: id_hex,
                            accepted: false,
                            message: format!("error: {error}"),
                        },
                        &metrics,
                    );
                }
                continue;
            }
        };
        // Only batches that committed are measured, so every series counts
        // the same batches.
        let commit_started = commit_started.unwrap_or(committed);
        metrics.writer_queue_depth.observe(queued);
        metrics
            .writer_prepare
            .observe(write_started - batch_started);
        metrics.writer_write.observe(commit_started - write_started);
        metrics.writer_commit.observe(committed - commit_started);
        let stored = events
            .iter()
            .filter(|event| matches!(event.status, EventWriteStatus::Written))
            .count();
        metrics.writer_commit_events.observe(stored as u64);
        let newest = events
            .iter()
            .filter(|event| matches!(event.status, EventWriteStatus::Written))
            .map(|event| event.lev_id)
            .max();
        if let Some(newest) = newest {
            search.note_stored(newest, &metrics);
        }
        if let (Some(before), Some(after)) = (storage_before, storage_writes.bytes()) {
            metrics
                .writer_storage_bytes_total
                .fetch_add(after.saturating_sub(before), Ordering::Relaxed);
        }
        let reply_started = Instant::now();
        if !report_updates.is_empty() {
            // The writer serializes both management commands and report
            // inserts, so committed deltas can update the snapshot directly.
            let mut snapshot = moderation.write();
            for (id, reason) in report_updates {
                snapshot.reported_events.insert(id, reason);
            }
        }
        for event in &events {
            let conn_id = &event.context;
            let packed = PackedEventView::new(&event.packed).ok();
            let id_hex = packed
                .as_ref()
                .map(|p| to_hex(p.id()))
                .unwrap_or_else(|| "?".into());
            let (written, message) = match event.status {
                EventWriteStatus::Written => {
                    metrics.written_events_total.fetch_add(1, Ordering::Relaxed);
                    (true, String::new())
                }
                EventWriteStatus::Duplicate => {
                    metrics.dup_events_total.fetch_add(1, Ordering::Relaxed);
                    (true, "duplicate: have this event".into())
                }
                EventWriteStatus::Replaced => {
                    metrics
                        .rejected_events_total
                        .fetch_add(1, Ordering::Relaxed);
                    (false, SUPERSEDED_OK_REASON.into())
                }
                EventWriteStatus::Deleted => {
                    metrics
                        .rejected_events_total
                        .fetch_add(1, Ordering::Relaxed);
                    (false, "blocked: user requested deletion".into())
                }
                EventWriteStatus::QuotaExceeded => {
                    metrics
                        .abuse_pubkey_quota_rejections
                        .fetch_add(1, Ordering::Relaxed);
                    metrics.refused(Setting::MaxStoredEventsPerPubkey);
                    (false, "blocked: author storage quota exceeded".into())
                }
                EventWriteStatus::Pending => (false, "error: write still pending".into()),
            };
            conns.send(
                *conn_id,
                RelayMessage::Ok {
                    event_id: id_hex,
                    accepted: written,
                    message,
                },
                &metrics,
            );
        }
        broadcast_stored(&mon_txs, &stored_in_flight, &mut events);
        metrics.writer_reply.observe(reply_started.elapsed());
    }
}

/// What the calling thread has sent to storage, from Linux's
/// `/proc/thread-self/io`, so the writer can count the bytes its
/// transactions write. Elsewhere, or when the file cannot be read, nothing.
struct ThreadStorageWrites {
    file: Option<std::fs::File>,
    text: String,
}

impl ThreadStorageWrites {
    /// Open the file for the calling thread, which is the one it measures.
    fn open() -> Self {
        Self {
            file: std::fs::File::open("/proc/thread-self/io").ok(),
            text: String::new(),
        }
    }

    /// The thread's `write_bytes` so far.
    fn bytes(&mut self) -> Option<u64> {
        use std::io::{Read, Seek, SeekFrom};
        let file = self.file.as_mut()?;
        file.seek(SeekFrom::Start(0)).ok()?;
        self.text.clear();
        file.read_to_string(&mut self.text).ok()?;
        // A loop, not a closure, so the reachability baselines blessed where
        // there is no `/proc` (macOS) match the ones checked on Linux.
        for line in self.text.lines() {
            if let Some(value) = line.strip_prefix("write_bytes:") {
                return value.trim().parse().ok();
            }
        }
        None
    }
}

/// Builds `wok_Event__tagKind` in the background, one bounded write
/// transaction at a time: by a key-ordered pass for a database from before
/// the index, and in local-id order for the events an earlier release
/// inserted. Nothing is built while `relay.tag_kind_index_enabled` is off.
pub(super) struct TagKindBackfill {
    step: TagKindStep,
    enabled: bool,
    pending: bool,
    paused_for_disk: bool,
    run: Option<TagKindBackfillRun>,
}

struct TagKindBackfillRun {
    started: std::time::Instant,
    last_log: std::time::Instant,
    entries: u64,
    slowest: Duration,
}

impl TagKindBackfill {
    pub(super) fn new(step: TagKindStep) -> Self {
        Self {
            step,
            enabled: false,
            pending: false,
            paused_for_disk: false,
            run: None,
        }
    }

    /// Whether a step would index anything.
    pub(super) fn pending(&self) -> bool {
        self.enabled && self.pending
    }

    pub(super) fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Read where the index stands and start a backfill if it is behind.
    /// The writer does this at start and on every maintenance tick: another
    /// process, such as an earlier release's `wok import`, may have stored
    /// events without entries.
    pub(super) fn recheck(&mut self, env: &Env, metrics: &Metrics, enabled: bool) {
        self.enabled = enabled;
        let state = env.begin_ro().and_then(|txn| {
            let tag_entries = txn.entries(txn.env().dbis().event_tag)? as u64;
            Ok(wok_db::tag_kind_index_state_ro(&txn)?.map(|state| (state, tag_entries)))
        });
        match state {
            Ok(Some((state, tag_entries))) => {
                publish_tag_kind_state(metrics, state, tag_entries);
                if state.schema == Some(wok_db::TAG_KIND_SCHEMA_VERSION) && !state.complete() {
                    self.pending = true;
                }
            }
            Ok(None) => {}
            Err(error) => tracing::warn!(%error, "could not read the tag-kind index state"),
        }
    }

    /// Index one bounded step in its own write transaction, unless free disk
    /// space is below `min_free_disk_bytes`, the reserve that also refuses
    /// publications: the build then waits for a maintenance tick that finds
    /// the space.
    pub(super) fn step(&mut self, env: &Env, metrics: &Metrics, min_free_disk_bytes: u64) {
        if min_free_disk_bytes != 0 {
            let available = env.available_disk_bytes();
            if !matches!(available, Ok(bytes) if bytes >= min_free_disk_bytes) {
                if !self.paused_for_disk {
                    match available {
                        Ok(bytes) => tracing::warn!(
                            available = bytes,
                            reserve = min_free_disk_bytes,
                            "pausing the (tag, kind, created_at) index build: free disk space is below database.min_free_disk_bytes"
                        ),
                        Err(error) => tracing::warn!(
                            %error,
                            "pausing the (tag, kind, created_at) index build: free disk space could not be checked"
                        ),
                    }
                }
                self.paused_for_disk = true;
                self.pending = false;
                return;
            }
            if std::mem::take(&mut self.paused_for_disk) {
                tracing::info!("resuming the (tag, kind, created_at) index build");
            }
        }
        let started = std::time::Instant::now();
        let result = (|| {
            let mut txn = env.begin_rw()?;
            let step =
                wok_db::backfill_tag_kind_index(&mut txn, self.step.max_entries, self.step.budget)?;
            txn.commit()?;
            Ok::<_, wok_db::DbError>(step)
        })();
        let elapsed = started.elapsed();
        let step = match result {
            Ok(Some(step)) => step,
            Ok(None) => {
                self.pending = false;
                return;
            }
            Err(error) => {
                // The next maintenance tick retries, rather than a tight loop.
                tracing::error!(%error, "tag-kind index backfill transaction aborted");
                self.pending = false;
                self.run = None;
                return;
            }
        };
        let state = step.state;
        tracing::debug!(
            entries = step.entries,
            prepared = step.prepared,
            ms = elapsed.as_secs_f64() * 1000.0,
            "tag-kind index backfill step"
        );
        publish_tag_kind_state(metrics, state, step.tag_entries);
        metrics
            .tag_kind_backfill_entries_total
            .fetch_add(step.entries, Ordering::Relaxed);
        metrics.tag_kind_backfill_micros_total.fetch_add(
            u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        let complete = state.complete();
        if self.run.is_none() && !(complete && step.entries == 0) {
            match state.bulk_pass {
                Some(_) => tracing::info!(
                    tag_entries = step.tag_entries,
                    high_water = state.high_water,
                    "building the (tag, kind, created_at) index in the background, in key order"
                ),
                None => tracing::info!(
                    indexed_through = state.indexed_through,
                    high_water = state.high_water,
                    "indexing stored events missing from the (tag, kind, created_at) index in the background"
                ),
            }
            self.run = Some(TagKindBackfillRun {
                started,
                last_log: started,
                entries: 0,
                slowest: Duration::ZERO,
            });
        }
        if let Some(run) = self.run.as_mut() {
            run.entries += step.entries;
            run.slowest = run.slowest.max(elapsed);
            if complete {
                tracing::info!(
                    entries = run.entries,
                    seconds = run.started.elapsed().as_secs_f64(),
                    slowest_step_ms = run.slowest.as_secs_f64() * 1000.0,
                    high_water = state.high_water,
                    "the (tag, kind, created_at) index is complete"
                );
                self.run = None;
            } else if run.last_log.elapsed() >= TAG_KIND_PROGRESS_INTERVAL {
                run.last_log = std::time::Instant::now();
                match state.bulk_pass {
                    Some(pass) => tracing::info!(
                        visited = pass.visited,
                        tag_entries = step.tag_entries,
                        entries = run.entries,
                        "tag-kind index build progress"
                    ),
                    None => tracing::info!(
                        indexed_through = state.indexed_through,
                        high_water = state.high_water,
                        entries = run.entries,
                        "tag-kind index backfill progress"
                    ),
                }
            }
        }
        self.pending = !complete;
    }
}

/// The NIP-50 search index's background build. Publishing writes no
/// postings: the writer indexes the events above the index's marker in
/// transactions of their own, whenever it is idle, and before each batch
/// once [`SEARCH_BUILD_BUSY_LAG`] events wait, so each step indexes many at
/// once. Nothing is built while search is off.
pub(super) struct SearchBuild {
    enabled: bool,
    /// Where the index stands: read at start and on each maintenance tick,
    /// then moved by each step and each committed batch, as only this writer
    /// moves the marker.
    state: Option<wok_db::SearchIndexState>,
    /// Free disk space ran short, or a step failed: no steps until a
    /// maintenance tick rechecks.
    stalled: bool,
    paused_for_disk: bool,
    run: Option<SearchBuildRun>,
}

struct SearchBuildRun {
    started: std::time::Instant,
    last_log: std::time::Instant,
    events: u64,
    slowest: Duration,
}

impl SearchBuild {
    pub(super) fn new() -> Self {
        Self {
            enabled: false,
            state: None,
            stalled: false,
            paused_for_disk: false,
            run: None,
        }
    }

    /// Events stored above the marker.
    pub(super) fn lag(&self) -> u64 {
        self.state.map_or(0, |state| state.lag())
    }

    /// Whether a step would index anything.
    pub(super) fn pending(&self) -> bool {
        self.enabled && !self.stalled && self.lag() > 0
    }

    pub(super) fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Read where the index stands. The writer does this at start and on
    /// every maintenance tick, which also retries a stalled build.
    pub(super) fn recheck(&mut self, env: &Env, metrics: &Metrics, enabled: bool) {
        self.enabled = enabled;
        self.stalled = false;
        match env
            .begin_ro()
            .and_then(|txn| wok_db::search_index_state_ro(&txn))
        {
            Ok(state) => {
                self.state = state;
                self.publish(metrics);
            }
            Err(error) => tracing::warn!(%error, "could not read the search index state"),
        }
    }

    /// A batch committed, storing events up to local id `newest`.
    pub(super) fn note_stored(&mut self, newest: u64, metrics: &Metrics) {
        if let Some(state) = self.state.as_mut() {
            state.high_water = state.high_water.max(newest);
            self.publish(metrics);
        }
    }

    fn publish(&self, metrics: &Metrics) {
        metrics
            .search_index_lag_events
            .store(self.lag(), Ordering::Relaxed);
    }

    /// Index one bounded step in its own write transaction, unless free disk
    /// space is below `min_free_disk_bytes`, the reserve that also refuses
    /// publications: the build then waits for a maintenance tick that finds
    /// the space.
    pub(super) fn step(&mut self, env: &Env, metrics: &Metrics, min_free_disk_bytes: u64) {
        if min_free_disk_bytes != 0 {
            let available = env.available_disk_bytes();
            if !matches!(available, Ok(bytes) if bytes >= min_free_disk_bytes) {
                if !self.paused_for_disk {
                    match available {
                        Ok(bytes) => tracing::warn!(
                            available = bytes,
                            reserve = min_free_disk_bytes,
                            "pausing the search index build: free disk space is below database.min_free_disk_bytes"
                        ),
                        Err(error) => tracing::warn!(
                            %error,
                            "pausing the search index build: free disk space could not be checked"
                        ),
                    }
                }
                self.paused_for_disk = true;
                self.stalled = true;
                return;
            }
            if std::mem::take(&mut self.paused_for_disk) {
                tracing::info!("resuming the search index build");
            }
        }
        let lag_before = self.lag();
        let started = std::time::Instant::now();
        let result = (|| {
            let mut txn = env.begin_rw()?;
            let step = wok_db::build_search_index(
                &mut txn,
                wok_db::SEARCH_BUILD_STEP_EVENTS,
                wok_db::SEARCH_BUILD_STEP_BUDGET,
            )?;
            txn.commit()?;
            Ok::<_, wok_db::DbError>(step)
        })();
        let elapsed = started.elapsed();
        let step = match result {
            Ok(Some(step)) => step,
            Ok(None) => {
                self.state = None;
                self.publish(metrics);
                return;
            }
            Err(error) => {
                // The next maintenance tick retries, rather than a tight loop.
                tracing::error!(%error, "search index build transaction aborted");
                self.stalled = true;
                self.run = None;
                return;
            }
        };
        self.state = Some(step.state);
        self.publish(metrics);
        metrics
            .search_index_build_events_total
            .fetch_add(step.events, Ordering::Relaxed);
        metrics.search_index_build_micros_total.fetch_add(
            u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        let lag = step.state.lag();
        if self.run.is_none() && lag_before >= SEARCH_BUILD_LOG_LAG {
            tracing::info!(
                indexed_through = step.state.indexed_through,
                high_water = step.state.high_water,
                "building the search index in the background"
            );
            self.run = Some(SearchBuildRun {
                started,
                last_log: started,
                events: 0,
                slowest: Duration::ZERO,
            });
        }
        if let Some(run) = self.run.as_mut() {
            run.events += step.events;
            run.slowest = run.slowest.max(elapsed);
            if lag < SEARCH_BUILD_BUSY_LAG {
                tracing::info!(
                    events = run.events,
                    seconds = run.started.elapsed().as_secs_f64(),
                    slowest_step_ms = run.slowest.as_secs_f64() * 1000.0,
                    lag,
                    "the search index has caught up"
                );
                self.run = None;
            } else if run.last_log.elapsed() >= TAG_KIND_PROGRESS_INTERVAL {
                run.last_log = std::time::Instant::now();
                tracing::info!(
                    indexed_through = step.state.indexed_through,
                    high_water = step.state.high_water,
                    events = run.events,
                    "search index build progress"
                );
            }
        }
    }
}

fn publish_tag_kind_state(metrics: &Metrics, state: wok_db::TagKindIndexState, tag_entries: u64) {
    metrics
        .tag_kind_index_complete
        .store(u64::from(state.complete()), Ordering::Relaxed);
    metrics
        .tag_kind_indexed_through
        .store(state.indexed_through, Ordering::Relaxed);
    metrics
        .tag_kind_high_water
        .store(state.high_water, Ordering::Relaxed);
    metrics.tag_kind_pass_visited.store(
        state.bulk_pass.map_or(0, |pass| pass.visited),
        Ordering::Relaxed,
    );
    metrics
        .tag_kind_tag_entries
        .store(tag_entries, Ordering::Relaxed);
}

/// NIP-56 report kind; accepted reports feed the NIP-86 moderation queue.
pub(super) const REPORT_KIND: u64 = 1984;
/// Most `e` tags harvested from one report event.
const MAX_REPORT_TARGETS: usize = 64;

/// Record NIP-86 moderation-queue entries for kind 1984 reports written in
/// this batch. Runs inside the same transaction so a stored report and its
/// queue entries commit atomically. Queue-cap exhaustion is logged once per
/// batch, never fatal to the event write. Returns the committed snapshot
/// deltas without rescanning the moderation table.
pub(super) fn record_reports<C>(
    txn: &mut wok_db::RwTxn<'_>,
    evs: &[EventToWrite<C>],
    mut new_records_remaining: usize,
) -> HashMap<[u8; 32], String> {
    let mut updates = HashMap::new();
    let mut capacity_warned = false;
    for ev in evs {
        if ev.status != EventWriteStatus::Written {
            continue;
        }
        let Ok(packed) = PackedEventView::new(&ev.packed) else {
            continue;
        };
        if packed.kind() != REPORT_KIND {
            continue;
        }
        let content = serde_json::from_str::<Value>(&ev.json)
            .ok()
            .and_then(|event| {
                event
                    .get("content")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_default();
        let reason = report_reason(packed.pubkey(), &content);
        let mut targets = 0usize;
        packed.foreach_tag(|name, value| {
            if name == 'e' && value.len() == 32 && targets < MAX_REPORT_TARGETS {
                let mut id = [0u8; 32];
                id.copy_from_slice(value);
                match report_event(txn, &id, &reason, &mut new_records_remaining) {
                    Ok(true) => {
                        updates.insert(id, reason.clone());
                    }
                    Ok(false) if !capacity_warned => {
                        capacity_warned = true;
                        tracing::warn!(
                            limit = MAX_MODERATION_RECORDS,
                            "moderation queue capacity reached; dropping new targets"
                        );
                    }
                    Ok(false) => {}
                    Err(error) => {
                        tracing::warn!(event_id = %to_hex(&id), %error, "moderation queue insert failed")
                    }
                }
                targets += 1;
            }
            true
        });
    }
    updates
}

pub(super) fn report_reason(pubkey: &[u8], content: &str) -> String {
    let mut reason = format!("reported by {}", to_hex(pubkey));
    if content.is_empty() {
        return reason;
    }
    reason.push_str(": ");
    for ch in content.chars().take(200) {
        if reason.len().saturating_add(ch.len_utf8()) > MAX_REASON_BYTES {
            break;
        }
        reason.push(ch);
    }
    reason
}

/// Apply a NIP-86 management mutation on the writer thread: commit to LMDB,
/// then atomically refresh the in-memory snapshot used by ingest and
/// connection admission.
pub(super) fn apply_management(
    env: &Env,
    moderation: &parking_lot::RwLock<ModerationSnapshot>,
    cmd: ManagementCmd,
) -> Result<(), String> {
    let mut txn = env.begin_rw().map_err(|e| e.to_string())?;
    cmd.apply(&mut txn).map_err(|e| e.to_string())?;
    txn.commit().map_err(|e| e.to_string())?;
    let snap = env
        .begin_ro()
        .and_then(|txn| load_moderation_snapshot_ro(&txn))
        .map_err(|e| e.to_string())?;
    *moderation.write() = snap;
    Ok(())
}

pub(super) fn event_matches_vanish_markers(
    packed: PackedEventView<'_>,
    markers: &HashMap<[u8; 32], u64>,
    json: &str,
) -> bool {
    if packed.kind() != VANISH_KIND {
        let mut author = [0u8; 32];
        author.copy_from_slice(packed.pubkey());
        if markers
            .get(&author)
            .is_some_and(|timestamp| packed.created_at() <= *timestamp)
            && !wok_db::is_deletion_protected_json(packed, json).unwrap_or(false)
        {
            return true;
        }
    }
    if GIFT_WRAP_KINDS.contains(&packed.kind()) {
        let mut matched = false;
        packed.foreach_tag(|name, value| {
            if name == 'p' && value.len() == 32 {
                let mut recipient = [0u8; 32];
                recipient.copy_from_slice(value);
                if markers.get(&recipient).is_some_and(|timestamp| {
                    wok_db::gift_wrap_vanished(packed.created_at(), *timestamp)
                }) {
                    matched = true;
                    return false;
                }
            }
            true
        });
        if matched {
            return true;
        }
    }
    false
}

pub(super) fn run_cron(writer: Sender<WriterMsg>, shutdown: Arc<AtomicBool>) {
    while sleep_unless_shutdown(&shutdown, Duration::from_secs(2)) {
        if writer.try_send(WriterMsg::Maintenance).is_err() && writer.is_full() {
            tracing::debug!("writer busy; maintenance deferred");
        }
    }
}

pub(super) fn run_maintenance(
    env: &Env,
    cfg_snap: &Config,
    vanish_cursor: &mut wok_db::VanishSweepCursor,
) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let ephemeral_cutoff = now.saturating_sub(cfg_snap.events.ephemeral_lifetime_secs);
    let mut expired = Vec::new();
    if let Ok(txn) = env.begin_ro() {
        let _ = txn.foreach_full(
            txn.env().dbis().event_expiration,
            &0u64.to_ne_bytes(),
            &0u64.to_ne_bytes(),
            false,
            |k, v| {
                if k.len() != 8 || v.len() != 8 {
                    return true;
                }
                let expiration = u64::from_ne_bytes(k.try_into().unwrap());
                let lev = u64::from_ne_bytes(v.try_into().unwrap());
                if expiration > now {
                    return false;
                }
                if expiration == 1 {
                    if let Ok(Some(buf)) = wok_db::get_packed_ro(&txn, lev) {
                        if let Ok(p) = PackedEventView::new(&buf) {
                            if p.created_at() <= ephemeral_cutoff {
                                expired.push(lev);
                            }
                        }
                    }
                } else {
                    expired.push(lev);
                }
                expired.len() < cfg_snap.relay.nip62.deletion_batch_size
            },
        );
    }
    let mut next_cursor = vanish_cursor.clone();
    let result = (|| -> Result<(u64, u64), wok_db::DbError> {
        let mut txn = env.begin_rw()?;
        let mut sink = DeferredSink::default();
        let expired_deleted = wok_db::delete_events(&mut txn, &mut sink, expired)?;
        let vanished_deleted = sweep_vanished_events(
            &mut txn,
            &mut sink,
            cfg_snap.relay.nip62.deletion_batch_size,
            &mut next_cursor,
        )?
        .deleted;
        let mut cache = NegentropyFilterCache::default();
        sink.apply(&mut cache, &mut txn)
            .map_err(|e| wok_db::DbError::msg(e.to_string()))?;
        txn.commit()?;
        Ok((expired_deleted, vanished_deleted))
    })();
    match result {
        Ok((expired_deleted, vanished_deleted)) => {
            *vanish_cursor = next_cursor;
            if expired_deleted > 0 || vanished_deleted > 0 {
                tracing::info!(
                    expired_deleted,
                    vanished_deleted,
                    "relay maintenance deleted events"
                );
            }
        }
        Err(error) => tracing::error!(%error, "relay maintenance transaction aborted"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wok_event::{PackedEventBuilder, PackedEventTagBuilder};

    #[test]
    fn events_from_connections_closed_in_the_same_batch_are_committed() {
        // A publisher that sends EVENT and disconnects at once has its EVENT
        // and its Close drained by the writer together. The validated event
        // must still be stored; only its OK has nowhere to go.
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), wok_db::EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let config = Config {
            db: dir.path().to_path_buf(),
            ..Config::default()
        };
        let moderation = Arc::new(parking_lot::RwLock::new(
            env.begin_ro()
                .and_then(|txn| load_moderation_snapshot_ro(&txn))
                .unwrap(),
        ));
        const PUBLISHERS: u64 = 8;
        let (writer_tx, writer_rx) = bounded(2 * PUBLISHERS as usize);
        for conn_id in 1..=PUBLISHERS {
            let id = [conn_id as u8; 32];
            let author = [0x40 + conn_id as u8; 32];
            let packed = PackedEventBuilder::build(
                &id,
                &author,
                1_700_000_000,
                1,
                0,
                &PackedEventTagBuilder::default(),
            )
            .unwrap();
            let json = json!({
                "id": to_hex(&id),
                "pubkey": to_hex(&author),
                "created_at": 1_700_000_000u64,
                "kind": 1,
                "tags": [],
                "content": "",
                "sig": "00".repeat(64),
            })
            .to_string();
            writer_tx
                .send(WriterMsg::AddEvent {
                    conn_id,
                    source: TransportSource::ip_address("127.0.0.1".parse().unwrap()),
                    packed: packed.into_bytes(),
                    json,
                    authed: None,
                    grant: Default::default(),
                })
                .unwrap();
            writer_tx.send(WriterMsg::Close { conn_id }).unwrap();
        }
        drop(writer_tx);

        let metrics = Arc::new(Metrics::default());
        run_writer(
            env.clone(),
            Arc::new(parking_lot::RwLock::new(config)),
            Arc::new(ConnTable::new()),
            metrics.clone(),
            writer_rx,
            Vec::new(),
            moderation,
            TAG_KIND_STEP,
        );

        let txn = env.begin_ro().unwrap();
        assert_eq!(txn.entries(env.dbis().event).unwrap(), PUBLISHERS as usize);
        // Everything was queued before the writer started, so it took one
        // batch and committed once.
        assert_eq!(metrics.writer_queue_depth.count(), 1);
        assert_eq!(metrics.writer_queue_depth.sum(), 2 * PUBLISHERS);
        assert_eq!(metrics.writer_commit_events.sum(), PUBLISHERS);
        for steps in [
            &metrics.writer_prepare,
            &metrics.writer_write,
            &metrics.writer_commit,
            &metrics.writer_reply,
        ] {
            assert_eq!(steps.count(), 1);
        }
        // A temporary directory may be on tmpfs, which counts no storage
        // writes, so check only that Linux reports the counter.
        if cfg!(target_os = "linux") {
            assert!(ThreadStorageWrites::open().bytes().is_some());
        }
    }

    /// An unsigned kind 1 from its own author; the writer does not check
    /// signatures.
    fn note(n: u8) -> WriterMsg {
        let (id, author) = ([n; 32], [0x40 + n; 32]);
        let packed = PackedEventBuilder::build(
            &id,
            &author,
            1_700_000_000,
            1,
            0,
            &PackedEventTagBuilder::default(),
        )
        .unwrap();
        let json = json!({
            "id": to_hex(&id),
            "pubkey": to_hex(&author),
            "created_at": 1_700_000_000u64,
            "kind": 1,
            "tags": [],
            "content": "",
            "sig": "00".repeat(64),
        })
        .to_string();
        WriterMsg::AddEvent {
            conn_id: u64::from(n),
            source: TransportSource::ip_address("127.0.0.1".parse().unwrap()),
            packed: packed.into_bytes(),
            json,
            authed: None,
            grant: Default::default(),
        }
    }

    /// Runs a writer over `messages`, all queued before it starts, and
    /// returns its metrics.
    fn write_all(config: Config, env: &Env, messages: Vec<WriterMsg>) -> Arc<Metrics> {
        let moderation = Arc::new(parking_lot::RwLock::new(
            env.begin_ro()
                .and_then(|txn| load_moderation_snapshot_ro(&txn))
                .unwrap(),
        ));
        let (writer_tx, writer_rx) = bounded(messages.len());
        for message in messages {
            writer_tx.send(message).unwrap();
        }
        drop(writer_tx);
        let metrics = Arc::new(Metrics::default());
        run_writer(
            env.clone(),
            Arc::new(parking_lot::RwLock::new(config)),
            Arc::new(ConnTable::new()),
            metrics.clone(),
            writer_rx,
            Vec::new(),
            moderation,
            TAG_KIND_STEP,
        );
        metrics
    }

    #[test]
    fn writer_metrics_count_committed_batches_and_stored_events() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), wok_db::EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let config = Config {
            db: dir.path().to_path_buf(),
            ..Config::default()
        };
        // Three events and a copy of the first, one batch.
        let metrics = write_all(config, &env, vec![note(1), note(2), note(3), note(1)]);
        assert_eq!(metrics.writer_queue_depth.count(), 1);
        assert_eq!(metrics.writer_queue_depth.sum(), 4);
        assert_eq!(
            metrics.writer_commit_events.sum(),
            3,
            "the copy stored nothing"
        );
        for step in [
            &metrics.writer_prepare,
            &metrics.writer_write,
            &metrics.writer_commit,
            &metrics.writer_reply,
        ] {
            assert_eq!(step.count(), 1);
        }
    }

    /// An unsigned event `id` from `author`, sent by connection `conn_id`.
    /// A vanish request names every relay.
    fn copy_of(conn_id: u64, id: u8, author: [u8; 32], created_at: u64, kind: u64) -> WriterMsg {
        let mut tags = PackedEventTagBuilder::default();
        if wok_event::is_replaceable_kind(kind) {
            tags.add('d', b"").unwrap();
        }
        let packed =
            PackedEventBuilder::build(&[id; 32], &author, created_at, kind, 0, &tags).unwrap();
        let json = json!({
            "id": to_hex(&[id; 32]),
            "pubkey": to_hex(&author),
            "created_at": created_at,
            "kind": kind,
            "tags": if kind == VANISH_KIND { json!([["relay", "ALL_RELAYS"]]) } else { json!([]) },
            "content": "",
            "sig": "00".repeat(64),
        })
        .to_string();
        WriterMsg::AddEvent {
            conn_id,
            source: TransportSource::ip_address("127.0.0.1".parse().unwrap()),
            packed: packed.into_bytes(),
            json,
            authed: None,
            grant: Default::default(),
        }
    }

    /// The `[accepted, message]` of the OK each of `copies`' connections
    /// gets when the writer takes them in one batch.
    fn replies_to(config: Config, env: &Env, copies: Vec<WriterMsg>) -> Vec<Value> {
        let conns = Arc::new(ConnTable::new());
        let mut receivers = Vec::new();
        for copy in &copies {
            let WriterMsg::AddEvent { conn_id, .. } = copy else {
                unreachable!()
            };
            let (out, rx) = tokio::sync::mpsc::unbounded_channel();
            conns.insert(*conn_id, Outbound::new(out, 0));
            receivers.push(rx);
        }
        let moderation = Arc::new(parking_lot::RwLock::new(
            env.begin_ro()
                .and_then(|txn| load_moderation_snapshot_ro(&txn))
                .unwrap(),
        ));
        let (writer_tx, writer_rx) = bounded(copies.len());
        for copy in copies {
            writer_tx.send(copy).unwrap();
        }
        drop(writer_tx);
        run_writer(
            env.clone(),
            Arc::new(parking_lot::RwLock::new(config)),
            conns,
            Arc::new(Metrics::default()),
            writer_rx,
            Vec::new(),
            moderation,
            TAG_KIND_STEP,
        );
        receivers
            .iter_mut()
            .map(|rx| {
                let ok: Value = serde_json::from_str(&rx.try_recv().unwrap().into_text()).unwrap();
                json!([ok[2], ok[3]])
            })
            .collect()
    }

    #[test]
    fn every_copy_in_one_batch_is_answered_like_the_first() {
        let author = [0x55; 32];
        let fresh = || {
            let dir = tempfile::tempdir().unwrap();
            let env = Env::open(dir.path(), wok_db::EnvOptions::for_tests()).unwrap();
            env.ensure_initialized().unwrap();
            let mut config = Config {
                db: dir.path().to_path_buf(),
                ..Config::default()
            };
            config.db_min_free_disk_bytes = 0;
            (dir, env, config)
        };

        // Stored, then a copy from each of two connections.
        let (_dir, env, config) = fresh();
        let replies = replies_to(
            config,
            &env,
            vec![copy_of(1, 1, author, 100, 1), copy_of(2, 1, author, 100, 1)],
        );
        assert_eq!(
            replies,
            [
                json!([true, ""]),
                json!([true, "duplicate: have this event"])
            ]
        );

        // Superseded by a stored newer version: neither copy is a duplicate.
        let (_dir, env, config) = fresh();
        replies_to(
            config.clone(),
            &env,
            vec![copy_of(1, 1, author, 200, 10002)],
        );
        let replies = replies_to(
            config,
            &env,
            vec![
                copy_of(1, 2, author, 100, 10002),
                copy_of(2, 2, author, 100, 10002),
            ],
        );
        let superseded = json!([false, SUPERSEDED_OK_REASON]);
        assert_eq!(replies, [superseded.clone(), superseded]);

        // The author is at the per-author quota.
        let (_dir, env, mut config) = fresh();
        config.relay.abuse.enabled = true;
        config.relay.abuse.max_stored_events_per_pubkey = 1;
        replies_to(config.clone(), &env, vec![copy_of(1, 1, author, 100, 1)]);
        let replies = replies_to(
            config,
            &env,
            vec![copy_of(1, 2, author, 200, 1), copy_of(2, 2, author, 200, 1)],
        );
        let over_quota = json!([false, "blocked: author storage quota exceeded"]);
        assert_eq!(replies, [over_quota.clone(), over_quota]);
        assert_eq!(
            env.begin_ro().unwrap().entries(env.dbis().event).unwrap(),
            1
        );

        // Refusals made before the write see no other copy and decide each
        // one alike.
        let (_dir, env, config) = fresh();
        let mut txn = env.begin_rw().unwrap();
        wok_db::ban_event(&mut txn, &[3; 32], "").unwrap();
        txn.commit().unwrap();
        let replies = replies_to(
            config,
            &env,
            vec![copy_of(1, 3, author, 100, 1), copy_of(2, 3, author, 100, 1)],
        );
        let banned = json!([false, "restricted: event is banned by the relay operator"]);
        assert_eq!(replies, [banned.clone(), banned]);

        // A full relay still stores a vanish request, and answers its copy
        // as a duplicate, not with the global quota's refusal.
        let (_dir, env, mut config) = fresh();
        config.relay.abuse.max_stored_events = 1;
        config.relay.nip62.service_url = "wss://relay.example.com".into();
        replies_to(config.clone(), &env, vec![copy_of(1, 1, author, 100, 1)]);
        let replies = replies_to(
            config,
            &env,
            vec![
                copy_of(1, 4, author, 200, VANISH_KIND),
                copy_of(2, 4, author, 200, VANISH_KIND),
                copy_of(3, 5, [0x66; 32], 200, 1),
            ],
        );
        assert_eq!(
            replies,
            [
                json!([true, ""]),
                json!([true, "duplicate: have this event"]),
                json!([false, "error: global storage quota of 1 events exceeded"]),
            ]
        );
    }

    #[test]
    fn writer_metrics_leave_out_batches_that_did_not_commit() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), wok_db::EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let mut config = Config {
            db: dir.path().to_path_buf(),
            ..Config::default()
        };
        // Two events over a one-event global quota abort the transaction.
        config.relay.abuse.enabled = true;
        config.relay.abuse.max_stored_events = 1;
        let metrics = write_all(config, &env, vec![note(1), note(2)]);
        let txn = env.begin_ro().unwrap();
        assert_eq!(txn.entries(env.dbis().event).unwrap(), 0);
        assert_eq!(metrics.writer_queue_depth.count(), 0);
        assert_eq!(metrics.writer_commit_events.count(), 0);
        for step in [
            &metrics.writer_prepare,
            &metrics.writer_write,
            &metrics.writer_commit,
            &metrics.writer_reply,
        ] {
            assert_eq!(step.count(), 0);
        }
        assert_eq!(
            metrics.writer_storage_bytes_total.load(Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn the_global_quota_never_refuses_a_vanish_request() {
        // #248: NIP-62 says a relay MUST honor a request to vanish that
        // targets it. On a full relay the request is still recorded and what
        // its author published is deleted; everything else stays under the
        // quota.
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), wok_db::EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let mut config = Config {
            db: dir.path().to_path_buf(),
            db_min_free_disk_bytes: 0,
            ..Config::default()
        };
        config.relay.abuse.max_stored_events = 1;
        config.relay.nip62.service_url = "wss://relay.example.com".into();
        // An unsigned event `n` from `author`, answered on connection `n`.
        let event = |n: u8, author: u8, created_at: u64, kind: u64, tags: Value| {
            let (id, author) = ([n; 32], [author; 32]);
            let packed = PackedEventBuilder::build(
                &id,
                &author,
                created_at,
                kind,
                0,
                &PackedEventTagBuilder::default(),
            )
            .unwrap();
            let json = json!({
                "id": to_hex(&id),
                "pubkey": to_hex(&author),
                "created_at": created_at,
                "kind": kind,
                "tags": tags,
                "content": "",
                "sig": "00".repeat(64),
            })
            .to_string();
            WriterMsg::AddEvent {
                conn_id: u64::from(n),
                source: TransportSource::ip_address("127.0.0.1".parse().unwrap()),
                packed: packed.into_bytes(),
                json,
                authed: None,
                grant: Default::default(),
            }
        };
        let vanish = |n: u8, author: u8, relay: &str| {
            event(n, author, 200, VANISH_KIND, json!([["relay", relay]]))
        };
        // One writer batch; the `OK` each event got, in order.
        let write = |config: &Config, messages: Vec<WriterMsg>| -> Vec<Value> {
            let conns = Arc::new(ConnTable::new());
            let mut replies = Vec::new();
            let (writer_tx, writer_rx) = bounded(messages.len());
            for message in messages {
                if let WriterMsg::AddEvent { conn_id, .. } = &message {
                    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
                    conns.insert(*conn_id, Outbound::new(tx, 0));
                    replies.push(rx);
                }
                writer_tx.send(message).unwrap();
            }
            drop(writer_tx);
            let moderation = env
                .begin_ro()
                .and_then(|txn| load_moderation_snapshot_ro(&txn))
                .unwrap();
            run_writer(
                env.clone(),
                Arc::new(parking_lot::RwLock::new(config.clone())),
                conns,
                Arc::new(Metrics::default()),
                writer_rx,
                Vec::new(),
                Arc::new(parking_lot::RwLock::new(moderation)),
                TAG_KIND_STEP,
            );
            replies
                .iter_mut()
                .map(|rx| serde_json::from_str(&rx.try_recv().unwrap().into_text()).unwrap())
                .collect()
        };
        let stored = || env.begin_ro().unwrap().entries(env.dbis().event).unwrap();
        let quota_refusal = json!("error: global storage quota of 1 events exceeded");

        // Author 0xa1's note fills the relay.
        let replies = write(&config, vec![event(1, 0xa1, 100, 1, json!([]))]);
        assert_eq!(replies[0][2], true, "{replies:?}");

        // Its author's vanish request is stored over the quota. A note, and a
        // vanish request for another relay, which records nothing, are not.
        let replies = write(
            &config,
            vec![
                vanish(2, 0xa1, "ALL_RELAYS"),
                event(3, 0xb2, 200, 1, json!([])),
                vanish(4, 0xc3, "wss://other.example.com"),
            ],
        );
        assert_eq!(replies[0][2], true, "{replies:?}");
        assert_eq!(replies[1][3], quota_refusal, "{replies:?}");
        assert_eq!(replies[2][3], quota_refusal, "{replies:?}");
        assert_eq!(stored(), 2);
        {
            let txn = env.begin_ro().unwrap();
            let (_, note) = wok_db::lookup_event_by_id_ro(&txn, &[1; 32])
                .unwrap()
                .unwrap();
            assert!(is_event_vanished_ro(&txn, PackedEventView::new(&note).unwrap()).unwrap());
        }
        // Maintenance then deletes the note.
        run_maintenance(&env, &config, &mut Default::default());
        let txn = env.begin_ro().unwrap();
        assert!(wok_db::lookup_event_by_id_ro(&txn, &[1; 32])
            .unwrap()
            .is_none());
        drop(txn);
        assert_eq!(stored(), 1);

        // A fresh key's request is stored while the relay is still full.
        let replies = write(&config, vec![vanish(5, 0xd4, "ALL_RELAYS")]);
        assert_eq!(replies[0][2], true, "{replies:?}");
        assert_eq!(stored(), 2);

        // With NIP-62 off, a kind 62 is an ordinary event, and over the quota.
        config.relay.nip62.enabled = false;
        let replies = write(&config, vec![vanish(6, 0xe5, "ALL_RELAYS")]);
        assert_eq!(replies[0][3], quota_refusal, "{replies:?}");
        assert_eq!(stored(), 2);
    }

    #[test]
    fn a_tree_with_more_tag_letters_than_max_tags_per_filter_keeps_writes_and_maintenance_working()
    {
        // #243: the writer and maintenance parsed stored tree filters with
        // relay.max_tags_per_filter, so a tree naming more tag letters than
        // it made every write and every maintenance tick fail.
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), wok_db::EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let recipient = [0xa1; 32];
        let filter = json!({"#p": [to_hex(&recipient)], "#t": ["nostr"]}).to_string();
        let mut txn = env.begin_rw().unwrap();
        wok_db::bump_negentropy_mod_counter(&mut txn).unwrap();
        let tree_id = wok_db::insert_negentropy_filter(&mut txn, &filter).unwrap();
        txn.commit().unwrap();
        let event = |n: u8, expiration: u64| {
            let (id, author) = ([n; 32], [0x40 + n; 32]);
            let mut tags = PackedEventTagBuilder::default();
            tags.add('p', &recipient).unwrap();
            tags.add('t', b"nostr").unwrap();
            let packed =
                PackedEventBuilder::build(&id, &author, 1_700_000_000, 1, expiration, &tags)
                    .unwrap();
            let json = json!({
                "id": to_hex(&id),
                "pubkey": to_hex(&author),
                "created_at": 1_700_000_000u64,
                "kind": 1,
                "tags": [
                    ["p", to_hex(&recipient)],
                    ["t", "nostr"],
                    ["expiration", expiration.to_string()],
                ],
                "content": "",
                "sig": "00".repeat(64),
            })
            .to_string();
            (packed.into_bytes(), json)
        };
        // An event that has expired, for maintenance to delete.
        let (packed, json) = event(1, 1_700_000_001);
        let mut txn = env.begin_rw().unwrap();
        wok_db::write_events(
            &mut txn,
            &mut NegentropyFilterCache::default(),
            &mut [EventToWrite::new(packed, json)],
            false,
        )
        .unwrap();
        txn.commit().unwrap();

        let mut config = Config {
            db: dir.path().to_path_buf(),
            ..Config::default()
        };
        config.relay.max_tags_per_filter = 1;
        let (writer_tx, writer_rx) = bounded(1);
        let (packed, json) = event(2, 0);
        writer_tx
            .send(WriterMsg::AddEvent {
                conn_id: 1,
                source: TransportSource::ip_address("127.0.0.1".parse().unwrap()),
                packed,
                json,
                authed: None,
                grant: Default::default(),
            })
            .unwrap();
        drop(writer_tx);
        run_writer(
            env.clone(),
            Arc::new(parking_lot::RwLock::new(config.clone())),
            Arc::new(ConnTable::new()),
            Arc::new(Metrics::default()),
            writer_rx,
            Vec::new(),
            moderation(&env),
            TAG_KIND_STEP,
        );
        let tree_size = |txn: &wok_db::RoTxn<'_>| {
            wok_negentropy::open_ro(txn, tree_id)
                .unwrap()
                .size_mut()
                .unwrap()
        };
        assert_eq!(
            tree_size(&env.begin_ro().unwrap()),
            2,
            "the publication was stored in the tree"
        );

        run_maintenance(&env, &config, &mut Default::default());
        let txn = env.begin_ro().unwrap();
        assert_eq!(txn.entries(env.dbis().event).unwrap(), 1);
        assert!(wok_db::lookup_event_by_id_ro(&txn, &[1; 32])
            .unwrap()
            .is_none());
        assert_eq!(tree_size(&txn), 1, "maintenance removed the expired event");
        assert_eq!(
            wok_negentropy::verify_tree(&txn, tree_id, &filter).unwrap(),
            1
        );
    }

    /// An unsigned gift wrap to Alice; the writer does not check signatures.
    fn gift_wrap(n: u64) -> (Vec<u8>, String) {
        let id = {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&n.to_be_bytes());
            id
        };
        let (author, recipient) = ([0x51; 32], [0xa1; 32]);
        let mut tags = PackedEventTagBuilder::default();
        tags.add('p', &recipient).unwrap();
        let packed =
            PackedEventBuilder::build(&id, &author, 1_700_000_000 + n, 1059, 0, &tags).unwrap();
        let json = json!({
            "id": to_hex(&id),
            "pubkey": to_hex(&author),
            "created_at": 1_700_000_000 + n,
            "kind": 1059,
            "tags": [["p", to_hex(&recipient)]],
            "content": "",
            "sig": "00".repeat(64),
        })
        .to_string();
        (packed.into_bytes(), json)
    }

    /// A database of `events` gift wraps whose tag-kind index starts over,
    /// as one from before the index does.
    fn unindexed_database(events: u64) -> (tempfile::TempDir, Env) {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), wok_db::EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let mut stored: Vec<_> = (0..events)
            .map(|n| {
                let (packed, json) = gift_wrap(n);
                EventToWrite::new(packed, json)
            })
            .collect();
        let mut txn = env.begin_rw().unwrap();
        wok_db::write_events(&mut txn, &mut wok_db::NoopNegentropy, &mut stored, false).unwrap();
        wok_db::reset_tag_kind_index(&mut txn).unwrap();
        txn.commit().unwrap();
        (dir, env)
    }

    fn tag_kind_state(env: &Env) -> wok_db::TagKindIndexState {
        wok_db::tag_kind_index_state_ro(&env.begin_ro().unwrap())
            .unwrap()
            .unwrap()
    }

    fn moderation(env: &Env) -> Arc<parking_lot::RwLock<ModerationSnapshot>> {
        Arc::new(parking_lot::RwLock::new(
            env.begin_ro()
                .and_then(|txn| load_moderation_snapshot_ro(&txn))
                .unwrap(),
        ))
    }

    fn add_event(n: u64) -> WriterMsg {
        let (packed, json) = gift_wrap(n);
        WriterMsg::AddEvent {
            conn_id: 1,
            source: TransportSource::ip_address("127.0.0.1".parse().unwrap()),
            packed,
            json,
            authed: None,
            grant: Default::default(),
        }
    }

    const TEN_ENTRIES: TagKindStep = TagKindStep {
        max_entries: 10,
        budget: Duration::MAX,
    };

    #[test]
    fn backfill_steps_are_bounded_and_interleave_with_writes() {
        let (dir, env) = unindexed_database(50);
        let mut config = Config {
            db: dir.path().to_path_buf(),
            ..Config::default()
        };
        // The queued gift wrap is stored only while someone could read it.
        config.relay.auth.service_url = "wss://relay.example.com".into();
        let metrics = Arc::new(Metrics::default());
        // The publication is queued before the writer starts, and the channel
        // closes behind it.
        let (writer_tx, writer_rx) = bounded(4);
        writer_tx.send(add_event(50)).unwrap();
        drop(writer_tx);

        run_writer(
            env.clone(),
            Arc::new(parking_lot::RwLock::new(config)),
            Arc::new(ConnTable::new()),
            metrics.clone(),
            writer_rx,
            Vec::new(),
            moderation(&env),
            TEN_ENTRIES,
        );

        // One step of the key-ordered pass ran before the publication's
        // batch and one after it; the publication did not wait for the
        // other 30 entries.
        let state = tag_kind_state(&env);
        assert_eq!((state.indexed_through, state.high_water), (0, 51));
        assert_eq!(state.bulk_pass.map(|pass| pass.visited), Some(20));
        assert_eq!(
            metrics
                .tag_kind_backfill_entries_total
                .load(Ordering::Relaxed),
            20
        );
        let txn = env.begin_ro().unwrap();
        assert_eq!(txn.entries(env.dbis().event).unwrap(), 51);
        // The writer indexed the publication itself.
        let key = wok_db::tag_kind_key(b'p', &[0xa1; 32], 1059, 1_700_000_050);
        let lev = 51u64.to_ne_bytes();
        let mut indexed = false;
        txn.foreach_full(
            env.dbis().event_tag_kind.unwrap(),
            &key,
            &lev,
            false,
            |found_key, found_lev| {
                indexed = found_key == key && found_lev == lev;
                false
            },
        )
        .unwrap();
        assert!(indexed);
    }

    #[test]
    fn backfill_waits_while_free_disk_space_is_below_the_reserve() {
        let (dir, env) = unindexed_database(50);
        let mut config = Config {
            db: dir.path().to_path_buf(),
            ..Config::default()
        };
        config.db_min_free_disk_bytes = u64::MAX;
        let metrics = Arc::new(Metrics::default());
        let (writer_tx, writer_rx) = bounded(4);
        writer_tx.send(add_event(50)).unwrap();
        drop(writer_tx);

        run_writer(
            env.clone(),
            Arc::new(parking_lot::RwLock::new(config)),
            Arc::new(ConnTable::new()),
            metrics.clone(),
            writer_rx,
            Vec::new(),
            moderation(&env),
            TEN_ENTRIES,
        );

        // Neither the publication nor the build wrote anything.
        let state = tag_kind_state(&env);
        assert_eq!((state.indexed_through, state.bulk_pass), (0, None));
        assert_eq!(
            metrics
                .tag_kind_backfill_entries_total
                .load(Ordering::Relaxed),
            0
        );
        let txn = env.begin_ro().unwrap();
        assert_eq!(txn.entries(env.dbis().event).unwrap(), 50);
        assert_eq!(txn.entries(env.dbis().event_tag_kind.unwrap()).unwrap(), 2);
    }

    #[test]
    fn backfill_completes_in_the_background_and_resumes_after_maintenance_finds_a_gap() {
        let (dir, env) = unindexed_database(50);
        let config = Config {
            db: dir.path().to_path_buf(),
            ..Config::default()
        };
        let metrics = Arc::new(Metrics::default());
        let (writer_tx, writer_rx) = bounded(4);
        let writer = {
            let (env, metrics, moderation) = (env.clone(), metrics.clone(), moderation(&env));
            std::thread::spawn(move || {
                run_writer(
                    env,
                    Arc::new(parking_lot::RwLock::new(config)),
                    Arc::new(ConnTable::new()),
                    metrics,
                    writer_rx,
                    Vec::new(),
                    moderation,
                    TEN_ENTRIES,
                )
            })
        };
        let wait_until_complete = || {
            let deadline = std::time::Instant::now() + Duration::from_secs(20);
            while metrics.tag_kind_index_complete.load(Ordering::Relaxed) == 0 {
                assert!(std::time::Instant::now() < deadline, "backfill stalled");
                std::thread::sleep(Duration::from_millis(5));
            }
        };
        wait_until_complete();
        let report = wok_db::check_integrity(&env.begin_ro().unwrap()).unwrap();
        let tag_kind = report.tag_kind_index.unwrap();
        assert!(tag_kind.complete && tag_kind.missing_entries == 0);
        assert_eq!(tag_kind.actual_entries, 50);
        assert!(metrics
            .render()
            .contains("\nwok_tag_kind_index_complete 1\n"));
        assert!(metrics
            .render()
            .contains("\nwok_tag_kind_index_indexed_through 50\n"));

        // Another process leaves the index behind; the next maintenance tick
        // notices and the writer indexes the events again.
        let mut txn = env.begin_rw().unwrap();
        wok_db::reset_tag_kind_index(&mut txn).unwrap();
        txn.commit().unwrap();
        metrics.tag_kind_index_complete.store(0, Ordering::Relaxed);
        writer_tx.send(WriterMsg::Maintenance).unwrap();
        wait_until_complete();
        writer_tx.send(WriterMsg::Stop).unwrap();
        writer.join().unwrap();
        assert!(tag_kind_state(&env).complete());
        assert_eq!(
            metrics
                .tag_kind_backfill_entries_total
                .load(Ordering::Relaxed),
            100
        );
    }

    #[test]
    fn with_the_tag_kind_index_off_the_writer_neither_posts_nor_builds() {
        let (dir, env) = unindexed_database(50);
        let mut config = Config {
            db: dir.path().to_path_buf(),
            ..Config::default()
        };
        config.relay.tag_kind_index_enabled = false;
        // The gift wraps are stored only while someone could read them.
        config.relay.auth.service_url = "wss://relay.example.com".into();
        let config = Arc::new(parking_lot::RwLock::new(config));
        let metrics = Arc::new(Metrics::default());
        let (writer_tx, writer_rx) = bounded(4);
        let writer = {
            let (env, config, metrics, moderation) = (
                env.clone(),
                config.clone(),
                metrics.clone(),
                moderation(&env),
            );
            std::thread::spawn(move || {
                run_writer(
                    env,
                    config,
                    Arc::new(ConnTable::new()),
                    metrics,
                    writer_rx,
                    Vec::new(),
                    moderation,
                    TEN_ENTRIES,
                )
            })
        };
        let wait_for = |what: &str, done: &dyn Fn() -> bool| {
            let deadline = std::time::Instant::now() + Duration::from_secs(20);
            while !done() {
                assert!(std::time::Instant::now() < deadline, "{what}");
                std::thread::sleep(Duration::from_millis(5));
            }
        };
        // The writer takes its messages in order, so once the second
        // publication is stored, the maintenance tick before it has run.
        writer_tx.send(add_event(50)).unwrap();
        writer_tx.send(WriterMsg::Maintenance).unwrap();
        writer_tx.send(add_event(51)).unwrap();
        wait_for("publications not stored", &|| {
            metrics.written_events_total.load(Ordering::Relaxed) == 2
        });
        let off = tag_kind_state(&env);
        assert_eq!((off.indexed_through, off.high_water), (0, 52));
        let report = wok_db::check_integrity(&env.begin_ro().unwrap()).unwrap();
        assert_eq!(report.tag_kind_index.unwrap().actual_entries, 0);
        assert_eq!(
            metrics
                .tag_kind_backfill_entries_total
                .load(Ordering::Relaxed),
            0
        );

        // Back on, the next maintenance tick starts the build, which covers
        // the publications too.
        config.write().relay.tag_kind_index_enabled = true;
        writer_tx.send(WriterMsg::Maintenance).unwrap();
        wait_for("backfill stalled", &|| {
            metrics.tag_kind_index_complete.load(Ordering::Relaxed) == 1
        });
        writer_tx.send(WriterMsg::Stop).unwrap();
        writer.join().unwrap();
        let report = wok_db::check_integrity(&env.begin_ro().unwrap()).unwrap();
        let tag_kind = report.tag_kind_index.unwrap();
        assert!(tag_kind.complete && tag_kind.missing_entries == 0);
        assert_eq!(tag_kind.actual_entries, 52);
    }

    /// An unsigned note saying "hello world".
    fn hello(n: u64) -> (Vec<u8>, String) {
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&n.to_be_bytes());
        let author = [0x51; 32];
        let packed = PackedEventBuilder::build(
            &id,
            &author,
            1_700_000_000 + n,
            1,
            0,
            &PackedEventTagBuilder::default(),
        )
        .unwrap();
        let json = json!({
            "id": to_hex(&id),
            "pubkey": to_hex(&author),
            "created_at": 1_700_000_000 + n,
            "kind": 1,
            "tags": [],
            "content": "hello world",
            "sig": "00".repeat(64),
        })
        .to_string();
        (packed.into_bytes(), json)
    }

    fn add_hello(n: u64) -> WriterMsg {
        let (packed, json) = hello(n);
        WriterMsg::AddEvent {
            conn_id: 1,
            source: TransportSource::ip_address("127.0.0.1".parse().unwrap()),
            packed,
            json,
            authed: None,
            grant: Default::default(),
        }
    }

    /// A database of `events` notes, stored as publishing stores them: with
    /// no search postings.
    fn unsearched_database(events: u64) -> (tempfile::TempDir, Env) {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), wok_db::EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let mut stored: Vec<_> = (0..events)
            .map(|n| {
                let (packed, json) = hello(n);
                EventToWrite::new(packed, json)
            })
            .collect();
        let mut txn = env.begin_rw().unwrap();
        wok_db::write_events(&mut txn, &mut wok_db::NoopNegentropy, &mut stored, false).unwrap();
        txn.commit().unwrap();
        (dir, env)
    }

    fn search_state(env: &Env) -> (u64, usize) {
        let txn = env.begin_ro().unwrap();
        let state = wok_db::search_index_state_ro(&txn).unwrap().unwrap();
        (
            state.indexed_through,
            wok_db::search_posting_count(&txn, "hello").unwrap(),
        )
    }

    /// Run a writer on `env` over `queued` publications until the channel
    /// closes behind them.
    fn run_queued(env: &Env, search_enabled: bool, queued: &[u64]) -> Arc<Metrics> {
        let mut config = Config {
            db: env.path().to_path_buf(),
            ..Config::default()
        };
        config.relay.search_enabled = search_enabled;
        let metrics = Arc::new(Metrics::default());
        let (writer_tx, writer_rx) = bounded(queued.len().max(1));
        for &n in queued {
            writer_tx.send(add_hello(n)).unwrap();
        }
        drop(writer_tx);
        run_writer(
            env.clone(),
            Arc::new(parking_lot::RwLock::new(config)),
            Arc::new(ConnTable::new()),
            metrics.clone(),
            writer_rx,
            Vec::new(),
            moderation(env),
            TAG_KIND_STEP,
        );
        metrics
    }

    #[test]
    fn a_busy_writer_builds_the_search_index_once_1000_events_wait() {
        let (_dir, env) = unsearched_database(SEARCH_BUILD_BUSY_LAG - 2);
        // The publication is stored with no postings, and with 999 events
        // waiting, a writer with messages to take does not build.
        let metrics = run_queued(&env, true, &[SEARCH_BUILD_BUSY_LAG - 2]);
        assert_eq!(search_state(&env), (0, 0));
        assert_eq!(
            metrics.search_index_lag_events.load(Ordering::Relaxed),
            SEARCH_BUILD_BUSY_LAG - 1
        );
        assert_eq!(
            metrics
                .search_index_build_events_total
                .load(Ordering::Relaxed),
            0
        );

        // The next makes 1,000, and one step runs before the writer takes
        // another message.
        let metrics = run_queued(&env, true, &[SEARCH_BUILD_BUSY_LAG - 1]);
        let built = metrics
            .search_index_build_events_total
            .load(Ordering::Relaxed);
        assert!(built > 0);
        assert_eq!(search_state(&env), (built, built as usize));
    }

    #[test]
    fn an_idle_writer_builds_the_search_index_while_search_is_on() {
        let (dir, env) = unsearched_database(50);
        let mut config = Config {
            db: dir.path().to_path_buf(),
            ..Config::default()
        };
        config.relay.search_enabled = false;
        let config = Arc::new(parking_lot::RwLock::new(config));
        let metrics = Arc::new(Metrics::default());
        let (writer_tx, writer_rx) = bounded(4);
        let writer = {
            let (env, config, metrics, moderation) = (
                env.clone(),
                config.clone(),
                metrics.clone(),
                moderation(&env),
            );
            std::thread::spawn(move || {
                run_writer(
                    env,
                    config,
                    Arc::new(ConnTable::new()),
                    metrics,
                    writer_rx,
                    Vec::new(),
                    moderation,
                    TAG_KIND_STEP,
                )
            })
        };
        let wait_until_built = |events: u64| {
            let deadline = std::time::Instant::now() + Duration::from_secs(20);
            while metrics
                .search_index_build_events_total
                .load(Ordering::Relaxed)
                < events
            {
                assert!(std::time::Instant::now() < deadline, "build stalled");
                std::thread::sleep(Duration::from_millis(5));
            }
        };

        // With search off, an idle writer builds nothing.
        writer_tx.send(add_hello(50)).unwrap();
        std::thread::sleep(SEARCH_BUILD_IDLE * 10);
        assert_eq!(search_state(&env), (0, 0));
        assert_eq!(metrics.search_index_lag_events.load(Ordering::Relaxed), 51);

        // A reload turns search on: the next message the writer takes
        // starts the build.
        config.write().relay.search_enabled = true;
        writer_tx.send(WriterMsg::Maintenance).unwrap();
        wait_until_built(51);
        assert_eq!(search_state(&env), (51, 51));
        assert!(metrics
            .render()
            .contains("\nwok_search_index_lag_events 0\n"));

        // A publication is indexed once the writer is idle again.
        writer_tx.send(add_hello(51)).unwrap();
        wait_until_built(52);
        writer_tx.send(WriterMsg::Stop).unwrap();
        writer.join().unwrap();
        assert_eq!(search_state(&env), (52, 52));
        assert_eq!(metrics.search_index_lag_events.load(Ordering::Relaxed), 0);
        let report = wok_db::check_integrity(&env.begin_ro().unwrap()).unwrap();
        assert!(report.ok(), "{:?}", report.issues);
    }
}
