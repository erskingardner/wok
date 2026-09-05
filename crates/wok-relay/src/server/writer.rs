//! Single-writer mutation, publication receipts and maintenance.
use super::*;

pub(super) fn run_writer(
    env: Env,
    cfg: Arc<parking_lot::RwLock<Config>>,
    conns: Arc<ConnTable>,
    metrics: Arc<Metrics>,
    rx: Receiver<WriterMsg>,
    mon_txs: Vec<Sender<MonitorMsg>>,
    moderation: Arc<parking_lot::RwLock<ModerationSnapshot>>,
) {
    let mut plugin = PluginEventSifter::new(cfg.read().relay.write_policy_timeout_secs);
    let mut negentropy_max_tags = cfg.read().relay.max_tags_per_filter;
    let mut negentropy_cache = NegentropyFilterCache::new(negentropy_max_tags);
    let mut batch = Vec::with_capacity(WRITER_BATCH_MAX);
    let mut event_batch = Vec::with_capacity(WRITER_BATCH_MAX);
    let mut closed = std::collections::HashSet::new();
    let mut maintenance_cursor = Vec::new();
    let mut batch_vanish: HashMap<[u8; 32], u64> = HashMap::new();
    let mut events: Vec<EventToWrite<u64>> = Vec::with_capacity(256);
    while let Ok(msg) = rx.recv() {
        batch.clear();
        event_batch.clear();
        closed.clear();
        batch_vanish.clear();
        events.clear();
        batch.push(msg);
        while batch.len() < WRITER_BATCH_MAX {
            match rx.try_recv() {
                Ok(more) => batch.push(more),
                Err(_) => break,
            }
        }
        // Filter out events from connections closed within this batch, like
        // C++ RelayWriter (a per-batch set; a persistent set would leak one
        // entry per closed connection for the life of the process).
        for m in &batch {
            if let WriterMsg::Close { conn_id } = m {
                closed.insert(*conn_id);
            }
        }
        // Management mutations take priority over every event in the drained
        // batch. This closes the same-batch race where an event queued just
        // before a ban/revocation could otherwise pass its stored-state
        // recheck and be committed after the management command returned.
        let mut maintenance_requested = false;
        for m in batch.drain(..) {
            if let WriterMsg::Management(msg) = m {
                let result = apply_management(&env, &moderation, msg.cmd);
                let _ = msg.reply.send(result);
            } else if matches!(m, WriterMsg::Maintenance) {
                maintenance_requested = true;
            } else {
                event_batch.push(m);
            }
        }
        let cfg_snap = cfg.read().clone();
        if maintenance_requested {
            run_maintenance(&env, &cfg_snap, &mut maintenance_cursor);
        }
        let vanish_policy = cfg_snap.vanish_policy();
        // A valid vanish request and an ephemeral gift wrap can arrive in the
        // same drained writer batch. Compute the batch markers up front so a
        // live-only event cannot be broadcast immediately before its request
        // is persisted later in that batch.
        for m in &event_batch {
            let WriterMsg::AddEvent {
                conn_id,
                packed,
                json,
                ..
            } = m
            else {
                continue;
            };
            if closed.contains(conn_id) {
                continue;
            }
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
        for m in event_batch.drain(..) {
            if let WriterMsg::AddEvent {
                conn_id,
                source,
                packed,
                json,
                authed,
            } = m
            {
                if closed.contains(&conn_id) {
                    continue;
                }
                let mut ok_msg = String::new();
                let is_vanish_request =
                    PackedEventView::new(&packed).is_ok_and(|event| event.kind() == VANISH_KIND);
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
                        let mut author = [0u8; 32];
                        author.copy_from_slice(packed_view.pubkey());
                        let stored_checks = env.begin_ro().and_then(|txn| {
                            Ok::<_, wok_db::DbError>((
                                if is_vanish_request {
                                    false
                                } else {
                                    is_event_vanished_ro(&txn, packed_view)?
                                },
                                moderation_reason_ro(&txn, packed_view)?,
                                // Recheck allowlist/role eligibility against
                                // committed state: a ban/revocation may have
                                // landed after the ingester's snapshot check.
                                // Vanish requests bypass their own markers,
                                // but not moderation or write restrictions.
                                stored_write_permitted(&txn, &cfg_snap, &author)?,
                            ))
                        });
                        let (vanished, moderated, write_allowed) = match stored_checks {
                            Ok((vanished, moderated, write_allowed)) => (
                                vanished
                                    || event_matches_vanish_markers(packed_view, &batch_vanish),
                                moderated,
                                write_allowed,
                            ),
                            Err(error) => {
                                conns.send(
                                    conn_id,
                                    RelayMessage::Ok {
                                        event_id: to_hex(packed_view.id()),
                                        accepted: false,
                                        message: format!("Write error: {error}"),
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
                        if let Some(reason) = moderated {
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
                            let id_hex = PackedEventView::new(&packed)
                                .map(|event| to_hex(event.id()))
                                .unwrap_or_else(|_| "?".into());
                            conns.send(
                                conn_id,
                                RelayMessage::Ok {
                                    event_id: id_hex,
                                    accepted: false,
                                    message:
                                        "restricted: writes are restricted to allowlisted pubkeys"
                                            .into(),
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
                        broadcast_ephemeral(&mon_txs, &packed, &json);
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
                                    "blocked: disk reserve requires {} free bytes",
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
                                message: format!("Write error: disk space check failed: {error}"),
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
        let write_res = (|| {
            let mut txn = env.begin_rw()?;
            if negentropy_max_tags != cfg_snap.relay.max_tags_per_filter {
                negentropy_max_tags = cfg_snap.relay.max_tags_per_filter;
                negentropy_cache = NegentropyFilterCache::new(negentropy_max_tags);
            }
            let mut tree_batch = negentropy_cache.batch();
            wok_db::write::write_events_with_quota(
                &mut txn,
                &mut tree_batch,
                &mut events,
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
            let report_updates = record_reports(&mut txn, &events, report_capacity);
            if cfg_snap.relay.abuse.enabled && cfg_snap.relay.abuse.max_stored_events != 0 {
                let stored = txn.entries(txn.env().dbis().event)? as u64;
                if stored > cfg_snap.relay.abuse.max_stored_events {
                    metrics
                        .abuse_global_quota_rejections
                        .fetch_add(events.len() as u64, Ordering::Relaxed);
                    return Err(wok_db::DbError::msg(format!(
                        "global storage quota of {} events exceeded",
                        cfg_snap.relay.abuse.max_stored_events
                    )));
                }
            }
            txn.commit()?;
            Ok::<_, wok_db::DbError>(report_updates)
        })();
        let report_updates = match write_res {
            Ok(report_updates) => report_updates,
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
                            message: format!("Write error: {error}"),
                        },
                        &metrics,
                    );
                }
                continue;
            }
        };
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
                    (false, "replaced: have newer event".into())
                }
                EventWriteStatus::Deleted => {
                    metrics
                        .rejected_events_total
                        .fetch_add(1, Ordering::Relaxed);
                    (false, "deleted: user requested deletion".into())
                }
                EventWriteStatus::QuotaExceeded => {
                    metrics
                        .abuse_pubkey_quota_rejections
                        .fetch_add(1, Ordering::Relaxed);
                    (false, "blocked: author storage quota exceeded".into())
                }
                EventWriteStatus::Pending => (false, "Write error: pending".into()),
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
        broadcast_db_change(&mon_txs);
    }
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
) -> bool {
    if packed.kind() != VANISH_KIND {
        let mut author = [0u8; 32];
        author.copy_from_slice(packed.pubkey());
        if markers
            .get(&author)
            .is_some_and(|timestamp| packed.created_at() <= *timestamp)
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
                if markers.contains_key(&recipient) {
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
    while !shutdown.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_secs(2));
        if writer.try_send(WriterMsg::Maintenance).is_err() && writer.is_full() {
            tracing::debug!("writer busy; maintenance deferred");
        }
    }
}

pub(super) fn run_maintenance(env: &Env, cfg_snap: &Config, vanish_cursor: &mut Vec<u8>) {
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
        )?;
        let mut cache = NegentropyFilterCache::new(cfg_snap.relay.max_tags_per_filter);
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
