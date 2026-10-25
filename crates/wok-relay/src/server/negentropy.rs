//! Bounded reconciliation sessions. Only provably public trees bypass the
//! shared per-event visibility predicate; personalized views are temporary.
use super::*;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use wok_negentropy::{Negentropy, Vector};

// Covers protocol input/output buffers, query/filter state and traversal stacks.
use wok_negentropy::ROUND_MEMORY_BYTES as ROUND_BYTES;

#[derive(Default)]
pub(super) struct MemoryPool(Mutex<MemoryUsage>);
#[derive(Default)]
struct MemoryUsage {
    total: u64,
    connections: HashMap<u64, u64>,
}
struct Reservation {
    pool: Arc<MemoryPool>,
    conn: u64,
    bytes: u64,
}
impl MemoryPool {
    /// Reserve `bytes` for `conn`, or name the budget that refuses them.
    fn reserve(
        self: &Arc<Self>,
        conn: u64,
        bytes: u64,
        cfg: &Config,
    ) -> Result<Reservation, Setting> {
        let mut usage = self.0.lock();
        let per_conn = usage.connections.get(&conn).copied().unwrap_or(0);
        let fits = |used: u64, budget: u64| used.checked_add(bytes).is_some_and(|n| n <= budget);
        if !fits(usage.total, cfg.relay.sync_memory_total) {
            return Err(Setting::SyncMemoryTotal);
        }
        if !fits(per_conn, cfg.relay.sync_memory_per_connection) {
            return Err(Setting::SyncMemoryPerConnection);
        }
        usage.total += bytes;
        usage.connections.insert(conn, per_conn + bytes);
        Ok(Reservation {
            pool: self.clone(),
            conn,
            bytes,
        })
    }
}
impl Reservation {
    fn shrink(&mut self, bytes: u64) {
        let released = self.bytes.saturating_sub(bytes);
        self.bytes -= released;
        let mut usage = self.pool.0.lock();
        usage.total -= released;
        if let Some(conn) = usage.connections.get_mut(&self.conn) {
            *conn -= released;
            if *conn == 0 {
                usage.connections.remove(&self.conn);
            }
        }
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        self.shrink(0);
    }
}

enum View {
    Memory { initial: Vec<u8>, items: Vector },
    Tree { sub: Subscription, tree_id: u64 },
}
struct Session {
    view: View,
    reservation: Reservation,
    waiting_since: Option<Instant>,
    expires_at: u64,
    /// The serialized size of the filter it keeps.
    filter_bytes: usize,
    /// The filter it was opened with, checked again when a reload changes
    /// `relay.filter_validation`.
    filter: NostrFilterGroup,
}

/// Close `conn_id`'s sessions and scans: its identities changed, and with
/// them what it may see.
fn reauthenticated(
    sessions: &mut HashMap<(u64, String), Session>,
    queries: &mut QueryScheduler,
    conns: &ConnTable,
    metrics: &Metrics,
    conn_id: u64,
) {
    sessions.retain(|(conn, sid), _| {
        if *conn == conn_id {
            fail(
                conns,
                metrics,
                *conn,
                sid,
                "closed: authentication changed; reopen synchronization",
            );
            false
        } else {
            true
        }
    });
    queries.close_conn(conn_id);
}

fn fail(conns: &ConnTable, metrics: &Metrics, conn: u64, sid: &str, message: &str) {
    conns.send(
        conn,
        RelayMessage::NegErr {
            sub_id: sid.into(),
            message: message.into(),
            extra: None,
        },
        metrics,
    );
}

// Conservative eligibility proof, independent of session identity. No database
// population scan: marker table sizes and at most one seek per restricted kind.
// If any condition cannot be established, fall back to a filtered memory view.
fn public_tree_allowed(
    txn: &wok_db::RoTxn<'_>,
    sub: &Subscription,
    cfg: &Config,
) -> Result<bool, wok_db::DbError> {
    let db = txn.env().dbis();
    // A filter that never matches leaves no filter; its memory view is empty.
    let Some(filter) = sub.filter_group.filters.first() else {
        return Ok(false);
    };
    if !wok_query::visibility::physical_tree_is_globally_visible(txn, filter)? {
        return Ok(false);
    }
    let policy = cfg.read_restrictor();
    for kind in policy.restricted_kinds() {
        if filter
            .kinds
            .as_ref()
            .is_some_and(|kinds| !(0..kinds.size()).any(|i| kinds.at(i) == kind))
        {
            continue;
        }
        let mut present = false;
        txn.foreach_full(
            db.event_kind,
            &wok_db::keys::make_key_u64_u64(kind, 0),
            &[],
            false,
            |key, _| {
                present = key.get(..8) == Some(kind.to_ne_bytes().as_slice());
                false
            },
        )?;
        if present {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Who `relay.auth.read_policy` admits, as far as configuration decides it:
/// the policy, and under `members` the admin pubkeys, which are members
/// without a moderation record. A session opened under other access is
/// closed, so its connection is admitted again by its next NEG-OPEN.
fn read_access(cfg: &Config) -> (AccessPolicy, Option<Vec<String>>) {
    let policy = cfg.relay.auth.read_policy;
    let admins = (policy == AccessPolicy::Members).then(|| cfg.admin.pubkeys.clone());
    (policy, admins)
}

/// The most NEG-CLOSEs the worker handles in a row before it takes its next
/// snapshot.
const CLOSE_RUN: usize = 1024;

/// How long NEG-CLOSEs alone may keep the worker from its snapshot: its
/// configuration copy, read transaction and pass over every session.
const CLOSE_ONLY_SNAPSHOT_INTERVAL: Duration = Duration::from_millis(250);

/// Whether the worker takes its snapshot this pass. It always does before any
/// other message and while scans run, so sessions and scans see current
/// policy. A pass that only closed sessions skips it until
/// `CLOSE_ONLY_SNAPSHOT_INTERVAL` has passed since the last one, so closes
/// arriving one at a time cost no more than a run of them.
fn snapshot_due(closed_only: bool, scans_running: bool, since_last: Duration) -> bool {
    !closed_only || scans_running || since_last >= CLOSE_ONLY_SNAPSHOT_INTERVAL
}

pub(super) fn run_negentropy(
    env: Env,
    cfg: Arc<parking_lot::RwLock<Config>>,
    conns: Arc<ConnTable>,
    metrics: Arc<Metrics>,
    rx: Receiver<NegMsg>,
    pool: Arc<MemoryPool>,
) {
    let initial_cfg = cfg.read().clone();
    let mut queries = QueryScheduler::new(
        initial_cfg.relay.abuse.max_concurrent_historical_queries,
        initial_cfg.relay.max_sync_events.saturating_add(1),
        0,
    );
    queries.ensure_exists = false;
    let mut sessions: HashMap<(u64, String), Session> = HashMap::new();
    let mut authed: HashMap<u64, Vec<[u8; 32]>> = HashMap::new();
    let mut auth_epoch = 0;
    let mut policy = read_visibility(&initial_cfg, vec![]);
    let mut access = read_access(&initial_cfg);
    let mut filters = FilterRules::new(&initial_cfg);
    let mut generation = None;
    let mut last_snapshot = Instant::now();
    loop {
        let msg = if queries.has_running() {
            match rx.try_recv() {
                Ok(msg) => Some(msg),
                Err(crossbeam_channel::TryRecvError::Empty) => None,
                Err(_) => break,
            }
        } else {
            match rx.recv_timeout(Duration::from_millis(250)) {
                Ok(msg) => Some(msg),
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => None,
                Err(_) => break,
            }
        };
        // Closing a session needs no snapshot, so a run of NEG-CLOSEs is
        // handled here, a removal each. The configuration copy, read
        // transaction and pass over every session below then run once for
        // the run, not once per close, and scans still get their timeslice.
        let mut msg = msg;
        let mut closed = 0;
        for _ in 0..CLOSE_RUN {
            let Some(NegMsg::CloseSub { conn_id, sub_id }) = &msg else {
                break;
            };
            queries.remove_sub(*conn_id, sub_id);
            sessions.remove(&(*conn_id, sub_id.to_string()));
            closed += 1;
            msg = rx.try_recv().ok();
        }
        let closed_only = closed > 0 && msg.is_none();
        if !snapshot_due(closed_only, queries.has_running(), last_snapshot.elapsed()) {
            continue;
        }
        last_snapshot = Instant::now();
        let cfg = cfg.read().clone();
        // A reload that made AUTH unusable ended every login, so a session
        // opened since sees what its connection no longer may.
        for conn_id in expire_logins(&mut authed, &mut auth_epoch, cfg.auth_epoch) {
            reauthenticated(&mut sessions, &mut queries, &conns, &metrics, conn_id);
        }
        let txn = match env.begin_ro() {
            Ok(txn) => txn,
            Err(_) => continue,
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let next_policy = read_visibility(&cfg, vec![]);
        let next_access = read_access(&cfg);
        let current_generation = wok_db::state::policy_generation(&txn).ok();
        // A moderation commit bumps the generation, which also covers
        // membership by allowlist and role.
        let changed = next_policy != policy
            || next_access != access
            || current_generation != generation
            || current_generation.is_none()
            || !cfg.relay.negentropy_enabled;
        sessions.retain(|(conn, sid), session| {
            let idle = session
                .waiting_since
                .is_some_and(|since| since.elapsed().as_secs() >= cfg.relay.sync_idle_timeout_secs);
            if changed || idle || now >= session.expires_at {
                queries.remove_sub(*conn, &SubId::new(sid).unwrap());
                fail(
                    &conns,
                    &metrics,
                    *conn,
                    sid,
                    if idle {
                        "closed: idle synchronization"
                    } else {
                        "closed: visibility changed; reopen synchronization"
                    },
                );
                false
            } else {
                true
            }
        });
        // A reload that tightened the filter rules closes each session whose
        // filter they now refuse, with the NEG-ERR its NEG-OPEN would get.
        if filters.follow(&cfg) {
            let validator = &filters.validator;
            sessions.retain(|(conn, sid), session| {
                let Err(error) = validator.validate(&session.filter) else {
                    return true;
                };
                queries.remove_sub(*conn, &SubId::new(sid).unwrap());
                count_filter_limit(&metrics, &error);
                fail(&conns, &metrics, *conn, sid, &neg_filter_refusal(&error));
                false
            });
        }
        policy = next_policy;
        access = next_access;
        generation = current_generation;
        queries.set_max_subs_per_connection(cfg.relay.abuse.max_concurrent_historical_queries);
        // A NEG-OPEN over the concurrency cap waits, as a REQ does (#97 F2).
        // Sessions per connection are capped at this already.
        queries.set_max_waiting_per_connection(cfg.relay.max_subs_per_connection);
        queries.set_max_total_events_per_req(cfg.relay.max_sync_events.saturating_add(1));
        if let Some(msg) = msg {
            match msg {
                NegMsg::Open {
                    mut sub,
                    filter_str,
                    payload,
                } => {
                    let conn = sub.conn_id;
                    let sid = sub.sub_id.to_string();
                    let key = (conn, sid.clone());
                    // Sessions keep their filters for their lifetime, so a
                    // connection's sessions have a filter budget, as its live
                    // REQs and its COUNTs each do. The session this replaces
                    // is counted out, so, as for a REQ, a replacement no
                    // larger than it always fits.
                    let filter_budget = cfg.relay.max_filter_bytes_per_connection;
                    let replaced = sessions.get(&key).map_or(0, |session| session.filter_bytes);
                    let held: usize = sessions
                        .iter()
                        .filter(|(k, _)| k.0 == conn)
                        .map(|(_, session)| session.filter_bytes)
                        .sum();
                    if filter_budget != 0
                        && filter_str.len() > replaced
                        && held - replaced + filter_str.len() > filter_budget
                    {
                        // NIP-77: reusing the id closed its session, and the
                        // NEG-ERR ends this one, so neither is kept.
                        sessions.remove(&key);
                        queries.remove_sub(conn, &sub.sub_id);
                        metrics.refused(Setting::MaxFilterBytesPerConnection);
                        fail(
                            &conns,
                            &metrics,
                            conn,
                            &sid,
                            &format!(
                                "blocked: this connection's filters exceed {filter_budget} bytes"
                            ),
                        );
                        continue;
                    }
                    sessions.remove(&key);
                    queries.remove_sub(conn, &sub.sub_id);
                    // The ingester admitted this NEG-OPEN by the read policy
                    // of its time. One still queued when the access above
                    // changed would open a session nothing closes, so it is
                    // admitted again, by the state this view is read from;
                    // a retry is then refused with the reason.
                    let identities = authed.get(&conn).map_or(&[][..], Vec::as_slice);
                    let admitted = stored_reader_admitted(&txn, &cfg, identities);
                    if matches!(admitted, Ok(false)) {
                        metrics.refused(Setting::ReadPolicy);
                    }
                    if !admitted.unwrap_or(false) {
                        fail(
                            &conns,
                            &metrics,
                            conn,
                            &sid,
                            "closed: visibility changed; reopen synchronization",
                        );
                        continue;
                    }
                    // And by the filter rules, which a reload may have
                    // tightened since.
                    if let Err(error) = filters.validator.validate(&sub.filter_group) {
                        count_filter_limit(&metrics, &error);
                        fail(&conns, &metrics, conn, &sid, &neg_filter_refusal(&error));
                        continue;
                    }
                    if sessions.keys().filter(|k| k.0 == conn).count()
                        >= cfg.relay.max_subs_per_connection
                    {
                        metrics.refused(Setting::MaxSubsPerConnection);
                        fail(
                            &conns,
                            &metrics,
                            conn,
                            &sid,
                            "blocked: too many synchronization sessions",
                        );
                        continue;
                    }
                    let mut tree_id = None;
                    if public_tree_allowed(&txn, &sub, &cfg).unwrap_or(false) {
                        let _ = wok_db::foreach_negentropy_filter(&txn, |id, f| {
                            if f == filter_str {
                                tree_id = Some(id);
                                false
                            } else {
                                true
                            }
                        });
                    }
                    // The match-all tree must contain exactly one item per primary
                    // event. Detect old CLI import/delete drift without scanning the
                    // database on the network worker. Filtered trees get an exact
                    // membership check through the operator's `wok doctor`.
                    if let Some(id) = tree_id.filter(|_| filter_str == "{}") {
                        let complete = (|| -> Result<bool, wok_negentropy::NegError> {
                            let mut tree = wok_negentropy::open_ro(&txn, id)?;
                            Ok(tree.size_mut()? == txn.entries(txn.env().dbis().event)? as u64)
                        })();
                        if !matches!(complete, Ok(true)) {
                            fail(&conns, &metrics, conn, &sid,
                                "error: inconsistent negentropy tree; operator must run wok doctor and reindex");
                            continue;
                        }
                    }
                    // Reserve the construction peak before scheduling the query.
                    // Dedup tables, ranking heaps, vector growth and temporary hits
                    // are covered, then release excess after the immutable set seals.
                    let entries = txn.entries(txn.env().dbis().event).unwrap_or(usize::MAX) as u64;
                    let cap = cfg
                        .relay
                        .max_sync_events
                        .saturating_add(1)
                        .min(entries.saturating_add(1));
                    for f in &mut sub.filter_group.filters {
                        f.limit = f.limit.min(cap);
                    }
                    let first = sub.filter_group.filters.first();
                    let limit = first.map_or(0, |f| f.limit);
                    let per_item = wok_negentropy::memory_view_item_bytes(
                        first.is_some_and(|f| f.search.is_some()),
                    );
                    let bytes = if tree_id.is_some() {
                        ROUND_BYTES
                    } else {
                        ROUND_BYTES.saturating_add(limit.saturating_mul(per_item))
                    };
                    let reservation = match pool.reserve(conn, bytes, &cfg) {
                        Ok(reservation) => reservation,
                        Err(setting) => {
                            metrics.refused(setting);
                            fail(
                                &conns,
                                &metrics,
                                conn,
                                &sid,
                                "blocked: synchronization memory budget exceeded; narrow the \
                                 filter",
                            );
                            continue;
                        }
                    };
                    let filter = sub.filter_group.clone();
                    let view = if let Some(tree_id) = tree_id {
                        View::Tree { sub, tree_id }
                    } else {
                        // A view that waits for a scan slot is built, and
                        // answered, once its scan runs.
                        match queries.add_sub(&txn, sub) {
                            Ok(Scheduled::Running | Scheduled::Waiting) => View::Memory {
                                initial: payload.clone(),
                                items: Vector::new(),
                            },
                            refused => {
                                if let Ok(Scheduled::Refused) = refused {
                                    metrics.refused(scheduler_refusal(&cfg));
                                }
                                fail(
                                    &conns,
                                    &metrics,
                                    conn,
                                    &sid,
                                    "blocked: synchronization query unavailable",
                                );
                                continue;
                            }
                        }
                    };
                    let mut session = Session {
                        view,
                        reservation,
                        waiting_since: None,
                        expires_at: u64::MAX,
                        filter_bytes: filter_str.len(),
                        filter,
                    };
                    if let View::Tree { sub, tree_id } = &session.view {
                        if !reconcile_tree(
                            &txn, &conns, &metrics, conn, &sid, *tree_id, sub, &payload,
                        ) {
                            continue;
                        }
                        session.waiting_since = Some(Instant::now());
                    }
                    sessions.insert(key, session);
                }
                NegMsg::Msg {
                    conn_id,
                    sub_id,
                    payload,
                } => {
                    let key = (conn_id, sub_id.to_string());
                    let mut valid = false;
                    if let Some(session) = sessions.get_mut(&key) {
                        valid = match &mut session.view {
                            View::Memory { items, .. } if items.is_sealed() => send_vector(
                                &conns,
                                &metrics,
                                conn_id,
                                sub_id.as_str(),
                                items,
                                &payload,
                            ),
                            View::Tree { sub, tree_id }
                                if public_tree_allowed(&txn, sub, &cfg).unwrap_or(false) =>
                            {
                                reconcile_tree(
                                    &txn,
                                    &conns,
                                    &metrics,
                                    conn_id,
                                    sub_id.as_str(),
                                    *tree_id,
                                    sub,
                                    &payload,
                                )
                            }
                            _ => false,
                        };
                        if valid {
                            session.waiting_since = Some(Instant::now());
                        }
                    }
                    if !valid {
                        sessions.remove(&key);
                        queries.remove_sub(conn_id, &sub_id);
                        fail(
                            &conns,
                            &metrics,
                            conn_id,
                            sub_id.as_str(),
                            "closed: unknown subscription handle",
                        );
                    }
                }
                NegMsg::SetAuth {
                    conn_id,
                    authed: pk,
                    epoch,
                } => {
                    for conn_id in expire_logins(&mut authed, &mut auth_epoch, epoch) {
                        reauthenticated(&mut sessions, &mut queries, &conns, &metrics, conn_id);
                    }
                    // A login from an epoch a reload already ended is void.
                    if epoch == auth_epoch {
                        let identities = authed.entry(conn_id).or_default();
                        if !identities.contains(&pk) {
                            identities.push(pk);
                            reauthenticated(&mut sessions, &mut queries, &conns, &metrics, conn_id);
                        }
                    }
                }
                NegMsg::CloseSub { conn_id, sub_id } => {
                    queries.remove_sub(conn_id, &sub_id);
                    sessions.remove(&(conn_id, sub_id.to_string()));
                }
                NegMsg::Fail {
                    conn_id,
                    sub_id,
                    message,
                } => {
                    queries.remove_sub(conn_id, &sub_id);
                    sessions.remove(&(conn_id, sub_id.to_string()));
                    fail(&conns, &metrics, conn_id, sub_id.as_str(), &message);
                }
                NegMsg::Close { conn_id } => {
                    queries.close_conn(conn_id);
                    sessions.retain(|k, _| k.0 != conn_id);
                    authed.remove(&conn_id);
                }
            }
        }
        let mut done = Vec::new();
        let mut failed = Vec::new();
        let scan = queries.process_visible(
            &txn,
            cfg.relay.query_timeslice_budget_us,
            |sub| read_visibility(&cfg, authed.get(&sub.conn_id).cloned().unwrap_or_default()),
            |sub, lev, _| {
                let key = (sub.conn_id, sub.sub_id.to_string());
                let Some(session) = sessions.get_mut(&key) else {
                    return true;
                };
                let View::Memory { items, .. } = &mut session.view else {
                    return true;
                };
                let inserted = (|| {
                    let raw = txn
                        .get_u64(txn.env().dbis().event, lev)?
                        .ok_or_else(|| wok_db::DbError::msg("missing sync event"))?;
                    let event = PackedEventView::new(raw)?;
                    let expiration = if event.expiration() == 1 {
                        event
                            .created_at()
                            .saturating_add(cfg.events.ephemeral_lifetime_secs)
                    } else if event.expiration() > 1 {
                        event.expiration()
                    } else {
                        u64::MAX
                    };
                    session.expires_at = session.expires_at.min(expiration);
                    items
                        .insert(event.created_at(), event.id())
                        .map_err(|e| wok_db::DbError::msg(e.to_string()))
                })();
                if inserted.is_err() {
                    failed.push(key);
                    return false;
                }
                true
            },
            |sub, total, _, _, _| done.push((sub.clone(), total)),
        );
        if scan.is_err() {
            for (conn, sid) in sessions.keys() {
                fail(
                    &conns,
                    &metrics,
                    *conn,
                    sid,
                    "error: synchronization scan failed",
                );
                queries.close_conn(*conn);
            }
            sessions.clear();
        }
        for key in failed {
            sessions.remove(&key);
            queries.remove_sub(key.0, &SubId::new(&key.1).unwrap());
            fail(
                &conns,
                &metrics,
                key.0,
                &key.1,
                "error: synchronization construction failed",
            );
        }
        for (sub, total) in done {
            let key = (sub.conn_id, sub.sub_id.to_string());
            if total > cfg.relay.max_sync_events {
                metrics.refused(Setting::MaxSyncEvents);
                sessions.remove(&key);
                fail(
                    &conns,
                    &metrics,
                    key.0,
                    &key.1,
                    "blocked: too many query results",
                );
                continue;
            }
            if let Some(session) = sessions.get_mut(&key) {
                if let View::Memory { initial, items } = &mut session.view {
                    if items.seal().is_err()
                        || !send_vector(&conns, &metrics, key.0, &key.1, items, initial)
                    {
                        sessions.remove(&key);
                        fail(
                            &conns,
                            &metrics,
                            key.0,
                            &key.1,
                            "error: synchronization reconciliation failed",
                        );
                        continue;
                    }
                    *initial = Vec::new();
                    session
                        .reservation
                        .shrink(ROUND_BYTES + items.allocated_bytes() as u64);
                    session.waiting_since = Some(Instant::now());
                }
            }
        }
    }
}

fn send_vector(
    conns: &ConnTable,
    metrics: &Metrics,
    conn: u64,
    sid: &str,
    items: &mut Vector,
    payload: &[u8],
) -> bool {
    match Negentropy::new(items, 500_000).and_then(|mut ne| ne.reconcile(payload)) {
        Ok(reply) => {
            conns.send(
                conn,
                RelayMessage::NegMsg {
                    sub_id: sid.into(),
                    payload_hex: hex::encode(reply),
                },
                metrics,
            );
            true
        }
        Err(_) => false,
    }
}

/// Reconcile one message against a precomputed tree ("stateless" view in
/// C++). Returns false on protocol error (caller removes the view).
#[allow(clippy::too_many_arguments)]
fn reconcile_tree(
    txn: &wok_db::RoTxn<'_>,
    conns: &ConnTable,
    metrics: &Metrics,
    conn: u64,
    sid: &str,
    tree_id: u64,
    sub: &Subscription,
    payload: &[u8],
) -> bool {
    let resp = (|| -> Result<Vec<u8>, String> {
        let mut tree = wok_negentropy::open_ro(txn, tree_id).map_err(|e| e.to_string())?;
        let f = sub.filter_group.filters.first();
        let since = f.map(|f| f.since).unwrap_or(0);
        let until = f.map(|f| f.until).unwrap_or(u64::MAX);
        let lower = wok_negentropy::Bound::timestamp(since);
        let upper = wok_negentropy::Bound::timestamp(if until == u64::MAX {
            u64::MAX
        } else {
            until.saturating_add(1)
        });
        let sub_store =
            wok_negentropy::SubRange::new(&mut tree, &lower, &upper).map_err(|e| e.to_string())?;
        let mut ne = Negentropy::new(sub_store, 500_000).map_err(|e| e.to_string())?;
        ne.reconcile(payload).map_err(|e| e.to_string())
    })();
    match resp {
        Ok(r) => {
            conns.send(
                conn,
                RelayMessage::NegMsg {
                    sub_id: sid.to_string(),
                    payload_hex: hex::encode(r),
                },
                metrics,
            );
            true
        }
        Err(_) => {
            fail(
                conns,
                metrics,
                conn,
                sid,
                "error: invalid reconciliation message",
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The next frame `rx` receives.
    fn next(rx: &mut tokio::sync::mpsc::UnboundedReceiver<OutboundFrame>) -> Value {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(frame) = rx.try_recv() {
                return serde_json::from_str(&frame.into_text()).unwrap();
            }
            assert!(Instant::now() < deadline, "no frame");
            thread::sleep(Duration::from_millis(1));
        }
    }

    /// A NEG-OPEN the ingester admitted under an earlier read policy, still
    /// queued when access tightened, gets no session: the worker admits it
    /// again by the state it reads.
    #[test]
    fn queued_opens_are_admitted_again_by_the_worker() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), wok_db::EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let member = [7u8; 32];
        let mut txn = env.begin_rw().unwrap();
        wok_db::allow_pubkey(&mut txn, &member, "").unwrap();
        txn.commit().unwrap();
        let mut cfg = Config::default();
        cfg.db = dir.path().to_path_buf();
        cfg.relay.auth.read_policy = AccessPolicy::Members;
        let cfg = Arc::new(parking_lot::RwLock::new(cfg));
        let conns = Arc::new(ConnTable::new());
        let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel();
        conns.insert(1, Outbound::new(out_tx, 0));
        let (tx, rx) = crossbeam_channel::unbounded();
        let metrics = Arc::new(Metrics::default());
        let worker = {
            let (conns, metrics) = (conns.clone(), metrics.clone());
            let pool = Arc::new(MemoryPool::default());
            thread::spawn(move || run_negentropy(env, cfg, conns, metrics, rx, pool))
        };
        let mut store = wok_negentropy::Vector::new();
        store.seal().unwrap();
        let init = wok_negentropy::Negentropy::new(store, 60_000)
            .unwrap()
            .initiate()
            .unwrap();
        let open = |sub_id: &str| {
            let filter = json!({"kinds": [1]});
            let group = NostrFilterGroup::from_value(&filter, 1_000_001, 8, 16).unwrap();
            NegMsg::Open {
                sub: Subscription::new(1, SubId::new(sub_id).unwrap(), group, false),
                filter_str: filter.to_string(),
                payload: init.clone(),
            }
        };

        tx.send(open("anonymous")).unwrap();
        assert_eq!(
            next(&mut out_rx),
            json!([
                "NEG-ERR",
                "anonymous",
                "closed: visibility changed; reopen synchronization"
            ])
        );
        // The read policy refused it.
        assert_eq!(metrics.refusals.get(Setting::ReadPolicy), 1);
        tx.send(NegMsg::SetAuth {
            conn_id: 1,
            authed: member,
            epoch: 0,
        })
        .unwrap();
        tx.send(open("member")).unwrap();
        let reply = next(&mut out_rx);
        assert_eq!(
            (&reply[0], &reply[1]),
            (&json!("NEG-MSG"), &json!("member"))
        );
        assert_eq!(metrics.refusals.get(Setting::ReadPolicy), 1);
        drop(tx);
        worker.join().unwrap();
    }

    /// A reload that tightened `relay.filter_validation` closes each
    /// session whose filter it refuses, and refuses a NEG-OPEN still queued.
    #[test]
    fn a_reload_that_tightens_filter_validation_closes_the_sessions_it_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), wok_db::EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let mut cfg = Config::default();
        cfg.db = dir.path().to_path_buf();
        let cfg = Arc::new(parking_lot::RwLock::new(cfg));
        let conns = Arc::new(ConnTable::new());
        let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel();
        conns.insert(1, Outbound::new(out_tx, 0));
        let (tx, rx) = crossbeam_channel::unbounded();
        let worker = {
            let (cfg, conns) = (cfg.clone(), conns.clone());
            let metrics = Arc::new(Metrics::default());
            let pool = Arc::new(MemoryPool::default());
            thread::spawn(move || run_negentropy(env, cfg, conns, metrics, rx, pool))
        };
        let mut store = wok_negentropy::Vector::new();
        store.seal().unwrap();
        let init = wok_negentropy::Negentropy::new(store, 60_000)
            .unwrap()
            .initiate()
            .unwrap();
        let open = |sub_id: &str, filter: Value| {
            let group = NostrFilterGroup::from_value(&filter, 1_000_001, 8, 16).unwrap();
            NegMsg::Open {
                sub: Subscription::new(1, SubId::new(sub_id).unwrap(), group, false),
                filter_str: filter.to_string(),
                payload: init.clone(),
            }
        };
        let served = |reply: Value, sub_id: &str| {
            assert_eq!((&reply[0], &reply[1]), (&json!("NEG-MSG"), &json!(sub_id)));
        };
        let refused = |reply: Value, sub_id: &str| {
            assert_eq!((&reply[0], &reply[1]), (&json!("NEG-ERR"), &json!(sub_id)));
            let reason = reply[2].as_str().unwrap();
            assert!(
                reason.starts_with("blocked: filter validation failed: "),
                "{reason}"
            );
        };

        tx.send(open("all", json!({"kinds": [1]}))).unwrap();
        served(next(&mut out_rx), "all");
        tx.send(open("tagged", json!({"kinds": [1], "#t": ["wok"]})))
            .unwrap();
        served(next(&mut out_rx), "tagged");
        cfg.write().relay.filter_validation.require_scoped_filters = true;
        // Queued before the reload: admitted again by the rules it meets now.
        tx.send(open("queued", json!({"kinds": [1]}))).unwrap();
        refused(next(&mut out_rx), "all");
        refused(next(&mut out_rx), "queued");
        tx.send(open("tagged-again", json!({"kinds": [1], "#t": ["wok"]})))
            .unwrap();
        served(next(&mut out_rx), "tagged-again");
        drop(tx);
        worker.join().unwrap();
    }

    /// A reload that made AUTH unusable ended every login, so the sessions
    /// a login opened are closed, and a login from before it is void.
    #[test]
    fn a_reload_that_makes_auth_unusable_closes_the_sessions_of_a_login() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), wok_db::EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let member = [7u8; 32];
        let mut txn = env.begin_rw().unwrap();
        wok_db::allow_pubkey(&mut txn, &member, "").unwrap();
        txn.commit().unwrap();
        let mut cfg = Config::default();
        cfg.db = dir.path().to_path_buf();
        cfg.relay.auth.read_policy = AccessPolicy::Members;
        let cfg = Arc::new(parking_lot::RwLock::new(cfg));
        let conns = Arc::new(ConnTable::new());
        let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel();
        conns.insert(1, Outbound::new(out_tx, 0));
        let (tx, rx) = crossbeam_channel::unbounded();
        let worker = {
            let (cfg, conns) = (cfg.clone(), conns.clone());
            let metrics = Arc::new(Metrics::default());
            let pool = Arc::new(MemoryPool::default());
            thread::spawn(move || run_negentropy(env, cfg, conns, metrics, rx, pool))
        };
        let mut store = wok_negentropy::Vector::new();
        store.seal().unwrap();
        let init = wok_negentropy::Negentropy::new(store, 60_000)
            .unwrap()
            .initiate()
            .unwrap();
        let open = |sub_id: &str| {
            let filter = json!({"kinds": [1]});
            let group = NostrFilterGroup::from_value(&filter, 1_000_001, 8, 16).unwrap();
            NegMsg::Open {
                sub: Subscription::new(1, SubId::new(sub_id).unwrap(), group, false),
                filter_str: filter.to_string(),
                payload: init.clone(),
            }
        };
        let login = |epoch| NegMsg::SetAuth {
            conn_id: 1,
            authed: member,
            epoch,
        };
        let refused = |sub_id: &str| {
            json!([
                "NEG-ERR",
                sub_id,
                "closed: visibility changed; reopen synchronization"
            ])
        };
        let served = |reply: Value, sub_id: &str| {
            assert_eq!((&reply[0], &reply[1]), (&json!("NEG-MSG"), &json!(sub_id)));
        };

        tx.send(login(0)).unwrap();
        tx.send(open("member")).unwrap();
        served(next(&mut out_rx), "member");
        cfg.write().auth_epoch = 1;
        tx.send(open("after")).unwrap();
        assert_eq!(
            next(&mut out_rx),
            json!([
                "NEG-ERR",
                "member",
                "closed: authentication changed; reopen synchronization"
            ])
        );
        assert_eq!(next(&mut out_rx), refused("after"));
        // A login from before the reload, still queued, is void.
        tx.send(login(0)).unwrap();
        tx.send(open("stale")).unwrap();
        assert_eq!(next(&mut out_rx), refused("stale"));
        tx.send(login(1)).unwrap();
        tx.send(open("again")).unwrap();
        served(next(&mut out_rx), "again");
        drop(tx);
        worker.join().unwrap();
    }

    #[test]
    fn closes_alone_take_a_snapshot_at_most_every_interval() {
        let soon = CLOSE_ONLY_SNAPSHOT_INTERVAL / 10;
        // Closes alone, just after a snapshot: none, however they arrive.
        assert!(!snapshot_due(true, false, soon));
        // Once the interval has passed, closes alone take one.
        assert!(snapshot_due(true, false, CLOSE_ONLY_SNAPSHOT_INTERVAL));
        // Any other message, or a running scan, always takes one.
        assert!(snapshot_due(false, false, soon));
        assert!(snapshot_due(true, true, soon));
    }

    /// A long run of NEG-CLOSEs, almost all for sessions that do not exist,
    /// closes the one that does, and the NEG-OPEN queued behind the run is
    /// still answered.
    #[test]
    fn a_run_of_closes_closes_its_session_and_the_next_open_is_answered() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), wok_db::EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let mut cfg = Config::default();
        cfg.db = dir.path().to_path_buf();
        let cfg = Arc::new(parking_lot::RwLock::new(cfg));
        let conns = Arc::new(ConnTable::new());
        let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel();
        conns.insert(1, Outbound::new(out_tx, 0));
        let (tx, rx) = crossbeam_channel::unbounded();
        let worker = {
            let conns = conns.clone();
            let metrics = Arc::new(Metrics::default());
            let pool = Arc::new(MemoryPool::default());
            thread::spawn(move || run_negentropy(env, cfg, conns, metrics, rx, pool))
        };
        let mut store = wok_negentropy::Vector::new();
        store.seal().unwrap();
        let init = wok_negentropy::Negentropy::new(store, 60_000)
            .unwrap()
            .initiate()
            .unwrap();
        let open = |sub_id: &str| {
            let filter = json!({"kinds": [1]});
            let group = NostrFilterGroup::from_value(&filter, 1_000_001, 8, 16).unwrap();
            NegMsg::Open {
                sub: Subscription::new(1, SubId::new(sub_id).unwrap(), group, false),
                filter_str: filter.to_string(),
                payload: init.clone(),
            }
        };
        let close = |sub_id: &str| NegMsg::CloseSub {
            conn_id: 1,
            sub_id: SubId::new(sub_id).unwrap(),
        };

        tx.send(open("kept")).unwrap();
        assert_eq!(next(&mut out_rx)[1], "kept");
        for n in 0..3 * CLOSE_RUN {
            tx.send(close(&format!("none-{n}"))).unwrap();
        }
        tx.send(close("kept")).unwrap();
        tx.send(open("next")).unwrap();
        let reply = next(&mut out_rx);
        assert_eq!((&reply[0], &reply[1]), (&json!("NEG-MSG"), &json!("next")));
        tx.send(NegMsg::Msg {
            conn_id: 1,
            sub_id: SubId::new("kept").unwrap(),
            payload: init.clone(),
        })
        .unwrap();
        assert_eq!(
            next(&mut out_rx),
            json!(["NEG-ERR", "kept", "closed: unknown subscription handle"])
        );
        drop(tx);
        worker.join().unwrap();
    }

    /// A connection's sessions share `max_filter_bytes_per_connection`: a
    /// NEG-OPEN past it is refused, a replacement no larger than the session
    /// it replaces always fits, and closing a session gives its bytes back.
    /// A refused replacement closes the session it reused, as NIP-77 says.
    #[test]
    fn sessions_share_the_connection_filter_budget() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), wok_db::EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let filter = json!({"kinds": [1]});
        let mut cfg = Config::default();
        cfg.db = dir.path().to_path_buf();
        // Room for two sessions' filters, not three.
        cfg.relay.max_filter_bytes_per_connection = 2 * filter.to_string().len() + 1;
        let cfg = Arc::new(parking_lot::RwLock::new(cfg));
        let conns = Arc::new(ConnTable::new());
        let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel();
        conns.insert(1, Outbound::new(out_tx, 0));
        let (tx, rx) = crossbeam_channel::unbounded();
        let metrics = Arc::new(Metrics::default());
        let worker = {
            let (conns, metrics) = (conns.clone(), metrics.clone());
            let pool = Arc::new(MemoryPool::default());
            thread::spawn(move || run_negentropy(env, cfg, conns, metrics, rx, pool))
        };
        let mut store = wok_negentropy::Vector::new();
        store.seal().unwrap();
        let init = wok_negentropy::Negentropy::new(store, 60_000)
            .unwrap()
            .initiate()
            .unwrap();
        let open_with = |sub_id: &str, filter: &Value| {
            let group = NostrFilterGroup::from_value(filter, 1_000_001, 8, 16).unwrap();
            NegMsg::Open {
                sub: Subscription::new(1, SubId::new(sub_id).unwrap(), group, false),
                filter_str: filter.to_string(),
                payload: init.clone(),
            }
        };
        let open = |sub_id: &str| open_with(sub_id, &filter);
        let answer = |rx: &mut tokio::sync::mpsc::UnboundedReceiver<OutboundFrame>| {
            let reply = next(rx);
            (
                reply[0].as_str().unwrap().to_string(),
                reply[1].as_str().unwrap().to_string(),
            )
        };

        for sub_id in ["a", "b"] {
            tx.send(open(sub_id)).unwrap();
            assert_eq!(answer(&mut out_rx), ("NEG-MSG".into(), sub_id.into()));
        }
        tx.send(open("c")).unwrap();
        let refused = next(&mut out_rx);
        assert_eq!((&refused[0], &refused[1]), (&json!("NEG-ERR"), &json!("c")));
        assert!(refused[2]
            .as_str()
            .unwrap()
            .starts_with("blocked: this connection's filters"));
        assert_eq!(
            metrics.refusals.get(Setting::MaxFilterBytesPerConnection),
            1
        );
        // Replacing a session with a filter no larger reuses its own bytes.
        tx.send(open("a")).unwrap();
        assert_eq!(answer(&mut out_rx), ("NEG-MSG".into(), "a".into()));
        // A larger replacement past the budget is refused, and the session
        // whose id it reused is closed.
        tx.send(open_with("a", &json!({"kinds": [1, 2, 3]})))
            .unwrap();
        let refused = next(&mut out_rx);
        assert_eq!((&refused[0], &refused[1]), (&json!("NEG-ERR"), &json!("a")));
        tx.send(NegMsg::Msg {
            conn_id: 1,
            sub_id: SubId::new("a").unwrap(),
            payload: init.clone(),
        })
        .unwrap();
        assert_eq!(
            next(&mut out_rx),
            json!(["NEG-ERR", "a", "closed: unknown subscription handle"])
        );
        // Closing one frees its bytes.
        tx.send(NegMsg::CloseSub {
            conn_id: 1,
            sub_id: SubId::new("b").unwrap(),
        })
        .unwrap();
        tx.send(open("c")).unwrap();
        assert_eq!(answer(&mut out_rx), ("NEG-MSG".into(), "c".into()));
        drop(tx);
        worker.join().unwrap();
    }

    /// A refused replacement of a session whose scan is still waiting also
    /// cancels that scan: once the scan ahead of it finishes, nothing comes
    /// for the id.
    #[test]
    fn a_refused_replacement_cancels_the_waiting_scan_it_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let options = wok_db::EnvOptions {
            map_size: 1 << 30,
            ..wok_db::EnvOptions::default()
        };
        let env = Env::open(dir.path(), options).unwrap();
        env.ensure_initialized().unwrap();
        // Enough notes that a scan over them takes many timeslices.
        let mut events: Vec<wok_db::EventToWrite> = (0..5_000u64)
            .map(|i| {
                let mut id = [0xCCu8; 32];
                id[..8].copy_from_slice(&i.to_be_bytes());
                let event = json!({
                    "id": hex::encode(id), "pubkey": "ab".repeat(32),
                    "created_at": 1_700_000_000 + i, "kind": 1, "tags": [],
                    "content": "note", "sig": "00".repeat(64),
                });
                let parsed = wok_event::parse_and_verify_event(
                    &event,
                    &wok_event::EventLimits::default(),
                    None,
                    false,
                    false,
                )
                .unwrap();
                wok_db::EventToWrite::new(parsed.packed.into_bytes(), parsed.json)
            })
            .collect();
        let mut txn = env.begin_rw().unwrap();
        wok_db::write_events(&mut txn, &mut wok_db::NoopNegentropy, &mut events, false).unwrap();
        txn.commit().unwrap();

        let notes = json!({"kinds": [1]});
        let small = json!({"kinds": [7]});
        let large = json!({"kinds": [7, 8, 9]});
        let mut cfg = Config::default();
        cfg.db = dir.path().to_path_buf();
        // One scan at a time, in short slices, and room for `notes` and
        // `small` but not `notes` and `large`.
        cfg.relay.abuse.max_concurrent_historical_queries = 1;
        cfg.relay.query_timeslice_budget_us = 1;
        cfg.relay.max_filter_bytes_per_connection =
            notes.to_string().len() + small.to_string().len() + 1;
        let cfg = Arc::new(parking_lot::RwLock::new(cfg));
        let conns = Arc::new(ConnTable::new());
        let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel();
        conns.insert(1, Outbound::new(out_tx, 0));
        let (tx, rx) = crossbeam_channel::unbounded();
        let worker = {
            let conns = conns.clone();
            let metrics = Arc::new(Metrics::default());
            let pool = Arc::new(MemoryPool::default());
            thread::spawn(move || run_negentropy(env, cfg, conns, metrics, rx, pool))
        };
        let mut store = wok_negentropy::Vector::new();
        store.seal().unwrap();
        let init = wok_negentropy::Negentropy::new(store, 60_000)
            .unwrap()
            .initiate()
            .unwrap();
        let open = |sub_id: &str, filter: &Value| {
            let group = NostrFilterGroup::from_value(filter, 1_000_001, 8, 16).unwrap();
            NegMsg::Open {
                sub: Subscription::new(1, SubId::new(sub_id).unwrap(), group, false),
                filter_str: filter.to_string(),
                payload: init.clone(),
            }
        };
        // Frames until one for `sub_id` of type `kind`, none of them an
        // answer for "a".
        let until = |rx: &mut tokio::sync::mpsc::UnboundedReceiver<OutboundFrame>,
                     kind: &str,
                     sub_id: &str| loop {
            let frame = next(rx);
            assert_ne!(
                (&frame[0], &frame[1]),
                (&json!("NEG-MSG"), &json!("a")),
                "the replaced session answered"
            );
            if frame[0] == kind && frame[1] == sub_id {
                return frame;
            }
        };

        // "x" takes the only scan slot, so "a" waits behind it.
        tx.send(open("x", &notes)).unwrap();
        tx.send(open("a", &small)).unwrap();
        tx.send(open("a", &large)).unwrap();
        let refused = until(&mut out_rx, "NEG-ERR", "a");
        assert!(refused[2]
            .as_str()
            .unwrap()
            .starts_with("blocked: this connection's filters"));
        // "x" finishes, and the scan "a" waited for never starts.
        until(&mut out_rx, "NEG-MSG", "x");
        tx.send(NegMsg::Msg {
            conn_id: 1,
            sub_id: SubId::new("a").unwrap(),
            payload: init.clone(),
        })
        .unwrap();
        let reply = until(&mut out_rx, "NEG-ERR", "a");
        assert_eq!(reply[2], "closed: unknown subscription handle");
        drop(tx);
        worker.join().unwrap();
    }

    #[test]
    fn memory_pool_enforces_global_and_connection_limits_and_reclaims_on_drop() {
        let pool = Arc::new(MemoryPool::default());
        let mut cfg = Config::default();
        cfg.relay.sync_memory_per_connection = 10;
        cfg.relay.sync_memory_total = 15;
        let mut first = pool.reserve(1, 10, &cfg).unwrap();
        // A refusal names the budget it would exceed.
        let refused = |conn, bytes| pool.reserve(conn, bytes, &cfg).err();
        assert_eq!(refused(1, 1), Some(Setting::SyncMemoryPerConnection));
        assert_eq!(refused(2, 6), Some(Setting::SyncMemoryTotal));
        let second = pool.reserve(2, 5, &cfg).unwrap();
        first.shrink(4);
        assert_eq!(pool.0.lock().total, 9);
        drop(first);
        drop(second);
        assert_eq!(pool.0.lock().total, 0);
        assert!(pool.0.lock().connections.is_empty());
        assert_eq!(refused(1, u64::MAX), Some(Setting::SyncMemoryTotal));
    }
}
