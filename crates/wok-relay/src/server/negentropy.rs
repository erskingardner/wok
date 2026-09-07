//! Bounded reconciliation sessions. Only provably public trees bypass the
//! shared per-event visibility predicate; personalized views are temporary.
use super::*;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use wok_negentropy::{Negentropy, Vector};

// Covers protocol input/output buffers, query/filter state and traversal stacks.
const ROUND_BYTES: u64 = 4 * 1024 * 1024;

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
    fn reserve(self: &Arc<Self>, conn: u64, bytes: u64, cfg: &Config) -> Option<Reservation> {
        let mut usage = self.0.lock();
        let per_conn = usage.connections.get(&conn).copied().unwrap_or(0);
        if usage.total.checked_add(bytes)? > cfg.relay.sync_memory_total
            || per_conn.checked_add(bytes)? > cfg.relay.sync_memory_per_connection
        {
            return None;
        }
        usage.total += bytes;
        usage.connections.insert(conn, per_conn + bytes);
        Some(Reservation {
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
    for dbi in [db.moderation, db.vanish_pubkey].into_iter().flatten() {
        if txn.entries(dbi)? != 0 {
            return Ok(false);
        }
    }
    // Expiring/TTL records need per-event checks even between cleanup ticks.
    if txn.entries(db.event_expiration)? != 0 {
        return Ok(false);
    }
    let policy = restrictor(cfg);
    if !policy.restrict_to_involved {
        return Ok(true);
    }
    let filter = &sub.filter_group.filters[0];
    for kind in &policy.restricted_kinds {
        if filter
            .kinds
            .as_ref()
            .is_some_and(|kinds| !(0..kinds.size()).any(|i| kinds.at(i) == *kind))
        {
            continue;
        }
        let mut present = false;
        txn.foreach_full(
            db.event_kind,
            &wok_db::keys::make_key_u64_u64(*kind, 0),
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
    let mut policy = read_visibility(&initial_cfg, vec![]);
    let mut generation = None;
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
        let cfg = cfg.read().clone();
        let txn = match env.begin_ro() {
            Ok(txn) => txn,
            Err(_) => continue,
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let next_policy = read_visibility(&cfg, vec![]);
        let current_generation = wok_db::state::policy_generation(&txn).ok();
        let changed = next_policy != policy
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
        policy = next_policy;
        generation = current_generation;
        queries.set_max_subs_per_connection(cfg.relay.abuse.max_concurrent_historical_queries);
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
                    sessions.remove(&key);
                    queries.remove_sub(conn, &sub.sub_id);
                    if sessions.keys().filter(|k| k.0 == conn).count()
                        >= cfg.relay.max_subs_per_connection
                    {
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
                    let limit = sub.filter_group.filters[0].limit;
                    let per_item = if sub.filter_group.filters[0].search.is_some() {
                        1024
                    } else {
                        256
                    };
                    let bytes = if tree_id.is_some() {
                        ROUND_BYTES
                    } else {
                        ROUND_BYTES.saturating_add(limit.saturating_mul(per_item))
                    };
                    let Some(reservation) = pool.reserve(conn, bytes, &cfg) else {
                        fail(
                            &conns,
                            &metrics,
                            conn,
                            &sid,
                            "blocked: synchronization memory budget exceeded; narrow the filter",
                        );
                        continue;
                    };
                    let view = if let Some(tree_id) = tree_id {
                        View::Tree { sub, tree_id }
                    } else {
                        match queries.add_sub(&txn, sub) {
                            Ok(true) => View::Memory {
                                initial: payload.clone(),
                                items: Vector::new(),
                            },
                            _ => {
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
                } => {
                    let identities = authed.entry(conn_id).or_default();
                    if !identities.contains(&pk) {
                        identities.push(pk);
                        sessions.retain(|(conn, sid), _| {
                            if *conn == conn_id {
                                fail(
                                    &conns,
                                    &metrics,
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
                }
                NegMsg::CloseSub { conn_id, sub_id } => {
                    queries.remove_sub(conn_id, &sub_id);
                    sessions.remove(&(conn_id, sub_id.to_string()));
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
                    return;
                };
                let View::Memory { items, .. } = &mut session.view else {
                    return;
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
                }
            },
            |sub, total, _, _| done.push((sub.clone(), total)),
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
    #[test]
    fn memory_pool_enforces_global_and_connection_limits_and_reclaims_on_drop() {
        let pool = Arc::new(MemoryPool::default());
        let mut cfg = Config::default();
        cfg.relay.sync_memory_per_connection = 10;
        cfg.relay.sync_memory_total = 15;
        let mut first = pool.reserve(1, 10, &cfg).unwrap();
        assert!(pool.reserve(1, 1, &cfg).is_none());
        assert!(pool.reserve(2, 6, &cfg).is_none());
        let second = pool.reserve(2, 5, &cfg).unwrap();
        first.shrink(4);
        assert_eq!(pool.0.lock().total, 9);
        drop(first);
        drop(second);
        assert_eq!(pool.0.lock().total, 0);
        assert!(pool.0.lock().connections.is_empty());
        assert!(pool.reserve(1, u64::MAX, &cfg).is_none());
    }
}
