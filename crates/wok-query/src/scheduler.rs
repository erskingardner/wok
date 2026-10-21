use crate::scan::{Completeness, DbQuery};
use crate::subid::{SubId, Subscription};
use std::collections::{HashMap, VecDeque};
use wok_db::{most_recent_levid_ro, RoTxn};

/// A connection's queries, by subscription id and whether they answer a COUNT.
/// REQ and COUNT ids are separate namespaces: neither replaces the other.
type QueryKey = (SubId, bool);

/// A query whose scan failed. The scheduler has already dropped it.
#[derive(Debug)]
pub struct QueryFailure {
    pub sub: Subscription,
    pub error: wok_db::DbError,
}

impl std::fmt::Display for QueryFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "query {} failed: {}", self.sub.sub_id, self.error)
    }
}

impl std::error::Error for QueryFailure {}

pub struct QueryScheduler {
    pub ensure_exists: bool,
    conns: HashMap<u64, HashMap<QueryKey, usize>>,
    queries: Vec<Option<DbQuery>>,
    free: Vec<usize>,
    running: VecDeque<usize>,
    max_subs_per_connection: usize,
    max_total_events_per_req: u64,
    count_dedup_budget: u64,
    completeness: bool,
}

impl QueryScheduler {
    pub fn new(
        max_subs_per_connection: usize,
        max_total_events_per_req: u64,
        count_dedup_budget: u64,
    ) -> Self {
        Self {
            ensure_exists: true,
            conns: HashMap::new(),
            queries: Vec::new(),
            free: Vec::new(),
            running: VecDeque::new(),
            max_subs_per_connection,
            max_total_events_per_req,
            count_dedup_budget,
            completeness: false,
        }
    }

    /// Schedule a query. Its snapshot, the newest local event id it may
    /// return, is taken now unless the caller already fixed it (a REQ's is
    /// fixed at admission). It replaces a query of the same kind (REQ or
    /// COUNT) with the same id. False when the connection already runs
    /// `max_subs_per_connection` queries.
    pub fn add_sub(
        &mut self,
        txn: &RoTxn<'_>,
        mut sub: Subscription,
    ) -> Result<bool, wok_db::DbError> {
        // Replace first: a query that fails to start still ends the one with
        // its id, rather than leaving it running after the refusal.
        self.remove_query(sub.conn_id, &sub.sub_id, sub.count_only);
        if sub.latest_event_id == u64::MAX {
            sub.latest_event_id = most_recent_levid_ro(txn)?;
        }
        let conn = self.conns.entry(sub.conn_id).or_default();
        if conn.len() >= self.max_subs_per_connection {
            return Ok(false);
        }
        let mut q = DbQuery::new(sub, self.max_total_events_per_req, self.count_dedup_budget);
        if self.completeness {
            q.track_completeness();
        }
        // Reuse slots of finished/dead queries instead of growing forever.
        let idx = match self.free.pop() {
            Some(i) => {
                self.queries[i] = Some(q);
                i
            }
            None => {
                self.queries.push(Some(q));
                self.queries.len() - 1
            }
        };
        let sub = &self.queries[idx].as_ref().unwrap().sub;
        conn.insert((sub.sub_id.clone(), sub.count_only), idx);
        self.running.push_front(idx);
        Ok(true)
    }

    /// Drop the subscription (non-COUNT) query with this id, if it is running.
    pub fn remove_sub(&mut self, conn_id: u64, sub_id: &SubId) {
        self.remove_query(conn_id, sub_id, false);
    }

    /// Drop the REQ (`count_only` false) or COUNT query with this id, if it
    /// is still this generation's.
    pub fn remove_generation(
        &mut self,
        conn_id: u64,
        sub_id: &SubId,
        count_only: bool,
        generation: u64,
    ) {
        let current = self
            .conns
            .get(&conn_id)
            .and_then(|map| map.get(&(sub_id.clone(), count_only)))
            .and_then(|&idx| self.queries[idx].as_ref())
            .is_some_and(|q| q.sub.generation == generation);
        if current {
            self.remove_query(conn_id, sub_id, count_only);
        }
    }

    /// Drop the REQ (`count_only` false) or COUNT query with this id.
    pub fn remove_query(&mut self, conn_id: u64, sub_id: &SubId, count_only: bool) {
        if let Some(map) = self.conns.get_mut(&conn_id) {
            if let Some(idx) = map.remove(&(sub_id.clone(), count_only)) {
                if self.queries[idx].take().is_some() {
                    self.running.retain(|queued| *queued != idx);
                    self.free.push(idx);
                }
            }
            if map.is_empty() {
                self.conns.remove(&conn_id);
            }
        }
    }

    pub fn close_conn(&mut self, conn_id: u64) {
        if let Some(map) = self.conns.remove(&conn_id) {
            for idx in map.values() {
                if self.queries[*idx].take().is_some() {
                    self.running.retain(|queued| queued != idx);
                    self.free.push(*idx);
                }
            }
        }
    }

    pub fn process<F, C>(
        &mut self,
        txn: &RoTxn<'_>,
        time_budget_us: u64,
        on_event: F,
        on_complete: C,
    ) -> Result<(), QueryFailure>
    where
        F: FnMut(&Subscription, u64, Option<&[u8]>) -> bool,
        C: FnMut(&Subscription, u64, Option<String>, bool, Completeness),
    {
        self.process_visible(
            txn,
            time_budget_us,
            |_| Default::default(),
            on_event,
            on_complete,
        )
    }

    /// Give the first running query a time slice. `on_event` gets each event
    /// it sends and says whether the event reached the subscriber; a REQ that
    /// lost one cannot report NIP-67 `finish`.
    pub fn process_visible<F, C, V>(
        &mut self,
        txn: &RoTxn<'_>,
        time_budget_us: u64,
        visibility: V,
        mut on_event: F,
        mut on_complete: C,
    ) -> Result<(), QueryFailure>
    where
        V: Fn(&Subscription) -> crate::visibility::ReadVisibility,
        F: FnMut(&Subscription, u64, Option<&[u8]>) -> bool,
        C: FnMut(&Subscription, u64, Option<String>, bool, Completeness),
    {
        let Some(idx) = self.running.pop_front() else {
            return Ok(());
        };
        let dead = self
            .queries
            .get(idx)
            .and_then(|q| q.as_ref())
            .map(|q| q.dead)
            .unwrap_or(true);
        if dead {
            self.queries[idx] = None;
            self.free.push(idx);
            return Ok(());
        }
        let ensure_exists = self.ensure_exists;
        let result = {
            let q = self.queries[idx].as_mut().unwrap();
            q.set_visibility(visibility(&q.sub));
            let mut undelivered = false;
            let result = q.process(
                txn,
                |sub, lev| {
                    let payload = if ensure_exists {
                        txn.get_u64(txn.env().dbis().event_payload, lev)
                            .ok()
                            .flatten()
                    } else {
                        None
                    };
                    if ensure_exists && payload.is_none() {
                        undelivered = true;
                        return;
                    }
                    if !on_event(sub, lev, payload) {
                        undelivered = true;
                    }
                },
                time_budget_us,
            );
            if undelivered {
                q.mark_incomplete();
            }
            result
        };
        let complete = match result {
            Ok(complete) => complete,
            Err(error) => {
                // A mid-scan error must not leak the slot: recycle it and
                // drop the sub from the conn map exactly like completion,
                // or the connection's concurrent-query budget is permanently
                // reduced by one per error.
                let q = self.queries[idx].take().unwrap();
                self.free.push(idx);
                self.remove_query(q.sub.conn_id, &q.sub.sub_id, q.sub.count_only);
                return Err(QueryFailure { sub: q.sub, error });
            }
        };
        if complete {
            let q = self.queries[idx].take().unwrap();
            self.free.push(idx);
            self.remove_query(q.sub.conn_id, &q.sub.sub_id, q.sub.count_only);
            on_complete(
                &q.sub,
                q.sent_count(),
                q.hll_hex(),
                q.count_dedup_limited(),
                q.completeness(),
            );
        } else {
            self.running.push_back(idx);
        }
        Ok(())
    }

    pub fn has_running(&self) -> bool {
        !self.running.is_empty()
    }

    /// The query the next `process` call gives a time slice to.
    pub fn next_query(&self) -> Option<&Subscription> {
        let idx = *self.running.front()?;
        self.queries[idx].as_ref().map(|q| &q.sub)
    }

    pub fn set_max_subs_per_connection(&mut self, maximum: usize) {
        self.max_subs_per_connection = maximum;
    }

    pub fn set_max_total_events_per_req(&mut self, maximum: u64) {
        self.max_total_events_per_req = maximum;
    }

    /// Applies to queries added afterwards; see [`DbQuery::new`].
    pub fn set_count_dedup_budget(&mut self, budget: u64) {
        self.count_dedup_budget = budget;
    }

    /// Work out NIP-67 [`Completeness`] for the REQs added afterwards; see
    /// [`DbQuery::track_completeness`].
    pub fn set_completeness(&mut self, track: bool) {
        self.completeness = track;
    }
}
