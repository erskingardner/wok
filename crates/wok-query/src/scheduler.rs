use crate::scan::DbQuery;
use crate::subid::{SubId, Subscription};
use std::collections::{HashMap, VecDeque};
use wok_db::{most_recent_levid_ro, RoTxn};

pub struct QueryScheduler {
    pub ensure_exists: bool,
    conns: HashMap<u64, HashMap<SubId, usize>>,
    queries: Vec<Option<DbQuery>>,
    free: Vec<usize>,
    running: VecDeque<usize>,
    max_subs_per_connection: usize,
}

impl QueryScheduler {
    pub fn new(max_subs_per_connection: usize) -> Self {
        Self {
            ensure_exists: true,
            conns: HashMap::new(),
            queries: Vec::new(),
            free: Vec::new(),
            running: VecDeque::new(),
            max_subs_per_connection,
        }
    }

    pub fn add_sub(
        &mut self,
        txn: &RoTxn<'_>,
        mut sub: Subscription,
    ) -> Result<bool, wok_db::DbError> {
        sub.latest_event_id = most_recent_levid_ro(txn)?;
        self.remove_sub(sub.conn_id, &sub.sub_id);
        let conn = self.conns.entry(sub.conn_id).or_default();
        if conn.len() >= self.max_subs_per_connection {
            return Ok(false);
        }
        let q = DbQuery::new(sub);
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
        conn.insert(self.queries[idx].as_ref().unwrap().sub.sub_id.clone(), idx);
        self.running.push_front(idx);
        Ok(true)
    }

    pub fn remove_sub(&mut self, conn_id: u64, sub_id: &SubId) {
        if let Some(map) = self.conns.get_mut(&conn_id) {
            if let Some(idx) = map.remove(sub_id) {
                if let Some(q) = self.queries.get_mut(idx).and_then(|s| s.as_mut()) {
                    q.dead = true;
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
                if let Some(q) = self.queries.get_mut(*idx).and_then(|s| s.as_mut()) {
                    q.dead = true;
                }
            }
        }
    }

    pub fn process<F, C>(
        &mut self,
        txn: &RoTxn<'_>,
        time_budget_us: u64,
        mut on_event: F,
        mut on_complete: C,
    ) -> Result<(), wok_db::DbError>
    where
        F: FnMut(&Subscription, u64, Option<&[u8]>),
        C: FnMut(&Subscription, u64),
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
        let mut events: Vec<(Subscription, u64, Option<Vec<u8>>)> = Vec::new();
        let complete = {
            let q = self.queries[idx].as_mut().unwrap();
            q.process(
                txn,
                |sub, lev| {
                    let payload = if self.ensure_exists {
                        txn.get_u64(txn.env().dbis().event_payload, lev)
                            .ok()
                            .flatten()
                            .map(|b| b.to_vec())
                    } else {
                        None
                    };
                    if self.ensure_exists && payload.is_none() {
                        return;
                    }
                    events.push((sub.clone(), lev, payload));
                },
                time_budget_us,
            )?
        };
        for (sub, lev, payload) in events {
            on_event(&sub, lev, payload.as_deref());
        }
        if complete {
            let q = self.queries[idx].take().unwrap();
            self.free.push(idx);
            self.remove_sub(q.sub.conn_id, &q.sub.sub_id);
            on_complete(&q.sub, q.sent_count());
        } else {
            self.running.push_back(idx);
        }
        Ok(())
    }

    pub fn has_running(&self) -> bool {
        !self.running.is_empty()
    }

    pub fn set_max_subs_per_connection(&mut self, maximum: usize) {
        self.max_subs_per_connection = maximum;
    }
}
