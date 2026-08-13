//! Live subscription inverted index matching `src/ActiveMonitors.h`.

use crate::subid::{SubId, Subscription};
use std::collections::HashMap;
use wok_db::SearchTermSet;
use wok_event::PackedEventView;

#[derive(Clone, Debug)]
pub struct Recipient {
    pub conn_id: u64,
    pub sub_id: SubId,
}

struct MonitorItem {
    conn_id: u64,
    sub_id: SubId,
}

pub struct ActiveMonitors {
    conns: HashMap<u64, HashMap<SubId, Subscription>>,
    all_ids: HashMap<[u8; 32], Vec<MonitorItem>>,
    all_authors: HashMap<[u8; 32], Vec<MonitorItem>>,
    all_tags: HashMap<Vec<u8>, Vec<MonitorItem>>,
    all_kinds: HashMap<u64, Vec<MonitorItem>>,
    all_others: Vec<MonitorItem>,
    max_subs: usize,
}

impl ActiveMonitors {
    pub fn new(max_subs: usize) -> Self {
        Self {
            conns: HashMap::new(),
            all_ids: HashMap::new(),
            all_authors: HashMap::new(),
            all_tags: HashMap::new(),
            all_kinds: HashMap::new(),
            all_others: Vec::new(),
            max_subs,
        }
    }

    pub fn add_sub(&mut self, sub: Subscription, _curr_event_id: u64) -> bool {
        self.remove_sub(sub.conn_id, &sub.sub_id);
        let conn = self.conns.entry(sub.conn_id).or_default();
        if conn.len() >= self.max_subs {
            return false;
        }
        let conn_id = sub.conn_id;
        let sub_id = sub.sub_id.clone();
        conn.insert(sub_id.clone(), sub);
        let installed = self
            .conns
            .get(&conn_id)
            .unwrap()
            .get(&sub_id)
            .unwrap()
            .clone();
        self.install(&installed);
        true
    }

    pub fn remove_sub(&mut self, conn_id: u64, sub_id: &SubId) {
        if let Some(map) = self.conns.get_mut(&conn_id) {
            if let Some(sub) = map.remove(sub_id) {
                if map.is_empty() {
                    self.conns.remove(&conn_id);
                }
                self.uninstall(&sub);
            }
        }
    }

    pub fn close_conn(&mut self, conn_id: u64) {
        if let Some(map) = self.conns.remove(&conn_id) {
            for (_, sub) in map {
                self.uninstall(&sub);
            }
        }
    }

    pub fn requires_content(&self) -> bool {
        self.conns
            .values()
            .flat_map(HashMap::values)
            .any(|subscription| subscription.filter_group.requires_content())
    }

    pub fn process(
        &mut self,
        lev_id: u64,
        packed: PackedEventView<'_>,
        search_terms: Option<&SearchTermSet>,
    ) -> Vec<Recipient> {
        self.process_inner(Some(lev_id), packed, search_terms)
    }

    /// Match a live-only event without advancing a subscription's persisted
    /// local-event cursor. This keeps later DB-backed delivery monotonic.
    pub fn process_ephemeral(
        &mut self,
        packed: PackedEventView<'_>,
        search_terms: Option<&SearchTermSet>,
    ) -> Vec<Recipient> {
        self.process_inner(None, packed, search_terms)
    }

    fn process_inner(
        &mut self,
        lev_id: Option<u64>,
        packed: PackedEventView<'_>,
        search_terms: Option<&SearchTermSet>,
    ) -> Vec<Recipient> {
        let mut recipients = Vec::new();
        let mut candidates: Vec<(u64, SubId)> = Vec::new();
        let mut id = [0u8; 32];
        id.copy_from_slice(packed.id());
        if let Some(items) = self.all_ids.get(&id) {
            for it in items {
                candidates.push((it.conn_id, it.sub_id.clone()));
            }
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(packed.pubkey());
        if let Some(items) = self.all_authors.get(&pk) {
            for it in items {
                candidates.push((it.conn_id, it.sub_id.clone()));
            }
        }
        packed.foreach_tag(|name, val| {
            let mut spec = Vec::with_capacity(1 + val.len());
            spec.push(name as u8);
            spec.extend_from_slice(val);
            if let Some(items) = self.all_tags.get(&spec) {
                for it in items {
                    candidates.push((it.conn_id, it.sub_id.clone()));
                }
            }
            true
        });
        if let Some(items) = self.all_kinds.get(&packed.kind()) {
            for it in items {
                candidates.push((it.conn_id, it.sub_id.clone()));
            }
        }
        for it in &self.all_others {
            candidates.push((it.conn_id, it.sub_id.clone()));
        }

        candidates.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.as_str().cmp(b.1.as_str())));
        candidates.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);

        for (conn_id, sub_id) in candidates {
            if let Some(sub) = self
                .conns
                .get_mut(&conn_id)
                .and_then(|m| m.get_mut(&sub_id))
            {
                if let Some(lev_id) = lev_id {
                    if sub.latest_event_id >= lev_id {
                        continue;
                    }
                }
                if sub
                    .filter_group
                    .does_match_with_search_terms(packed, search_terms)
                {
                    if let Some(lev_id) = lev_id {
                        sub.latest_event_id = lev_id;
                    }
                    recipients.push(Recipient { conn_id, sub_id });
                }
            }
        }
        recipients
    }

    fn install(&mut self, sub: &Subscription) {
        for f in &sub.filter_group.filters {
            let item = || MonitorItem {
                conn_id: sub.conn_id,
                sub_id: sub.sub_id.clone(),
            };
            if let Some(ids) = &f.ids {
                for i in 0..ids.size() {
                    let mut id = [0u8; 32];
                    id.copy_from_slice(ids.at(i));
                    self.all_ids.entry(id).or_default().push(item());
                }
            } else if let Some(authors) = &f.authors {
                for i in 0..authors.size() {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(authors.at(i));
                    self.all_authors.entry(a).or_default().push(item());
                }
            } else if !f.tags.is_empty() {
                for (name, set) in &f.tags {
                    for i in 0..set.size() {
                        let mut spec = vec![*name as u8];
                        spec.extend_from_slice(set.at(i));
                        self.all_tags.entry(spec).or_default().push(item());
                    }
                }
            } else if let Some(kinds) = &f.kinds {
                for i in 0..kinds.size() {
                    self.all_kinds.entry(kinds.at(i)).or_default().push(item());
                }
            } else {
                self.all_others.push(item());
            }
        }
    }

    /// Remove exactly the lookup keys `install` added for this subscription,
    /// like C++ `uninstallLookups`: O(filter size), not O(index size).
    fn uninstall(&mut self, sub: &Subscription) {
        let pred = |it: &MonitorItem| it.conn_id == sub.conn_id && it.sub_id == sub.sub_id;
        for f in &sub.filter_group.filters {
            if let Some(ids) = &f.ids {
                for i in 0..ids.size() {
                    let mut id = [0u8; 32];
                    id.copy_from_slice(ids.at(i));
                    remove_where(&mut self.all_ids, &id, &pred);
                }
            } else if let Some(authors) = &f.authors {
                for i in 0..authors.size() {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(authors.at(i));
                    remove_where(&mut self.all_authors, &a, &pred);
                }
            } else if !f.tags.is_empty() {
                for (name, set) in &f.tags {
                    for i in 0..set.size() {
                        let mut spec = vec![*name as u8];
                        spec.extend_from_slice(set.at(i));
                        remove_where(&mut self.all_tags, &spec, &pred);
                    }
                }
            } else if let Some(kinds) = &f.kinds {
                for i in 0..kinds.size() {
                    remove_where(&mut self.all_kinds, &kinds.at(i), &pred);
                }
            } else {
                self.all_others.retain(|it| !pred(it));
            }
        }
    }
}

fn remove_where<K: std::hash::Hash + Eq>(
    map: &mut HashMap<K, Vec<MonitorItem>>,
    key: &K,
    pred: &dyn Fn(&MonitorItem) -> bool,
) {
    if let Some(v) = map.get_mut(key) {
        v.retain(|it| !pred(it));
        if v.is_empty() {
            map.remove(key);
        }
    }
}
