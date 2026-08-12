//! Live subscription inverted index matching `src/ActiveMonitors.h`.

use crate::subid::{SubId, Subscription};
use std::collections::HashMap;
use wok_event::PackedEventView;

#[derive(Clone, Debug)]
pub struct Recipient {
    pub conn_id: u64,
    pub sub_id: SubId,
}

struct MonitorItem {
    conn_id: u64,
    sub_id: SubId,
    latest_event_id: u64,
}

pub struct ActiveMonitors {
    conns: HashMap<u64, HashMap<SubId, Subscription>>,
    all_ids: HashMap<[u8; 32], Vec<(usize, MonitorItem)>>,
    all_authors: HashMap<[u8; 32], Vec<(usize, MonitorItem)>>,
    all_tags: HashMap<Vec<u8>, Vec<(usize, MonitorItem)>>,
    all_kinds: HashMap<u64, Vec<(usize, MonitorItem)>>,
    all_others: Vec<(usize, MonitorItem)>,
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

    pub fn add_sub(&mut self, sub: Subscription, curr_event_id: u64) -> bool {
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
        self.install(&installed, curr_event_id);
        true
    }

    pub fn remove_sub(&mut self, conn_id: u64, sub_id: &SubId) {
        let removed = self
            .conns
            .get_mut(&conn_id)
            .and_then(|map| map.remove(sub_id))
            .is_some();
        if removed {
            if self
                .conns
                .get(&conn_id)
                .map(|m| m.is_empty())
                .unwrap_or(false)
            {
                self.conns.remove(&conn_id);
            }
            self.uninstall(conn_id, sub_id);
        }
    }

    pub fn close_conn(&mut self, conn_id: u64) {
        if let Some(map) = self.conns.remove(&conn_id) {
            for sub_id in map.keys() {
                self.uninstall(conn_id, sub_id);
            }
        }
    }

    pub fn process(&mut self, lev_id: u64, packed: PackedEventView<'_>) -> Vec<Recipient> {
        let mut recipients = Vec::new();
        let mut candidates: Vec<(u64, SubId)> = Vec::new();
        let mut id = [0u8; 32];
        id.copy_from_slice(packed.id());
        if let Some(items) = self.all_ids.get(&id) {
            for (_, it) in items {
                candidates.push((it.conn_id, it.sub_id.clone()));
            }
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(packed.pubkey());
        if let Some(items) = self.all_authors.get(&pk) {
            for (_, it) in items {
                candidates.push((it.conn_id, it.sub_id.clone()));
            }
        }
        packed.foreach_tag(|name, val| {
            let mut spec = Vec::with_capacity(1 + val.len());
            spec.push(name as u8);
            spec.extend_from_slice(val);
            if let Some(items) = self.all_tags.get(&spec) {
                for (_, it) in items {
                    candidates.push((it.conn_id, it.sub_id.clone()));
                }
            }
            true
        });
        if let Some(items) = self.all_kinds.get(&packed.kind()) {
            for (_, it) in items {
                candidates.push((it.conn_id, it.sub_id.clone()));
            }
        }
        for (_, it) in &self.all_others {
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
                if sub.latest_event_id >= lev_id {
                    continue;
                }
                if sub.filter_group.does_match(packed) {
                    sub.latest_event_id = lev_id;
                    recipients.push(Recipient { conn_id, sub_id });
                }
            }
        }
        recipients
    }

    fn install(&mut self, sub: &Subscription, curr: u64) {
        for (fi, f) in sub.filter_group.filters.iter().enumerate() {
            let item = MonitorItem {
                conn_id: sub.conn_id,
                sub_id: sub.sub_id.clone(),
                latest_event_id: curr,
            };
            if let Some(ids) = &f.ids {
                for i in 0..ids.size() {
                    let mut id = [0u8; 32];
                    id.copy_from_slice(ids.at(i));
                    self.all_ids
                        .entry(id)
                        .or_default()
                        .push((fi, item_clone(&item)));
                }
            } else if let Some(authors) = &f.authors {
                for i in 0..authors.size() {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(authors.at(i));
                    self.all_authors
                        .entry(a)
                        .or_default()
                        .push((fi, item_clone(&item)));
                }
            } else if !f.tags.is_empty() {
                for (name, set) in &f.tags {
                    for i in 0..set.size() {
                        let mut spec = vec![*name as u8];
                        spec.extend_from_slice(set.at(i));
                        self.all_tags
                            .entry(spec)
                            .or_default()
                            .push((fi, item_clone(&item)));
                    }
                }
            } else if let Some(kinds) = &f.kinds {
                for i in 0..kinds.size() {
                    self.all_kinds
                        .entry(kinds.at(i))
                        .or_default()
                        .push((fi, item_clone(&item)));
                }
            } else {
                self.all_others.push((fi, item));
            }
        }
    }

    fn uninstall(&mut self, conn_id: u64, sub_id: &SubId) {
        let pred = |it: &MonitorItem| it.conn_id == conn_id && it.sub_id == *sub_id;
        for v in self.all_ids.values_mut() {
            v.retain(|(_, it)| !pred(it));
        }
        self.all_ids.retain(|_, v| !v.is_empty());
        for v in self.all_authors.values_mut() {
            v.retain(|(_, it)| !pred(it));
        }
        self.all_authors.retain(|_, v| !v.is_empty());
        for v in self.all_tags.values_mut() {
            v.retain(|(_, it)| !pred(it));
        }
        self.all_tags.retain(|_, v| !v.is_empty());
        for v in self.all_kinds.values_mut() {
            v.retain(|(_, it)| !pred(it));
        }
        self.all_kinds.retain(|_, v| !v.is_empty());
        self.all_others.retain(|(_, it)| !pred(it));
    }
}

fn item_clone(item: &MonitorItem) -> MonitorItem {
    MonitorItem {
        conn_id: item.conn_id,
        sub_id: item.sub_id.clone(),
        latest_event_id: item.latest_event_id,
    }
}
