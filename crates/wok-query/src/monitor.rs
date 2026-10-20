//! Live subscription inverted index matching `src/ActiveMonitors.h`.

use crate::{
    pending::PendingBuffer,
    subid::{SubId, Subscription},
    NostrFilter,
};
use std::collections::HashMap;
use wok_db::SearchTermSet;
use wok_event::PackedEventView;

#[derive(Clone, Debug)]
pub struct Recipient {
    pub conn_id: u64,
    pub sub_id: SubId,
    /// The subscription's history is still being sent: buffer the match in
    /// its [`PendingBuffer`] instead of delivering it.
    pub pending: bool,
}

struct MonitorItem {
    conn_id: u64,
    sub_id: SubId,
}

/// A subscription and, until its history has been sent, the live matches
/// held back for it.
struct Monitored {
    sub: Subscription,
    pending: Option<PendingBuffer>,
}

pub struct ActiveMonitors {
    conns: HashMap<u64, HashMap<SubId, Monitored>>,
    all_ids: HashMap<[u8; 32], Vec<MonitorItem>>,
    all_authors: HashMap<[u8; 32], Vec<MonitorItem>>,
    all_tags: HashMap<Vec<u8>, Vec<MonitorItem>>,
    all_kinds: HashMap<u64, Vec<MonitorItem>>,
    all_others: Vec<MonitorItem>,
    max_subs: usize,
    content_subscriptions: usize,
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
            content_subscriptions: 0,
        }
    }

    /// Apply a reloaded per-connection cap. Subscriptions over a lowered cap
    /// stay and can still be replaced; new ids are refused until the count
    /// drops.
    pub fn set_max_subs(&mut self, max_subs: usize) {
        self.max_subs = max_subs;
    }

    pub fn add_sub(&mut self, sub: Subscription, _curr_event_id: u64) -> bool {
        // Only a new id takes a slot. Replacing an open one must succeed even
        // when a lowered cap leaves the connection over it, or the client
        // keeps an id that silently stops receiving.
        let open = self.conns.get(&sub.conn_id);
        let replacing = open.is_some_and(|conn| conn.contains_key(&sub.sub_id));
        if !replacing && open.map_or(0, |conn| conn.len()) >= self.max_subs {
            return false;
        }
        self.insert(sub, None);
        true
    }

    /// Register a subscription whose history is still being sent. Its matches
    /// are reported as pending, for `buffer`, until [`Self::finish_pending`].
    /// It replaces any subscription with the same id and takes no slot check:
    /// the caller admitted it.
    pub fn add_pending(&mut self, sub: Subscription, buffer: PendingBuffer) {
        self.insert(sub, Some(buffer));
    }

    fn insert(&mut self, sub: Subscription, pending: Option<PendingBuffer>) {
        self.remove_sub(sub.conn_id, &sub.sub_id);
        self.install(&sub);
        self.conns
            .entry(sub.conn_id)
            .or_default()
            .insert(sub.sub_id.clone(), Monitored { sub, pending });
    }

    pub fn remove_sub(&mut self, conn_id: u64, sub_id: &SubId) {
        if let Some(map) = self.conns.get_mut(&conn_id) {
            if let Some(entry) = map.remove(sub_id) {
                if map.is_empty() {
                    self.conns.remove(&conn_id);
                }
                self.uninstall(&entry.sub);
            }
        }
    }

    pub fn close_conn(&mut self, conn_id: u64) {
        if let Some(map) = self.conns.remove(&conn_id) {
            for (_, entry) in map {
                self.uninstall(&entry.sub);
            }
        }
    }

    pub fn subscription(&self, conn_id: u64, sub_id: &SubId) -> Option<&Subscription> {
        self.conns
            .get(&conn_id)?
            .get(sub_id)
            .map(|entry| &entry.sub)
    }

    /// The buffer of a subscription whose history is still being sent.
    pub fn pending_mut(&mut self, conn_id: u64, sub_id: &SubId) -> Option<&mut PendingBuffer> {
        self.conns
            .get_mut(&conn_id)?
            .get_mut(sub_id)?
            .pending
            .as_mut()
    }

    /// The history of this generation of the subscription has been sent up
    /// to `delivered`: deliver it live from now on, skipping stored events up
    /// to `delivered`, and hand back what was buffered. `None`, changing
    /// nothing, if that generation is no longer pending (closed, replaced, or
    /// already live).
    pub fn finish_pending(
        &mut self,
        conn_id: u64,
        sub_id: &SubId,
        generation: u64,
        delivered: u64,
    ) -> Option<PendingBuffer> {
        let entry = self.conns.get_mut(&conn_id)?.get_mut(sub_id)?;
        if entry.sub.generation != generation {
            return None;
        }
        let buffer = entry.pending.take()?;
        entry.sub.latest_event_id = entry.sub.latest_event_id.max(delivered);
        Some(buffer)
    }

    /// Whether the subscription with this id is pending, by generation.
    pub fn pending_generation(&self, conn_id: u64, sub_id: &SubId) -> Option<u64> {
        let entry = self.conns.get(&conn_id)?.get(sub_id)?;
        entry.pending.as_ref().map(|_| entry.sub.generation)
    }

    pub fn requires_content(&self) -> bool {
        self.content_subscriptions != 0
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
        let candidates = self.candidates(packed);

        for (conn_id, sub_id) in candidates {
            if let Some(entry) = self
                .conns
                .get_mut(&conn_id)
                .and_then(|m| m.get_mut(&sub_id))
            {
                let pending = entry.pending.is_some();
                let sub = &mut entry.sub;
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
                    recipients.push(Recipient {
                        conn_id,
                        sub_id,
                        pending,
                    });
                }
            }
        }
        recipients
    }

    fn candidates(&self, packed: PackedEventView<'_>) -> Vec<(u64, SubId)> {
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

        candidates
    }

    /// Content is needed only if an indexed candidate has a search filter
    /// whose other predicates match this event.
    pub fn event_requires_content(&self, packed: PackedEventView<'_>) -> bool {
        self.requires_content()
            && self.candidates(packed).iter().any(|(conn, sid)| {
                self.conns
                    .get(conn)
                    .and_then(|subs| subs.get(sid))
                    .is_some_and(|entry| {
                        entry
                            .sub
                            .filter_group
                            .filters
                            .iter()
                            .any(|f| f.search.is_some() && f.does_match_without_search(packed))
                    })
            })
    }

    fn install(&mut self, sub: &Subscription) {
        self.content_subscriptions += usize::from(sub.filter_group.requires_content());
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
            } else if !f.tags.is_empty() || !f.and_tags.is_empty() {
                for spec in tag_lookup_specs(f) {
                    self.all_tags.entry(spec).or_default().push(item());
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
        self.content_subscriptions -= usize::from(sub.filter_group.requires_content());
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
            } else if !f.tags.is_empty() || !f.and_tags.is_empty() {
                for spec in tag_lookup_specs(f) {
                    remove_where(&mut self.all_tags, &spec, &pred);
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

fn tag_lookup_specs(filter: &NostrFilter) -> Vec<Vec<u8>> {
    if let Some((name, values)) = filter.and_tags.first_key_value() {
        let mut spec = vec![*name as u8];
        spec.extend_from_slice(values.at(0));
        return vec![spec];
    }

    filter
        .tags
        .iter()
        .flat_map(|(name, values)| {
            (0..values.size()).map(move |i| {
                let mut spec = vec![*name as u8];
                spec.extend_from_slice(values.at(i));
                spec
            })
        })
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NostrFilterGroup;
    use serde_json::json;
    use wok_event::{PackedEventBuilder, PackedEventTagBuilder};

    fn event(id: u8, tags: &[&[u8]]) -> wok_event::PackedEvent {
        let mut builder = PackedEventTagBuilder::default();
        for value in tags {
            builder.add('t', value).unwrap();
        }
        PackedEventBuilder::build(&[id; 32], &[2; 32], id as u64, 1, 0, &builder).unwrap()
    }

    #[test]
    fn nip91_live_monitor_uses_a_seed_then_checks_every_constraint() {
        let group = NostrFilterGroup::from_value(
            &json!({
                "&t":["meme", "cat"],
                "#t":["meme", "cat", "black"]
            }),
            500,
            3,
            16,
        )
        .unwrap();
        let sub_id = SubId::new("nip91").unwrap();
        let mut sub = Subscription::new(1, sub_id.clone(), group, false);
        sub.latest_event_id = 0;
        let mut monitors = ActiveMonitors::new(10);
        assert!(monitors.add_sub(sub, 0));

        let matching = event(1, &[b"meme", b"cat", b"black"]);
        assert_eq!(monitors.process(1, matching.view(), None).len(), 1);
        let missing_or = event(2, &[b"meme", b"cat"]);
        assert!(monitors.process(2, missing_or.view(), None).is_empty());
        let missing_and = event(3, &[b"meme", b"black"]);
        assert!(monitors.process(3, missing_and.view(), None).is_empty());

        monitors.remove_sub(1, &sub_id);
        let later = event(4, &[b"meme", b"cat", b"black"]);
        assert!(monitors.process(4, later.view(), None).is_empty());
    }

    fn pending_sub(sub_id: &SubId, tag: &str, generation: u64, live_from: u64) -> Subscription {
        let group = NostrFilterGroup::from_value(&json!({"#t": [tag]}), 500, 3, 16).unwrap();
        let mut sub = Subscription::new(1, sub_id.clone(), group, false);
        sub.generation = generation;
        sub.latest_event_id = live_from;
        sub
    }

    #[test]
    fn pending_subscriptions_match_until_their_generation_goes_live() {
        let sub_id = SubId::new("s").unwrap();
        let mut monitors = ActiveMonitors::new(usize::MAX);
        monitors.add_pending(pending_sub(&sub_id, "a", 1, 10), PendingBuffer::new(10, 0));
        assert_eq!(monitors.pending_generation(1, &sub_id), Some(1));

        // Matched like a live subscription, but reported as pending.
        let first = event(11, &[b"a"]);
        let recipients = monitors.process(11, first.view(), None);
        assert_eq!(recipients.len(), 1);
        assert!(recipients[0].pending);
        // Stored events the monitor saw before registering are not rematched.
        let old = event(9, &[b"a"]);
        assert!(monitors.process(9, old.view(), None).is_empty());

        // A stale generation changes nothing.
        assert!(monitors.finish_pending(1, &sub_id, 0, 20).is_none());
        assert!(monitors.pending_mut(1, &sub_id).is_some());

        assert!(monitors.finish_pending(1, &sub_id, 1, 20).is_some());
        assert_eq!(monitors.pending_generation(1, &sub_id), None);
        // History covered everything up to 20.
        let covered = event(20, &[b"a"]);
        assert!(monitors.process(20, covered.view(), None).is_empty());
        let live = event(21, &[b"a"]);
        let recipients = monitors.process(21, live.view(), None);
        assert!(!recipients[0].pending);
        assert!(monitors.finish_pending(1, &sub_id, 1, 30).is_none());
    }

    #[test]
    fn a_new_generation_replaces_the_old_filter_at_once() {
        let sub_id = SubId::new("s").unwrap();
        let mut monitors = ActiveMonitors::new(usize::MAX);
        monitors.add_pending(pending_sub(&sub_id, "old", 1, 0), PendingBuffer::new(0, 0));
        monitors.finish_pending(1, &sub_id, 1, 0).unwrap();
        monitors.add_pending(pending_sub(&sub_id, "new", 2, 0), PendingBuffer::new(0, 0));

        let old = event(1, &[b"old"]);
        assert!(monitors.process(1, old.view(), None).is_empty());
        let new = event(2, &[b"new"]);
        let recipients = monitors.process_ephemeral(new.view(), None);
        assert!(recipients[0].pending);
        assert!(monitors.finish_pending(1, &sub_id, 1, 0).is_none());
        assert_eq!(monitors.subscription(1, &sub_id).unwrap().generation, 2);
    }
}
