//! Live subscription inverted index matching `src/ActiveMonitors.h`.
//!
//! Each filter is indexed under one dimension: its ids, else its authors,
//! else its tag values, else its kinds, else with the filters that can match
//! any event. An event's candidates are the subscriptions under its id, its
//! author, its tags and its kind, plus those unindexed filters. Each candidate
//! is then matched in full, so the index only has to find every subscription
//! that can match.
//!
//! Subscriptions sit in numbered slots and the index holds slot numbers. Each
//! posting knows which of its slot's postings it is, and each slot records
//! where its postings sit in their buckets. Adding or removing a subscription
//! therefore costs O(its keys), however many subscriptions share them, and an
//! event is matched without allocating per tag or per candidate. A posting
//! also carries a mask of its filter's kinds, so a popular author's reactions
//! skip the feeds that want only notes without reading those subscriptions.

use crate::{
    pending::PendingBuffer,
    subid::{SubId, Subscription},
    NostrFilter,
};
use std::borrow::Borrow;
use std::collections::HashMap;
use std::hash::Hash;
use wok_db::SearchTermSet;
use wok_event::PackedEventView;

#[derive(Clone, Debug)]
pub struct Recipient {
    pub conn_id: u64,
    pub sub_id: SubId,
    /// The subscription's history is still being sent: buffer the match in
    /// its [`PendingBuffer`] instead of delivering it.
    pub pending: bool,
    /// The REQ generation of the subscription that matched.
    pub generation: u64,
}

/// A subscription and, until its history has been sent, the live matches
/// held back for it.
struct Monitored {
    sub: Subscription,
    pending: Option<PendingBuffer>,
}

/// One filter's entry under one key.
#[derive(Clone, Copy, Debug)]
struct Posting {
    slot: u32,
    /// Which of the slot's postings this is, in the order they were added.
    nth: u32,
    /// [`kind_bit`] of each kind the filter takes, or every bit if it takes
    /// any kind. An event whose bit is clear cannot match the filter.
    kinds: u64,
}

/// One of 64 bits for a kind, spread by a multiplicative hash so that common
/// kinds rarely share one.
fn kind_bit(kind: u64) -> u64 {
    1 << (kind.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 58)
}

fn kind_mask(filter: &NostrFilter) -> u64 {
    filter.kinds.as_ref().map_or(u64::MAX, |kinds| {
        kinds.iter().fold(0, |mask, kind| mask | kind_bit(kind))
    })
}

type Buckets<K> = HashMap<K, Vec<Posting>>;

/// A key of the index, borrowed from a filter.
#[derive(Clone, Copy)]
enum Key<'a> {
    Id(&'a [u8]),
    Author(&'a [u8]),
    Tag(u8, &'a [u8]),
    Kind(u64),
    Any,
}

/// Postings by key, each bucket in no particular order.
struct Index {
    ids: Buckets<[u8; 32]>,
    authors: Buckets<[u8; 32]>,
    /// By tag name byte, then by value as PackedEvent holds it.
    tags: Vec<Buckets<Box<[u8]>>>,
    /// Postings in `tags`, so an event's tags are read only if there are any.
    tag_postings: usize,
    kinds: Buckets<u64>,
    any: Vec<Posting>,
}

impl Index {
    fn new() -> Self {
        Self {
            ids: HashMap::new(),
            authors: HashMap::new(),
            tags: (0..=u8::MAX).map(|_| HashMap::new()).collect(),
            tag_postings: 0,
            kinds: HashMap::new(),
            any: Vec::new(),
        }
    }

    /// Add `posting` under `key` and return its position in the bucket.
    fn push(&mut self, key: Key<'_>, posting: Posting) -> u32 {
        let bucket = match key {
            Key::Id(id) => self.ids.entry(key32(id)).or_default(),
            Key::Author(pk) => self.authors.entry(key32(pk)).or_default(),
            Key::Tag(name, value) => {
                self.tag_postings += 1;
                let values = &mut self.tags[usize::from(name)];
                // Only a new key allocates.
                if !values.contains_key(value) {
                    values.insert(value.into(), Vec::new());
                }
                values.get_mut(value).expect("inserted above")
            }
            Key::Kind(kind) => self.kinds.entry(kind).or_default(),
            Key::Any => &mut self.any,
        };
        bucket.push(posting);
        position(bucket.len() - 1)
    }

    /// Remove the posting at `at` under `key`. The posting moved into its
    /// place records its new position in `places`.
    fn remove(&mut self, key: Key<'_>, at: u32, places: &mut [Vec<u32>]) {
        match key {
            Key::Id(id) => remove_from(&mut self.ids, id, at, places),
            Key::Author(pk) => remove_from(&mut self.authors, pk, at, places),
            Key::Tag(name, value) => {
                self.tag_postings -= 1;
                remove_from(&mut self.tags[usize::from(name)], value, at, places);
            }
            Key::Kind(kind) => remove_from(&mut self.kinds, &kind, at, places),
            Key::Any => {
                swap_remove(&mut self.any, at, places);
            }
        }
    }

    /// Call `add` with each bucket an event's id, author, tags and kind select,
    /// and the unindexed filters.
    fn lookup(&self, packed: PackedEventView<'_>, mut add: impl FnMut(&[Posting])) {
        let mut found = |bucket: Option<&Vec<Posting>>| {
            if let Some(bucket) = bucket {
                add(bucket);
            }
        };
        if !self.ids.is_empty() {
            found(self.ids.get(packed.id()));
        }
        if !self.authors.is_empty() {
            found(self.authors.get(packed.pubkey()));
        }
        if self.tag_postings != 0 {
            packed.foreach_tag(|name, value| {
                let values = &self.tags[usize::from(name as u8)];
                if !values.is_empty() {
                    found(values.get(value));
                }
                true
            });
        }
        if !self.kinds.is_empty() {
            found(self.kinds.get(&packed.kind()));
        }
        found(Some(&self.any));
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.ids.is_empty()
            && self.authors.is_empty()
            && self.tags.iter().all(HashMap::is_empty)
            && self.tag_postings == 0
            && self.kinds.is_empty()
            && self.any.is_empty()
    }

    #[cfg(test)]
    fn bucket(&self, key: Key<'_>) -> Option<&Vec<Posting>> {
        match key {
            Key::Id(id) => self.ids.get(id),
            Key::Author(pk) => self.authors.get(pk),
            Key::Tag(name, value) => self.tags[usize::from(name)].get(value),
            Key::Kind(kind) => self.kinds.get(&kind),
            Key::Any => Some(&self.any),
        }
    }

    /// Postings in every bucket, and in the tag buckets alone.
    #[cfg(test)]
    fn postings(&self) -> (usize, usize) {
        let tags: usize = self
            .tags
            .iter()
            .flat_map(HashMap::values)
            .map(Vec::len)
            .sum();
        let others: usize = self
            .ids
            .values()
            .chain(self.authors.values())
            .chain(self.kinds.values())
            .map(Vec::len)
            .sum();
        (tags + others + self.any.len(), tags)
    }
}

fn key32(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().expect("ids and authors are 32 bytes")
}

fn position(n: usize) -> u32 {
    u32::try_from(n).expect("fewer than 2^32 postings")
}

fn remove_from<K, Q>(map: &mut Buckets<K>, key: &Q, at: u32, places: &mut [Vec<u32>])
where
    K: Borrow<Q> + Hash + Eq,
    Q: Hash + Eq + ?Sized,
{
    let bucket = map.get_mut(key).expect("a key the slot was added under");
    if swap_remove(bucket, at, places) {
        map.remove(key);
    }
}

/// Remove `bucket[at]` in O(1) and point the posting that takes its place at
/// its new position. True if the bucket is now empty.
fn swap_remove(bucket: &mut Vec<Posting>, at: u32, places: &mut [Vec<u32>]) -> bool {
    bucket.swap_remove(at as usize);
    if let Some(moved) = bucket.get(at as usize) {
        places[moved.slot as usize][moved.nth as usize] = at;
    }
    bucket.is_empty()
}

/// Call `f` with each key `filter` is indexed under. An event the filter
/// matches has at least one of them.
fn for_each_key<'a>(filter: &'a NostrFilter, mut f: impl FnMut(Key<'a>)) {
    if let Some(ids) = &filter.ids {
        ids.iter().for_each(|id| f(Key::Id(id)));
    } else if let Some(authors) = &filter.authors {
        authors.iter().for_each(|pk| f(Key::Author(pk)));
    } else if let Some((name, values)) = filter.and_tags.first_key_value() {
        // A match has every AND value, so any one of them finds it.
        f(Key::Tag(*name as u8, values.at(0)));
    } else if let Some((name, values)) = filter.tags.iter().min_by_key(|(_, values)| values.size())
    {
        // A match has a value of every tag name, so one name's values find it.
        values
            .iter()
            .for_each(|value| f(Key::Tag(*name as u8, value)));
    } else if let Some(kinds) = &filter.kinds {
        kinds.iter().for_each(|kind| f(Key::Kind(kind)));
    } else {
        f(Key::Any);
    }
}

pub struct ActiveMonitors {
    conns: HashMap<u64, HashMap<SubId, u32>>,
    /// Subscriptions by slot. A free slot holds `None`.
    slots: Vec<Option<Monitored>>,
    /// For each slot, where its postings sit in their buckets, by `nth`.
    places: Vec<Vec<u32>>,
    free: Vec<u32>,
    /// Filters without a search. Filters with one are in `search`, so the
    /// check for whether an event's content is needed looks only at those.
    index: Index,
    search: Index,
    /// The candidate pass that last took each slot, so a pass takes it once.
    seen: Vec<u64>,
    pass: u64,
    /// The slots the last pass took. Kept to reuse its allocation.
    candidates: Vec<u32>,
    max_subs: usize,
    content_subscriptions: usize,
}

impl ActiveMonitors {
    pub fn new(max_subs: usize) -> Self {
        Self {
            conns: HashMap::new(),
            slots: Vec::new(),
            places: Vec::new(),
            free: Vec::new(),
            index: Index::new(),
            search: Index::new(),
            seen: Vec::new(),
            pass: 0,
            candidates: Vec::new(),
            max_subs,
            content_subscriptions: 0,
        }
    }

    /// Whether no connection holds a subscription.
    pub fn is_empty(&self) -> bool {
        self.conns.is_empty()
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
        let open = self
            .conns
            .get(&sub.conn_id)
            .and_then(|subs| subs.get(&sub.sub_id))
            .copied();
        let slot = match open {
            // A new generation takes over the slot of the one it replaces.
            Some(slot) => {
                self.uninstall(slot);
                slot
            }
            None => {
                let slot = self.allocate();
                self.conns
                    .entry(sub.conn_id)
                    .or_default()
                    .insert(sub.sub_id.clone(), slot);
                slot
            }
        };
        self.slots[slot as usize] = Some(Monitored { sub, pending });
        self.install(slot);
    }

    pub fn remove_sub(&mut self, conn_id: u64, sub_id: &SubId) {
        let Some(subs) = self.conns.get_mut(&conn_id) else {
            return;
        };
        let Some(slot) = subs.remove(sub_id) else {
            return;
        };
        if subs.is_empty() {
            self.conns.remove(&conn_id);
        }
        self.release(slot);
    }

    /// Remove each subscription, pending or live, that `refusal` gives a
    /// reason for, returning its connection, id, generation and reason.
    pub fn remove_refused<R>(
        &mut self,
        mut refusal: impl FnMut(&Subscription) -> Option<R>,
    ) -> Vec<(u64, SubId, u64, R)> {
        let mut refused = Vec::new();
        for subs in self.conns.values() {
            for &slot in subs.values() {
                let Some(entry) = &self.slots[slot as usize] else {
                    continue;
                };
                if let Some(reason) = refusal(&entry.sub) {
                    let sub = &entry.sub;
                    refused.push((sub.conn_id, sub.sub_id.clone(), sub.generation, reason));
                }
            }
        }
        for (conn_id, sub_id, _, _) in &refused {
            self.remove_sub(*conn_id, sub_id);
        }
        refused
    }

    pub fn close_conn(&mut self, conn_id: u64) {
        if let Some(subs) = self.conns.remove(&conn_id) {
            for slot in subs.into_values() {
                self.release(slot);
            }
        }
    }

    pub fn subscription(&self, conn_id: u64, sub_id: &SubId) -> Option<&Subscription> {
        self.entry(conn_id, sub_id).map(|entry| &entry.sub)
    }

    /// The buffer of a subscription whose history is still being sent.
    pub fn pending_mut(&mut self, conn_id: u64, sub_id: &SubId) -> Option<&mut PendingBuffer> {
        self.entry_mut(conn_id, sub_id)?.pending.as_mut()
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
        let entry = self.entry_mut(conn_id, sub_id)?;
        if entry.sub.generation != generation {
            return None;
        }
        let buffer = entry.pending.take()?;
        entry.sub.latest_event_id = entry.sub.latest_event_id.max(delivered);
        Some(buffer)
    }

    /// Whether the subscription with this id is pending, by generation.
    pub fn pending_generation(&self, conn_id: u64, sub_id: &SubId) -> Option<u64> {
        let entry = self.entry(conn_id, sub_id)?;
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
        self.collect(packed, false);
        let mut recipients = Vec::new();
        for &slot in &self.candidates {
            let entry = self.slots[slot as usize]
                .as_mut()
                .expect("an indexed slot is occupied");
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
                    conn_id: sub.conn_id,
                    sub_id: sub.sub_id.clone(),
                    pending: entry.pending.is_some(),
                    generation: sub.generation,
                });
            }
        }
        // By connection, then subscription id.
        recipients.sort_unstable_by(|a, b| {
            a.conn_id
                .cmp(&b.conn_id)
                .then_with(|| a.sub_id.as_str().cmp(b.sub_id.as_str()))
        });
        recipients
    }

    /// Content is needed only if an indexed candidate has a search filter
    /// whose other predicates match this event.
    pub fn event_requires_content(&mut self, packed: PackedEventView<'_>) -> bool {
        if !self.requires_content() {
            return false;
        }
        self.collect(packed, true);
        self.candidates.iter().any(|&slot| {
            self.slots[slot as usize].as_ref().is_some_and(|entry| {
                entry
                    .sub
                    .filter_group
                    .filters
                    .iter()
                    .any(|f| f.search.is_some() && f.does_match_without_search(packed))
            })
        })
    }

    /// Gather into `candidates`, once each, the slots an event's keys select,
    /// from every filter or only from those with a search, leaving out
    /// filters that do not take the event's kind.
    fn collect(&mut self, packed: PackedEventView<'_>, search_only: bool) {
        self.pass += 1;
        self.candidates.clear();
        let (pass, seen, candidates) = (self.pass, &mut self.seen, &mut self.candidates);
        let kind = kind_bit(packed.kind());
        let mut add = |bucket: &[Posting]| {
            for posting in bucket {
                if posting.kinds & kind == 0 {
                    continue;
                }
                let seen = &mut seen[posting.slot as usize];
                if *seen != pass {
                    *seen = pass;
                    candidates.push(posting.slot);
                }
            }
        };
        if !search_only {
            self.index.lookup(packed, &mut add);
        }
        self.search.lookup(packed, &mut add);
    }

    fn entry(&self, conn_id: u64, sub_id: &SubId) -> Option<&Monitored> {
        let slot = *self.conns.get(&conn_id)?.get(sub_id)?;
        self.slots[slot as usize].as_ref()
    }

    fn entry_mut(&mut self, conn_id: u64, sub_id: &SubId) -> Option<&mut Monitored> {
        let slot = *self.conns.get(&conn_id)?.get(sub_id)?;
        self.slots[slot as usize].as_mut()
    }

    fn allocate(&mut self) -> u32 {
        self.free.pop().unwrap_or_else(|| {
            let slot = u32::try_from(self.slots.len()).expect("fewer than 2^32 subscriptions");
            self.slots.push(None);
            self.places.push(Vec::new());
            self.seen.push(0);
            slot
        })
    }

    fn release(&mut self, slot: u32) {
        self.uninstall(slot);
        self.free.push(slot);
    }

    /// Index the subscription in `slot` under every key of its filters.
    fn install(&mut self, slot: u32) {
        let sub = &self.slots[slot as usize]
            .as_ref()
            .expect("a subscription to install")
            .sub;
        self.content_subscriptions += usize::from(sub.filter_group.requires_content());
        let places = &mut self.places[slot as usize];
        for filter in &sub.filter_group.filters {
            let index = if filter.search.is_some() {
                &mut self.search
            } else {
                &mut self.index
            };
            let kinds = kind_mask(filter);
            for_each_key(filter, |key| {
                let nth = position(places.len());
                places.push(index.push(key, Posting { slot, nth, kinds }));
            });
        }
    }

    /// Take the subscription out of `slot` and remove exactly the postings
    /// `install` added for it, in the same order: O(its keys), like C++
    /// `uninstallLookups`.
    fn uninstall(&mut self, slot: u32) -> Monitored {
        let entry = self.slots[slot as usize]
            .take()
            .expect("a subscription to uninstall");
        self.content_subscriptions -= usize::from(entry.sub.filter_group.requires_content());
        let mut nth = 0;
        for filter in &entry.sub.filter_group.filters {
            let index = if filter.search.is_some() {
                &mut self.search
            } else {
                &mut self.index
            };
            for_each_key(filter, |key| {
                // Read now: removing an earlier posting may have moved this one.
                let at = self.places[slot as usize][nth];
                nth += 1;
                index.remove(key, at, &mut self.places);
            });
        }
        self.places[slot as usize].clear();
        entry
    }

    /// The index holds exactly the keys of the subscriptions in `conns`, each
    /// posting where its slot says, and the free slots are the empty ones.
    #[cfg(test)]
    fn assert_consistent(&self) {
        let mut occupied = 0;
        for (&conn_id, subs) in &self.conns {
            assert!(!subs.is_empty());
            for (sub_id, &slot) in subs {
                let sub = &self.slots[slot as usize].as_ref().unwrap().sub;
                assert_eq!((sub.conn_id, &sub.sub_id), (conn_id, sub_id));
                occupied += 1;
            }
        }
        assert_eq!(occupied + self.free.len(), self.slots.len());
        let mut postings = 0;
        let mut content = 0;
        for (slot, entry) in self.slots.iter().enumerate() {
            let places = &self.places[slot];
            let Some(entry) = entry else {
                assert!(places.is_empty() && self.free.contains(&(slot as u32)));
                continue;
            };
            content += usize::from(entry.sub.filter_group.requires_content());
            let mut nth = 0;
            for filter in &entry.sub.filter_group.filters {
                let index = if filter.search.is_some() {
                    &self.search
                } else {
                    &self.index
                };
                for_each_key(filter, |key| {
                    let posting = index.bucket(key).unwrap()[places[nth] as usize];
                    assert_eq!((posting.slot, posting.nth), (slot as u32, nth as u32));
                    nth += 1;
                });
            }
            assert_eq!(nth, places.len());
            postings += nth;
        }
        let (plain, plain_tags) = self.index.postings();
        let (search, search_tags) = self.search.postings();
        assert_eq!(plain + search, postings);
        assert_eq!(
            (self.index.tag_postings, self.search.tag_postings),
            (plain_tags, search_tags)
        );
        assert_eq!(self.content_subscriptions, content);
    }

    #[cfg(test)]
    fn assert_empty(&self) {
        self.assert_consistent();
        assert!(self.conns.is_empty());
        assert!(self.slots.iter().all(Option::is_none));
        assert!(self.index.is_empty() && self.search.is_empty());
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

    fn sub(conn_id: u64, sub_id: &str, filters: serde_json::Value) -> Subscription {
        let group = NostrFilterGroup::from_value(&filters, 500, 3, 16).unwrap();
        let mut sub = Subscription::new(conn_id, SubId::new(sub_id).unwrap(), group, false);
        sub.latest_event_id = 0;
        sub
    }

    fn by(author: u8, kind: u64) -> wok_event::PackedEvent {
        let tags = PackedEventTagBuilder::default();
        PackedEventBuilder::build(&[9; 32], &[author; 32], 1, kind, 0, &tags).unwrap()
    }

    fn matched(recipients: &[Recipient]) -> Vec<(u64, &str)> {
        recipients
            .iter()
            .map(|r| (r.conn_id, r.sub_id.as_str()))
            .collect()
    }

    #[test]
    fn removing_one_subscription_leaves_the_shared_keys_to_the_others() {
        let a = hex::encode([1u8; 32]);
        let b = hex::encode([2u8; 32]);
        let mut monitors = ActiveMonitors::new(usize::MAX);
        // Same key twice in one subscription, and unindexed filters twice.
        monitors.add_sub(
            sub(1, "x", json!([{"authors": [a]}, {"authors": [a, b]}])),
            0,
        );
        monitors.add_sub(sub(2, "y", json!({"authors": [b, a]})), 0);
        monitors.add_sub(sub(3, "z", json!([{"authors": [a]}, {}, {}])), 0);
        monitors.add_sub(sub(1, "w", json!({"kinds": [7]})), 0);
        monitors.assert_consistent();

        let mut lev = 0;
        let mut process = |monitors: &mut ActiveMonitors, author, kind| {
            lev += 1;
            let event = by(author, kind);
            let recipients = monitors.process(lev, event.view(), None);
            matched(&recipients)
                .into_iter()
                .map(|(c, s)| (c, s.to_owned()))
                .collect::<Vec<_>>()
        };
        let all = |ids: &[(u64, &str)]| -> Vec<(u64, String)> {
            ids.iter().map(|&(c, s)| (c, s.to_owned())).collect()
        };
        assert_eq!(
            process(&mut monitors, 1, 7),
            all(&[(1, "w"), (1, "x"), (2, "y"), (3, "z")])
        );

        monitors.remove_sub(1, &SubId::new("x").unwrap());
        monitors.assert_consistent();
        assert_eq!(process(&mut monitors, 1, 1), all(&[(2, "y"), (3, "z")]));
        assert_eq!(process(&mut monitors, 3, 1), all(&[(3, "z")]));

        monitors.close_conn(3);
        monitors.assert_consistent();
        assert_eq!(process(&mut monitors, 2, 7), all(&[(1, "w"), (2, "y")]));

        monitors.close_conn(1);
        monitors.remove_sub(2, &SubId::new("y").unwrap());
        monitors.assert_empty();
        assert!(process(&mut monitors, 1, 7).is_empty());
    }

    #[test]
    fn replacing_a_subscription_moves_it_to_the_new_keys() {
        let a = hex::encode([1u8; 32]);
        let mut monitors = ActiveMonitors::new(usize::MAX);
        monitors.add_sub(sub(1, "s", json!({"authors": [a], "#t": ["x"]})), 0);
        monitors.add_sub(sub(1, "s", json!({"#t": ["x", "y"], "#p": [a]})), 0);
        monitors.add_sub(sub(1, "s", json!({"kinds": [1]})), 0);
        monitors.assert_consistent();
        assert_eq!(monitors.slots.len(), 1);
        assert!(monitors.index.authors.is_empty() && monitors.index.tag_postings == 0);

        let event = by(3, 1);
        assert_eq!(
            matched(&monitors.process(1, event.view(), None)),
            [(1, "s")]
        );
        monitors.remove_sub(1, &SubId::new("s").unwrap());
        monitors.assert_empty();
    }

    #[test]
    fn a_tag_filter_is_indexed_under_its_smallest_tag_name() {
        let p = hex::encode([1u8; 32]);
        let mut monitors = ActiveMonitors::new(usize::MAX);
        monitors.add_sub(sub(1, "s", json!({"#t": ["a", "b", "c"], "#p": [p]})), 0);
        assert_eq!(monitors.index.tag_postings, 1);
        assert_eq!(monitors.index.tags[usize::from(b'p')].len(), 1);

        let mut tags = PackedEventTagBuilder::default();
        tags.add('t', b"b").unwrap();
        tags.add('p', &[1; 32]).unwrap();
        let event = PackedEventBuilder::build(&[9; 32], &[2; 32], 1, 1, 0, &tags).unwrap();
        assert_eq!(
            matched(&monitors.process(1, event.view(), None)),
            [(1, "s")]
        );
    }

    #[test]
    fn only_search_filters_decide_whether_content_is_needed() {
        let a = hex::encode([1u8; 32]);
        let mut monitors = ActiveMonitors::new(usize::MAX);
        monitors.add_sub(
            sub(
                1,
                "s",
                json!([{"authors": [a]}, {"search": "foo", "kinds": [1]}]),
            ),
            0,
        );
        assert!(monitors.requires_content());
        assert!(monitors.event_requires_content(by(2, 1).view()));
        // The plain filter matches, but needs no content.
        assert!(!monitors.event_requires_content(by(1, 2).view()));

        let event = by(2, 1);
        let terms = wok_db::search_term_set("foo bar");
        assert!(monitors.process(1, event.view(), None).is_empty());
        assert_eq!(
            matched(&monitors.process(2, event.view(), Some(&terms))),
            [(1, "s")]
        );
        monitors.close_conn(1);
        assert!(!monitors.requires_content());
        monitors.assert_empty();
    }

    mod model {
        //! Random add, replace, remove and close sequences against a matcher
        //! that tries every subscription.

        use super::*;
        use proptest::prelude::*;
        use std::collections::BTreeMap;

        const CONNS: u64 = 3;
        const SUB_IDS: u8 = 4;
        const MAX_SUBS: usize = 3;
        const WORDS: [&str; 3] = ["foo", "bar", "foo bar"];
        const TAG_VALUES: [&[u8]; 3] = [b"a", b"b", b"c"];

        #[derive(Clone, Debug)]
        enum Op {
            Add {
                conn: u64,
                sid: u8,
                filters: serde_json::Value,
                latest: u64,
            },
            AddPending {
                conn: u64,
                sid: u8,
                filters: serde_json::Value,
                generation: u64,
                live_from: u64,
            },
            Finish {
                conn: u64,
                sid: u8,
                generation: u64,
                delivered: u64,
            },
            Remove {
                conn: u64,
                sid: u8,
            },
            Close {
                conn: u64,
            },
            Stored(Event),
            Ephemeral(Event),
        }

        #[derive(Clone, Debug)]
        struct Event {
            id: u8,
            author: u8,
            kind: u64,
            created_at: u64,
            /// Tag name, then a value index: `t` and `x` take [`TAG_VALUES`],
            /// `p` takes a 32-byte key.
            tags: Vec<(char, u8)>,
            word: usize,
        }

        impl Event {
            fn packed(&self) -> wok_event::PackedEvent {
                let mut tags = PackedEventTagBuilder::default();
                for &(name, value) in &self.tags {
                    if name == 'p' {
                        tags.add(name, &[value; 32]).unwrap();
                    } else {
                        tags.add(name, TAG_VALUES[usize::from(value)]).unwrap();
                    }
                }
                let (id, author) = ([self.id; 32], [self.author; 32]);
                PackedEventBuilder::build(&id, &author, self.created_at, self.kind, 0, &tags)
                    .unwrap()
            }
        }

        fn keys() -> impl Strategy<Value = Vec<String>> {
            prop::collection::btree_set(0u8..4, 1..3)
                .prop_map(|set| set.into_iter().map(|b| hex::encode([b; 32])).collect())
        }

        fn words() -> impl Strategy<Value = Vec<String>> {
            prop::collection::btree_set(0usize..3, 1..3).prop_map(|set| {
                set.into_iter()
                    .map(|i| String::from_utf8(TAG_VALUES[i].to_vec()).unwrap())
                    .collect()
            })
        }

        fn filter() -> impl Strategy<Value = serde_json::Value> {
            (
                prop::option::weighted(0.15, keys()),
                prop::option::weighted(0.4, keys()),
                prop::option::weighted(0.4, prop::collection::btree_set(0u64..4, 1..3)),
                prop::option::weighted(0.4, words()),
                prop::option::weighted(0.3, keys()),
                prop::option::weighted(0.15, words()),
                prop::option::weighted(0.2, 0u64..6),
                prop::option::weighted(0.2, 4u64..10),
                prop::option::weighted(0.15, 0usize..2),
            )
                .prop_map(
                    |(ids, authors, kinds, t, p, and_t, since, until, search)| {
                        let mut f = serde_json::Map::new();
                        let mut set = |name: &str, value: Option<serde_json::Value>| {
                            if let Some(value) = value {
                                f.insert(name.into(), value);
                            }
                        };
                        set("ids", ids.map(|v| json!(v)));
                        set("authors", authors.map(|v| json!(v)));
                        set("kinds", kinds.map(|v| json!(v)));
                        set("#t", t.map(|v| json!(v)));
                        set("#p", p.map(|v| json!(v)));
                        set("&t", and_t.map(|v| json!(v)));
                        set("since", since.map(|v| json!(v)));
                        set("until", until.map(|v| json!(v)));
                        set("search", search.map(|i| json!(WORDS[i])));
                        serde_json::Value::Object(f)
                    },
                )
        }

        fn filters() -> impl Strategy<Value = serde_json::Value> {
            prop::collection::vec(filter(), 1..4).prop_map(|v| json!(v))
        }

        fn event() -> impl Strategy<Value = Event> {
            let tag = prop_oneof![
                (0u8..3).prop_map(|v| ('t', v)),
                (0u8..4).prop_map(|v| ('p', v)),
                (0u8..3).prop_map(|v| ('x', v)),
            ];
            (
                0u8..4,
                0u8..4,
                0u64..4,
                0u64..10,
                prop::collection::vec(tag, 0..5),
                0usize..3,
            )
                .prop_map(|(id, author, kind, created_at, tags, word)| Event {
                    id,
                    author,
                    kind,
                    created_at,
                    tags,
                    word,
                })
        }

        fn op() -> impl Strategy<Value = Op> {
            let conn = 0..CONNS;
            let sid = 0..SUB_IDS;
            prop_oneof![
                3 => (conn.clone(), sid.clone(), filters(), 0u64..30).prop_map(
                    |(conn, sid, filters, latest)| Op::Add { conn, sid, filters, latest }
                ),
                3 => (conn.clone(), sid.clone(), filters(), 0u64..4, 0u64..30).prop_map(
                    |(conn, sid, filters, generation, live_from)| Op::AddPending {
                        conn, sid, filters, generation, live_from,
                    }
                ),
                2 => (conn.clone(), sid.clone(), 0u64..4, 0u64..40).prop_map(
                    |(conn, sid, generation, delivered)| Op::Finish {
                        conn, sid, generation, delivered,
                    }
                ),
                2 => (conn.clone(), sid).prop_map(|(conn, sid)| Op::Remove { conn, sid }),
                1 => conn.prop_map(|conn| Op::Close { conn }),
                4 => event().prop_map(Op::Stored),
                2 => event().prop_map(Op::Ephemeral),
            ]
        }

        struct Modelled {
            group: NostrFilterGroup,
            latest: u64,
            pending: bool,
            generation: u64,
        }

        /// The reference: every subscription, by connection and then id.
        #[derive(Default)]
        struct Model {
            subs: BTreeMap<(u64, String), Modelled>,
        }

        impl Model {
            fn requires_content(&self, event: PackedEventView<'_>) -> bool {
                self.subs.values().any(|sub| {
                    sub.group
                        .filters
                        .iter()
                        .any(|f| f.search.is_some() && f.does_match_without_search(event))
                })
            }

            fn process(
                &mut self,
                lev: Option<u64>,
                event: PackedEventView<'_>,
                terms: Option<&SearchTermSet>,
            ) -> Vec<(u64, String, bool, u64)> {
                let mut out = Vec::new();
                for ((conn, sid), sub) in &mut self.subs {
                    if lev.is_some_and(|lev| sub.latest >= lev) {
                        continue;
                    }
                    if sub.group.does_match_with_search_terms(event, terms) {
                        if let Some(lev) = lev {
                            sub.latest = lev;
                        }
                        out.push((*conn, sid.clone(), sub.pending, sub.generation));
                    }
                }
                out
            }
        }

        fn sub_id(sid: u8) -> String {
            format!("s{sid}")
        }

        fn subscription(
            conn: u64,
            sid: u8,
            filters: &serde_json::Value,
            latest: u64,
            generation: u64,
        ) -> Subscription {
            let mut sub = sub(conn, &sub_id(sid), filters.clone());
            sub.latest_event_id = latest;
            sub.generation = generation;
            sub
        }

        fn group(filters: &serde_json::Value) -> NostrFilterGroup {
            NostrFilterGroup::from_value(filters, 500, 3, 16).unwrap()
        }

        /// Match a stored event (with its local id) or an ephemeral one, the
        /// way the relay does: content only if a search filter needs it.
        fn check_event(
            monitors: &mut ActiveMonitors,
            model: &mut Model,
            lev: Option<u64>,
            event: &Event,
        ) {
            let packed = event.packed();
            let view = packed.view();
            let content = model.requires_content(view);
            assert_eq!(monitors.event_requires_content(view), content);
            let terms = content.then(|| wok_db::search_term_set(WORDS[event.word]));
            let actual = match lev {
                Some(lev) => monitors.process(lev, view, terms.as_ref()),
                None => monitors.process_ephemeral(view, terms.as_ref()),
            };
            let actual: Vec<_> = actual
                .into_iter()
                .map(|r| (r.conn_id, r.sub_id.to_string(), r.pending, r.generation))
                .collect();
            assert_eq!(actual, model.process(lev, view, terms.as_ref()));
        }

        fn run(ops: Vec<Op>) {
            let mut monitors = ActiveMonitors::new(MAX_SUBS);
            let mut model = Model::default();
            let mut lev = 0;
            for op in ops {
                match op {
                    Op::Add {
                        conn,
                        sid,
                        filters,
                        latest,
                    } => {
                        let key = (conn, sub_id(sid));
                        let open = model.subs.keys().filter(|(c, _)| *c == conn).count();
                        let admitted = model.subs.contains_key(&key) || open < MAX_SUBS;
                        let added =
                            monitors.add_sub(subscription(conn, sid, &filters, latest, 0), 0);
                        assert_eq!(added, admitted);
                        if admitted {
                            let sub = Modelled {
                                group: group(&filters),
                                latest,
                                pending: false,
                                generation: 0,
                            };
                            model.subs.insert(key, sub);
                        }
                    }
                    Op::AddPending {
                        conn,
                        sid,
                        filters,
                        generation,
                        live_from,
                    } => {
                        let sub = subscription(conn, sid, &filters, live_from, generation);
                        monitors.add_pending(sub, PendingBuffer::new(live_from, 0));
                        let sub = Modelled {
                            group: group(&filters),
                            latest: live_from,
                            pending: true,
                            generation,
                        };
                        model.subs.insert((conn, sub_id(sid)), sub);
                    }
                    Op::Finish {
                        conn,
                        sid,
                        generation,
                        delivered,
                    } => {
                        let id = SubId::new(&sub_id(sid)).unwrap();
                        let expected = model.subs.get_mut(&(conn, sub_id(sid))).and_then(|sub| {
                            (sub.pending && sub.generation == generation).then(|| {
                                sub.pending = false;
                                sub.latest = sub.latest.max(delivered);
                            })
                        });
                        let finished = monitors.finish_pending(conn, &id, generation, delivered);
                        assert_eq!(finished.is_some(), expected.is_some());
                    }
                    Op::Remove { conn, sid } => {
                        model.subs.remove(&(conn, sub_id(sid)));
                        monitors.remove_sub(conn, &SubId::new(&sub_id(sid)).unwrap());
                    }
                    Op::Close { conn } => {
                        model.subs.retain(|(c, _), _| *c != conn);
                        monitors.close_conn(conn);
                    }
                    Op::Stored(event) => {
                        lev += 1;
                        check_event(&mut monitors, &mut model, Some(lev), &event);
                    }
                    Op::Ephemeral(event) => check_event(&mut monitors, &mut model, None, &event),
                }
                monitors.assert_consistent();
                for ((conn, sid), sub) in &model.subs {
                    let id = SubId::new(sid).unwrap();
                    let open = monitors.subscription(*conn, &id).unwrap();
                    assert_eq!(
                        (open.latest_event_id, open.generation),
                        (sub.latest, sub.generation)
                    );
                    let pending = sub.pending.then_some(sub.generation);
                    assert_eq!(monitors.pending_generation(*conn, &id), pending);
                }
            }
            for conn in 0..CONNS {
                monitors.close_conn(conn);
            }
            monitors.assert_empty();
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(512))]

            #[test]
            fn the_index_matches_every_subscription_and_empties(
                ops in prop::collection::vec(op(), 1..60)
            ) {
                run(ops);
            }
        }
    }
}
