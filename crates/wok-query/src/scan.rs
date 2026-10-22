//! Resumable DBScan matching `src/DBQuery.h`.

use crate::visibility::{ReadSnapshot, ReadVisibility};

use crate::filter::NostrFilter;
use crate::subid::Subscription;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use wok_db::keys::{make_key_string_u64, parse_key_string_u64, u64_from_ne, u64_from_ne_checked};
use wok_db::{
    search_bigram_posting_exists, search_posting_count, search_posting_exists, search_postings,
    RoTxn, SearchQuery,
};
use wok_event::PackedEventView;

use crate::HyperLogLog;

#[derive(Clone, Debug)]
struct CandidateEvent {
    packed: u64,
    lev_id: u64,
}

impl CandidateEvent {
    fn new(lev_id: u64, created: u64, scan_index: u64) -> Self {
        Self {
            packed: (scan_index << 40) | (created & 0xFF_FFFFFFFF),
            lev_id,
        }
    }
    fn lev_id(&self) -> u64 {
        self.lev_id
    }
    fn created(&self) -> u64 {
        self.packed & 0xFF_FFFFFFFF
    }
    fn scan_index(&self) -> u64 {
        self.packed >> 40
    }
}

/// Most (author, kind) cursors a PubkeyKind plan opens past strfry's 1000:
/// about 4 MiB of cursor state, enough for every author a filter can name
/// (2047 fit its 65535 bytes) across eight kinds.
const MAX_PUBKEY_KIND_CURSORS: usize = 16_384;

/// Whether an `authors` and `kinds` filter seeks each (author, kind) pair in
/// the PubkeyKind index instead of reading every event the authors wrote from
/// the Pubkey index and checking its kind.
fn plans_pubkey_kind(f: &NostrFilter) -> bool {
    let (Some(authors), Some(kinds)) = (&f.authors, &f.kinds) else {
        return false;
    };
    let pairs = authors.size().saturating_mul(kinds.size());
    // strfry's bound (DBQuery.h).
    if pairs < 1000 {
        return true;
    }
    if pairs > MAX_PUBKEY_KIND_CURSORS {
        return false;
    }
    // A replaceable kind holds one live version per author and an addressable
    // kind one per address, so every seek reads few entries, all of them
    // matches, while the Pubkey index would read the authors' whole history.
    if kinds.iter().all(|kind| {
        wok_event::is_replaceable_kind(kind) || wok_event::is_param_replaceable_kind(kind)
    }) {
        return true;
    }
    // Otherwise the Pubkey plan wins only when `limit` stops it early on kinds
    // most of the authors' events have, and it reads each candidate's event
    // to check the kind. While the seeks this plan adds stay within `limit`,
    // it costs at most about twice as much even then, and far less when few
    // events match or the limit is not reached. That holds for one kind and
    // for COUNT and NEG-OPEN, whose limits are their caps. Sparse kinds under
    // a small limit still read the authors' history: telling them apart
    // needs statistics.
    pairs - authors.size() <= usize::try_from(f.limit).unwrap_or(usize::MAX)
}

/// Whether a filter with one OR tag and `kinds` seeks each (value, kind) pair
/// in the TagKind index instead of reading, from the Tag index, every event
/// that tags its values and checking its kind. A popular value has thousands
/// of events, of which a DM inbox or a zap list wants one kind.
///
/// The index must hold every event in this snapshot; until the writer's
/// background build completes it, the Tag plan stands. The pair bounds are
/// the PubkeyKind plan's, for the same reason: past 1000 pairs, the seeks
/// this plan adds must fit the limit. The Tag plan checks each candidate's
/// event as well, so both plans return the same events in the same order.
fn plans_tag_kind(f: &NostrFilter, txn: &RoTxn<'_>) -> bool {
    if f.ids.is_some() || !f.and_tags.is_empty() || f.tags.len() != 1 {
        return false;
    }
    let (Some(kinds), Some((_, values))) = (&f.kinds, f.tags.iter().next()) else {
        return false;
    };
    let pairs = values.size().saturating_mul(kinds.size());
    let bounded = pairs < 1000
        || (pairs <= MAX_PUBKEY_KIND_CURSORS
            && pairs - values.size() <= usize::try_from(f.limit).unwrap_or(usize::MAX));
    // A read failure keeps the established plan.
    bounded && wok_db::tag_kind_index_complete_ro(txn).unwrap_or(false)
}

fn cmp_cand(a: &CandidateEvent, b: &CandidateEvent) -> std::cmp::Ordering {
    // Newer first; if equal created, higher levId first (matches C++ sort predicate).
    b.created()
        .cmp(&a.created())
        .then_with(|| b.lev_id().cmp(&a.lev_id()))
}

struct ScanCursor {
    resume_key: Vec<u8>,
    resume_val: u64,
    search: Vec<u8>,
    match_mode: MatchMode,
    outstanding: u64,
}

#[derive(Clone, Copy)]
enum MatchMode {
    Prefix,
    PrefixExactLen,
    Kind(u64),
    Always,
}

impl ScanCursor {
    fn active(&self) -> bool {
        !self.resume_key.is_empty()
    }

    fn key_match(&self, k: &[u8]) -> bool {
        match self.match_mode {
            MatchMode::Prefix => k.starts_with(&self.search),
            MatchMode::PrefixExactLen => {
                k.len() == self.search.len() + 8 && k.starts_with(&self.search)
            }
            MatchMode::Kind(kind) => k.len() >= 8 && u64_from_ne(&k[0..8]) == kind,
            MatchMode::Always => true,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn collect(
        &mut self,
        txn: &RoTxn<'_>,
        index_dbi: lmdb_sys::MDB_dbi,
        scan_index: u64,
        since: u64,
        until: u64,
        mut limit: u64,
        output: &mut VecDeque<CandidateEvent>,
    ) -> Result<u64, wok_db::DbError> {
        let mut added = 0u64;
        while self.active() && limit > 0 {
            let start_key = self.resume_key.clone();
            let start_dup = self.resume_val.to_ne_bytes();
            let mut finished_naturally = true;
            let mut stop = false;
            let mut scan_err = None;
            txn.foreach_full(index_dbi, &start_key, &start_dup, true, |k, v| {
                if limit == 0 {
                    self.resume_key = k.to_vec();
                    match u64_from_ne_checked(v) {
                        Ok(n) => self.resume_val = n,
                        Err(e) => scan_err = Some(e),
                    }
                    finished_naturally = false;
                    stop = true;
                    return false;
                }
                if !self.key_match(k) {
                    self.resume_key.clear();
                    finished_naturally = false;
                    stop = true;
                    return false;
                }
                let parsed = parse_key_string_u64(k);
                let Ok((prefix, created)) = parsed else {
                    return true;
                };
                if created < since {
                    self.resume_key = make_key_string_u64(prefix, 0);
                    self.resume_val = 0;
                    finished_naturally = false;
                    stop = true;
                    return false;
                }
                if created > until {
                    self.resume_key = make_key_string_u64(prefix, until);
                    self.resume_val = u64::MAX;
                    finished_naturally = false;
                    stop = true;
                    return false;
                }
                match u64_from_ne_checked(v) {
                    Ok(lev_id) => {
                        output.push_back(CandidateEvent::new(lev_id, created, scan_index));
                        added += 1;
                        limit -= 1;
                        true
                    }
                    Err(e) => {
                        scan_err = Some(e);
                        finished_naturally = false;
                        stop = true;
                        false
                    }
                }
            })?;
            if let Some(e) = scan_err {
                return Err(e);
            }
            if finished_naturally {
                self.resume_key.clear();
            }
            if stop && !self.active() {
                break;
            }
            if stop && limit == 0 {
                break;
            }
            if stop {
                continue;
            }
        }
        self.outstanding += added;
        Ok(added)
    }
}

pub struct DbScan {
    index_only: bool,
    index_dbi: lmdb_sys::MDB_dbi,
    pub desc: &'static str,
    cursors: Vec<ScanCursor>,
    event_queue: VecDeque<CandidateEvent>,
    initial_scan_depth: u64,
    refill_scan_depth: u64,
    next_init_index: usize,
    pub approx_work: u64,
    since: u64,
    until: u64,
    /// The cursor of the candidate a handler stopped the scan on, which a
    /// resumed scan settles before taking the next one.
    unsettled: Option<usize>,
}

#[derive(Debug, PartialEq, Eq)]
struct SearchHit {
    lev_id: u64,
    score: u64,
    created_at: u64,
    id: [u8; 32],
}

impl Ord for SearchHit {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.score
            .cmp(&other.score)
            .then_with(|| self.created_at.cmp(&other.created_at))
            // A lexically smaller event id is the deterministic better result.
            .then_with(|| other.id.cmp(&self.id))
            .then_with(|| self.lev_id.cmp(&other.lev_id))
    }
}

impl PartialOrd for SearchHit {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Resumable NIP-50 posting intersection and relevance ranking.
struct SearchScan {
    query: SearchQuery,
    primary_term: String,
    term_document_counts: HashMap<String, usize>,
    resume_lev_id: u64,
    gathering_complete: bool,
    top_hits: BinaryHeap<Reverse<SearchHit>>,
    ranked_hits: Vec<SearchHit>,
    max_hits: usize,
    emit_index: usize,
    approx_work: u64,
    /// A hit ranked below `max_hits`: a match the reader may see that this
    /// filter does not send.
    overflow: Option<u64>,
    /// A match was hidden by the restricted-read rule alone.
    restricted: bool,
}

struct SearchGroupScan {
    scans: Vec<SearchScan>,
    gather_index: usize,
    ranked_hits: Vec<SearchHit>,
    emit_index: usize,
    merged: bool,
}

impl SearchGroupScan {
    fn new(filters: &[NostrFilter], txn: &RoTxn<'_>) -> Result<Self, wok_db::DbError> {
        let scans = filters
            .iter()
            .map(|filter| SearchScan::new(filter, txn))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            scans,
            gather_index: 0,
            ranked_hits: Vec::new(),
            emit_index: 0,
            merged: false,
        })
    }

    fn process<H>(
        &mut self,
        snapshot: &ReadSnapshot<'_>,
        filters: &[NostrFilter],
        latest_event_id: u64,
        time_budget_us: u64,
        visibility: &ReadVisibility,
        mut handle_event: H,
    ) -> Result<bool, wok_db::DbError>
    where
        H: FnMut(u64),
    {
        if !self.merged {
            let started = std::time::Instant::now();
            while self.gather_index < self.scans.len() {
                let elapsed_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
                let remaining_us = time_budget_us.saturating_sub(elapsed_us);
                let complete = self.scans[self.gather_index].gather(
                    snapshot,
                    &filters[self.gather_index],
                    latest_event_id,
                    remaining_us,
                    visibility,
                )?;
                if !complete {
                    return Ok(false);
                }
                self.gather_index += 1;
                if self.gather_index < self.scans.len()
                    && started.elapsed().as_micros() >= u128::from(time_budget_us)
                {
                    return Ok(false);
                }
            }

            let mut best_by_event = HashMap::<u64, SearchHit>::new();
            for scan in &mut self.scans {
                for hit in scan.ranked_hits.drain(..) {
                    match best_by_event.entry(hit.lev_id) {
                        std::collections::hash_map::Entry::Vacant(entry) => {
                            entry.insert(hit);
                        }
                        std::collections::hash_map::Entry::Occupied(mut entry) => {
                            if hit > *entry.get() {
                                entry.insert(hit);
                            }
                        }
                    }
                }
            }
            self.ranked_hits = best_by_event.into_values().collect();
            self.ranked_hits.sort_by(|a, b| b.cmp(a));
            self.merged = true;
        }

        while self.emit_index < self.ranked_hits.len() {
            handle_event(self.ranked_hits[self.emit_index].lev_id);
            self.emit_index += 1;
        }
        Ok(true)
    }
}

impl SearchScan {
    fn new(filter: &NostrFilter, txn: &RoTxn<'_>) -> Result<Self, wok_db::DbError> {
        let query = filter
            .search
            .clone()
            .ok_or_else(|| wok_db::DbError::msg("search scanner requires search filter"))?;
        let mut term_document_counts = HashMap::new();
        for term in &query.terms {
            term_document_counts.insert(term.clone(), search_posting_count(txn, term)?);
        }
        let primary_term = query
            .terms
            .iter()
            .min_by_key(|term| term_document_counts.get(*term).copied().unwrap_or(0))
            .cloned()
            .unwrap();
        Ok(Self {
            query,
            primary_term,
            term_document_counts,
            resume_lev_id: 0,
            gathering_complete: false,
            top_hits: BinaryHeap::new(),
            ranked_hits: Vec::new(),
            max_hits: usize::try_from(filter.limit).unwrap_or(usize::MAX),
            emit_index: 0,
            approx_work: 0,
            overflow: None,
            restricted: false,
        })
    }

    fn base_score(&self) -> u64 {
        let mut score = 0u64;
        for term in &self.query.terms {
            let document_count = self.term_document_counts[term] as u64;
            let rarity = 1_000_000_000u64 / document_count.saturating_add(1);
            score = score.saturating_add(rarity.saturating_mul(100));
        }
        score
    }

    // `is_multiple_of` is not available at Wok's Rust 1.85 MSRV.
    #[allow(clippy::manual_is_multiple_of)]
    fn gather(
        &mut self,
        snapshot: &ReadSnapshot<'_>,
        filter: &NostrFilter,
        latest_event_id: u64,
        time_budget_us: u64,
        visibility: &ReadVisibility,
    ) -> Result<bool, wok_db::DbError> {
        let txn = snapshot.txn();
        if self.gathering_complete {
            return Ok(true);
        }
        // A limit of 0 means no hits are ranked or emitted, so there is
        // nothing to gather: don't walk the posting list at all.
        if self.max_hits == 0 {
            self.gathering_complete = true;
            return Ok(true);
        }
        if self.term_document_counts[&self.primary_term] == 0 {
            self.gathering_complete = true;
            return Ok(true);
        }

        let start = std::time::Instant::now();
        let primary = self.primary_term.clone();
        let other_terms: Vec<_> = self
            .query
            .terms
            .iter()
            .filter(|term| **term != primary)
            .cloned()
            .collect();
        let phrase_pairs: Vec<_> = self
            .query
            .phrase_terms
            .windows(2)
            .map(|pair| (pair[0].clone(), pair[1].clone()))
            .collect();
        let base_score = self.base_score();
        let starting_work = self.approx_work;
        let mut error = None;
        let completed = search_postings(txn, &primary, self.resume_lev_id, |lev_id| {
            // Check before consuming this candidate so every miss path yields,
            // and resume still points at the first unprocessed posting.
            if self.approx_work > starting_work
                && self.approx_work % 128 == 0
                && (self.approx_work - starting_work >= 4096
                    || start.elapsed().as_micros() as u64 > time_budget_us)
            {
                return false;
            }
            self.resume_lev_id = lev_id.saturating_add(1);
            self.approx_work = self.approx_work.saturating_add(1);
            if lev_id > latest_event_id {
                return true;
            }
            for term in &other_terms {
                match search_posting_exists(txn, term, lev_id) {
                    Ok(true) => {}
                    Ok(false) => return true,
                    Err(err) => {
                        error = Some(err);
                        return false;
                    }
                }
            }
            let packed_raw = match txn.get_u64(txn.env().dbis().event, lev_id) {
                Ok(Some(raw)) => raw,
                Ok(None) => return true,
                Err(err) => {
                    error = Some(err);
                    return false;
                }
            };
            let packed = match PackedEventView::new(packed_raw) {
                Ok(packed) => packed,
                Err(_) => return true,
            };
            if !filter.does_match_without_search(packed) {
                return true;
            }
            match visibility.allows_noting_restricted(snapshot, packed, &mut self.restricted) {
                Ok(true) => {}
                Ok(false) => return true,
                Err(err) => {
                    error = Some(err);
                    return false;
                }
            }
            let mut score = base_score;
            for (first, second) in &phrase_pairs {
                match search_bigram_posting_exists(txn, first, second, lev_id) {
                    Ok(true) => score = score.saturating_add(2_000_000_000),
                    Ok(false) => {}
                    Err(err) => {
                        error = Some(err);
                        return false;
                    }
                }
            }
            let mut id = [0u8; 32];
            id.copy_from_slice(packed.id());
            if self.max_hits != 0 {
                self.top_hits.push(Reverse(SearchHit {
                    lev_id,
                    score,
                    created_at: packed.created_at(),
                    id,
                }));
                if self.top_hits.len() > self.max_hits {
                    self.overflow = self.top_hits.pop().map(|Reverse(hit)| hit.lev_id);
                }
            }

            true
        })?;
        if let Some(error) = error {
            return Err(error);
        }
        if completed {
            self.gathering_complete = true;
            self.ranked_hits = self.top_hits.drain().map(|Reverse(hit)| hit).collect();
            self.ranked_hits.sort_by(|a, b| b.cmp(a));
        }
        Ok(completed)
    }

    fn scan<H>(
        &mut self,
        snapshot: &ReadSnapshot<'_>,
        filter: &NostrFilter,
        latest_event_id: u64,
        time_budget_us: u64,
        visibility: &ReadVisibility,
        mut handle_event: H,
    ) -> Result<bool, wok_db::DbError>
    where
        H: FnMut(u64) -> bool,
    {
        if !self.gather(
            snapshot,
            filter,
            latest_event_id,
            time_budget_us,
            visibility,
        )? {
            return Ok(false);
        }
        while self.emit_index < self.ranked_hits.len() {
            let lev_id = self.ranked_hits[self.emit_index].lev_id;
            self.emit_index += 1;
            if handle_event(lev_id) {
                return Ok(true);
            }
        }
        Ok(true)
    }

    /// What a finished search left that is not in `sent`: a ranked hit the
    /// handler stopped before, else one ranked below the limit.
    fn remaining(&self, sent: &HashSet<u64>) -> Peek {
        if let Some(hit) = self.ranked_hits[self.emit_index..]
            .iter()
            .find(|hit| !sent.contains(&hit.lev_id))
        {
            return Peek::Found(hit.lev_id);
        }
        match self.overflow {
            None => Peek::Exhausted,
            Some(lev_id) if !sent.contains(&lev_id) => Peek::Found(lev_id),
            // Another filter sent it; whether more ranked below is unknown.
            Some(_) => Peek::Unknown,
        }
    }
}

enum QueryScanner {
    Chronological(DbScan),
    Search(SearchScan),
}

impl DbScan {
    /// Number of index cursors this scan opens. A `&` (AND) tag filter always
    /// seeds exactly one, whatever the size of its value set.
    pub fn cursor_count(&self) -> usize {
        self.cursors.len()
    }

    pub fn new(f: &NostrFilter, txn: &RoTxn<'_>) -> Self {
        let default = Self::new_unplanned(f, txn);
        // A tiny author history can otherwise lose to a ubiquitous tag. Bound
        // this probe to 64 postings and eight seeks per alternative; avoid a
        // statistics table or a database-sized planning pass. Uncertain/error
        // cases retain the established plan.
        if !default.cursors.is_empty()
            && f.ids.is_none()
            && f.authors.is_some()
            && (!f.tags.is_empty() || !f.and_tags.is_empty())
        {
            let mut author_filter = f.clone();
            author_filter.tags.clear();
            author_filter.and_tags.clear();
            author_filter.index_only_scans = false;
            let author = Self::new_unplanned(&author_filter, txn);
            if author.cursors.len() <= 8
                && default.cursors.len() <= 8
                && author.probe_size(txn).is_ok_and(|n| n < 16)
                && default.probe_size(txn).is_ok_and(|n| n == 64)
            {
                // Retain full original-filter checks when scanning this seed.
                return author;
            }
        }
        default
    }

    fn probe_size(&self, txn: &RoTxn<'_>) -> Result<usize, wok_db::DbError> {
        let mut count = 0;
        for cursor in &self.cursors {
            txn.foreach_full(
                self.index_dbi,
                &cursor.resume_key,
                &cursor.resume_val.to_ne_bytes(),
                true,
                |key, _| {
                    if !cursor.key_match(key) {
                        return false;
                    }
                    count += 1;
                    count < 64
                },
            )?;
            if count >= 64 {
                return Ok(64);
            }
        }
        Ok(count)
    }

    fn new_unplanned(f: &NostrFilter, txn: &RoTxn<'_>) -> Self {
        let dbis = txn.env().dbis();
        let mut index_only = f.index_only_scans;
        let mut cursors = Vec::new();
        let tag_kind = match dbis.event_tag_kind {
            Some(dbi) if f.limit != 0 && !f.never_match && plans_tag_kind(f, txn) => Some(dbi),
            _ => None,
        };
        let (index_dbi, desc) = if f.ids.is_some() {
            (dbis.event_id, "ID")
        } else if let Some(dbi) = tag_kind {
            // An entry can outlive its event when an earlier release deleted
            // it, so every candidate is checked against its stored event.
            index_only = false;
            (dbi, "TagKind")
        } else if !f.tags.is_empty() || !f.and_tags.is_empty() {
            (dbis.event_tag, "Tag")
        } else if plans_pubkey_kind(f) {
            (dbis.event_pubkey_kind, "PubkeyKind")
        } else if f.authors.is_some() {
            if f.kinds.is_some() {
                index_only = false;
            }
            (dbis.event_pubkey, "Pubkey")
        } else if f.kinds.is_some() {
            (dbis.event_kind, "Kind")
        } else {
            (dbis.event_created_at, "CreatedAt")
        };

        if f.limit == 0 || f.never_match {
            // No stored event can be returned (NIP-01 `limit: 0`), so no
            // index is read.
        } else if let Some(ids) = &f.ids {
            for i in 0..ids.size() {
                let search = ids.at(i).to_vec();
                let mut resume = search.clone();
                resume.extend_from_slice(&[0xFF; 8]);
                cursors.push(ScanCursor {
                    resume_key: resume,
                    resume_val: u64::MAX,
                    search,
                    match_mode: MatchMode::Prefix,
                    outstanding: 0,
                });
            }
        } else if tag_kind.is_some() {
            // A TagKind key is the Tag key with the kind before the time, so
            // the cursors read it the same way.
            let (tag_name, values) = f.tags.iter().next().unwrap();
            let kinds = f.kinds.as_ref().unwrap();
            for i in 0..values.size() {
                for j in 0..kinds.size() {
                    let mut search = vec![*tag_name as u8];
                    search.extend_from_slice(values.at(i));
                    search.extend_from_slice(&kinds.at(j).to_ne_bytes());
                    let mut resume = search.clone();
                    resume.extend_from_slice(&[0xFF; 8]);
                    cursors.push(ScanCursor {
                        resume_key: resume,
                        resume_val: u64::MAX,
                        search,
                        match_mode: MatchMode::PrefixExactLen,
                        outstanding: 0,
                    });
                }
            }
        } else if !f.tags.is_empty() || !f.and_tags.is_empty() {
            // A required (`&`) tag seeds a single cursor because every listed
            // value must be present, while an OR tag needs one cursor per
            // alternative, so a required tag always wins on cursor count when
            // one is available. Index cardinality is not known at planning
            // time, so cursor count is the only comparable unit: a narrow
            // `#e:[<id>]` can still lose to a broad `&t:["nostr"]`. That costs
            // extra scanning, never correctness, because a non-empty `and_tags`
            // forces every candidate through full-event verification.
            let and_choice = f.and_tags.iter().min_by_key(|(_, values)| values.size());
            let or_choice = f.tags.iter().min_by_key(|(_, values)| values.size());
            let (tag_name, filter_set, from_and) = match (and_choice, or_choice) {
                (Some((tag, values)), _) => (*tag, values, true),
                (None, Some((tag, values))) => (*tag, values, false),
                (None, None) => unreachable!(),
            };
            let cursor_count = if from_and { 1 } else { filter_set.size() };
            for i in 0..cursor_count {
                let mut search = vec![tag_name as u8];
                search.extend_from_slice(filter_set.at(i));
                let mut resume = search.clone();
                resume.extend_from_slice(&[0xFF; 8]);
                cursors.push(ScanCursor {
                    resume_key: resume,
                    resume_val: u64::MAX,
                    search,
                    match_mode: MatchMode::PrefixExactLen,
                    outstanding: 0,
                });
            }
        } else if plans_pubkey_kind(f) {
            let authors = f.authors.as_ref().unwrap();
            let kinds = f.kinds.as_ref().unwrap();
            for i in 0..authors.size() {
                for j in 0..kinds.size() {
                    let mut search = authors.at(i).to_vec();
                    search.extend_from_slice(&kinds.at(j).to_ne_bytes());
                    let mut resume = search.clone();
                    resume.extend_from_slice(&[0xFF; 8]);
                    cursors.push(ScanCursor {
                        resume_key: resume,
                        resume_val: u64::MAX,
                        search,
                        match_mode: MatchMode::Prefix,
                        outstanding: 0,
                    });
                }
            }
        } else if let Some(authors) = &f.authors {
            for i in 0..authors.size() {
                let search = authors.at(i).to_vec();
                let mut resume = search.clone();
                resume.extend_from_slice(&[0xFF; 8]);
                cursors.push(ScanCursor {
                    resume_key: resume,
                    resume_val: u64::MAX,
                    search,
                    match_mode: MatchMode::Prefix,
                    outstanding: 0,
                });
            }
        } else if let Some(kinds) = &f.kinds {
            for i in 0..kinds.size() {
                let kind = kinds.at(i);
                let mut resume = kind.to_ne_bytes().to_vec();
                resume.extend_from_slice(&[0xFF; 8]);
                cursors.push(ScanCursor {
                    resume_key: resume,
                    resume_val: u64::MAX,
                    search: kind.to_ne_bytes().to_vec(),
                    match_mode: MatchMode::Kind(kind),
                    outstanding: 0,
                });
            }
        } else {
            cursors.push(ScanCursor {
                resume_key: vec![0xFF; 8],
                resume_val: u64::MAX,
                search: Vec::new(),
                match_mode: MatchMode::Always,
                outstanding: 0,
            });
        }

        let n = cursors.len().max(1) as u64;
        let initial = (f.limit / n).clamp(5, 50);
        Self {
            index_only,
            index_dbi,
            desc,
            cursors,
            event_queue: VecDeque::new(),
            initial_scan_depth: initial,
            refill_scan_depth: 10 * initial,
            next_init_index: 0,
            approx_work: 0,
            since: f.since,
            until: f.until,
            unsettled: None,
        }
    }

    pub fn scan<H, P>(
        &mut self,
        txn: &RoTxn<'_>,
        filter: &NostrFilter,
        mut handle_event: H,
        mut do_pause: P,
    ) -> Result<bool, wok_db::DbError>
    where
        H: FnMut(u64) -> bool,
        P: FnMut(u64) -> bool,
    {
        if let Some(si) = self.unsettled.take() {
            self.settle(txn, si)?;
        }
        loop {
            self.approx_work += 1;
            if do_pause(self.approx_work) {
                return Ok(false);
            }
            if self.next_init_index < self.cursors.len() {
                let idx = self.next_init_index;
                self.approx_work += self.cursors[idx].collect(
                    txn,
                    self.index_dbi,
                    idx as u64,
                    self.since,
                    self.until,
                    self.initial_scan_depth,
                    &mut self.event_queue,
                )?;
                self.next_init_index += 1;
                if self.next_init_index == self.cursors.len() {
                    let mut v: Vec<_> = self.event_queue.drain(..).collect();
                    v.sort_by(cmp_cand);
                    self.event_queue = v.into();
                }
                continue;
            } else if self.event_queue.is_empty() {
                return Ok(true);
            }

            let ev = self.event_queue.pop_front().unwrap();
            let lev_id = ev.lev_id();
            let mut do_send = false;
            if self.index_only {
                if filter.does_match_times(ev.created()) {
                    do_send = true;
                }
            } else {
                self.approx_work += 10;
                if let Some(buf) = txn.get_u64(txn.env().dbis().event, lev_id)? {
                    if let Ok(view) = PackedEventView::new(buf) {
                        if filter.does_match(view) {
                            do_send = true;
                        }
                    }
                }
            }
            let si = ev.scan_index() as usize;
            if do_send && handle_event(lev_id) {
                self.unsettled = Some(si);
                return Ok(true);
            }
            self.settle(txn, si)?;
        }
    }

    /// One of cursor `si`'s candidates was taken. Once the queue holds none
    /// of its candidates, its next entries are read and merged in, so the
    /// queue's head stays the newest entry left in any cursor.
    fn settle(&mut self, txn: &RoTxn<'_>, si: usize) -> Result<(), wok_db::DbError> {
        self.cursors[si].outstanding -= 1;
        if self.cursors[si].outstanding == 0 {
            let mut more = VecDeque::new();
            self.approx_work += self.cursors[si].collect(
                txn,
                self.index_dbi,
                si as u64,
                self.since,
                self.until,
                self.refill_scan_depth,
                &mut more,
            )?;
            let mut merged: Vec<_> = self.event_queue.drain(..).chain(more).collect();
            merged.sort_by(cmp_cand);
            self.event_queue = merged.into();
        }
        Ok(())
    }
}

/// Most work the NIP-67 peeks of one REQ do, looking past where cut filters
/// stopped for one more match, in `DbScan::approx_work` units: a refill of
/// one cursor and about a hundred event reads. The peek that spends the last
/// of it may overrun it by one cursor refill; later ones do no work. A peek
/// that runs out has learned nothing, and the REQ's EOSE carries neither
/// `finish` nor `more`.
const PEEK_WORK: u64 = 2048;
/// Most candidates those peeks check the read policy of.
const PEEK_CANDIDATES: u32 = 64;

/// What a NIP-67 peek found past the matches a filter sent.
enum Peek {
    /// A match the reader may see that was not sent.
    Found(u64),
    /// No such match is left.
    Exhausted,
    /// The peek ran out of budget first, or cannot tell.
    Unknown,
}

/// What a REQ's peeks may still spend.
struct PeekBudget {
    work: u64,
    candidates: u32,
}

/// NIP-67: what a REQ's finished history scan knows about the stored matches
/// it did not send, up to its snapshot. A field is set only when it holds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Completeness {
    /// Every stored match the reader may see was sent.
    pub finish: bool,
    /// A stored match the reader may see was not sent.
    pub more: bool,
    /// A stored match was hidden by the restricted-read rule alone, which
    /// authenticating as an involved pubkey lifts.
    pub restricted: bool,
}

pub struct DbQuery {
    pub visibility: ReadVisibility,
    pub sub: Subscription,
    scanner: Option<QueryScanner>,
    search_group: Option<SearchGroupScan>,
    all_filters_search: bool,
    filter_group_index: usize,
    pub dead: bool,
    sent_events_full: HashSet<u64>,
    sent_events_curr: HashSet<u64>,
    last_work_checked: u64,
    max_total_events: u64,
    hll: Option<HyperLogLog>,
    count_dedup_budget: u64,
    count_dedup_limited: bool,
    /// Whether to work out [`Completeness`], peeking past cut filters.
    completeness: bool,
    /// Matches peeks found past cut filters, unsent when found.
    witnesses: Vec<u64>,
    /// A filter may have matches left that no peek could find.
    unknown: bool,
    restricted: bool,
    peek_budget: PeekBudget,
    /// The read policy changed between time slices, after an AUTH, a reload
    /// or a moderation, vanish or deletion commit, so earlier slices hid or
    /// sent by another.
    visibility_changed: bool,
    /// The database's visibility generation the first slice read under.
    policy_generation: Option<u64>,
    started: bool,
}

impl DbQuery {
    /// `count_dedup_budget` caps the total dedup-set size for COUNT scans
    /// (0 = no cap). Each filter's limit only bounds its own scan, so a
    /// multi-filter COUNT could otherwise multiply the shared dedup set
    /// (hundreds of MB transient per connection). The reported count is
    /// capped at max_filter_limit_count anyway, so a budget of
    /// max_filter_limit_count + 1 changes no legitimate result; hitting it
    /// completes the query with limited: true.
    pub fn new(sub: Subscription, max_total_events: u64, count_dedup_budget: u64) -> Self {
        let max_total_events = if sub.count_only { 0 } else { max_total_events };
        // A sketch is for a COUNT that sent one filter, even if others were
        // dropped as never matching.
        let hll = if sub.count_only
            && sub.filter_group.filters.len() == 1
            && sub.filter_group.never_matching == 0
        {
            HyperLogLog::for_filter(&sub.filter_group.filters[0])
        } else {
            None
        };
        let count_dedup_budget = if sub.count_only {
            count_dedup_budget
        } else {
            0
        };
        let all_filters_search = !sub.filter_group.filters.is_empty()
            && sub
                .filter_group
                .filters
                .iter()
                .all(|filter| filter.search.is_some());
        Self {
            sub,
            visibility: ReadVisibility::default(),
            scanner: None,
            search_group: None,
            all_filters_search,
            filter_group_index: 0,
            dead: false,
            sent_events_full: HashSet::new(),
            sent_events_curr: HashSet::new(),
            last_work_checked: 0,
            // COUNT needs the exact deduplicated count up to its separate
            // max_filter_limit_count. The request-wide delivery ceiling is
            // for EVENT responses.
            max_total_events,
            hll,
            count_dedup_budget,
            count_dedup_limited: false,
            completeness: false,
            witnesses: Vec::new(),
            unknown: false,
            restricted: false,
            peek_budget: PeekBudget {
                work: PEEK_WORK,
                candidates: PEEK_CANDIDATES,
            },
            visibility_changed: false,
            policy_generation: None,
            started: false,
        }
    }

    /// Work out [`Completeness`] for a REQ's history (NIP-67). It costs a
    /// bounded peek past each filter cut by its limit or the request-wide
    /// ceiling, so COUNT and sync scans leave it off.
    pub fn track_completeness(&mut self) {
        self.completeness = !self.sub.count_only;
    }

    /// The read policy for the next time slice.
    pub fn set_visibility(&mut self, visibility: ReadVisibility) {
        if self.started && visibility != self.visibility {
            self.visibility_changed = true;
        }
        self.visibility = visibility;
    }

    pub fn sent_count(&self) -> u64 {
        self.sent_events_full.len() as u64
    }

    pub fn hll_hex(&self) -> Option<String> {
        self.hll.as_ref().map(HyperLogLog::encode_hex)
    }

    /// True when a COUNT scan stopped early because the total dedup-set
    /// budget was exhausted (report `limited: true`).
    pub fn count_dedup_limited(&self) -> bool {
        self.count_dedup_limited
    }

    /// What the finished scan knows about the matches it did not send; all
    /// false unless [`track_completeness`](Self::track_completeness) was
    /// called. `finish` needs every filter to have run out of matches or a
    /// peek past its cut to find none; `more` needs a match a peek found to
    /// be still unsent at the end, as a later filter may have sent it.
    pub fn completeness(&self) -> Completeness {
        if !self.completeness || self.visibility_changed {
            return Completeness::default();
        }
        let more = self
            .witnesses
            .iter()
            .any(|lev_id| !self.sent_events_full.contains(lev_id));
        Completeness {
            finish: !self.unknown && self.witnesses.is_empty(),
            more,
            restricted: self.restricted,
        }
    }

    /// An event the scan counted as sent did not reach the reader (its
    /// payload could not be read or decoded), so `finish` would be wrong.
    pub fn mark_incomplete(&mut self) {
        self.unknown = true;
    }

    fn note(&mut self, peek: Peek) {
        match peek {
            Peek::Found(lev_id) => self.witnesses.push(lev_id),
            Peek::Exhausted => {}
            Peek::Unknown => self.unknown = true,
        }
    }

    fn visible_event_pubkey(
        snapshot: &ReadSnapshot<'_>,
        lev_id: u64,
        visibility: &ReadVisibility,
        restricted: &mut bool,
    ) -> Result<Option<[u8; 32]>, wok_db::DbError> {
        let txn = snapshot.txn();
        let Some(raw) = txn.get_u64(txn.env().dbis().event, lev_id)? else {
            return Ok(None);
        };
        let packed = PackedEventView::new(raw)?;
        if !visibility.allows_noting_restricted(snapshot, packed, restricted)? {
            return Ok(None);
        }
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(packed.pubkey());
        Ok(Some(pubkey))
    }

    /// Resume `scanner` past where it stopped, looking for a match the
    /// reader may see that is not in `sent`, within `budget`.
    #[allow(clippy::too_many_arguments)]
    fn peek(
        scanner: &mut DbScan,
        snapshot: &ReadSnapshot<'_>,
        filter: &NostrFilter,
        latest: u64,
        sent: &HashSet<u64>,
        visibility: &ReadVisibility,
        restricted: &mut bool,
        budget: &mut PeekBudget,
    ) -> Result<Peek, wok_db::DbError> {
        // Resuming would settle the stopped cursor, a refill, for nothing.
        if budget.work == 0 || budget.candidates == 0 {
            return Ok(Peek::Unknown);
        }
        let (start, work) = (scanner.approx_work, budget.work);
        let mut found = None;
        let mut out_of_candidates = false;
        let mut error = None;
        let candidates = &mut budget.candidates;
        let complete = scanner.scan(
            snapshot.txn(),
            filter,
            |lev_id| {
                if lev_id > latest || sent.contains(&lev_id) {
                    return false;
                }
                if *candidates == 0 {
                    out_of_candidates = true;
                    return true;
                }
                *candidates -= 1;
                match Self::visible_event_pubkey(snapshot, lev_id, visibility, restricted) {
                    Ok(Some(_)) => {
                        found = Some(lev_id);
                        true
                    }
                    Ok(None) => false,
                    Err(e) => {
                        error = Some(e);
                        true
                    }
                }
            },
            |approx_work| approx_work - start > work,
        )?;
        budget.work = work.saturating_sub(scanner.approx_work - start);
        if let Some(error) = error {
            return Err(error);
        }
        Ok(match found {
            Some(lev_id) => Peek::Found(lev_id),
            None if complete && !out_of_candidates => Peek::Exhausted,
            None => Peek::Unknown,
        })
    }

    /// After the request-wide ceiling cut the scan, look in the filters it
    /// never reached for a match the reader may see that was not sent.
    fn peek_unscanned(&mut self, snapshot: &ReadSnapshot<'_>) -> Result<Peek, wok_db::DbError> {
        let latest = self.sub.latest_event_id;
        for f in &self.sub.filter_group.filters[self.filter_group_index + 1..] {
            // A limit of 0 asks for no stored events, and a search ranks all
            // of its hits before it can say anything.
            if f.limit == 0 || f.search.is_some() {
                return Ok(Peek::Unknown);
            }
            let peek = Self::peek(
                &mut DbScan::new(f, snapshot.txn()),
                snapshot,
                f,
                latest,
                &self.sent_events_full,
                &self.visibility,
                &mut self.restricted,
                &mut self.peek_budget,
            )?;
            if !matches!(peek, Peek::Exhausted) {
                return Ok(peek);
            }
        }
        Ok(Peek::Exhausted)
    }

    /// Returns true when the scan is complete.
    pub fn process<F>(
        &mut self,
        txn: &RoTxn<'_>,
        mut cb: F,
        time_budget_us: u64,
    ) -> Result<bool, wok_db::DbError>
    where
        F: FnMut(&Subscription, u64),
    {
        if self.completeness {
            // Moderation, vanish and deletion commits change what a slice
            // may send without changing `visibility`.
            let generation = wok_db::state::policy_generation(txn).ok();
            if generation.is_none() || (self.started && generation != self.policy_generation) {
                self.visibility_changed = true;
            }
            self.policy_generation = generation;
        }
        self.started = true;
        // The clock and which policy tables can hide an event, read once for
        // the slice rather than for each event.
        let snapshot = ReadSnapshot::for_stored(txn);
        if self.all_filters_search {
            let mut group = match self.search_group.take() {
                Some(group) => group,
                None => SearchGroupScan::new(&self.sub.filter_group.filters, txn)?,
            };
            let mut sent = std::mem::take(&mut self.sent_events_full);
            let mut hits = Vec::new();
            let mut visibility_error = None;
            let mut dedup_budget_hit = false;
            let mut restricted = self.restricted;
            // The first hit the request-wide ceiling kept out.
            let mut unsent = None;
            let count_dedup_budget = self.count_dedup_budget;
            let complete = group.process(
                &snapshot,
                &self.sub.filter_group.filters,
                self.sub.latest_event_id,
                time_budget_us,
                &self.visibility,
                |lev_id| {
                    let pubkey = match Self::visible_event_pubkey(
                        &snapshot,
                        lev_id,
                        &self.visibility,
                        &mut restricted,
                    ) {
                        Ok(Some(pubkey)) => pubkey,
                        Ok(None) => return,
                        Err(error) => {
                            visibility_error = Some(error);
                            return;
                        }
                    };
                    if count_dedup_budget != 0 && sent.len() as u64 >= count_dedup_budget {
                        // Stop growing the dedup set; reported as limited.
                        dedup_budget_hit = true;
                        return;
                    }
                    if self.max_total_events == 0 || (sent.len() as u64) < self.max_total_events {
                        if sent.insert(lev_id) {
                            hits.push((lev_id, pubkey));
                        }
                    } else if !sent.contains(&lev_id) {
                        unsent.get_or_insert(lev_id);
                    }
                },
            )?;
            if let Some(error) = visibility_error {
                return Err(error);
            }
            self.sent_events_full = sent;
            self.restricted = restricted;
            for (lev_id, pubkey) in hits {
                if let Some(hll) = &mut self.hll {
                    hll.add_pubkey(&pubkey);
                }
                cb(&self.sub, lev_id);
            }
            if dedup_budget_hit {
                self.count_dedup_limited = true;
                return Ok(true);
            }
            let capped = self.max_total_events != 0
                && self.sent_events_full.len() as u64 >= self.max_total_events;
            if !complete && !capped {
                self.search_group = Some(group);
                return Ok(false);
            }
            if self.completeness {
                if !complete {
                    self.unknown = true;
                }
                if let Some(lev_id) = unsent {
                    self.witnesses.push(lev_id);
                }
                let peeks: Vec<_> = group
                    .scans
                    .iter()
                    .zip(&self.sub.filter_group.filters)
                    .map(|(scan, filter)| match filter.limit {
                        0 => Peek::Unknown,
                        _ => scan.remaining(&self.sent_events_full),
                    })
                    .collect();
                for peek in peeks {
                    self.note(peek);
                }
                self.restricted |= group.scans.iter().any(|scan| scan.restricted);
            }
            return Ok(true);
        }

        // One clock for the whole slice, unlike C++ DBQuery's per filter: a
        // REQ's filters share its budget rather than each getting one.
        let start = std::time::Instant::now();
        let elapsed_us = || u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
        while self.filter_group_index < self.sub.filter_group.filters.len() {
            let f = self.sub.filter_group.filters[self.filter_group_index].clone();
            let mut scanner = match self.scanner.take() {
                Some(scanner) => scanner,
                None => {
                    // A new scanner counts its work from 0, so the next
                    // check comes as soon after its start as after a resume.
                    self.last_work_checked = 0;
                    if f.search.is_some() {
                        QueryScanner::Search(SearchScan::new(&f, txn)?)
                    } else {
                        QueryScanner::Chronological(DbScan::new(&f, txn))
                    }
                }
            };
            let latest = self.sub.latest_event_id;
            let mut sent_full = std::mem::take(&mut self.sent_events_full);
            let mut sent_curr = std::mem::take(&mut self.sent_events_curr);
            let mut last_work = self.last_work_checked;
            let mut hits: Vec<(u64, [u8; 32])> = Vec::new();
            let mut visibility_error = None;
            let mut dedup_budget_hit = false;
            let mut restricted = self.restricted;
            // The scan stopped at this filter's limit or the request-wide
            // ceiling rather than running out of matches.
            let mut cut = false;
            let count_dedup_budget = self.count_dedup_budget;
            let mut handle = |lev_id| {
                if f.limit == 0 {
                    return true;
                }
                if lev_id > latest {
                    return false;
                }
                let pubkey = match Self::visible_event_pubkey(
                    &snapshot,
                    lev_id,
                    &self.visibility,
                    &mut restricted,
                ) {
                    Ok(Some(pubkey)) => pubkey,
                    Ok(None) => return false,
                    Err(error) => {
                        visibility_error = Some(error);
                        return true;
                    }
                };
                if count_dedup_budget != 0 && sent_full.len() as u64 >= count_dedup_budget {
                    // Total dedup-set budget exhausted: stop the scan and
                    // report limited rather than growing memory further.
                    dedup_budget_hit = true;
                    return true;
                }
                if sent_full.insert(lev_id) {
                    hits.push((lev_id, pubkey));
                }
                sent_curr.insert(lev_id);
                cut = sent_curr.len() as u64 >= f.limit
                    || (self.max_total_events != 0
                        && sent_full.len() as u64 >= self.max_total_events);
                cut
            };
            let complete = match &mut scanner {
                QueryScanner::Chronological(scanner) => {
                    scanner.scan(txn, &f, &mut handle, |approx_work| {
                        if approx_work > last_work + 2000 {
                            last_work = approx_work;
                            elapsed_us() >= time_budget_us
                        } else {
                            false
                        }
                    })?
                }
                QueryScanner::Search(scanner) => scanner.scan(
                    &snapshot,
                    &f,
                    latest,
                    time_budget_us.saturating_sub(elapsed_us()),
                    &self.visibility,
                    &mut handle,
                )?,
            };
            if let Some(error) = visibility_error {
                return Err(error);
            }
            if let QueryScanner::Search(scanner) = &scanner {
                restricted |= scanner.restricted;
            }
            let peek = match &mut scanner {
                _ if !self.completeness || !complete || dedup_budget_hit => None,
                _ if f.limit == 0 => Some(Peek::Unknown),
                QueryScanner::Chronological(scanner) if cut => Some(Self::peek(
                    scanner,
                    &snapshot,
                    &f,
                    latest,
                    &sent_full,
                    &self.visibility,
                    &mut restricted,
                    &mut self.peek_budget,
                )?),
                QueryScanner::Chronological(_) => Some(Peek::Exhausted),
                QueryScanner::Search(scanner) => Some(scanner.remaining(&sent_full)),
            };
            self.sent_events_full = sent_full;
            self.sent_events_curr = sent_curr;
            self.last_work_checked = last_work;
            self.restricted = restricted;
            for (lev, pubkey) in hits {
                if let Some(hll) = &mut self.hll {
                    hll.add_pubkey(&pubkey);
                }
                cb(&self.sub, lev);
            }
            if dedup_budget_hit {
                self.count_dedup_limited = true;
                return Ok(true);
            }
            let exhausted = matches!(peek, Some(Peek::Exhausted));
            if let Some(peek) = peek {
                self.note(peek);
            }
            if self.max_total_events != 0
                && self.sent_events_full.len() as u64 >= self.max_total_events
            {
                // Nothing more is sent, so whatever the filters not reached
                // hold, and this one does not, decides between the hints.
                if self.completeness && exhausted {
                    let peek = self.peek_unscanned(&snapshot)?;
                    self.note(peek);
                }
                return Ok(true);
            }
            if !complete {
                self.scanner = Some(scanner);
                return Ok(false);
            }
            self.scanner = None;
            self.filter_group_index += 1;
            self.sent_events_curr.clear();
            // A filter that finished between work checks may have spent the
            // slice; the next one starts in the next slice.
            if self.filter_group_index < self.sub.filter_group.filters.len()
                && elapsed_us() >= time_budget_us
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Records matching `filter`, for operator tools that address stored records
/// (`wok scan`, `wok delete`, `wok dict`). Global visibility applies, but kind
/// 22242 AUTH events, hidden from clients, are included.
pub fn foreach_by_filter<F>(
    txn: &RoTxn<'_>,
    filter: &serde_json::Value,
    max_limit: u64,
    max_tags: usize,
    max_and_entries: usize,
    cb: F,
) -> Result<(), crate::subid::QueryError>
where
    F: FnMut(u64),
{
    let visibility = ReadVisibility {
        include_auth_events: true,
        ..ReadVisibility::default()
    };
    foreach_visible_by_filter(
        txn,
        filter,
        max_limit,
        max_tags,
        max_and_entries,
        visibility,
        cb,
    )
}

/// Records matching `filter` that `visibility` lets a reader see.
pub fn foreach_visible_by_filter<F>(
    txn: &RoTxn<'_>,
    filter: &serde_json::Value,
    max_limit: u64,
    max_tags: usize,
    max_and_entries: usize,
    visibility: ReadVisibility,
    mut cb: F,
) -> Result<(), crate::subid::QueryError>
where
    F: FnMut(u64),
{
    let fg =
        crate::filter::NostrFilterGroup::from_value(filter, max_limit, max_tags, max_and_entries)?;
    let sub = Subscription::new(1, crate::subid::SubId::new(".").unwrap(), fg, false);
    let mut q = DbQuery::new(sub, 0, 0);
    q.visibility = visibility;
    q.process(txn, |_, lev| cb(lev), u64::MAX)
        .map_err(|e| crate::subid::QueryError::msg(e.to_string()))?;
    Ok(())
}
