//! Resumable DBScan matching `src/DBQuery.h`.

use crate::filter::NostrFilter;
use crate::subid::Subscription;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use wok_db::keys::{make_key_string_u64, parse_key_string_u64, u64_from_ne, u64_from_ne_checked};
use wok_db::{
    is_event_moderated_ro, is_event_vanished_ro, search_bigram_posting_exists,
    search_posting_count, search_posting_exists, search_postings, RoTxn, SearchQuery,
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
                if since != 0 && created < since {
                    self.resume_key = make_key_string_u64(prefix, 0);
                    self.resume_val = 0;
                    finished_naturally = false;
                    stop = true;
                    return false;
                }
                if until != 0 && until != u64::MAX && created > until {
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
        txn: &RoTxn<'_>,
        filters: &[NostrFilter],
        latest_event_id: u64,
        time_budget_us: u64,
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
                    txn,
                    &filters[self.gather_index],
                    latest_event_id,
                    remaining_us,
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
        txn: &RoTxn<'_>,
        filter: &NostrFilter,
        latest_event_id: u64,
        time_budget_us: u64,
    ) -> Result<bool, wok_db::DbError> {
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
        let mut error = None;
        let completed = search_postings(txn, &primary, self.resume_lev_id, |lev_id| {
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
                    self.top_hits.pop();
                }
            }

            self.approx_work % 128 != 0 || start.elapsed().as_micros() as u64 <= time_budget_us
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
        txn: &RoTxn<'_>,
        filter: &NostrFilter,
        latest_event_id: u64,
        time_budget_us: u64,
        mut handle_event: H,
    ) -> Result<bool, wok_db::DbError>
    where
        H: FnMut(u64) -> bool,
    {
        if !self.gather(txn, filter, latest_event_id, time_budget_us)? {
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
        let dbis = txn.env().dbis();
        let mut index_only = f.index_only_scans;
        let mut cursors = Vec::new();
        let (index_dbi, desc) = if f.ids.is_some() {
            (dbis.event_id, "ID")
        } else if !f.tags.is_empty() || !f.and_tags.is_empty() {
            (dbis.event_tag, "Tag")
        } else if f.authors.is_some()
            && f.kinds.is_some()
            && f.authors.as_ref().unwrap().size() * f.kinds.as_ref().unwrap().size() < 1000
        {
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

        if let Some(ids) = &f.ids {
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
        } else if f.authors.is_some()
            && f.kinds.is_some()
            && f.authors.as_ref().unwrap().size() * f.kinds.as_ref().unwrap().size() < 1000
        {
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
            if do_send && handle_event(lev_id) {
                return Ok(true);
            }
            let si = ev.scan_index() as usize;
            self.cursors[si].outstanding -= 1;
            if self.cursors[si].outstanding == 0 {
                let mut more = VecDeque::new();
                self.approx_work += self.cursors[si].collect(
                    txn,
                    self.index_dbi,
                    ev.scan_index(),
                    self.since,
                    self.until,
                    self.refill_scan_depth,
                    &mut more,
                )?;
                let mut merged: Vec<_> = self.event_queue.drain(..).chain(more).collect();
                merged.sort_by(cmp_cand);
                self.event_queue = merged.into();
            }
        }
    }
}

pub struct DbQuery {
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
        let hll = if sub.count_only && sub.filter_group.filters.len() == 1 {
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
        }
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

    fn visible_event_pubkey(
        txn: &RoTxn<'_>,
        lev_id: u64,
    ) -> Result<Option<[u8; 32]>, wok_db::DbError> {
        let Some(raw) = txn.get_u64(txn.env().dbis().event, lev_id)? else {
            return Ok(None);
        };
        let packed = PackedEventView::new(raw)?;
        if is_event_vanished_ro(txn, packed)? {
            return Ok(None);
        }
        if is_event_moderated_ro(txn, packed)? {
            return Ok(None);
        }
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(packed.pubkey());
        Ok(Some(pubkey))
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
        if self.all_filters_search {
            let mut group = match self.search_group.take() {
                Some(group) => group,
                None => SearchGroupScan::new(&self.sub.filter_group.filters, txn)?,
            };
            let mut sent = std::mem::take(&mut self.sent_events_full);
            let mut hits = Vec::new();
            let mut visibility_error = None;
            let mut dedup_budget_hit = false;
            let count_dedup_budget = self.count_dedup_budget;
            let complete = group.process(
                txn,
                &self.sub.filter_group.filters,
                self.sub.latest_event_id,
                time_budget_us,
                |lev_id| {
                    let pubkey = match Self::visible_event_pubkey(txn, lev_id) {
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
                    if (self.max_total_events == 0 || (sent.len() as u64) < self.max_total_events)
                        && sent.insert(lev_id)
                    {
                        hits.push((lev_id, pubkey));
                    }
                },
            )?;
            if let Some(error) = visibility_error {
                return Err(error);
            }
            self.sent_events_full = sent;
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
            if self.max_total_events != 0
                && self.sent_events_full.len() as u64 >= self.max_total_events
            {
                return Ok(true);
            }
            if !complete {
                self.search_group = Some(group);
            }
            return Ok(complete);
        }

        while self.filter_group_index < self.sub.filter_group.filters.len() {
            // C++ DBQuery resets the timeslice clock per filter.
            let start = std::time::Instant::now();
            let f = self.sub.filter_group.filters[self.filter_group_index].clone();
            let mut scanner = match self.scanner.take() {
                Some(scanner) => scanner,
                None if f.search.is_some() => QueryScanner::Search(SearchScan::new(&f, txn)?),
                None => QueryScanner::Chronological(DbScan::new(&f, txn)),
            };
            let latest = self.sub.latest_event_id;
            let mut sent_full = std::mem::take(&mut self.sent_events_full);
            let mut sent_curr = std::mem::take(&mut self.sent_events_curr);
            let mut last_work = self.last_work_checked;
            let mut hits: Vec<(u64, [u8; 32])> = Vec::new();
            let mut visibility_error = None;
            let mut dedup_budget_hit = false;
            let count_dedup_budget = self.count_dedup_budget;
            let mut handle = |lev_id| {
                if f.limit == 0 {
                    return true;
                }
                if lev_id > latest {
                    return false;
                }
                let pubkey = match Self::visible_event_pubkey(txn, lev_id) {
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
                sent_curr.len() as u64 >= f.limit
                    || (self.max_total_events != 0
                        && sent_full.len() as u64 >= self.max_total_events)
            };
            let complete = match &mut scanner {
                QueryScanner::Chronological(scanner) => {
                    scanner.scan(txn, &f, &mut handle, |approx_work| {
                        if approx_work > last_work + 2000 {
                            last_work = approx_work;
                            start.elapsed().as_micros() as u64 > time_budget_us
                        } else {
                            false
                        }
                    })?
                }
                QueryScanner::Search(scanner) => {
                    scanner.scan(txn, &f, latest, time_budget_us, &mut handle)?
                }
            };
            if let Some(error) = visibility_error {
                return Err(error);
            }
            self.sent_events_full = sent_full;
            self.sent_events_curr = sent_curr;
            self.last_work_checked = last_work;
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
            if self.max_total_events != 0
                && self.sent_events_full.len() as u64 >= self.max_total_events
            {
                return Ok(true);
            }
            if !complete {
                self.scanner = Some(scanner);
                return Ok(false);
            }
            self.scanner = None;
            self.filter_group_index += 1;
            self.sent_events_curr.clear();
        }
        Ok(true)
    }
}

pub fn foreach_by_filter<F>(
    txn: &RoTxn<'_>,
    filter: &serde_json::Value,
    max_limit: u64,
    max_tags: usize,
    max_and_entries: usize,
    mut cb: F,
) -> Result<(), crate::subid::QueryError>
where
    F: FnMut(u64),
{
    let fg =
        crate::filter::NostrFilterGroup::from_value(filter, max_limit, max_tags, max_and_entries)?;
    let sub = Subscription::new(1, crate::subid::SubId::new(".").unwrap(), fg, false);
    let mut q = DbQuery::new(sub, 0, 0);
    q.process(txn, |_, lev| cb(lev), u64::MAX)
        .map_err(|e| crate::subid::QueryError::msg(e.to_string()))?;
    Ok(())
}
