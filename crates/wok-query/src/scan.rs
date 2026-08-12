//! Resumable DBScan matching `src/DBQuery.h`.

use crate::filter::NostrFilter;
use crate::subid::Subscription;
use std::collections::{HashSet, VecDeque};
use wok_db::keys::{make_key_string_u64, parse_key_string_u64, u64_from_ne};
use wok_db::RoTxn;
use wok_event::PackedEventView;

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
            txn.foreach_full(index_dbi, &start_key, &start_dup, true, |k, v| {
                if limit == 0 {
                    self.resume_key = k.to_vec();
                    self.resume_val = u64_from_ne(v);
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
                let lev_id = u64_from_ne(v);
                output.push_back(CandidateEvent::new(lev_id, created, scan_index));
                added += 1;
                limit -= 1;
                true
            })?;
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

impl DbScan {
    pub fn new(f: &NostrFilter, txn: &RoTxn<'_>) -> Self {
        let dbis = txn.env().dbis();
        let mut index_only = f.index_only_scans;
        let mut cursors = Vec::new();
        let (index_dbi, desc) = if f.ids.is_some() {
            (dbis.event_id, "ID")
        } else if !f.tags.is_empty() {
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
        } else if !f.tags.is_empty() {
            let (tag_name, filter_set) = f
                .tags
                .iter()
                .min_by_key(|(_, s)| s.size())
                .map(|(k, v)| (*k, v))
                .unwrap();
            for i in 0..filter_set.size() {
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
    scanner: Option<DbScan>,
    filter_group_index: usize,
    pub dead: bool,
    sent_events_full: HashSet<u64>,
    sent_events_curr: HashSet<u64>,
    last_work_checked: u64,
}

impl DbQuery {
    pub fn new(sub: Subscription) -> Self {
        Self {
            sub,
            scanner: None,
            filter_group_index: 0,
            dead: false,
            sent_events_full: HashSet::new(),
            sent_events_curr: HashSet::new(),
            last_work_checked: 0,
        }
    }

    pub fn sent_count(&self) -> u64 {
        self.sent_events_full.len() as u64
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
        let start = std::time::Instant::now();
        while self.filter_group_index < self.sub.filter_group.filters.len() {
            let f = self.sub.filter_group.filters[self.filter_group_index].clone();
            let mut scanner = match self.scanner.take() {
                Some(s) => s,
                None => DbScan::new(&f, txn),
            };
            let latest = self.sub.latest_event_id;
            let mut sent_full = std::mem::take(&mut self.sent_events_full);
            let mut sent_curr = std::mem::take(&mut self.sent_events_curr);
            let mut last_work = self.last_work_checked;
            let mut hits: Vec<u64> = Vec::new();
            let complete = scanner.scan(
                txn,
                &f,
                |lev_id| {
                    if f.limit == 0 {
                        return true;
                    }
                    if lev_id > latest {
                        return false;
                    }
                    if sent_full.insert(lev_id) {
                        hits.push(lev_id);
                    }
                    sent_curr.insert(lev_id);
                    sent_curr.len() as u64 >= f.limit
                },
                |approx_work| {
                    if approx_work > last_work + 2000 {
                        last_work = approx_work;
                        start.elapsed().as_micros() as u64 > time_budget_us
                    } else {
                        false
                    }
                },
            )?;
            self.sent_events_full = sent_full;
            self.sent_events_curr = sent_curr;
            self.last_work_checked = last_work;
            for lev in hits {
                cb(&self.sub, lev);
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
    mut cb: F,
) -> Result<(), crate::subid::QueryError>
where
    F: FnMut(u64),
{
    let fg = crate::filter::NostrFilterGroup::from_value(filter, max_limit, max_tags)?;
    let sub = Subscription::new(1, crate::subid::SubId::new(".").unwrap(), fg, false);
    let mut q = DbQuery::new(sub);
    q.process(txn, |_, lev| cb(lev), u64::MAX)
        .map_err(|e| crate::subid::QueryError::msg(e.to_string()))?;
    Ok(())
}
