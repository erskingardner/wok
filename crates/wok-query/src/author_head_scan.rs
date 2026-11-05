//! Opt-in initialization from snapshot-bound, two-position author frontiers.
//!
//! This only replaces depth-one initialization of wide, pure-author scans. The
//! ordinary heap, refill, visibility, latest-ID checks and peek remain owners
//! of their existing state. A normal delivery batch has at most 32 keys and
//! seeds/charges all of them before the next pause check; no pending uncharged
//! lookup survives a yield. Peeks never use this path. The coarser initialization
//! check may overshoot by one batch (at most 64 logical work plus the next
//! loop check), not a fixed duration. Native/header costs are separate counters.

use super::*;
use wok_db::AuthorHead;

const BATCH_KEYS: usize = 32;
#[cfg(all(test, feature = "rocksdb-read-diagnostics"))]
pub(super) const DIAGNOSTIC_BATCH_KEYS: usize = BATCH_KEYS;
const PACKED_TIME_MAX: u64 = 0xFF_FFFFFFFF;

// Query-level observations for the distinct native seed diagnostic only.
// These add no lookups and do not extend WrapperCounters or ordinary builds.
#[cfg(all(test, feature = "rocksdb-read-diagnostics"))]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct InitializationStats {
    pub(super) issued_keys: u64,
    pub(super) seeded_heads: u64,
    pub(super) fallback_missing: u64,
    pub(super) fallback_below_since: u64,
    pub(super) fallback_above_until: u64,
    pub(super) fallback_unsupported_timestamp: u64,
    pub(super) fallback_postings_collected: u64,
    // A native batch error does not establish whether decoding or I/O failed.
    pub(super) failed_batch_keys: u64,
    pub(super) failed_batch_calls: u64,
    pub(super) header_keys_during_peek: u64,
}

#[cfg(all(test, feature = "rocksdb-read-diagnostics"))]
impl InitializationStats {
    pub(super) fn classified_keys(self) -> u64 {
        self.seeded_heads
            + self.fallback_missing
            + self.fallback_below_since
            + self.fallback_above_until
            + self.fallback_unsupported_timestamp
    }

    /// A scanner may survive several process slices. Add only the new work;
    /// all scanners, including a short-lived unscanned-filter peek, contribute.
    pub(super) fn add_delta(&mut self, after: Self, before: Self, peek: bool) {
        macro_rules! add {
            ($($field:ident),+ $(,)?) => {$(self.$field += after.$field - before.$field;)+};
        }
        add!(
            issued_keys,
            seeded_heads,
            fallback_missing,
            fallback_below_since,
            fallback_above_until,
            fallback_unsupported_timestamp,
            fallback_postings_collected,
            failed_batch_keys,
            failed_batch_calls,
        );
        self.header_keys_during_peek +=
            after.header_keys_during_peek - before.header_keys_during_peek;
        if peek {
            self.header_keys_during_peek += after.issued_keys - before.issued_keys;
        }
    }

    pub(super) fn observe(&mut self, head: Option<AuthorHead>, since: u64, until: u64) {
        match head {
            None => self.fallback_missing += 1,
            Some(head) if head.first.created_at > PACKED_TIME_MAX => {
                self.fallback_unsupported_timestamp += 1;
            }
            Some(head) if head.first.created_at < since => self.fallback_below_since += 1,
            Some(head) if head.first.created_at > until => self.fallback_above_until += 1,
            Some(_) => self.seeded_heads += 1,
        }
    }
}

pub(super) fn eligible(f: &NostrFilter, plan: ScanPlan, depth: u64, cursors: usize) -> bool {
    plan == ScanPlan::Pubkey
        && cursors > 1
        && depth == 1
        && f.index_only_scans
        && f.authors.is_some()
        && f.ids.is_none()
        && f.kinds.is_none()
        && f.tags.is_empty()
        && f.and_tags.is_empty()
        && f.search.is_none()
        && !f.never_match
        && f.limit != 0
}

pub(super) fn enabled(scan: &DbScan) -> bool {
    if !scan.author_head_reads || !scan.index_only {
        return false;
    }
    // Preserve the independent bounded-global diagnostic's author suffix as
    // its established control, rather than combining two experiments silently.
    #[cfg(all(test, feature = "rocksdb-read-diagnostics"))]
    if scan.diagnostic_feed_stats.configured {
        return false;
    }
    true
}

pub(super) fn physical<'slot, 'tx>(
    slot: &'slot mut Option<Cursor<'tx>>,
    txn: &'tx RoTxn<'_>,
    dbi: lmdb_sys::MDB_dbi,
) -> Result<&'slot mut Cursor<'tx>, wok_db::DbError> {
    if slot.is_none() {
        *slot = Some(txn.cursor(dbi)?);
    }
    Ok(slot.as_mut().expect("initialized physical scan cursor"))
}

/// Seed the exact second physical posting, not the first one's predecessor.
/// Keeping the existing lookahead endpoint avoids inspecting a newly backdated
/// posting in the gap after a later snapshot refresh.
fn seed(cursor: &mut ScanCursor, head: AuthorHead, index: usize) -> CandidateEvent {
    assert_eq!(cursor.outstanding, 0);
    if let Some(next) = head.next {
        let time_at = cursor.resume_key.len() - 8;
        cursor.resume_key[time_at..].copy_from_slice(&next.created_at.to_ne_bytes());
        cursor.resume_val = next.local_id;
    } else {
        cursor.resume_key.clear();
    }
    cursor.outstanding = 1;
    CandidateEvent::new(head.first.local_id, head.first.created_at, index as u64)
}

/// The caller has charged/checked the first key's ordinary loop attempt.
/// All future key attempts and candidate additions are charged in this call,
/// even when a native/header/fallback error aborts the batch.
pub(super) fn initialize<'tx>(
    scan: &mut DbScan,
    txn: &'tx RoTxn<'_>,
    cursor: &mut Option<Cursor<'tx>>,
) -> Result<bool, wok_db::DbError> {
    if !enabled(scan) {
        return Ok(false);
    }
    let start = scan.next_init_index;
    let end = (start + BATCH_KEYS).min(scan.cursors.len());
    #[cfg(all(test, feature = "rocksdb-read-diagnostics"))]
    {
        scan.diagnostic_author_frontier_initialization.issued_keys += (end - start) as u64;
    }
    let head_result = txn.author_heads(scan.cursors[start..end].iter().map(|range| {
        <&[u8; 32]>::try_from(range.search.as_slice()).expect("pure author range key")
    }));
    let heads = match head_result {
        Ok(heads) => heads,
        Err(error) => {
            #[cfg(all(test, feature = "rocksdb-read-diagnostics"))]
            {
                scan.diagnostic_author_frontier_initialization
                    .failed_batch_keys += (end - start) as u64;
                scan.diagnostic_author_frontier_initialization
                    .failed_batch_calls += 1;
            }
            scan.approx_work += (end - start - 1) as u64;
            return Err(error);
        }
    };
    if heads.len() != end - start {
        scan.approx_work += (end - start - 1) as u64;
        return Err(wok_db::DbError::msg(
            "author frontier result count mismatch",
        ));
    }
    initialize_entries(scan, txn, cursor, start, heads)?;
    Ok(true)
}

fn initialize_entries<'tx>(
    scan: &mut DbScan,
    txn: &'tx RoTxn<'_>,
    cursor: &mut Option<Cursor<'tx>>,
    start: usize,
    heads: Vec<Option<AuthorHead>>,
) -> Result<(), wok_db::DbError> {
    let end = start + heads.len();
    for (offset, head) in heads.into_iter().enumerate() {
        let index = start + offset;
        #[cfg(all(test, feature = "rocksdb-read-diagnostics"))]
        scan.diagnostic_author_frontier_initialization
            .observe(head, scan.since, scan.until);
        if offset != 0 {
            scan.approx_work += 1;
        }
        if let Some(head) = head.filter(|head| {
            head.first.created_at >= scan.since
                && head.first.created_at <= scan.until
                // Keep inherited timestamp packing limitations separate.
                && head.first.created_at <= PACKED_TIME_MAX
        }) {
            let candidate = seed(&mut scan.cursors[index], head, index);
            scan.event_queue.extend(std::iter::once(candidate));
            scan.approx_work += 1;
        } else {
            // A missing head is never proof of an empty author. Any timestamp
            // outside the requested window keeps the existing bounded seek.
            let added = (|| {
                scan.cursors[index].collect(
                    physical(cursor, txn, scan.index_dbi)?,
                    index as u64,
                    scan.since,
                    scan.until,
                    1,
                    &mut scan.collection_buffer,
                )
            })();
            match added {
                Ok(added) => {
                    scan.approx_work += added;
                    #[cfg(all(test, feature = "rocksdb-read-diagnostics"))]
                    {
                        scan.diagnostic_author_frontier_initialization
                            .fallback_postings_collected += added;
                    }
                }
                Err(error) => {
                    // Later keys were looked up by the issued MultiGet even
                    // though their ordinary fallback is no longer attempted.
                    scan.approx_work += (end - index - 1) as u64;
                    return Err(error);
                }
            }
            scan.event_queue.extend(scan.collection_buffer.drain(..));
        }
        scan.next_init_index += 1;
    }
    Ok(())
}

#[cfg(all(test, feature = "rocksdb-read-diagnostics"))]
#[path = "author_head_tests.rs"]
mod tests;
