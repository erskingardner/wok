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
const PACKED_TIME_MAX: u64 = 0xFF_FFFFFFFF;

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
    let head_result = txn.author_heads(scan.cursors[start..end].iter().map(|range| {
        <&[u8; 32]>::try_from(range.search.as_slice()).expect("pure author range key")
    }));
    let heads = match head_result {
        Ok(heads) => heads,
        Err(error) => {
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
                Ok(added) => scan.approx_work += added,
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
