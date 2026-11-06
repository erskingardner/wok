//! Stored-event verification and fingerprints for RocksDB databases.

#![forbid(unsafe_code)]

use crate::{foreach_event_from, DbError, Decompressor, Env, RoTxn};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::panic::AssertUnwindSafe;
use std::sync::{Mutex, PoisonError};
use wok_event::PackedEventView;

/// Failures [`verify_events`] names; the rest are only counted.
const MAX_REPORTED_FAILURES: usize = 100;
/// Local ids a [`verify_events`] worker takes at a time.
const VERIFY_RUN: u64 = 4096;
/// Largest payload JSON decoded, as integrity decodes it.
const MAX_PAYLOAD_JSON: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EventFingerprint {
    pub count: u64,
    pub sha256: [u8; 32],
}

/// Hash the complete logical event records without decompressing or
/// reserializing them. Length framing makes the digest unambiguous.
pub fn event_fingerprint(env: &Env) -> Result<EventFingerprint, DbError> {
    fingerprint(env, false, &BTreeSet::new())
}

/// [`event_fingerprint`] over PackedEvent records without their hashed tag
/// values, which reindex adds to records that dropped long values. It stays
/// the same across such a repack.
pub fn event_fingerprint_without_hashed_tag_values(env: &Env) -> Result<EventFingerprint, DbError> {
    fingerprint(env, true, &BTreeSet::new())
}

/// [`event_fingerprint`], or with `without_hashed_tag_values`
/// [`event_fingerprint_without_hashed_tag_values`], of the records other than
/// the local IDs in `excluded`: what a database holding only the others hashes
/// to. Every excluded record must be stored.
pub fn event_fingerprint_excluding(
    env: &Env,
    excluded: &BTreeSet<u64>,
    without_hashed_tag_values: bool,
) -> Result<EventFingerprint, DbError> {
    fingerprint(env, without_hashed_tag_values, excluded)
}

fn fingerprint(
    env: &Env,
    without_hashed_tag_values: bool,
    excluded: &BTreeSet<u64>,
) -> Result<EventFingerprint, DbError> {
    let txn = env.begin_ro()?;
    let mut hasher = Sha256::new();
    let mut count = 0u64;
    let mut skipped = 0usize;
    let mut error = None;
    foreach_event_from(&txn, 0, |lev_id, packed| {
        if excluded.contains(&lev_id) {
            skipped += 1;
            return true;
        }
        match txn.get_u64(env.dbis().event_payload, lev_id) {
            Ok(Some(payload)) => {
                let packed = if without_hashed_tag_values {
                    crate::long_tags::without_hashed_tag_values(packed)
                } else {
                    std::borrow::Cow::Borrowed(packed)
                };
                hasher.update(lev_id.to_be_bytes());
                hasher.update((packed.len() as u64).to_be_bytes());
                hasher.update(&*packed);
                hasher.update((payload.len() as u64).to_be_bytes());
                hasher.update(payload);
                count += 1;
                true
            }
            Ok(None) => {
                error = Some(DbError::msg(format!(
                    "event {lev_id} has no payload during migration verification"
                )));
                false
            }
            Err(err) => {
                error = Some(err);
                false
            }
        }
    })?;
    if let Some(error) = error {
        return Err(error);
    }
    if skipped != excluded.len() {
        return Err(DbError::msg(format!(
            "{} of the {} records excluded from the fingerprint are not stored",
            excluded.len() - skipped,
            excluded.len()
        )));
    }
    Ok(EventFingerprint {
        count,
        sha256: hasher.finalize().into(),
    })
}

/// A stored event whose payload does not verify against its PackedEvent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EventVerificationFailure {
    pub lev_id: u64,
    /// The PackedEvent's id, which the indexes key the event by. Empty when
    /// the record does not decode.
    pub id: String,
    pub reason: String,
}

/// What [`verify_events`] found.
#[derive(Clone, Debug, Default, Serialize)]
pub struct EventVerificationReport {
    pub events: u64,
    pub failed: u64,
    /// The failures with the lowest local ids, at most 100.
    pub failures: Vec<EventVerificationFailure>,
}

impl EventVerificationReport {
    pub fn ok(&self) -> bool {
        self.failed == 0
    }
}

/// Verify every stored event against its payload with
/// [`wok_event::verify_strfry_event`]: the payload names the PackedEvent's
/// id, pubkey, kind and created_at, hashes to that id, and is signed by that
/// pubkey, and the PackedEvent, from which every index is derived, indexes
/// nothing the payload does not carry.
///
/// Up to `threads` workers, the calling thread among them, each open one
/// read transaction and take runs of local ids from a shared counter. Each
/// uses its own RocksDB snapshot. On a database being written, events stored
/// after the call begins may be skipped; use the offline migration API for a
/// single immutable source snapshot and bounded conversion validation.
pub fn verify_events(env: &Env, threads: usize) -> Result<EventVerificationReport, DbError> {
    let runs = Runs {
        next: Mutex::new(Some(0)),
        largest: env.begin_ro()?.largest_integer_key(env.dbis().event)?,
    };
    // Retain the configured worker budget; the calling thread verifies too.
    let stats = env.stats()?;
    let spare = stats.max_readers.saturating_sub(stats.readers) as usize;
    let spawned = threads.saturating_sub(1).min(spare);
    let reports = std::thread::scope(|scope| {
        // A worker the OS cannot start leaves its runs to the others, and
        // the ones already started are still joined below.
        let workers: Vec<_> = (0..spawned)
            .map_while(|_| {
                std::thread::Builder::new()
                    .spawn_scoped(scope, || verify_runs(env, &runs))
                    .ok()
            })
            .collect();
        let mine = std::panic::catch_unwind(AssertUnwindSafe(|| verify_runs(env, &runs)));
        // Join every worker before any result can return. A scope waits only
        // for a worker's closure: LMDB frees its reader slot later, as the
        // thread exits, and would write to the environment's lock file
        // after the caller had closed it.
        let joined: Vec<_> = workers.into_iter().map(|worker| worker.join()).collect();
        joined
            .into_iter()
            .chain([mine])
            .map(|report| report.unwrap_or_else(|panic| std::panic::resume_unwind(panic)))
            .collect::<Result<Vec<_>, _>>()
    })?;
    let mut total = EventVerificationReport::default();
    for report in reports {
        total.events += report.events;
        total.failed += report.failed;
        total.failures.extend(report.failures);
    }
    // Each worker keeps its lowest failures, so the lowest overall are here.
    total.failures.sort_by_key(|failure| failure.lev_id);
    total.failures.truncate(MAX_REPORTED_FAILURES);
    Ok(total)
}

/// The local ids no [`verify_events`] worker has claimed: from `next`, or
/// none, through `largest`.
struct Runs {
    next: Mutex<Option<u64>>,
    largest: u64,
}

impl Runs {
    /// Claim the next run, `first..=last`.
    fn claim(&self) -> Option<(u64, u64)> {
        let mut next = self.next.lock().unwrap_or_else(PoisonError::into_inner);
        let first = next.filter(|first| *first <= self.largest)?;
        let last = first.saturating_add(VERIFY_RUN - 1);
        *next = last.checked_add(1);
        Some((first, last))
    }

    /// No event is stored between a claimed run and `lev_id`, so skip the
    /// gap: work then follows the events stored, not the largest local id.
    fn skip_to(&self, lev_id: u64) {
        let mut next = self.next.lock().unwrap_or_else(PoisonError::into_inner);
        if next.is_some_and(|first| first < lev_id) {
            *next = Some(lev_id);
        }
    }
}

fn verify_runs(env: &Env, runs: &Runs) -> Result<EventVerificationReport, DbError> {
    let txn = env.begin_ro()?;
    let mut decompressor = Decompressor::new();
    let mut report = EventVerificationReport::default();
    let mut error = None;
    while let Some((first, last)) = runs.claim() {
        let mut beyond = None;
        foreach_event_from(&txn, first, |lev_id, packed| {
            if lev_id > last {
                beyond = Some(lev_id);
                return false;
            }
            report.events += 1;
            let reason = match verify_event(&txn, &mut decompressor, lev_id, packed) {
                Ok(None) => return true,
                Ok(Some(reason)) => reason,
                Err(lookup) => {
                    error = Some(lookup);
                    return false;
                }
            };
            report.failed += 1;
            if report.failures.len() < MAX_REPORTED_FAILURES {
                report.failures.push(EventVerificationFailure {
                    lev_id,
                    id: PackedEventView::new(packed)
                        .map(|packed| wok_event::to_hex(packed.id()))
                        .unwrap_or_default(),
                    reason,
                });
            }
            true
        })?;
        if let Some(error) = error {
            return Err(error);
        }
        if let Some(lev_id) = beyond {
            runs.skip_to(lev_id);
        }
    }
    Ok(report)
}

/// Why the event `lev_id` does not verify, if it does not. Only a failed
/// lookup is an error.
fn verify_event(
    txn: &RoTxn<'_>,
    decompressor: &mut Decompressor,
    lev_id: u64,
    packed: &[u8],
) -> Result<Option<String>, DbError> {
    let packed = match PackedEventView::new(packed) {
        Ok(packed) => packed,
        Err(error) => return Ok(Some(format!("PackedEvent: {error}"))),
    };
    let Some(payload) = txn.get_u64(txn.env().dbis().event_payload, lev_id)? else {
        return Ok(Some("no payload".into()));
    };
    let json = match decompressor.decode(txn, payload, MAX_PAYLOAD_JSON) {
        Ok(json) => json,
        Err(error) => return Ok(Some(format!("payload: {error}"))),
    };
    Ok(wok_event::json::parse_strict(json)
        .and_then(|event| wok_event::verify_strfry_event(packed, &event))
        .err()
        .map(|error| error.to_string()))
}
