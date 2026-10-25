//! Read-only snapshot and verification helpers for strfry migration.

#![allow(unsafe_code)]

use crate::{foreach_event_from, DbError, Decompressor, Env, EnvOptions, RoTxn};
use lmdb_sys::{
    mdb_env_close, mdb_env_copy2, mdb_env_create, mdb_env_open, MDB_CP_COMPACT, MDB_NORDAHEAD,
    MDB_RDONLY, MDB_READERS_FULL,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::ffi::CString;
use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::ptr;
use std::sync::{Mutex, PoisonError};
use wok_event::PackedEventView;

/// Failures [`verify_events`] names; the rest are only counted.
const MAX_REPORTED_FAILURES: usize = 100;
/// Local ids a [`verify_events`] worker takes at a time.
const VERIFY_RUN: u64 = 4096;
/// Largest payload JSON decoded, as integrity decodes it.
const MAX_PAYLOAD_JSON: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventFingerprint {
    pub count: u64,
    pub sha256: [u8; 32],
}

/// Take a transactionally consistent compact copy without opening any write
/// transaction against the source environment.
pub fn snapshot_lmdb_readonly(
    source: &Path,
    destination: &Path,
    no_read_ahead: bool,
) -> Result<(), DbError> {
    if destination.exists() {
        return Err(DbError::msg(format!(
            "snapshot destination '{}' already exists",
            destination.display()
        )));
    }
    std::fs::create_dir_all(destination).map_err(|e| DbError::msg(e.to_string()))?;

    let source = CString::new(source.to_string_lossy().as_bytes())
        .map_err(|_| DbError::msg("source DB path contains NUL"))?;
    let destination = CString::new(destination.to_string_lossy().as_bytes())
        .map_err(|_| DbError::msg("snapshot destination path contains NUL"))?;

    let mut raw_env = ptr::null_mut();
    let result = (|| {
        crate::error::check(unsafe { mdb_env_create(&mut raw_env) })?;
        let mut flags = MDB_RDONLY;
        if no_read_ahead {
            flags |= MDB_NORDAHEAD;
        }
        crate::error::check(unsafe { mdb_env_open(raw_env, source.as_ptr(), flags, 0o664) })?;
        crate::error::check(unsafe { mdb_env_copy2(raw_env, destination.as_ptr(), MDB_CP_COMPACT) })
    })();
    if !raw_env.is_null() {
        unsafe { mdb_env_close(raw_env) };
    }
    result
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
/// holds an LMDB reader slot, so no more are started than the environment
/// has slots never used. On a database being written, events stored after
/// the call begins may be skipped.
pub fn verify_events(env: &Env, threads: usize) -> Result<EventVerificationReport, DbError> {
    let runs = Runs {
        next: Mutex::new(Some(0)),
        largest: env.begin_ro()?.largest_integer_key(env.dbis().event)?,
    };
    // The calling thread holds a slot now, and verifies too.
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
    let txn = match env.begin_ro() {
        Ok(txn) => txn,
        // Another process took the slot; the other workers take the runs.
        Err(DbError::Lmdb(MDB_READERS_FULL, _)) => return Ok(EventVerificationReport::default()),
        Err(error) => return Err(error),
    };
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

impl Env {
    /// Mark a verified strfry v3 snapshot as Wok-owned. No event or index data
    /// is rewritten by this operation.
    pub fn upgrade_strfry_v3_to_wok(&self) -> Result<(), DbError> {
        let mut txn = crate::RwTxn::begin(self)?;
        let raw = txn
            .get_u64(self.dbis().meta, 1)?
            .ok_or_else(|| DbError::msg("strfry source has no Meta record"))?;
        let mut meta = crate::decode_meta(raw)?;
        if meta.endianness != 1 {
            return Err(DbError::msg(
                "strfry source was created on a machine with different endianness",
            ));
        }
        if meta.db_version != wok_event::STRFRY_DB_VERSION {
            return Err(DbError::msg(format!(
                "strfry source database version {} (expected {})",
                meta.db_version,
                wok_event::STRFRY_DB_VERSION
            )));
        }
        meta.db_version = wok_event::WOK_DB_VERSION;
        txn.put_u64(self.dbis().meta, 1, &crate::encode_meta(&meta), 0)?;
        txn.commit()
    }
}

/// Open a snapshot without allowing the storage layer to create it. Kept here
/// as a small convenience for migration callers.
pub fn open_snapshot(path: &Path, no_read_ahead: bool) -> Result<Env, DbError> {
    Env::open(
        path,
        EnvOptions {
            no_read_ahead,
            create_dir: false,
            create_dbis: false,
            ..EnvOptions::default()
        },
    )
}
