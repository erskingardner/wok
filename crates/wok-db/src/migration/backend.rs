//! Offline, full-state Wok LMDB -> RocksDB migration.
//!
//! The operator must stop every source writer for the entire operation. The
//! source is a registered read-only LMDB snapshot (lock-file coordination is
//! allowed); data.mdb identity and the latest transaction are checked again
//! before sealing. Every known logical table is copied, including opaque policy,
//! dictionaries, negentropy nodes, sequence holes, and unfinished index/sweep
//! progress. Only a v4 Meta version field is normalized to v5. No event is
//! reimported, repacked, reindexed, or replayed through publication policy.
//!
//! The destination must not exist. Failures retain it; incomplete copies carry
//! a pending marker and sentinel that ordinary opens refuse. A filesystem error
//! after sealing can leave a verified, unpublished copy if refusal cannot be
//! restored. There is no resume/overwrite path. Callers must use private staging
//! and publish only after this API returns successfully.
// The private lmdb child is the documented, isolated native FFI boundary.
#![deny(unsafe_code)]

#[path = "lmdb.rs"]
mod lmdb;

use crate::rocks::{
    cf_name, decode, encode, physical_cf_names, reversed, spec, COMBINED, FORMAT, FORMAT_KEY,
};
use crate::{DbError, Env, RwTxn};
use lmdb_sys::{MDB_INTEGERDUP, MDB_INTEGERKEY};
use rocksdb::{ReadOptions, WriteBatch, WriteOptions, DB};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

const PENDING: &[u8] = b"wok-rocksdb-migration-incomplete:lmdb-full-state-v1";
/// Normal Env opens must reject this before performing any native operation.
pub(crate) const INCOMPLETE_MARKER_FILE: &str = ".wok-migration-incomplete";
const MAX_BATCH_BYTES: usize = 16 << 20;
const MAX_RECORD_BYTES: usize = 64 << 20;
const MAX_JSON_BYTES: usize = 16 << 20;

/// Bounded conversion buffers, excluding the native engines' configured caches.
/// A single record may exceed a batch and is handled alone, up to its own bound.
/// Writer overlays have a constant-factor encoding/copy overhead; neither the
/// verification iterators nor their returned values accumulate in a RoTxn arena.
#[derive(Clone, Debug)]
pub struct LmdbToRocksOptions {
    pub batch_bytes: usize,
    pub max_record_bytes: usize,
    pub max_json_bytes: usize,
}
impl Default for LmdbToRocksOptions {
    fn default() -> Self {
        Self {
            batch_bytes: 8 << 20,
            max_record_bytes: MAX_RECORD_BYTES,
            max_json_bytes: MAX_JSON_BYTES,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct LmdbSourceReport {
    pub source: PathBuf,
    pub db_version: u64,
    pub target_db_version: u64,
    pub transaction_id: u64,
    pub data_file_bytes: u64,
    pub logical_records: u64,
    pub tables: Vec<LmdbTableInfo>,
}
#[derive(Clone, Debug, Serialize)]
pub struct LmdbTableInfo {
    pub name: String,
    pub present: bool,
    /// Persistent LMDB flags, excluding the transient MDB_CREATE flag.
    pub flags: u32,
    pub records: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LmdbTableVerification {
    pub name: String,
    pub source_present: bool,
    pub records: u64,
    pub key_bytes: u64,
    pub value_bytes: u64,
    pub source_sha256: String,
    /// Equals source_sha256 except for the explicitly reported v4 Meta upgrade.
    pub expected_target_sha256: String,
    pub target_sha256: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct LmdbToRocksReport {
    pub source: LmdbSourceReport,
    pub destination: PathBuf,
    pub target_layout: String,
    pub tables: Vec<LmdbTableVerification>,
    pub commits: u64,
    pub verified_events: u64,
    pub primary_fingerprint_sha256: String,
    pub meta_version_normalized: bool,
    pub source_unchanged: bool,
    pub verified: bool,
    pub sealed: bool,
}

/// Inspect only known DBI names, native flags, Meta and transactional counts.
/// No primary records are decoded. Stop source writers even for this check.
pub fn inspect_lmdb_source(path: &Path) -> Result<LmdbSourceReport, DbError> {
    Ok(lmdb::Source::open(path)?.report.clone())
}

/// Copy and verify a stopped Wok v4/v5 database into an absent destination.
/// Its parent must already exist at its canonical path, without symlink
/// ancestors. The destination must not overlap the source directory.
/// Errors preserve every source record and any destination. Once verification
/// has completed, a sealing/filesystem error may leave a verified, unpublished
/// copy; the caller must never promote a copy unless this API returns success.
pub fn migrate_lmdb_to_rocksdb(
    source: &Path,
    destination: &Path,
    options: &LmdbToRocksOptions,
) -> Result<LmdbToRocksReport, DbError> {
    migrate(source, destination, options, Fault::None)
}

fn failure(label: &str) -> DbError {
    DbError::msg(format!("LMDB -> RocksDB migration: {label}"))
}
fn io(error: std::io::Error) -> DbError {
    failure(&error.to_string())
}
fn native(error: rocksdb::Error) -> DbError {
    failure(error.as_ref())
}
fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}
fn sync_directory(path: &Path) -> Result<(), DbError> {
    File::open(path).and_then(|f| f.sync_all()).map_err(io)
}
fn read_options() -> ReadOptions {
    let mut ro = ReadOptions::default();
    ro.fill_cache(false);
    ro
}
fn synced() -> WriteOptions {
    let mut o = WriteOptions::default();
    o.set_sync(true);
    o.disable_wal(false);
    o
}

#[derive(Clone)]
struct Framed {
    hash: Sha256,
    rows: u64,
    key_bytes: u64,
    value_bytes: u64,
}
impl Framed {
    fn new(name: &str) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"WOK-LOGICAL-TABLE-V1\0");
        hash.update((name.len() as u64).to_be_bytes());
        hash.update(name.as_bytes());
        Self {
            hash,
            rows: 0,
            key_bytes: 0,
            value_bytes: 0,
        }
    }
    fn row(&mut self, key: &[u8], value: &[u8]) -> Result<(), DbError> {
        self.rows = self
            .rows
            .checked_add(1)
            .ok_or_else(|| failure("row count overflow"))?;
        self.key_bytes = self
            .key_bytes
            .checked_add(key.len() as u64)
            .ok_or_else(|| failure("key bytes overflow"))?;
        self.value_bytes = self
            .value_bytes
            .checked_add(value.len() as u64)
            .ok_or_else(|| failure("value bytes overflow"))?;
        self.hash.update([1]);
        self.hash.update((key.len() as u64).to_be_bytes());
        self.hash.update(key);
        self.hash.update((value.len() as u64).to_be_bytes());
        self.hash.update(value);
        Ok(())
    }
    fn digest(&self) -> String {
        let mut hash = self.hash.clone();
        hash.update([0]);
        for n in [self.rows, self.key_bytes, self.value_bytes] {
            hash.update(n.to_be_bytes());
        }
        hex(hash.finalize())
    }
}

fn validate_row(
    dbi: u32,
    key: &[u8],
    value: &[u8],
    options: &LmdbToRocksOptions,
) -> Result<(), DbError> {
    if key
        .len()
        .checked_add(value.len())
        .is_none_or(|n| n > options.max_record_bytes)
    {
        return Err(failure("record exceeds configured byte bound"));
    }
    // LMDB's native integer comparators require their canonical width. This
    // also prevents an integer-key alias from changing at-rest identity.
    let flags = spec(dbi).flags;
    if flags & MDB_INTEGERKEY != 0 && key.len() != 8 {
        return Err(failure("noncanonical integer key in source"));
    }
    if flags & MDB_INTEGERDUP != 0 && value.len() != 8 {
        return Err(failure("noncanonical integer duplicate in source"));
    }
    if dbi == 20 {
        if [
            crate::state::HIGH_WATER,
            crate::state::POLICY_GENERATION,
            crate::state::VANISH_MARKER_CHANGES,
            crate::state::SUPERSEDED_EVENTS,
            crate::state::LEGACY_SUPERSEDED_EVENTS,
        ]
        .contains(&key)
            || (key.first() == Some(&b'a') && key.len() == 33)
        {
            crate::state::decode(value)
                .map_err(|_| failure("invalid known scalar in wok_State"))?;
        } else if key.first() == Some(&crate::state::VANISH_SWEEP) && key.len() == 33 {
            crate::vanish::SweepProgress::decode(value)
                .map_err(|_| failure("invalid vanish sweep progress in wok_State"))?;
        }
    }
    Ok(())
}

// v4 -> v5 adds lazy bookkeeping only. Patch the one existing scalar rather
// than rebuilding the FlatBuffer (which would discard padding/unknown fields).
fn normalize_meta(raw: &[u8]) -> Result<Vec<u8>, DbError> {
    let meta = crate::decode_meta(raw)?;
    if meta.db_version != 4 {
        return Ok(raw.to_vec());
    }
    let root = u32::from_le_bytes(
        raw.get(..4)
            .ok_or_else(|| failure("short Meta"))?
            .try_into()
            .unwrap(),
    ) as usize;
    let relative = i32::from_le_bytes(
        raw.get(root..root + 4)
            .ok_or_else(|| failure("short Meta root"))?
            .try_into()
            .unwrap(),
    );
    let vtable = (root as i64)
        .checked_sub(relative as i64)
        .and_then(|n| usize::try_from(n).ok())
        .ok_or_else(|| failure("invalid Meta vtable"))?;
    let field = u16::from_le_bytes(
        raw.get(vtable + 4..vtable + 6)
            .ok_or_else(|| failure("missing Meta version field"))?
            .try_into()
            .unwrap(),
    ) as usize;
    if field == 0 {
        return Err(failure("missing Meta version scalar"));
    }
    let mut out = raw.to_vec();
    out.get_mut(root + field..root + field + 8)
        .ok_or_else(|| failure("Meta version outside record"))?
        .copy_from_slice(&wok_event::WOK_DB_VERSION.to_le_bytes());
    let after = crate::decode_meta(&out)?;
    if after.db_version != wok_event::WOK_DB_VERSION
        || after.endianness != meta.endianness
        || after.negentropy_modification_counter != meta.negentropy_modification_counter
    {
        return Err(failure("Meta-only version normalization failed"));
    }
    Ok(out)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    AfterPending,
    AfterBatch,
    AfterCopy,
    BeforeSeal,
    AfterSeal,
    AfterSentinelRemoval,
}
fn injected(actual: Fault, point: Fault) -> Result<(), DbError> {
    if actual == point {
        Err(failure("injected migration failure"))
    } else {
        Ok(())
    }
}
struct Batches<'a> {
    env: &'a Env,
    txn: Option<RwTxn<'a>>,
    options: &'a LmdbToRocksOptions,
    bytes: usize,
    rows: usize,
    commits: u64,
    fault: Fault,
}
impl<'a> Batches<'a> {
    fn new(env: &'a Env, options: &'a LmdbToRocksOptions, fault: Fault) -> Self {
        Self {
            env,
            txn: None,
            options,
            bytes: 0,
            rows: 0,
            commits: 0,
            fault,
        }
    }
    fn room(&mut self, bytes: usize) -> Result<(), DbError> {
        // Account per-row node/key overhead as well as input bytes so tiny rows
        // cannot build an unbounded overlay. A large record runs alone.
        let charge = bytes
            .checked_add(256)
            .ok_or_else(|| failure("batch byte overflow"))?;
        if self.rows != 0 && self.bytes.saturating_add(charge) > self.options.batch_bytes {
            self.flush()?;
        }
        self.bytes = self
            .bytes
            .checked_add(charge)
            .ok_or_else(|| failure("batch byte overflow"))?;
        self.rows += 1;
        if self.txn.is_none() {
            self.txn = Some(RwTxn::begin(self.env)?);
        }
        Ok(())
    }
    fn put(&mut self, dbi: u32, key: &[u8], value: &[u8]) -> Result<(), DbError> {
        self.room(key.len() + value.len())?;
        if !self.txn.as_mut().unwrap().put(dbi, key, value, 0)? {
            return Err(failure("logical row was not copied"));
        }
        Ok(())
    }
    fn primary(&mut self, key: &[u8], packed: &[u8], payload: &[u8]) -> Result<(), DbError> {
        self.room(
            key.len()
                .saturating_mul(2)
                .saturating_add(packed.len())
                .saturating_add(payload.len()),
        )?;
        let txn = self.txn.as_mut().unwrap();
        txn.put(3, key, packed, 0)?;
        txn.put(15, key, payload, 0)?;
        Ok(())
    }
    fn flush(&mut self) -> Result<(), DbError> {
        if let Some(txn) = self.txn.take() {
            txn.commit()?;
            self.commits += 1;
            self.bytes = 0;
            self.rows = 0;
            injected(self.fault, Fault::AfterBatch)?;
        }
        Ok(())
    }
}

fn new_pending(destination: &Path) -> Result<Env, DbError> {
    // create_dir, never create_dir_all: no reuse of an existing empty directory,
    // broken symlink, previous failure, or previously initialized database.
    fs::DirBuilder::new()
        .mode(0o700)
        .create(destination)
        .map_err(io)?;
    sync_directory(destination.parent().unwrap_or_else(|| Path::new(".")))?;
    mark_incomplete(destination)?;
    let (mut options, descriptors) = crate::env::native_options(true, physical_cf_names());
    options.set_error_if_exists(true);
    let db = DB::open_cf_descriptors(&options, destination, descriptors).map_err(native)?;
    // A crash before this write leaves no accepted marker, also refused by an
    // ordinary open. No callback or caller sees a usable intermediate Env.
    db.put_opt(FORMAT_KEY, PENDING, &synced()).map_err(native)?;
    sync_directory(destination)?;
    Env::from_native_db(db, destination, false)
}
fn pending_readonly(destination: &Path) -> Result<Env, DbError> {
    readonly_marker(destination, PENDING)
}
fn readonly_marker(destination: &Path, marker: &[u8]) -> Result<Env, DbError> {
    crate::env::check_cf_set(destination)?;
    let (mut options, descriptors) = crate::env::native_options(false, physical_cf_names());
    options.set_skip_stats_update_on_db_open(true);
    let db = DB::open_cf_descriptors_read_only(&options, destination, descriptors, false)
        .map_err(native)?;
    if db.get(FORMAT_KEY).map_err(native)?.as_deref() != Some(marker) {
        return Err(failure("pending destination marker mismatch"));
    }
    Env::from_native_db(db, destination, true)
}

fn mark_incomplete(destination: &Path) -> Result<(), DbError> {
    let mut marker = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination.join(INCOMPLETE_MARKER_FILE))
        .map_err(io)?;
    marker.write_all(PENDING).map_err(io)?;
    marker.sync_all().map_err(io)?;
    sync_directory(destination)
}

fn destination_path(source: &Path, destination: &Path) -> Result<PathBuf, DbError> {
    if destination.as_os_str().is_empty() {
        return Err(failure("destination path is empty"));
    }
    let destination = std::path::absolute(destination).map_err(io)?;
    if destination
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(failure(
            "destination path must not contain parent traversal",
        ));
    }
    let parent = destination
        .parent()
        .ok_or_else(|| failure("destination parent missing"))?;
    let canonical = fs::canonicalize(parent).map_err(io)?;
    if canonical != parent {
        return Err(failure(
            "destination parent must be canonical and contain no symlinks",
        ));
    }
    if destination.starts_with(source) || source.starts_with(&destination) {
        return Err(failure("source and destination paths must not overlap"));
    }
    match fs::symlink_metadata(&destination) {
        Ok(_) => return Err(failure("destination already exists")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(io(error)),
    }
    Ok(destination)
}

fn migrate(
    source: &Path,
    destination: &Path,
    options: &LmdbToRocksOptions,
    fault: Fault,
) -> Result<LmdbToRocksReport, DbError> {
    if options.batch_bytes == 0
        || options.batch_bytes > MAX_BATCH_BYTES
        || options.max_record_bytes == 0
        || options.max_record_bytes > MAX_RECORD_BYTES
        || options.max_json_bytes == 0
        || options.max_json_bytes > MAX_JSON_BYTES
    {
        return Err(failure("invalid bounded migration options"));
    }
    let source = lmdb::Source::open(source)?;
    let destination = destination_path(&source.report.source, destination)?;
    let destination = destination.as_path();
    let env = new_pending(destination)?;
    injected(fault, Fault::AfterPending)?;
    let mut original: Vec<_> = crate::dbi_specs()
        .iter()
        .map(|s| Framed::new(s.name))
        .collect();
    let mut expected = original.clone();
    let commits;
    {
        let mut batches = Batches::new(&env, options, fault);
        // Copy Meta first so all later writes see the v5 marker. Raw RwTxn
        // bypasses initialization: no default filters, counters, or rebuilds.
        for dbi in [1u32, 3]
            .into_iter()
            .chain((2..=crate::dbi_specs().len() as u32).filter(|n| !matches!(*n, 3 | 15)))
        {
            // These two scalar keys are mirrored by the ordinary writer. A
            // corrupt source with unbounded duplicate marker values must not
            // turn a bounded migration into a database-sized in-memory mirror.
            let mut seen_markers = [false; 2];
            if let Some(mut cursor) = source.cursor(dbi)? {
                while let Some((key, value)) = cursor.next()? {
                    validate_row(dbi, key, value, options)?;
                    original[dbi as usize - 1].row(key, value)?;
                    if dbi == 3 {
                        let payload = source
                            .get(15, key)?
                            .ok_or_else(|| failure("primary has no payload"))?;
                        validate_row(15, key, payload, options)?;
                        if key
                            .len()
                            .checked_add(value.len())
                            .and_then(|n| n.checked_add(payload.len()))
                            .is_none_or(|n| n > options.max_record_bytes)
                        {
                            return Err(failure(
                                "combined primary exceeds configured record bound",
                            ));
                        }
                        original[14].row(key, payload)?;
                        expected[14].row(key, payload)?;
                        expected[2].row(key, value)?;
                        batches.primary(key, value, payload)?;
                    } else if dbi == 1 && key == 1u64.to_ne_bytes() && source.report.db_version == 4
                    {
                        let normalized = normalize_meta(value)?;
                        expected[0].row(key, &normalized)?;
                        batches.put(dbi, key, &normalized)?;
                    } else {
                        if dbi == 21 && crate::tag_kind::is_tag_kind_marker(key) {
                            let marker = usize::from(key == b"\0through");
                            if std::mem::replace(&mut seen_markers[marker], true) {
                                return Err(failure(
                                    "multiple values for a scalar tag-kind progress marker",
                                ));
                            }
                        }
                        expected[dbi as usize - 1].row(key, value)?;
                        batches.put(dbi, key, value)?;
                    }
                }
            }
            batches.flush()?;
            tracing::info!(
                table = spec(dbi).name,
                records = original[dbi as usize - 1].rows,
                "LMDB -> RocksDB table copied"
            );
        }
        commits = batches.commits;
    }
    // Missing/orphan payloads are never normalized into a valid combined row.
    for (index, hash) in original.iter().enumerate() {
        if hash.rows != source.report.tables[index].records {
            return Err(failure("source table count mismatch or orphan payload"));
        }
    }
    env.check_background_errors()?;
    env.inner.db.flush_wal(true).map_err(native)?;
    drop(env);
    injected(fault, Fault::AfterCopy)?;

    let env = pending_readonly(destination)?;
    let mut tables = Vec::new();
    for dbi in 1..=crate::dbi_specs().len() as u32 {
        let actual = hash_table(&env, dbi, options)?;
        let i = dbi as usize - 1;
        if actual.digest() != expected[i].digest() {
            return Err(failure(&format!(
                "logical bytes differ in {}",
                spec(dbi).name
            )));
        }
        let count = env.begin_ro()?.entries(dbi)? as u64;
        if count != actual.rows {
            return Err(failure("destination transactional count mismatch"));
        }
        tables.push(LmdbTableVerification {
            name: spec(dbi).name.to_owned(),
            source_present: source.report.tables[i].present,
            records: actual.rows,
            key_bytes: actual.key_bytes,
            value_bytes: actual.value_bytes,
            source_sha256: original[i].digest(),
            expected_target_sha256: expected[i].digest(),
            target_sha256: actual.digest(),
        });
        tracing::info!(
            table = spec(dbi).name,
            records = actual.rows,
            "LMDB -> RocksDB table verified"
        );
    }
    let (verified_events, primary_fingerprint_sha256) = verify_primaries(&env, options)?;
    if verified_events != source.report.tables[2].records
        || verified_events != source.report.tables[9].records
    {
        return Err(failure(
            "thin author index is not bijective with primary records",
        ));
    }
    #[cfg(feature = "rocksdb-author-heads")]
    verify_heads(&env)?;
    env.check_background_errors()?;
    drop(env);
    source.check_unchanged()?;
    injected(fault, Fault::BeforeSeal)?;
    seal_verified(&source, destination, fault)?;
    Ok(LmdbToRocksReport {
        source: source.report.clone(),
        destination: destination.to_path_buf(),
        target_layout: String::from_utf8_lossy(FORMAT).into_owned(),
        tables,
        commits,
        verified_events,
        primary_fingerprint_sha256,
        meta_version_normalized: source.report.db_version == 4,
        source_unchanged: true,
        verified: true,
        sealed: true,
    })
}

fn seal_verified(source: &lmdb::Source, destination: &Path, fault: Fault) -> Result<(), DbError> {
    let seal = || {
        // The sentinel remains present throughout sealing and private reopen;
        // ordinary Env::open cannot observe a half-finished sealing operation.
        crate::env::check_cf_set(destination)?;
        let (options, descriptors) = crate::env::native_options(false, physical_cf_names());
        let db = DB::open_cf_descriptors(&options, destination, descriptors).map_err(native)?;
        if db.get(FORMAT_KEY).map_err(native)?.as_deref() != Some(PENDING) {
            return Err(failure("pending marker changed before seal"));
        }
        let mut seal = WriteBatch::default();
        seal.put(FORMAT_KEY, FORMAT);
        db.write_opt(seal, &synced()).map_err(native)?;
        db.flush_wal(true).map_err(native)?;
        drop(db);
        sync_directory(destination)?;
        injected(fault, Fault::AfterSeal)?;
        let env = readonly_marker(destination, FORMAT)?;
        if env.db_version()? != wok_event::WOK_DB_VERSION {
            return Err(failure("sealed Meta version mismatch"));
        }
        env.check_background_errors()?;
        drop(env);
        source.check_unchanged()?;
        fs::remove_file(destination.join(INCOMPLETE_MARKER_FILE)).map_err(io)?;
        injected(fault, Fault::AfterSentinelRemoval)?;
        sync_directory(destination)?;
        sync_directory(destination.parent().unwrap_or_else(|| Path::new(".")))?;
        Ok(())
    };
    if let Err(error) = seal() {
        // Retain the directory and best-effort restore refusal even if failure
        // happened after unlink. If the filesystem cannot restore the marker,
        // report that honestly; publication still requires API success.
        if fs::symlink_metadata(destination.join(INCOMPLETE_MARKER_FILE)).is_err()
            && mark_incomplete(destination).is_err()
        {
            return Err(failure(&format!("{error}; verification completed but incomplete-marker restoration failed; verified copy remains unpublished and must not be promoted")));
        }
        return Err(error);
    }
    Ok(())
}

fn hash_table(env: &Env, dbi: u32, options: &LmdbToRocksOptions) -> Result<Framed, DbError> {
    let cf = env
        .inner
        .db
        .cf_handle(cf_name(dbi))
        .ok_or_else(|| failure("missing logical CF"))?;
    let mut it = env.inner.db.raw_iterator_cf_opt(cf, read_options());
    if reversed(dbi) {
        it.seek_to_last()
    } else {
        it.seek_to_first()
    }
    let mut hash = Framed::new(spec(dbi).name);
    while let Some((key, value)) = it.item() {
        validate_physical_row(key, value, options)?;
        let (key, value) = if matches!(dbi, 3 | 15) {
            let (key, _) = decode(dbi, key, &[])?;
            let (packed, payload) = crate::rocks::parts(value)?;
            let value = if dbi == 3 { packed } else { payload };
            let Some(value) = value else {
                return Err(failure("missing combined primary component"));
            };
            (key, value.to_vec())
        } else {
            decode(dbi, key, value)?
        };
        validate_row(dbi, &key, &value, options)?;
        hash.row(&key, &value)?;
        if reversed(dbi) {
            it.prev()
        } else {
            it.next()
        }
    }
    it.status().map_err(native)?;
    Ok(hash)
}

fn validate_physical_row(
    key: &[u8],
    value: &[u8],
    options: &LmdbToRocksOptions,
) -> Result<(), DbError> {
    // Escaping can double a logical key's bytes; combined primaries also add
    // fixed component framing. Check borrowed native bytes before decode can
    // clone either key or value, including on an unexpectedly damaged target.
    let limit = options
        .max_record_bytes
        .checked_mul(2)
        .and_then(|n| n.checked_add(128))
        .ok_or_else(|| failure("physical record bound overflow"))?;
    if key.len().checked_add(value.len()).is_none_or(|n| n > limit) {
        return Err(failure("physical record exceeds configured byte bound"));
    }
    Ok(())
}

fn verify_primaries(env: &Env, options: &LmdbToRocksOptions) -> Result<(u64, String), DbError> {
    let db = &env.inner.db;
    let primary = db
        .cf_handle(COMBINED)
        .ok_or_else(|| failure("missing combined CF"))?;
    let thin = db
        .cf_handle(cf_name(10))
        .ok_or_else(|| failure("missing thin author CF"))?;
    let dicts = db
        .cf_handle(cf_name(14))
        .ok_or_else(|| failure("missing dictionaries CF"))?;
    let mut it = db.raw_iterator_cf_opt(primary, read_options());
    let point_options = read_options();
    it.seek_to_first();
    let mut count = 0;
    let mut digest = Sha256::new();
    while let Some((key, record)) = it.item() {
        validate_physical_row(key, record, options)?;
        let (local_id, _) = decode(3, key, &[])?;
        let id = u64::from_ne_bytes(
            local_id
                .as_slice()
                .try_into()
                .map_err(|_| failure("malformed primary local ID"))?,
        );
        let (packed, payload) = crate::rocks::parts(record)?;
        let packed = packed.ok_or_else(|| failure("orphan event payload"))?;
        let payload = payload.ok_or_else(|| failure("missing event payload"))?;
        let event = wok_event::PackedEventView::new(packed)?;
        let posting = encode(
            10,
            &crate::keys::make_key_string_u64(event.pubkey(), event.created_at()),
            Some(&local_id),
        );
        if db
            .get_pinned_cf_opt(thin, posting, &point_options)
            .map_err(native)?
            .as_deref()
            != Some(&[])
        {
            return Err(failure("primary has no exact thin author posting"));
        }
        #[cfg(feature = "rocksdb-author-heads")]
        {
            let cf = db
                .cf_handle(crate::rocks::HEAD_CF)
                .ok_or_else(|| failure("missing frontiers CF"))?;
            let head = db
                .get_pinned_cf_opt(cf, event.pubkey(), &point_options)
                .map_err(native)?
                .ok_or_else(|| failure("primary has no author frontier"))?;
            let head = crate::AuthorHead::decode(&head)?;
            let position = crate::AuthorPosition {
                created_at: event.created_at(),
                local_id: id,
            };
            if head.first < position
                || (position != head.first && head.next.is_none_or(|next| next < position))
            {
                return Err(failure(
                    "author frontier is not the exact newest two positions",
                ));
            }
        }
        // Only one dictionary/decompression buffer is retained for the current
        // event; arbitrary dictionary populations cannot grow a decoder cache.
        let decoded;
        let json = match crate::payload::parse_payload(payload)? {
            crate::payload::PayloadView::Raw(raw) => {
                if raw.len() > options.max_json_bytes {
                    return Err(failure("event JSON exceeds configured bound"));
                }
                std::str::from_utf8(raw).map_err(|_| failure("event payload is not UTF8"))?
            }
            crate::payload::PayloadView::Zstd {
                dict_id,
                compressed,
            } => {
                let dict = db
                    .get_pinned_cf_opt(
                        dicts,
                        encode(14, &(dict_id as u64).to_ne_bytes(), None),
                        &point_options,
                    )
                    .map_err(native)?
                    .ok_or_else(|| failure("compressed payload dictionary missing"))?;
                if dict.len() > options.max_record_bytes {
                    return Err(failure("dictionary exceeds configured bound"));
                }
                let dict = crate::decode_compression_dictionary(&dict)?;
                let mut decoder = zstd::bulk::Decompressor::with_dictionary(&dict.dict)
                    .map_err(|_| failure("dictionary decode failed"))?;
                decoded = decoder
                    .decompress(compressed, options.max_json_bytes)
                    .map_err(|_| failure("compressed event decode failed"))?;
                std::str::from_utf8(&decoded)
                    .map_err(|_| failure("decoded event payload is not UTF8"))?
            }
        };
        let parsed = wok_event::json::parse_strict(json)?;
        wok_event::verify_strfry_event(event, &parsed)?;
        digest.update(id.to_be_bytes());
        digest.update((packed.len() as u64).to_be_bytes());
        digest.update(packed);
        digest.update((payload.len() as u64).to_be_bytes());
        digest.update(payload);
        count += 1;
        if count % 100_000 == 0 {
            tracing::info!(
                events = count,
                "LMDB -> RocksDB primary verification progress"
            );
        }
        it.next();
    }
    it.status().map_err(native)?;
    Ok((count, hex(digest.finalize())))
}

#[cfg(feature = "rocksdb-author-heads")]
fn verify_heads(env: &Env) -> Result<(), DbError> {
    let db = &env.inner.db;
    let cf = db
        .cf_handle(crate::rocks::HEAD_CF)
        .ok_or_else(|| failure("missing frontiers CF"))?;
    let primary = db
        .cf_handle(COMBINED)
        .ok_or_else(|| failure("missing combined CF"))?;
    let mut it = db.raw_iterator_cf_opt(cf, read_options());
    let point_options = read_options();
    it.seek_to_first();
    while let Some((author, value)) = it.item() {
        if author.len() != 32 {
            return Err(failure("malformed frontier author"));
        }
        let head = crate::AuthorHead::decode(value)?;
        for position in std::iter::once(head.first).chain(head.next) {
            let record = db
                .get_pinned_cf_opt(
                    primary,
                    encode(3, &position.local_id.to_ne_bytes(), None),
                    &point_options,
                )
                .map_err(native)?
                .ok_or_else(|| failure("frontier primary missing"))?;
            let packed = crate::rocks::parts(&record)?
                .0
                .ok_or_else(|| failure("frontier packed event missing"))?;
            let event = wok_event::PackedEventView::new(packed)?;
            if event.pubkey() != author || event.created_at() != position.created_at {
                return Err(failure("frontier differs from primary"));
            }
        }
        it.next();
    }
    it.status().map_err(native)
}

#[cfg(test)]
#[path = "backend_tests.rs"]
mod tests;
