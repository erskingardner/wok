//! Registered, read-only LMDB access for the offline backend migration.
//!
//! This is a separate FFI boundary because a RocksDB build's `Env` is RocksDB.
//! The owner is deliberately !Send/!Sync; every mmap slice is bounded by its
//! transaction/cursor borrow. No source write transaction or DBI creation is
//! performed. LMDB may update lock.mdb to register/release the reader slot.
#![allow(unsafe_code)]

use super::{LmdbSourceReport, LmdbTableInfo, SourceKind};
use crate::comparators::{
    lmdb_comparator_string_u64, lmdb_comparator_string_u64_u64, lmdb_comparator_u64_u64,
};
use crate::error::check;
use crate::schema::{dbi_specs, ComparatorKind};
use crate::{decode_meta, DbError};
use lmdb_sys::*;
use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs::{File, Metadata};
use std::marker::PhantomData;
use std::os::fd::BorrowedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::rc::Rc;

type Row<'a> = (&'a [u8], &'a [u8]);

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
    bytes: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}
impl FileIdentity {
    fn read(path: &Path) -> Result<Self, DbError> {
        let m = std::fs::symlink_metadata(path).map_err(|e| DbError::msg(e.to_string()))?;
        if !m.is_file() {
            return Err(DbError::msg("LMDB source data.mdb must be a regular file"));
        }
        Ok(Self::from_metadata(&m))
    }
    fn from_metadata(m: &Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            bytes: m.len(),
            mtime: (m.mtime(), m.mtime_nsec()),
            ctime: (m.ctime(), m.ctime_nsec()),
        }
    }
    fn opened(env: *mut MDB_env) -> Result<Self, DbError> {
        let mut fd = -1;
        // SAFETY: callers own a live LMDB environment. BorrowedFd neither
        // takes ownership nor closes LMDB's fd; the clone has its own lifetime.
        check(unsafe { mdb_env_get_fd(env, &mut fd) })?;
        let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
        let copy = borrowed
            .try_clone_to_owned()
            .map_err(|e| DbError::msg(e.to_string()))?;
        let metadata = File::from(copy)
            .metadata()
            .map_err(|e| DbError::msg(e.to_string()))?;
        Ok(Self::from_metadata(&metadata))
    }
}

pub(super) struct Source {
    // Drop aborts txn before closing env, after every borrowing cursor is gone.
    txn: *mut MDB_txn,
    env: *mut MDB_env,
    dbis: Vec<Option<MDB_dbi>>,
    path: PathBuf,
    before: FileIdentity,
    pub report: LmdbSourceReport,
    _not_send_sync: PhantomData<Rc<()>>,
}
impl Drop for Source {
    fn drop(&mut self) {
        // SAFETY: these handles are created once below and never transferred;
        // Rust borrows ensure cursors/slices are no longer in use at this point.
        unsafe {
            if !self.txn.is_null() {
                mdb_txn_abort(self.txn);
            }
            if !self.env.is_null() {
                mdb_env_close(self.env);
            }
        }
    }
}
impl Source {
    pub fn open(path: &Path) -> Result<Self, DbError> {
        Self::open_kind(path, SourceKind::Wok)
    }
    pub fn open_kind(path: &Path, kind: SourceKind) -> Result<Self, DbError> {
        if !cfg!(target_endian = "little") || std::mem::size_of::<usize>() != 8 {
            return Err(DbError::msg(
                "LMDB migration requires a 64-bit little-endian host",
            ));
        }
        let path = std::fs::canonicalize(path).map_err(|e| DbError::msg(e.to_string()))?;
        if !path.is_dir() || path.join("CURRENT").exists() {
            return Err(DbError::msg(
                "source must be an LMDB directory, not RocksDB",
            ));
        }
        let before = FileIdentity::read(&path.join("data.mdb"))?;
        let cpath = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| DbError::msg("LMDB source path contains NUL"))?;
        let mut source = Self {
            txn: ptr::null_mut(),
            env: ptr::null_mut(),
            dbis: Vec::new(),
            path,
            before,
            report: LmdbSourceReport::default(),
            _not_send_sync: PhantomData,
        };
        // SAFETY: out-pointers belong to the source owner; errors drop whatever
        // handles were initialized. Read-only open validates LMDB's file header.
        unsafe {
            check(mdb_env_create(&mut source.env))?;
            check(mdb_env_set_maxdbs(source.env, 64))?;
            check(mdb_env_open(
                source.env,
                cpath.as_ptr(),
                MDB_RDONLY | MDB_NOTLS | MDB_NORDAHEAD,
                0o640,
            ))?;
            if FileIdentity::opened(source.env)? != source.before {
                return Err(DbError::msg(
                    "LMDB source path changed while opening data.mdb",
                ));
            }
            let mut fd = -1;
            check(mdb_env_get_fd(source.env, &mut fd))?;
            let flags = libc::fcntl(fd, libc::F_GETFD);
            if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) < 0 {
                return Err(DbError::msg(
                    "could not mark migration source fd close-on-exec",
                ));
            }
            check(mdb_txn_begin(
                source.env,
                ptr::null_mut(),
                MDB_RDONLY,
                &mut source.txn,
            ))?;
        }
        source.open_tables()?;
        let raw = source
            .get(1, &1u64.to_ne_bytes())?
            .ok_or_else(|| DbError::msg("LMDB source has no Meta record"))?;
        let meta = decode_meta(raw)?;
        match kind {
            SourceKind::Wok if !matches!(meta.db_version, 4 | 5) => {
                return Err(DbError::msg(format!(
                    "unsupported Wok LMDB version {} (expected 4 or 5; use `wok migrate strfry` for v3)",
                    meta.db_version
                )));
            }
            SourceKind::Strfry if meta.db_version != wok_event::STRFRY_DB_VERSION => {
                return Err(DbError::msg(format!(
                    "unsupported strfry LMDB version {} (expected 3)",
                    meta.db_version
                )));
            }
            _ => {}
        }
        if kind == SourceKind::Strfry && source.report.tables[16..].iter().any(|t| t.present) {
            return Err(DbError::msg(
                "strfry v3 source contains Wok-owned tables; refusing mixed ownership",
            ));
        }
        if meta.endianness != 1 {
            return Err(DbError::msg(
                "LMDB source endianness does not match this host",
            ));
        }
        if meta.db_version == 5 && source.dbis[19].is_none() {
            return Err(DbError::msg(
                "v5 LMDB source has no wok_State table; allocation history cannot be reconstructed",
            ));
        }
        source.validate_scalar_state()?;
        source.report.db_version = meta.db_version;
        source.report.target_db_version = wok_event::WOK_DB_VERSION;
        // SAFETY: the transaction remains alive in source.
        source.report.transaction_id = unsafe { mdb_txn_id(source.txn) } as u64;
        source.report.data_file_bytes = source.before.bytes;
        source.report.source = source.path.clone();
        source.check_unchanged()?;
        Ok(source)
    }

    fn validate_scalar_state(&self) -> Result<(), DbError> {
        let keys = [
            crate::state::HIGH_WATER,
            crate::state::POLICY_GENERATION,
            crate::state::VANISH_MARKER_CHANGES,
            crate::state::SUPERSEDED_EVENTS,
            crate::state::LEGACY_SUPERSEDED_EVENTS,
        ];
        for key in keys {
            if let Some(raw) = self.get(20, key)? {
                let value = crate::state::decode(raw)
                    .map_err(|_| DbError::msg("invalid known scalar in source wok_State"))?;
                if key == crate::state::HIGH_WATER {
                    let mut cursor = self.cursor(3)?.expect("required event DBI");
                    let largest = cursor
                        .last()?
                        .map(|(key, _)| crate::comparators::u64_from_ne_checked(key))
                        .transpose()?
                        .unwrap_or(0);
                    if value < largest {
                        return Err(DbError::msg(
                            "source allocation high-water is below its greatest surviving local ID",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    fn open_tables(&mut self) -> Result<(), DbError> {
        // Every unnamed-main row must name a known DBI. Otherwise copying only
        // named Wok tables would silently discard application state.
        let mut main = 0;
        // SAFETY: source owns a live read-only txn; null name denotes main DBI.
        check(unsafe { mdb_dbi_open(self.txn, ptr::null(), 0, &mut main) })?;
        let mut names = BTreeSet::new();
        {
            let mut cursor = Cursor::open(self, main)?;
            while let Some((name, _)) = cursor.next()? {
                let name = std::str::from_utf8(name)
                    .map_err(|_| DbError::msg("unknown non-UTF8 main LMDB record"))?;
                if !dbi_specs().iter().any(|spec| spec.name == name) {
                    return Err(DbError::msg(format!(
                        "unknown LMDB table/main record: {name}"
                    )));
                }
                names.insert(name.to_owned());
            }
        }
        for (index, spec) in dbi_specs().iter().enumerate() {
            let present = names.contains(spec.name);
            // The original 16 tables are mandatory. Wok-owned tables were
            // added lazily; absent ones have the same empty/lazy semantics in
            // the destination, without inventing any progress or policy state.
            if !present && index < 16 {
                return Err(DbError::msg(format!(
                    "required LMDB table missing: {}",
                    spec.name
                )));
            }
            let mut flags = spec.flags & !MDB_CREATE;
            let mut records = 0;
            let dbi = if present {
                let name = CString::new(spec.name).unwrap();
                let mut dbi = 0;
                // SAFETY: existing names only, no MDB_CREATE. Comparator
                // callbacks are process-local and do not modify database pages.
                unsafe {
                    check(mdb_dbi_open(self.txn, name.as_ptr(), 0, &mut dbi))?;
                    check(mdb_dbi_flags(self.txn, dbi, &mut flags))?;
                    if flags != spec.flags & !MDB_CREATE {
                        return Err(DbError::msg(format!(
                            "LMDB table flags mismatch: {}",
                            spec.name
                        )));
                    }
                    let comparator = match spec.comparator {
                        ComparatorKind::Default => None,
                        ComparatorKind::StringUint64 => {
                            Some(lmdb_comparator_string_u64 as *mut MDB_cmp_func)
                        }
                        ComparatorKind::Uint64Uint64 => {
                            Some(lmdb_comparator_u64_u64 as *mut MDB_cmp_func)
                        }
                        ComparatorKind::StringUint64Uint64 => {
                            Some(lmdb_comparator_string_u64_u64 as *mut MDB_cmp_func)
                        }
                    };
                    if let Some(comparator) = comparator {
                        check(mdb_set_compare(self.txn, dbi, comparator))?;
                    }
                    let mut stat = std::mem::zeroed();
                    check(mdb_stat(self.txn, dbi, &mut stat))?;
                    records = stat.ms_entries as u64;
                }
                Some(dbi)
            } else {
                None
            };
            self.dbis.push(dbi);
            self.report.logical_records = self
                .report
                .logical_records
                .checked_add(records)
                .ok_or_else(|| DbError::msg("LMDB record count overflow"))?;
            self.report.tables.push(LmdbTableInfo {
                name: spec.name.to_owned(),
                present,
                flags,
                records,
            });
        }
        Ok(())
    }

    pub fn cursor(&self, logical: u32) -> Result<Option<Cursor<'_>>, DbError> {
        self.dbis[logical as usize - 1]
            .map(|dbi| Cursor::open(self, dbi))
            .transpose()
    }
    pub fn get(&self, logical: u32, key: &[u8]) -> Result<Option<&[u8]>, DbError> {
        let Some(dbi) = self.dbis[logical as usize - 1] else {
            return Ok(None);
        };
        let mut key = val(key);
        let mut value = val(&[]);
        // SAFETY: buffers/txn live across this call; returned mmap data is
        // borrowed from self, which owns and aborts the transaction on drop.
        let rc = unsafe { mdb_get(self.txn, dbi, &mut key, &mut value) };
        if rc == MDB_NOTFOUND {
            return Ok(None);
        }
        check(rc)?;
        // SAFETY: successful mdb_get returned an MDB_val valid for this txn.
        Ok(Some(unsafe { slice(&value) }))
    }
    pub fn stats(&self) -> Result<crate::EnvironmentStats, DbError> {
        // SAFETY: source owns this environment; LMDB fills both POD structs.
        unsafe {
            let mut info = std::mem::zeroed();
            let mut stat = std::mem::zeroed();
            check(mdb_env_info(self.env, &mut info))?;
            check(mdb_env_stat(self.env, &mut stat))?;
            Ok(crate::EnvironmentStats {
                map_size: info.me_mapsize,
                used_bytes: (info.me_last_pgno as u64 + 1) * stat.ms_psize as u64,
                page_size: stat.ms_psize,
                last_page_number: info.me_last_pgno,
                entries: self.report.logical_records as usize,
                readers: info.me_numreaders,
                max_readers: info.me_maxreaders,
            })
        }
    }
    pub fn contains(&self, logical: u32, key: &[u8], value: &[u8]) -> Result<bool, DbError> {
        let Some(dbi) = self.dbis[logical as usize - 1] else {
            return Ok(false);
        };
        let cursor = Cursor::open(self, dbi)?;
        let (mut key, mut value) = (val(key), val(value));
        // SAFETY: the transaction and input buffers remain live for the call.
        let rc = unsafe { mdb_cursor_get(cursor.cursor, &mut key, &mut value, MDB_GET_BOTH) };
        if rc == MDB_NOTFOUND {
            return Ok(false);
        }
        check(rc)?;
        Ok(true)
    }
    pub fn check_unchanged(&self) -> Result<(), DbError> {
        if FileIdentity::read(&self.path.join("data.mdb"))? != self.before
            || FileIdentity::opened(self.env)? != self.before
        {
            return Err(DbError::msg(
                "LMDB source data.mdb changed during migration; stop all writers",
            ));
        }
        let mut info = std::mem::MaybeUninit::<MDB_envinfo>::uninit();
        // SAFETY: live env, fully initialized by successful mdb_env_info.
        check(unsafe { mdb_env_info(self.env, info.as_mut_ptr()) })?;
        let info = unsafe { info.assume_init() };
        // Also consult a new registered snapshot, rather than relying only on
        // file timestamps or the original transaction's frozen identifier.
        let mut latest = ptr::null_mut();
        check(unsafe { mdb_txn_begin(self.env, ptr::null_mut(), MDB_RDONLY, &mut latest) })?;
        let latest_id = unsafe { mdb_txn_id(latest) } as u64;
        unsafe { mdb_txn_abort(latest) };
        let fixed_id = unsafe { mdb_txn_id(self.txn) } as u64;
        if info.me_last_txnid as u64 != fixed_id || latest_id != fixed_id {
            return Err(DbError::msg(
                "LMDB source transaction changed during migration; stop all writers",
            ));
        }
        if FileIdentity::read(&self.path.join("data.mdb"))? != self.before
            || FileIdentity::opened(self.env)? != self.before
        {
            return Err(DbError::msg(
                "LMDB source data.mdb changed during the final identity check",
            ));
        }
        Ok(())
    }
}

fn val(raw: &[u8]) -> MDB_val {
    MDB_val {
        mv_size: raw.len(),
        mv_data: raw.as_ptr().cast_mut().cast(),
    }
}
// SAFETY: callers only use successful LMDB result values from a live txn.
unsafe fn slice<'a>(value: &MDB_val) -> &'a [u8] {
    if value.mv_size == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(value.mv_data.cast(), value.mv_size) }
    }
}
pub(super) struct Cursor<'txn> {
    cursor: *mut MDB_cursor,
    started: bool,
    source: PhantomData<&'txn Source>,
}
impl Cursor<'_> {
    fn open(source: &Source, dbi: MDB_dbi) -> Result<Cursor<'_>, DbError> {
        let mut cursor = ptr::null_mut();
        // SAFETY: live txn; owner lifetime is carried by the returned cursor.
        check(unsafe { mdb_cursor_open(source.txn, dbi, &mut cursor) })?;
        Ok(Cursor {
            cursor,
            started: false,
            source: PhantomData,
        })
    }
    pub fn next(&mut self) -> Result<Option<Row<'_>>, DbError> {
        let op = if self.started { MDB_NEXT } else { MDB_FIRST };
        self.started = true;
        self.get(op)
    }
    fn last(&mut self) -> Result<Option<Row<'_>>, DbError> {
        self.started = true;
        self.get(MDB_LAST)
    }
    fn get(&mut self, op: MDB_cursor_op) -> Result<Option<Row<'_>>, DbError> {
        let (mut key, mut value) = (val(&[]), val(&[]));
        // SAFETY: live cursor, mmap results remain borrowed until next use.
        let rc = unsafe { mdb_cursor_get(self.cursor, &mut key, &mut value, op) };
        if rc == MDB_NOTFOUND {
            return Ok(None);
        }
        check(rc)?;
        Ok(Some(unsafe { (slice(&key), slice(&value)) }))
    }
}
impl Drop for Cursor<'_> {
    fn drop(&mut self) {
        // SAFETY: cursor is uniquely owned and its transaction is still alive.
        unsafe { mdb_cursor_close(self.cursor) }
    }
}

#[cfg(test)]
pub(super) mod fixture {
    use super::*;
    /// Synthetic native LMDB writer; never exported in a production build.
    pub struct Writer {
        env: *mut MDB_env,
        txn: *mut MDB_txn,
        pub dbis: Vec<MDB_dbi>,
    }
    impl Writer {
        pub fn new(path: &Path, missing_optional: bool) -> Self {
            Self::with_flags(path, missing_optional, None)
        }
        pub fn wrong_integer_flags(path: &Path) -> Self {
            Self::with_flags(path, false, Some(1))
        }
        fn with_flags(path: &Path, missing_optional: bool, wrong_index: Option<usize>) -> Self {
            std::fs::create_dir_all(path).unwrap();
            let mut out = Self {
                env: ptr::null_mut(),
                txn: ptr::null_mut(),
                dbis: Vec::new(),
            };
            let path = CString::new(path.as_os_str().as_bytes()).unwrap();
            unsafe {
                check(mdb_env_create(&mut out.env)).unwrap();
                check(mdb_env_set_maxdbs(out.env, 64)).unwrap();
                check(mdb_env_set_mapsize(out.env, 256 << 20)).unwrap();
                check(mdb_env_open(out.env, path.as_ptr(), 0, 0o640)).unwrap();
                check(mdb_txn_begin(out.env, ptr::null_mut(), 0, &mut out.txn)).unwrap();
                for (i, spec) in dbi_specs().iter().enumerate() {
                    if missing_optional && i >= 16 {
                        break;
                    }
                    let name = CString::new(spec.name).unwrap();
                    let mut dbi = 0;
                    let flags = if wrong_index == Some(i) {
                        spec.flags & !MDB_INTEGERKEY
                    } else {
                        spec.flags
                    };
                    check(mdb_dbi_open(out.txn, name.as_ptr(), flags, &mut dbi)).unwrap();
                    let comparator = match spec.comparator {
                        ComparatorKind::Default => None,
                        ComparatorKind::StringUint64 => {
                            Some(lmdb_comparator_string_u64 as *mut MDB_cmp_func)
                        }
                        ComparatorKind::Uint64Uint64 => {
                            Some(lmdb_comparator_u64_u64 as *mut MDB_cmp_func)
                        }
                        ComparatorKind::StringUint64Uint64 => {
                            Some(lmdb_comparator_string_u64_u64 as *mut MDB_cmp_func)
                        }
                    };
                    if let Some(cmp) = comparator {
                        check(mdb_set_compare(out.txn, dbi, cmp)).unwrap();
                    }
                    out.dbis.push(dbi);
                }
            }
            out
        }
        pub fn put(&self, logical: u32, key: &[u8], value: &[u8]) {
            let (mut key, mut value) = (val(key), val(value));
            check(unsafe {
                mdb_put(
                    self.txn,
                    self.dbis[logical as usize - 1],
                    &mut key,
                    &mut value,
                    0,
                )
            })
            .unwrap();
        }
        pub fn unknown(&self) {
            let mut dbi = 0;
            check(unsafe {
                mdb_dbi_open(
                    self.txn,
                    c"unknown-application-state".as_ptr(),
                    MDB_CREATE,
                    &mut dbi,
                )
            })
            .unwrap();
        }
        pub fn commit(mut self) {
            // LMDB consumes the handle on success AND failure. Null it before
            // checking so an error cannot double-abort during unwinding.
            let txn = std::mem::replace(&mut self.txn, ptr::null_mut());
            check(unsafe { mdb_txn_commit(txn) }).unwrap();
        }
    }
    impl Drop for Writer {
        fn drop(&mut self) {
            unsafe {
                if !self.txn.is_null() {
                    mdb_txn_abort(self.txn)
                }
                if !self.env.is_null() {
                    mdb_env_close(self.env)
                }
            }
        }
    }
}
