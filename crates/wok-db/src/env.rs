//! LMDB environment.
//!
//! # Safety
//!
//! All unsafe LMDB FFI is isolated in this module and `txn`. Invariants:
//! - `EnvInner.env` is a valid `MDB_env` until `Drop`.
//! - DBI handles are opened once and remain valid for the env lifetime.
//! - Transactions and cursors never outlive the env.
//! - mmap-backed slices returned by get/cursor are only valid for the
//!   originating transaction's lifetime and must not cross `.await`.

use crate::comparators::{
    lmdb_comparator_string_u64, lmdb_comparator_string_u64_u64, lmdb_comparator_u64_u64,
};
use crate::error::check;
use crate::fbs::{decode_meta, encode_meta, encode_negentropy_filter, Meta};
use crate::schema::{
    dbi_specs, ComparatorKind, DBI_EVENT, DBI_EVENT_SEARCH, DBI_META, DBI_VANISH_PUBKEY,
};
use crate::txn::{RoTxn, RwTxn};
use crate::DbError;
use lmdb_sys::*;
use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct EnvOptions {
    pub max_readers: u32,
    pub map_size: usize,
    pub no_read_ahead: bool,
    pub max_dbs: u32,
    pub create_dir: bool,
    pub create_dbis: bool,
    /// Open the LMDB environment and all transactions without write access.
    pub read_only: bool,
}

impl Default for EnvOptions {
    fn default() -> Self {
        Self {
            max_readers: 256,
            map_size: 10_995_116_277_760,
            no_read_ahead: false,
            max_dbs: 64,
            create_dir: true,
            create_dbis: true,
            read_only: false,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Dbis {
    pub meta: MDB_dbi,
    pub negentropy_filter: MDB_dbi,
    pub event: MDB_dbi,
    pub event_id: MDB_dbi,
    pub event_pubkey_kind: MDB_dbi,
    pub event_tag: MDB_dbi,
    pub event_deletion: MDB_dbi,
    pub event_replace: MDB_dbi,
    pub event_created_at: MDB_dbi,
    pub event_pubkey: MDB_dbi,
    pub event_replace_deletion: MDB_dbi,
    pub event_kind: MDB_dbi,
    pub event_expiration: MDB_dbi,
    pub compression_dictionary: MDB_dbi,
    pub event_payload: MDB_dbi,
    pub negentropy: MDB_dbi,
    /// Absent only while inspecting an unmodified strfry v3 source.
    pub event_search: Option<MDB_dbi>,
    /// Absent only while inspecting an unmodified strfry v3 source.
    pub vanish_pubkey: Option<MDB_dbi>,
}

#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct EnvironmentStats {
    pub map_size: usize,
    pub used_bytes: u64,
    pub page_size: u32,
    pub last_page_number: usize,
    pub entries: usize,
    pub readers: u32,
    pub max_readers: u32,
}

pub struct EnvInner {
    pub env: *mut MDB_env,
    pub dbis: Dbis,
    pub path: PathBuf,
    pub read_only: bool,
}

unsafe impl Send for EnvInner {}
unsafe impl Sync for EnvInner {}

impl Drop for EnvInner {
    fn drop(&mut self) {
        unsafe { mdb_env_close(self.env) }
    }
}

#[derive(Clone)]
pub struct Env {
    pub inner: Arc<EnvInner>,
}

fn meta_version_in_open_txn(txn: *mut MDB_txn, meta_dbi: MDB_dbi) -> Result<u64, DbError> {
    let mut key_bytes = 1u64.to_ne_bytes();
    let mut key = MDB_val {
        mv_size: key_bytes.len(),
        mv_data: key_bytes.as_mut_ptr().cast(),
    };
    let mut value = MDB_val {
        mv_size: 0,
        mv_data: ptr::null_mut(),
    };
    let rc = unsafe { mdb_get(txn, meta_dbi, &mut key, &mut value) };
    if rc == MDB_NOTFOUND {
        return Ok(0);
    }
    check(rc)?;
    let raw = unsafe { std::slice::from_raw_parts(value.mv_data.cast::<u8>(), value.mv_size) };
    Ok(decode_meta(raw)?.db_version)
}

impl Env {
    pub fn open(path: impl AsRef<Path>, opts: EnvOptions) -> Result<Self, DbError> {
        let path = path.as_ref();
        if opts.create_dir {
            std::fs::create_dir_all(path).map_err(|e| DbError::msg(e.to_string()))?;
        }

        let mut env = ptr::null_mut();
        unsafe {
            check(mdb_env_create(&mut env))?;
            check(mdb_env_set_maxdbs(env, opts.max_dbs))?;
            check(mdb_env_set_maxreaders(env, opts.max_readers))?;
            check(mdb_env_set_mapsize(env, opts.map_size))?;
        }

        // MDB_CREATE is a DBI-open flag, not an environment flag. It happens
        // to share its numeric value with MDB_NOMETASYNC, so passing it here
        // would silently weaken LMDB durability.
        let mut flags = 0;
        if opts.no_read_ahead {
            flags |= MDB_NORDAHEAD;
        }
        if opts.read_only {
            flags |= MDB_RDONLY;
        }
        let cpath = CString::new(path.to_string_lossy().as_bytes())
            .map_err(|_| DbError::msg("db path contains NUL"))?;
        let rc = unsafe { mdb_env_open(env, cpath.as_ptr(), flags, 0o664) };
        if rc != 0 {
            unsafe { mdb_env_close(env) };
            return Err(DbError::from_rc(rc));
        }

        // Match the C++ setup: reclaim stale reader slots left by crashed
        // processes, and don't leak the mmap fd into child processes.
        unsafe {
            let mut dead: i32 = 0;
            if !opts.read_only {
                check(mdb_reader_check(env, &mut dead))?;
            }
            let mut fd: libc::c_int = -1;
            let _ = mdb_env_get_fd(env, &mut fd);
            let cur = libc::fcntl(fd, libc::F_GETFD);
            if cur == -1 || libc::fcntl(fd, libc::F_SETFD, cur | libc::FD_CLOEXEC) == -1 {
                let e = std::io::Error::last_os_error();
                mdb_env_close(env);
                return Err(DbError::msg(format!(
                    "unable to enable CLOEXEC on LMDB fd: {e}"
                )));
            }
        }

        // Open all DBIs and install process-local comparators. A read-only
        // transaction is sufficient when the environment is read-only.
        let mut txn = ptr::null_mut();
        let txn_flags = if opts.read_only { MDB_RDONLY } else { 0 };
        if let Err(e) = unsafe { check(mdb_txn_begin(env, ptr::null_mut(), txn_flags, &mut txn)) } {
            unsafe { mdb_env_close(env) };
            return Err(e);
        }

        let mut opened: Vec<MDB_dbi> = Vec::new();
        for spec in dbi_specs() {
            let cname = CString::new(spec.name).unwrap();
            let mut dbi: MDB_dbi = 0;
            let wok_only = matches!(spec.name, DBI_EVENT_SEARCH | DBI_VANISH_PUBKEY);
            let foreign_source = wok_only && !opened.is_empty() && {
                let version = match meta_version_in_open_txn(txn, opened[0]) {
                    Ok(version) => version,
                    Err(error) => {
                        unsafe { mdb_txn_abort(txn) };
                        unsafe { mdb_env_close(env) };
                        return Err(error);
                    }
                };
                version != 0 && version != wok_event::WOK_DB_VERSION
            };
            let dbi_flags = if opts.create_dbis && !foreign_source {
                spec.flags
            } else {
                spec.flags & !MDB_CREATE
            };
            let rc = unsafe { mdb_dbi_open(txn, cname.as_ptr(), dbi_flags, &mut dbi) };
            if rc == MDB_NOTFOUND && wok_only && (!opts.create_dbis || foreign_source) {
                opened.push(0);
                continue;
            }
            if rc != 0 {
                unsafe { mdb_txn_abort(txn) };
                unsafe { mdb_env_close(env) };
                return Err(DbError::from_rc(rc));
            }
            if foreign_source {
                opened.push(0);
                continue;
            }
            let cmp_rc = match spec.comparator {
                ComparatorKind::Default => 0,
                ComparatorKind::StringUint64 => unsafe {
                    mdb_set_compare(txn, dbi, lmdb_comparator_string_u64 as *mut MDB_cmp_func)
                },
                ComparatorKind::Uint64Uint64 => unsafe {
                    mdb_set_compare(txn, dbi, lmdb_comparator_u64_u64 as *mut MDB_cmp_func)
                },
                ComparatorKind::StringUint64Uint64 => unsafe {
                    mdb_set_compare(
                        txn,
                        dbi,
                        lmdb_comparator_string_u64_u64 as *mut MDB_cmp_func,
                    )
                },
            };
            if cmp_rc != 0 {
                unsafe { mdb_txn_abort(txn) };
                unsafe { mdb_env_close(env) };
                return Err(DbError::from_rc(cmp_rc));
            }
            opened.push(dbi);
        }

        let dbis = Dbis {
            meta: opened[0],
            negentropy_filter: opened[1],
            event: opened[2],
            event_id: opened[3],
            event_pubkey_kind: opened[4],
            event_tag: opened[5],
            event_deletion: opened[6],
            event_replace: opened[7],
            event_created_at: opened[8],
            event_pubkey: opened[9],
            event_replace_deletion: opened[10],
            event_kind: opened[11],
            event_expiration: opened[12],
            compression_dictionary: opened[13],
            event_payload: opened[14],
            negentropy: opened[15],
            event_search: (opened[16] != 0).then_some(opened[16]),
            vanish_pubkey: (opened[17] != 0).then_some(opened[17]),
        };

        if let Err(e) = unsafe { check(mdb_txn_commit(txn)) } {
            unsafe { mdb_env_close(env) };
            return Err(e);
        }

        let inner = Arc::new(EnvInner {
            env,
            dbis,
            path: path.to_path_buf(),
            read_only: opts.read_only,
        });
        Ok(Self { inner })
    }

    pub fn path(&self) -> &Path {
        &self.inner.path
    }

    pub fn dbis(&self) -> Dbis {
        self.inner.dbis
    }

    pub fn begin_ro(&self) -> Result<RoTxn<'_>, DbError> {
        RoTxn::begin(self)
    }

    pub fn begin_rw(&self) -> Result<RwTxn<'_>, DbError> {
        if self.inner.read_only {
            return Err(DbError::msg("database environment was opened read-only"));
        }
        let version = self.db_version()?;
        if version != 0 && version != wok_event::WOK_DB_VERSION {
            return Err(DbError::msg(format!(
                "database version {version} is an import source and is read-only; run `wok migrate strfry`"
            )));
        }
        RwTxn::begin(self)
    }

    /// Initialize Meta + default `{}` negentropy filter if the DB is empty.
    pub fn ensure_initialized(&self) -> Result<(), DbError> {
        let mut txn = self.begin_rw()?;
        if txn.get_u64(self.dbis().meta, 1)?.is_none() {
            let meta = Meta {
                db_version: wok_event::CURR_DB_VERSION,
                endianness: 1,
                negentropy_modification_counter: 1,
            };
            txn.put_u64(
                self.dbis().meta,
                1,
                &encode_meta(&meta),
                MDB_NOOVERWRITE | MDB_APPEND,
            )?;
            txn.put_u64(
                self.dbis().negentropy_filter,
                1,
                &encode_negentropy_filter("{}"),
                MDB_NOOVERWRITE | MDB_APPEND,
            )?;
        } else {
            let raw = txn
                .get_u64(self.dbis().meta, 1)?
                .ok_or_else(|| DbError::msg("missing Meta"))?;
            let meta = decode_meta(raw)?;
            if meta.endianness != 1 {
                return Err(DbError::msg(
                    "DB was created on a machine with different endianness",
                ));
            }
            if meta.db_version != wok_event::CURR_DB_VERSION {
                return Err(DbError::msg(format!(
                    "Database version {} (expected {})",
                    meta.db_version,
                    wok_event::CURR_DB_VERSION
                )));
            }
        }
        txn.commit()?;
        crate::search::ensure_search_index(self)?;
        Ok(())
    }

    pub fn db_version(&self) -> Result<u64, DbError> {
        let txn = self.begin_ro()?;
        match txn.get_u64(self.dbis().meta, 1)? {
            None => Ok(0),
            Some(raw) => Ok(decode_meta(raw)?.db_version),
        }
    }

    pub fn db_meta(&self) -> Result<Option<Meta>, DbError> {
        let txn = self.begin_ro()?;
        txn.get_u64(self.dbis().meta, 1)?
            .map(decode_meta)
            .transpose()
    }

    pub fn stats(&self) -> Result<EnvironmentStats, DbError> {
        let mut info: MDB_envinfo = unsafe { std::mem::zeroed() };
        let mut stat: MDB_stat = unsafe { std::mem::zeroed() };
        check(unsafe { mdb_env_info(self.inner.env, &mut info) })?;
        check(unsafe { mdb_env_stat(self.inner.env, &mut stat) })?;
        Ok(EnvironmentStats {
            map_size: info.me_mapsize,
            used_bytes: (info.me_last_pgno as u64 + 1).saturating_mul(stat.ms_psize as u64),
            page_size: stat.ms_psize,
            last_page_number: info.me_last_pgno,
            entries: stat.ms_entries,
            readers: info.me_numreaders,
            max_readers: info.me_maxreaders,
        })
    }

    /// Bytes currently available to an unprivileged writer on the filesystem
    /// containing this LMDB environment.
    pub fn available_disk_bytes(&self) -> Result<u64, DbError> {
        let path = CString::new(self.inner.path.to_string_lossy().as_bytes())
            .map_err(|_| DbError::msg("db path contains NUL"))?;
        let mut stats: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(path.as_ptr(), &mut stats) } != 0 {
            return Err(DbError::msg(std::io::Error::last_os_error().to_string()));
        }
        Ok((stats.f_bavail as u64).saturating_mul(stats.f_frsize as u64))
    }

    pub fn compact_to_fd(&self, fd: i32) -> Result<(), DbError> {
        check(unsafe { mdb_env_copyfd2(self.inner.env, fd, MDB_CP_COMPACT) })
    }

    pub fn compact_to_path(&self, path: &Path) -> Result<(), DbError> {
        if path.exists() {
            return Err(DbError::msg(format!(
                "output file '{}' exists, not overwriting",
                path.display()
            )));
        }
        let cpath = CString::new(path.to_string_lossy().as_bytes())
            .map_err(|_| DbError::msg("path NUL"))?;
        check(unsafe { mdb_env_copy2(self.inner.env, cpath.as_ptr(), MDB_CP_COMPACT) })
    }
}

impl std::fmt::Debug for Env {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Env")
            .field("path", &self.inner.path)
            .finish()
    }
}

// Silence unused import of DBI_EVENT used by docs/integrity.
#[allow(dead_code)]
fn _schema_touch() {
    let _ = DBI_EVENT;
    let _ = DBI_META;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_read_only_environment_supports_reads_and_refuses_writes() {
        let temp = tempfile::tempdir().unwrap();
        let writable = Env::open(temp.path(), EnvOptions::default()).unwrap();
        writable.ensure_initialized().unwrap();
        drop(writable);

        let readonly = Env::open(
            temp.path(),
            EnvOptions {
                create_dir: false,
                create_dbis: false,
                read_only: true,
                ..EnvOptions::default()
            },
        )
        .unwrap();
        assert_eq!(readonly.db_version().unwrap(), wok_event::WOK_DB_VERSION);
        let error = match readonly.begin_rw() {
            Ok(_) => panic!("read-only environment unexpectedly allowed a write transaction"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "database environment was opened read-only"
        );
    }
}
