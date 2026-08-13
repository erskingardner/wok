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
use crate::schema::{dbi_specs, ComparatorKind, DBI_EVENT, DBI_META};
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
            check(mdb_reader_check(env, &mut dead))?;
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

        // Open all DBIs and install comparators in a write txn.
        let mut txn = ptr::null_mut();
        if let Err(e) = unsafe { check(mdb_txn_begin(env, ptr::null_mut(), 0, &mut txn)) } {
            unsafe { mdb_env_close(env) };
            return Err(e);
        }

        let mut opened: Vec<MDB_dbi> = Vec::new();
        for spec in dbi_specs() {
            let cname = CString::new(spec.name).unwrap();
            let mut dbi: MDB_dbi = 0;
            let dbi_flags = if opts.create_dbis {
                spec.flags
            } else {
                spec.flags & !MDB_CREATE
            };
            let rc = unsafe { mdb_dbi_open(txn, cname.as_ptr(), dbi_flags, &mut dbi) };
            if rc != 0 {
                unsafe { mdb_txn_abort(txn) };
                unsafe { mdb_env_close(env) };
                return Err(DbError::from_rc(rc));
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
        };

        if let Err(e) = unsafe { check(mdb_txn_commit(txn)) } {
            unsafe { mdb_env_close(env) };
            return Err(e);
        }

        let inner = Arc::new(EnvInner {
            env,
            dbis,
            path: path.to_path_buf(),
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
