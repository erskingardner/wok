//! Read-only snapshot and verification helpers for strfry migration.

#![allow(unsafe_code)]

use crate::{foreach_event_from, DbError, Env, EnvOptions};
use lmdb_sys::{
    mdb_env_close, mdb_env_copy2, mdb_env_create, mdb_env_open, MDB_CP_COMPACT, MDB_NORDAHEAD,
    MDB_RDONLY,
};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::path::Path;
use std::ptr;

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
    let txn = env.begin_ro()?;
    let mut hasher = Sha256::new();
    let mut count = 0u64;
    let mut error = None;
    foreach_event_from(&txn, 0, |lev_id, packed| {
        match txn.get_u64(env.dbis().event_payload, lev_id) {
            Ok(Some(payload)) => {
                hasher.update(lev_id.to_be_bytes());
                hasher.update((packed.len() as u64).to_be_bytes());
                hasher.update(packed);
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
    Ok(EventFingerprint {
        count,
        sha256: hasher.finalize().into(),
    })
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
