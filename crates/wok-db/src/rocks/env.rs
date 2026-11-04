//! RocksDB environment for the opt-in experimental relay binary.
#![forbid(unsafe_code)]
use crate::fbs::{decode_meta, encode_meta, encode_negentropy_filter, Meta};
use crate::rocks::*;
use crate::txn::{RoTxn, RwTxn};
use crate::{dbi_specs, DbError};
use lmdb_sys::*;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
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

impl EnvOptions {
    /// Defaults with a 1 GiB map for tests and fixtures.
    ///
    /// Each open env reserves `map_size` of virtual address space, so many
    /// concurrently running tests at the 10 TiB production default exhaust it
    /// and fail with `ENOMEM`. Not for production databases.
    pub fn for_tests() -> Self {
        Self {
            map_size: 1 << 30,
            ..Self::default()
        }
    }
}

/// Permission bits for the database files Wok creates: LMDB's `data.mdb` and
/// `lock.mdb`, and compact copies. Stored events include gift wraps and other
/// recipient-only kinds, so users outside the file's group get no access; the
/// group keeps read, and the umask can only remove more. A file that already
/// exists keeps its mode.
pub(crate) const DB_FILE_MODE: u32 = 0o640;

/// Create a new file for a compact copy with [`DB_FILE_MODE`]. LMDB's
/// `mdb_env_copy2` would create it with mode `0666`.
pub(crate) fn create_copy_file(path: &Path) -> Result<std::fs::File, DbError> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(DB_FILE_MODE)
        .open(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                DbError::msg(format!(
                    "output file '{}' exists, not overwriting",
                    path.display()
                ))
            } else {
                DbError::msg(format!("create '{}': {e}", path.display()))
            }
        })
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
    /// Absent only while inspecting an unmodified strfry v3 source.
    pub moderation: Option<MDB_dbi>,
    pub state: Option<MDB_dbi>,
    /// Absent while inspecting an unmodified strfry v3 source, or read-only
    /// before the first writable open by a release that has it.
    pub event_tag_kind: Option<MDB_dbi>,
    /// Absent where `event_tag_kind` is.
    pub event_tag_kind_build: Option<MDB_dbi>,
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
    pub db: rocksdb::DB,
    pub dbis: Dbis,
    pub path: PathBuf,
    pub read_only: bool,
    pub writer: Mutex<()>,
    /// Published only after its synchronous WriteBatch completes. The sequence
    /// couples these tiny immutable metadata values to every read snapshot.
    pub(crate) marker_state: Mutex<Option<MarkerState>>,
}
#[derive(Clone)]
pub struct Env {
    pub inner: Arc<EnvInner>,
}
pub fn lmdb_version() -> (i32, i32, i32) {
    (0, 9, 37)
}
impl std::fmt::Debug for Env {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RocksEnv")
            .field("path", &self.path())
            .finish()
    }
}
impl Env {
    pub fn open(path: impl AsRef<Path>, opts: EnvOptions) -> Result<Self, DbError> {
        use rocksdb::{
            BlockBasedOptions, Cache, ColumnFamilyDescriptor, DBCompressionType,
            DataBlockIndexType, Options,
        };
        let path = path.as_ref();
        if path.join("data.mdb").exists() || path.join("lock.mdb").exists() {
            return Err(err(
                "refusing LMDB directory; RocksDB requires a separate new database",
            ));
        }
        if !path.exists() && opts.create_dir {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(path)
                .map_err(err)?;
        }
        let fresh = !path.join("CURRENT").exists();
        if fresh && (!opts.create_dbis || opts.read_only) {
            return Err(err("database does not exist"));
        }
        if fresh && std::fs::read_dir(path).map_err(err)?.next().is_some() {
            return Err(err("refusing nonempty unrecognized database directory"));
        }
        let cache = Cache::new_hyper_clock_cache(8usize << 30, 0);
        let cfopts = || {
            let mut o = Options::default();
            let mut t = BlockBasedOptions::default();
            t.set_block_cache(&cache);
            t.set_bloom_filter(10.0, false);
            t.set_cache_index_and_filter_blocks(true);
            t.set_pin_l0_filter_and_index_blocks_in_cache(true);
            t.set_block_size(4 << 10);
            t.set_data_block_index_type(DataBlockIndexType::BinaryAndHash);
            t.set_data_block_hash_ratio(0.75);
            o.set_block_based_table_factory(&t);
            o.set_write_buffer_size(64 << 20);
            o.set_max_write_buffer_number(4);
            o.set_level_compaction_dynamic_level_bytes(true);
            o.set_compression_type(DBCompressionType::Lz4);
            o.set_bottommost_compression_type(DBCompressionType::Lz4);
            o
        };
        let mut options = cfopts();
        options.create_if_missing(fresh);
        options.create_missing_column_families(fresh);
        options.set_max_background_jobs(8);
        options.set_max_subcompactions(4);
        options.set_db_write_buffer_size(2 << 30);
        options.set_max_total_wal_size(1 << 30);
        options.set_bytes_per_sync(1 << 20);
        options.set_row_cache(&Cache::new_lru_cache(2 << 30));
        let mut names = vec!["default", COMBINED, COVERING];
        names.extend(
            dbi_specs()
                .iter()
                .filter(|s| {
                    s.name != crate::schema::DBI_EVENT && s.name != crate::schema::DBI_EVENT_PAYLOAD
                })
                .map(|s| s.name),
        );
        let cfs = names
            .into_iter()
            .map(|n| ColumnFamilyDescriptor::new(n, cfopts()))
            .collect::<Vec<_>>();
        let db = if opts.read_only {
            rocksdb::DB::open_cf_descriptors_read_only(&options, path, cfs, false)
        } else {
            rocksdb::DB::open_cf_descriptors(&options, path, cfs)
        }
        .map_err(err)?;
        match db.get(FORMAT_KEY).map_err(err)? {
            Some(v) if v == FORMAT => {}
            None if fresh => {
                let mut wo = rocksdb::WriteOptions::default();
                wo.set_sync(true);
                db.put_opt(FORMAT_KEY, FORMAT, &wo).map_err(err)?;
            }
            _ => return Err(err("unsupported or absent Wok RocksDB layout marker")),
        }
        let dbis = Dbis {
            meta: 1,
            negentropy_filter: 2,
            event: 3,
            event_id: 4,
            event_pubkey_kind: 5,
            event_tag: 6,
            event_deletion: 7,
            event_replace: 8,
            event_created_at: 9,
            event_pubkey: 10,
            event_replace_deletion: 11,
            event_kind: 12,
            event_expiration: 13,
            compression_dictionary: 14,
            event_payload: 15,
            negentropy: 16,
            event_search: Some(17),
            vanish_pubkey: Some(18),
            moderation: Some(19),
            state: Some(20),
            event_tag_kind: Some(21),
            event_tag_kind_build: Some(22),
        };
        let markers = Arc::new(load_markers(&db)?);
        let marker_sequence = db.latest_sequence_number();
        Ok(Self {
            inner: Arc::new(EnvInner {
                marker_state: Mutex::new(Some((marker_sequence, markers))),
                db,
                dbis,
                path: path.to_path_buf(),
                read_only: opts.read_only,
                writer: Mutex::new(()),
            }),
        })
    }
    #[cfg(test)]
    pub(crate) fn into_test_fixture_without_state(self, version: u64) {
        let mut txn = self.begin_rw().unwrap();
        let mut meta = decode_meta(txn.get_u64(self.dbis().meta, 1).unwrap().unwrap()).unwrap();
        meta.db_version = version;
        txn.put_u64(self.dbis().meta, 1, &encode_meta(&meta), 0)
            .unwrap();
        txn.clear(self.dbis().state.unwrap()).unwrap();
        txn.commit().unwrap();
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
            return Err(err("database environment was opened read-only"));
        }
        let version = self.db_version()?;
        if version != 0 && version != wok_event::WOK_DB_VERSION {
            return Err(err("database version is read-only; migration required"));
        }
        RwTxn::begin(self)
    }
    pub fn covering_pubkey_dbi(&self) -> MDB_dbi {
        COVER_DBI
    }
    pub fn check_background_errors(&self) -> Result<(), DbError> {
        for name in std::iter::once("default")
            .chain(dbi_specs().iter().map(|s| {
                cf_name((dbi_specs().iter().position(|v| v.name == s.name).unwrap() + 1) as u32)
            }))
            .chain([COVERING])
        {
            let cf = self
                .inner
                .db
                .cf_handle(name)
                .ok_or_else(|| err("missing column family"))?;
            if self
                .inner
                .db
                .property_int_value_cf(cf, "rocksdb.background-errors")
                .map_err(err)?
                .unwrap_or(0)
                != 0
            {
                return Err(err(format!("background errors in {name}")));
            }
        }
        Ok(())
    }
    pub fn stats(&self) -> Result<EnvironmentStats, DbError> {
        self.check_background_errors()?;
        let used = std::fs::read_dir(self.path())
            .map_err(err)?
            .filter_map(Result::ok)
            .filter_map(|f| f.metadata().ok())
            .map(|m| m.len())
            .sum();
        Ok(EnvironmentStats {
            map_size: 0,
            used_bytes: used,
            page_size: 0,
            last_page_number: 0,
            entries: self.begin_ro()?.entries(self.dbis().event)?,
            readers: 0,
            max_readers: 0,
        })
    }
    pub fn available_disk_bytes(&self) -> Result<u64, DbError> {
        fs2::available_space(self.path()).map_err(err)
    }
    // RocksDB's exclusive process lock rejects a competing writer at open.
    pub fn open_in_another_process(&self) -> Result<bool, DbError> {
        Ok(false)
    }
    pub fn compact_to_fd(&self, _fd: i32) -> Result<(), DbError> {
        Err(err(
            "RocksDB checkpoints are directories; stream compaction is unsupported",
        ))
    }
    pub fn compact_to_path(&self, _path: &Path) -> Result<(), DbError> {
        Err(err(
            "use a closed RocksDB directory copy; LMDB compact-file output is unsupported",
        ))
    }
    #[cfg(feature = "op-log")]
    pub fn set_no_meta_sync(&self, _on: bool) -> Result<(), DbError> {
        Err(err("LMDB durability flag is unavailable on RocksDB"))
    }
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
        crate::state::discard_legacy_superseded_events(&mut txn)?;
        crate::state::superseded_events(&mut txn)?;
        crate::tag_kind::ensure_tag_kind_index(&mut txn)?;
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
}

impl Drop for EnvInner {
    fn drop(&mut self) {
        // Observe, never force flush/compaction. This happens after relay threads
        // join and before RocksDB's own destructor; final child rusage captures
        // subsequent shutdown I/O as well.
        let mut cf_stats = serde_json::Map::new();
        let mut names = vec!["default", COMBINED, COVERING];
        names.extend(
            dbi_specs()
                .iter()
                .filter(|s| {
                    s.name != crate::schema::DBI_EVENT && s.name != crate::schema::DBI_EVENT_PAYLOAD
                })
                .map(|s| s.name),
        );
        for name in names {
            let Some(cf) = self.db.cf_handle(name) else {
                continue;
            };
            let properties = [
                "rocksdb.background-errors",
                "rocksdb.estimate-pending-compaction-bytes",
                "rocksdb.compaction-pending",
                "rocksdb.mem-table-flush-pending",
                "rocksdb.estimate-table-readers-mem",
                "rocksdb.cur-size-all-mem-tables",
                "rocksdb.block-cache-usage",
            ];
            let values = properties
                .into_iter()
                .map(|key| {
                    (
                        key.to_string(),
                        match self.db.property_int_value_cf(cf, key) {
                            Ok(Some(n)) => serde_json::json!(n),
                            Ok(None) => serde_json::Value::Null,
                            Err(e) => serde_json::json!({"error":e.to_string()}),
                        },
                    )
                })
                .collect::<serde_json::Map<_, _>>();
            cf_stats.insert(name.to_string(), serde_json::Value::Object(values));
        }
        eprintln!(
            "WOK_ROCKSDB_FINAL_STATS {}",
            serde_json::json!({"column_families":cf_stats,"policy":"sync WAL per committed application batch; no forced settlement"})
        );
    }
}
