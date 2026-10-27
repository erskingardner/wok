//! Replays a `wok-bench --scenario db_write --db-record-ops` log on one
//! storage engine and reports what each step's commits cost (#257 item 12).
//!
//! The log holds every write transaction `db_write` committed, in order, with
//! the phases it marked: `preload N`, then `step BATCH EVENTS` per step. The
//! replay commits the same transactions, durably, on:
//!
//! - `lmdb`: Wok's own environment, as the control. Its bytes and commit
//!   times should match `db_write`'s.
//! - `lmdb-nometasync`: the same with `MDB_NOMETASYNC`.
//! - `rocksdb`: one column family per table, each key re-encoded so RocksDB's
//!   byte order matches the table's comparator, a duplicate appended to its
//!   key, and one `WriteBatch` per transaction written with `sync`.
//!
//! The replay does not repeat `db_write`'s reads, parsing or index building,
//! so transaction times here are the storage engine's share only.
//!
//! RocksDB defers work to flushes and compactions. After the preload the
//! replay flushes and waits until no background work is pending, so steps
//! start on a settled tree. During a step most background work is still
//! owed, so the report also gives an all-in cost per event: what the step
//! wrote other than flushes and compactions (its WAL) plus its logical bytes
//! times the flush and compaction bytes per logical byte the second half of
//! the preload needed, settling included.
//! After the last step it flushes and settles again and reports that too.
//!
//! Reader threads run during the steps: each repeats "an author's newest 50
//! events with their payloads" for authors sampled from the log.

use anyhow::{bail, ensure, Context, Result};
use clap::{Parser, ValueEnum};
use hdrhistogram::Histogram;
use serde::Serialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const EVENT_TABLE: &str = "rasgueadb_defaultDb__Event";
const PUBKEY_TABLE: &str = "rasgueadb_defaultDb__Event__pubkey";
const PAYLOAD_TABLE: &str = "rasgueadb_defaultDb__EventPayload";
/// Events per untimed preload transaction in `db_write`.
const PRELOAD_BATCH: u64 = 1_000;
const READ_LIMIT: usize = 50;
const SAMPLED_AUTHORS: usize = 20_000;
/// Authors whose answers [`Report::read_digest`] covers.
const DIGEST_AUTHORS: usize = 200;
/// How far each preload copy shifts local IDs.
const COPY_OFFSET: u64 = 1 << 40;

const MDB_REVERSEKEY: u32 = 0x02;
const MDB_DUPSORT: u32 = 0x04;
const MDB_INTEGERKEY: u32 = 0x08;
const MDB_INTEGERDUP: u32 = 0x20;

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum, Serialize)]
#[serde(rename_all = "kebab-case")]
enum EngineKind {
    Lmdb,
    LmdbNometasync,
    Rocksdb,
}

#[derive(Parser)]
struct Args {
    /// The op log `db_write` recorded.
    #[arg(long)]
    log: PathBuf,
    #[arg(long, value_enum)]
    engine: EngineKind,
    /// Database directory; must not exist yet.
    #[arg(long)]
    dir: PathBuf,
    /// JSON report.
    #[arg(long)]
    out: PathBuf,
    /// Reader threads during the steps.
    #[arg(long, default_value_t = 2)]
    readers: usize,
    /// RocksDB block cache.
    #[arg(long, default_value_t = 8_192)]
    rocks_cache_mb: usize,
    /// RocksDB: store the integers of `StringUint64` and
    /// `StringUint64Uint64` keys and their duplicates inverted, so an
    /// author's newest events come first in a forward scan, and fetch a
    /// query's payloads with one multi-get.
    #[arg(long)]
    rocks_newest_first: bool,
    /// RocksDB: commit the preload this many times, each copy's local IDs
    /// shifted above the last, for a tree as deep as a larger history's.
    #[arg(long, default_value_t = 1)]
    preload_repeat: u64,
}

// ---------------------------------------------------------------- the log

struct Table {
    name: String,
    flags: u32,
    comparator: u8,
}

enum Op {
    Put {
        table: usize,
        flags: u32,
        key: Vec<u8>,
        val: Vec<u8>,
    },
    Del {
        table: usize,
        key: Vec<u8>,
        val: Option<Vec<u8>>,
    },
    Clear {
        table: usize,
    },
}

#[derive(Default)]
struct Txn {
    ops: Vec<Op>,
    /// Puts into the event table: events stored.
    stored: u64,
    /// Key and value bytes the transaction writes.
    logical_bytes: u64,
}

enum Item {
    Txn(Txn),
    Phase(String),
    End,
}

struct Log {
    r: zstd::Decoder<'static, BufReader<File>>,
    tables: Vec<Table>,
    by_dbi: HashMap<u32, usize>,
    event_table: usize,
    pubkey_table: usize,
}

impl Log {
    fn open(path: &Path) -> Result<Self> {
        let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
        let mut r = zstd::Decoder::new(file)?;
        let mut magic = [0u8; 8];
        r.read_exact(&mut magic)?;
        ensure!(&magic == wok_db::op_log::MAGIC, "not an op log");
        let mut tables = Vec::new();
        let mut by_dbi = HashMap::new();
        for _ in 0..read_u32(&mut r)? {
            let dbi = read_u32(&mut r)?;
            let flags = read_u32(&mut r)?;
            let comparator = read_u8(&mut r)?;
            let len = read_u16(&mut r)? as usize;
            let name = String::from_utf8(read_bytes(&mut r, len)?)?;
            by_dbi.insert(dbi, tables.len());
            tables.push(Table {
                name,
                flags,
                comparator,
            });
        }
        let find = |name: &str| {
            tables
                .iter()
                .position(|t| t.name == name)
                .with_context(|| format!("log has no {name} table"))
        };
        let event_table = find(EVENT_TABLE)?;
        let pubkey_table = find(PUBKEY_TABLE)?;
        Ok(Self {
            r,
            tables,
            by_dbi,
            event_table,
            pubkey_table,
        })
    }

    fn table(&mut self) -> Result<usize> {
        let dbi = read_u32(&mut self.r)?;
        self.by_dbi
            .get(&dbi)
            .copied()
            .with_context(|| format!("unknown dbi {dbi}"))
    }

    fn next(&mut self) -> Result<Item> {
        let mut txn = Txn::default();
        loop {
            match read_u8(&mut self.r)? {
                b'H' => {
                    ensure!(txn.ops.is_empty(), "phase marker inside a transaction");
                    let len = read_u16(&mut self.r)? as usize;
                    return Ok(Item::Phase(String::from_utf8(read_bytes(
                        &mut self.r,
                        len,
                    )?)?));
                }
                b'E' => {
                    ensure!(txn.ops.is_empty(), "log ends inside a transaction");
                    return Ok(Item::End);
                }
                b'C' => return Ok(Item::Txn(txn)),
                b'P' => {
                    let table = self.table()?;
                    let flags = read_u32(&mut self.r)?;
                    let key = read_len_bytes(&mut self.r)?;
                    let val = read_len_bytes(&mut self.r)?;
                    txn.stored += (table == self.event_table) as u64;
                    txn.logical_bytes += (key.len() + val.len()) as u64;
                    txn.ops.push(Op::Put {
                        table,
                        flags,
                        key,
                        val,
                    });
                }
                b'D' => {
                    let table = self.table()?;
                    let key = read_len_bytes(&mut self.r)?;
                    let val = match read_u8(&mut self.r)? {
                        0 => None,
                        _ => Some(read_len_bytes(&mut self.r)?),
                    };
                    txn.logical_bytes += key.len() as u64;
                    txn.ops.push(Op::Del { table, key, val });
                }
                b'X' => {
                    let table = self.table()?;
                    txn.ops.push(Op::Clear { table });
                }
                tag => bail!("bad record tag {tag:#x}"),
            }
        }
    }
}

/// Where a table holds local IDs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LocalIds {
    None,
    Key,
    Duplicate,
}

fn local_ids(t: &Table) -> LocalIds {
    if t.name == EVENT_TABLE || t.name == PAYLOAD_TABLE {
        LocalIds::Key
    } else if t.flags & MDB_DUPSORT != 0 && t.flags & MDB_INTEGERDUP != 0 {
        LocalIds::Duplicate
    } else {
        LocalIds::None
    }
}

/// Add `by` to every local ID `txn` writes or deletes.
fn shift_local_ids(txn: &mut Txn, tables: &[LocalIds], by: u64) {
    let add = |b: &mut Vec<u8>| {
        if let Ok(raw) = <[u8; 8]>::try_from(&b[..]) {
            b.copy_from_slice(&(u64::from_ne_bytes(raw) + by).to_ne_bytes());
        }
    };
    for op in &mut txn.ops {
        match op {
            Op::Put {
                table, key, val, ..
            } => match tables[*table] {
                LocalIds::Key => add(key),
                LocalIds::Duplicate => add(val),
                LocalIds::None => {}
            },
            Op::Del { table, key, val } => match (tables[*table], val) {
                (LocalIds::Key, _) => add(key),
                (LocalIds::Duplicate, Some(val)) => add(val),
                _ => {}
            },
            Op::Clear { .. } => {}
        }
    }
}

fn read_u8(r: &mut impl Read) -> Result<u8> {
    let mut b = [0u8; 1];
    r.read_exact(&mut b)?;
    Ok(b[0])
}

fn read_u16(r: &mut impl Read) -> Result<u16> {
    let mut b = [0u8; 2];
    r.read_exact(&mut b)?;
    Ok(u16::from_le_bytes(b))
}

fn read_u32(r: &mut impl Read) -> Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn read_bytes(r: &mut impl Read, len: usize) -> Result<Vec<u8>> {
    let mut b = vec![0u8; len];
    r.read_exact(&mut b)?;
    Ok(b)
}

fn read_len_bytes(r: &mut impl Read) -> Result<Vec<u8>> {
    let len = read_u32(r)? as usize;
    read_bytes(r, len)
}

// ---------------------------------------------------------------- engines

#[derive(Default, Clone, Copy, Serialize)]
struct Background {
    wal_bytes: u64,
    flush_bytes: u64,
    compact_bytes: u64,
    stall_us: u64,
}

impl Background {
    fn since(self, before: Self) -> Self {
        Self {
            wal_bytes: self.wal_bytes.saturating_sub(before.wal_bytes),
            flush_bytes: self.flush_bytes.saturating_sub(before.flush_bytes),
            compact_bytes: self.compact_bytes.saturating_sub(before.compact_bytes),
            stall_us: self.stall_us.saturating_sub(before.stall_us),
        }
    }
}

/// What a reader's query returned: its events, and an order-sensitive
/// digest of their local IDs.
#[derive(Default)]
struct Answer {
    events: usize,
    digest: u64,
}

impl Answer {
    fn add(&mut self, lev_id: u64) {
        self.events += 1;
        self.digest = self.digest.rotate_left(7) ^ lev_id.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }
}

trait Engine: Send + Sync {
    /// Commit `txn` durably: (transaction µs, commit µs, ops that did not
    /// apply as recorded).
    fn apply(&self, txn: &Txn) -> Result<(u64, u64, u64)>;
    /// Flush buffered writes if `flush`, then wait for background work.
    fn settle(&self, flush: bool) -> Result<()>;
    /// Background counters; zero for LMDB.
    fn background(&self) -> Background;
    /// Compaction bytes RocksDB estimates it owes.
    fn pending_compaction_bytes(&self) -> u64;
    /// An author's newest `limit` events with their payloads: events read.
    fn newest_by_author(&self, pubkey: &[u8], limit: usize) -> Result<Answer>;
}

struct Lmdb {
    env: wok_db::Env,
    dbis: Vec<lmdb_sys::MDB_dbi>,
    pubkey: lmdb_sys::MDB_dbi,
    payload: lmdb_sys::MDB_dbi,
}

impl Lmdb {
    fn open(dir: &Path, tables: &[Table], no_meta_sync: bool) -> Result<Self> {
        let env = wok_db::Env::open(dir, wok_db::EnvOptions::default())?;
        env.ensure_initialized()?;
        if no_meta_sync {
            env.set_no_meta_sync(true)?;
        }
        let named: HashMap<_, _> = wok_db::op_log::table_dbis(&env).into_iter().collect();
        let dbi = |name: &str| {
            named
                .get(name)
                .copied()
                .with_context(|| format!("no {name} table"))
        };
        let dbis = tables
            .iter()
            .map(|t| dbi(&t.name))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            pubkey: dbi(PUBKEY_TABLE)?,
            payload: dbi(PAYLOAD_TABLE)?,
            env,
            dbis,
        })
    }
}

impl Engine for Lmdb {
    fn apply(&self, txn: &Txn) -> Result<(u64, u64, u64)> {
        let started = Instant::now();
        let mut rw = self.env.begin_rw()?;
        let mut divergent = 0;
        for op in &txn.ops {
            let applied = match op {
                Op::Put {
                    table,
                    flags,
                    key,
                    val,
                } => rw.put(self.dbis[*table], key, val, *flags)?,
                Op::Del { table, key, val } => rw.del(self.dbis[*table], key, val.as_deref())?,
                Op::Clear { table } => {
                    rw.clear(self.dbis[*table])?;
                    true
                }
            };
            divergent += (!applied) as u64;
        }
        let commit_started = Instant::now();
        rw.commit()?;
        Ok((
            started.elapsed().as_micros() as u64,
            commit_started.elapsed().as_micros() as u64,
            divergent,
        ))
    }

    fn settle(&self, _flush: bool) -> Result<()> {
        Ok(())
    }

    fn background(&self) -> Background {
        Background::default()
    }

    fn pending_compaction_bytes(&self) -> u64 {
        0
    }

    fn newest_by_author(&self, pubkey: &[u8], limit: usize) -> Result<Answer> {
        use lmdb_sys::{MDB_LAST, MDB_PREV, MDB_SET_RANGE};
        let ro = self.env.begin_ro()?;
        let mut cursor = ro.cursor(self.pubkey)?;
        let mut seek = pubkey.to_vec();
        seek.extend_from_slice(&u64::MAX.to_ne_bytes());
        let mut at = match cursor.get(Some(&seek), None, MDB_SET_RANGE)? {
            Some(_) => cursor.get(None, None, MDB_PREV)?,
            None => cursor.get(None, None, MDB_LAST)?,
        };
        let mut answer = Answer::default();
        while let Some((key, lev_id)) = at {
            if answer.events == limit || !key.starts_with(pubkey) {
                break;
            }
            let payload = ro.get(self.payload, lev_id)?.context("payload missing")?;
            std::hint::black_box(payload);
            answer.add(u64::from_ne_bytes(lev_id.try_into()?));
            at = cursor.get(None, None, MDB_PREV)?;
        }
        Ok(answer)
    }
}

struct Rocks {
    db: rocksdb::DB,
    tables: Vec<Table>,
    newest_first: bool,
    /// The options the database was opened with, for its statistics.
    opts: Mutex<rocksdb::Options>,
}

impl Rocks {
    fn open(dir: &Path, tables: Vec<Table>, cache_mb: usize, newest_first: bool) -> Result<Self> {
        use rocksdb::{
            BlockBasedOptions, Cache, ColumnFamilyDescriptor, DBCompressionType, Options,
        };
        let cache = Cache::new_lru_cache(cache_mb << 20);
        let cf_opts = || {
            let mut table = BlockBasedOptions::default();
            table.set_block_cache(&cache);
            table.set_block_size(16 << 10);
            table.set_bloom_filter(10.0, false);
            table.set_cache_index_and_filter_blocks(true);
            table.set_pin_l0_filter_and_index_blocks_in_cache(true);
            let mut o = Options::default();
            o.set_block_based_table_factory(&table);
            o.set_write_buffer_size(64 << 20);
            o.set_max_write_buffer_number(4);
            o.set_level_compaction_dynamic_level_bytes(true);
            o.set_compression_type(DBCompressionType::Lz4);
            o.set_bottommost_compression_type(DBCompressionType::Zstd);
            o
        };
        let mut opts = cf_opts();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts.set_max_background_jobs(8);
        opts.set_max_subcompactions(4);
        opts.set_db_write_buffer_size(2 << 30);
        opts.set_max_total_wal_size(1 << 30);
        opts.set_bytes_per_sync(1 << 20);
        opts.enable_statistics();
        let cfs = tables
            .iter()
            .map(|t| ColumnFamilyDescriptor::new(&t.name, cf_opts()))
            .collect::<Vec<_>>();
        let db = rocksdb::DB::open_cf_descriptors(&opts, dir, cfs)?;
        Ok(Self {
            db,
            tables,
            newest_first,
            opts: Mutex::new(opts),
        })
    }

    fn cf(&self, table: usize) -> &rocksdb::ColumnFamily {
        self.db
            .cf_handle(&self.tables[table].name)
            .expect("every table has a column family")
    }

    fn cf_named(&self, name: &str) -> &rocksdb::ColumnFamily {
        self.db.cf_handle(name).expect("column family")
    }

    fn sum_property(&self, name: &str) -> u64 {
        (0..self.tables.len())
            .map(|t| {
                self.db
                    .property_int_value_cf(self.cf(t), name)
                    .ok()
                    .flatten()
                    .unwrap_or(0)
            })
            .sum()
    }
}

/// `key` re-encoded so bytewise order matches the table's LMDB order, with
/// the duplicate `dup` appended for a DUPSORT table. With `newest_first`,
/// the integers of `StringUint64` and `StringUint64Uint64` keys and their
/// duplicates sort in reverse.
fn rocks_key(t: &Table, key: &[u8], dup: Option<&[u8]>, newest_first: bool) -> Vec<u8> {
    let invert = newest_first && matches!(t.comparator, 1 | 3);
    let be = |b: &[u8]| -> [u8; 8] {
        let v = u64::from_ne_bytes(b.try_into().unwrap());
        if invert { !v } else { v }.to_be_bytes()
    };
    let int_be = |b: &[u8]| -> [u8; 8] { u64::from_ne_bytes(b.try_into().unwrap()).to_be_bytes() };
    let mut out = Vec::with_capacity(key.len() + 8);
    let n = key.len();
    if t.flags & MDB_INTEGERKEY != 0 && n == 8 {
        out.extend_from_slice(&int_be(key));
    } else if t.flags & MDB_REVERSEKEY != 0 {
        out.extend(key.iter().rev());
    } else {
        match t.comparator {
            // StringUint64
            1 if n >= 8 => {
                out.extend_from_slice(&key[..n - 8]);
                out.extend_from_slice(&be(&key[n - 8..]));
            }
            // Uint64Uint64
            2 if n == 16 => {
                out.extend_from_slice(&int_be(&key[..8]));
                out.extend_from_slice(&int_be(&key[8..]));
            }
            // StringUint64Uint64
            3 if n >= 16 => {
                out.extend_from_slice(&key[..n - 16]);
                out.extend_from_slice(&be(&key[n - 16..n - 8]));
                out.extend_from_slice(&be(&key[n - 8..]));
            }
            _ => out.extend_from_slice(key),
        }
    }
    if let Some(dup) = dup {
        if t.flags & MDB_INTEGERDUP != 0 && dup.len() == 8 {
            out.extend_from_slice(&be(dup));
        } else {
            out.extend_from_slice(dup);
        }
    }
    out
}

impl Engine for Rocks {
    fn apply(&self, txn: &Txn) -> Result<(u64, u64, u64)> {
        let started = Instant::now();
        let mut batch = rocksdb::WriteBatch::default();
        for op in &txn.ops {
            match op {
                Op::Put {
                    table, key, val, ..
                } => {
                    let t = &self.tables[*table];
                    if t.flags & MDB_DUPSORT != 0 {
                        batch.put_cf(
                            self.cf(*table),
                            rocks_key(t, key, Some(val), self.newest_first),
                            [],
                        );
                    } else {
                        batch.put_cf(
                            self.cf(*table),
                            rocks_key(t, key, None, self.newest_first),
                            val,
                        );
                    }
                }
                Op::Del { table, key, val } => {
                    let t = &self.tables[*table];
                    if t.flags & MDB_DUPSORT != 0 {
                        let dup = val
                            .as_deref()
                            .context("whole-key delete on a DUPSORT table")?;
                        batch.delete_cf(
                            self.cf(*table),
                            rocks_key(t, key, Some(dup), self.newest_first),
                        );
                    } else {
                        batch
                            .delete_cf(self.cf(*table), rocks_key(t, key, None, self.newest_first));
                    }
                }
                Op::Clear { table } => {
                    batch.delete_range_cf(self.cf(*table), Vec::new(), vec![0xFF; 1024]);
                }
            }
        }
        let mut wo = rocksdb::WriteOptions::default();
        wo.set_sync(true);
        let commit_started = Instant::now();
        self.db.write_opt(batch, &wo)?;
        Ok((
            started.elapsed().as_micros() as u64,
            commit_started.elapsed().as_micros() as u64,
            0,
        ))
    }

    fn settle(&self, flush: bool) -> Result<()> {
        if flush {
            for t in 0..self.tables.len() {
                self.db.flush_cf(self.cf(t))?;
            }
        }
        loop {
            let busy = self.sum_property("rocksdb.compaction-pending")
                + self.sum_property("rocksdb.mem-table-flush-pending")
                + self
                    .db
                    .property_int_value("rocksdb.num-running-compactions")?
                    .unwrap_or(0)
                + self
                    .db
                    .property_int_value("rocksdb.num-running-flushes")?
                    .unwrap_or(0);
            if busy == 0 {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn background(&self) -> Background {
        let stats = self
            .opts
            .lock()
            .unwrap()
            .get_statistics()
            .unwrap_or_default();
        let ticker = |name: &str| {
            stats
                .lines()
                .find_map(|line| {
                    let mut words = line.split_whitespace();
                    (words.next() == Some(name)).then(|| words.last()?.parse().ok())?
                })
                .unwrap_or(0)
        };
        Background {
            wal_bytes: ticker("rocksdb.wal.bytes"),
            flush_bytes: ticker("rocksdb.flush.write.bytes"),
            compact_bytes: ticker("rocksdb.compact.write.bytes"),
            stall_us: ticker("rocksdb.stall.micros"),
        }
    }

    fn pending_compaction_bytes(&self) -> u64 {
        self.sum_property("rocksdb.estimate-pending-compaction-bytes")
    }

    fn newest_by_author(&self, pubkey: &[u8], limit: usize) -> Result<Answer> {
        // One snapshot for the index and the payloads, as an LMDB read
        // transaction has: otherwise an event replaced in between has an
        // index entry and no payload.
        let snapshot = self.db.snapshot();
        let opts = || {
            let mut opts = rocksdb::ReadOptions::default();
            opts.set_snapshot(&snapshot);
            opts
        };
        let payload = self.cf_named(PAYLOAD_TABLE);
        let mut it = self
            .db
            .raw_iterator_cf_opt(self.cf_named(PUBKEY_TABLE), opts());
        let get_opts = opts();
        if self.newest_first {
            it.seek(pubkey);
            let mut lev_ids = Vec::with_capacity(limit);
            while lev_ids.len() < limit && it.valid() {
                let key = it.key().unwrap();
                if !key.starts_with(pubkey) {
                    break;
                }
                let inverted = u64::from_be_bytes(key[key.len() - 8..].try_into().unwrap());
                lev_ids.push((!inverted).to_be_bytes());
                it.next();
            }
            it.status()?;
            let mut answer = Answer::default();
            for (lev_id, value) in lev_ids.iter().zip(self.db.batched_multi_get_cf_opt(
                payload,
                lev_ids.iter(),
                false,
                &get_opts,
            )) {
                std::hint::black_box(&*value?.context("payload missing")?);
                answer.add(u64::from_be_bytes(*lev_id));
            }
            return Ok(answer);
        }
        let mut seek = pubkey.to_vec();
        seek.extend_from_slice(&[0xFF; 16]);
        it.seek_for_prev(&seek);
        let mut answer = Answer::default();
        while answer.events < limit && it.valid() {
            let key = it.key().unwrap();
            if !key.starts_with(pubkey) {
                break;
            }
            let lev_id = &key[key.len() - 8..];
            let value = self
                .db
                .get_pinned_cf_opt(payload, lev_id, &get_opts)?
                .context("payload missing")?;
            std::hint::black_box(&*value);
            answer.add(u64::from_be_bytes(lev_id.try_into()?));
            it.prev();
        }
        it.status()?;
        Ok(answer)
    }
}

// ---------------------------------------------------------------- report

#[derive(Serialize, Default)]
struct Latency {
    count: u64,
    p50_us: u64,
    p99_us: u64,
    max_us: u64,
}

impl Latency {
    fn of(h: &Histogram<u64>) -> Self {
        Self {
            count: h.len(),
            p50_us: h.value_at_quantile(0.50),
            p99_us: h.value_at_quantile(0.99),
            max_us: h.max(),
        }
    }
}

#[derive(Serialize)]
struct Preload {
    events: u64,
    stored: u64,
    commits: u64,
    secs: f64,
    settle_secs: f64,
    bytes_written: Option<u64>,
    logical_bytes: u64,
    background: Background,
    /// Flush and compaction bytes per logical byte over the preload's second
    /// half, settling included.
    background_per_logical_byte: f64,
}

#[derive(Serialize)]
struct Step {
    batch: u64,
    events: u64,
    stored: u64,
    /// Transactions with events, as `db_write` counts commits.
    commits: u64,
    /// All transactions, search build steps included.
    txns: u64,
    secs: f64,
    stored_per_s: f64,
    txn: Latency,
    commit: Latency,
    bytes_written: Option<u64>,
    bytes_per_stored: Option<f64>,
    logical_bytes: u64,
    background: Background,
    /// RocksDB: bytes written other than by flushes and compactions, plus
    /// logical bytes times the preload's background bytes per logical byte.
    /// LMDB: `bytes_per_stored`.
    all_in_bytes_per_stored: Option<f64>,
    pending_compaction_bytes_at_end: u64,
    reads: Latency,
    /// Mean events a reader's query returned (at most 50).
    read_events_per_query: f64,
}

#[derive(Serialize)]
struct Report {
    engine: EngineKind,
    rocks_newest_first: bool,
    preload_repeat: u64,
    log: PathBuf,
    preload: Option<Preload>,
    steps: Vec<Step>,
    /// After the last step: a flush, then waiting for background work.
    final_settle_secs: f64,
    final_settle_bytes_written: Option<u64>,
    final_settle_background: Background,
    /// Steps plus the final settle: background bytes per logical byte.
    steps_background_per_logical_byte: f64,
    footprint_bytes: u64,
    divergent_ops: u64,
    /// Reader queries that failed; the first is printed.
    read_errors: u64,
    /// Digest of the newest events of the first sampled authors after the
    /// last step: equal across engines that replayed the same log once.
    read_digest: String,
}

fn process_write_bytes() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/self/io").ok()?;
    text.lines()
        .find_map(|line| line.strip_prefix("write_bytes:"))?
        .trim()
        .parse()
        .ok()
}

fn dir_bytes(dir: &Path) -> u64 {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok()?.metadata().ok())
                .filter(|m| m.is_file())
                .map(|m| m.len())
                .sum()
        })
        .unwrap_or(0)
}

/// What one phase did so far.
struct Phase {
    label: String,
    batch: u64,
    events: u64,
    started: Instant,
    io_before: Option<u64>,
    bg_before: Background,
    stored: u64,
    commits: u64,
    txns: u64,
    logical_bytes: u64,
    txn_hist: Histogram<u64>,
    commit_hist: Histogram<u64>,
    /// Preload only: counters at its halfway point.
    half: Option<(u64, Background)>,
}

impl Phase {
    fn start(label: String, engine: &dyn Engine, preload_repeat: u64) -> Result<Self> {
        let mut words = label.split_whitespace();
        let kind = words.next().unwrap_or_default();
        let (batch, events) = match kind {
            "preload" => (
                PRELOAD_BATCH,
                words.next().unwrap_or("0").parse::<u64>()? * preload_repeat,
            ),
            "step" => (
                words.next().unwrap_or("0").parse()?,
                words.next().unwrap_or("0").parse()?,
            ),
            _ => bail!("unknown phase {label:?}"),
        };
        Ok(Self {
            label,
            batch,
            events,
            started: Instant::now(),
            io_before: process_write_bytes(),
            bg_before: engine.background(),
            stored: 0,
            commits: 0,
            txns: 0,
            logical_bytes: 0,
            txn_hist: Histogram::new(3)?,
            commit_hist: Histogram::new(3)?,
            half: None,
        })
    }

    fn is_preload(&self) -> bool {
        self.label.starts_with("preload")
    }

    /// Commit `txn` and count it: ops that did not apply as recorded.
    fn apply(&mut self, engine: &dyn Engine, txn: &Txn) -> Result<u64> {
        let (txn_us, commit_us, divergent) = engine.apply(txn)?;
        self.txns += 1;
        self.logical_bytes += txn.logical_bytes;
        if txn.stored > 0 {
            self.stored += txn.stored;
            self.commits += 1;
            self.txn_hist.record(txn_us.max(1))?;
            self.commit_hist.record(commit_us.max(1))?;
        }
        if self.is_preload()
            && self.half.is_none()
            && self.commits * PRELOAD_BATCH * 2 >= self.events
        {
            self.half = Some((self.logical_bytes, engine.background()));
        }
        Ok(divergent)
    }
}

/// Commit the preload of the log at `path` again, local IDs shifted by
/// `copy` × [`COPY_OFFSET`].
fn apply_preload_copy(
    path: &Path,
    copy: u64,
    shifts: &[LocalIds],
    engine: &dyn Engine,
    p: &mut Phase,
) -> Result<u64> {
    let mut log = Log::open(path)?;
    match log.next()? {
        Item::Phase(label) if label.starts_with("preload") => {}
        _ => bail!("the log does not start with its preload"),
    }
    let mut divergent = 0;
    while let Item::Txn(mut txn) = log.next()? {
        shift_local_ids(&mut txn, shifts, copy * COPY_OFFSET);
        divergent += p.apply(engine, &txn)?;
    }
    Ok(divergent)
}

fn main() -> Result<()> {
    let args = Args::parse();
    ensure!(!args.dir.exists(), "{} already exists", args.dir.display());
    std::fs::create_dir_all(&args.dir)?;
    let mut log = Log::open(&args.log)?;
    let tables = std::mem::take(&mut log.tables);
    ensure!(
        args.preload_repeat == 1 || args.engine == EngineKind::Rocksdb,
        "--preload-repeat is for RocksDB: LMDB's MDB_APPEND puts need rising keys"
    );
    ensure!(
        !args.rocks_newest_first || args.engine == EngineKind::Rocksdb,
        "--rocks-newest-first is for RocksDB"
    );
    let shifts: Vec<LocalIds> = tables.iter().map(local_ids).collect();
    let engine: Arc<dyn Engine> = match args.engine {
        EngineKind::Lmdb => Arc::new(Lmdb::open(&args.dir, &tables, false)?),
        EngineKind::LmdbNometasync => Arc::new(Lmdb::open(&args.dir, &tables, true)?),
        EngineKind::Rocksdb => Arc::new(Rocks::open(
            &args.dir,
            tables,
            args.rocks_cache_mb,
            args.rocks_newest_first,
        )?),
    };

    let mut authors: Vec<Vec<u8>> = Vec::new();
    let mut authors_seen = 0u64;
    let mut rng = 0x9E37_79B9_7F4A_7C15u64;
    let mut next_random = move || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };

    let stop = Arc::new(AtomicBool::new(false));
    let reads = Arc::new(Mutex::new(Histogram::<u64>::new(3)?));
    let read_errors = Arc::new(AtomicU64::new(0));
    // Events the readers' queries returned, for comparing engines' answers.
    let read_events = Arc::new(AtomicU64::new(0));
    let mut readers = Vec::new();

    let mut check_authors: Vec<Vec<u8>> = Vec::new();
    let mut preload = None;
    let mut steps = Vec::new();
    let mut divergent_ops = 0;
    let mut phase: Option<Phase> = None;
    let mut steps_logical = 0u64;
    let mut steps_bg_before = Background::default();
    let mut background_per_logical_byte = 0.0;

    loop {
        let item = log.next()?;
        if !matches!(item, Item::Txn(_)) {
            if let Some(p) = phase.as_mut().filter(|p| p.is_preload()) {
                for copy in 1..args.preload_repeat {
                    divergent_ops +=
                        apply_preload_copy(&args.log, copy, &shifts, engine.as_ref(), p)?;
                    eprintln!(
                        "preload copy {copy}: {:.0} s",
                        p.started.elapsed().as_secs_f64()
                    );
                }
            }
            if let Some(done) = phase.take() {
                let secs = done.started.elapsed().as_secs_f64();
                if done.is_preload() {
                    let settle_started = Instant::now();
                    engine.settle(true)?;
                    let settle_secs = settle_started.elapsed().as_secs_f64();
                    let bg = engine.background();
                    let (half_logical, half_bg) = done.half.unwrap_or((0, done.bg_before));
                    let since_half = bg.since(half_bg);
                    background_per_logical_byte =
                        (since_half.flush_bytes + since_half.compact_bytes) as f64
                            / (done.logical_bytes - half_logical).max(1) as f64;
                    preload = Some(Preload {
                        events: done.events,
                        stored: done.stored,
                        commits: done.commits,
                        secs,
                        settle_secs,
                        bytes_written: process_write_bytes()
                            .zip(done.io_before)
                            .map(|(a, b)| a - b),
                        logical_bytes: done.logical_bytes,
                        background: bg.since(done.bg_before),
                        background_per_logical_byte,
                    });
                    eprintln!("preload: {secs:.0} s + settle {settle_secs:.0} s");
                    steps_bg_before = engine.background();
                    let mut chosen = authors.clone();
                    chosen.truncate(SAMPLED_AUTHORS);
                    let chosen = Arc::new(chosen);
                    check_authors = chosen[..chosen.len().min(DIGEST_AUTHORS)].to_vec();
                    for i in 0..args.readers {
                        let (engine, stop, reads, errors, events, chosen) = (
                            engine.clone(),
                            stop.clone(),
                            reads.clone(),
                            read_errors.clone(),
                            read_events.clone(),
                            chosen.clone(),
                        );
                        readers.push(std::thread::spawn(move || {
                            let mut x = 0x2545_F491_4F6C_DD1Du64 ^ (i as u64 + 1);
                            while !stop.load(Ordering::Relaxed) && !chosen.is_empty() {
                                x ^= x << 13;
                                x ^= x >> 7;
                                x ^= x << 17;
                                let author = &chosen[(x % chosen.len() as u64) as usize];
                                let started = Instant::now();
                                match engine.newest_by_author(author, READ_LIMIT) {
                                    Ok(answer) => {
                                        let us = started.elapsed().as_micros() as u64;
                                        let mut reads = reads.lock().unwrap();
                                        let _ = reads.record(us.max(1));
                                        events.fetch_add(answer.events as u64, Ordering::Relaxed);
                                    }
                                    Err(error) => {
                                        if errors.fetch_add(1, Ordering::Relaxed) == 0 {
                                            eprintln!("read failed: {error:#}");
                                        }
                                    }
                                }
                            }
                        }));
                    }
                } else {
                    let bytes_written = process_write_bytes()
                        .zip(done.io_before)
                        .map(|(a, b)| a - b);
                    let bg = engine.background().since(done.bg_before);
                    let stored = done.stored.max(1) as f64;
                    let all_in = match args.engine {
                        EngineKind::Rocksdb => {
                            // What the step wrote besides flushes and
                            // compactions (the WAL, page by page), where
                            // `/proc` counts it, plus its share of them.
                            let own = match bytes_written {
                                Some(b) => b.saturating_sub(bg.flush_bytes + bg.compact_bytes),
                                None => bg.wal_bytes,
                            };
                            Some(
                                (own as f64
                                    + done.logical_bytes as f64 * background_per_logical_byte)
                                    / stored,
                            )
                        }
                        _ => bytes_written.map(|b| b as f64 / stored),
                    };
                    let (read_latency, read_events_per_query) = {
                        let mut h = reads.lock().unwrap();
                        let latency = Latency::of(&h);
                        let per_query =
                            read_events.swap(0, Ordering::Relaxed) as f64 / h.len().max(1) as f64;
                        h.reset();
                        (latency, per_query)
                    };
                    steps_logical += done.logical_bytes;
                    eprintln!(
                        "{}: {:.0} stored/s, commit p99 {} µs, {:.0} B/stored",
                        done.label,
                        done.stored as f64 / secs,
                        done.commit_hist.value_at_quantile(0.99),
                        bytes_written.map_or(0.0, |b| b as f64 / stored)
                    );
                    steps.push(Step {
                        batch: done.batch,
                        events: done.events,
                        stored: done.stored,
                        commits: done.commits,
                        txns: done.txns,
                        secs,
                        stored_per_s: done.stored as f64 / secs,
                        txn: Latency::of(&done.txn_hist),
                        commit: Latency::of(&done.commit_hist),
                        bytes_written,
                        bytes_per_stored: bytes_written.map(|b| b as f64 / stored),
                        logical_bytes: done.logical_bytes,
                        background: bg,
                        all_in_bytes_per_stored: all_in,
                        pending_compaction_bytes_at_end: engine.pending_compaction_bytes(),
                        reads: read_latency,
                        read_events_per_query,
                    });
                }
            }
        }
        match item {
            Item::Phase(label) => {
                if label.starts_with("step") && preload.is_none() {
                    bail!("a step before the preload");
                }
                // Readers measure steps only.
                let mut h = reads.lock().unwrap();
                h.reset();
                read_events.store(0, Ordering::Relaxed);
                drop(h);
                phase = Some(Phase::start(label, engine.as_ref(), args.preload_repeat)?);
            }
            Item::Txn(txn) => {
                let p = phase.as_mut().context("a transaction before any phase")?;
                if p.is_preload() {
                    for op in &txn.ops {
                        if let Op::Put { table, key, .. } = op {
                            if *table == log.pubkey_table && key.len() >= 32 {
                                // Reservoir sample of authors' posting keys.
                                authors_seen += 1;
                                if authors.len() < SAMPLED_AUTHORS {
                                    authors.push(key[..32].to_vec());
                                } else {
                                    let slot = (next_random() % authors_seen) as usize;
                                    if slot < SAMPLED_AUTHORS {
                                        authors[slot] = key[..32].to_vec();
                                    }
                                }
                            }
                        }
                    }
                }
                divergent_ops += p.apply(engine.as_ref(), &txn)?;
            }
            Item::End => break,
        }
    }

    stop.store(true, Ordering::Relaxed);
    for reader in readers {
        let _ = reader.join();
    }
    let io_before = process_write_bytes();
    let bg_before = engine.background();
    let settle_started = Instant::now();
    engine.settle(true)?;
    let final_settle_secs = settle_started.elapsed().as_secs_f64();
    let final_bg = engine.background();
    let steps_bg = final_bg.since(steps_bg_before);
    let mut read_digest = 0u64;
    for author in &check_authors {
        let answer = engine.newest_by_author(author, READ_LIMIT)?;
        read_digest = read_digest.rotate_left(13) ^ answer.digest ^ answer.events as u64;
    }
    let report = Report {
        engine: args.engine,
        rocks_newest_first: args.rocks_newest_first,
        preload_repeat: args.preload_repeat,
        log: args.log.clone(),
        preload,
        steps,
        final_settle_secs,
        final_settle_bytes_written: process_write_bytes().zip(io_before).map(|(a, b)| a - b),
        final_settle_background: final_bg.since(bg_before),
        steps_background_per_logical_byte: (steps_bg.flush_bytes + steps_bg.compact_bytes) as f64
            / steps_logical.max(1) as f64,
        footprint_bytes: dir_bytes(&args.dir),
        divergent_ops,
        read_errors: read_errors.load(Ordering::Relaxed),
        read_digest: format!("{read_digest:016x}"),
    };
    std::fs::write(&args.out, serde_json::to_string_pretty(&report)?)?;
    ensure!(
        report.read_errors == 0,
        "{} reads failed",
        report.read_errors
    );
    Ok(())
}
