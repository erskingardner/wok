//! Snapshot reads and a single-writer overlay committed as one synchronous WAL
//! batch across all column families. Returned slices are transaction-owned.
#![forbid(unsafe_code)]
use crate::env::Env;
use crate::rocks::*;
use crate::DbError;
use bumpalo::Bump;
use elsa::FrozenMap;
use lmdb_sys::*;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::marker::PhantomData;
use std::ops::Bound::{Excluded, Included};
use std::rc::Rc;
use std::sync::{Arc, MutexGuard};

type Kv<'a> = (&'a [u8], &'a [u8]);
type Overlay = BTreeMap<(u32, Vec<u8>), Option<Vec<u8>>>;
fn physical(dbi: u32) -> u32 {
    if combined(dbi) {
        3
    } else {
        dbi
    }
}
fn count_key(dbi: u32) -> Vec<u8> {
    format!("entries/{dbi}").into_bytes()
}
enum RecordBytes<'env> {
    Owned(Box<[u8]>),
    Pinned(rocksdb::DBPinnableSlice<'env>),
}
impl AsRef<[u8]> for RecordBytes<'_> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Owned(raw) => raw,
            Self::Pinned(raw) => raw,
        }
    }
}
fn record_key(id: u64) -> [u8; 9] {
    let mut key = [1; 9];
    key[1..].copy_from_slice(&id.to_be_bytes());
    key
}
// Erase the cache's invariant internal lifetime so View remains covariant and
// cursors can borrow it for less than the Env's full lifetime. Pins still keep
// their concrete DB lifetime inside RecordStore; no lifetime is extended.
trait RecordCache {
    fn get(
        &self,
        id: u64,
        dbi: u32,
        snapshot: &rocksdb::Snapshot<'_>,
    ) -> Result<Option<&[u8]>, DbError>;
    fn cache(&self, id: u64, raw: &[u8]) -> &[u8];
}
struct RecordStore<'env> {
    db: &'env rocksdb::DB,
    records: FrozenMap<u64, Box<RecordBytes<'env>>>,
}
impl RecordCache for RecordStore<'_> {
    fn get(
        &self,
        id: u64,
        dbi: u32,
        snapshot: &rocksdb::Snapshot<'_>,
    ) -> Result<Option<&[u8]>, DbError> {
        if let Some(raw) = self.records.get(&id) {
            return Ok(Some(raw.as_ref()));
        }
        let mut options = rocksdb::ReadOptions::default();
        options.set_snapshot(snapshot);
        let cf = self
            .db
            .cf_handle(cf_name(dbi))
            .expect("validated column family");
        // The pin owns its native storage reference and is tied to the Env's
        // DB. The snapshot selects which version is pinned at lookup.
        Ok(self
            .db
            .get_pinned_cf_opt(cf, record_key(id), &options)
            .map_err(err)?
            .map(|raw| {
                self.records
                    .insert(id, Box::new(RecordBytes::Pinned(raw)))
                    .as_ref()
            }))
    }
    fn cache(&self, id: u64, raw: &[u8]) -> &[u8] {
        self.records
            .get(&id)
            .unwrap_or_else(|| {
                self.records
                    .insert(id, Box::new(RecordBytes::Owned(raw.into())))
            })
            .as_ref()
    }
}
struct View<'env> {
    env: &'env Env,
    snapshot: rocksdb::Snapshot<'env>,
    markers: Arc<MarkerMap>,
    arena: Bump,
    records: Box<dyn RecordCache + 'env>,
    _not_send_or_sync: PhantomData<Rc<()>>,
}
impl<'env> View<'env> {
    fn new(env: &'env Env) -> Result<Self, DbError> {
        loop {
            let (sequence, markers) = env
                .inner
                .marker_state
                .lock()
                .map_err(|_| err("metadata cache mutex poisoned"))?
                .clone()
                .ok_or_else(|| err("metadata cache unavailable after a storage error; reopen"))?;
            let before = env.inner.db.latest_sequence_number();
            let snapshot = env.inner.db.snapshot();
            let after = env.inner.db.latest_sequence_number();
            if sequence == before && before == after {
                return Ok(Self {
                    env,
                    snapshot,
                    markers,
                    arena: Bump::new(),
                    records: Box::new(RecordStore {
                        db: &env.inner.db,
                        records: FrozenMap::new(),
                    }),
                    _not_send_or_sync: PhantomData,
                });
            }
            // A writer published between the metadata clone and snapshot, or is
            // completing publication after sync WAL. Retry without serializing
            // readers behind the writer's fsync or changing RocksDB's snapshot.
            match env.inner.writer.try_lock() {
                Ok(_guard) => {
                    // Native maintenance/test writes can bypass RwTxn. Rebuild
                    // the derived mirror once if no writer is publishing it.
                    let current = env.inner.db.latest_sequence_number();
                    let mut state = env
                        .inner
                        .marker_state
                        .lock()
                        .map_err(|_| err("metadata cache mutex poisoned"))?;
                    if state
                        .as_ref()
                        .is_some_and(|(version, _)| *version != current)
                    {
                        *state = Some((current, Arc::new(load_markers(&env.inner.db)?)));
                    }
                }
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    return Err(err("writer mutex poisoned"))
                }
                Err(std::sync::TryLockError::WouldBlock) => {}
            }
            std::thread::yield_now();
        }
    }
    fn cf(&self, dbi: u32) -> &rocksdb::ColumnFamily {
        self.env
            .inner
            .db
            .cf_handle(cf_name(dbi))
            .expect("validated column family")
    }
    fn raw(
        &self,
        dbi: u32,
        key: &[u8],
        staged: Option<&Overlay>,
    ) -> Result<Option<Vec<u8>>, DbError> {
        if let Some(v) = staged.and_then(|s| s.get(&(physical(dbi), key.to_vec()))) {
            return Ok(v.clone());
        }
        self.snapshot.get_cf(self.cf(dbi), key).map_err(err)
    }
    fn count(&self, dbi: u32) -> Result<u64, DbError> {
        let dbi = if dbi == COVER_DBI { 10 } else { dbi };
        self.snapshot
            .get(count_key(dbi))
            .map_err(err)?
            .map(|v| {
                v.as_slice()
                    .try_into()
                    .map(u64::from_le_bytes)
                    .map_err(|_| err("invalid entry counter"))
            })
            .transpose()
            .map(|v| v.unwrap_or(0))
    }
    // Covering iterator values last only until the iterator moves. Keep their
    // exact combined bytes once, sharing the cache with pinned primary reads.
    fn cache_record(&self, id: u64, raw: &[u8]) -> &[u8] {
        self.records.cache(id, raw)
    }
    fn get_record<'a>(
        &'a self,
        dbi: u32,
        id: u64,
        staged: Option<&'a Overlay>,
    ) -> Result<Option<&'a [u8]>, DbError> {
        let raw = if staged.is_none() {
            match self.records.get(id, dbi, &self.snapshot)? {
                Some(raw) => raw,
                None => return Ok(None),
            }
        } else {
            match self.raw(dbi, &record_key(id), staged)? {
                Some(raw) => self.arena.alloc_slice_copy(&raw),
                None => return Ok(None),
            }
        };
        let (packed, payload) = parts(raw)?;
        Ok(if dbi == 3 { packed } else { payload })
    }
    fn get<'a>(
        &'a self,
        dbi: u32,
        key: &[u8],
        staged: Option<&'a Overlay>,
    ) -> Result<Option<&'a [u8]>, DbError> {
        if combined(dbi) {
            let id = u64::from_ne_bytes(key.try_into().map_err(|_| err("invalid event local ID"))?);
            return self.get_record(dbi, id, staged);
        }
        if spec(dbi).flags & MDB_DUPSORT != 0 {
            let mut cursor = Cursor::new(self, dbi, staged);
            return Ok(cursor.get(Some(key), None, MDB_SET_KEY)?.map(|(_, v)| v));
        }
        Ok(self
            .raw(dbi, &encode(dbi, key, None), staged)?
            .map(|v| &*self.arena.alloc_slice_copy(&v)))
    }
}
pub struct RoTxn<'env> {
    view: View<'env>,
}
pub struct RwTxn<'env> {
    view: View<'env>,
    staged: Overlay,
    counts: HashMap<u32, u64>,
    marker_values: MarkerMap,
    touched_records: HashSet<u64>,
    touched_postings: HashSet<Vec<u8>>,
    _writer: MutexGuard<'env, ()>,
    pub(crate) event_sequence: Option<u64>,
    pub(crate) superseded_events: Option<u64>,
    pub(crate) author_counts: HashMap<Vec<u8>, u64>,
    pub(crate) defer_tag_kind: bool,
    #[cfg(feature = "op-log")]
    op_log: Vec<u8>,
}
impl<'env> RoTxn<'env> {
    pub fn begin(env: &'env Env) -> Result<Self, DbError> {
        Ok(Self {
            view: View::new(env)?,
        })
    }
    pub fn env(&self) -> &'env Env {
        self.view.env
    }
    pub fn get(&self, dbi: u32, key: &[u8]) -> Result<Option<&[u8]>, DbError> {
        if cached_marker(dbi, key) {
            return Ok(self
                .view
                .markers
                .get(key)
                .and_then(|v| v.first())
                .map(Vec::as_slice));
        }
        self.view.get(dbi, key, None)
    }
    pub fn get_u64(&self, dbi: u32, key: u64) -> Result<Option<&[u8]>, DbError> {
        if combined(dbi) {
            self.view.get_record(dbi, key, None)
        } else {
            self.get(dbi, &key.to_ne_bytes())
        }
    }
    pub fn cursor(&self, dbi: u32) -> Result<Cursor<'_>, DbError> {
        Ok(Cursor::new(&self.view, dbi, None))
    }
    pub fn entries(&self, dbi: u32) -> Result<usize, DbError> {
        usize::try_from(self.view.count(dbi)?).map_err(err)
    }
    pub(crate) fn largest_integer_key(&self, dbi: u32) -> Result<u64, DbError> {
        largest(self.cursor(dbi)?)
    }
    pub fn foreach_full<F>(
        &self,
        dbi: u32,
        key: &[u8],
        dup: &[u8],
        reverse: bool,
        cb: F,
    ) -> Result<bool, DbError>
    where
        F: FnMut(&[u8], &[u8]) -> bool,
    {
        self.cursor(dbi)?.foreach_full(key, dup, reverse, cb)
    }
    pub fn abort(self) {}
}
impl<'env> RwTxn<'env> {
    pub(crate) fn begin(env: &'env Env) -> Result<Self, DbError> {
        let guard = env
            .inner
            .writer
            .lock()
            .map_err(|_| err("writer mutex poisoned"))?;
        // Holding the writer lock also permits a one-time mirror refresh after
        // native maintenance/test writes. View::new must not try to reacquire it.
        {
            let current = env.inner.db.latest_sequence_number();
            let mut state = env
                .inner
                .marker_state
                .lock()
                .map_err(|_| err("metadata cache mutex poisoned"))?;
            if state
                .as_ref()
                .is_some_and(|(version, _)| *version != current)
            {
                *state = Some((current, Arc::new(load_markers(&env.inner.db)?)));
            }
        }
        let view = View::new(env)?;
        let marker_values = (*view.markers).clone();
        Ok(Self {
            view,
            marker_values,
            staged: BTreeMap::new(),
            counts: HashMap::new(),
            touched_records: HashSet::new(),
            touched_postings: HashSet::new(),
            _writer: guard,
            event_sequence: None,
            superseded_events: None,
            author_counts: HashMap::new(),
            defer_tag_kind: false,
            #[cfg(feature = "op-log")]
            op_log: Vec::new(),
        })
    }
    pub fn env(&self) -> &'env Env {
        self.view.env
    }
    pub fn get(&self, dbi: u32, key: &[u8]) -> Result<Option<&[u8]>, DbError> {
        if cached_marker(dbi, key) {
            return Ok(self
                .marker_values
                .get(key)
                .and_then(|v| v.first())
                .map(Vec::as_slice));
        }
        self.view.get(dbi, key, Some(&self.staged))
    }
    pub fn get_u64(&self, dbi: u32, key: u64) -> Result<Option<&[u8]>, DbError> {
        self.get(dbi, &key.to_ne_bytes())
    }
    pub fn cursor(&self, dbi: u32) -> Result<Cursor<'_>, DbError> {
        Ok(Cursor::new(&self.view, dbi, Some(&self.staged)))
    }
    pub fn entries(&self, dbi: u32) -> Result<usize, DbError> {
        let n = self
            .counts
            .get(&dbi)
            .copied()
            .map(Ok)
            .unwrap_or_else(|| self.view.count(dbi))?;
        usize::try_from(n).map_err(err)
    }
    pub(crate) fn largest_integer_key(&self, dbi: u32) -> Result<u64, DbError> {
        largest(self.cursor(dbi)?)
    }
    pub fn next_integer_key(&self, dbi: u32) -> Result<u64, DbError> {
        self.largest_integer_key(dbi)?
            .checked_add(1)
            .ok_or_else(|| err("integer key space exhausted"))
    }
    pub fn foreach_full<F>(
        &self,
        dbi: u32,
        key: &[u8],
        dup: &[u8],
        reverse: bool,
        cb: F,
    ) -> Result<bool, DbError>
    where
        F: FnMut(&[u8], &[u8]) -> bool,
    {
        self.cursor(dbi)?.foreach_full(key, dup, reverse, cb)
    }
    fn change_count(&mut self, dbi: u32, insert: bool) -> Result<(), DbError> {
        let n = self
            .counts
            .get(&dbi)
            .copied()
            .map(Ok)
            .unwrap_or_else(|| self.view.count(dbi))?;
        let n = if insert {
            n.checked_add(1)
        } else {
            n.checked_sub(1)
        }
        .ok_or_else(|| err("entry counter overflow/underflow"))?;
        self.counts.insert(dbi, n);
        Ok(())
    }
    pub fn put(&mut self, dbi: u32, key: &[u8], val: &[u8], flags: u32) -> Result<bool, DbError> {
        if dbi == COVER_DBI {
            return Err(err("covering index is derived"));
        }
        let dup = spec(dbi).flags & MDB_DUPSORT != 0;
        let pk = encode(dbi, key, dup.then_some(val));
        let exists = if combined(dbi) {
            self.get(dbi, key)?.is_some()
        } else {
            self.view.raw(dbi, &pk, Some(&self.staged))?.is_some()
        };
        if (flags & MDB_NOOVERWRITE != 0 && self.get(dbi, key)?.is_some())
            || (flags & MDB_NODUPDATA != 0 && exists)
        {
            return Ok(false);
        }
        // APPEND is an assertion about the logical comparator, not a durability flag.
        // Wok inserts fresh monotonically allocated local IDs on integer tables.
        if flags & MDB_APPEND != 0 {
            let last = self
                .cursor(dbi)?
                .get(None, None, MDB_LAST)?
                .map(|(k, _)| k.to_vec());
            if last.as_deref().is_some_and(|last| {
                if reversed(dbi) {
                    encode(dbi, last, None) <= encode(dbi, key, None)
                } else {
                    encode(dbi, last, None) >= encode(dbi, key, None)
                }
            }) {
                return Ok(false);
            }
        }
        if combined(dbi) {
            let mut record = self
                .view
                .raw(dbi, &pk, Some(&self.staged))?
                .map(|v| Record::decode(&v))
                .transpose()?
                .unwrap_or_default();
            if dbi == 3 {
                record.packed = Some(val.to_vec());
            } else {
                record.payload = Some(val.to_vec());
            }
            self.staged.insert((3, pk), Some(record.encode()));
            self.touched_records.insert(u64::from_ne_bytes(
                key.try_into().map_err(|_| err("invalid local ID"))?,
            ));
        } else {
            if dbi == 10 {
                self.touched_postings.insert(pk.clone());
            }
            self.staged
                .insert((dbi, pk), Some(if dup { Vec::new() } else { val.to_vec() }));
        }
        if !exists {
            self.change_count(dbi, true)?;
        }
        if cached_marker(dbi, key) {
            let values = self.marker_values.entry(key.to_vec()).or_default();
            if !values.iter().any(|v| v == val) {
                values.push(val.to_vec());
                sort_marker_values(key, values);
            }
        }
        #[cfg(feature = "op-log")]
        if crate::op_log::active() {
            crate::op_log::put(&mut self.op_log, dbi, flags, key, val);
        }
        Ok(true)
    }
    pub fn put_u64(&mut self, dbi: u32, key: u64, val: &[u8], flags: u32) -> Result<bool, DbError> {
        self.put(dbi, &key.to_ne_bytes(), val, flags)
    }
    pub fn del(&mut self, dbi: u32, key: &[u8], val: Option<&[u8]>) -> Result<bool, DbError> {
        if dbi == COVER_DBI {
            return Err(err("covering index is derived"));
        }
        let dup = spec(dbi).flags & MDB_DUPSORT != 0;
        if dup && val.is_none() {
            let vals = if cached_marker(dbi, key) {
                self.marker_values.get(key).cloned().unwrap_or_default()
            } else {
                let mut c = self.cursor(dbi)?;
                let mut row = c.get(Some(key), None, MDB_SET_KEY)?;
                let mut vals = Vec::new();
                while let Some((_, v)) = row {
                    vals.push(v.to_vec());
                    row = c.get(None, None, MDB_NEXT_DUP)?;
                }
                vals
            };
            let mut removed = false;
            for v in vals {
                removed |= self.del(dbi, key, Some(&v))?;
            }
            return Ok(removed);
        }
        let pk = encode(dbi, key, if dup { val } else { None });
        if combined(dbi) {
            let Some(raw) = self.view.raw(dbi, &pk, Some(&self.staged))? else {
                return Ok(false);
            };
            let mut record = Record::decode(&raw)?;
            let part = if dbi == 3 {
                &mut record.packed
            } else {
                &mut record.payload
            };
            if part.take().is_none() {
                return Ok(false);
            }
            self.staged.insert(
                (3, pk),
                if record.packed.is_none() && record.payload.is_none() {
                    None
                } else {
                    Some(record.encode())
                },
            );
            self.touched_records.insert(u64::from_ne_bytes(
                key.try_into().map_err(|_| err("invalid local ID"))?,
            ));
        } else {
            if self.view.raw(dbi, &pk, Some(&self.staged))?.is_none() {
                return Ok(false);
            }
            if dbi == 10 {
                self.touched_postings.insert(pk.clone());
            }
            self.staged.insert((dbi, pk), None);
        }
        self.change_count(dbi, false)?;
        if cached_marker(dbi, key) {
            self.marker_values
                .entry(key.to_vec())
                .or_default()
                .retain(|v| Some(v.as_slice()) != val);
        }
        #[cfg(feature = "op-log")]
        if crate::op_log::active() {
            crate::op_log::del(&mut self.op_log, dbi, key, val);
        }
        Ok(true)
    }
    pub fn del_u64(&mut self, dbi: u32, key: u64, val: Option<&[u8]>) -> Result<bool, DbError> {
        self.del(dbi, &key.to_ne_bytes(), val)
    }
    pub fn clear(&mut self, dbi: u32) -> Result<(), DbError> {
        let records = {
            let mut c = self.cursor(dbi)?;
            let mut rows = Vec::new();
            let mut row = c.get(None, None, MDB_FIRST)?;
            while let Some((k, v)) = row {
                rows.push((k.to_vec(), v.to_vec()));
                row = c.get(None, None, MDB_NEXT)?;
            }
            rows
        };
        for (k, v) in records {
            self.del(
                dbi,
                &k,
                (spec(dbi).flags & MDB_DUPSORT != 0).then_some(v.as_slice()),
            )?;
        }
        Ok(())
    }
    fn refresh_covers(&mut self) -> Result<(), DbError> {
        let mut keys = std::mem::take(&mut self.touched_postings);
        for &id in &self.touched_records {
            let k = id.to_ne_bytes();
            let pk = encode(3, &k, None);
            for staged in [None, Some(&self.staged)] {
                if let Some(raw) = self.view.raw(3, &pk, staged)? {
                    if let Some(packed) = parts(&raw)?.0 {
                        let Ok(event) = wok_event::PackedEventView::new(packed) else {
                            continue;
                        };
                        keys.insert(encode(
                            10,
                            &crate::keys::make_key_string_u64(event.pubkey(), event.created_at()),
                            Some(&k),
                        ));
                    }
                }
            }
        }
        for pk in keys {
            let present = self.view.raw(10, &pk, Some(&self.staged))?.is_some();
            let value = if present {
                let (_, id) = decode(10, &pk, &[])?;
                // Raw maintenance/test transactions can intentionally expose damaged
                // primaries. Keep the derived cover faithful, including missing parts;
                // readers and the offline audit must observe, never hide, that damage.
                let raw = if id.len() == 8 {
                    self.view
                        .raw(3, &encode(3, &id, None), Some(&self.staged))?
                        .unwrap_or_else(|| Record::default().encode())
                } else {
                    Record::default().encode()
                };
                Some(raw)
            } else {
                None
            };
            self.staged.insert((COVER_DBI, pk), value);
        }
        Ok(())
    }
    pub fn commit(mut self) -> Result<(), DbError> {
        #[cfg(test)]
        crate::crash_tests::checkpoint("write-before-flush");
        crate::state::flush(&mut self)?;
        self.refresh_covers()?;
        let mut batch = rocksdb::WriteBatch::default();
        for ((dbi, key), value) in &self.staged {
            match value {
                Some(v) => batch.put_cf(self.view.cf(*dbi), key, v),
                None => batch.delete_cf(self.view.cf(*dbi), key),
            }
        }
        for (&dbi, &n) in &self.counts {
            batch.put(count_key(dbi), n.to_le_bytes());
        }
        let mut options = rocksdb::WriteOptions::default();
        options.set_sync(true);
        options.disable_wal(false);
        #[cfg(test)]
        crate::crash_tests::checkpoint("write-before-commit");
        if let Err(error) = self.view.env.inner.db.write_opt(batch, &options) {
            // An I/O error can make commit outcome ambiguous. Refuse new reads
            // rather than allow a stale marker mirror or spin awaiting publish.
            *self
                .view
                .env
                .inner
                .marker_state
                .lock()
                .map_err(|_| err("metadata cache mutex poisoned"))? = None;
            return Err(err(error));
        }
        let sequence = self.view.env.inner.db.latest_sequence_number();
        *self
            .view
            .env
            .inner
            .marker_state
            .lock()
            .map_err(|_| err("metadata cache mutex poisoned"))? =
            Some((sequence, Arc::new(std::mem::take(&mut self.marker_values))));
        #[cfg(test)]
        crate::crash_tests::checkpoint("write-after-commit");
        #[cfg(feature = "op-log")]
        if crate::op_log::active() {
            crate::op_log::committed(&self.op_log);
        }
        Ok(())
    }
    pub fn abort(self) {}
}
fn largest(mut c: Cursor<'_>) -> Result<u64, DbError> {
    match c.get(None, None, MDB_LAST)? {
        Some((k, _)) => Ok(u64::from_ne_bytes(
            k.try_into().map_err(|_| err("invalid integer key"))?,
        )),
        None => Ok(0),
    }
}

pub struct Cursor<'txn> {
    view: &'txn View<'txn>,
    dbi: u32,
    staged: Option<&'txn Overlay>,
    it: rocksdb::DBRawIterator<'txn>,
    current: Option<Vec<u8>>,
    logical_key: Option<Vec<u8>>,
}
impl<'txn> Cursor<'txn> {
    fn new(view: &'txn View<'txn>, dbi: u32, staged: Option<&'txn Overlay>) -> Self {
        let mut opts = rocksdb::ReadOptions::default();
        opts.set_total_order_seek(true);
        Self {
            view,
            dbi,
            staged,
            it: view.snapshot.raw_iterator_cf_opt(view.cf(dbi), opts),
            current: None,
            logical_key: None,
        }
    }
    /// Independently position and scan newest-first historical postings. The
    /// snapshot fast path borrows each physical key, reads its two integers
    /// directly and advances the native iterator. It does not populate the
    /// generic cursor's transaction-lifetime key/value arena.
    pub fn foreach_index<F>(
        &mut self,
        start_key: &[u8],
        start_dup: u64,
        mut callback: F,
    ) -> Result<bool, DbError>
    where
        F: FnMut(crate::index::IndexEntry<'_>) -> bool,
    {
        use crate::index::IndexEntry;
        if self.staged.is_some() || !matches!(self.dbi, 4 | 5 | 6 | 9 | 10 | 12 | 21 | 23) {
            return crate::index::foreach_logical(self, start_key, start_dup, callback);
        }
        let bound = encode(self.dbi, start_key, Some(&start_dup.to_ne_bytes()));
        if start_key.is_empty() {
            self.it.seek_to_first();
        } else {
            self.it.seek(&bound);
        }
        while let Some((key, value)) = self.it.item() {
            let entry = IndexEntry::from_matching_rocks(self.dbi, key, start_key, &bound)
                .or_else(|| IndexEntry::from_rocks(self.dbi, key));
            if let Some(entry) = entry {
                if self.dbi == COVER_DBI {
                    self.view.cache_record(entry.local_id()?, value);
                }
                if !callback(entry) {
                    return Ok(false);
                }
            } else {
                // Raw maintenance transactions can create noncanonical keys
                // and duplicates. Keep the generic decoder's validation and
                // historical short-key handling for those records.
                let (logical, duplicate) = decode(self.dbi, key, value)?;
                let entry = IndexEntry::from_logical(&logical, &duplicate);
                if self.dbi == COVER_DBI {
                    self.view.cache_record(entry.local_id()?, value);
                }
                if !callback(entry) {
                    return Ok(false);
                }
            }
            self.it.next();
        }
        self.it.status().map_err(err)?;
        Ok(true)
    }
    fn position(
        &mut self,
        mut bound: Option<Vec<u8>>,
        forward: bool,
        mut inclusive: bool,
    ) -> Result<Option<Kv<'txn>>, DbError> {
        loop {
            // A snapshot cursor can step directly from its current native
            // position, in either direction. Overlay cursors still seek and
            // merge: their last returned key may exist only in staged writes.
            // Unsuccessful operations restore the logical position in `get`
            // but can move/invalidate the native iterator, so check the actual
            // key before reusing it (and reseek after a failed boundary/seek).
            let on_bound = bound
                .as_deref()
                .is_some_and(|key| self.it.key() == Some(key));
            if self.staged.is_some() || !on_bound {
                match (&bound, forward) {
                    (Some(b), true) => self.it.seek(b),
                    (Some(b), false) => self.it.seek_for_prev(b),
                    (None, true) => self.it.seek_to_first(),
                    (None, false) => self.it.seek_to_last(),
                }
            }
            if !inclusive && bound.is_some() && self.it.key() == bound.as_deref() {
                if forward {
                    self.it.next();
                } else {
                    self.it.prev();
                }
            }
            self.it.status().map_err(err)?;
            let db = self.it.item().map(|(k, v)| (k.to_vec(), v.to_vec()));
            let id = physical(self.dbi);
            let staged = self.staged.and_then(|s| {
                let lo = if forward {
                    bound
                        .as_ref()
                        .map(|b| {
                            if inclusive {
                                Included((id, b.clone()))
                            } else {
                                Excluded((id, b.clone()))
                            }
                        })
                        .unwrap_or(Included((id, Vec::new())))
                } else {
                    Included((id, Vec::new()))
                };
                let hi = if !forward {
                    bound
                        .as_ref()
                        .map(|b| {
                            if inclusive {
                                Included((id, b.clone()))
                            } else {
                                Excluded((id, b.clone()))
                            }
                        })
                        .unwrap_or(Excluded((id + 1, Vec::new())))
                } else {
                    Excluded((id + 1, Vec::new()))
                };
                let mut range = s.range((lo, hi));
                let item = if forward {
                    range.next()
                } else {
                    range.next_back()
                };
                item.map(|((_, k), v)| (k.clone(), v.clone()))
            });
            let item = match (db, staged) {
                (Some(d), Some(s)) => {
                    if (forward && s.0 <= d.0) || (!forward && s.0 >= d.0) {
                        Some((s.0, s.1))
                    } else {
                        Some((d.0, Some(d.1)))
                    }
                }
                (Some(d), None) => Some((d.0, Some(d.1))),
                (None, Some(s)) => Some(s),
                (None, None) => return Ok(None),
            };
            let (pk, value) = item.unwrap();
            let Some(value) = value else {
                bound = Some(pk);
                inclusive = false;
                continue;
            };
            let (key, val) = if combined(self.dbi) {
                let (key, _) = decode(self.dbi, &pk, &[])?;
                let (a, b) = parts(&value)?;
                let Some(v) = (if self.dbi == 3 { a } else { b }) else {
                    bound = Some(pk);
                    inclusive = false;
                    continue;
                };
                (key, v.to_vec())
            } else {
                decode(self.dbi, &pk, &value)?
            };
            if self.dbi == COVER_DBI {
                let id = u64::from_ne_bytes(
                    val.as_slice()
                        .try_into()
                        .map_err(|_| err("invalid covering local ID"))?,
                );
                self.view.cache_record(id, &value);
            }
            self.current = Some(pk);
            self.logical_key = Some(key.clone());
            return Ok(Some((
                self.view.arena.alloc_slice_copy(&key),
                self.view.arena.alloc_slice_copy(&val),
            )));
        }
    }
    // First or last logical duplicate of a key, optionally accepting other keys.
    fn key_edge(&mut self, key: &[u8], first: bool) -> Result<Option<Kv<'txn>>, DbError> {
        let prefix = encode(self.dbi, key, None);
        let reverse = reversed(self.dbi);
        if first != reverse {
            self.position(Some(prefix), true, true)
        } else {
            self.position(successor(&prefix), false, false)
        }
    }
    pub fn get(
        &mut self,
        key: Option<&[u8]>,
        val: Option<&[u8]>,
        op: u32,
    ) -> Result<Option<Kv<'txn>>, DbError> {
        let previous = (self.current.clone(), self.logical_key.clone());
        let result = self.get_inner(key, val, op);
        if matches!(result, Ok(None)) {
            self.current = previous.0;
            self.logical_key = previous.1;
        }
        result
    }
    fn get_inner(
        &mut self,
        key: Option<&[u8]>,
        val: Option<&[u8]>,
        op: u32,
    ) -> Result<Option<Kv<'txn>>, DbError> {
        let rev = reversed(self.dbi);
        let current_key = self.logical_key.clone();
        match op {
            MDB_FIRST => self.position(None, !rev, true),
            MDB_LAST => self.position(None, rev, true),
            MDB_NEXT => self.position(self.current.clone(), !rev, false),
            MDB_PREV => self.position(self.current.clone(), rev, false),
            MDB_GET_CURRENT => match self.current.clone() {
                Some(k) => self.position(Some(k), true, true),
                None => Ok(None),
            },
            MDB_SET | MDB_SET_KEY | MDB_SET_RANGE => {
                let key = key.ok_or_else(|| err("missing seek key"))?;
                let row = self.key_edge(key, true)?;
                Ok(if op == MDB_SET_RANGE {
                    row
                } else {
                    row.filter(|(k, _)| *k == key)
                })
            }
            MDB_GET_BOTH | MDB_GET_BOTH_RANGE => {
                let k = key.ok_or_else(|| err("missing seek key"))?;
                let v = val.ok_or_else(|| err("missing seek duplicate"))?;
                let row = self.position(Some(encode(self.dbi, k, Some(v))), !rev, true)?;
                Ok(row.filter(|(rk, rv)| *rk == k && (op == MDB_GET_BOTH_RANGE || *rv == v)))
            }
            MDB_NEXT_DUP | MDB_PREV_DUP => {
                let row = self.position(
                    self.current.clone(),
                    if op == MDB_NEXT_DUP { !rev } else { rev },
                    false,
                )?;
                Ok(row.filter(|(k, _)| Some(*k) == current_key.as_deref()))
            }
            MDB_FIRST_DUP | MDB_LAST_DUP => match current_key {
                Some(k) => self.key_edge(&k, op == MDB_FIRST_DUP),
                None => Ok(None),
            },
            MDB_NEXT_NODUP | MDB_PREV_NODUP => {
                let Some(k) = current_key else {
                    return self.position(
                        None,
                        if op == MDB_NEXT_NODUP { !rev } else { rev },
                        true,
                    );
                };
                let prefix = encode(self.dbi, &k, None);
                if (op == MDB_NEXT_NODUP) != rev {
                    match successor(&prefix) {
                        Some(up) => self.position(Some(up), true, true),
                        None => Ok(None),
                    }
                } else {
                    self.position(Some(prefix), false, false)
                }
            }
            _ => Err(err("unsupported cursor operation")),
        }
    }
    /// Start an independent range scan, reusing this transaction's cursor.
    /// Returns false when the callback stops the scan. Each call repositions
    /// from its supplied endpoint, including after a failed or exhausted scan.
    pub fn foreach_full<F>(
        &mut self,
        key: &[u8],
        dup: &[u8],
        reverse: bool,
        cb: F,
    ) -> Result<bool, DbError>
    where
        F: FnMut(&[u8], &[u8]) -> bool,
    {
        foreach(self, key, dup, reverse, cb)
    }
    pub fn count(&mut self) -> Result<usize, DbError> {
        let Some(key) = self.logical_key.clone() else {
            return Ok(0);
        };
        let mut c = Cursor::new(self.view, self.dbi, self.staged);
        let mut row = c.get(Some(&key), None, MDB_SET_KEY)?;
        let mut n = 0;
        while row.is_some() {
            n += 1;
            row = c.get(None, None, MDB_NEXT_DUP)?;
        }
        Ok(n)
    }
}
fn foreach<F>(
    cursor: &mut Cursor<'_>,
    start_key: &[u8],
    start_dup: &[u8],
    reverse: bool,
    mut cb: F,
) -> Result<bool, DbError>
where
    F: FnMut(&[u8], &[u8]) -> bool,
{
    let dups = spec(cursor.dbi).flags & MDB_DUPSORT != 0;
    let first = if start_key.is_empty() {
        cursor.get(None, None, if reverse { MDB_LAST } else { MDB_FIRST })?
    } else if cursor.staged.is_none() && dups && !start_dup.is_empty() {
        // With a complete logical (key, duplicate) endpoint, bytewise
        // positioning already expresses the whole inclusive range. In the
        // reversed indexes, newest-first is a forward seek/step. Avoid the
        // generic exact-key/duplicate probes, which also open reverse seeks
        // on every author with no record at its requested cutoff.
        cursor.position(
            Some(encode(cursor.dbi, start_key, Some(start_dup))),
            reverse == reversed(cursor.dbi),
            true,
        )?
    } else if reverse {
        if dups {
            let at = if start_dup.is_empty() {
                None
            } else {
                cursor.get(Some(start_key), Some(start_dup), MDB_GET_BOTH_RANGE)?
            };
            if let Some((_, v)) = at {
                if v == start_dup {
                    at
                } else {
                    cursor.get(None, None, MDB_PREV)?
                }
            } else if cursor.get(Some(start_key), None, MDB_SET_KEY)?.is_some() {
                cursor.get(None, None, MDB_LAST_DUP)?
            } else if cursor.get(Some(start_key), None, MDB_SET_RANGE)?.is_some() {
                cursor.get(None, None, MDB_PREV)?
            } else {
                cursor.get(None, None, MDB_LAST)?
            }
        } else if let Some((k, v)) = cursor.get(Some(start_key), None, MDB_SET_RANGE)? {
            if k == start_key {
                Some((k, v))
            } else {
                cursor.get(None, None, MDB_PREV)?
            }
        } else {
            cursor.get(None, None, MDB_LAST)?
        }
    } else if dups {
        if !start_dup.is_empty() {
            if let Some(row) = cursor.get(Some(start_key), Some(start_dup), MDB_GET_BOTH_RANGE)? {
                Some(row)
            } else if cursor.get(Some(start_key), None, MDB_SET_KEY)?.is_some() {
                cursor.get(None, None, MDB_NEXT_NODUP)?
            } else {
                cursor.get(Some(start_key), None, MDB_SET_RANGE)?
            }
        } else if cursor.get(Some(start_key), None, MDB_SET_KEY)?.is_some() {
            cursor.get(None, None, MDB_NEXT_NODUP)?
        } else {
            cursor.get(Some(start_key), None, MDB_SET_RANGE)?
        }
    } else {
        cursor.get(Some(start_key), None, MDB_SET_RANGE)?
    };
    let mut row = first;
    while let Some((k, v)) = row {
        if !cb(k, v) {
            return Ok(false);
        }
        row = cursor.get(None, None, if reverse { MDB_PREV } else { MDB_NEXT })?;
    }
    Ok(true)
}

#[cfg(test)]
mod index_reader_tests {
    use super::*;
    use rocksdb::perf::{set_perf_stats, PerfContext, PerfMetric, PerfStatsLevel};

    #[test]
    fn native_postings_step_without_retaining_logical_candidate_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), crate::EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let dbi = env.dbis().event_pubkey;
        let prefix = [0; 32];
        let mut tx = env.begin_rw().unwrap();
        for id in 1..=2048u64 {
            tx.put(
                dbi,
                &crate::keys::make_key_string_u64(&prefix, id),
                &id.to_ne_bytes(),
                0,
            )
            .unwrap();
        }
        tx.commit().unwrap();
        let tx = env.begin_ro().unwrap();
        let mut cursor = tx.cursor(dbi).unwrap();
        let before = tx.view.arena.allocated_bytes();
        set_perf_stats(PerfStatsLevel::EnableCount);
        let mut perf = PerfContext::default();
        perf.reset();
        let mut expected = 2048;
        cursor
            .foreach_index(
                &crate::keys::make_key_string_u64(&prefix, u64::MAX),
                u64::MAX,
                |entry| {
                    assert_eq!(
                        (entry.created_at.unwrap(), entry.local_id().unwrap()),
                        (expected, expected)
                    );
                    assert!(entry.prefix_matches(&prefix, true));
                    expected -= 1;
                    true
                },
            )
            .unwrap();
        let seeks = perf.metric(PerfMetric::SeekOnMemtableCount)
            + perf.metric(PerfMetric::SeekChildSeekCount);
        let steps = perf.metric(PerfMetric::NextOnMemtableCount);
        set_perf_stats(PerfStatsLevel::Disable);
        assert_eq!(expected, 0);
        assert_eq!(tx.view.arena.allocated_bytes(), before);
        assert!(
            seeks <= 2,
            "native scan re-sought its consecutive postings: {seeks}"
        );
        assert!(
            steps >= 2048,
            "native scan did not step its iterator: {steps}"
        );
    }
}
