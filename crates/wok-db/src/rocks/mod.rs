//! Experimental optimized RocksDB layout. All relay policy remains in Wok.
//! Bytewise ordered indexes are globally reversed, so newest-first logical
//! scans advance forward physically. Event/payload components share one record;
//! Author reads have a covering index while feeds retain thin postings, unless
//! the separate `rocksdb-coverless` physical layout is selected at build time.
#![forbid(unsafe_code)]

mod audit;
#[cfg(feature = "rocksdb-author-heads")]
pub(crate) mod author_heads;

use crate::schema::{dbi_specs, ComparatorKind};
use crate::DbError;
use lmdb_sys::*;

/// Only two reserved metadata keys; keep all duplicates to preserve raw API semantics.
pub(crate) type MarkerMap = std::collections::BTreeMap<Vec<u8>, Vec<Vec<u8>>>;
pub(crate) type MarkerState = (u64, std::sync::Arc<MarkerMap>);
pub(crate) fn cached_marker(dbi: u32, key: &[u8]) -> bool {
    dbi == 21 && crate::tag_kind::is_tag_kind_marker(key)
}
pub(crate) fn sort_marker_values(key: &[u8], values: &mut [Vec<u8>]) {
    values.sort_by(|a, b| {
        encode(21, key, Some(a))
            .cmp(&encode(21, key, Some(b)))
            .reverse()
    });
}
/// Forward, prefix-bounded bootstrap avoids reverse traversal over tombstone
/// histories. It runs before this Env is exposed to relay threads, never on a
/// marker read or publication. No data/format migration or forced flush occurs.
pub(crate) fn load_markers(db: &rocksdb::DB) -> Result<MarkerMap, DbError> {
    let cf = db
        .cf_handle(cf_name(21))
        .ok_or_else(|| err("missing marker CF"))?;
    let mut result = MarkerMap::new();
    for key in [b"\0schema".as_slice(), b"\0through".as_slice()] {
        let prefix = encode(21, key, None);
        let mut options = rocksdb::ReadOptions::default();
        options.set_total_order_seek(true);
        options.set_iterate_lower_bound(prefix.clone());
        if let Some(upper) = successor(&prefix) {
            options.set_iterate_upper_bound(upper);
        }
        #[cfg(feature = "rocksdb-read-diagnostics")]
        crate::read_diagnostics::record(|c| c.iterator_creations += 1);
        let mut it = db.raw_iterator_cf_opt(cf, options);
        #[cfg(feature = "rocksdb-read-diagnostics")]
        crate::read_diagnostics::record(|c| c.seek += 1);
        it.seek(&prefix);
        let mut values = Vec::new();
        while let Some((physical, value)) = it.item() {
            let (found, dup) = decode(21, physical, value)?;
            if found != key {
                break;
            }
            values.push(dup);
            #[cfg(feature = "rocksdb-read-diagnostics")]
            crate::read_diagnostics::record(|c| c.next += 1);
            it.next();
        }
        it.status().map_err(err)?;
        sort_marker_values(key, &mut values);
        result.insert(key.to_vec(), values);
    }
    Ok(result)
}

pub(crate) const COMBINED: &str = "wok_events_combined_v1";
pub(crate) const COVERING: &str = "wok_pubkey_covering_v1";
#[cfg(feature = "rocksdb-author-heads")]
pub(crate) const HEAD_CF: &str = "wok_author_frontiers_v1";
pub(crate) const COVER_DBI: u32 = 23;
pub(crate) const FORMAT_KEY: &[u8] = b"wok-rocksdb-format";
#[cfg(not(feature = "rocksdb-coverless"))]
pub(crate) const FORMAT: &[u8] = b"wok-rocks-v1:combined:dual-author:reverse-order:sync-wal";
#[cfg(all(feature = "rocksdb-coverless", not(feature = "rocksdb-author-heads")))]
pub(crate) const FORMAT: &[u8] = b"wok-rocks-v2:combined:thin-author:reverse-order:sync-wal";
#[cfg(feature = "rocksdb-author-heads")]
pub(crate) const FORMAT: &[u8] =
    b"wok-rocks-v3:combined:thin-author-frontiers:reverse-order:sync-wal";

/// Exact physical CF set for this binary; logical Event/Payload share COMBINED.
pub(crate) fn physical_cf_names() -> Vec<&'static str> {
    let mut names = vec!["default", COMBINED];
    if !cfg!(feature = "rocksdb-coverless") {
        names.push(COVERING);
    }
    #[cfg(feature = "rocksdb-author-heads")]
    names.push(HEAD_CF);
    names.extend(
        dbi_specs()
            .iter()
            .filter(|s| {
                s.name != crate::schema::DBI_EVENT && s.name != crate::schema::DBI_EVENT_PAYLOAD
            })
            .map(|s| s.name),
    );
    names
}

pub(crate) fn validate_dbi(dbi: u32) -> Result<(), DbError> {
    if cfg!(feature = "rocksdb-coverless") && dbi == COVER_DBI {
        return Err(err("covering index is absent in the coverless layout"));
    }
    Ok(())
}
pub(crate) fn err(e: impl std::fmt::Display) -> DbError {
    DbError::msg(format!("rocksdb: {e}"))
}
pub(crate) fn spec(dbi: u32) -> &'static crate::schema::DbiSpec {
    &dbi_specs()[if dbi == COVER_DBI {
        9
    } else {
        (dbi - 1) as usize
    }]
}
pub(crate) fn combined(dbi: u32) -> bool {
    dbi == 3 || dbi == 15
}
pub(crate) fn cf_name(dbi: u32) -> &'static str {
    if combined(dbi) {
        COMBINED
    } else if dbi == COVER_DBI {
        COVERING
    } else {
        spec(dbi).name
    }
}
pub(crate) fn reversed(dbi: u32) -> bool {
    spec(dbi).flags & MDB_DUPSORT != 0
}
pub(crate) fn successor(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut out = prefix.to_vec();
    while let Some(b) = out.pop() {
        if b != 255 {
            out.push(b + 1);
            return Some(out);
        }
    }
    None
}
fn escape(raw: &[u8], out: &mut Vec<u8>) {
    for &b in raw {
        if b == 0 {
            out.extend_from_slice(&[0, 255]);
        } else {
            out.push(b);
        }
    }
    out.extend_from_slice(&[0, 0]);
}
fn unescape(raw: &[u8], at: &mut usize) -> Result<Vec<u8>, DbError> {
    let mut out = Vec::new();
    while *at < raw.len() {
        let b = raw[*at];
        *at += 1;
        if b != 0 {
            out.push(b);
            continue;
        }
        let c = *raw.get(*at).ok_or_else(|| err("truncated escaped key"))?;
        *at += 1;
        match c {
            0 => return Ok(out),
            255 => out.push(0),
            _ => return Err(err("invalid escaped key")),
        }
    }
    Err(err("unterminated escaped key"))
}
pub(crate) fn key_prefix(dbi: u32, key: &[u8]) -> Vec<u8> {
    let s = spec(dbi);
    let mut out = Vec::new();
    let ints = match s.comparator {
        ComparatorKind::StringUint64 => 1,
        ComparatorKind::StringUint64Uint64 | ComparatorKind::Uint64Uint64 => 2,
        _ => 0,
    };
    if ints != 0 {
        let valid = key.len() >= ints * 8
            && (s.comparator != ComparatorKind::Uint64Uint64 || key.len() == 16);
        out.push(u8::from(valid));
        if !valid {
            escape(key, &mut out);
        } else {
            if s.comparator != ComparatorKind::Uint64Uint64 {
                escape(&key[..key.len() - ints * 8], &mut out);
            }
            for n in key[key.len() - ints * 8..].chunks_exact(8) {
                out.extend_from_slice(&u64::from_ne_bytes(n.try_into().unwrap()).to_be_bytes());
            }
        }
    } else if s.flags & MDB_INTEGERKEY != 0 {
        out.push(u8::from(key.len() == 8));
        if key.len() == 8 {
            out.extend_from_slice(&u64::from_ne_bytes(key.try_into().unwrap()).to_be_bytes());
        } else {
            escape(key, &mut out);
        }
    } else if s.flags & MDB_REVERSEKEY != 0 {
        escape(&key.iter().rev().copied().collect::<Vec<_>>(), &mut out);
    } else {
        escape(key, &mut out);
    }
    out
}
pub(crate) fn encode(dbi: u32, key: &[u8], dup: Option<&[u8]>) -> Vec<u8> {
    let mut out = key_prefix(dbi, key);
    if let Some(v) = dup {
        if spec(dbi).flags & MDB_INTEGERDUP != 0 && v.len() == 8 {
            out.push(1);
            out.extend_from_slice(&u64::from_ne_bytes(v.try_into().unwrap()).to_be_bytes());
        } else {
            if spec(dbi).flags & MDB_INTEGERDUP != 0 {
                out.push(0);
            }
            escape(v, &mut out);
        }
    }
    if reversed(dbi) {
        for b in &mut out {
            *b = !*b;
        }
    }
    #[cfg(feature = "rocksdb-read-diagnostics")]
    crate::read_diagnostics::record(|c| {
        c.ordered_key_encodes += 1;
        c.ordered_key_bytes += out.len() as u64;
    });
    out
}
pub(crate) fn decode(dbi: u32, raw: &[u8], value: &[u8]) -> Result<(Vec<u8>, Vec<u8>), DbError> {
    #[cfg(feature = "rocksdb-read-diagnostics")]
    crate::read_diagnostics::record(|c| c.logical_decode_calls += 1);
    let bytes: Vec<u8> = raw
        .iter()
        .map(|b| if reversed(dbi) { !*b } else { *b })
        .collect();
    let raw = &bytes[..];
    let s = spec(dbi);
    let mut at = 0;
    let mut key = Vec::new();
    let ints = match s.comparator {
        ComparatorKind::StringUint64 => 1,
        ComparatorKind::StringUint64Uint64 | ComparatorKind::Uint64Uint64 => 2,
        _ => 0,
    };
    if ints != 0 || s.flags & MDB_INTEGERKEY != 0 {
        let valid = *raw.first().ok_or_else(|| err("empty key"))?;
        at = 1;
        if valid == 0 {
            key = unescape(raw, &mut at)?;
        } else if valid == 1 {
            if ints != 0 && s.comparator != ComparatorKind::Uint64Uint64 {
                key = unescape(raw, &mut at)?;
            }
            for _ in 0..ints.max(1) {
                let n = raw
                    .get(at..at + 8)
                    .ok_or_else(|| err("truncated integer key"))?;
                key.extend_from_slice(&u64::from_be_bytes(n.try_into().unwrap()).to_ne_bytes());
                at += 8;
            }
        } else {
            return Err(err("invalid key header"));
        }
    } else {
        key = unescape(raw, &mut at)?;
        if s.flags & MDB_REVERSEKEY != 0 {
            key.reverse();
        }
    }
    let val = if s.flags & MDB_DUPSORT != 0 {
        if s.flags & MDB_INTEGERDUP != 0 {
            let valid = *raw.get(at).ok_or_else(|| err("missing duplicate header"))?;
            at += 1;
            if valid == 0 {
                unescape(raw, &mut at)?
            } else if valid == 1 {
                let n = raw
                    .get(at..at + 8)
                    .ok_or_else(|| err("truncated duplicate"))?;
                at += 8;
                u64::from_be_bytes(n.try_into().unwrap())
                    .to_ne_bytes()
                    .to_vec()
            } else {
                return Err(err("invalid duplicate header"));
            }
        } else {
            unescape(raw, &mut at)?
        }
    } else {
        value.to_vec()
    };
    if at != raw.len() {
        return Err(err("trailing key bytes"));
    }
    Ok((key, val))
}
#[derive(Default, Clone)]
pub(crate) struct Record {
    pub packed: Option<Vec<u8>>,
    pub payload: Option<Vec<u8>>,
}
type Components<'a> = (Option<&'a [u8]>, Option<&'a [u8]>);
pub(crate) fn parts(mut raw: &[u8]) -> Result<Components<'_>, DbError> {
    fn part<'a>(raw: &mut &'a [u8]) -> Result<Option<&'a [u8]>, DbError> {
        let n = raw.get(..4).ok_or_else(|| err("short combined record"))?;
        let n = u32::from_le_bytes(n.try_into().unwrap());
        *raw = &raw[4..];
        if n == u32::MAX {
            return Ok(None);
        }
        let n = n as usize;
        let v = raw
            .get(..n)
            .ok_or_else(|| err("short combined component"))?;
        *raw = &raw[n..];
        Ok(Some(v))
    }
    let result = (part(&mut raw)?, part(&mut raw)?);
    if !raw.is_empty() {
        return Err(err("trailing combined bytes"));
    }
    Ok(result)
}
impl Record {
    pub fn decode(raw: &[u8]) -> Result<Self, DbError> {
        let (packed, payload) = parts(raw)?;
        Ok(Self {
            packed: packed.map(<[u8]>::to_vec),
            payload: payload.map(<[u8]>::to_vec),
        })
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for v in [&self.packed, &self.payload] {
            out.extend_from_slice(
                &v.as_ref()
                    .map_or(u32::MAX, |v| v.len() as u32)
                    .to_le_bytes(),
            );
            if let Some(v) = v {
                out.extend_from_slice(v);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Env, EnvOptions};
    use proptest::prelude::*;
    fn compare(dbi: u32, a: &[u8], b: &[u8]) -> std::cmp::Ordering {
        use crate::comparators::*;
        let s = spec(dbi);
        match s.comparator {
            ComparatorKind::StringUint64 => cmp_string_u64(a, b),
            ComparatorKind::StringUint64Uint64 => cmp_string_u64_u64(a, b),
            ComparatorKind::Uint64Uint64 => cmp_u64_u64(a, b),
            _ if s.flags & MDB_INTEGERKEY != 0 => u64_from_ne(a).cmp(&u64_from_ne(b)),
            _ if s.flags & MDB_REVERSEKEY != 0 => a.iter().rev().cmp(b.iter().rev()),
            _ => a.cmp(b),
        }
    }
    proptest! {
        #[test]
        fn ordered_codec_preserves_every_table_comparator(a in prop::collection::vec(any::<u8>(),0..48),b in prop::collection::vec(any::<u8>(),0..48),x in any::<u64>(),y in any::<u64>(),d1 in any::<u64>(),d2 in any::<u64>()){
            for dbi in 1..=22{
                let key=|p:&[u8],n:u64|{
                    match spec(dbi).comparator {
                        ComparatorKind::StringUint64=>crate::keys::make_key_string_u64(p,n),
                        ComparatorKind::StringUint64Uint64=>crate::keys::make_key_string_u64_u64(p,n,n),
                        ComparatorKind::Uint64Uint64=>crate::keys::make_key_u64_u64(n,n),
                        _ if spec(dbi).flags & MDB_INTEGERKEY!=0=>n.to_ne_bytes().to_vec(),
                        _=>p.to_vec(),
                    }
                };
                let(ka,kb)=(key(&a,x),key(&b,y));let dup=spec(dbi).flags & MDB_DUPSORT!=0;
                let da=d1.to_ne_bytes();let db=d2.to_ne_bytes();
                let ea=encode(dbi,&ka,dup.then_some(&da));let eb=encode(dbi,&kb,dup.then_some(&db));
                let want=compare(dbi,&ka,&kb).then(if dup{d1.cmp(&d2)}else{std::cmp::Ordering::Equal});
                prop_assert_eq!(if reversed(dbi){ea.cmp(&eb).reverse()}else{ea.cmp(&eb)},want);
                let (k,v)=decode(dbi,&ea,b"value").unwrap();prop_assert_eq!(k,ka);
                prop_assert_eq!(v,if dup{da.to_vec()}else{b"value".to_vec()});
            }
        }
    }
    #[test]
    fn transaction_abort_read_your_writes_and_snapshot_isolation() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let dbi = env.dbis().state.unwrap();
        let old = env.begin_ro().unwrap();
        {
            let mut tx = env.begin_rw().unwrap();
            tx.put(dbi, b"a", b"one", 0).unwrap();
            assert_eq!(tx.get(dbi, b"a").unwrap(), Some(&b"one"[..]));
            tx.abort();
        }
        assert!(env.begin_ro().unwrap().get(dbi, b"a").unwrap().is_none());
        let mut tx = env.begin_rw().unwrap();
        tx.put(dbi, b"a", b"one", 0).unwrap();
        tx.put(dbi, b"b", b"two", 0).unwrap();
        tx.put(dbi, b"a", b"changed", 0).unwrap();
        let mut c = tx.cursor(dbi).unwrap();
        assert_eq!(
            c.get(Some(b"a"), None, MDB_SET_KEY).unwrap().unwrap().1,
            b"changed"
        );
        drop(c);
        tx.commit().unwrap();
        assert!(old.get(dbi, b"a").unwrap().is_none());
        assert_eq!(
            env.begin_ro().unwrap().get(dbi, b"a").unwrap(),
            Some(&b"changed"[..])
        );
    }
    #[test]
    fn combined_components_are_distinct_and_abort_is_atomic() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let db = env.dbis();
        let mut tx = env.begin_rw().unwrap();
        tx.put_u64(db.event, 1, b"packed", 0).unwrap();
        tx.put_u64(db.event_payload, 1, b"payload", 0).unwrap();
        tx.commit().unwrap();
        let before = env.begin_ro().unwrap();
        assert_eq!(before.entries(db.event).unwrap(), 1);
        assert_eq!(before.entries(db.event_payload).unwrap(), 1);
        let mut tx = env.begin_rw().unwrap();
        tx.del_u64(db.event, 1, None).unwrap();
        assert!(tx.get_u64(db.event, 1).unwrap().is_none());
        assert_eq!(
            tx.get_u64(db.event_payload, 1).unwrap(),
            Some(&b"payload"[..])
        );
        tx.abort();
        let mut tx = env.begin_rw().unwrap();
        tx.clear(db.event).unwrap();
        tx.commit().unwrap();
        let after = env.begin_ro().unwrap();
        assert_eq!(after.entries(db.event).unwrap(), 0);
        assert_eq!(after.entries(db.event_payload).unwrap(), 1);
        assert_eq!(
            after.get_u64(db.event_payload, 1).unwrap(),
            Some(&b"payload"[..])
        );
        assert_eq!(before.get_u64(db.event, 1).unwrap(), Some(&b"packed"[..]));
    }
    #[test]
    fn refuses_lmdb_and_unrecognized_nonempty_paths() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("data.mdb"), b"untouched").unwrap();
        assert!(Env::open(dir.path(), EnvOptions::for_tests()).is_err());
        assert_eq!(
            std::fs::read(dir.path().join("data.mdb")).unwrap(),
            b"untouched"
        );
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("other"), b"untouched").unwrap();
        assert!(Env::open(dir.path(), EnvOptions::for_tests()).is_err());
    }
    #[test]
    fn rejects_malformed_primary_keys_and_competing_writers() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let mut txn = env.begin_rw().unwrap();
        assert!(txn
            .put(env.dbis().event, &1u32.to_ne_bytes(), b"packed", 0)
            .is_err());
        txn.abort();
        assert!(Env::open(dir.path(), EnvOptions::for_tests()).is_err());
    }
    #[test]
    fn hot_marker_reads_do_not_seek_through_deleted_duplicate_histories() {
        use rocksdb::perf::{set_perf_stats, PerfContext, PerfMetric, PerfStatsLevel};
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let key = b"\0through";
        let cf = env.inner.db.cf_handle(cf_name(21)).unwrap();
        let mut batch = rocksdb::WriteBatch::default();
        for n in 0..20000u64 {
            batch.delete_cf(cf, encode(21, key, Some(&n.to_ne_bytes())));
        }
        batch.put_cf(cf, encode(21, key, Some(&20000u64.to_ne_bytes())), []);
        let mut options = rocksdb::WriteOptions::default();
        options.set_sync(true);
        env.inner.db.write_opt(batch, &options).unwrap();
        // Reopen is the same bounded-forward bootstrap used on existing v1 seeds.
        drop(env);
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
        let txn = env.begin_ro().unwrap();
        set_perf_stats(PerfStatsLevel::EnableCount);
        let mut perf = PerfContext::default();
        perf.reset();
        let got = txn.get(21, key).unwrap().unwrap().to_vec();
        let compares = perf.metric(PerfMetric::UserKeyComparisonCount);
        let seeks = perf.metric(PerfMetric::SeekOnMemtableCount)
            + perf.metric(PerfMetric::SeekChildSeekCount);
        set_perf_stats(PerfStatsLevel::Disable);
        assert_eq!(got, 20000u64.to_ne_bytes());
        assert_eq!(compares, 0, "marker read entered RocksDB");
        assert_eq!(seeks, 0, "marker read opened a prefix iterator");
    }
    #[test]
    fn marker_mirror_preserves_duplicate_order_abort_and_old_snapshots() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let old = env.begin_ro().unwrap();
        let key = b"\0through";
        let mut txn = env.begin_rw().unwrap();
        txn.del(21, key, None).unwrap();
        txn.put(21, key, &9u64.to_ne_bytes(), 0).unwrap();
        txn.put(21, key, &3u64.to_ne_bytes(), 0).unwrap();
        assert_eq!(
            txn.get(21, key).unwrap(),
            Some(3u64.to_ne_bytes().as_slice())
        );
        txn.del(21, key, Some(&3u64.to_ne_bytes())).unwrap();
        assert_eq!(
            txn.get(21, key).unwrap(),
            Some(9u64.to_ne_bytes().as_slice())
        );
        txn.abort();
        assert_eq!(
            env.begin_ro().unwrap().get(21, key).unwrap(),
            Some(0u64.to_ne_bytes().as_slice())
        );
        let mut txn = env.begin_rw().unwrap();
        txn.del(21, key, None).unwrap();
        txn.put(21, key, &7u64.to_ne_bytes(), 0).unwrap();
        txn.commit().unwrap();
        assert_eq!(
            old.get(21, key).unwrap(),
            Some(0u64.to_ne_bytes().as_slice())
        );
        assert_eq!(
            env.begin_ro().unwrap().get(21, key).unwrap(),
            Some(7u64.to_ne_bytes().as_slice())
        );
    }
    #[test]
    fn marker_mirror_and_database_snapshot_publish_the_same_commit() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                for n in 1..=1000u64 {
                    let mut txn = env.begin_rw().unwrap();
                    txn.del(21, b"\0through", None).unwrap();
                    txn.put(21, b"\0through", &n.to_ne_bytes(), 0).unwrap();
                    txn.put(20, b"marker-test-sequence", &n.to_ne_bytes(), 0)
                        .unwrap();
                    txn.commit().unwrap();
                }
            });
            for _ in 0..5000 {
                let txn = env.begin_ro().unwrap();
                let marker = txn.get(21, b"\0through").unwrap().unwrap();
                let data = txn
                    .get(20, b"marker-test-sequence")
                    .unwrap()
                    .unwrap_or(&[0; 8]);
                assert_eq!(
                    marker, data,
                    "metadata mirror crossed a RocksDB snapshot boundary"
                );
            }
        });
    }
}
