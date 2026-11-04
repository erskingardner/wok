#![cfg(feature = "rocksdb-backend")]
//! Snapshot cursor traversal, including recovery after unsuccessful operations.

use lmdb_sys::*;
use proptest::prelude::*;
use rocksdb::perf::{set_perf_stats, PerfContext, PerfMetric, PerfStatsLevel};
use wok_db::txn::Cursor;
use wok_db::{Env, EnvOptions};

fn owned(row: Option<(&[u8], &[u8])>) -> Option<(Vec<u8>, Vec<u8>)> {
    row.map(|(k, v)| (k.to_vec(), v.to_vec()))
}

fn at(cursor: &mut Cursor<'_>, op: u32) -> Option<(u64, u64)> {
    cursor.get(None, None, op).unwrap().map(|(k, v)| {
        (
            u64::from_ne_bytes(k.try_into().unwrap()),
            u64::from_ne_bytes(v.try_into().unwrap()),
        )
    })
}

#[test]
fn unpositioned_steps_on_empty_indexes_return_none() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let tx = env.begin_ro().unwrap();
    for dbi in [env.dbis().event, env.dbis().event_created_at] {
        let mut c = tx.cursor(dbi).unwrap();
        for op in [MDB_NEXT, MDB_PREV, MDB_FIRST, MDB_LAST, MDB_GET_CURRENT] {
            assert!(c.get(None, None, op).unwrap().is_none());
        }
    }
}

#[test]
fn failed_duplicate_steps_and_seeks_preserve_the_last_returned_position() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let dbi = env.dbis().event_created_at;
    let mut tx = env.begin_rw().unwrap();
    for (k, v) in [(10u64, 1u64), (10, 2), (20, 3), (20, 4)] {
        tx.put_u64(dbi, k, &v.to_ne_bytes(), 0).unwrap();
    }
    tx.commit().unwrap();
    let tx = env.begin_ro().unwrap();
    let mut c = tx.cursor(dbi).unwrap();
    assert_eq!(at(&mut c, MDB_LAST), Some((20, 4)));
    assert_eq!(at(&mut c, MDB_PREV_DUP), Some((20, 3)));
    assert_eq!(at(&mut c, MDB_PREV_DUP), None);
    assert_eq!(at(&mut c, MDB_GET_CURRENT), Some((20, 3)));
    assert_eq!(at(&mut c, MDB_NEXT_DUP), Some((20, 4)));
    assert_eq!(at(&mut c, MDB_NEXT), None);
    assert_eq!(at(&mut c, MDB_PREV), Some((20, 3)));
    assert!(c
        .get(Some(&15u64.to_ne_bytes()), None, MDB_SET_KEY)
        .unwrap()
        .is_none());
    assert_eq!(at(&mut c, MDB_PREV), Some((10, 2)));
    assert!(c
        .get(
            Some(&10u64.to_ne_bytes()),
            Some(&9u64.to_ne_bytes()),
            MDB_GET_BOTH_RANGE
        )
        .unwrap()
        .is_none());
    assert_eq!(at(&mut c, MDB_NEXT), Some((20, 3)));
    assert_eq!(at(&mut c, MDB_PREV), Some((10, 2)));
    assert_eq!(at(&mut c, MDB_FIRST_DUP), Some((10, 1)));
    assert_eq!(at(&mut c, MDB_PREV), None);
    assert_eq!(at(&mut c, MDB_NEXT_NODUP), Some((20, 3)));
    assert_eq!(at(&mut c, MDB_PREV_NODUP), Some((10, 2)));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]
    #[test]
    fn snapshot_walk_matches_the_seeking_writer_cursor(
        operations in proptest::collection::vec((0u8..15, 0u64..10, 0u64..6), 1..192),
    ) {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let mut tx = env.begin_rw().unwrap();
        let plain = env.dbis().state.unwrap();
        let dup = env.dbis().event_created_at;
        for k in [1u64, 3, 5, 7] {
            tx.put(plain, &[b'a' + k as u8], &[k as u8], 0).unwrap();
            for v in [1u64, 3, 5] {
                tx.put_u64(dup, k, &v.to_ne_bytes(), 0).unwrap();
            }
            // Each component is independently present. Traversal must skip
            // the other component's records in the combined column family.
            if k != 3 { tx.put_u64(env.dbis().event, k, &[k as u8], 0).unwrap(); }
            if k != 5 { tx.put_u64(env.dbis().event_payload, k, &[k as u8 + 10], 0).unwrap(); }
        }
        tx.commit().unwrap();
        let ro = env.begin_ro().unwrap();
        let rw = env.begin_rw().unwrap();
        let ops = [MDB_FIRST, MDB_LAST, MDB_NEXT, MDB_PREV, MDB_GET_CURRENT,
            MDB_SET_KEY, MDB_SET_RANGE, MDB_GET_BOTH, MDB_GET_BOTH_RANGE,
            MDB_NEXT_DUP, MDB_PREV_DUP, MDB_FIRST_DUP, MDB_LAST_DUP,
            MDB_NEXT_NODUP, MDB_PREV_NODUP];
        for dbi in [plain, dup, env.dbis().event, env.dbis().event_payload] {
            let mut fast = ro.cursor(dbi).unwrap();
            let mut reference = rw.cursor(dbi).unwrap();
            for &(op, k, v) in &operations {
                let op = ops[if dbi == dup { op as usize } else { op as usize % 7 }];
                let key = if dbi == plain { vec![b'a' + k as u8] } else { k.to_ne_bytes().to_vec() };
                let val = v.to_ne_bytes();
                prop_assert_eq!(
                    owned(fast.get(Some(&key), Some(&val), op).unwrap()),
                    owned(reference.get(Some(&key), Some(&val), op).unwrap()),
                    "dbi {} op {} key {} val {}", dbi, op, k, v,
                );
            }
        }
    }
}

#[test]
fn traversal_keeps_snapshot_and_borrowed_bytes_across_commits_and_repositioning() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let dbi = env.dbis().state.unwrap();
    let mut tx = env.begin_rw().unwrap();
    for k in *b"abc" {
        tx.put(dbi, &[k], &[k, 0, 255], 0).unwrap();
    }
    tx.commit().unwrap();
    let old = env.begin_ro().unwrap();
    let mut c = old.cursor(dbi).unwrap();
    let borrowed = c.get(None, None, MDB_FIRST).unwrap().unwrap();
    let mut tx = env.begin_rw().unwrap();
    tx.del(dbi, b"b", None).unwrap();
    tx.put(dbi, b"c", b"changed", 0).unwrap();
    tx.commit().unwrap();
    assert_eq!(
        c.get(None, None, MDB_NEXT).unwrap().unwrap(),
        (b"b".as_slice(), &[b'b', 0, 255][..])
    );
    assert_eq!(
        c.get(None, None, MDB_NEXT).unwrap().unwrap(),
        (b"c".as_slice(), &[b'c', 0, 255][..])
    );
    assert!(c.get(Some(b"z"), None, MDB_SET_RANGE).unwrap().is_none());
    assert_eq!(c.get(None, None, MDB_PREV).unwrap().unwrap().0, b"b");
    drop(c);
    assert_eq!(borrowed, (b"a".as_slice(), &[b'a', 0, 255][..]));
    let new = env.begin_ro().unwrap();
    let mut c = new.cursor(dbi).unwrap();
    assert_eq!(c.get(None, None, MDB_FIRST).unwrap().unwrap().0, b"a");
    assert_eq!(c.get(None, None, MDB_NEXT).unwrap().unwrap().1, b"changed");
}

#[test]
fn sequential_snapshot_steps_do_not_reseek() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let dbi = env.dbis().event_created_at;
    let mut tx = env.begin_rw().unwrap();
    for k in 0..32u64 {
        for v in 0..64u64 {
            tx.put_u64(dbi, k, &v.to_ne_bytes(), 0).unwrap();
        }
    }
    tx.commit().unwrap();
    let tx = env.begin_ro().unwrap();
    for (edge, step) in [(MDB_LAST, MDB_PREV), (MDB_FIRST, MDB_NEXT)] {
        let mut c = tx.cursor(dbi).unwrap();
        assert!(c.get(None, None, edge).unwrap().is_some());
        set_perf_stats(PerfStatsLevel::EnableCount);
        let mut perf = PerfContext::default();
        perf.reset();
        let started = std::time::Instant::now();
        let mut rows = 1;
        while c.get(None, None, step).unwrap().is_some() {
            rows += 1;
        }
        let elapsed = started.elapsed();
        let seeks = perf.metric(PerfMetric::SeekOnMemtableCount)
            + perf.metric(PerfMetric::SeekChildSeekCount);
        let next = perf.metric(PerfMetric::NextOnMemtableCount);
        let prev = perf.metric(PerfMetric::PrevOnMemtableCount);
        set_perf_stats(PerfStatsLevel::Disable);
        eprintln!(
            "step={step} rows={rows} seeks={seeks} next={next} prev={prev} elapsed_us={}",
            elapsed.as_micros()
        );
        assert_eq!(rows, 2048);
        assert_eq!(
            seeks, 0,
            "sequential snapshot steps re-entered RocksDB seek"
        );
    }
}
