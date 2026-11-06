//! Positioning semantics of `foreach_full` against C++ `generic_foreachFull`.

use tempfile::TempDir;
use wok_db::{Env, EnvOptions};

/// Build an env whose `Event__created_at` index has:
///   key 100 -> dups {1, 2}
///   key 200 -> dups {3}
fn env_with_created_at_dups() -> Env {
    let tmp = TempDir::new().unwrap();
    // Keep the tempdir so the env path outlives the test setup; tests are
    // short-lived processes so this is fine.
    let path = tmp.keep();
    let env = Env::open(&path, EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let mut txn = env.begin_rw().unwrap();
    let dbi = env.dbis().event_created_at;
    for (k, v) in [(100u64, 1u64), (100, 2), (200, 3)] {
        txn.put_u64(dbi, k, &v.to_ne_bytes(), 0).unwrap();
    }
    txn.commit().unwrap();
    env
}

#[test]
fn forward_scan_from_mid_dup_starts_at_dup() {
    let env = env_with_created_at_dups();
    let txn = env.begin_ro().unwrap();
    let mut seen = Vec::new();
    txn.foreach_full(
        env.dbis().event_created_at,
        &100u64.to_ne_bytes(),
        &2u64.to_ne_bytes(),
        false,
        |k, v| {
            seen.push((
                u64::from_ne_bytes(k.try_into().unwrap()),
                u64::from_ne_bytes(v.try_into().unwrap()),
            ));
            true
        },
    )
    .unwrap();
    assert_eq!(seen, vec![(100, 2), (200, 3)]);
}

#[test]
fn forward_scan_past_last_dup_skips_to_next_key() {
    let env = env_with_created_at_dups();
    let txn = env.begin_ro().unwrap();
    let mut seen = Vec::new();
    // Key 100 exists, but all its dups sort before 5. C++ generic_foreachFull
    // does MDB_NEXT_NODUP here: the first yielded record must be (200, 3).
    txn.foreach_full(
        env.dbis().event_created_at,
        &100u64.to_ne_bytes(),
        &5u64.to_ne_bytes(),
        false,
        |k, v| {
            seen.push((
                u64::from_ne_bytes(k.try_into().unwrap()),
                u64::from_ne_bytes(v.try_into().unwrap()),
            ));
            true
        },
    )
    .unwrap();
    assert_eq!(seen, vec![(200, 3)]);
}

#[test]
fn forward_scan_missing_key_starts_at_next_key_first_dup() {
    let env = env_with_created_at_dups();
    let txn = env.begin_ro().unwrap();
    let mut seen = Vec::new();
    txn.foreach_full(
        env.dbis().event_created_at,
        &150u64.to_ne_bytes(),
        &0u64.to_ne_bytes(),
        false,
        |k, v| {
            seen.push((
                u64::from_ne_bytes(k.try_into().unwrap()),
                u64::from_ne_bytes(v.try_into().unwrap()),
            ));
            true
        },
    )
    .unwrap();
    assert_eq!(seen, vec![(200, 3)]);
}

#[test]
fn reused_cursor_ranges_match_an_ordered_model_after_stops_and_empty_ranges() {
    let env = env_with_created_at_dups();
    let txn = env.begin_ro().unwrap();
    let mut cursor = txn.cursor(env.dbis().event_created_at).unwrap();
    let rows = [(100u64, 1u64), (100, 2), (200, 3)];
    for key in [
        None,
        Some(0u64),
        Some(100),
        Some(150),
        Some(200),
        Some(u64::MAX),
    ] {
        for dup in [None, Some(0u64), Some(1), Some(2), Some(4), Some(u64::MAX)] {
            for reverse in [true, false] {
                for cap in [1, 2, 8] {
                    let mut expected: Vec<_> = rows
                        .iter()
                        .copied()
                        .filter(|&(k, v)| {
                            let Some(key) = key else {
                                return true;
                            };
                            match (reverse, dup) {
                                (true, Some(dup)) => k < key || (k == key && v <= dup),
                                (true, None) => k <= key,
                                (false, Some(dup)) => k > key || (k == key && v >= dup),
                                (false, None) => k > key,
                            }
                        })
                        .collect();
                    if reverse {
                        expected.reverse();
                    }
                    let complete = expected.len() < cap;
                    expected.truncate(cap);
                    let mut seen = Vec::new();
                    let result = cursor
                        .foreach_full(
                            &key.map(|k| k.to_ne_bytes().to_vec()).unwrap_or_default(),
                            &dup.map(|v| v.to_ne_bytes().to_vec()).unwrap_or_default(),
                            reverse,
                            |k, v| {
                                seen.push((
                                    u64::from_ne_bytes(k.try_into().unwrap()),
                                    u64::from_ne_bytes(v.try_into().unwrap()),
                                ));
                                seen.len() < cap
                            },
                        )
                        .unwrap();
                    assert_eq!(
                        (seen, result),
                        (expected, complete),
                        "key={key:?} dup={dup:?} reverse={reverse} cap={cap}"
                    );
                }
            }
        }
    }
}
