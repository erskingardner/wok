//! Typed postings must agree with the independently decoded cursor across all
//! historical index layouts, integer boundaries and independently resumed calls.
use lmdb_sys::*;
use wok_db::keys::{make_key_string_u64, make_key_string_u64_u64, make_key_u64_u64};
use wok_db::{Env, EnvOptions};

fn populated() -> (tempfile::TempDir, Env) {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let d = env.dbis();
    let mut tx = env.begin_rw().unwrap();
    for prefix in [vec![], vec![0], vec![0, 255, b't', 0], vec![255; 32]] {
        for time in [0, 1, 255, 256, u32::MAX as u64, u64::MAX] {
            for id in [1u64, 255, 256, u64::MAX] {
                let key = make_key_string_u64(&prefix, time);
                for dbi in [d.event_id, d.event_tag, d.event_pubkey] {
                    tx.put(dbi, &key, &id.to_ne_bytes(), 0).unwrap();
                }
                for kind in [0, 256, u64::MAX] {
                    let key = make_key_string_u64_u64(&prefix, kind, time);
                    tx.put(d.event_pubkey_kind, &key, &id.to_ne_bytes(), 0)
                        .unwrap();
                    tx.put(d.event_tag_kind.unwrap(), &key, &id.to_ne_bytes(), 0)
                        .unwrap();
                }
            }
        }
    }
    for time in [0u64, 1, 255, 256, u32::MAX as u64, u64::MAX] {
        for id in [1u64, 255, 256, u64::MAX] {
            tx.put(
                d.event_created_at,
                &time.to_ne_bytes(),
                &id.to_ne_bytes(),
                0,
            )
            .unwrap();
            for kind in [0, 256, u64::MAX] {
                tx.put(
                    d.event_kind,
                    &make_key_u64_u64(kind, time),
                    &id.to_ne_bytes(),
                    0,
                )
                .unwrap();
            }
        }
    }
    tx.commit().unwrap();
    (dir, env)
}

#[test]
fn typed_reader_matches_generic_rows_and_prefixes_for_every_query_index() {
    let (_dir, env) = populated();
    let d = env.dbis();
    let tx = env.begin_ro().unwrap();
    for dbi in [
        d.event_id,
        d.event_pubkey_kind,
        d.event_tag,
        d.event_created_at,
        d.event_pubkey,
        d.event_kind,
        d.event_tag_kind.unwrap(),
        env.covering_pubkey_dbi(),
    ] {
        let mut generic = tx.cursor(dbi).unwrap();
        let mut want = Vec::new();
        let mut row = generic.get(None, None, MDB_LAST).unwrap();
        while let Some((key, value)) = row {
            if key.len() >= 8 {
                want.push((key.to_vec(), value.to_vec()));
            }
            row = generic.get(None, None, MDB_PREV).unwrap();
        }
        let start = want.first().unwrap().0.clone();
        let mut cursor = tx.cursor(dbi).unwrap();
        let mut got = Vec::new();
        cursor
            .foreach_index(&start, u64::MAX, |entry| {
                if entry.created_at.is_none() {
                    return true;
                }
                let key = entry.to_key();
                let prefix = &key[..key.len() - 8];
                assert!(entry.prefix_matches(prefix, true));
                assert!(entry.prefix_matches(&prefix[..prefix.len() / 2], false));
                let mut extended = prefix.to_vec();
                extended.push(1);
                assert!(!entry.prefix_matches(&extended, true));
                let kind = u64::from_ne_bytes(key[..8].try_into().unwrap());
                assert!(entry.matches_kind(kind));
                assert!(!entry.matches_kind(kind.wrapping_add(1)));
                got.push((key, entry.local_id().unwrap().to_ne_bytes().to_vec()));
                true
            })
            .unwrap();
        assert_eq!(got.len(), want.len(), "dbi {dbi}");
        for (at, (got, want)) in got.iter().zip(&want).enumerate() {
            assert_eq!(got, want, "dbi {dbi}, row {at}");
        }
        let mut from_end = Vec::new();
        cursor
            .foreach_index(&[], u64::MAX, |entry| {
                if entry.created_at.is_none() {
                    return true;
                }
                from_end.push((
                    entry.to_key(),
                    entry.local_id().unwrap().to_ne_bytes().to_vec(),
                ));
                true
            })
            .unwrap();
        assert_eq!(from_end.len(), want.len(), "empty endpoint, dbi {dbi}");
        for (got, want) in from_end.iter().zip(&want) {
            assert_eq!(got, want, "empty endpoint, dbi {dbi}");
        }

        // Every resume endpoint is inclusive, including a duplicate in a tie.
        for offset in [0, 1, want.len() / 2, want.len() - 1] {
            let mut resumed = Vec::new();
            let local_id = u64::from_ne_bytes(want[offset].1[..].try_into().unwrap());
            let finished = cursor
                .foreach_index(&want[offset].0, local_id, |entry| {
                    if entry.created_at.is_none() {
                        return true;
                    }
                    resumed.push((
                        entry.to_key(),
                        entry.local_id().unwrap().to_ne_bytes().to_vec(),
                    ));
                    resumed.len() < 7
                })
                .unwrap();
            assert_eq!(
                resumed,
                want[offset..].iter().take(7).cloned().collect::<Vec<_>>()
            );
            assert_eq!(finished, want.len() - offset < 7);
        }
    }
}

#[test]
fn typed_writer_overlay_and_old_snapshot_return_their_own_postings() {
    let (_dir, env) = populated();
    let dbi = env.dbis().event_tag;
    let key = make_key_string_u64(b"t\0topic", 7);
    let old = env.begin_ro().unwrap();
    let seen = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let mut writer = env.begin_rw().unwrap();
                writer.put(dbi, &key, &42u64.to_ne_bytes(), 0).unwrap();
                let mut seen = Vec::new();
                writer
                    .cursor(dbi)
                    .unwrap()
                    .foreach_index(&key, u64::MAX, |entry| {
                        if !entry.prefix_matches(b"t\0topic", true) {
                            return false;
                        }
                        seen.push((entry.created_at.unwrap(), entry.local_id().unwrap()));
                        true
                    })
                    .unwrap();
                writer.commit().unwrap();
                seen
            })
            .join()
            .unwrap()
    });
    assert_eq!(seen, [(7, 42)]);
    let check = |tx: &wok_db::RoTxn<'_>, expected: Vec<u64>| {
        let mut seen = Vec::new();
        tx.cursor(dbi)
            .unwrap()
            .foreach_index(&key, u64::MAX, |entry| {
                if !entry.prefix_matches(b"t\0topic", true) {
                    return false;
                }
                seen.push(entry.local_id().unwrap());
                true
            })
            .unwrap();
        assert_eq!(seen, expected);
    };
    check(&old, vec![]);
    drop(old);
    check(&env.begin_ro().unwrap(), vec![42]);
}
