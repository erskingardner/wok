use super::*;
use crate::{keys::make_key_string_u64, Env, EnvOptions};
use lmdb_sys::{MDB_FIRST, MDB_LAST, MDB_NEXT, MDB_PREV, MDB_SET_KEY};
use wok_event::{PackedEventBuilder, PackedEventTagBuilder};

fn database() -> (tempfile::TempDir, Env) {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let mut tx = env.begin_rw().unwrap();
    let db = env.dbis();
    for id in 1..=12u64 {
        let author = [(id % 3) as u8; 32];
        let tags = PackedEventTagBuilder::default();
        let packed = PackedEventBuilder::build(&[id as u8; 32], &author, id, 1, 0, &tags).unwrap();
        tx.put_u64(db.event, id, packed.as_bytes(), 0).unwrap();
        tx.put_u64(db.event_payload, id, b"payload", 0).unwrap();
        tx.put(
            db.event_pubkey,
            &make_key_string_u64(&author, id),
            &id.to_ne_bytes(),
            0,
        )
        .unwrap();
    }
    tx.commit().unwrap();
    (dir, env)
}

#[test]
fn primary_pins_are_shared_between_components_and_cover_does_not_copy_them() {
    let (_dir, env) = database();
    let tx = env.begin_ro().unwrap();
    let (_, measured) = measure(|| {
        tx.get_u64(env.dbis().event, 12).unwrap().unwrap();
        tx.get_u64(env.dbis().event_payload, 12).unwrap().unwrap();
        assert!(tx.get_u64(env.dbis().event, 999).unwrap().is_none());
        let mut cursor = tx.cursor(env.covering_pubkey_dbi()).unwrap();
        cursor
            .foreach_index(&make_key_string_u64(&[0; 32], u64::MAX), u64::MAX, |_| {
                false
            })
            .unwrap();
    })
    .unwrap();
    let c = measured.wrapper;
    assert_eq!(
        (
            c.primary_pin_lookups,
            c.primary_pins_found,
            c.primary_pins_missing
        ),
        (2, 1, 1)
    );
    assert_eq!(c.primary_cached_pinned_hits, 1);
    assert_eq!(c.cover_cached_pinned_hits, u64::from(!true));
    assert_eq!(c.cover_records_copied, 0);
    let bytes = tx.get_u64(env.dbis().event, 12).unwrap().unwrap().len() + 7 + 8;
    assert_eq!(c.primary_pin_returned_bytes, bytes as u64);
}

#[test]

fn coverless_author_postings_do_not_populate_the_primary_cache() {
    let (_dir, env) = database();
    assert_eq!(env.covering_pubkey_dbi(), env.dbis().event_pubkey);
    let tx = env.begin_ro().unwrap();
    let (_, measured) = measure(|| {
        tx.cursor(env.covering_pubkey_dbi())
            .unwrap()
            .foreach_index(
                &make_key_string_u64(&[0; 32], u64::MAX),
                u64::MAX,
                |entry| {
                    assert_eq!(entry.local_id().unwrap(), 12);
                    false
                },
            )
            .unwrap();
        tx.get_u64(env.dbis().event, 12).unwrap().unwrap();
        tx.get_u64(env.dbis().event_payload, 12).unwrap().unwrap();
    })
    .unwrap();
    let c = measured.wrapper;
    assert_eq!(
        (c.iterator_creations, c.seek, c.typed_index_entries),
        (1, 1, 1)
    );
    assert_eq!(
        (c.cover_records_copied, c.cover_record_bytes_copied),
        (0, 0)
    );
    assert_eq!(
        (c.cover_cached_owned_hits, c.cover_cached_pinned_hits),
        (0, 0)
    );
    assert_eq!((c.primary_pins_found, c.primary_cached_pinned_hits), (1, 1));
}

#[test]
fn generic_cursor_counts_physical_rows_and_native_direction_changes() {
    let (_dir, env) = database();
    let tx = env.begin_ro().unwrap();
    let (_, measured) = measure(|| {
        let mut cursor = tx.cursor(env.dbis().event).unwrap();
        for op in [MDB_FIRST, MDB_NEXT, MDB_PREV, MDB_LAST] {
            assert!(cursor.get(None, None, op).unwrap().is_some());
        }
    })
    .unwrap();
    let c = measured.wrapper;
    assert_eq!(
        (
            c.iterator_creations,
            c.seek_to_first,
            c.seek_to_last,
            c.next,
            c.prev
        ),
        (1, 1, 1, 1, 1)
    );
    assert_eq!((c.seek, c.seek_for_prev), (0, 0));
    assert_eq!(
        (c.generic_row_materializations, c.logical_decode_calls),
        (4, 4)
    );
    assert_eq!(c.generic_key_copy_bytes, 4 * 9);
    assert!(c.generic_value_copy_bytes > c.arena_copy_bytes);
    assert!(c.arena_copy_bytes > 0);

    let (_, reverse_seek) = measure(|| {
        let mut cursor = tx.cursor(env.dbis().event_pubkey).unwrap();
        let row = cursor
            .get(Some(&make_key_string_u64(&[0; 32], 9)), None, MDB_SET_KEY)
            .unwrap()
            .unwrap();
        assert_eq!(row.1, 9u64.to_ne_bytes());
    })
    .unwrap();
    assert_eq!(reverse_seek.wrapper.seek_for_prev, 1);
    assert_eq!(reverse_seek.wrapper.seek, 0);
}

#[test]
fn noncanonical_native_posting_records_one_fallback_and_an_owned_boundary() {
    let (_dir, env) = database();
    let mut writer = env.begin_rw().unwrap();
    writer
        .put(env.dbis().event_pubkey, b"short", &99u64.to_ne_bytes(), 0)
        .unwrap();
    writer.commit().unwrap();
    let tx = env.begin_ro().unwrap();
    let mut malformed = false;
    let (_, measured) = measure(|| {
        tx.cursor(env.dbis().event_pubkey)
            .unwrap()
            .foreach_index(&[], u64::MAX, |entry| {
                if entry.created_at.is_none() {
                    assert_eq!(entry.local_id().unwrap(), 99);
                    assert_eq!(entry.to_key(), b"short");
                    malformed = true;
                }
                true
            })
            .unwrap();
    })
    .unwrap();
    assert!(malformed);
    let c = measured.wrapper;
    assert_eq!((c.seek_to_first, c.seek, c.next), (1, 0, 13));
    assert_eq!((c.typed_index_entries, c.fallback_index_entries), (12, 1));
    assert_eq!(c.logical_decode_calls, 1);
    assert_eq!((c.resume_key_copies, c.resume_key_bytes), (1, 5));
    assert_eq!(c.generic_row_materializations, 0);
}

#[test]
fn nested_scope_is_rejected_without_resetting_the_outer_read() {
    let (_dir, env) = database();
    let tx = env.begin_ro().unwrap();
    let ran_nested = std::cell::Cell::new(false);
    let (_, measured) = measure(|| {
        tx.get_u64(env.dbis().event, 1).unwrap().unwrap();
        let nested = measure(|| ran_nested.set(true));
        assert_eq!(nested.unwrap_err(), ScopeAlreadyActive);
        tx.get_u64(env.dbis().event_payload, 1).unwrap().unwrap();
    })
    .unwrap();
    assert!(!ran_nested.get());
    assert_eq!(measured.wrapper.primary_pins_found, 1);
    assert_eq!(measured.wrapper.primary_cached_pinned_hits, 1);
}

#[test]
fn error_and_panic_leave_the_next_scope_clean_and_native_stats_disabled() {
    let (_dir, env) = database();
    let tx = env.begin_ro().unwrap();
    let (failed, counters) = measure(|| tx.get(env.dbis().event, b"bad key")).unwrap();
    assert!(failed.is_err());
    assert_eq!(counters.wrapper.primary_pin_lookups, 0);
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = measure(|| {
            tx.get_u64(env.dbis().event, 1).unwrap().unwrap();
            panic!("diagnostic unwind regression");
        });
    }));
    assert!(panicked.is_err());
    let fresh = env.begin_ro().unwrap();
    let mut perf = PerfContext::default();
    perf.reset();
    fresh.get_u64(env.dbis().event, 2).unwrap().unwrap();
    assert_eq!(perf.metric(PerfMetric::UserKeyComparisonCount), 0);
    assert_eq!(perf.metric(PerfMetric::GetReadBytes), 0);
    let (_, clean) = measure(|| tx.get_u64(env.dbis().event, 3).unwrap().unwrap()).unwrap();
    assert_eq!(clean.wrapper.primary_pins_found, 1);
    assert_eq!(clean.wrapper.primary_cached_pinned_hits, 0);
}

#[test]
fn measurements_do_not_include_other_threads_or_disable_their_scopes() {
    let (_dir, env) = database();
    let tx = env.begin_ro().unwrap();
    let (_, outer) = measure(|| {
        tx.get_u64(env.dbis().event, 1).unwrap().unwrap();
        std::thread::scope(|threads| {
            let other = threads.spawn(|| {
                let tx = env.begin_ro().unwrap();
                tx.get_u64(env.dbis().event, 2).unwrap().unwrap();
                measure(|| tx.get_u64(env.dbis().event, 3).unwrap().unwrap())
                    .unwrap()
                    .1
            });
            let measured = other.join().unwrap();
            assert_eq!(measured.wrapper.primary_pins_found, 1);
        });
        tx.get_u64(env.dbis().event_payload, 1).unwrap().unwrap();
    })
    .unwrap();
    assert_eq!(outer.wrapper.primary_pins_found, 1);
    assert_eq!(outer.wrapper.primary_cached_pinned_hits, 1);
}
