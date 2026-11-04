//! Invalid duplicates are decoded only when a historical scan consumes them.
//! A different range or an excluded time must retain its boundary behavior.

use serde_json::{json, Value};
use wok_db::keys::{make_key_string_u64, make_key_string_u64_u64, make_key_u64_u64};
use wok_db::{Env, EnvOptions};
use wok_query::{DbScan, NostrFilterGroup};

#[derive(Clone, Copy, Debug)]
enum Index {
    Tag,
    Kind,
    AuthorKind,
    Id,
}

const INDEXES: [Index; 4] = [Index::Tag, Index::Kind, Index::AuthorKind, Index::Id];

impl Index {
    fn dbi(self, env: &Env) -> u32 {
        let d = env.dbis();
        match self {
            Self::Tag => d.event_tag,
            Self::Kind => d.event_kind,
            Self::AuthorKind => d.event_pubkey_kind,
            Self::Id => d.event_id,
        }
    }

    fn key(self, time: u64, matching: bool) -> Vec<u8> {
        let prefix = [if matching { 0x22 } else { 0x11 }; 32];
        match self {
            Self::Tag => make_key_string_u64(if matching { b"tm" } else { b"tl" }, time),
            Self::Kind => make_key_u64_u64(u64::from(matching), time),
            Self::AuthorKind => make_key_string_u64_u64(&prefix, 1, time),
            Self::Id => make_key_string_u64(&prefix, time),
        }
    }

    fn filter(self) -> Value {
        let reference = hex::encode([0x22; 32]);
        match self {
            Self::Tag => json!({"#t": ["m"]}),
            Self::Kind => json!({"kinds": [1]}),
            Self::AuthorKind => json!({"authors": [reference], "kinds": [1]}),
            Self::Id => json!({"ids": [reference]}),
        }
    }
}

fn fixture(index: Index, invalid_time: u64, invalid_matches: bool) -> (tempfile::TempDir, Env) {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let mut tx = env.begin_rw().unwrap();
    tx.put(
        index.dbi(&env),
        &index.key(50, true),
        &7u64.to_ne_bytes(),
        0,
    )
    .unwrap();
    // Separate keys permit a malformed duplicate in the raw maintenance API,
    // even though normal event writers always use an eight-byte local ID.
    tx.put(
        index.dbi(&env),
        &index.key(invalid_time, invalid_matches),
        b"bad",
        0,
    )
    .unwrap();
    tx.commit().unwrap();
    (dir, env)
}

fn scan(env: &Env, mut value: Value) -> Result<Vec<u64>, wok_db::DbError> {
    value["limit"] = json!(50);
    let group = NostrFilterGroup::from_value(&value, 100, 8, 16).unwrap();
    let filter = &group.filters[0];
    assert!(filter.index_only_scans);
    let tx = env.begin_ro().unwrap();
    let mut scan = DbScan::new(filter, &tx);
    let mut seen = Vec::new();
    assert!(scan.scan(
        &tx,
        filter,
        |id| {
            seen.push(id);
            false
        },
        |_| false,
    )?);
    Ok(seen)
}

#[test]
fn an_invalid_duplicate_in_the_next_prefix_does_not_fail_the_requested_range() {
    for index in INDEXES {
        let (_dir, env) = fixture(index, 50, false);
        assert_eq!(scan(&env, index.filter()).unwrap(), [7], "{index:?}");
    }
}

#[test]
fn an_invalid_duplicate_above_until_is_skipped_before_validation() {
    for index in INDEXES {
        let (_dir, env) = fixture(index, 200, true);
        let mut filter = index.filter();
        filter["until"] = json!(100);
        assert_eq!(scan(&env, filter).unwrap(), [7], "{index:?}");
    }
}

#[test]
fn an_invalid_duplicate_below_since_is_skipped_before_validation() {
    for index in INDEXES {
        let (_dir, env) = fixture(index, 10, true);
        let mut filter = index.filter();
        filter["since"] = json!(20);
        assert_eq!(scan(&env, filter).unwrap(), [7], "{index:?}");
    }
}

#[test]
fn an_invalid_duplicate_inside_the_consumed_range_still_fails() {
    for index in INDEXES {
        let (_dir, env) = fixture(index, 40, true);
        assert!(scan(&env, index.filter()).is_err(), "{index:?}");
    }
}

#[test]
fn a_short_nonmatching_key_stops_before_later_malformed_rows() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
    env.ensure_initialized().unwrap();
    let dbi = env.dbis().event_kind;
    let mut tx = env.begin_rw().unwrap();
    tx.put(dbi, &make_key_u64_u64(1, 50), &7u64.to_ne_bytes(), 0)
        .unwrap();
    // The pair comparator orders all malformed keys below valid pairs, then
    // compares their raw bytes. Reverse traversal reaches the short key first.
    tx.put(dbi, &[255], &9u64.to_ne_bytes(), 0).unwrap();
    tx.put(dbi, &1u64.to_ne_bytes(), b"bad", 0).unwrap();
    tx.commit().unwrap();

    // The short key is outside kind 1 and ends its range. Skipping it inside
    // the reader would reach the eight-byte malformed key and fail decoding.
    assert_eq!(scan(&env, json!({"kinds": [1]})).unwrap(), [7]);
}
