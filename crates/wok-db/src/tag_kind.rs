//! Rebuildable `(tag, kind, created_at)` postings in `wok_Event__tagKind`.
//!
//! Each single-letter tag of an event is keyed `tagName || tagVal || kind ||
//! created_at`, with the local event id as its duplicate value. The value is
//! the packed one, so a value longer than 255 bytes is hashed and a legacy
//! record that dropped it has no entry, exactly as in `Event__tag`. A filter
//! with one tag and `kinds` can then read the events of each requested kind
//! without reading the rest of the tag value's history.
//!
//! The writer maintains the entries in the transaction that inserts or deletes
//! their event. Two markers, with keys shorter than any posting so that they
//! sort first, describe the table:
//!
//! - `schema` is the key layout. A writable open that finds no layout, or
//!   another one, empties the table and starts again from local id 0.
//! - `indexed-through` is a local id: every event at or below it has its
//!   entries. The index is complete once it reaches the sequence high-water
//!   mark, the greatest local id ever allocated, and only then may a query
//!   rely on it.
//!
//! An earlier Wok release does not open this table. The events it inserts take
//! ids above the marker, so the index stays incomplete until they are indexed.
//! The events it deletes leave their entries behind. Local ids are never
//! reused, so such a stale entry names an event that is no longer stored and
//! readers must skip it; `wok integrity` counts them and `wok reindex`
//! rebuilds the table without them.

use crate::keys::make_key_string_u64_u64;
use crate::{DbError, RoTxn, RwTxn};
use lmdb_sys::MDB_dbi;
use serde::Serialize;
use wok_event::PackedEventView;

/// Marker keys are shorter than the 16 bytes of a posting's two integers, so
/// the `StringUint64Uint64` comparator orders them before every posting.
const SCHEMA_KEY: &[u8] = b"\0schema";
const INDEXED_THROUGH_KEY: &[u8] = b"\0through";

/// The key layout this release reads and writes.
pub const TAG_KIND_SCHEMA_VERSION: u64 = 1;

/// The `wok_Event__tagKind` key of one packed single-letter tag value.
pub fn tag_kind_key(tag_name: u8, tag_value: &[u8], kind: u64, created_at: u64) -> Vec<u8> {
    let mut tag = Vec::with_capacity(1 + tag_value.len());
    tag.push(tag_name);
    tag.extend_from_slice(tag_value);
    make_key_string_u64_u64(&tag, kind, created_at)
}

/// The distinct `wok_Event__tagKind` keys of `packed`, one per packed
/// single-letter tag value.
pub(crate) fn tag_kind_keys(packed: PackedEventView<'_>) -> Vec<Vec<u8>> {
    let mut keys = Vec::new();
    packed.foreach_tag(|name, value| {
        keys.push(tag_kind_key(
            name as u8,
            value,
            packed.kind(),
            packed.created_at(),
        ));
        true
    });
    keys.sort_unstable();
    keys.dedup();
    keys
}

pub(crate) fn is_tag_kind_marker(key: &[u8]) -> bool {
    key == SCHEMA_KEY || key == INDEXED_THROUGH_KEY
}

/// Where the `wok_Event__tagKind` table stands in one snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TagKindIndexState {
    /// The stored key layout, `None` before a writable open initializes it.
    pub schema: Option<u64>,
    /// Every event with a local id at or below this one has its entries.
    pub indexed_through: u64,
    /// The greatest local id ever allocated.
    pub high_water: u64,
}

impl TagKindIndexState {
    /// Whether every stored event has its entries in this release's layout.
    /// Stale entries may remain even then; readers skip them.
    pub fn complete(&self) -> bool {
        self.schema == Some(TAG_KIND_SCHEMA_VERSION) && self.indexed_through >= self.high_water
    }
}

fn marker(value: Option<&[u8]>) -> Option<u64> {
    Some(u64::from_ne_bytes(value?.try_into().ok()?))
}

/// The table's state, or `None` when the database has no such table: a strfry
/// source, or a database no release with the table has opened writable yet.
pub fn tag_kind_index_state_ro(txn: &RoTxn<'_>) -> Result<Option<TagKindIndexState>, DbError> {
    let Some(dbi) = txn.env().dbis().event_tag_kind else {
        return Ok(None);
    };
    // The stored sequence covers deleted tails; the newest record covers a
    // database whose sequence was never stored. A malformed sequence is
    // integrity's to report, and the newest record still bounds the events.
    let sequence = match txn.env().dbis().state {
        Some(state) => txn
            .get(state, crate::state::HIGH_WATER)?
            .and_then(|raw| crate::state::decode(raw).ok()),
        None => None,
    };
    let high_water = sequence
        .unwrap_or(0)
        .max(txn.largest_integer_key(txn.env().dbis().event)?);
    Ok(Some(TagKindIndexState {
        schema: marker(txn.get(dbi, SCHEMA_KEY)?),
        indexed_through: marker(txn.get(dbi, INDEXED_THROUGH_KEY)?).unwrap_or(0),
        high_water,
    }))
}

fn set_marker(txn: &mut RwTxn<'_>, dbi: MDB_dbi, key: &[u8], value: u64) -> Result<(), DbError> {
    // A DUPSORT key keeps every value put under it; replace the one there.
    txn.del(dbi, key, None)?;
    txn.put(dbi, key, &value.to_ne_bytes(), 0)?;
    Ok(())
}

/// Record that the table holds this layout and every event up to
/// `indexed_through`, after a rebuild derived all of them.
pub(crate) fn initialize_tag_kind_index_state(
    txn: &mut RwTxn<'_>,
    indexed_through: u64,
) -> Result<(), DbError> {
    let Some(dbi) = txn.env().dbis().event_tag_kind else {
        return Ok(());
    };
    set_marker(txn, dbi, SCHEMA_KEY, TAG_KIND_SCHEMA_VERSION)?;
    set_marker(txn, dbi, INDEXED_THROUGH_KEY, indexed_through)
}

/// On a writable open, empty a table that holds no layout or another layout,
/// and mark it as indexing nothing yet. A table in this layout is kept.
pub(crate) fn ensure_tag_kind_index(txn: &mut RwTxn<'_>) -> Result<(), DbError> {
    let Some(dbi) = txn.env().dbis().event_tag_kind else {
        return Ok(());
    };
    if marker(txn.get(dbi, SCHEMA_KEY)?) == Some(TAG_KIND_SCHEMA_VERSION) {
        return Ok(());
    }
    txn.clear(dbi)?;
    initialize_tag_kind_index_state(txn, 0)
}

pub(crate) fn put_tag_kind_entries(
    txn: &mut RwTxn<'_>,
    lev_id: u64,
    keys: &[Vec<u8>],
) -> Result<(), DbError> {
    let Some(dbi) = txn.env().dbis().event_tag_kind else {
        return Ok(());
    };
    let lev = lev_id.to_ne_bytes();
    for key in keys {
        txn.put(dbi, key, &lev, 0)?;
    }
    Ok(())
}

pub(crate) fn del_tag_kind_entries(
    txn: &mut RwTxn<'_>,
    lev_id: u64,
    keys: &[Vec<u8>],
) -> Result<(), DbError> {
    let Some(dbi) = txn.env().dbis().event_tag_kind else {
        return Ok(());
    };
    let lev = lev_id.to_ne_bytes();
    for key in keys {
        txn.del(dbi, key, Some(&lev))?;
    }
    Ok(())
}

/// After a write transaction indexed the events it inserted, local ids
/// `first..=last`, move the marker past them if it already covered every
/// earlier id. Otherwise ids below `first` still lack entries, and the
/// marker stays until they are indexed.
pub(crate) fn note_tag_kind_indexed(
    txn: &mut RwTxn<'_>,
    first: u64,
    last: u64,
) -> Result<(), DbError> {
    let Some(dbi) = txn.env().dbis().event_tag_kind else {
        return Ok(());
    };
    if marker(txn.get(dbi, SCHEMA_KEY)?) != Some(TAG_KIND_SCHEMA_VERSION) {
        return Ok(());
    }
    let through = marker(txn.get(dbi, INDEXED_THROUGH_KEY)?).unwrap_or(0);
    if through.saturating_add(1) >= first && through < last {
        set_marker(txn, dbi, INDEXED_THROUGH_KEY, last)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::comparators::cmp_string_u64_u64;
    use crate::{check_integrity, Env, EnvOptions, EventToWrite, NoopNegentropy};
    use serde_json::json;
    use std::cmp::Ordering;

    fn event(time: u64) -> EventToWrite {
        use secp256k1::{Keypair, SecretKey, SECP256K1};
        let secret = SecretKey::from_byte_array(&[7; 32]).unwrap();
        let key = Keypair::from_secret_key(SECP256K1, &secret);
        let mut value = json!({"pubkey":hex::encode(key.x_only_public_key().0.serialize()),
            "kind":1059,"created_at":time,"tags":[["p","22".repeat(32)]],"content":""});
        let id = wok_event::event_id_hash(&value).unwrap();
        value["id"] = json!(hex::encode(id));
        value["sig"] = json!(hex::encode(
            SECP256K1.sign_schnorr_no_aux_rand(&id, &key).as_ref()
        ));
        let parsed =
            wok_event::parse_and_verify_event(&value, &Default::default(), None, true, false)
                .unwrap();
        EventToWrite::new(parsed.packed.into_bytes(), parsed.json)
    }

    fn write(env: &Env, time: u64) -> EventToWrite {
        let mut events = [event(time)];
        let mut txn = env.begin_rw().unwrap();
        crate::write_events(&mut txn, &mut NoopNegentropy, &mut events, false).unwrap();
        txn.commit().unwrap();
        let [event] = events;
        event
    }

    fn state(env: &Env) -> TagKindIndexState {
        tag_kind_index_state_ro(&env.begin_ro().unwrap())
            .unwrap()
            .unwrap()
    }

    fn postings(env: &Env) -> usize {
        let txn = env.begin_ro().unwrap();
        let mut count = 0;
        txn.foreach_full(
            env.dbis().event_tag_kind.unwrap(),
            &[],
            &[],
            false,
            |key, _| {
                count += usize::from(!is_tag_kind_marker(key));
                true
            },
        )
        .unwrap();
        count
    }

    /// What an earlier release leaves when it inserts `event`: no entries, and
    /// the marker where it was.
    fn as_if_inserted_by_an_earlier_release(env: &Env, event: &EventToWrite, through: u64) {
        let keys = tag_kind_keys(PackedEventView::new(&event.packed).unwrap());
        let dbi = env.dbis().event_tag_kind.unwrap();
        let mut txn = env.begin_rw().unwrap();
        del_tag_kind_entries(&mut txn, event.lev_id, &keys).unwrap();
        set_marker(&mut txn, dbi, INDEXED_THROUGH_KEY, through).unwrap();
        txn.commit().unwrap();
    }

    #[test]
    fn the_marker_moves_only_over_ids_that_are_all_indexed() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let empty = state(&env);
        assert_eq!((empty.indexed_through, empty.high_water), (0, 0));
        assert!(empty.complete());
        write(&env, 100);
        write(&env, 101);
        assert_eq!(state(&env).indexed_through, 2);

        let earlier = write(&env, 102);
        as_if_inserted_by_an_earlier_release(&env, &earlier, 2);
        let gap = state(&env);
        assert_eq!((gap.indexed_through, gap.high_water), (2, 3));
        assert!(!gap.complete());

        // A later write indexes its own event but cannot cover the gap.
        let later = write(&env, 103);
        assert_eq!(later.lev_id, 4);
        let after = state(&env);
        assert_eq!((after.indexed_through, after.high_water), (2, 4));
        assert_eq!(postings(&env), 3);
        // Integrity expects entries only at or below the marker.
        let report = check_integrity(&env.begin_ro().unwrap()).unwrap();
        assert!(report.ok(), "{:#?}", report.issues);
        let tag_kind = report.tag_kind_index.unwrap();
        assert!(!tag_kind.complete);
        assert_eq!((tag_kind.expected_entries, tag_kind.missing_entries), (2, 0));
    }

    #[test]
    fn deleting_the_newest_event_keeps_the_index_complete() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        write(&env, 100);
        let newest = write(&env, 101);
        let mut txn = env.begin_rw().unwrap();
        crate::delete_events(&mut txn, &mut NoopNegentropy, [newest.lev_id]).unwrap();
        txn.commit().unwrap();
        let deleted = state(&env);
        assert_eq!((deleted.indexed_through, deleted.high_water), (2, 2));
        assert!(deleted.complete());
        assert_eq!(write(&env, 102).lev_id, 3);
        assert_eq!(state(&env).indexed_through, 3);
        assert_eq!(postings(&env), 2);
    }

    #[test]
    fn a_writable_open_empties_a_table_in_another_layout() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        write(&env, 100);
        write(&env, 101);
        let dbi = env.dbis().event_tag_kind.unwrap();
        let mut txn = env.begin_rw().unwrap();
        set_marker(&mut txn, dbi, SCHEMA_KEY, TAG_KIND_SCHEMA_VERSION + 1).unwrap();
        txn.commit().unwrap();
        let foreign = state(&env);
        assert_eq!(foreign.schema, Some(TAG_KIND_SCHEMA_VERSION + 1));
        assert!(!foreign.complete());
        // Another layout's postings are counted but not checked.
        let report = check_integrity(&env.begin_ro().unwrap()).unwrap();
        assert!(report.ok(), "{:#?}", report.issues);
        assert_eq!(report.tag_kind_index.unwrap().actual_entries, 2);

        env.ensure_initialized().unwrap();
        let reset = state(&env);
        assert_eq!(reset.schema, Some(TAG_KIND_SCHEMA_VERSION));
        assert_eq!((reset.indexed_through, reset.high_water), (0, 2));
        assert_eq!(postings(&env), 0);
        // This layout is kept from then on.
        write(&env, 102);
        env.ensure_initialized().unwrap();
        assert_eq!(postings(&env), 1);
        assert_eq!(state(&env).indexed_through, 0);
    }

    #[test]
    fn markers_sort_before_every_posting() {
        let smallest = tag_kind_key(0, &[], 0, 0);
        for marker in [SCHEMA_KEY, INDEXED_THROUGH_KEY] {
            assert!(marker.len() < 16);
            assert_eq!(cmp_string_u64_u64(marker, &smallest), Ordering::Less);
        }
    }

    #[test]
    fn keys_order_by_tag_then_kind_then_time() {
        let key = |value: &[u8], kind, at| tag_kind_key(b'p', value, kind, at);
        let ordered = [
            key(b"a", 1, 9),
            key(b"a", 7, 1),
            key(b"a", 7, 2),
            key(b"a", 1059, 0),
            key(b"b", 0, 0),
        ];
        for pair in ordered.windows(2) {
            assert_eq!(cmp_string_u64_u64(&pair[0], &pair[1]), Ordering::Less);
        }
    }
}
