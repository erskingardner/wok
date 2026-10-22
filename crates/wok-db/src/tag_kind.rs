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
//! The writer's backfill fills the table in bounded steps. A table at marker 0
//! with events stored (a database from before the table, or one reset) is
//! built by a pass over `Event__tag` in key order, which puts the postings of
//! one tag value next to each other: in local-id order, nearly every posting
//! would rewrite a page of its own. `wok_Event__tagKindBuild` holds the
//! pass's cursor and target, the high-water mark when it began; once the
//! walk ends, the marker takes the target. Any other gap above the marker is
//! indexed in local-id order.
//!
//! An earlier Wok release does not open these tables. The events it inserts take
//! ids above the marker, so the index stays incomplete until they are indexed.
//! The events it deletes leave their entries behind. Local ids are never
//! reused, so such a stale entry names an event that is no longer stored and
//! readers must skip it; `wok integrity` counts them and `wok reindex`
//! rebuilds the table without them.

use crate::keys::make_key_string_u64_u64;
use crate::{DbError, RoTxn, RwTxn};
use lmdb_sys::MDB_dbi;
use serde::Serialize;
use std::time::{Duration, Instant};
use wok_event::PackedEventView;

/// Marker keys are shorter than the 16 bytes of a posting's two integers, so
/// the `StringUint64Uint64` comparator orders them before every posting.
const SCHEMA_KEY: &[u8] = b"\0schema";
const INDEXED_THROUGH_KEY: &[u8] = b"\0through";

/// Keys of `wok_Event__tagKindBuild`, which holds a key-ordered pass while
/// one runs and nothing otherwise.
const PASS_TARGET_KEY: &[u8] = b"target";
const PASS_VISITED_KEY: &[u8] = b"visited";
const PASS_CURSOR_KEY: &[u8] = b"cursor";

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
    /// The key-ordered pass that builds the table, while one runs.
    pub bulk_pass: Option<TagKindBulkPass>,
}

/// A key-ordered pass over `Event__tag` that builds the table from marker 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TagKindBulkPass {
    /// The high-water mark when the pass began; the marker once it ends.
    pub target: u64,
    /// `Event__tag` entries visited so far.
    pub visited: u64,
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
    let sequence = match txn.env().dbis().state {
        Some(state) => txn.get(state, crate::state::HIGH_WATER)?,
        None => None,
    };
    let high_water = high_water(sequence, txn.largest_integer_key(txn.env().dbis().event)?);
    let bulk_pass = match txn.env().dbis().event_tag_kind_build {
        Some(build) => read_pass(
            txn.get(build, PASS_TARGET_KEY)?,
            txn.get(build, PASS_VISITED_KEY)?,
        ),
        None => None,
    };
    Ok(Some(TagKindIndexState {
        schema: marker(txn.get(dbi, SCHEMA_KEY)?),
        indexed_through: marker(txn.get(dbi, INDEXED_THROUGH_KEY)?).unwrap_or(0),
        high_water,
        bulk_pass,
    }))
}

/// Whether a query reading this snapshot may rely on the index: every event
/// stored in it has its entries. Readers must still skip stale entries.
pub fn tag_kind_index_complete_ro(txn: &RoTxn<'_>) -> Result<bool, DbError> {
    Ok(tag_kind_index_state_ro(txn)?.is_some_and(|state| state.complete()))
}

/// The greatest local id ever allocated. The stored sequence covers deleted
/// tails, and the newest record covers a database whose sequence was never
/// stored. A malformed sequence is integrity's to report; the newest record
/// still bounds the events.
fn high_water(sequence: Option<&[u8]>, newest_event: u64) -> u64 {
    sequence
        .and_then(|raw| crate::state::decode(raw).ok())
        .unwrap_or(0)
        .max(newest_event)
}

fn set_marker(txn: &mut RwTxn<'_>, dbi: MDB_dbi, key: &[u8], value: u64) -> Result<(), DbError> {
    // A DUPSORT key keeps every value put under it; replace the one there.
    txn.del(dbi, key, None)?;
    txn.put(dbi, key, &value.to_ne_bytes(), 0)?;
    Ok(())
}

/// Record that the table holds this layout and every event up to
/// `indexed_through`, with no pass running, after a rebuild derived all of
/// them or a reset emptied it.
pub(crate) fn initialize_tag_kind_index_state(
    txn: &mut RwTxn<'_>,
    indexed_through: u64,
) -> Result<(), DbError> {
    let Some(dbi) = txn.env().dbis().event_tag_kind else {
        return Ok(());
    };
    if let Some(build) = txn.env().dbis().event_tag_kind_build {
        txn.clear(build)?;
    }
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

/// Empty the table and restart its marker at 0, so that the backfill indexes
/// every stored event again.
pub fn reset_tag_kind_index(txn: &mut RwTxn<'_>) -> Result<(), DbError> {
    let Some(dbi) = txn.env().dbis().event_tag_kind else {
        return Ok(());
    };
    txn.clear(dbi)?;
    initialize_tag_kind_index_state(txn, 0)
}

/// What one backfill step did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TagKindBackfillStep {
    /// Postings the step put.
    pub entries: u64,
    /// `Event__tag` entries stored, which a key-ordered pass visits once.
    pub tag_entries: u64,
    /// The table's state once the step commits.
    pub state: TagKindIndexState,
}

/// Do one bounded step of the backfill in `txn`. A table at marker 0 with
/// events stored is built by a key-ordered pass over `Event__tag`; anything
/// else above the marker is indexed in local-id order. A step stops after
/// `max_entries` postings, or once it has run for `budget`, whichever comes
/// first, and always makes some progress. `None` when the table is absent or
/// not in this release's layout.
pub fn backfill_tag_kind_index(
    txn: &mut RwTxn<'_>,
    max_entries: usize,
    budget: Duration,
) -> Result<Option<TagKindBackfillStep>, DbError> {
    let started = Instant::now();
    let dbis = txn.env().dbis();
    let Some(dbi) = dbis.event_tag_kind else {
        return Ok(None);
    };
    if marker(txn.get(dbi, SCHEMA_KEY)?) != Some(TAG_KIND_SCHEMA_VERSION) {
        return Ok(None);
    }
    let limits = StepLimits {
        started,
        max_entries: max_entries.max(1),
        budget,
    };
    let through = marker(txn.get(dbi, INDEXED_THROUGH_KEY)?).unwrap_or(0);
    let sequence = match dbis.state {
        Some(state) => txn.get(state, crate::state::HIGH_WATER)?,
        None => None,
    };
    let high_water = high_water(sequence, txn.largest_integer_key(dbis.event)?)
        .max(txn.event_sequence.unwrap_or(0));
    let tag_entries = txn.entries(dbis.event_tag)? as u64;
    let mut pass = None;
    if let Some(build) = dbis.event_tag_kind_build {
        pass = read_pass(
            txn.get(build, PASS_TARGET_KEY)?,
            txn.get(build, PASS_VISITED_KEY)?,
        );
        if pass.is_none() && through == 0 && txn.entries(dbis.event)? != 0 {
            // A new pass covers every event stored when it begins.
            txn.clear(build)?;
            let start = TagKindBulkPass {
                target: high_water,
                visited: 0,
            };
            write_pass(txn, build, start)?;
            pass = Some(start);
        }
    }
    let (entries, indexed_through, pass) = match (pass, dbis.event_tag_kind_build) {
        (Some(pass), Some(build)) => key_ordered_step(txn, dbi, build, pass, through, limits)?,
        _ => {
            let (entries, indexed_through) = local_id_step(txn, dbi, through, high_water, limits)?;
            (entries, indexed_through, None)
        }
    };
    Ok(Some(TagKindBackfillStep {
        entries,
        tag_entries,
        state: TagKindIndexState {
            schema: Some(TAG_KIND_SCHEMA_VERSION),
            indexed_through,
            high_water,
            bulk_pass: pass,
        },
    }))
}

#[derive(Clone, Copy)]
struct StepLimits {
    started: Instant,
    max_entries: usize,
    budget: Duration,
}

impl StepLimits {
    /// Whether a step that has put `entries` postings stops here.
    fn reached(&self, entries: usize) -> bool {
        entries >= self.max_entries || self.started.elapsed() >= self.budget
    }
}

/// Continue the key-ordered pass from its cursor. Postings for one tag value
/// sit next to each other, so a step dirties few pages, where local-id order
/// would dirty about one page per posting. The marker moves to the pass's
/// target once the walk reaches the end of `Event__tag`.
fn key_ordered_step(
    txn: &mut RwTxn<'_>,
    dbi: MDB_dbi,
    build: MDB_dbi,
    mut pass: TagKindBulkPass,
    through: u64,
    limits: StepLimits,
) -> Result<(u64, u64, Option<TagKindBulkPass>), DbError> {
    let cursor = txn.get(build, PASS_CURSOR_KEY)?.and_then(read_cursor);
    let (start_key, start_dup) = match &cursor {
        // Resume after the last entry visited, whether or not it remains.
        Some((key, lev_id)) => (key.clone(), lev_id.saturating_add(1).to_ne_bytes().to_vec()),
        None => (Vec::new(), Vec::new()),
    };
    let mut batch = Vec::new();
    let mut error = None;
    let walked_to_end = txn.foreach_full(
        txn.env().dbis().event_tag,
        &start_key,
        &start_dup,
        false,
        |key, value| {
            match crate::keys::u64_from_ne_checked(value) {
                Ok(lev_id) => batch.push((key.to_vec(), lev_id)),
                Err(err) => error = Some(err),
            }
            error.is_none() && batch.len() < limits.max_entries
        },
    )?;
    if let Some(error) = error {
        return Err(error);
    }
    let mut visited = 0;
    let mut entries = 0u64;
    for (key, lev_id) in &batch {
        visited += 1;
        let (tag, created_at) = crate::keys::parse_key_string_u64(key)?;
        // A tag entry whose event is gone gets no posting; integrity
        // reports it in `Event__tag`.
        let kind = match txn.get_u64(txn.env().dbis().event, *lev_id)? {
            Some(raw) => Some(PackedEventView::new(raw)?.kind()),
            None => None,
        };
        if let (Some(kind), Some((&name, value))) = (kind, tag.split_first()) {
            txn.put(
                dbi,
                &tag_kind_key(name, value, kind, created_at),
                &lev_id.to_ne_bytes(),
                0,
            )?;
            entries += 1;
        }
        if limits.reached(visited) {
            break;
        }
    }
    pass.visited += visited as u64;
    if walked_to_end && visited == batch.len() {
        // Every event at or below the target has its postings.
        let indexed_through = pass.target.max(through);
        txn.clear(build)?;
        set_marker(txn, dbi, INDEXED_THROUGH_KEY, indexed_through)?;
        return Ok((entries, indexed_through, None));
    }
    let (key, lev_id) = &batch[visited - 1];
    let mut cursor = key.clone();
    cursor.extend_from_slice(&lev_id.to_ne_bytes());
    txn.put(build, PASS_CURSOR_KEY, &cursor, 0)?;
    write_pass(txn, build, pass)?;
    Ok((entries, through, Some(pass)))
}

/// Index the stored events above the marker in local-id order and move the
/// marker past them. Every id above the marker is visited, since postings
/// the writer put for newer events say nothing of the ids below them;
/// putting those again changes nothing. A step that reaches the newest
/// stored event moves the marker to the high-water mark.
fn local_id_step(
    txn: &mut RwTxn<'_>,
    dbi: MDB_dbi,
    through: u64,
    high_water: u64,
    limits: StepLimits,
) -> Result<(u64, u64), DbError> {
    let mut batch = Vec::new();
    let mut error = None;
    let mut walked_to_end = true;
    if through < high_water {
        walked_to_end = txn.foreach_full(
            txn.env().dbis().event,
            &through.saturating_add(1).to_ne_bytes(),
            &[],
            false,
            |key, value| {
                let event = crate::keys::u64_from_ne_checked(key)
                    .and_then(|lev_id| Ok((lev_id, tag_kind_keys(PackedEventView::new(value)?))));
                match event {
                    Ok(event) => batch.push(event),
                    Err(err) => error = Some(err),
                }
                error.is_none() && batch.len() < limits.max_entries
            },
        )?;
    }
    if let Some(error) = error {
        return Err(error);
    }
    let mut done = 0;
    let mut entries = 0;
    for (lev_id, keys) in &batch {
        put_tag_kind_entries(txn, *lev_id, keys)?;
        done += 1;
        entries += keys.len();
        if limits.reached(entries) {
            break;
        }
    }
    let indexed_through = if walked_to_end && done == batch.len() {
        high_water
    } else {
        batch[done - 1].0
    }
    .max(through);
    if indexed_through != through {
        set_marker(txn, dbi, INDEXED_THROUGH_KEY, indexed_through)?;
    }
    Ok((entries as u64, indexed_through))
}

fn read_pass(target: Option<&[u8]>, visited: Option<&[u8]>) -> Option<TagKindBulkPass> {
    Some(TagKindBulkPass {
        target: marker(target)?,
        visited: marker(visited)?,
    })
}

fn write_pass(txn: &mut RwTxn<'_>, build: MDB_dbi, pass: TagKindBulkPass) -> Result<(), DbError> {
    txn.put(build, PASS_TARGET_KEY, &pass.target.to_ne_bytes(), 0)?;
    txn.put(build, PASS_VISITED_KEY, &pass.visited.to_ne_bytes(), 0)?;
    Ok(())
}

/// The `Event__tag` key and local id last visited, stored as the key followed
/// by the id.
fn read_cursor(raw: &[u8]) -> Option<(Vec<u8>, u64)> {
    let (key, lev_id) = raw.split_at(raw.len().checked_sub(8)?);
    (key.len() > 8).then(|| (key.to_vec(), u64::from_ne_bytes(lev_id.try_into().unwrap())))
}

/// Whether `wok_Event__tagKindBuild` holds `key` with a value of this shape.
pub(crate) fn is_valid_pass_record(key: &[u8], value: &[u8]) -> bool {
    match key {
        PASS_TARGET_KEY | PASS_VISITED_KEY => value.len() == 8,
        PASS_CURSOR_KEY => read_cursor(value).is_some(),
        _ => false,
    }
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
        assert_eq!(
            (tag_kind.expected_entries, tag_kind.missing_entries),
            (2, 0)
        );
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

    fn step_within(env: &Env, max_entries: usize, budget: Duration) -> TagKindBackfillStep {
        let mut txn = env.begin_rw().unwrap();
        let step = backfill_tag_kind_index(&mut txn, max_entries, budget)
            .unwrap()
            .unwrap();
        txn.commit().unwrap();
        assert_eq!(step.state, state(env));
        step
    }

    fn step(env: &Env, max_entries: usize) -> TagKindBackfillStep {
        step_within(env, max_entries, Duration::MAX)
    }

    /// The postings put, the marker, and the entries the pass has visited.
    fn progress(step: TagKindBackfillStep) -> (u64, u64, Option<u64>) {
        (
            step.entries,
            step.state.indexed_through,
            step.state.bulk_pass.map(|pass| pass.visited),
        )
    }

    fn reset(env: &Env) {
        let mut txn = env.begin_rw().unwrap();
        reset_tag_kind_index(&mut txn).unwrap();
        txn.commit().unwrap();
    }

    fn delete(env: &Env, lev_id: u64) {
        let mut txn = env.begin_rw().unwrap();
        crate::delete_events(&mut txn, &mut NoopNegentropy, [lev_id]).unwrap();
        txn.commit().unwrap();
    }

    fn assert_complete_and_consistent(env: &Env) {
        let report = check_integrity(&env.begin_ro().unwrap()).unwrap();
        assert!(report.ok(), "{:#?}", report.issues);
        let tag_kind = report.tag_kind_index.unwrap();
        assert!(tag_kind.complete, "{tag_kind:?}");
        assert_eq!(tag_kind.state.bulk_pass, None);
        assert_eq!(tag_kind.stale_entries, 0);
        assert_eq!(tag_kind.actual_entries, tag_kind.expected_entries);
        assert!(tag_kind_index_complete_ro(&env.begin_ro().unwrap()).unwrap());
    }

    fn unindexed(events: u64) -> (tempfile::TempDir, Env) {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        for time in 0..events {
            write(&env, 100 + time);
        }
        reset(&env);
        assert_eq!(postings(&env), 0);
        assert!(!tag_kind_index_complete_ro(&env.begin_ro().unwrap()).unwrap());
        (dir, env)
    }

    #[test]
    fn a_key_ordered_pass_builds_the_table_in_bounded_steps() {
        let (_dir, env) = unindexed(25);
        let steps: Vec<_> = (0..3).map(|_| progress(step(&env, 10))).collect();
        // The marker stays at 0 until the pass ends, then takes its target.
        assert_eq!(steps, [(10, 0, Some(10)), (10, 0, Some(20)), (5, 25, None)]);
        assert_eq!(postings(&env), 25);
        assert_complete_and_consistent(&env);
        // A complete index needs nothing more.
        assert_eq!(progress(step(&env, 10)), (0, 25, None));
    }

    #[test]
    fn a_step_out_of_time_still_makes_progress() {
        let (_dir, env) = unindexed(3);
        let steps: Vec<_> = (0..4)
            .map(|_| progress(step_within(&env, 10, Duration::ZERO)))
            .collect();
        // The third step reaches the last entry and ends the pass.
        assert_eq!(
            steps,
            [(1, 0, Some(1)), (1, 0, Some(2)), (1, 3, None), (0, 3, None)]
        );
        assert_complete_and_consistent(&env);
    }

    #[test]
    fn a_key_ordered_pass_resumes_from_its_cursor_after_a_restart() {
        let (dir, env) = unindexed(25);
        assert_eq!(progress(step(&env, 10)), (10, 0, Some(10)));
        // A step that does not commit leaves no progress behind.
        let mut txn = env.begin_rw().unwrap();
        backfill_tag_kind_index(&mut txn, 10, Duration::MAX)
            .unwrap()
            .unwrap();
        txn.abort();
        drop(env);

        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        assert_eq!(
            state(&env).bulk_pass,
            Some(TagKindBulkPass {
                target: 25,
                visited: 10
            })
        );
        assert_eq!(postings(&env), 10);
        assert_eq!(progress(step(&env, 100)), (15, 25, None));
        assert_complete_and_consistent(&env);
    }

    #[test]
    fn writes_during_a_key_ordered_pass_keep_the_table_exact() {
        let (_dir, env) = unindexed(20);
        assert_eq!(progress(step(&env, 8)), (8, 0, Some(8)));
        // This release indexes what it writes; deletions remove postings
        // whether or not the pass has reached them.
        let written = write(&env, 50);
        delete(&env, 3);
        delete(&env, 15);
        assert_eq!(postings(&env), 8);
        while state(&env).bulk_pass.is_some() {
            step(&env, 8);
        }
        assert_eq!(state(&env).indexed_through, 20);
        assert_eq!(postings(&env), 19);
        // The marker reached the target; the write path covered the rest.
        step(&env, 8);
        assert_eq!(state(&env).indexed_through, written.lev_id);
        assert_complete_and_consistent(&env);
    }

    #[test]
    fn local_id_steps_catch_up_what_an_earlier_release_inserted_during_a_pass() {
        let (_dir, env) = unindexed(10);
        assert_eq!(progress(step(&env, 4)), (4, 0, Some(4)));
        let earlier = write(&env, 50);
        as_if_inserted_by_an_earlier_release(&env, &earlier, 0);
        while state(&env).bulk_pass.is_some() {
            step(&env, 4);
        }
        // The pass covers the events stored when it began; the earlier
        // release's event above them is not indexed yet.
        let after_pass = state(&env);
        assert_eq!(
            (after_pass.indexed_through, after_pass.high_water),
            (10, 11)
        );
        assert!(!after_pass.complete());
        assert_eq!(progress(step(&env, 4)), (1, 11, None));
        assert_eq!(postings(&env), 11);
        assert_complete_and_consistent(&env);
    }

    #[test]
    fn local_id_steps_catch_up_events_an_earlier_release_inserted() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        write(&env, 100);
        write(&env, 101);
        let earlier = write(&env, 102);
        as_if_inserted_by_an_earlier_release(&env, &earlier, 2);
        // This release's next write indexes its own event above the gap.
        write(&env, 103);
        assert_eq!(postings(&env), 3);

        // The marker is past 0, so no key-ordered pass starts.
        assert_eq!(progress(step(&env, 10)), (2, 4, None));
        assert_eq!(postings(&env), 4);
        assert_complete_and_consistent(&env);
        // Writes move the marker again once the gap is closed.
        write(&env, 104);
        assert_eq!(state(&env).indexed_through, 5);
    }

    #[test]
    fn local_id_steps_are_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        write(&env, 100);
        let earlier: Vec<_> = (0..5).map(|time| write(&env, 101 + time)).collect();
        for event in &earlier {
            as_if_inserted_by_an_earlier_release(&env, event, 1);
        }
        let steps: Vec<_> = (0..3).map(|_| progress(step(&env, 2))).collect();
        assert_eq!(steps, [(2, 3, None), (2, 5, None), (1, 6, None)]);
        assert_complete_and_consistent(&env);
    }

    #[test]
    fn a_pass_past_a_deleted_tail_ends_at_the_high_water_mark() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let events: Vec<_> = (0..5).map(|time| write(&env, 100 + time)).collect();
        delete(&env, events[3].lev_id);
        delete(&env, events[4].lev_id);
        reset(&env);
        // Three entries fill this step exactly; the next finds no more and
        // ends the pass at the high-water mark.
        assert_eq!(progress(step(&env, 3)), (3, 0, Some(3)));
        assert_eq!(progress(step(&env, 3)), (0, 5, None));
        assert_complete_and_consistent(&env);
        assert_eq!(write(&env, 105).lev_id, 6);
        assert_eq!(state(&env).indexed_through, 6);
    }

    #[test]
    fn a_malformed_pass_starts_over_and_integrity_reports_it() {
        let (_dir, env) = unindexed(5);
        step(&env, 2);
        let build = env.dbis().event_tag_kind_build.unwrap();
        let mut txn = env.begin_rw().unwrap();
        txn.put(build, PASS_VISITED_KEY, b"short", 0).unwrap();
        txn.commit().unwrap();
        let report = check_integrity(&env.begin_ro().unwrap()).unwrap();
        assert!(!report.ok());
        assert!(report
            .issues
            .iter()
            .any(|issue| issue.table == "event_tag_kind_build"));
        assert_eq!(state(&env).bulk_pass, None);

        assert_eq!(progress(step(&env, 10)), (5, 5, None));
        assert_complete_and_consistent(&env);
    }

    #[test]
    fn backfill_leaves_a_table_in_another_layout_alone() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        write(&env, 100);
        let dbi = env.dbis().event_tag_kind.unwrap();
        let mut txn = env.begin_rw().unwrap();
        set_marker(&mut txn, dbi, SCHEMA_KEY, TAG_KIND_SCHEMA_VERSION + 1).unwrap();
        set_marker(&mut txn, dbi, INDEXED_THROUGH_KEY, 0).unwrap();
        assert_eq!(
            backfill_tag_kind_index(&mut txn, 10, Duration::MAX).unwrap(),
            None
        );
        txn.commit().unwrap();
        assert_eq!(state(&env).indexed_through, 0);
    }
}
