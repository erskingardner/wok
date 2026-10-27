//! Database integrity checks for primaries, payloads, metadata, and every
//! event-derived secondary index.

use crate::fbs::{decode_compression_dictionary, decode_meta, decode_negentropy_filter};
use crate::payload::{parse_payload, Decompressor, PayloadView};
use crate::search::{is_search_marker, search_index_entries, search_term_from_key};
use crate::tag_kind::{
    is_tag_kind_marker, is_valid_pass_record, tag_kind_index_state_ro, tag_kind_keys,
    TagKindIndexState, TAG_KIND_SCHEMA_VERSION,
};
use crate::txn::RoTxn;
use crate::write::{event_index_entries, replace_key, EventIndexEntry};
use crate::DbError;
use lmdb_sys::MDB_dbi;
use serde::Serialize;
use std::collections::HashMap;
use wok_event::PackedEventView;

const MAX_REPORTED_ISSUES: usize = 100;

/// Local-id buckets in a [`PostingBalance`]: 8 MiB of counters, whatever the
/// size of the database.
const BALANCE_BUCKETS: usize = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IntegrityIssue {
    pub category: &'static str,
    pub table: &'static str,
    pub detail: String,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct IntegrityReport {
    pub events: u64,
    pub payloads: u64,
    /// Structurally valid replacement groups retaining more than one version.
    /// Advisory only: lossless migration is allowed to preserve this history.
    pub superseded_groups: u64,
    pub superseded_events: u64,
    /// Records whose PackedEvent lacks single-letter tag values longer than
    /// 255 bytes, as packed by strfry or by earlier Wok releases, and that
    /// `wok reindex` would pack again. Advisory, counted where payloads are
    /// decoded (databases with the search table).
    pub legacy_long_tag_records: u64,
    /// Deletion requests stored by strfry or earlier Wok releases that lack a
    /// tombstone those releases did not index: for a plain replaceable
    /// address (`<kind>:<pubkey>:`), or for the canonical spelling of an
    /// address whose kind an `a` tag pads with leading zeros. Advisory:
    /// `wok reindex` adds the tombstones and deletes the versions the
    /// requests name.
    pub legacy_untombstoned_deletions: u64,
    pub expected_index_entries: u64,
    pub actual_index_entries: u64,
    pub missing_payloads: Vec<u64>,
    pub orphan_payloads: Vec<u64>,
    pub missing_index_entries: u64,
    pub extra_index_entries: u64,
    pub malformed_records: u64,
    pub packed_parse_errors: u64,
    pub payload_parse_errors: u64,
    pub metadata_errors: u64,
    pub author_counts_checked: u64,
    pub author_count_errors: u64,
    pub lookup_errors: u64,
    /// The `(tag, kind, created_at)` index, when the database has the table.
    pub tag_kind_index: Option<TagKindIndexReport>,
    pub issues: Vec<IntegrityIssue>,
}

/// What integrity found in `wok_Event__tagKind`. It is checked apart from the
/// other indexes, whose entries every event must have: here only the events
/// at or below the table's marker must have theirs.
#[derive(Debug, Clone, Serialize)]
pub struct TagKindIndexReport {
    #[serde(flatten)]
    pub state: TagKindIndexState,
    /// Every stored event has its entries, so queries may rely on the index.
    pub complete: bool,
    /// `Event__tag` entries, which a key-ordered pass visits once.
    pub tag_entries: u64,
    /// Entries derived from the events at or below `indexed_through`.
    pub expected_entries: u64,
    /// Postings stored, markers excluded.
    pub actual_entries: u64,
    /// Entries that an event at or below `indexed_through` lacks. Queries
    /// relying on the index would miss the event.
    pub missing_entries: u64,
    /// Entries naming a stored event that does not derive them, or
    /// malformed. Neither the writer nor an earlier release writes these.
    pub unexpected_entries: u64,
    /// Entries naming an event that is no longer stored: an earlier Wok
    /// release deleted it. Advisory: readers skip them, and `wok reindex`
    /// rebuilds the table without them.
    pub stale_entries: u64,
}

impl TagKindIndexReport {
    fn new(state: TagKindIndexState, tag_entries: u64) -> Self {
        Self {
            state,
            complete: state.complete(),
            tag_entries,
            expected_entries: 0,
            actual_entries: 0,
            missing_entries: 0,
            unexpected_entries: 0,
            stale_entries: 0,
        }
    }

    /// Whether this release can derive the stored postings: its own layout,
    /// or a table not initialized yet that only its writer filled.
    fn verifiable(&self) -> bool {
        matches!(self.state.schema, None | Some(TAG_KIND_SCHEMA_VERSION))
    }

    /// The greatest local id whose event must have its entries.
    fn expected_through(&self) -> u64 {
        if self.state.schema == Some(TAG_KIND_SCHEMA_VERSION) {
            self.state.indexed_through
        } else {
            0
        }
    }
}

impl IntegrityReport {
    pub fn ok(&self) -> bool {
        self.missing_payloads.is_empty()
            && self.orphan_payloads.is_empty()
            && self.missing_index_entries == 0
            && self.extra_index_entries == 0
            && self.malformed_records == 0
            && self.packed_parse_errors == 0
            && self.payload_parse_errors == 0
            && self.metadata_errors == 0
            && self.author_count_errors == 0
            && self.lookup_errors == 0
            && self.tag_kind_index.as_ref().is_none_or(|tag_kind| {
                tag_kind.missing_entries == 0 && tag_kind.unexpected_entries == 0
            })
    }

    fn issue(&mut self, category: &'static str, table: &'static str, detail: String) {
        if self.issues.len() < MAX_REPORTED_ISSUES {
            self.issues.push(IntegrityIssue {
                category,
                table,
                detail,
            });
        }
    }
}

fn read_u64(bytes: &[u8]) -> Option<u64> {
    Some(u64::from_ne_bytes(bytes.try_into().ok()?))
}

/// Balances the postings of one table, or of several, against the entries
/// their events derive, so that each event's entries are derived once rather
/// than once per posting.
/// The event pass subtracts, in the bucket of the event's local id, each entry
/// it derives and finds stored; the postings pass adds each posting that names
/// an event the event pass derived, a lookup with no derivation. Every bucket
/// then holds the postings that its events do not derive. Only the events of
/// a bucket left positive are derived again, to name those postings.
struct PostingBalance(Vec<i64>);

impl PostingBalance {
    fn new(buckets: usize) -> Self {
        Self(vec![0; buckets])
    }

    fn bucket(&self, lev_id: u64) -> usize {
        (lev_id % self.0.len() as u64) as usize
    }

    /// The event pass found an entry of the event at `lev_id` stored.
    fn derived(&mut self, lev_id: u64) {
        let bucket = self.bucket(lev_id);
        self.0[bucket] -= 1;
    }

    /// A posting names the readable event at `lev_id`.
    fn stored(&mut self, lev_id: u64) {
        let bucket = self.bucket(lev_id);
        self.0[bucket] += 1;
    }

    /// Postings that their event does not derive.
    fn unexpected(&self) -> u64 {
        self.0.iter().map(|&count| count.max(0) as u64).sum()
    }

    /// Whether the bucket of `lev_id` holds postings not named yet.
    fn suspect(&self, lev_id: u64) -> bool {
        self.0[self.bucket(lev_id)] > 0
    }

    /// One of the postings of the bucket of `lev_id` is named.
    fn named(&mut self, lev_id: u64) {
        let bucket = self.bucket(lev_id);
        self.0[bucket] -= 1;
    }
}

/// Report the `remaining` postings of `dbi` that `balance` counted as
/// unexpected, in key order, while the report has room. `unexpected` derives
/// the event of a posting in a suspect bucket and gives the issue's detail
/// when it is one that the balance counted and that its event does not derive.
fn name_unexpected_postings(
    txn: &RoTxn<'_>,
    dbi: MDB_dbi,
    table: &'static str,
    mut remaining: u64,
    balance: &mut PostingBalance,
    report: &mut IntegrityReport,
    mut unexpected: impl FnMut(&[u8], u64) -> Option<String>,
) -> Result<(), DbError> {
    if remaining == 0 || report.issues.len() >= MAX_REPORTED_ISSUES {
        return Ok(());
    }
    txn.foreach_full(dbi, &[], &[], false, |key, value| {
        let Some(lev_id) = read_u64(value) else {
            return true;
        };
        if !balance.suspect(lev_id) {
            return true;
        }
        if let Some(detail) = unexpected(key, lev_id) {
            balance.named(lev_id);
            remaining -= 1;
            report.issue("unexpected-index", table, detail);
        }
        remaining > 0 && report.issues.len() < MAX_REPORTED_ISSUES
    })?;
    Ok(())
}

/// Whether the event pass derives the entries of the event at `lev_id`: it is
/// stored, with a PackedEvent long enough to read.
fn readable_event(txn: &RoTxn<'_>, lev_id: u64) -> bool {
    matches!(
        txn.get_u64(txn.env().dbis().event, lev_id),
        Ok(Some(raw)) if PackedEventView::new(raw).is_ok()
    )
}

/// Whether the event at `lev_id`, whose payload is `payload`, derives the
/// search posting `key`.
fn derives_search_posting(
    txn: &RoTxn<'_>,
    decompressor: &mut Decompressor,
    payload: &[u8],
    lev_id: u64,
    key: &[u8],
) -> bool {
    decompressor
        .decode(txn, payload, 16 * 1024 * 1024)
        .ok()
        .and_then(|json| search_index_entries(lev_id, json).ok())
        .is_some_and(|entries| entries.iter().any(|(expected, _)| expected == key))
}

fn entry_exists(txn: &RoTxn<'_>, entry: &EventIndexEntry) -> Result<bool, DbError> {
    let mut found = false;
    txn.foreach_full(entry.dbi, &entry.key, &entry.value, false, |key, value| {
        found = key == entry.key && value == entry.value;
        false
    })?;
    Ok(found)
}

fn check_metadata_tables(txn: &RoTxn<'_>, report: &mut IntegrityReport) -> Result<(), DbError> {
    let dbis = txn.env().dbis();
    if txn.get_u64(dbis.meta, 1)?.is_none() {
        report.metadata_errors += 1;
        report.issue("missing", "meta", "missing required Meta record 1".into());
    }
    txn.foreach_full(dbis.meta, &[], &[], false, |key, value| {
        if read_u64(key).is_none() {
            report.malformed_records += 1;
            report.issue(
                "malformed-key",
                "meta",
                format!("key has {} bytes", key.len()),
            );
        }
        if let Err(error) = decode_meta(value) {
            report.metadata_errors += 1;
            report.issue("decode", "meta", error.to_string());
        }
        true
    })?;

    txn.foreach_full(dbis.negentropy_filter, &[], &[], false, |key, value| {
        if read_u64(key).is_none() {
            report.malformed_records += 1;
            report.issue(
                "malformed-key",
                "negentropy_filter",
                format!("key has {} bytes", key.len()),
            );
        }
        if let Err(error) = decode_negentropy_filter(value) {
            report.metadata_errors += 1;
            report.issue("decode", "negentropy_filter", error.to_string());
        }
        true
    })?;

    txn.foreach_full(
        dbis.compression_dictionary,
        &[],
        &[],
        false,
        |key, value| {
            if read_u64(key).is_none() {
                report.malformed_records += 1;
                report.issue(
                    "malformed-key",
                    "compression_dictionary",
                    format!("key has {} bytes", key.len()),
                );
            }
            if let Err(error) = decode_compression_dictionary(value) {
                report.metadata_errors += 1;
                report.issue("decode", "compression_dictionary", error.to_string());
            }
            true
        },
    )?;

    txn.foreach_full(dbis.negentropy, &[], &[], false, |key, value| {
        if key.len() != 16 {
            report.malformed_records += 1;
            report.issue(
                "malformed-key",
                "negentropy",
                format!("key has {} bytes, expected 16", key.len()),
            );
            return true;
        }
        // node_id == 0 is the per-tree metadata record (root || next ids).
        if u64::from_ne_bytes(key[8..16].try_into().unwrap()) == 0 {
            if value.len() != 16 {
                report.malformed_records += 1;
                report.issue(
                    "malformed-value",
                    "negentropy",
                    format!("metadata value has {} bytes, expected 16", value.len()),
                );
            }
            return true;
        }
        // B-tree node record: fixed 3952-byte encoding (32-byte header +
        // 32-byte accumulator + 81 keys x 48 bytes), num_items in 1..=80 —
        // zero-item nodes are never persisted and larger counts are rejected
        // at decode time.
        const NODE_SIZE: usize = 3952;
        if value.len() != NODE_SIZE {
            report.malformed_records += 1;
            report.issue(
                "malformed-value",
                "negentropy",
                format!("node has {} bytes, expected {NODE_SIZE}", value.len()),
            );
            return true;
        }
        let num_items = u64::from_ne_bytes(value[..8].try_into().unwrap());
        if !(1..=80).contains(&num_items) {
            report.malformed_records += 1;
            report.issue(
                "malformed-value",
                "negentropy",
                format!("node has num_items {num_items}, expected 1..=80"),
            );
        }
        true
    })?;
    if let Some(vanish_pubkey) = dbis.vanish_pubkey {
        txn.foreach_full(vanish_pubkey, &[], &[], false, |key, value| {
            if key.len() != 32 {
                report.malformed_records += 1;
                report.issue(
                    "malformed-key",
                    "vanish_pubkey",
                    format!("key has {} bytes, expected 32", key.len()),
                );
            }
            if value.len() != 8 {
                report.malformed_records += 1;
                report.issue(
                    "malformed-value",
                    "vanish_pubkey",
                    format!("value has {} bytes, expected 8", value.len()),
                );
            }
            true
        })?;
    }
    Ok(())
}

/// Author counts are rebuildable; the historical sequence is not. Missing
/// keys are legitimate lazy initialization, but an existing sequence must
/// cover every surviving local ID. Deleted-tail history cannot be reconstructed
/// from the current snapshot and must never be inferred to be zero.
fn check_state(
    txn: &RoTxn<'_>,
    report: &mut IntegrityReport,
    authors: &HashMap<[u8; 32], u64>,
    largest_id: u64,
) -> Result<(), DbError> {
    let Some(dbi) = txn.env().dbis().state else {
        let version = txn
            .get_u64(txn.env().dbis().meta, 1)?
            .and_then(|raw| decode_meta(raw).ok())
            .map(|meta| meta.db_version);
        if version.is_some_and(|version| version >= 5) {
            report.metadata_errors += 1;
            report.issue(
                "missing-table",
                "state",
                "v5 database has no wok_State table".into(),
            );
        }
        return Ok(());
    };
    txn.foreach_full(dbi, &[], &[], false, |key, raw| {
        if key.first() == Some(&b'a') {
            let Ok(author): Result<&[u8; 32], _> = key[1..].try_into() else {
                report.author_count_errors += 1;
                report.issue(
                    "malformed-key",
                    "author_counts",
                    format!("key has {} bytes, expected 33", key.len()),
                );
                return true;
            };
            report.author_counts_checked += 1;
            match crate::state::decode(raw) {
                Ok(count) => {
                    let expected = authors.get(author).copied().unwrap_or(0);
                    if count != expected {
                        report.author_count_errors += 1;
                        report.issue(
                            "counter-mismatch",
                            "author_counts",
                            format!(
                                "author {}: stored {count}, primary records {expected}",
                                wok_event::to_hex(author)
                            ),
                        );
                    }
                }
                Err(error) => {
                    report.author_count_errors += 1;
                    report.issue("malformed-value", "author_counts", error.to_string());
                }
            }
        } else if key == crate::state::HIGH_WATER
            || key == crate::state::POLICY_GENERATION
            || key == crate::state::SUPERSEDED_EVENTS
            || key == crate::state::LEGACY_SUPERSEDED_EVENTS
        {
            match crate::state::decode(raw) {
                Ok(sequence) if key == crate::state::HIGH_WATER && sequence < largest_id => {
                    report.metadata_errors += 1;
                    report.issue(
                        "sequence-regression",
                        "state",
                        format!("stored sequence {sequence} is below greatest surviving local ID {largest_id}"),
                    );
                }
                Ok(_) => {}
                Err(error) => {
                    report.metadata_errors += 1;
                    report.issue(
                        "malformed-value",
                        "state",
                        format!("{}: {error}", String::from_utf8_lossy(key)),
                    );
                }
            }
        } else {
            report.metadata_errors += 1;
            report.issue(
                "malformed-key",
                "state",
                format!("unknown key {}", wok_event::to_hex(key)),
            );
        }
        true
    })?;
    Ok(())
}

fn check_payload(txn: &RoTxn<'_>, lev_id: u64, raw: &[u8], report: &mut IntegrityReport) {
    match parse_payload(raw) {
        Ok(PayloadView::Raw(json)) => {
            if std::str::from_utf8(json).is_err() {
                report.payload_parse_errors += 1;
                report.issue(
                    "decode",
                    "event_payload",
                    format!("levId {lev_id}: invalid UTF-8"),
                );
            }
        }
        Ok(PayloadView::Zstd { dict_id, .. }) => {
            match txn.get_u64(txn.env().dbis().compression_dictionary, dict_id as u64) {
                Ok(Some(_)) => {}
                Ok(None) => {
                    report.payload_parse_errors += 1;
                    report.issue(
                        "missing-dictionary",
                        "event_payload",
                        format!("levId {lev_id}: dictId {dict_id}"),
                    );
                }
                Err(error) => {
                    report.payload_parse_errors += 1;
                    report.lookup_errors += 1;
                    report.issue("lookup", "event_payload", error.to_string());
                }
            }
        }
        Err(error) => {
            report.payload_parse_errors += 1;
            report.issue(
                "decode",
                "event_payload",
                format!("levId {lev_id}: {error}"),
            );
        }
    }
}

/// Check every `wok_Event__tagKind` posting against the event it names.
fn check_tag_kind_postings(
    txn: &RoTxn<'_>,
    dbi: MDB_dbi,
    tag_kind: &mut TagKindIndexReport,
    balance: &mut PostingBalance,
    report: &mut IntegrityReport,
) -> Result<(), DbError> {
    const TABLE: &str = "event_tag_kind";
    let verifiable = tag_kind.verifiable();
    txn.foreach_full(dbi, &[], &[], false, |key, value| {
        if is_tag_kind_marker(key) {
            if read_u64(value).is_none() {
                report.malformed_records += 1;
                report.issue(
                    "malformed-value",
                    TABLE,
                    format!("marker value has {} bytes, expected 8", value.len()),
                );
            }
            return true;
        }
        tag_kind.actual_entries += 1;
        if !verifiable {
            return true;
        }
        // The shortest posting is a tag name and the two integers.
        let lev_id = match read_u64(value) {
            Some(lev_id) if key.len() > 16 => lev_id,
            _ => {
                report.malformed_records += 1;
                tag_kind.unexpected_entries += 1;
                report.issue(
                    "malformed-record",
                    TABLE,
                    format!("key has {} bytes, value {}", key.len(), value.len()),
                );
                return true;
            }
        };
        match txn.get_u64(txn.env().dbis().event, lev_id) {
            Ok(Some(raw)) if PackedEventView::new(raw).is_ok() => balance.stored(lev_id),
            Ok(Some(_)) => {
                tag_kind.unexpected_entries += 1;
                report.issue("unverifiable-index", TABLE, format!("levId {lev_id}"));
            }
            Ok(None) => {
                tag_kind.stale_entries += 1;
                report.issue("stale-index", TABLE, format!("levId {lev_id}"));
            }
            Err(error) => {
                report.lookup_errors += 1;
                report.issue("lookup", TABLE, error.to_string());
            }
        }
        true
    })?;
    let count = balance.unexpected();
    tag_kind.unexpected_entries += count;
    name_unexpected_postings(txn, dbi, TABLE, count, balance, report, |key, lev_id| {
        if is_tag_kind_marker(key) || key.len() <= 16 {
            return None;
        }
        let raw = txn.get_u64(txn.env().dbis().event, lev_id).ok()??;
        let packed = PackedEventView::new(raw).ok()?;
        (!tag_kind_keys(packed).iter().any(|expected| expected == key))
            .then(|| format!("levId {lev_id}"))
    })
}

/// Check every `wok_Event__search` posting against the payload it names.
fn check_search_postings(
    txn: &RoTxn<'_>,
    dbi: MDB_dbi,
    balance: &mut PostingBalance,
    report: &mut IntegrityReport,
) -> Result<(), DbError> {
    const TABLE: &str = "event_search";
    let payloads = txn.env().dbis().event_payload;
    let mut decompressor = Decompressor::new();
    txn.foreach_full(dbi, &[], &[], false, |key, value| {
        if is_search_marker(key) {
            if read_u64(value).is_none() {
                report.malformed_records += 1;
                report.issue(
                    "malformed-value",
                    TABLE,
                    format!("marker value has {} bytes, expected 8", value.len()),
                );
            }
            return true;
        }
        report.actual_index_entries += 1;
        let Some(term) = search_term_from_key(key) else {
            report.malformed_records += 1;
            report.extra_index_entries += 1;
            report.issue("malformed-key", TABLE, "invalid term key".into());
            return true;
        };
        let Some(lev_id) = read_u64(value) else {
            report.malformed_records += 1;
            report.extra_index_entries += 1;
            report.issue(
                "malformed-value",
                TABLE,
                format!("value has {} bytes, expected 8", value.len()),
            );
            return true;
        };
        let payload = match txn.get_u64(payloads, lev_id) {
            Ok(Some(payload)) => payload,
            Ok(None) => {
                report.extra_index_entries += 1;
                report.issue("dangling-index", TABLE, format!("levId {lev_id}"));
                return true;
            }
            Err(error) => {
                report.lookup_errors += 1;
                report.issue("lookup", TABLE, error.to_string());
                return true;
            }
        };
        // The event pass derived the entries of a readable event. A payload
        // without one, orphaned or under a PackedEvent too short, is rare:
        // derive it here.
        if readable_event(txn, lev_id) {
            balance.stored(lev_id);
        } else if !derives_search_posting(txn, &mut decompressor, payload, lev_id, key) {
            report.extra_index_entries += 1;
            report.issue(
                "unexpected-index",
                TABLE,
                format!("term {term:?}, levId {lev_id}"),
            );
        }
        true
    })?;
    let count = balance.unexpected();
    report.extra_index_entries += count;
    name_unexpected_postings(txn, dbi, TABLE, count, balance, report, |key, lev_id| {
        let term = search_term_from_key(key)?;
        let payload = txn.get_u64(payloads, lev_id).ok()??;
        (readable_event(txn, lev_id)
            && !derives_search_posting(txn, &mut decompressor, payload, lev_id, key))
        .then(|| format!("term {term:?}, levId {lev_id}"))
    })
}

/// Check the records of a key-ordered pass in progress.
fn check_tag_kind_pass(
    txn: &RoTxn<'_>,
    build: MDB_dbi,
    report: &mut IntegrityReport,
) -> Result<(), DbError> {
    txn.foreach_full(build, &[], &[], false, |key, value| {
        if !is_valid_pass_record(key, value) {
            report.malformed_records += 1;
            report.issue(
                "malformed-record",
                "event_tag_kind_build",
                format!(
                    "key {} with a {}-byte value",
                    String::from_utf8_lossy(key),
                    value.len()
                ),
            );
        }
        true
    })?;
    Ok(())
}

/// The position of `dbi` among `indexes`.
fn index_of(indexes: &[(&'static str, MDB_dbi)], dbi: MDB_dbi) -> usize {
    indexes
        .iter()
        .position(|&(_, index)| index == dbi)
        .expect("an event-derived index")
}

fn index_specs(txn: &RoTxn<'_>) -> [(&'static str, MDB_dbi); 10] {
    let dbis = txn.env().dbis();
    [
        ("event_id", dbis.event_id),
        ("event_pubkey_kind", dbis.event_pubkey_kind),
        ("event_tag", dbis.event_tag),
        ("event_deletion", dbis.event_deletion),
        ("event_replace", dbis.event_replace),
        ("event_created_at", dbis.event_created_at),
        ("event_pubkey", dbis.event_pubkey),
        ("event_replace_deletion", dbis.event_replace_deletion),
        ("event_kind", dbis.event_kind),
        ("event_expiration", dbis.event_expiration),
    ]
}

pub fn check_integrity(txn: &RoTxn<'_>) -> Result<IntegrityReport, DbError> {
    check_integrity_with_buckets(txn, BALANCE_BUCKETS)
}

fn check_integrity_with_buckets(
    txn: &RoTxn<'_>,
    buckets: usize,
) -> Result<IntegrityReport, DbError> {
    let dbis = txn.env().dbis();
    let mut report = IntegrityReport::default();
    let mut search_decompressor = Decompressor::new();
    let mut search_balance = PostingBalance::new(buckets);
    let mut tag_kind_balance = PostingBalance::new(buckets);
    // The strfry-layout indexes share one balance, except `event_replace`:
    // superseded history is counted from the postings their versions derive,
    // so each of its postings is checked against its event's replacement key.
    // Per index, the entries the event pass found stored and the postings
    // naming a readable event; the difference is the unexpected postings.
    let indexes = index_specs(txn);
    let mut index_balance = PostingBalance::new(buckets);
    let mut found = [0u64; 10];
    let mut stored = [0u64; 10];
    let mut authors = HashMap::<[u8; 32], u64>::new();
    let mut largest_id = 0;
    let tag_entries = txn.entries(dbis.event_tag)? as u64;
    let mut tag_kind =
        tag_kind_index_state_ro(txn)?.map(|state| TagKindIndexReport::new(state, tag_entries));
    let tag_kind_through = tag_kind
        .as_ref()
        .map_or(0, TagKindIndexReport::expected_through);

    check_metadata_tables(txn, &mut report)?;

    txn.foreach_full(dbis.event, &[], &[], false, |key, value| {
        report.events += 1;
        let Some(lev_id) = read_u64(key) else {
            report.malformed_records += 1;
            report.issue(
                "malformed-key",
                "event",
                format!("key has {} bytes, expected 8", key.len()),
            );
            return true;
        };

        largest_id = largest_id.max(lev_id);
        match txn.get_u64(dbis.event_payload, lev_id) {
            Ok(Some(payload)) => check_payload(txn, lev_id, payload, &mut report),
            Ok(None) => {
                report.missing_payloads.push(lev_id);
                report.issue("missing", "event_payload", format!("levId {lev_id}"));
            }
            Err(error) => {
                report.lookup_errors += 1;
                report.issue("lookup", "event_payload", error.to_string());
            }
        }

        let packed = match PackedEventView::new(value) {
            Ok(packed) => packed,
            Err(error) => {
                report.packed_parse_errors += 1;
                report.issue("decode", "event", format!("levId {lev_id}: {error}"));
                return true;
            }
        };
        *authors
            .entry(packed.pubkey().try_into().expect("validated packed pubkey"))
            .or_default() += 1;
        let mut lacks_legacy_entries = false;
        for entry in event_index_entries(dbis, lev_id, packed) {
            match entry_exists(txn, &entry) {
                Ok(true) if entry.dbi == dbis.event_replace => {}
                Ok(true) => {
                    index_balance.derived(lev_id);
                    found[index_of(&indexes, entry.dbi)] += 1;
                }
                Ok(false) if entry.legacy_optional => {
                    lacks_legacy_entries = true;
                    continue;
                }
                Ok(false) => {
                    report.missing_index_entries += 1;
                    report.issue("missing-index", entry.name, format!("levId {lev_id}"));
                }
                Err(error) => {
                    report.lookup_errors += 1;
                    report.issue("lookup", entry.name, error.to_string());
                }
            }
            report.expected_index_entries += 1;
        }
        if lacks_legacy_entries {
            report.legacy_untombstoned_deletions += 1;
        }
        if let (Some(dbi), Some(tag_kind)) = (dbis.event_tag_kind, tag_kind.as_mut()) {
            // Only events at or below the marker must have their entries,
            // but any stored event may: the balance needs them all.
            if tag_kind.verifiable() {
                let required = lev_id <= tag_kind_through;
                for key in tag_kind_keys(packed) {
                    let entry = EventIndexEntry {
                        name: "event_tag_kind",
                        dbi,
                        key,
                        value: lev_id.to_ne_bytes().to_vec(),
                        legacy_optional: false,
                    };
                    if required {
                        tag_kind.expected_entries += 1;
                    }
                    match entry_exists(txn, &entry) {
                        Ok(true) => tag_kind_balance.derived(lev_id),
                        Ok(false) if required => {
                            tag_kind.missing_entries += 1;
                            report.issue("missing-index", entry.name, format!("levId {lev_id}"));
                        }
                        Ok(false) => {}
                        Err(error) => {
                            report.lookup_errors += 1;
                            report.issue("lookup", entry.name, error.to_string());
                        }
                    }
                }
            }
        }
        if let Some(search_dbi) = dbis.event_search {
            let payload = match txn.get_u64(dbis.event_payload, lev_id) {
                Ok(Some(payload)) => payload.to_vec(),
                _ => return true,
            };
            let json = match search_decompressor.decode(txn, &payload, 16 * 1024 * 1024) {
                Ok(json) => json.to_owned(),
                Err(error) => {
                    report.payload_parse_errors += 1;
                    report.issue("decode", "event_search", format!("levId {lev_id}: {error}"));
                    return true;
                }
            };
            // Unparseable JSON is reported by the search check below.
            if matches!(
                crate::long_tags::long_tag_packing(value, &json),
                Ok(crate::long_tags::LongTagPacking::Repack(_))
            ) {
                report.legacy_long_tag_records += 1;
            }
            match search_index_entries(lev_id, &json) {
                Ok(entries) => {
                    for (key, value) in entries {
                        let entry = EventIndexEntry {
                            name: "event_search",
                            dbi: search_dbi,
                            key,
                            value,
                            legacy_optional: false,
                        };
                        report.expected_index_entries += 1;
                        match entry_exists(txn, &entry) {
                            Ok(true) => search_balance.derived(lev_id),
                            Ok(false) => {
                                report.missing_index_entries += 1;
                                report.issue(
                                    "missing-index",
                                    "event_search",
                                    format!("levId {lev_id}"),
                                );
                            }
                            Err(error) => {
                                report.lookup_errors += 1;
                                report.issue("lookup", "event_search", error.to_string());
                            }
                        }
                    }
                }
                Err(error) => {
                    report.payload_parse_errors += 1;
                    report.issue("decode", "event_search", format!("levId {lev_id}: {error}"));
                }
            }
        }
        true
    })?;

    check_state(txn, &mut report, &authors, largest_id)?;
    drop(authors);

    txn.foreach_full(dbis.event_payload, &[], &[], false, |key, value| {
        report.payloads += 1;
        let Some(lev_id) = read_u64(key) else {
            report.malformed_records += 1;
            report.issue(
                "malformed-key",
                "event_payload",
                format!("key has {} bytes, expected 8", key.len()),
            );
            return true;
        };
        match txn.get_u64(dbis.event, lev_id) {
            Ok(Some(_)) => {}
            Ok(None) => {
                report.orphan_payloads.push(lev_id);
                report.issue("orphan", "event_payload", format!("levId {lev_id}"));
                check_payload(txn, lev_id, value, &mut report);
            }
            Err(error) => {
                report.lookup_errors += 1;
                report.issue("lookup", "event", error.to_string());
            }
        }
        true
    })?;

    for (index, &(name, dbi)) in indexes.iter().enumerate() {
        let mut replacement_key = Vec::new();
        let mut replacement_count = 0u64;
        txn.foreach_full(dbi, &[], &[], false, |key, value| {
            report.actual_index_entries += 1;
            let Some(lev_id) = read_u64(value) else {
                report.malformed_records += 1;
                report.extra_index_entries += 1;
                report.issue(
                    "malformed-value",
                    name,
                    format!("value has {} bytes, expected 8", value.len()),
                );
                return true;
            };
            let packed = match txn.get_u64(dbis.event, lev_id) {
                Ok(Some(raw)) => match PackedEventView::new(raw) {
                    Ok(packed) => packed,
                    Err(_) => {
                        report.extra_index_entries += 1;
                        report.issue("unverifiable-index", name, format!("levId {lev_id}"));
                        return true;
                    }
                },
                Ok(None) => {
                    report.extra_index_entries += 1;
                    report.issue("dangling-index", name, format!("levId {lev_id}"));
                    return true;
                }
                Err(error) => {
                    report.lookup_errors += 1;
                    report.issue("lookup", name, error.to_string());
                    return true;
                }
            };
            if dbi != dbis.event_replace {
                stored[index] += 1;
                index_balance.stored(lev_id);
            } else if replace_key(packed).as_deref() != Some(key) {
                report.extra_index_entries += 1;
                report.issue("unexpected-index", name, format!("levId {lev_id}"));
            } else if wok_event::is_replaceable_kind(packed.kind())
                || wok_event::is_param_replaceable_kind(packed.kind())
            {
                // DUPSORT groups each address contiguously; constant extra memory.
                if replacement_key != key {
                    replacement_key = key.to_vec();
                    replacement_count = 0;
                }
                replacement_count += 1;
                if replacement_count == 2 {
                    report.superseded_groups += 1;
                }
                if replacement_count > 1 {
                    report.superseded_events += 1;
                }
            }
            true
        })?;
    }
    for (index, &(name, dbi)) in indexes.iter().enumerate() {
        // Lookup errors, already reported, can leave either count short.
        let count = stored[index].saturating_sub(found[index]);
        report.extra_index_entries += count;
        name_unexpected_postings(
            txn,
            dbi,
            name,
            count,
            &mut index_balance,
            &mut report,
            |key, lev_id| {
                let raw = txn.get_u64(dbis.event, lev_id).ok()??;
                let packed = PackedEventView::new(raw).ok()?;
                (!event_index_entries(dbis, lev_id, packed)
                    .iter()
                    .any(|entry| entry.dbi == dbi && entry.key == key))
                .then(|| format!("levId {lev_id}"))
            },
        )?;
    }
    drop(index_balance);

    if let Some(search_dbi) = dbis.event_search {
        check_search_postings(txn, search_dbi, &mut search_balance, &mut report)?;
    }

    if let (Some(dbi), Some(tag_kind)) = (dbis.event_tag_kind, tag_kind.as_mut()) {
        check_tag_kind_postings(txn, dbi, tag_kind, &mut tag_kind_balance, &mut report)?;
    }
    if let Some(build) = dbis.event_tag_kind_build {
        check_tag_kind_pass(txn, build, &mut report)?;
    }
    report.tag_kind_index = tag_kind;

    // The advisory count includes only validated replacement entries. A broken
    // index cannot establish drift in the separately maintained physical count.
    if report.missing_index_entries == 0
        && report.extra_index_entries == 0
        && report.lookup_errors == 0
    {
        if let Some(count) = crate::state::superseded_events_ro(txn)? {
            if count != report.superseded_events {
                report.metadata_errors += 1;
                report.issue(
                    "counter-drift",
                    "state",
                    format!(
                        "superseded event count is {count}, expected {}",
                        report.superseded_events
                    ),
                );
            }
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::make_key_string_u64;
    use crate::tag_kind::tag_kind_key;
    use crate::{write_events, Env, EnvOptions, EventToWrite, NoopNegentropy};
    use serde_json::json;

    fn note(time: u64, content: &str) -> EventToWrite {
        use secp256k1::{Keypair, SecretKey, SECP256K1};
        let secret = SecretKey::from_byte_array(&[7; 32]).unwrap();
        let key = Keypair::from_secret_key(SECP256K1, &secret);
        let mut value = json!({"pubkey":hex::encode(key.x_only_public_key().0.serialize()),
            "kind":1,"created_at":time,"tags":[["t", "nostr"], ["p", "11".repeat(32)]],
            "content":content});
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

    /// With every event in one bucket, each posting of every event is
    /// suspect, and the check still names exactly the unexpected ones.
    #[test]
    fn one_bucket_names_the_same_postings_as_many() {
        let dir = tempfile::TempDir::new().unwrap();
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let mut events = (0..4)
            .map(|i| note(1_000 + i, &format!("alpha beta n{i}")))
            .collect::<Vec<_>>();
        let mut txn = env.begin_rw().unwrap();
        write_events(&mut txn, &mut NoopNegentropy, &mut events, false).unwrap();
        txn.commit().unwrap();

        let lev = |i: usize| events[i].lev_id.to_ne_bytes();
        let search = env.dbis().event_search.unwrap();
        let tag_kind = env.dbis().event_tag_kind.unwrap();
        let mut txn = env.begin_rw().unwrap();
        txn.put(search, b"\x01bogus", &lev(1), 0).unwrap();
        txn.put(search, b"\x01n0", &lev(3), 0).unwrap();
        assert!(txn.del(search, b"\x01n2", Some(&lev(2))).unwrap());
        txn.put(search, b"\x01alpha", &99u64.to_ne_bytes(), 0)
            .unwrap();
        txn.put(
            tag_kind,
            &tag_kind_key(b't', b"nostr", 7, 1_000),
            &lev(0),
            0,
        )
        .unwrap();
        txn.put(tag_kind, &tag_kind_key(b't', b"rust", 1, 1_002), &lev(2), 0)
            .unwrap();
        txn.commit().unwrap();

        let txn = env.begin_ro().unwrap();
        let shared = check_integrity_with_buckets(&txn, 1).unwrap();
        assert_eq!(shared.missing_index_entries, 1, "{shared:#?}");
        assert_eq!(shared.extra_index_entries, 3, "{shared:#?}");
        let tag_kind = shared.tag_kind_index.as_ref().unwrap();
        assert_eq!(tag_kind.unexpected_entries, 2, "{tag_kind:#?}");
        let unexpected = shared
            .issues
            .iter()
            .filter(|issue| issue.category == "unexpected-index")
            .map(|issue| (issue.table, issue.detail.as_str()))
            .collect::<Vec<_>>();
        let detail = |term: &str, i: usize| format!("term {term:?}, levId {}", events[i].lev_id);
        assert_eq!(
            unexpected,
            [
                ("event_search", detail("bogus", 1).as_str()),
                ("event_search", detail("n0", 3).as_str()),
                (
                    "event_tag_kind",
                    format!("levId {}", events[0].lev_id).as_str()
                ),
                (
                    "event_tag_kind",
                    format!("levId {}", events[2].lev_id).as_str()
                ),
            ]
        );
        let many = check_integrity(&txn).unwrap();
        assert_eq!(
            serde_json::to_value(&shared).unwrap(),
            serde_json::to_value(&many).unwrap()
        );
    }

    /// The strfry-layout indexes share one balance: unexpected postings of
    /// several indexes, in the buckets of the same events, are named in
    /// index and key order whatever the buckets.
    #[test]
    fn one_bucket_names_the_same_index_postings_as_many() {
        let dir = tempfile::TempDir::new().unwrap();
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        let mut events = (0..4)
            .map(|i| note(1_000 + i, &format!("n{i}")))
            .collect::<Vec<_>>();
        let mut txn = env.begin_rw().unwrap();
        write_events(&mut txn, &mut NoopNegentropy, &mut events, false).unwrap();
        txn.commit().unwrap();

        let dbis = env.dbis();
        let lev = |i: usize| events[i].lev_id;
        // The entry of event `i` in `table` whose key starts with `prefix`.
        let entry = |i: usize, table: &str, prefix: &[u8]| {
            let packed = PackedEventView::new(&events[i].packed).unwrap();
            event_index_entries(dbis, lev(i), packed)
                .into_iter()
                .find(|entry| entry.name == table && entry.key.starts_with(prefix))
                .unwrap()
        };
        let mut txn = env.begin_rw().unwrap();
        for (i, table, prefix, other) in [
            (0, "event_tag", &b"t"[..], 1),
            (2, "event_tag", b"p", 3),
            (3, "event_created_at", b"", 0),
            (0, "event_kind", b"", 2),
        ] {
            let entry = entry(i, table, prefix);
            txn.put(entry.dbi, &entry.key, &lev(other).to_ne_bytes(), 0)
                .unwrap();
        }
        let id = entry(1, "event_id", b"");
        assert!(txn.del(id.dbi, &id.key, Some(&id.value)).unwrap());
        let pubkey = entry(2, "event_pubkey", b"");
        txn.put(pubkey.dbi, &pubkey.key, &99u64.to_ne_bytes(), 0)
            .unwrap();
        let author = PackedEventView::new(&events[0].packed).unwrap().pubkey();
        let address = make_key_string_u64(&[author, b"x"].concat(), 1);
        txn.put(dbis.event_replace, &address, &lev(0).to_ne_bytes(), 0)
            .unwrap();
        txn.commit().unwrap();

        let txn = env.begin_ro().unwrap();
        let shared = check_integrity_with_buckets(&txn, 1).unwrap();
        assert_eq!(shared.missing_index_entries, 1, "{shared:#?}");
        assert_eq!(shared.extra_index_entries, 6, "{shared:#?}");
        let unexpected = shared
            .issues
            .iter()
            .filter(|issue| issue.category == "unexpected-index")
            .map(|issue| (issue.table, issue.detail.clone()))
            .collect::<Vec<_>>();
        let detail = |i: usize| format!("levId {}", lev(i));
        assert_eq!(
            unexpected,
            [
                ("event_replace", detail(0)),
                ("event_tag", detail(3)),
                ("event_tag", detail(1)),
                ("event_created_at", detail(0)),
                ("event_kind", detail(2)),
            ]
        );
        let many = check_integrity(&txn).unwrap();
        assert_eq!(
            serde_json::to_value(&shared).unwrap(),
            serde_json::to_value(&many).unwrap()
        );
    }
}
