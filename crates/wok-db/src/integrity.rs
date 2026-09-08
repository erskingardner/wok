//! Database integrity checks for primaries, payloads, metadata, and every
//! event-derived secondary index.

use crate::fbs::{decode_compression_dictionary, decode_meta, decode_negentropy_filter};
use crate::payload::{parse_payload, Decompressor, PayloadView};
use crate::search::{is_search_marker, search_index_entries, search_term_from_key};
use crate::txn::RoTxn;
use crate::write::{event_index_entries, EventIndexEntry};
use crate::DbError;
use lmdb_sys::MDB_dbi;
use serde::Serialize;
use std::collections::HashMap;
use wok_event::PackedEventView;

const MAX_REPORTED_ISSUES: usize = 100;

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
    pub issues: Vec<IntegrityIssue>,
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
        } else if key == crate::state::HIGH_WATER || key == crate::state::POLICY_GENERATION || key == crate::state::SUPERSEDED_EVENTS {
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
    let dbis = txn.env().dbis();
    let mut report = IntegrityReport::default();
    let mut search_decompressor = Decompressor::new();
    let mut authors = HashMap::<[u8; 32], u64>::new();
    let mut largest_id = 0;

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
        for entry in event_index_entries(dbis, lev_id, packed) {
            report.expected_index_entries += 1;
            match entry_exists(txn, &entry) {
                Ok(true) => {}
                Ok(false) => {
                    report.missing_index_entries += 1;
                    report.issue("missing-index", entry.name, format!("levId {lev_id}"));
                }
                Err(error) => {
                    report.lookup_errors += 1;
                    report.issue("lookup", entry.name, error.to_string());
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
            match search_index_entries(lev_id, &json) {
                Ok(entries) => {
                    for (key, value) in entries {
                        let entry = EventIndexEntry {
                            name: "event_search",
                            dbi: search_dbi,
                            key,
                            value,
                        };
                        report.expected_index_entries += 1;
                        match entry_exists(txn, &entry) {
                            Ok(true) => {}
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

    for (name, dbi) in index_specs(txn) {
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
            let expected = event_index_entries(dbis, lev_id, packed);
            if !expected
                .iter()
                .any(|entry| entry.name == name && entry.key == key && entry.value == value)
            {
                report.extra_index_entries += 1;
                report.issue("unexpected-index", name, format!("levId {lev_id}"));
            } else if name == "event_replace"
                && (wok_event::is_replaceable_kind(packed.kind())
                    || wok_event::is_param_replaceable_kind(packed.kind()))
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

    if let Some(search_dbi) = dbis.event_search {
        let mut decompressor = Decompressor::new();
        txn.foreach_full(search_dbi, &[], &[], false, |key, value| {
            if is_search_marker(key) {
                if read_u64(value).is_none() {
                    report.malformed_records += 1;
                    report.issue(
                        "malformed-value",
                        "event_search",
                        format!("marker value has {} bytes, expected 8", value.len()),
                    );
                }
                return true;
            }
            report.actual_index_entries += 1;
            let Some(term) = search_term_from_key(key) else {
                report.malformed_records += 1;
                report.extra_index_entries += 1;
                report.issue("malformed-key", "event_search", "invalid term key".into());
                return true;
            };
            let Some(lev_id) = read_u64(value) else {
                report.malformed_records += 1;
                report.extra_index_entries += 1;
                report.issue(
                    "malformed-value",
                    "event_search",
                    format!("value has {} bytes, expected 8", value.len()),
                );
                return true;
            };
            let payload = match txn.get_u64(dbis.event_payload, lev_id) {
                Ok(Some(payload)) => payload.to_vec(),
                Ok(None) => {
                    report.extra_index_entries += 1;
                    report.issue("dangling-index", "event_search", format!("levId {lev_id}"));
                    return true;
                }
                Err(error) => {
                    report.lookup_errors += 1;
                    report.issue("lookup", "event_search", error.to_string());
                    return true;
                }
            };
            let valid = decompressor
                .decode(txn, &payload, 16 * 1024 * 1024)
                .ok()
                .and_then(|json| search_index_entries(lev_id, json).ok())
                .is_some_and(|entries| {
                    entries.iter().any(|(expected_key, expected_value)| {
                        expected_key == key && expected_value == value
                    })
                });
            if !valid {
                report.extra_index_entries += 1;
                report.issue(
                    "unexpected-index",
                    "event_search",
                    format!("term {term:?}, levId {lev_id}"),
                );
            }
            true
        })?;
    }

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
