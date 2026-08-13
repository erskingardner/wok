//! Database integrity checks for primaries, payloads, metadata, and every
//! event-derived secondary index.

use crate::fbs::{decode_compression_dictionary, decode_meta, decode_negentropy_filter};
use crate::payload::{parse_payload, PayloadView};
use crate::txn::RoTxn;
use crate::write::{event_index_entries, EventIndexEntry};
use crate::DbError;
use lmdb_sys::MDB_dbi;
use wok_event::PackedEventView;

const MAX_REPORTED_ISSUES: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityIssue {
    pub category: &'static str,
    pub table: &'static str,
    pub detail: String,
}

#[derive(Debug, Default, Clone)]
pub struct IntegrityReport {
    pub events: u64,
    pub payloads: u64,
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
        }
        if value.is_empty() {
            report.malformed_records += 1;
            report.issue("malformed-value", "negentropy", "empty value".into());
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
        true
    })?;

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
            }
            true
        })?;
    }

    Ok(report)
}
