//! Bounded validation of a registered, immutable strfry v3 snapshot.
#![forbid(unsafe_code)]
use super::{failure, hex, lmdb, validate_row, LmdbSourceReport, LmdbToRocksOptions, SourceKind};
use crate::env::Dbis;
use crate::{
    DbError, EnvironmentStats, EventFingerprint, EventVerificationFailure, EventVerificationReport,
    IntegrityIssue, IntegrityReport,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;
use wok_event::PackedEventView;

#[derive(Clone, Debug, Serialize)]
pub struct StrfrySourceAudit {
    pub source: LmdbSourceReport,
    pub lmdb: EnvironmentStats,
    pub integrity: IntegrityReport,
    pub event_verification: Option<EventVerificationReport>,
    pub fingerprint: EventFingerprint,
}

/// Validate all source primary/payload pairs, metadata encodings and native
/// event indexes using bounded cursors. Optional signature checking is for
/// preflight; the converter always checks signatures and bodies before sealing.
/// No dictionary cache, author map, or transaction arena grows with the source.
/// The source must stay stopped; data-file identity and txnid are rechecked.
pub fn audit_strfry_source(path: &Path, verify: bool) -> Result<StrfrySourceAudit, DbError> {
    let source = lmdb::Source::open_kind(path, SourceKind::Strfry)?;
    audit(&source, verify, &LmdbToRocksOptions::default())
}

pub(super) fn logical_dbis() -> Dbis {
    Dbis {
        meta: 1,
        negentropy_filter: 2,
        event: 3,
        event_id: 4,
        event_pubkey_kind: 5,
        event_tag: 6,
        event_deletion: 7,
        event_replace: 8,
        event_created_at: 9,
        event_pubkey: 10,
        event_replace_deletion: 11,
        event_kind: 12,
        event_expiration: 13,
        compression_dictionary: 14,
        event_payload: 15,
        negentropy: 16,
        event_search: None,
        vanish_pubkey: None,
        moderation: None,
        state: None,
        event_tag_kind: None,
        event_tag_kind_build: None,
    }
}
fn issue(
    report: &mut IntegrityReport,
    category: &'static str,
    table: &'static str,
    detail: String,
) {
    if report.issues.len() < 100 {
        report.issues.push(IntegrityIssue {
            category,
            table,
            detail,
        });
    }
}
fn failed(report: &mut EventVerificationReport, id: u64, packed: &[u8], reason: String) {
    report.failed += 1;
    if report.failures.len() < 100 {
        report.failures.push(EventVerificationFailure {
            lev_id: id,
            id: PackedEventView::new(packed)
                .map(|p| hex(p.id()))
                .unwrap_or_default(),
            reason,
        });
    }
}
fn json(
    source: &lmdb::Source,
    payload: &[u8],
    options: &LmdbToRocksOptions,
) -> Result<String, DbError> {
    let decoded = match crate::parse_payload(payload)? {
        crate::PayloadView::Raw(raw) => {
            if raw.len() > options.max_json_bytes {
                return Err(failure("event JSON exceeds configured bound"));
            }
            raw.to_vec()
        }
        crate::PayloadView::Zstd {
            dict_id,
            compressed,
        } => {
            let dict = source
                .get(14, &(dict_id as u64).to_ne_bytes())?
                .ok_or_else(|| failure("compressed payload dictionary missing"))?;
            validate_row(14, &(dict_id as u64).to_ne_bytes(), dict, options)?;
            let dict = crate::decode_compression_dictionary(dict)?;
            zstd::bulk::Decompressor::with_dictionary(&dict.dict)
                .and_then(|mut d| d.decompress(compressed, options.max_json_bytes))
                .map_err(|_| failure("compressed event decode failed"))?
        }
    };
    String::from_utf8(decoded).map_err(|_| failure("event payload is not UTF8"))
}

pub(super) fn audit(
    source: &lmdb::Source,
    verify: bool,
    options: &LmdbToRocksOptions,
) -> Result<StrfrySourceAudit, DbError> {
    let mut report = IntegrityReport::default();
    let mut verification = EventVerificationReport::default();
    let dbis = logical_dbis();
    let mut found = [0u64; 16];
    let mut fingerprint = Sha256::new();
    let mut events = source.cursor(3)?.expect("required event table");
    while let Some((key, raw)) = events.next()? {
        validate_row(3, key, raw, options)?;
        let id = crate::comparators::u64_from_ne_checked(key)?;
        report.events += 1;
        verification.events += 1;
        let Some(payload) = source.get(15, key)? else {
            if report.missing_payloads.len() < 100 {
                report.missing_payloads.push(id);
            }
            issue(
                &mut report,
                "missing",
                "event_payload",
                format!("levId {id}"),
            );
            if verify {
                failed(&mut verification, id, raw, "no payload".into());
            }
            continue;
        };
        validate_row(15, key, payload, options)?;
        if raw
            .len()
            .checked_add(payload.len())
            .is_none_or(|n| n > options.max_record_bytes)
        {
            return Err(failure("combined primary exceeds configured record bound"));
        }
        fingerprint.update(id.to_be_bytes());
        fingerprint.update((raw.len() as u64).to_be_bytes());
        fingerprint.update(raw);
        fingerprint.update((payload.len() as u64).to_be_bytes());
        fingerprint.update(payload);
        let packed = match PackedEventView::new(raw) {
            Ok(p) => p,
            Err(e) => {
                report.packed_parse_errors += 1;
                issue(&mut report, "decode", "event", format!("levId {id}: {e}"));
                if verify {
                    failed(&mut verification, id, raw, format!("PackedEvent: {e}"));
                }
                continue;
            }
        };
        let mut lacks_legacy = false;
        for entry in crate::write::event_index_entries(dbis, id, packed) {
            if source.contains(entry.dbi, &entry.key, &entry.value)? {
                found[entry.dbi as usize - 1] += 1;
                report.expected_index_entries += 1;
            } else if entry.legacy_optional {
                lacks_legacy = true;
            } else {
                report.expected_index_entries += 1;
                report.missing_index_entries += 1;
                issue(
                    &mut report,
                    "missing-index",
                    entry.name,
                    format!("levId {id}"),
                );
            }
        }
        report.legacy_untombstoned_deletions += u64::from(lacks_legacy);
        match json(source, payload, options) {
            Ok(json) => {
                if matches!(
                    crate::long_tag_packing(raw, &json),
                    Ok(crate::LongTagPacking::Repack(_))
                ) {
                    report.legacy_long_tag_records += 1;
                }
                match wok_event::json::parse_strict(&json) {
                    Ok(event) if verify => {
                        if let Err(e) = wok_event::verify_strfry_event(packed, &event) {
                            failed(&mut verification, id, raw, e.to_string());
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        report.payload_parse_errors += 1;
                        if verify {
                            failed(&mut verification, id, raw, format!("payload: {e}"));
                        }
                    }
                }
            }
            Err(e) => {
                report.payload_parse_errors += 1;
                issue(
                    &mut report,
                    "decode",
                    "event_payload",
                    format!("levId {id}: {e}"),
                );
                if verify {
                    failed(&mut verification, id, raw, format!("payload: {e}"));
                }
            }
        }
        if report.events % 100_000 == 0 {
            tracing::info!(
                events = report.events,
                "strfry source verification progress"
            );
        }
    }
    // Every expected posting is a distinct (table,key,localID) after derivation
    // dedup. Exact membership + table count proves no extra/wrong/stale rows;
    // missing legacy-optional tombstones are counted only when actually present.
    for dbi in 4..=13u32 {
        let actual = source.report.tables[dbi as usize - 1].records;
        report.actual_index_entries += actual;
        report.extra_index_entries += actual.saturating_sub(found[dbi as usize - 1]);
    }
    let mut payloads = source.cursor(15)?.expect("required payload table");
    while let Some((key, value)) = payloads.next()? {
        validate_row(15, key, value, options)?;
        let id = crate::comparators::u64_from_ne_checked(key)?;
        report.payloads += 1;
        if source.get(3, key)?.is_none() {
            if report.orphan_payloads.len() < 100 {
                report.orphan_payloads.push(id);
            }
            issue(
                &mut report,
                "orphan",
                "event_payload",
                format!("levId {id}"),
            );
        }
    }
    for dbi in [1u32, 2, 14, 16] {
        let mut rows = source.cursor(dbi)?.expect("required metadata table");
        while let Some((key, value)) = rows.next()? {
            validate_row(dbi, key, value, options)?;
            let valid = if dbi == 16 {
                key.len() == 16
                    && if u64::from_ne_bytes(key[8..].try_into().unwrap()) == 0 {
                        value.len() == 16
                    } else {
                        value.len() == 3952
                            && (1..=80)
                                .contains(&u64::from_ne_bytes(value[..8].try_into().unwrap()))
                    }
            } else {
                key.len() == 8
                    && match dbi {
                        1 => crate::decode_meta(value).is_ok(),
                        2 => crate::decode_negentropy_filter(value).is_ok(),
                        14 => crate::decode_compression_dictionary(value).is_ok(),
                        _ => unreachable!(),
                    }
            };
            if !valid {
                report.metadata_errors += 1;
                issue(
                    &mut report,
                    "decode",
                    crate::dbi_specs()[dbi as usize - 1].name,
                    "malformed metadata row".into(),
                );
            }
        }
    }
    // Replacement rows are contiguous, so historical superseded counts need
    // only the current key and count, never a database-sized address map.
    let mut replacements = source.cursor(8)?.expect("required replace table");
    let mut last_key = Vec::new();
    let mut count = 0;
    while let Some((key, value)) = replacements.next()? {
        validate_row(8, key, value, options)?;
        let id = crate::comparators::u64_from_ne_checked(value)?;
        if let Some(raw) = source.get(3, &id.to_ne_bytes())? {
            validate_row(3, &id.to_ne_bytes(), raw, options)?;
            if let Ok(packed) = PackedEventView::new(raw) {
                if wok_event::is_replaceable_kind(packed.kind())
                    || wok_event::is_param_replaceable_kind(packed.kind())
                {
                    if last_key != key {
                        last_key = key.to_vec();
                        count = 0;
                    }
                    count += 1;
                    report.superseded_groups += u64::from(count == 2);
                    report.superseded_events += u64::from(count > 1);
                }
            }
        }
    }
    source.check_unchanged()?;
    Ok(StrfrySourceAudit {
        source: source.report.clone(),
        lmdb: source.stats()?,
        fingerprint: EventFingerprint {
            count: report.events,
            sha256: fingerprint.finalize().into(),
        },
        integrity: report,
        event_verification: verify.then_some(verification),
    })
}
