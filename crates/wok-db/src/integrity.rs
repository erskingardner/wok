//! Database integrity checks: missing primaries, orphan payloads, index drift.

use crate::keys::u64_from_ne;
use crate::txn::RoTxn;
use crate::DbError;
use wok_event::PackedEventView;

#[derive(Debug, Default, Clone)]
pub struct IntegrityReport {
    pub events: u64,
    pub payloads: u64,
    pub missing_payloads: Vec<u64>,
    pub orphan_payloads: Vec<u64>,
    pub missing_index_entries: u64,
    pub extra_index_entries: u64,
    pub packed_parse_errors: u64,
}

impl IntegrityReport {
    pub fn ok(&self) -> bool {
        self.missing_payloads.is_empty()
            && self.orphan_payloads.is_empty()
            && self.missing_index_entries == 0
            && self.extra_index_entries == 0
            && self.packed_parse_errors == 0
    }
}

pub fn check_integrity(txn: &RoTxn<'_>) -> Result<IntegrityReport, DbError> {
    let dbis = txn.env().dbis();
    let mut report = IntegrityReport::default();
    let mut event_ids = Vec::new();

    txn.foreach_full(dbis.event, &0u64.to_ne_bytes(), &[], false, |k, v| {
        report.events += 1;
        let lev = u64_from_ne(k);
        event_ids.push(lev);
        if PackedEventView::new(v).is_err() {
            report.packed_parse_errors += 1;
        }
        true
    })?;

    let mut payload_ids = Vec::new();
    txn.foreach_full(
        dbis.event_payload,
        &0u64.to_ne_bytes(),
        &[],
        false,
        |k, _v| {
            report.payloads += 1;
            payload_ids.push(u64_from_ne(k));
            true
        },
    )?;

    for lev in &event_ids {
        if txn.get_u64(dbis.event_payload, *lev)?.is_none() {
            report.missing_payloads.push(*lev);
        }
    }
    for lev in &payload_ids {
        if txn.get_u64(dbis.event, *lev)?.is_none() {
            report.orphan_payloads.push(*lev);
        }
    }

    // Count id-index entries vs events.
    let mut id_index = 0u64;
    txn.foreach_full(dbis.event_id, &[], &[], false, |_k, _v| {
        id_index += 1;
        true
    })?;
    if id_index < report.events {
        report.missing_index_entries += report.events - id_index;
    } else     if id_index > report.events {
        report.extra_index_entries += id_index - report.events;
    }

    Ok(report)
}
