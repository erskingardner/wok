//! Build a fresh database from authoritative primary records and derive every
//! event secondary index from PackedEvent again.

use crate::write::event_index_entries;
use crate::{DbError, RoTxn, RwTxn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReindexStats {
    pub events: u64,
    pub payloads: u64,
    pub index_entries: u64,
}

fn copy_table(
    source: &RoTxn<'_>,
    target: &mut RwTxn<'_>,
    source_dbi: lmdb_sys::MDB_dbi,
    target_dbi: lmdb_sys::MDB_dbi,
) -> Result<u64, DbError> {
    let mut count = 0u64;
    let mut error = None;
    source.foreach_full(source_dbi, &[], &[], false, |key, value| {
        match target.put(target_dbi, key, value, 0) {
            Ok(_) => count += 1,
            Err(err) => {
                error = Some(err);
                return false;
            }
        }
        true
    })?;
    if let Some(error) = error {
        return Err(error);
    }
    Ok(count)
}

pub fn rebuild_primary_and_event_indices(
    source: &RoTxn<'_>,
    target: &mut RwTxn<'_>,
) -> Result<ReindexStats, DbError> {
    let source_dbis = source.env().dbis();
    let target_dbis = target.env().dbis();
    for dbi in [
        target_dbis.meta,
        target_dbis.negentropy_filter,
        target_dbis.event,
        target_dbis.event_id,
        target_dbis.event_pubkey_kind,
        target_dbis.event_tag,
        target_dbis.event_deletion,
        target_dbis.event_replace,
        target_dbis.event_created_at,
        target_dbis.event_pubkey,
        target_dbis.event_replace_deletion,
        target_dbis.event_kind,
        target_dbis.event_expiration,
        target_dbis.compression_dictionary,
        target_dbis.event_payload,
        target_dbis.negentropy,
    ] {
        target.clear(dbi)?;
    }

    copy_table(source, target, source_dbis.meta, target_dbis.meta)?;
    copy_table(
        source,
        target,
        source_dbis.negentropy_filter,
        target_dbis.negentropy_filter,
    )?;
    copy_table(
        source,
        target,
        source_dbis.compression_dictionary,
        target_dbis.compression_dictionary,
    )?;
    let payloads = copy_table(
        source,
        target,
        source_dbis.event_payload,
        target_dbis.event_payload,
    )?;

    let mut events = 0u64;
    let mut index_entries = 0u64;
    let mut error = None;
    source.foreach_full(source_dbis.event, &[], &[], false, |key, packed_bytes| {
        let Some(lev_id) = key.try_into().ok().map(u64::from_ne_bytes) else {
            error = Some(DbError::msg("Event key is not 8 bytes"));
            return false;
        };
        let packed = match wok_event::PackedEventView::new(packed_bytes) {
            Ok(packed) => packed,
            Err(err) => {
                error = Some(DbError::msg(format!("levId {lev_id}: {err}")));
                return false;
            }
        };
        if let Err(err) = target.put(target_dbis.event, key, packed_bytes, 0) {
            error = Some(err);
            return false;
        }
        for entry in event_index_entries(target_dbis, lev_id, packed) {
            match target.put(entry.dbi, &entry.key, &entry.value, 0) {
                Ok(_) => index_entries += 1,
                Err(err) => {
                    error = Some(err);
                    return false;
                }
            }
        }
        events += 1;
        error.is_none()
    })?;
    if let Some(error) = error {
        return Err(error);
    }
    Ok(ReindexStats {
        events,
        payloads,
        index_entries,
    })
}
