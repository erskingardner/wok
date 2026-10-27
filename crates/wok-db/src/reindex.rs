//! Build a fresh database from authoritative primary records and derive every
//! event secondary index from PackedEvent again.

use crate::env::Dbis;
use crate::long_tags::{long_tag_packing, LongTagPacking};
use crate::tag_kind::{initialize_tag_kind_index_state, put_tag_kind_entries, tag_kind_keys};
use crate::write::{
    delete_event_basic, event_index_entries, is_repaired_address, repaired_address_deletions,
};
use crate::{index_event_search, payload::Decompressor, search::initialize_search_index_state};
use crate::{DbError, RoTxn, RwTxn};
use std::borrow::Cow;
use std::collections::BTreeSet;
use wok_event::{PackedEventView, DELETION_KIND};

/// What a rebuild does with each PackedEvent record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackedEventRebuild {
    /// Copy every record unchanged.
    Copy,
    /// Pack records that lack single-letter tag values longer than 255 bytes
    /// again from their payloads, as [`crate::long_tags`] allows, and copy
    /// the others unchanged. Then delete the stored versions named by the
    /// deletion requests' `a` tags whose tombstones strfry and earlier
    /// releases lacked or misspelled, as the write path does when a request
    /// arrives (see `write::is_repaired_address`).
    RepackLongTags,
}

/// What the rebuilt database holds, and what the rebuild changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReindexStats {
    pub events: u64,
    pub payloads: u64,
    pub index_entries: u64,
    /// Records packed again with their long tag values.
    pub repacked_long_tag_records: u64,
    /// Records lacking long tag values that were copied unchanged, because
    /// packing their payload again changes more than those values.
    pub skipped_long_tag_records: u64,
    /// Local IDs of the stored versions deleted because a deletion request's
    /// `a` tag names their address: one longer than 255 bytes, a replaceable
    /// event's, or one whose kind has leading zeros. strfry and earlier
    /// releases left them stored: the request had no working tombstone, or
    /// the version was keyed by another address.
    pub deleted_versions: BTreeSet<u64>,
}

/// Tables of records that events don't derive, which a rebuild copies
/// unchanged. Meta is copied too, then given this release's version. The
/// Wok tables are absent from a strfry v3 source.
fn copied_tables(dbis: Dbis) -> [Option<lmdb_sys::MDB_dbi>; 4] {
    [
        Some(dbis.negentropy_filter),
        Some(dbis.compression_dictionary),
        dbis.vanish_pubkey,
        dbis.moderation,
    ]
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
    packing: PackedEventRebuild,
) -> Result<ReindexStats, DbError> {
    let source_dbis = source.env().dbis();
    let target_dbis = target.env().dbis();
    let mut dbis_to_clear = vec![
        target_dbis.meta,
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
        target_dbis.event_payload,
        target_dbis.negentropy,
    ];
    if let Some(event_search) = target_dbis.event_search {
        dbis_to_clear.push(event_search);
    }
    if let Some(event_tag_kind) = target_dbis.event_tag_kind {
        dbis_to_clear.push(event_tag_kind);
    }
    for dbi in dbis_to_clear {
        target.clear(dbi)?;
    }

    copy_table(source, target, source_dbis.meta, target_dbis.meta)?;
    if let Some(state) = target_dbis.state {
        target.clear(state)?;
        crate::state::reset_for_reindex(source, target)?;
    }

    for (source_dbi, target_dbi) in copied_tables(source_dbis)
        .into_iter()
        .zip(copied_tables(target_dbis))
    {
        let Some(target_dbi) = target_dbi else {
            continue;
        };
        target.clear(target_dbi)?;
        if let Some(source_dbi) = source_dbi {
            copy_table(source, target, source_dbi, target_dbi)?;
        }
    }
    let payloads = copy_table(
        source,
        target,
        source_dbis.event_payload,
        target_dbis.event_payload,
    )?;

    let mut events = 0u64;
    let mut last_lev_id = 0u64;
    let mut index_entries = 0u64;
    let mut repacked_long_tag_records = 0u64;
    let mut skipped_long_tag_records = 0u64;
    let mut repaired_requests = Vec::new();
    let mut error = None;
    let mut decompressor = Decompressor::new();
    source.foreach_full(source_dbis.event, &[], &[], false, |key, packed_bytes| {
        let Some(lev_id) = key.try_into().ok().map(u64::from_ne_bytes) else {
            error = Some(DbError::msg("Event key is not 8 bytes"));
            return false;
        };
        let json = match payload_json(source, &mut decompressor, lev_id) {
            Ok(json) => json,
            Err(err) => {
                error = Some(err);
                return false;
            }
        };
        let packed_bytes = match packing {
            PackedEventRebuild::Copy => Cow::Borrowed(packed_bytes),
            PackedEventRebuild::RepackLongTags => match long_tag_packing(packed_bytes, &json) {
                Ok(LongTagPacking::Complete) => Cow::Borrowed(packed_bytes),
                Ok(LongTagPacking::Repack(repacked)) => {
                    repacked_long_tag_records += 1;
                    Cow::Owned(repacked)
                }
                Ok(LongTagPacking::Mismatch) => {
                    skipped_long_tag_records += 1;
                    Cow::Borrowed(packed_bytes)
                }
                Err(err) => {
                    error = Some(DbError::msg(format!("levId {lev_id}: {err}")));
                    return false;
                }
            },
        };
        let packed = match PackedEventView::new(&packed_bytes) {
            Ok(packed) => packed,
            Err(err) => {
                error = Some(DbError::msg(format!("levId {lev_id}: {err}")));
                return false;
            }
        };
        if packing == PackedEventRebuild::RepackLongTags && names_repaired_address(packed) {
            repaired_requests.push(lev_id);
        }
        if let Err(err) = target.put(target_dbis.event, key, &packed_bytes, 0) {
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
        if let Err(err) = put_tag_kind_entries(target, lev_id, &tag_kind_keys(packed)) {
            error = Some(err);
            return false;
        }
        if let Err(err) = index_event_search(target, lev_id, &json) {
            error = Some(err);
            return false;
        }
        events += 1;
        last_lev_id = lev_id;
        error.is_none()
    })?;
    if let Some(error) = error {
        return Err(error);
    }
    let sequence = target.event_sequence.unwrap_or(0).max(last_lev_id);
    target.event_sequence = Some(sequence);
    if let Some(raw) = target.get_u64(target_dbis.meta, 1)? {
        let mut meta = crate::decode_meta(raw)?;
        meta.db_version = wok_event::WOK_DB_VERSION;
        target.put_u64(target_dbis.meta, 1, &crate::encode_meta(&meta), 0)?;
    }
    // The sequence is set, so deleting the newest record cannot lower it.
    let deleted_versions = delete_versions_under_repaired_addresses(
        source,
        target,
        &mut decompressor,
        &repaired_requests,
    )?;
    crate::state::superseded_events(target)?;
    initialize_search_index_state(target, last_lev_id)?;
    // Every stored event is indexed, and the deleted tail needs no entries.
    initialize_tag_kind_index_state(target, sequence)?;
    let deleted = deleted_versions.lev_ids.len() as u64;
    Ok(ReindexStats {
        events: events - deleted,
        payloads: payloads - deleted,
        index_entries: index_entries - deleted_versions.index_entries,
        repacked_long_tag_records,
        skipped_long_tag_records,
        deleted_versions: deleted_versions.lev_ids,
    })
}

fn payload_json(
    source: &RoTxn<'_>,
    decompressor: &mut Decompressor,
    lev_id: u64,
) -> Result<String, DbError> {
    let payload = source
        .get_u64(source.env().dbis().event_payload, lev_id)?
        .ok_or_else(|| DbError::msg(format!("event {lev_id} has no payload")))?;
    Ok(decompressor
        .decode(source, payload, 16 * 1024 * 1024)?
        .to_owned())
}

/// Whether `packed` is a deletion request with an `a` tag that reindex
/// applies again (`write::is_repaired_address`).
fn names_repaired_address(packed: PackedEventView<'_>) -> bool {
    let mut repaired = false;
    if packed.kind() == DELETION_KIND {
        packed.foreach_tag(|name, value| {
            repaired = name == 'a' && is_repaired_address(value);
            !repaired
        });
    }
    repaired
}

struct DeletedVersions {
    lev_ids: BTreeSet<u64>,
    index_entries: u64,
}

/// Apply the repaired `a` tags of the stored deletion requests `requests` to
/// the rebuilt `target`, with the write path's deletion semantics: each
/// stored version of an address a request's author published, up to the
/// request's `created_at`, is deleted. strfry and earlier Wok releases left
/// such versions stored. They dropped long tags and keyed a version with a
/// long first `d` by another address, ignored replaceable addresses, and
/// tombstoned a padded kind by its spelling, so older versions came back.
fn delete_versions_under_repaired_addresses(
    source: &RoTxn<'_>,
    target: &mut RwTxn<'_>,
    decompressor: &mut Decompressor,
    requests: &[u64],
) -> Result<DeletedVersions, DbError> {
    let dbis = target.env().dbis();
    let stored = |target: &RwTxn<'_>, lev_id: u64| {
        target
            .get_u64(dbis.event, lev_id)?
            .map(<[u8]>::to_vec)
            .ok_or_else(|| DbError::msg(format!("levId {lev_id} is not stored")))
    };
    let mut lev_ids = BTreeSet::new();
    for &lev_id in requests {
        let request = stored(target, lev_id)?;
        let json = payload_json(source, decompressor, lev_id)?;
        lev_ids.extend(repaired_address_deletions(
            target,
            PackedEventView::new(&request)?,
            &json,
        )?);
    }
    let mut index_entries = 0u64;
    for &lev_id in &lev_ids {
        let version = stored(target, lev_id)?;
        index_entries +=
            event_index_entries(dbis, lev_id, PackedEventView::new(&version)?).len() as u64;
        if !delete_event_basic(target, lev_id)? {
            return Err(DbError::msg(format!("event {lev_id} has no payload")));
        }
    }
    Ok(DeletedVersions {
        lev_ids,
        index_entries,
    })
}
