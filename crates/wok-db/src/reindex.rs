//! Build a fresh database from authoritative primary records and derive every
//! event secondary index from PackedEvent again.

use crate::long_tags::{long_tag_packing, LongTagPacking};
use crate::write::{
    delete_event_basic, event_index_entries, long_address_deletions, version_tombstoned,
};
use crate::{index_event_search, payload::Decompressor, search::initialize_search_index_state};
use crate::{DbError, RoTxn, RwTxn};
use std::borrow::Cow;
use std::collections::BTreeSet;
use wok_event::{hashed_tag_value_digest, PackedEventView, DELETION_KIND};

/// What a rebuild does with each PackedEvent record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackedEventRebuild {
    /// Copy every record unchanged.
    Copy,
    /// Pack records that lack single-letter tag values longer than 255 bytes
    /// again from their payloads, as [`crate::long_tags`] allows, and copy
    /// the others unchanged. Then delete the stored versions named by
    /// deletion requests' `a` tags longer than 255 bytes, as the write path
    /// does when a request arrives.
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
    /// `a` tag longer than 255 bytes names their address. Before the repack,
    /// the request had no tombstone or the version was keyed by another
    /// address, so the write path had not deleted them.
    pub deleted_versions: BTreeSet<u64>,
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
    ];
    if let Some(event_search) = target_dbis.event_search {
        dbis_to_clear.push(event_search);
    }
    if let Some(vanish_pubkey) = target_dbis.vanish_pubkey {
        dbis_to_clear.push(vanish_pubkey);
    }
    for dbi in dbis_to_clear {
        target.clear(dbi)?;
    }

    copy_table(source, target, source_dbis.meta, target_dbis.meta)?;
    if let Some(state) = target_dbis.state {
        target.clear(state)?;
        crate::state::reset_for_reindex(source, target)?;
    }

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
    if let (Some(source_vanish), Some(target_vanish)) =
        (source_dbis.vanish_pubkey, target_dbis.vanish_pubkey)
    {
        copy_table(source, target, source_vanish, target_vanish)?;
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
    let mut long_address_requests = Vec::new();
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
        if packing == PackedEventRebuild::RepackLongTags && names_long_address(packed) {
            long_address_requests.push(lev_id);
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
    target.event_sequence = Some(target.event_sequence.unwrap_or(0).max(last_lev_id));
    if let Some(raw) = target.get_u64(target_dbis.meta, 1)? {
        let mut meta = crate::decode_meta(raw)?;
        meta.db_version = wok_event::WOK_DB_VERSION;
        target.put_u64(target_dbis.meta, 1, &crate::encode_meta(&meta), 0)?;
    }
    // The sequence is set, so deleting the newest record cannot lower it.
    let deleted_versions = delete_versions_under_long_addresses(
        source,
        target,
        &mut decompressor,
        &long_address_requests,
    )?;
    crate::state::superseded_events(target)?;
    initialize_search_index_state(target, last_lev_id)?;
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

/// Whether `packed` is a deletion request with an `a` tag longer than 255
/// bytes, which PackedEvent holds hashed.
fn names_long_address(packed: PackedEventView<'_>) -> bool {
    let mut long = false;
    if packed.kind() == DELETION_KIND {
        packed.foreach_tag(|name, value| {
            long = name == 'a' && hashed_tag_value_digest(value).is_some();
            !long
        });
    }
    long
}

struct DeletedVersions {
    lev_ids: BTreeSet<u64>,
    index_entries: u64,
}

/// Apply the long `a` tags of the stored deletion requests `requests` to the
/// rebuilt `target`, with the write path's deletion semantics: each stored
/// version of an address a request's author published, up to the request's
/// `created_at`, is deleted. strfry and earlier Wok releases dropped those
/// tags and keyed a version with a long first `d` by another address, so
/// such versions survived the requests that name them. A request whose
/// shorter `a` tags were never applied is a different gap, and stays as it is.
fn delete_versions_under_long_addresses(
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
        lev_ids.extend(long_address_deletions(
            target,
            PackedEventView::new(&request)?,
            &json,
        )?);
    }
    let mut index_entries = 0u64;
    for &lev_id in &lev_ids {
        let version = stored(target, lev_id)?;
        let view = PackedEventView::new(&version)?;
        let json = payload_json(source, decompressor, lev_id)?;
        // The tombstone that refuses such a version on arrival must cover
        // every version deleted here.
        if !version_tombstoned(target, view, &json)? {
            return Err(DbError::msg(format!(
                "levId {lev_id}: no deletion request tombstones the version to delete"
            )));
        }
        index_entries += event_index_entries(dbis, lev_id, view).len() as u64;
        if !delete_event_basic(target, lev_id)? {
            return Err(DbError::msg(format!("event {lev_id} has no payload")));
        }
    }
    Ok(DeletedVersions {
        lev_ids,
        index_entries,
    })
}
