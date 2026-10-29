//! Resolve the signed marker from payloads without changing PackedEvent or
//! migration bytes. Call only when author deletion would otherwise apply.

use crate::{lookup_event_by_id, lookup_event_by_id_ro, DbError, Decompressor, RoTxn, RwTxn};
use wok_event::{
    deletion_protection, nostr_json_to_packed_event, verify_nostr_event, EventLimits,
    PackedEventView,
};

const MAX_PAYLOAD_JSON: usize = 16 * 1024 * 1024;

/// A marker grants protection only after NIP-01 ID and signature verification,
/// including for historical data imported with verification disabled. Legacy
/// tao IDs remain importable, but do not acquire this extension's protection.
pub fn is_deletion_protected_json(
    packed: PackedEventView<'_>,
    json: &str,
) -> Result<bool, DbError> {
    let event = wok_event::json::parse_strict(json)?;
    if !deletion_protection(&event).unwrap_or(false) {
        return Ok(false);
    }
    // Historical imports need not meet today's configurable admission limits,
    // but they must still be structurally valid NIP-01 events. Repacking here
    // only checks the payload; it never rewrites migrated PackedEvent bytes.
    let limits = EventLimits {
        max_event_size: usize::MAX,
        max_num_tags: usize::MAX,
        max_tag_val_size: usize::MAX,
    };
    let Ok(repacked) = nostr_json_to_packed_event(&event, &limits) else {
        return Ok(false);
    };
    let expected = repacked.view();
    Ok(expected.id() == packed.id()
        && expected.pubkey() == packed.pubkey()
        && expected.kind() == packed.kind()
        && expected.created_at() == packed.created_at()
        && expected.expiration() == packed.expiration()
        && verify_nostr_event(packed, &event).is_ok())
}

pub(crate) fn is_deletion_protected_ro(
    txn: &RoTxn<'_>,
    packed: PackedEventView<'_>,
) -> Result<bool, DbError> {
    let Some((lev, _)) = lookup_event_by_id_ro(txn, packed.id())? else {
        return Ok(false);
    };
    let raw = txn
        .get_u64(txn.env().dbis().event_payload, lev)?
        .ok_or_else(|| DbError::msg("missing payload while checking deletion protection"))?;
    let mut decomp = Decompressor::new();
    is_deletion_protected_json(packed, decomp.decode(txn, raw, MAX_PAYLOAD_JSON)?)
}

pub(crate) fn is_deletion_protected_rw(
    txn: &RwTxn<'_>,
    lev: u64,
    packed: PackedEventView<'_>,
) -> Result<bool, DbError> {
    let raw = txn
        .get_u64(txn.env().dbis().event_payload, lev)?
        .ok_or_else(|| DbError::msg("missing payload while checking deletion protection"))?;
    let mut decomp = Decompressor::new();
    is_deletion_protected_json(packed, decomp.decode_rw(txn, raw, MAX_PAYLOAD_JSON)?)
}

pub(crate) fn is_stored_deletion_protected_rw(
    txn: &RwTxn<'_>,
    packed: PackedEventView<'_>,
) -> Result<bool, DbError> {
    match lookup_event_by_id(txn, packed.id())? {
        Some((lev, _)) => is_deletion_protected_rw(txn, lev, packed),
        None => Ok(false),
    }
}
