//! Resolve the signed marker from payloads without changing PackedEvent or
//! migration bytes. Call only when author deletion would otherwise apply.

use crate::{lookup_event_by_id, lookup_event_by_id_ro, DbError, Decompressor, RoTxn, RwTxn};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use wok_event::{
    deletion_protection, nostr_json_to_packed_event, verify_nostr_event, EventLimits,
    PackedEventView,
};

const MAX_PAYLOAD_JSON: usize = 16 * 1024 * 1024;
const CACHE_CAPACITY: usize = 4096;

/// Shared by an environment's readers and writer. Fingerprinting both primary
/// records makes entries safe across old snapshots, payload rewrites, and IDs
/// allocated again after an aborted transaction. No mmap bytes are retained.
#[derive(Default)]
pub(crate) struct ProtectionCache {
    values: HashMap<(u64, [u8; 32]), bool>,
    order: VecDeque<(u64, [u8; 32])>,
}

fn cached_protection(
    cache: &Mutex<ProtectionCache>,
    lev: u64,
    packed: PackedEventView<'_>,
    raw: &[u8],
    verify: impl FnOnce() -> Result<bool, DbError>,
) -> Result<bool, DbError> {
    let mut hash = Sha256::new();
    hash.update((packed.as_bytes().len() as u64).to_le_bytes());
    hash.update(packed.as_bytes());
    hash.update(raw);
    let key = (lev, hash.finalize().into());
    if let Some(value) = cache
        .lock()
        .ok()
        .and_then(|cache| cache.values.get(&key).copied())
    {
        return Ok(value);
    }
    // Signature verification happens outside the shared lock.
    let value = verify()?;
    if let Ok(mut cache) = cache.lock() {
        if !cache.values.contains_key(&key) {
            if cache.order.len() == CACHE_CAPACITY {
                if let Some(old) = cache.order.pop_front() {
                    cache.values.remove(&old);
                }
            }
            cache.order.push_back(key);
            cache.values.insert(key, value);
        }
    }
    Ok(value)
}

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
    cached_protection(&txn.env().inner.protection_cache, lev, packed, raw, || {
        let mut decomp = Decompressor::new();
        is_deletion_protected_json(packed, decomp.decode(txn, raw, MAX_PAYLOAD_JSON)?)
    })
}

pub(crate) fn is_deletion_protected_rw(
    txn: &RwTxn<'_>,
    lev: u64,
    packed: PackedEventView<'_>,
) -> Result<bool, DbError> {
    let raw = txn
        .get_u64(txn.env().dbis().event_payload, lev)?
        .ok_or_else(|| DbError::msg("missing payload while checking deletion protection"))?;
    cached_protection(&txn.env().inner.protection_cache, lev, packed, raw, || {
        let mut decomp = Decompressor::new();
        is_deletion_protected_json(packed, decomp.decode_rw(txn, raw, MAX_PAYLOAD_JSON)?)
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use wok_event::{PackedEventBuilder, PackedEventTagBuilder};

    #[test]
    fn repeated_reads_verify_once_but_changed_primary_bytes_verify_again() {
        let cache = Mutex::new(ProtectionCache::default());
        let packed = PackedEventBuilder::build(
            &[1; 32],
            &[2; 32],
            100,
            1,
            0,
            &PackedEventTagBuilder::default(),
        )
        .unwrap();
        let calls = Cell::new(0);
        let check = |raw: &[u8], answer| {
            cached_protection(&cache, 1, packed.view(), raw, || {
                calls.set(calls.get() + 1);
                Ok(answer)
            })
            .unwrap()
        };
        assert!(check(b"signed payload", true));
        assert!(check(b"signed payload", false));
        assert_eq!(calls.get(), 1);
        assert!(!check(b"changed payload", false));
        assert_eq!(calls.get(), 2);
        // A reader on the older snapshot still sees its own verified bytes.
        assert!(check(b"signed payload", false));
        assert_eq!(calls.get(), 2);
    }
}
