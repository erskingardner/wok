//! Transactional bookkeeping, separate from signed primary records.
use crate::keys::make_key_string_u64;
use crate::{DbError, RoTxn, RwTxn};

pub(crate) const HIGH_WATER: &[u8] = b"sequence";
pub(crate) const SUPERSEDED_EVENTS: &[u8] = b"superseded-events";
pub const POLICY_GENERATION: &[u8] = b"visibility";

pub(crate) fn decode(raw: &[u8]) -> Result<u64, DbError> {
    Ok(u64::from_le_bytes(
        raw.try_into()
            .map_err(|_| DbError::msg("invalid state counter"))?,
    ))
}

pub fn high_water_ro(txn: &RoTxn<'_>) -> Result<Option<u64>, DbError> {
    let Some(dbi) = txn.env().dbis().state else {
        return Ok(None);
    };
    txn.get(dbi, HIGH_WATER)?.map(decode).transpose()
}

pub fn allocate_event_id(txn: &mut RwTxn<'_>) -> Result<u64, DbError> {
    preserve_high_water(txn)?;
    let previous = txn.event_sequence.unwrap();
    let next = previous
        .checked_add(1)
        .ok_or_else(|| DbError::msg("local event sequence exhausted"))?;
    txn.event_sequence = Some(next);
    Ok(next)
}

pub fn preserve_high_water(txn: &mut RwTxn<'_>) -> Result<(), DbError> {
    let dbi = txn
        .env()
        .dbis()
        .state
        .ok_or_else(|| DbError::msg("missing Wok state table"))?;
    if txn.event_sequence.is_none() {
        txn.event_sequence = Some(match txn.get(dbi, HIGH_WATER)? {
            Some(raw) => decode(raw)?,
            None => txn.largest_integer_key(txn.env().dbis().event)?,
        });
    }
    Ok(())
}

fn author_key(pubkey: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.push(b'a');
    key.extend_from_slice(pubkey);
    key
}

/// Lazily initialize a requested count under the writer transaction. Quota
/// checks use this before mutation; authors whose count is never requested
/// need no stored counter. Existing counters are maintained even without quotas.
pub fn author_count(txn: &mut RwTxn<'_>, pubkey: &[u8]) -> Result<u64, DbError> {
    let dbi = txn
        .env()
        .dbis()
        .state
        .ok_or_else(|| DbError::msg("missing Wok state table"))?;
    let key = author_key(pubkey);
    if let Some(count) = txn.author_counts.get(&key) {
        return Ok(*count);
    }
    if let Some(raw) = txn.get(dbi, &key)? {
        return decode(raw);
    }
    let mut count = 0u64;
    txn.foreach_full(
        txn.env().dbis().event_pubkey,
        &make_key_string_u64(pubkey, 0),
        &[],
        false,
        |k, _| {
            if !k.starts_with(pubkey) {
                return false;
            }
            count += 1;
            true
        },
    )?;
    txn.author_counts.insert(key, count);
    Ok(count)
}

pub fn change_author_count(
    txn: &mut RwTxn<'_>,
    pubkey: &[u8],
    insert: bool,
) -> Result<(), DbError> {
    let dbi = txn
        .env()
        .dbis()
        .state
        .ok_or_else(|| DbError::msg("missing Wok state table"))?;
    let key = author_key(pubkey);
    let old = if let Some(count) = txn.author_counts.get(&key) {
        *count
    } else if let Some(raw) = txn.get(dbi, &key)? {
        decode(raw)?
    } else {
        // No cached count can become stale. A later quota check derives the
        // current count from the author index, including earlier mutations
        // in the same transaction, then keeps it current from that point on.
        return Ok(());
    };
    let count = if insert {
        old.checked_add(1)
    } else {
        old.checked_sub(1)
    }
    .ok_or_else(|| DbError::msg("author count overflow or drift"))?;
    txn.author_counts.insert(key, count);
    Ok(())
}

pub fn policy_generation(txn: &RoTxn<'_>) -> Result<u64, DbError> {
    let Some(dbi) = txn.env().dbis().state else {
        return Ok(0);
    };
    txn.get(dbi, POLICY_GENERATION)?
        .map(decode)
        .transpose()
        .map(|v| v.unwrap_or(0))
}

pub fn invalidate_visibility(txn: &mut RwTxn<'_>) -> Result<(), DbError> {
    let dbi = txn
        .env()
        .dbis()
        .state
        .ok_or_else(|| DbError::msg("missing Wok state table"))?;
    let generation = txn
        .get(dbi, POLICY_GENERATION)?
        .map(decode)
        .transpose()?
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| DbError::msg("visibility generation exhausted"))?;
    txn.put(dbi, POLICY_GENERATION, &generation.to_le_bytes(), 0)?;
    Ok(())
}

/// Flush once per transaction, coalescing all changes for each author.
pub(crate) fn flush(txn: &mut RwTxn<'_>) -> Result<(), DbError> {
    let Some(dbi) = txn.env().dbis().state else {
        return Ok(());
    };
    if let Some(sequence) = txn.event_sequence.take() {
        txn.put(dbi, HIGH_WATER, &sequence.to_le_bytes(), 0)?;
        #[cfg(test)]
        crate::crash_tests::checkpoint("sequence-staged");
    }
    if let Some(count) = txn.superseded_events.take() {
        txn.put(dbi, SUPERSEDED_EVENTS, &count.to_le_bytes(), 0)?;
    }
    for (key, count) in std::mem::take(&mut txn.author_counts) {
        txn.put(dbi, &key, &count.to_le_bytes(), 0)?;
        #[cfg(test)]
        crate::crash_tests::checkpoint("author-count-staged");
    }
    Ok(())
}

/// Rebuild derived counters lazily while retaining the source sequence across
/// deleted tails. Caller has already cleared the target state table.
pub(crate) fn reset_for_reindex(source: &RoTxn<'_>, target: &mut RwTxn<'_>) -> Result<(), DbError> {
    target.author_counts.clear();
    target.superseded_events = None;
    target.event_sequence = high_water_ro(source)?;
    Ok(())
}

/// None means this snapshot predates replacement bookkeeping; readers must
/// conservatively filter it until a writable initialization/reindex counts it.
pub fn superseded_events_ro(txn: &RoTxn<'_>) -> Result<Option<u64>, DbError> {
    let Some(dbi) = txn.env().dbis().state else {
        return Ok(None);
    };
    txn.get(dbi, SUPERSEDED_EVENTS)?.map(decode).transpose()
}

/// One ordered index scan on first initialization of an older database.
/// Signed primary records and the physical negentropy tree remain untouched.
pub(crate) fn superseded_events(txn: &mut RwTxn<'_>) -> Result<u64, DbError> {
    if let Some(count) = txn.superseded_events {
        return Ok(count);
    }
    let dbi = txn
        .env()
        .dbis()
        .state
        .ok_or_else(|| DbError::msg("missing Wok state table"))?;
    let count = if let Some(raw) = txn.get(dbi, SUPERSEDED_EVENTS)? {
        decode(raw)?
    } else {
        let mut previous = Vec::new();
        let mut count = 0u64;
        let mut error = None;
        txn.foreach_full(txn.env().dbis().event_replace, &[], &[], false, |key, _| {
            let kind = match crate::keys::parse_key_string_u64(key) {
                Ok((_, kind)) => kind,
                Err(err) => {
                    error = Some(err);
                    return false;
                }
            };
            if wok_event::is_replaceable_kind(kind) || wok_event::is_param_replaceable_kind(kind) {
                if previous == key {
                    count += 1;
                } else {
                    previous = key.to_vec();
                }
            }
            true
        })?;
        if let Some(error) = error {
            return Err(error);
        }
        count
    };
    txn.superseded_events = Some(count);
    Ok(count)
}

/// Call before inserting into, or after deleting from, the replacement index.
/// Each member beyond the first contributes exactly one superseded record,
/// irrespective of which event wins the timestamp/ID comparison.
pub(crate) fn change_replacement_count(
    txn: &mut RwTxn<'_>,
    key: &[u8],
    insert: bool,
) -> Result<(), DbError> {
    if txn.get(txn.env().dbis().event_replace, key)?.is_some() {
        // The caller initialized the count before any index mutation.
        let old = txn
            .superseded_events
            .ok_or_else(|| DbError::msg("replacement count not initialized"))?;
        txn.superseded_events = Some(
            if insert {
                old.checked_add(1)
            } else {
                old.checked_sub(1)
            }
            .ok_or_else(|| DbError::msg("replacement count overflow or drift"))?,
        );
    }
    Ok(())
}
