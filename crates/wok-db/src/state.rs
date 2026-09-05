//! Transactional bookkeeping, separate from signed primary records.
use crate::keys::make_key_string_u64;
use crate::{DbError, RoTxn, RwTxn};

const HIGH_WATER: &[u8] = b"sequence";
pub const POLICY_GENERATION: &[u8] = b"visibility";

fn decode(raw: &[u8]) -> Result<u64, DbError> {
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

/// Lazily initialize each author under the writer transaction. No startup
/// scan of the entire relay is required, and deletions initialize BEFORE removal.
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
    let old = author_count(txn, pubkey)?;
    let count = if insert {
        old.checked_add(1)
    } else {
        old.checked_sub(1)
    }
    .ok_or_else(|| DbError::msg("author count overflow or drift"))?;
    txn.author_counts.insert(author_key(pubkey), count);
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
    }
    for (key, count) in std::mem::take(&mut txn.author_counts) {
        txn.put(dbi, &key, &count.to_le_bytes(), 0)?;
    }
    Ok(())
}

/// Rebuild derived counters lazily while retaining the source sequence across
/// deleted tails. Caller has already cleared the target state table.
pub(crate) fn reset_for_reindex(source: &RoTxn<'_>, target: &mut RwTxn<'_>) -> Result<(), DbError> {
    target.author_counts.clear();
    target.event_sequence = high_water_ro(source)?;
    Ok(())
}
