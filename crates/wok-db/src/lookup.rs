//! Read helpers that work on both `RoTxn` and `RwTxn`.

use crate::keys::{make_key_string_u64, u64_from_ne};
use crate::txn::{RoTxn, RwTxn};
use crate::DbError;

pub fn lookup_event_by_id_ro(
    txn: &RoTxn<'_>,
    id: &[u8],
) -> Result<Option<(u64, Vec<u8>)>, DbError> {
    let start = make_key_string_u64(id, 0);
    let mut found = None;
    txn.foreach_full(
        txn.env().dbis().event_id,
        &start,
        &0u64.to_ne_bytes(),
        false,
        |k, v| {
            if k.starts_with(id) {
                found = Some(u64_from_ne(v));
            }
            false
        },
    )?;
    if let Some(lev) = found {
        if let Some(buf) = txn.get_u64(txn.env().dbis().event, lev)? {
            return Ok(Some((lev, buf.to_vec())));
        }
    }
    Ok(None)
}

pub fn most_recent_levid_ro(txn: &RoTxn<'_>) -> Result<u64, DbError> {
    let mut lev = 0u64;
    txn.foreach_full(
        txn.env().dbis().event,
        &u64::MAX.to_ne_bytes(),
        &[],
        true,
        |k, _v| {
            if k.len() == 8 {
                lev = u64_from_ne(k);
            }
            false
        },
    )?;
    Ok(lev)
}

pub fn get_packed_ro(txn: &RoTxn<'_>, lev_id: u64) -> Result<Option<Vec<u8>>, DbError> {
    Ok(txn
        .get_u64(txn.env().dbis().event, lev_id)?
        .map(|b| b.to_vec()))
}

pub fn get_payload_ro(txn: &RoTxn<'_>, lev_id: u64) -> Result<Option<Vec<u8>>, DbError> {
    Ok(txn
        .get_u64(txn.env().dbis().event_payload, lev_id)?
        .map(|b| b.to_vec()))
}

pub fn foreach_event_from<F>(txn: &RoTxn<'_>, start_lev_id: u64, mut cb: F) -> Result<(), DbError>
where
    F: FnMut(u64, &[u8]) -> bool,
{
    let start = start_lev_id.to_ne_bytes();
    txn.foreach_full(txn.env().dbis().event, &start, &[], false, |k, v| {
        let lev = u64_from_ne(k);
        if lev < start_lev_id {
            return true;
        }
        cb(lev, v)
    })?;
    Ok(())
}

pub fn foreach_created_at<F>(
    txn: &RoTxn<'_>,
    start: u64,
    start_dup: u64,
    reverse: bool,
    mut cb: F,
) -> Result<(), DbError>
where
    F: FnMut(u64, u64) -> bool,
{
    txn.foreach_full(
        txn.env().dbis().event_created_at,
        &start.to_ne_bytes(),
        &start_dup.to_ne_bytes(),
        reverse,
        |k, v| {
            if k.len() != 8 || v.len() != 8 {
                return true;
            }
            cb(u64_from_ne(k), u64_from_ne(v))
        },
    )?;
    Ok(())
}

pub fn foreach_negentropy_filter<F>(txn: &RoTxn<'_>, mut cb: F) -> Result<(), DbError>
where
    F: FnMut(u64, &str) -> bool,
{
    txn.foreach_full(
        txn.env().dbis().negentropy_filter,
        &0u64.to_ne_bytes(),
        &[],
        false,
        |k, v| {
            if k.len() != 8 {
                return true;
            }
            let id = u64_from_ne(k);
            match crate::fbs::decode_negentropy_filter(v) {
                Ok(rec) => cb(id, &rec.filter),
                Err(_) => true,
            }
        },
    )?;
    Ok(())
}

pub fn insert_negentropy_filter(txn: &mut RwTxn<'_>, filter: &str) -> Result<u64, DbError> {
    let id = txn.next_integer_key(txn.env().dbis().negentropy_filter)?;
    txn.put_u64(
        txn.env().dbis().negentropy_filter,
        id,
        &crate::fbs::encode_negentropy_filter(filter),
        0,
    )?;
    Ok(id)
}

pub fn bump_negentropy_mod_counter(txn: &mut RwTxn<'_>) -> Result<u64, DbError> {
    let raw = txn
        .get_u64(txn.env().dbis().meta, 1)?
        .ok_or_else(|| DbError::msg("no Meta entry"))?
        .to_vec();
    let mut meta = crate::fbs::decode_meta(&raw)?;
    meta.negentropy_modification_counter = meta.negentropy_modification_counter.saturating_add(1);
    txn.put_u64(txn.env().dbis().meta, 1, &crate::fbs::encode_meta(&meta), 0)?;
    Ok(meta.negentropy_modification_counter)
}

pub fn foreach_negentropy_filter_rw<F>(txn: &RwTxn<'_>, mut cb: F) -> Result<(), DbError>
where
    F: FnMut(u64, &str) -> bool,
{
    txn.foreach_full(
        txn.env().dbis().negentropy_filter,
        &0u64.to_ne_bytes(),
        &[],
        false,
        |k, v| {
            if k.len() != 8 {
                return true;
            }
            let id = u64_from_ne(k);
            match crate::fbs::decode_negentropy_filter(v) {
                Ok(rec) => cb(id, &rec.filter),
                Err(_) => true,
            }
        },
    )?;
    Ok(())
}
