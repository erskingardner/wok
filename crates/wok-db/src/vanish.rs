//! Persistent NIP-62 markers, immediate query suppression, and bounded sweep.

use crate::keys::{make_key_string_u64, make_key_u64_u64};
use crate::payload::{event_json_owned, Decompressor};
use crate::txn::{RoTxn, RwTxn};
use crate::write::{delete_events, NegentropySink};
use crate::{get_packed_ro, DbError, Env};
use std::collections::{HashMap, HashSet};
use wok_event::{PackedEventView, GIFT_WRAP_KINDS};

pub const VANISH_KIND: u64 = 62;
pub const ALL_RELAYS: &[u8] = b"ALL_RELAYS";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VanishPolicy {
    pub enabled: bool,
    pub service_url: String,
}

impl VanishPolicy {
    pub fn disabled() -> Self {
        Self::default()
    }

    pub fn targets_this_relay(&self, packed: PackedEventView<'_>) -> bool {
        if !self.enabled || packed.kind() != VANISH_KIND {
            return false;
        }
        let expected = normalize_relay_url(&self.service_url);
        let mut matched = false;
        packed.foreach_tag(|name, value| {
            if name != 'r' || value.is_empty() {
                return true;
            }
            // Packed tags retain only their first character. For kind 62 the
            // original tag name is `relay`, represented by `r` here.
            if value == ALL_RELAYS
                || (!expected.is_empty()
                    && std::str::from_utf8(value)
                        .map(normalize_relay_url)
                        .is_ok_and(|candidate| candidate == expected))
            {
                matched = true;
                return false;
            }
            true
        });
        matched
    }

    /// Strict target validation from the normalized event JSON. PackedEvent
    /// stores one-character tag names for indexing, which is not sufficient
    /// to distinguish `relay` from an unrelated `r...` tag.
    pub fn targets_this_relay_json(&self, json: &str) -> bool {
        if !self.enabled {
            return false;
        }
        let Ok(event) = serde_json::from_str::<serde_json::Value>(json) else {
            return false;
        };
        if event.get("kind").and_then(serde_json::Value::as_u64) != Some(VANISH_KIND) {
            return false;
        }
        let expected = normalize_relay_url(&self.service_url);
        event
            .get("tags")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_array)
            .any(|tag| {
                tag.first().and_then(serde_json::Value::as_str) == Some("relay")
                    && tag
                        .get(1)
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|value| {
                            value == "ALL_RELAYS"
                                || (!expected.is_empty() && normalize_relay_url(value) == expected)
                        })
            })
    }
}

fn normalize_relay_url(url: &str) -> String {
    let mut value = url.trim();
    if let Some(rest) = value.strip_prefix("wss://") {
        value = rest;
    } else if let Some(rest) = value.strip_prefix("ws://") {
        value = rest;
    }
    value.trim_end_matches('/').to_ascii_lowercase()
}

fn read_timestamp(raw: &[u8]) -> Option<u64> {
    Some(u64::from_ne_bytes(raw.try_into().ok()?))
}

pub fn vanish_timestamp_ro(txn: &RoTxn<'_>, pubkey: &[u8]) -> Result<Option<u64>, DbError> {
    let Some(dbi) = txn.env().dbis().vanish_pubkey else {
        return Ok(None);
    };
    Ok(txn.get(dbi, pubkey)?.and_then(read_timestamp))
}

pub fn vanish_timestamp_rw(txn: &RwTxn<'_>, pubkey: &[u8]) -> Result<Option<u64>, DbError> {
    let Some(dbi) = txn.env().dbis().vanish_pubkey else {
        return Ok(None);
    };
    Ok(txn.get(dbi, pubkey)?.and_then(read_timestamp))
}

pub fn mark_vanished(txn: &mut RwTxn<'_>, pubkey: &[u8], timestamp: u64) -> Result<(), DbError> {
    let dbi = txn
        .env()
        .dbis()
        .vanish_pubkey
        .ok_or_else(|| DbError::msg("NIP-62 marker database is unavailable"))?;
    let existing = txn.get(dbi, pubkey)?.and_then(read_timestamp).unwrap_or(0);
    if timestamp > existing {
        txn.put(dbi, pubkey, &timestamp.to_ne_bytes(), 0)?;
    }
    Ok(())
}

/// Discover valid request records that were already present before Wok gained
/// NIP-62 support (notably after a strfry migration) and materialize their
/// maximum-timestamp markers before the relay accepts traffic.
pub fn backfill_vanish_markers(
    env: &Env,
    policy: &VanishPolicy,
    max_event_size: usize,
) -> Result<u64, DbError> {
    if !policy.enabled {
        return Ok(0);
    }
    let txn = env.begin_ro()?;
    let mut decomp = Decompressor::new();
    let mut markers: HashMap<[u8; 32], u64> = HashMap::new();
    let mut error = None;
    let start = make_key_u64_u64(VANISH_KIND, 0);
    txn.foreach_full(
        txn.env().dbis().event_kind,
        &start,
        &[],
        false,
        |key, value| {
            if key.len() != 16 || value.len() != 8 {
                error = Some(DbError::msg("malformed kind-62 index entry"));
                return false;
            }
            let kind = u64::from_ne_bytes(key[..8].try_into().unwrap());
            if kind != VANISH_KIND {
                return false;
            }
            let lev_id = u64::from_ne_bytes(value.try_into().unwrap());
            let packed_bytes = match get_packed_ro(&txn, lev_id)
                .and_then(|value| value.ok_or_else(|| DbError::msg("dangling kind-62 index entry")))
            {
                Ok(packed) => packed,
                Err(err) => {
                    error = Some(err);
                    return false;
                }
            };
            let packed = match PackedEventView::new(&packed_bytes) {
                Ok(packed) => packed,
                Err(err) => {
                    error = Some(err.into());
                    return false;
                }
            };
            let json = match event_json_owned(&txn, &mut decomp, lev_id, max_event_size) {
                Ok(json) => json,
                Err(err) => {
                    error = Some(err);
                    return false;
                }
            };
            if policy.targets_this_relay_json(&json) {
                let mut pubkey = [0u8; 32];
                pubkey.copy_from_slice(packed.pubkey());
                markers
                    .entry(pubkey)
                    .and_modify(|timestamp| *timestamp = (*timestamp).max(packed.created_at()))
                    .or_insert(packed.created_at());
            }
            true
        },
    )?;
    if let Some(error) = error {
        return Err(error);
    }
    drop(txn);

    let mut updated = 0;
    let mut txn = env.begin_rw()?;
    for (pubkey, timestamp) in markers {
        if vanish_timestamp_rw(&txn, &pubkey)?.unwrap_or(0) < timestamp {
            mark_vanished(&mut txn, &pubkey, timestamp)?;
            updated += 1;
        }
    }
    txn.commit()?;
    Ok(updated)
}

pub fn is_event_vanished_ro(txn: &RoTxn<'_>, packed: PackedEventView<'_>) -> Result<bool, DbError> {
    if packed.kind() != VANISH_KIND
        && vanish_timestamp_ro(txn, packed.pubkey())?
            .is_some_and(|timestamp| packed.created_at() <= timestamp)
    {
        return Ok(true);
    }
    if GIFT_WRAP_KINDS.contains(&packed.kind()) {
        let mut vanished = false;
        let mut error = None;
        packed.foreach_tag(|name, value| {
            if name == 'p' {
                match vanish_timestamp_ro(txn, value) {
                    Ok(Some(_)) => {
                        vanished = true;
                        return false;
                    }
                    Ok(None) => {}
                    Err(err) => {
                        error = Some(err);
                        return false;
                    }
                }
            }
            true
        });
        if let Some(error) = error {
            return Err(error);
        }
        if vanished {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn is_event_vanished_rw(txn: &RwTxn<'_>, packed: PackedEventView<'_>) -> Result<bool, DbError> {
    if packed.kind() != VANISH_KIND
        && vanish_timestamp_rw(txn, packed.pubkey())?
            .is_some_and(|timestamp| packed.created_at() <= timestamp)
    {
        return Ok(true);
    }
    if GIFT_WRAP_KINDS.contains(&packed.kind()) {
        let mut vanished = false;
        let mut error = None;
        packed.foreach_tag(|name, value| {
            if name == 'p' {
                match vanish_timestamp_rw(txn, value) {
                    Ok(Some(_)) => {
                        vanished = true;
                        return false;
                    }
                    Ok(None) => {}
                    Err(err) => {
                        error = Some(err);
                        return false;
                    }
                }
            }
            true
        });
        if let Some(error) = error {
            return Err(error);
        }
        if vanished {
            return Ok(true);
        }
    }
    Ok(false)
}

fn next_marker(txn: &RwTxn<'_>, cursor: &[u8]) -> Result<Option<([u8; 32], u64)>, DbError> {
    let Some(dbi) = txn.env().dbis().vanish_pubkey else {
        return Ok(None);
    };
    let mut selected = None;
    txn.foreach_full(dbi, cursor, &[], false, |key, value| {
        if (!cursor.is_empty() && key <= cursor) || key.len() != 32 || value.len() != 8 {
            return true;
        }
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(key);
        selected = read_timestamp(value).map(|timestamp| (pubkey, timestamp));
        false
    })?;
    if selected.is_none() && !cursor.is_empty() {
        txn.foreach_full(dbi, &[], &[], false, |key, value| {
            if key.len() != 32 || value.len() != 8 {
                return true;
            }
            let mut pubkey = [0u8; 32];
            pubkey.copy_from_slice(key);
            selected = read_timestamp(value).map(|timestamp| (pubkey, timestamp));
            false
        })?;
    }
    Ok(selected)
}

/// Delete at most `batch_limit` records for one marker. If a full batch was
/// found the cursor stays before that marker so the next call continues it;
/// otherwise the cursor advances fairly to the next vanished pubkey.
pub fn sweep_vanished_events<N: NegentropySink>(
    txn: &mut RwTxn<'_>,
    ne: &mut N,
    batch_limit: usize,
    cursor: &mut Vec<u8>,
) -> Result<u64, DbError> {
    if batch_limit == 0 {
        return Ok(0);
    }
    let Some((pubkey, timestamp)) = next_marker(txn, cursor)? else {
        cursor.clear();
        return Ok(0);
    };
    let previous_cursor = cursor.clone();
    let mut lev_ids = Vec::new();
    let mut seen = HashSet::new();
    let pubkey_start = make_key_string_u64(&pubkey, 0);
    txn.foreach_full(
        txn.env().dbis().event_pubkey,
        &pubkey_start,
        &0u64.to_ne_bytes(),
        false,
        |key, value| {
            if !key.starts_with(&pubkey) || key.len() != 40 || value.len() != 8 {
                return false;
            }
            let created_at = u64::from_ne_bytes(key[32..40].try_into().unwrap());
            if created_at > timestamp {
                return false;
            }
            let lev_id = u64::from_ne_bytes(value.try_into().unwrap());
            if let Ok(Some(raw)) = txn.get_u64(txn.env().dbis().event, lev_id) {
                if PackedEventView::new(raw).is_ok_and(|event| event.kind() != VANISH_KIND)
                    && seen.insert(lev_id)
                {
                    lev_ids.push(lev_id);
                }
            }
            lev_ids.len() < batch_limit
        },
    )?;

    if lev_ids.len() < batch_limit {
        let mut tag_prefix = Vec::with_capacity(33);
        tag_prefix.push(b'p');
        tag_prefix.extend_from_slice(&pubkey);
        let tag_start = make_key_string_u64(&tag_prefix, 0);
        txn.foreach_full(
            txn.env().dbis().event_tag,
            &tag_start,
            &0u64.to_ne_bytes(),
            false,
            |key, value| {
                if !key.starts_with(&tag_prefix) || value.len() != 8 {
                    return false;
                }
                let lev_id = u64::from_ne_bytes(value.try_into().unwrap());
                if seen.insert(lev_id) {
                    if let Ok(Some(raw)) = txn.get_u64(txn.env().dbis().event, lev_id) {
                        if PackedEventView::new(raw)
                            .is_ok_and(|event| GIFT_WRAP_KINDS.contains(&event.kind()))
                        {
                            lev_ids.push(lev_id);
                        }
                    }
                }
                lev_ids.len() < batch_limit
            },
        )?;
    }

    if lev_ids.len() >= batch_limit {
        *cursor = previous_cursor;
    } else {
        *cursor = pubkey.to_vec();
    }
    delete_events(txn, ne, lev_ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wok_event::{PackedEventBuilder, PackedEventTagBuilder};

    #[test]
    fn policy_matches_global_and_normalized_service_urls() {
        let policy = VanishPolicy {
            enabled: true,
            service_url: "wss://Relay.Example.com/".into(),
        };
        let mut tags = PackedEventTagBuilder::default();
        tags.add('r', b"ws://relay.example.com").unwrap();
        let event =
            PackedEventBuilder::build(&[1; 32], &[2; 32], 1, VANISH_KIND, 0, &tags).unwrap();
        assert!(policy.targets_this_relay(event.view()));
        assert!(policy
            .targets_this_relay_json(r#"{"kind":62,"tags":[["relay","ws://relay.example.com"]]}"#));
        assert!(!policy.targets_this_relay_json(r#"{"kind":62,"tags":[["random","ALL_RELAYS"]]}"#));

        let mut tags = PackedEventTagBuilder::default();
        tags.add('r', ALL_RELAYS).unwrap();
        let event =
            PackedEventBuilder::build(&[1; 32], &[2; 32], 1, VANISH_KIND, 0, &tags).unwrap();
        assert!(policy.targets_this_relay(event.view()));
    }
}
