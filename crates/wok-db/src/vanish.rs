//! Persistent NIP-62 markers, immediate query suppression, and bounded sweep.

use crate::keys::{make_key_string_u64, make_key_u64_u64};
use crate::payload::{event_json_owned, Decompressor};
use crate::txn::{RoTxn, RwTxn};
use crate::write::{delete_events, NegentropySink};
use crate::{get_packed_ro, DbError, Env};
use serde_json::Value;
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
        wok_event::json::parse_strict(json).is_ok_and(|event| self.targets_this_relay_value(&event))
    }

    /// [`targets_this_relay_json`](Self::targets_this_relay_json) for an
    /// event already parsed, such as one a client sent and the relay has not
    /// yet verified.
    pub fn targets_this_relay_value(&self, event: &Value) -> bool {
        if !self.enabled || event.get("kind").and_then(Value::as_u64) != Some(VANISH_KIND) {
            return false;
        }
        let expected = normalize_relay_url(&self.service_url);
        event
            .get("tags")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_array)
            .any(|tag| {
                tag.first().and_then(Value::as_str) == Some("relay")
                    && tag.get(1).and_then(Value::as_str).is_some_and(|value| {
                        value == "ALL_RELAYS"
                            || (!expected.is_empty() && normalize_relay_url(value) == expected)
                    })
            })
    }
}

/// A relay URL as NIP-42 AUTH and NIP-62 vanish requests compare it with the
/// relay's service URL: without its query, fragment, trailing slashes, or
/// the port its scheme implies, and with its scheme and host in lowercase.
/// A URL without a scheme is `wss`, as clients take it, and `https` and
/// `http` count as `wss` and `ws`. The scheme and the path are kept, so
/// relays on another port or path of the same host, which proxies match
/// case-sensitively, do not accept each other's URLs. An empty URL stays
/// empty, so an unset service URL matches nothing.
pub fn normalize_relay_url(url: &str) -> String {
    let url = url.trim();
    if url.is_empty() {
        return String::new();
    }
    let (scheme, rest) = url.split_once("://").unwrap_or(("wss", url));
    let rest = rest.split(['?', '#']).next().unwrap_or_default();
    let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let scheme = match scheme.to_ascii_lowercase().as_str() {
        "https" => "wss".to_string(),
        "http" => "ws".to_string(),
        other => other.to_string(),
    };
    let default_port = match scheme.as_str() {
        "wss" => Some(":443"),
        "ws" => Some(":80"),
        _ => None,
    };
    let authority = default_port
        .and_then(|port| authority.strip_suffix(port))
        .unwrap_or(authority);
    format!(
        "{scheme}://{}{}",
        authority.to_ascii_lowercase(),
        path.trim_end_matches('/')
    )
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
        crate::state::invalidate_visibility(txn)?;
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
        tags.add('r', b"WSS://relay.example.com").unwrap();
        let event =
            PackedEventBuilder::build(&[1; 32], &[2; 32], 1, VANISH_KIND, 0, &tags).unwrap();
        assert!(policy.targets_this_relay(event.view()));
        assert!(policy.targets_this_relay_json(
            r#"{"kind":62,"tags":[["relay","WSS://relay.example.com"]]}"#
        ));
        assert!(!policy.targets_this_relay_json(r#"{"kind":62,"tags":[["random","ALL_RELAYS"]]}"#));
        // The JSON is read as strictly as any event: stock serde_json would
        // keep the second `tags`.
        assert!(!policy.targets_this_relay_json(
            r#"{"kind":62,"tags":[["relay","ALL_RELAYS"]],"tags":[["relay","ALL_RELAYS"]]}"#
        ));
        let stated =
            serde_json::json!({"kind": 62, "tags": [["relay", "wss://relay.example.com"]]});
        assert!(policy.targets_this_relay_value(&stated));
        assert!(!VanishPolicy::disabled().targets_this_relay_value(&stated));

        let mut tags = PackedEventTagBuilder::default();
        tags.add('r', ALL_RELAYS).unwrap();
        let event =
            PackedEventBuilder::build(&[1; 32], &[2; 32], 1, VANISH_KIND, 0, &tags).unwrap();
        assert!(policy.targets_this_relay(event.view()));
    }

    #[test]
    fn relay_urls_differ_by_path_but_not_by_spelling() {
        let same = [
            ("wss://relay.example.com", "wss://relay.example.com/"),
            ("wss://relay.example.com", "WSS://Relay.Example.COM//"),
            ("wss://relay.example.com", "wss://relay.example.com:443"),
            ("wss://relay.example.com", "https://relay.example.com:443/"),
            ("ws://relay.example.com", "ws://relay.example.com:80/"),
            (
                "wss://relay.example.com",
                "wss://relay.example.com/?client=x#y",
            ),
            ("wss://relay.example.com", " relay.example.com "),
            (
                "wss://host.example/relayA",
                "wss://host.example:443/relayA/",
            ),
            ("wss://host.example/relayA", "wss://HOST.example/relayA?x=1"),
            ("wss://[::1]:443/a", "wss://[::1]/a"),
        ];
        for (a, b) in same {
            assert_eq!(normalize_relay_url(a), normalize_relay_url(b), "{a} vs {b}");
        }
        let different = [
            ("wss://host.example/relayA", "wss://host.example/relayB"),
            ("wss://host.example/relayA", "wss://host.example"),
            ("wss://host.example/relayA", "wss://host.example/relayA/sub"),
            ("wss://host.example/relayA", "wss://host.example/RelayA"),
            ("wss://host.example", "wss://host.example:8443"),
            ("wss://host.example", "wss://host.example:80"),
            ("wss://host.example/relay", "ws://host.example/relay"),
            ("wss://host.example:443/relay", "ws://host.example:80/relay"),
            ("wss://host.example", "wss://other.example"),
        ];
        for (a, b) in different {
            assert_ne!(normalize_relay_url(a), normalize_relay_url(b), "{a} vs {b}");
        }
    }

    #[test]
    fn a_targeted_vanish_request_must_name_the_relay_path() {
        let policy = VanishPolicy {
            enabled: true,
            service_url: "wss://host.example/relayA".into(),
        };
        let request = |relay: &str| {
            policy.targets_this_relay_json(
                &serde_json::json!({"kind": 62, "tags": [["relay", relay]]}).to_string(),
            )
        };
        assert!(request("wss://host.example/relayA/"));
        assert!(request("wss://host.example:443/relayA"));
        assert!(!request("wss://host.example/relayB"));
        assert!(!request("wss://host.example/relaya"));
        assert!(!request("ws://host.example:80/relayA"));
        assert!(!request("wss://host.example"));
        assert!(request("ALL_RELAYS"));
    }

    #[test]
    fn an_unset_service_url_matches_only_all_relays() {
        let policy = VanishPolicy {
            enabled: true,
            service_url: String::new(),
        };
        for relay in ["", " ", "wss://", "wss:///"] {
            let request = serde_json::json!({"kind": 62, "tags": [["relay", relay]]});
            assert!(!policy.targets_this_relay_value(&request), "{relay:?}");
        }
        let all = serde_json::json!({"kind": 62, "tags": [["relay", "ALL_RELAYS"]]});
        assert!(policy.targets_this_relay_value(&all));
    }
}
