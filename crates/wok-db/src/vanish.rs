//! Persistent deletion markers, immediate query suppression, and bounded sweep.

use crate::keys::{
    make_key_string_u64, make_key_string_u64_u64, make_key_u64_u64, parse_key_string_u64,
    parse_key_string_u64_u64,
};
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
    // No marker sorts below any: a request at created_at 0 still leaves one,
    // which covers the author's events at 0 and the gift wraps at 0 that
    // p-tag the author.
    if txn.get(dbi, pubkey)?.and_then(read_timestamp) < Some(timestamp) {
        txn.put(dbi, pubkey, &timestamp.to_ne_bytes(), 0)?;
        crate::state::invalidate_visibility(txn)?;
        crate::state::count_vanish_marker_change(txn)?;
    }
    Ok(())
}

fn state_key(prefix: u8, pubkey: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.push(prefix);
    key.extend_from_slice(pubkey);
    key
}

/// A kind-5 recipient sweep covers the wraps already stored when the request
/// arrived, regardless of their signed timestamps. Later arrivals remain
/// eligible unless explicitly tombstoned. The local sequence is never reused.
pub(crate) fn mark_recipient_deleted(
    txn: &mut RwTxn<'_>,
    pubkey: &[u8],
    sequence: u64,
) -> Result<(), DbError> {
    let dbi = txn
        .env()
        .dbis()
        .state
        .ok_or_else(|| DbError::msg("missing Wok state table"))?;
    let key = state_key(crate::state::RECIPIENT_DELETE, pubkey);
    let old = txn.get(dbi, &key)?.map(crate::state::decode).transpose()?;
    if old < Some(sequence) {
        txn.put(dbi, &key, &sequence.to_le_bytes(), 0)?;
        crate::state::invalidate_visibility(txn)?;
        crate::state::count_vanish_marker_change(txn)?;
    }
    Ok(())
}

fn recipient_deleted(
    packed: PackedEventView<'_>,
    mut marker: impl FnMut(&[u8]) -> Result<Option<u64>, DbError>,
    local_id: impl FnOnce() -> Result<Option<u64>, DbError>,
) -> Result<bool, DbError> {
    if !GIFT_WRAP_KINDS.contains(&packed.kind()) {
        return Ok(false);
    }
    let mut cutoff = None;
    let mut error = None;
    packed.foreach_tag(|name, value| {
        if name == 'p' {
            match marker(value) {
                Ok(sequence) => cutoff = cutoff.max(sequence),
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
    match cutoff {
        Some(cutoff) => Ok(local_id()?.is_some_and(|lev| lev <= cutoff)),
        None => Ok(false),
    }
}

fn recipient_deleted_ro(txn: &RoTxn<'_>, packed: PackedEventView<'_>) -> Result<bool, DbError> {
    recipient_deleted(
        packed,
        |key| {
            let Some(dbi) = txn.env().dbis().state else {
                return Ok(None);
            };
            txn.get(dbi, &state_key(crate::state::RECIPIENT_DELETE, key))?
                .map(crate::state::decode)
                .transpose()
        },
        || Ok(crate::lookup_event_by_id_ro(txn, packed.id())?.map(|(lev, _)| lev)),
    )
}

fn recipient_deleted_rw(txn: &RwTxn<'_>, packed: PackedEventView<'_>) -> Result<bool, DbError> {
    recipient_deleted(
        packed,
        |key| {
            let Some(dbi) = txn.env().dbis().state else {
                return Ok(None);
            };
            txn.get(dbi, &state_key(crate::state::RECIPIENT_DELETE, key))?
                .map(crate::state::decode)
                .transpose()
        },
        || Ok(crate::lookup_event_by_id(txn, packed.id())?.map(|(lev, _)| lev)),
    )
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
        // The first duplicate, or requests at created_at 0 are skipped.
        &0u64.to_ne_bytes(),
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
        if vanish_timestamp_rw(&txn, &pubkey)? < Some(timestamp) {
            mark_vanished(&mut txn, &pubkey, timestamp)?;
            updated += 1;
        }
    }
    txn.commit()?;
    Ok(updated)
}

/// Whether a NIP-59 gift wrap created at `created_at` falls under the
/// vanish request at `timestamp` of a pubkey it p-tags. Wraps follow the
/// rule for the pubkey's own events: only those created at or before the
/// request vanish, so the key can be sent wraps again afterwards. NIP-59
/// backdates a wrap's `created_at` by up to two days, so a wrap sent in the
/// two days after the request can still fall under it. Every check of a
/// wrap against a marker goes through here; the sweep reads wraps in
/// `created_at` order and stops at the first this refuses, so the rule
/// must stay a bound on `created_at`.
pub fn gift_wrap_vanished(created_at: u64, timestamp: u64) -> bool {
    created_at <= timestamp
}

/// Whether a read batch needs per-event author or recipient deletion checks.
pub fn has_deletion_markers_ro(txn: &RoTxn<'_>) -> Result<bool, DbError> {
    if let Some(dbi) = txn.env().dbis().vanish_pubkey {
        if txn.entries(dbi)? != 0 {
            return Ok(true);
        }
    }
    let Some(dbi) = txn.env().dbis().state else {
        return Ok(false);
    };
    let mut found = false;
    txn.foreach_full(
        dbi,
        &[crate::state::RECIPIENT_DELETE],
        &[],
        false,
        |key, _| {
            found = key.first() == Some(&crate::state::RECIPIENT_DELETE);
            false
        },
    )?;
    Ok(found)
}

pub fn is_event_vanished_ro(txn: &RoTxn<'_>, packed: PackedEventView<'_>) -> Result<bool, DbError> {
    Ok(event_vanished(
        packed,
        |key| vanish_timestamp_ro(txn, key),
        || crate::deletion_protection::is_deletion_protected_ro(txn, packed),
    )? || recipient_deleted_ro(txn, packed)?)
}

/// The incoming event is not stored yet: read its signed marker from the
/// supplied payload, rather than mistaking an absent record for no protection.
pub fn is_event_vanished_ro_with_json(
    txn: &RoTxn<'_>,
    packed: PackedEventView<'_>,
    json: &str,
) -> Result<bool, DbError> {
    Ok(event_vanished(
        packed,
        |key| vanish_timestamp_ro(txn, key),
        || crate::is_deletion_protected_json(packed, json),
    )? || recipient_deleted_ro(txn, packed)?)
}

pub fn is_event_vanished_rw(txn: &RwTxn<'_>, packed: PackedEventView<'_>) -> Result<bool, DbError> {
    Ok(event_vanished(
        packed,
        |key| vanish_timestamp_rw(txn, key),
        || crate::deletion_protection::is_stored_deletion_protected_rw(txn, packed),
    )? || recipient_deleted_rw(txn, packed)?)
}

pub(crate) fn is_event_vanished_rw_with_json(
    txn: &RwTxn<'_>,
    packed: PackedEventView<'_>,
    json: &str,
) -> Result<bool, DbError> {
    Ok(event_vanished(
        packed,
        |key| vanish_timestamp_rw(txn, key),
        || crate::is_deletion_protected_json(packed, json),
    )? || recipient_deleted_rw(txn, packed)?)
}

fn event_vanished(
    packed: PackedEventView<'_>,
    mut timestamp: impl FnMut(&[u8]) -> Result<Option<u64>, DbError>,
    protected: impl FnOnce() -> Result<bool, DbError>,
) -> Result<bool, DbError> {
    if packed.kind() != VANISH_KIND
        && timestamp(packed.pubkey())?.is_some_and(|timestamp| packed.created_at() <= timestamp)
        && !protected()?
    {
        return Ok(true);
    }
    if GIFT_WRAP_KINDS.contains(&packed.kind()) {
        let mut vanished = false;
        let mut error = None;
        packed.foreach_tag(|name, value| {
            if name == 'p' {
                match timestamp(value) {
                    Ok(Some(timestamp)) if gift_wrap_vanished(packed.created_at(), timestamp) => {
                        vanished = true;
                        return false;
                    }
                    Ok(_) => {}
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

#[derive(Clone, Copy)]
struct Marker {
    pubkey: [u8; 32],
    target: u64,
    recipient: bool,
}

impl Marker {
    fn key(self) -> [u8; 33] {
        let mut key = [u8::from(self.recipient); 33];
        key[1..].copy_from_slice(&self.pubkey);
        key
    }

    fn progress_prefix(self) -> u8 {
        if self.recipient {
            crate::state::RECIPIENT_SWEEP
        } else {
            crate::state::VANISH_SWEEP
        }
    }
}

fn next_author_marker(txn: &RwTxn<'_>, cursor: &[u8]) -> Result<Option<Marker>, DbError> {
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
        selected = read_timestamp(value).map(|target| Marker {
            pubkey,
            target,
            recipient: false,
        });
        false
    })?;
    Ok(selected)
}

fn next_recipient_marker(txn: &RwTxn<'_>, cursor: &[u8]) -> Result<Option<Marker>, DbError> {
    let Some(dbi) = txn.env().dbis().state else {
        return Ok(None);
    };
    let seek = state_key(crate::state::RECIPIENT_DELETE, cursor);
    let mut selected = None;
    let mut error = None;
    txn.foreach_full(dbi, &seek, &[], false, |key, value| {
        if key.first() != Some(&crate::state::RECIPIENT_DELETE) {
            return false;
        }
        if !cursor.is_empty() && key <= seek.as_slice() {
            return true;
        }
        let result = (|| {
            let pubkey = key
                .get(1..)
                .and_then(|key| key.try_into().ok())
                .ok_or_else(|| DbError::msg("invalid recipient deletion key"))?;
            Ok::<_, DbError>(Marker {
                pubkey,
                target: crate::state::decode(value)?,
                recipient: true,
            })
        })();
        match result {
            Ok(marker) => selected = Some(marker),
            Err(err) => error = Some(err),
        }
        false
    })?;
    match error {
        Some(error) => Err(error),
        None => Ok(selected),
    }
}

/// The two marker namespaces form one round-robin order. A busy author cannot
/// starve recipient cleanup, and both share the same per-call entry budget.
fn next_marker(txn: &RwTxn<'_>, cursor: &[u8]) -> Result<Option<Marker>, DbError> {
    if cursor.len() == 33 && cursor[0] == 1 {
        if let Some(marker) = next_recipient_marker(txn, &cursor[1..])? {
            return Ok(Some(marker));
        }
        if let Some(marker) = next_author_marker(txn, &[])? {
            return Ok(Some(marker));
        }
        return next_recipient_marker(txn, &[]);
    }
    let after = if cursor.len() == 33 {
        &cursor[1..]
    } else {
        &[]
    };
    if let Some(marker) = next_author_marker(txn, after)? {
        return Ok(Some(marker));
    }
    if let Some(marker) = next_recipient_marker(txn, &[])? {
        return Ok(Some(marker));
    }
    if !after.is_empty() {
        return next_author_marker(txn, &[]);
    }
    Ok(None)
}

/// Persisted in `wok_State` under the authority's progress prefix and pubkey.
/// Author passes scan authored events and recipient tags through a timestamp;
/// recipient kind-5 passes scan gift wraps through a local-ID cutoff. Both
/// resume their index position after a restart. A raised cutoff starts another
/// pass over only the timestamp or local-ID range it adds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SweepProgress {
    /// The timestamp (author) or local ID (recipient) to delete through.
    target: u64,
    /// The inclusive timestamp/local-ID lower bound: 0 on the first pass,
    /// one past the previous target after a raise.
    from: u64,
    step: SweepStep,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SweepStep {
    /// The next author index entry to examine.
    Authored(Position),
    /// The next `p` tag index entry to examine.
    Tagged(Position),
    Done,
    /// Recipient kind-5 sweep when the tag-kind index does not cover the cutoff.
    RecipientTagged(Position),
    /// The next gift-wrap kind and position in a complete tag-kind index.
    RecipientKind(usize, Position),
}

/// An entry of an index keyed by a string and `created_at`, with local IDs
/// as its duplicates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Position {
    created_at: u64,
    lev_id: u64,
}

const SWEEP_PROGRESS_LEN: usize = 33;

impl SweepProgress {
    fn start(from: u64, target: u64) -> Self {
        Self {
            target,
            from,
            step: SweepStep::Authored(Position {
                created_at: from,
                lev_id: 0,
            }),
        }
    }

    fn start_recipient(txn: &RwTxn<'_>, from: u64, target: u64) -> Result<Self, DbError> {
        let position = Position {
            created_at: 0,
            lev_id: 0,
        };
        let step = if crate::tag_kind::tag_kind_index_covers_rw(txn, target)? {
            SweepStep::RecipientKind(0, position)
        } else {
            SweepStep::RecipientTagged(position)
        };
        Ok(Self { target, from, step })
    }

    fn encode(self) -> [u8; SWEEP_PROGRESS_LEN] {
        let (step, position) = match self.step {
            SweepStep::Authored(position) => (0, position),
            SweepStep::Tagged(position) => (1, position),
            SweepStep::RecipientTagged(position) => (3, position),
            SweepStep::RecipientKind(kind, position) => (4 + kind as u8, position),
            SweepStep::Done => (
                2,
                Position {
                    created_at: 0,
                    lev_id: 0,
                },
            ),
        };
        let mut raw = [0u8; SWEEP_PROGRESS_LEN];
        raw[..8].copy_from_slice(&self.target.to_le_bytes());
        raw[8..16].copy_from_slice(&self.from.to_le_bytes());
        raw[16] = step;
        raw[17..25].copy_from_slice(&position.created_at.to_le_bytes());
        raw[25..].copy_from_slice(&position.lev_id.to_le_bytes());
        raw
    }

    pub(crate) fn decode(raw: &[u8]) -> Result<Self, DbError> {
        let raw: &[u8; SWEEP_PROGRESS_LEN] = raw
            .try_into()
            .map_err(|_| DbError::msg("invalid vanish sweep progress"))?;
        let word = |at: usize| u64::from_le_bytes(raw[at..at + 8].try_into().unwrap());
        let position = Position {
            created_at: word(17),
            lev_id: word(25),
        };
        let step = match raw[16] {
            0 => SweepStep::Authored(position),
            1 => SweepStep::Tagged(position),
            2 => SweepStep::Done,
            3 => SweepStep::RecipientTagged(position),
            step if step >= 4 && usize::from(step - 4) < GIFT_WRAP_KINDS.len() => {
                SweepStep::RecipientKind(usize::from(step - 4), position)
            }
            _ => return Err(DbError::msg("invalid vanish sweep step")),
        };
        Ok(Self {
            target: word(0),
            from: word(8),
            step,
        })
    }

    pub(crate) fn decode_for(raw: &[u8], recipient: bool) -> Result<Self, DbError> {
        let progress = Self::decode(raw)?;
        let matches = match progress.step {
            SweepStep::Done => true,
            SweepStep::Authored(_) | SweepStep::Tagged(_) => !recipient,
            SweepStep::RecipientTagged(_) | SweepStep::RecipientKind(..) => recipient,
        };
        if !matches {
            return Err(DbError::msg("sweep step does not match deletion authority"));
        }
        Ok(progress)
    }
}

/// A malformed record, which `wok integrity` reports, starts the marker's
/// passes again rather than stopping maintenance.
fn sweep_progress(txn: &RwTxn<'_>, marker: Marker) -> Result<Option<SweepProgress>, DbError> {
    let Some(dbi) = txn.env().dbis().state else {
        return Ok(None);
    };
    Ok(txn
        .get(dbi, &state_key(marker.progress_prefix(), &marker.pubkey))?
        .and_then(
            |raw| match SweepProgress::decode_for(raw, marker.recipient) {
                Ok(progress) => Some(progress),
                Err(error) => {
                    tracing::warn!(
                        pubkey = %wok_event::to_hex(&marker.pubkey),
                        %error,
                        "vanish sweep progress unreadable; sweeping the marker again"
                    );
                    None
                }
            },
        ))
}

fn put_sweep_progress(
    txn: &mut RwTxn<'_>,
    marker: Marker,
    progress: SweepProgress,
) -> Result<(), DbError> {
    let dbi = txn
        .env()
        .dbis()
        .state
        .ok_or_else(|| DbError::msg("missing Wok state table"))?;
    txn.put(
        dbi,
        &state_key(marker.progress_prefix(), &marker.pubkey),
        &progress.encode(),
        0,
    )?;
    Ok(())
}

/// Where [`sweep_vanished_events`] goes on from, held by its caller between
/// calls. Each marker's own progress is stored.
#[derive(Clone, Debug, Default)]
pub struct VanishSweepCursor {
    /// The authority byte and pubkey of the marker visited last.
    marker: Vec<u8>,
    /// The count of marker changes, and the first of the markers visited
    /// since, all of whose passes had finished.
    finished_since: Option<(u64, [u8; 33])>,
    /// The count of marker changes at which every marker's pass had finished.
    /// Only a new or raised marker gives the sweep more work, and it adds one
    /// to the count.
    idle_at: Option<u64>,
}

/// What one call of [`sweep_vanished_events`] did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VanishSweepStep {
    /// Records deleted.
    pub deleted: u64,
    /// Index entries examined, at most the call's `batch_limit`.
    pub examined: usize,
    /// Markers visited, at most the call's `batch_limit`.
    pub markers: usize,
}

/// Carry author-vanish and kind-5 recipient passes a bounded step further: visit at most
/// `batch_limit` markers and examine at most `batch_limit` index entries, so
/// delete no more records than that. Markers take turns in key order from
/// `cursor`, and each one's pass resumes where it stopped. Once every
/// marker's pass has finished, a call does nothing until a marker is added
/// or raised.
pub fn sweep_vanished_events<N: NegentropySink>(
    txn: &mut RwTxn<'_>,
    ne: &mut N,
    batch_limit: usize,
    cursor: &mut VanishSweepCursor,
) -> Result<VanishSweepStep, DbError> {
    let changes = crate::state::vanish_marker_changes(txn)?;
    if batch_limit == 0 || cursor.idle_at == Some(changes) {
        return Ok(VanishSweepStep::default());
    }
    cursor.idle_at = None;
    let mut sweep = Sweep {
        entries: batch_limit,
        lev_ids: Vec::new(),
        seen: HashSet::new(),
    };
    let mut markers = 0;
    while markers < batch_limit && sweep.entries > 0 {
        let Some(marker) = next_marker(txn, &cursor.marker)? else {
            cursor.idle_at = Some(changes);
            break;
        };
        markers += 1;
        let key = marker.key();
        let stored = sweep_progress(txn, marker)?;
        let progress = match stored {
            Some(progress)
                if marker.recipient
                    && progress.step == SweepStep::Done
                    && progress.target >= marker.target =>
            {
                progress
            }
            Some(SweepProgress {
                target,
                step: SweepStep::Done,
                ..
            }) if target >= marker.target => {
                match cursor.finished_since {
                    Some((since, first)) if since == changes => {
                        if first == key {
                            // A whole round of markers, every one finished.
                            cursor.idle_at = Some(changes);
                            break;
                        }
                    }
                    _ => cursor.finished_since = Some((changes, key)),
                }
                cursor.marker = key.to_vec();
                continue;
            }
            // A later request raised the marker.
            Some(SweepProgress {
                target,
                step: SweepStep::Done,
                ..
            }) => {
                if marker.recipient {
                    SweepProgress::start_recipient(txn, target + 1, marker.target)?
                } else {
                    SweepProgress::start(target + 1, marker.target)
                }
            }
            Some(progress) => progress,
            None if marker.recipient => SweepProgress::start_recipient(txn, 0, marker.target)?,
            None => SweepProgress::start(0, marker.target),
        };
        cursor.finished_since = None;
        cursor.marker = key.to_vec();
        let progress = sweep.advance(txn, &marker.pubkey, progress)?;
        if marker.recipient && progress.step == SweepStep::Done && progress.target >= marker.target
        {
            // These records are deleted by this same transaction below.
            // Releasing completed work restores physical-tree fast paths;
            // unlike NIP-62, a kind-5 sweep does not bar later arrivals.
            let dbi = txn
                .env()
                .dbis()
                .state
                .ok_or_else(|| DbError::msg("missing Wok state table"))?;
            txn.del(
                dbi,
                &state_key(crate::state::RECIPIENT_DELETE, &marker.pubkey),
                None,
            )?;
            txn.del(
                dbi,
                &state_key(crate::state::RECIPIENT_SWEEP, &marker.pubkey),
                None,
            )?;
        } else if stored != Some(progress) {
            put_sweep_progress(txn, marker, progress)?;
        }
    }
    Ok(VanishSweepStep {
        examined: batch_limit - sweep.entries,
        markers,
        deleted: delete_events(txn, ne, sweep.lev_ids)?,
    })
}

/// One call's budget, and the events it deletes.
struct Sweep {
    /// Index entries left to examine.
    entries: usize,
    lev_ids: Vec<u64>,
    seen: HashSet<u64>,
}

impl Sweep {
    /// Carry `progress` as far as the budget allows.
    fn advance(
        &mut self,
        txn: &RwTxn<'_>,
        pubkey: &[u8; 32],
        mut progress: SweepProgress,
    ) -> Result<SweepProgress, DbError> {
        if let SweepStep::Authored(position) = progress.step {
            // Vanish requests stay stored.
            let next = self.walk(
                txn,
                txn.env().dbis().event_pubkey,
                (pubkey, None),
                position,
                |created_at| created_at <= progress.target,
                |lev, event| {
                    Ok(event.kind() != VANISH_KIND
                        && !crate::deletion_protection::is_deletion_protected_rw(txn, lev, event)?)
                },
            )?;
            // A later pass starts past the wraps the pass before covered:
            // `gift_wrap_vanished` covers every wrap created up to a request.
            progress.step = next.map_or(
                SweepStep::Tagged(Position {
                    created_at: progress.from,
                    lev_id: 0,
                }),
                SweepStep::Authored,
            );
        }
        if let SweepStep::Tagged(position) = progress.step {
            let mut tag = [b'p'; 33];
            tag[1..].copy_from_slice(pubkey);
            let next = self.walk(
                txn,
                txn.env().dbis().event_tag,
                (&tag, None),
                position,
                |created_at| gift_wrap_vanished(created_at, progress.target),
                |_, event| Ok(GIFT_WRAP_KINDS.contains(&event.kind())),
            )?;
            progress.step = next.map_or(SweepStep::Done, SweepStep::Tagged);
        }
        // An index reset while a pass is paused needs the bounded fallback.
        if matches!(progress.step, SweepStep::RecipientKind(..))
            && !crate::tag_kind::tag_kind_index_covers_rw(txn, progress.target)?
        {
            progress.step = SweepStep::RecipientTagged(Position {
                created_at: 0,
                lev_id: 0,
            });
        }
        if matches!(
            progress.step,
            SweepStep::RecipientTagged(_) | SweepStep::RecipientKind(..)
        ) {
            let mut tag = [b'p'; 33];
            tag[1..].copy_from_slice(pubkey);
            if let SweepStep::RecipientTagged(position) = progress.step {
                let next = self.walk(
                    txn,
                    txn.env().dbis().event_tag,
                    (&tag, None),
                    position,
                    |_| true,
                    |lev, event| {
                        Ok(lev >= progress.from
                            && lev <= progress.target
                            && GIFT_WRAP_KINDS.contains(&event.kind()))
                    },
                )?;
                progress.step = next.map_or(SweepStep::Done, SweepStep::RecipientTagged);
            }
            while let SweepStep::RecipientKind(kind, position) = progress.step {
                let dbi =
                    txn.env().dbis().event_tag_kind.ok_or_else(|| {
                        DbError::msg("missing tag-kind index during recipient sweep")
                    })?;
                let next = self.walk(
                    txn,
                    dbi,
                    (&tag, Some(GIFT_WRAP_KINDS[kind])),
                    position,
                    |_| true,
                    |lev, event| {
                        Ok(lev >= progress.from
                            && lev <= progress.target
                            && event.kind() == GIFT_WRAP_KINDS[kind])
                    },
                )?;
                if let Some(position) = next {
                    progress.step = SweepStep::RecipientKind(kind, position);
                    break;
                }
                progress.step = if kind + 1 < GIFT_WRAP_KINDS.len() {
                    SweepStep::RecipientKind(
                        kind + 1,
                        Position {
                            created_at: 0,
                            lev_id: 0,
                        },
                    )
                } else {
                    SweepStep::Done
                };
            }
        }
        Ok(progress)
    }

    /// Examine the entries of `dbi` under `prefix`, from `position` while
    /// `within` takes their `created_at`, keeping the events `deletes` picks.
    /// Returns the first entry left unexamined, or `None` once the range is
    /// done.
    fn walk(
        &mut self,
        txn: &RwTxn<'_>,
        dbi: lmdb_sys::MDB_dbi,
        range: (&[u8], Option<u64>),
        position: Position,
        within: impl Fn(u64) -> bool,
        deletes: impl Fn(u64, PackedEventView<'_>) -> Result<bool, DbError>,
    ) -> Result<Option<Position>, DbError> {
        let mut next = None;
        let mut error = None;
        let (prefix, kind) = range;
        let start = match kind {
            Some(kind) => make_key_string_u64_u64(prefix, kind, position.created_at),
            None => make_key_string_u64(prefix, position.created_at),
        };
        txn.foreach_full(
            dbi,
            &start,
            // Always a duplicate: without one, the entries at the start key
            // would be skipped.
            &position.lev_id.to_ne_bytes(),
            false,
            |key, value| {
                let parsed = match kind {
                    Some(kind) => parse_key_string_u64_u64(key).and_then(|(tag, found, at)| {
                        if found == kind {
                            Ok((tag, at))
                        } else {
                            Err(DbError::msg("end of recipient kind range"))
                        }
                    }),
                    None => parse_key_string_u64(key),
                };
                let (Ok((string, created_at)), Ok(lev_id)) = (parsed, <[u8; 8]>::try_from(value))
                else {
                    return false;
                };
                if string != prefix || !within(created_at) {
                    return false;
                }
                let lev_id = u64::from_ne_bytes(lev_id);
                if self.entries == 0 {
                    next = Some(Position { created_at, lev_id });
                    return false;
                }
                self.entries -= 1;
                match txn.get_u64(txn.env().dbis().event, lev_id) {
                    Ok(Some(raw)) => {
                        match PackedEventView::new(raw)
                            .map_err(DbError::from)
                            .and_then(|event| deletes(lev_id, event))
                        {
                            Ok(true) if self.seen.insert(lev_id) => self.lev_ids.push(lev_id),
                            Ok(_) => {}
                            Err(err) => {
                                error = Some(err);
                                return false;
                            }
                        }
                        true
                    }
                    Ok(None) => true,
                    Err(err) => {
                        error = Some(err);
                        false
                    }
                }
            },
        )?;
        match error {
            Some(error) => Err(error),
            None => Ok(next),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wok_event::{PackedEventBuilder, PackedEventTagBuilder};

    #[test]
    fn sweep_progress_round_trips() {
        let position = Position {
            created_at: 7,
            lev_id: u64::MAX,
        };
        for step in [
            SweepStep::Authored(position),
            SweepStep::Tagged(position),
            SweepStep::RecipientTagged(position),
            SweepStep::RecipientKind(0, position),
            SweepStep::RecipientKind(GIFT_WRAP_KINDS.len() - 1, position),
            SweepStep::Done,
        ] {
            let progress = SweepProgress {
                target: 200,
                from: 101,
                step,
            };
            assert_eq!(SweepProgress::decode(&progress.encode()).unwrap(), progress);
        }
        let mut raw = SweepProgress::start(0, 1).encode();
        raw[16] = u8::MAX;
        assert!(SweepProgress::decode(&raw).is_err());
        assert!(SweepProgress::decode(&raw[1..]).is_err());
    }

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
