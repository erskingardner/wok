//! Persistent NIP-62 markers, immediate query suppression, and bounded sweep.

use crate::keys::{make_key_string_u64, make_key_u64_u64, parse_key_string_u64};
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
    // which covers the author's events at 0 and the gift wraps that p-tag
    // the author.
    if txn.get(dbi, pubkey)?.and_then(read_timestamp) < Some(timestamp) {
        txn.put(dbi, pubkey, &timestamp.to_ne_bytes(), 0)?;
        crate::state::invalidate_visibility(txn)?;
        crate::state::count_vanish_marker_change(txn)?;
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

/// The latest `created_at` of the gift wraps to a vanished recipient that the
/// sweep deletes, for a marker at `timestamp`: with the gift-wrap kinds
/// [`Sweep::advance`] keeps, this is the sweep's whole rule for them. It
/// deletes every gift wrap to the recipient, whatever its `created_at`, as
/// `is_event_vanished_*` hides them all. A finished pass is not repeated, so
/// the write path must refuse the wraps this covers.
fn gift_wraps_swept_through(_timestamp: u64) -> u64 {
    u64::MAX
}

/// How far the sweep has carried out one vanish marker, kept in `wok_State`
/// under [`VANISH_SWEEP`](crate::state::VANISH_SWEEP) and the pubkey. A pass
/// examines the author's events, then the events that `p`-tag the author,
/// and resumes where it stopped, after a restart too. The write path refuses
/// the events a finished pass covered, so it is not repeated: a request that
/// raises the marker starts a pass over only what the raise adds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SweepProgress {
    /// The marker timestamp the pass deletes through.
    target: u64,
    /// The first `created_at` the pass examines: 0 on the marker's first
    /// pass, one past the target of the pass before on a later one.
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

    fn encode(self) -> [u8; SWEEP_PROGRESS_LEN] {
        let (step, position) = match self.step {
            SweepStep::Authored(position) => (0, position),
            SweepStep::Tagged(position) => (1, position),
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
            _ => return Err(DbError::msg("invalid vanish sweep step")),
        };
        Ok(Self {
            target: word(0),
            from: word(8),
            step,
        })
    }
}

fn sweep_progress_key(pubkey: &[u8; 32]) -> [u8; 33] {
    let mut key = [crate::state::VANISH_SWEEP; 33];
    key[1..].copy_from_slice(pubkey);
    key
}

/// A malformed record, which `wok integrity` reports, starts the marker's
/// passes again rather than stopping maintenance.
fn sweep_progress(txn: &RwTxn<'_>, pubkey: &[u8; 32]) -> Result<Option<SweepProgress>, DbError> {
    let Some(dbi) = txn.env().dbis().state else {
        return Ok(None);
    };
    Ok(txn.get(dbi, &sweep_progress_key(pubkey))?.and_then(|raw| {
        match SweepProgress::decode(raw) {
            Ok(progress) => Some(progress),
            Err(error) => {
                tracing::warn!(
                    pubkey = %wok_event::to_hex(pubkey),
                    %error,
                    "vanish sweep progress unreadable; sweeping the marker again"
                );
                None
            }
        }
    }))
}

fn put_sweep_progress(
    txn: &mut RwTxn<'_>,
    pubkey: &[u8; 32],
    progress: SweepProgress,
) -> Result<(), DbError> {
    let dbi = txn
        .env()
        .dbis()
        .state
        .ok_or_else(|| DbError::msg("missing Wok state table"))?;
    txn.put(dbi, &sweep_progress_key(pubkey), &progress.encode(), 0)?;
    Ok(())
}

/// Where [`sweep_vanished_events`] goes on from, held by its caller between
/// calls. Each marker's own progress is stored.
#[derive(Clone, Debug, Default)]
pub struct VanishSweepCursor {
    /// The pubkey of the marker visited last.
    marker: Vec<u8>,
    /// The count of marker changes, and the first of the markers visited
    /// since, all of whose passes had finished.
    finished_since: Option<(u64, [u8; 32])>,
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

/// Carry the vanish markers' passes a bounded step further: visit at most
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
        let Some((pubkey, timestamp)) = next_marker(txn, &cursor.marker)? else {
            cursor.idle_at = Some(changes);
            break;
        };
        markers += 1;
        let stored = sweep_progress(txn, &pubkey)?;
        let progress = match stored {
            Some(SweepProgress {
                target,
                step: SweepStep::Done,
                ..
            }) if target >= timestamp => {
                match cursor.finished_since {
                    Some((since, first)) if since == changes => {
                        if first == pubkey {
                            // A whole round of markers, every one finished.
                            cursor.idle_at = Some(changes);
                            break;
                        }
                    }
                    _ => cursor.finished_since = Some((changes, pubkey)),
                }
                cursor.marker = pubkey.to_vec();
                continue;
            }
            // A later request raised the marker.
            Some(SweepProgress {
                target,
                step: SweepStep::Done,
                ..
            }) => SweepProgress::start(target + 1, timestamp),
            Some(progress) => progress,
            None => SweepProgress::start(0, timestamp),
        };
        cursor.finished_since = None;
        cursor.marker = pubkey.to_vec();
        let progress = sweep.advance(txn, &pubkey, progress)?;
        if stored != Some(progress) {
            put_sweep_progress(txn, &pubkey, progress)?;
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
                pubkey,
                position,
                progress.target,
                |event| event.kind() != VANISH_KIND,
            )?;
            let tagged_from = match progress.from {
                0 => Some(0),
                from => gift_wraps_swept_through(from - 1).checked_add(1),
            };
            progress.step = match (next, tagged_from) {
                (Some(next), _) => SweepStep::Authored(next),
                (None, Some(created_at)) => SweepStep::Tagged(Position {
                    created_at,
                    lev_id: 0,
                }),
                (None, None) => SweepStep::Done,
            };
        }
        if let SweepStep::Tagged(position) = progress.step {
            let mut tag = [b'p'; 33];
            tag[1..].copy_from_slice(pubkey);
            let next = self.walk(
                txn,
                txn.env().dbis().event_tag,
                &tag,
                position,
                gift_wraps_swept_through(progress.target),
                |event| GIFT_WRAP_KINDS.contains(&event.kind()),
            )?;
            progress.step = next.map_or(SweepStep::Done, SweepStep::Tagged);
        }
        Ok(progress)
    }

    /// Examine the entries of `dbi` under `prefix`, from `position` through
    /// `created_at` `through`, keeping the events `deletes` picks. Returns the
    /// first entry left unexamined, or `None` once the range is done.
    fn walk(
        &mut self,
        txn: &RwTxn<'_>,
        dbi: lmdb_sys::MDB_dbi,
        prefix: &[u8],
        position: Position,
        through: u64,
        deletes: impl Fn(PackedEventView<'_>) -> bool,
    ) -> Result<Option<Position>, DbError> {
        let mut next = None;
        let mut error = None;
        txn.foreach_full(
            dbi,
            &make_key_string_u64(prefix, position.created_at),
            // Always a duplicate: without one, the entries at the start key
            // would be skipped.
            &position.lev_id.to_ne_bytes(),
            false,
            |key, value| {
                let (Ok((string, created_at)), Ok(lev_id)) =
                    (parse_key_string_u64(key), <[u8; 8]>::try_from(value))
                else {
                    return false;
                };
                if string != prefix || created_at > through {
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
                        if PackedEventView::new(raw).is_ok_and(&deletes) && self.seen.insert(lev_id)
                        {
                            self.lev_ids.push(lev_id);
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
        raw[16] = 3;
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
