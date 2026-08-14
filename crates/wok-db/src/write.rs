//! Event insert/delete/replace matching `src/events.cpp`.

use crate::env::Dbis;
use crate::keys::{
    make_key_string_u64, make_key_string_u64_u64, make_key_u64_u64, parse_key_string_u64,
};
use crate::payload::{encode_raw_payload, Decompressor};
use crate::search::{index_event_search, note_search_indexed_through, remove_event_search};
use crate::txn::RwTxn;
use crate::vanish::{is_event_vanished_rw, mark_vanished, VanishPolicy, VANISH_KIND};
use crate::DbError;
use lmdb_sys::{MDB_dbi, MDB_APPEND, MDB_NOOVERWRITE};
use wok_event::{
    is_event_a_before_event_b, is_param_replaceable_kind, is_replaceable_kind, parse_a_tag, sha256,
    to_hex, PackedEventView, GIFT_WRAP_KINDS,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventWriteStatus {
    Pending,
    Written,
    Duplicate,
    Replaced,
    Deleted,
}

#[derive(Debug, Clone)]
pub struct EventToWrite {
    pub packed: Vec<u8>,
    pub json: String,
    pub status: EventWriteStatus,
    pub lev_id: u64,
}

impl EventToWrite {
    pub fn new(packed: Vec<u8>, json: String) -> Self {
        Self {
            packed,
            json,
            status: EventWriteStatus::Pending,
            lev_id: 0,
        }
    }
}

pub trait NegentropySink {
    fn update(&mut self, packed: PackedEventView<'_>, insert: bool) -> Result<(), DbError>;
}

pub struct NoopNegentropy;

impl NegentropySink for NoopNegentropy {
    fn update(&mut self, _packed: PackedEventView<'_>, _insert: bool) -> Result<(), DbError> {
        Ok(())
    }
}

pub fn lookup_event_by_id(txn: &RwTxn<'_>, id: &[u8]) -> Result<Option<(u64, Vec<u8>)>, DbError> {
    let start = make_key_string_u64(id, 0);
    let mut found = None;
    txn.foreach_full(
        txn.env().dbis().event_id,
        &start,
        &0u64.to_ne_bytes(),
        false,
        |k, v| {
            if k.starts_with(id) {
                let lev = u64::from_ne_bytes(v.try_into().unwrap());
                found = Some(lev);
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

pub fn lookup_event_by_levid(txn: &RwTxn<'_>, lev_id: u64) -> Result<Option<Vec<u8>>, DbError> {
    Ok(txn
        .get_u64(txn.env().dbis().event, lev_id)?
        .map(|b| b.to_vec()))
}

pub fn most_recent_levid(txn: &RwTxn<'_>) -> Result<u64, DbError> {
    // C++ foreach_Event reverse=true, take first.
    let mut lev = 0u64;
    txn.foreach_full(
        txn.env().dbis().event,
        &u64::MAX.to_ne_bytes(),
        &[],
        true,
        |k, _v| {
            lev = u64::from_ne_bytes(k.try_into().unwrap());
            false
        },
    )?;
    Ok(lev)
}

pub fn deletion_exists(txn: &RwTxn<'_>, event_id: &[u8], pubkey: &[u8]) -> Result<bool, DbError> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(event_id);
    key.extend_from_slice(pubkey);
    Ok(txn.get(txn.env().dbis().event_deletion, &key)?.is_some())
}

fn index_event(packed: PackedEventView<'_>) -> EventIndices {
    let index_time = packed.created_at();
    let mut idx = EventIndices {
        created_at: Some(index_time),
        id: Some(make_key_string_u64(packed.id(), index_time)),
        pubkey: Some(make_key_string_u64(packed.pubkey(), index_time)),
        kind: Some(make_key_u64_u64(packed.kind(), index_time)),
        pubkey_kind: Some(make_key_string_u64_u64(
            packed.pubkey(),
            packed.kind(),
            index_time,
        )),
        tag: Vec::new(),
        deletion: Vec::new(),
        expiration: Vec::new(),
        replace: Vec::new(),
        replace_deletion: Vec::new(),
    };

    packed.foreach_tag(|tag_name, tag_val| {
        let mut tag_key = Vec::with_capacity(1 + tag_val.len());
        tag_key.push(tag_name as u8);
        tag_key.extend_from_slice(tag_val);
        idx.tag.push(make_key_string_u64(&tag_key, index_time));

        if tag_name == 'd' && idx.replace.is_empty() {
            let mut s = Vec::with_capacity(32 + tag_val.len());
            s.extend_from_slice(packed.pubkey());
            s.extend_from_slice(tag_val);
            idx.replace.push(make_key_string_u64(&s, packed.kind()));
        } else if tag_name == 'e' && packed.kind() == 5 {
            let mut s = Vec::with_capacity(tag_val.len() + 32);
            s.extend_from_slice(tag_val);
            s.extend_from_slice(packed.pubkey());
            idx.deletion.push(s);
        } else if tag_name == 'a' && packed.kind() == 5 {
            if let Ok(val) = std::str::from_utf8(tag_val) {
                if let Ok((kind, pubkey, _d)) = parse_a_tag(val) {
                    if is_param_replaceable_kind(kind) && pubkey.as_slice() == packed.pubkey() {
                        idx.replace_deletion
                            .push(make_key_string_u64(&sha256(tag_val), packed.created_at()));
                    }
                }
            }
        }
        true
    });

    if packed.expiration() != 0 {
        idx.expiration.push(packed.expiration());
    }
    idx
}

pub(crate) struct EventIndices {
    created_at: Option<u64>,
    id: Option<Vec<u8>>,
    pubkey: Option<Vec<u8>>,
    kind: Option<Vec<u8>>,
    pubkey_kind: Option<Vec<u8>>,
    tag: Vec<Vec<u8>>,
    deletion: Vec<Vec<u8>>,
    expiration: Vec<u64>,
    replace: Vec<Vec<u8>>,
    replace_deletion: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EventIndexEntry {
    pub name: &'static str,
    pub dbi: MDB_dbi,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

pub(crate) fn event_index_entries(
    dbis: Dbis,
    lev_id: u64,
    packed: PackedEventView<'_>,
) -> Vec<EventIndexEntry> {
    let idx = index_event(packed);
    let lev = lev_id.to_ne_bytes().to_vec();
    let mut entries = Vec::new();
    let mut push = |name, dbi, key: Vec<u8>| {
        entries.push(EventIndexEntry {
            name,
            dbi,
            key,
            value: lev.clone(),
        });
    };

    if let Some(key) = idx.created_at {
        push(
            "event_created_at",
            dbis.event_created_at,
            key.to_ne_bytes().to_vec(),
        );
    }
    for key in idx.deletion {
        push("event_deletion", dbis.event_deletion, key);
    }
    for key in idx.expiration {
        push(
            "event_expiration",
            dbis.event_expiration,
            key.to_ne_bytes().to_vec(),
        );
    }
    if let Some(key) = idx.id {
        push("event_id", dbis.event_id, key);
    }
    if let Some(key) = idx.kind {
        push("event_kind", dbis.event_kind, key);
    }
    if let Some(key) = idx.pubkey {
        push("event_pubkey", dbis.event_pubkey, key);
    }
    if let Some(key) = idx.pubkey_kind {
        push("event_pubkey_kind", dbis.event_pubkey_kind, key);
    }
    for key in idx.replace {
        push("event_replace", dbis.event_replace, key);
    }
    for key in idx.replace_deletion {
        push("event_replace_deletion", dbis.event_replace_deletion, key);
    }
    for key in idx.tag {
        push("event_tag", dbis.event_tag, key);
    }
    // DUPSORT databases store a key/value pair only once. Repeated identical
    // tags therefore describe one physical index entry.
    entries.sort_by(|a, b| {
        a.dbi
            .cmp(&b.dbi)
            .then_with(|| a.key.cmp(&b.key))
            .then_with(|| a.value.cmp(&b.value))
    });
    entries.dedup_by(|a, b| a.dbi == b.dbi && a.key == b.key && a.value == b.value);
    entries
}

fn put_indices(txn: &mut RwTxn<'_>, lev_id: u64, idx: &EventIndices) -> Result<(), DbError> {
    let dbis = txn.env().dbis();
    let lev = lev_id.to_ne_bytes();
    if let Some(k) = idx.created_at {
        txn.put_u64(dbis.event_created_at, k, &lev, 0)?;
    }
    for k in &idx.deletion {
        txn.put(dbis.event_deletion, k, &lev, 0)?;
    }
    for k in &idx.expiration {
        txn.put_u64(dbis.event_expiration, *k, &lev, 0)?;
    }
    if let Some(k) = &idx.id {
        txn.put(dbis.event_id, k, &lev, 0)?;
    }
    if let Some(k) = &idx.kind {
        txn.put(dbis.event_kind, k, &lev, 0)?;
    }
    if let Some(k) = &idx.pubkey {
        txn.put(dbis.event_pubkey, k, &lev, 0)?;
    }
    if let Some(k) = &idx.pubkey_kind {
        txn.put(dbis.event_pubkey_kind, k, &lev, 0)?;
    }
    for k in &idx.replace {
        txn.put(dbis.event_replace, k, &lev, 0)?;
    }
    for k in &idx.replace_deletion {
        txn.put(dbis.event_replace_deletion, k, &lev, 0)?;
    }
    for k in &idx.tag {
        txn.put(dbis.event_tag, k, &lev, 0)?;
    }
    Ok(())
}

fn del_indices(txn: &mut RwTxn<'_>, lev_id: u64, idx: &EventIndices) -> Result<(), DbError> {
    let dbis = txn.env().dbis();
    let lev = lev_id.to_ne_bytes();
    if let Some(k) = idx.created_at {
        txn.del_u64(dbis.event_created_at, k, Some(&lev))?;
    }
    for k in &idx.deletion {
        txn.del(dbis.event_deletion, k, Some(&lev))?;
    }
    for k in &idx.expiration {
        txn.del_u64(dbis.event_expiration, *k, Some(&lev))?;
    }
    if let Some(k) = &idx.id {
        txn.del(dbis.event_id, k, Some(&lev))?;
    }
    if let Some(k) = &idx.kind {
        txn.del(dbis.event_kind, k, Some(&lev))?;
    }
    if let Some(k) = &idx.pubkey {
        txn.del(dbis.event_pubkey, k, Some(&lev))?;
    }
    if let Some(k) = &idx.pubkey_kind {
        txn.del(dbis.event_pubkey_kind, k, Some(&lev))?;
    }
    for k in &idx.replace {
        txn.del(dbis.event_replace, k, Some(&lev))?;
    }
    for k in &idx.replace_deletion {
        txn.del(dbis.event_replace_deletion, k, Some(&lev))?;
    }
    for k in &idx.tag {
        txn.del(dbis.event_tag, k, Some(&lev))?;
    }
    Ok(())
}

pub fn delete_event_basic(txn: &mut RwTxn<'_>, lev_id: u64) -> Result<bool, DbError> {
    let dbis = txn.env().dbis();
    let json = if let Some(raw) = txn.get_u64(dbis.event_payload, lev_id)?.map(<[u8]>::to_vec) {
        let mut decompressor = Decompressor::new();
        Some(
            decompressor
                .decode_rw(txn, &raw, 16 * 1024 * 1024)?
                .to_owned(),
        )
    } else {
        None
    };
    // C++ deleteEventBasic: payload row first; the return value reports
    // whether a payload existed, independent of the primary record.
    let deleted = txn.del_u64(dbis.event_payload, lev_id, None)?;
    if let Some(json) = json {
        remove_event_search(txn, lev_id, &json)?;
    }
    if let Some(buf) = txn.get_u64(dbis.event, lev_id)?.map(|b| b.to_vec()) {
        let packed = PackedEventView::new(&buf)?;
        let idx = index_event(packed);
        del_indices(txn, lev_id, &idx)?;
        txn.del_u64(dbis.event, lev_id, None)?;
    }
    Ok(deleted)
}

fn insert_event(txn: &mut RwTxn<'_>, packed: &[u8], json: &str) -> Result<u64, DbError> {
    let dbis = txn.env().dbis();
    let lev_id = txn.next_integer_key(dbis.event)?;
    let inserted = txn.put_u64(dbis.event, lev_id, packed, MDB_NOOVERWRITE | MDB_APPEND)?;
    if !inserted {
        return Err(DbError::msg("duplicate insert into Event"));
    }
    let payload = encode_raw_payload(json);
    txn.put_u64(dbis.event_payload, lev_id, &payload, 0)?;
    let view = PackedEventView::new(packed)?;
    let idx = index_event(view);
    put_indices(txn, lev_id, &idx)?;
    index_event_search(txn, lev_id, json)?;
    Ok(lev_id)
}

pub fn write_events<N: NegentropySink>(
    txn: &mut RwTxn<'_>,
    ne: &mut N,
    evs: &mut [EventToWrite],
    _log_deletions: bool,
) -> Result<(), DbError> {
    write_events_with_policy(txn, ne, evs, _log_deletions, &VanishPolicy::disabled())
}

pub fn write_events_with_policy<N: NegentropySink>(
    txn: &mut RwTxn<'_>,
    ne: &mut N,
    evs: &mut [EventToWrite],
    _log_deletions: bool,
    vanish_policy: &VanishPolicy,
) -> Result<(), DbError> {
    evs.sort_by(|a, b| {
        let pa = PackedEventView::new(&a.packed).ok();
        let pb = PackedEventView::new(&b.packed).ok();
        match (pa, pb) {
            (Some(a), Some(b)) => a
                .created_at()
                .cmp(&b.created_at())
                .then_with(|| a.id().cmp(b.id())),
            _ => std::cmp::Ordering::Equal,
        }
    });

    let mut lev_ids_to_delete: Vec<u64> = Vec::new();
    let mut indexed_through = None;

    for i in 0..evs.len() {
        let packed_bytes = evs[i].packed.clone();
        let packed = PackedEventView::new(&packed_bytes)?;

        if lookup_event_by_id(txn, packed.id())?.is_some()
            || (i != 0 && evs[i].packed.get(0..32) == evs[i - 1].packed.get(0..32))
        {
            evs[i].status = EventWriteStatus::Duplicate;
            continue;
        }

        let is_vanish_request = packed.kind() == VANISH_KIND;
        if is_vanish_request
            && vanish_policy.enabled
            && !vanish_policy.targets_this_relay_json(&evs[i].json)
        {
            evs[i].status = EventWriteStatus::Deleted;
            continue;
        }

        if !is_vanish_request && is_event_vanished_rw(txn, packed)? {
            evs[i].status = EventWriteStatus::Deleted;
            continue;
        }

        // NIP-62 requests cannot be removed or preemptively tombstoned by a
        // kind 5 event. Validity and duplicate checks still apply.
        if !is_vanish_request && deletion_exists(txn, packed.id(), packed.pubkey())? {
            evs[i].status = EventWriteStatus::Deleted;
            continue;
        }

        if GIFT_WRAP_KINDS.contains(&packed.kind()) {
            let mut recipient_deleted = false;
            let mut scan_err: Option<DbError> = None;
            packed.foreach_tag(|tag_name, tag_val| {
                if scan_err.is_some() {
                    return false;
                }
                if tag_name == 'p' {
                    match deletion_exists(txn, packed.id(), tag_val) {
                        Ok(true) => {
                            recipient_deleted = true;
                            return false;
                        }
                        Ok(false) => {}
                        Err(e) => {
                            scan_err = Some(e);
                            return false;
                        }
                    }
                }
                true
            });
            if let Some(e) = scan_err {
                return Err(e);
            }
            if recipient_deleted {
                evs[i].status = EventWriteStatus::Deleted;
                continue;
            }
        }

        if is_replaceable_kind(packed.kind()) || is_param_replaceable_kind(packed.kind()) {
            if let Some(replace) = packed.first_d_tag() {
                let mut search_str = Vec::new();
                search_str.extend_from_slice(packed.pubkey());
                search_str.extend_from_slice(&replace);
                let search_key = make_key_string_u64(&search_str, packed.kind());

                let mut other: Option<u64> = None;
                txn.foreach_full(
                    txn.env().dbis().event_replace,
                    &search_key,
                    &u64::MAX.to_ne_bytes(),
                    true,
                    |k, v| {
                        if k != search_key.as_slice() {
                            return false;
                        }
                        let lev = u64::from_ne_bytes(v.try_into().unwrap());
                        other = Some(lev);
                        false
                    },
                )?;
                if let Some(lev) = other {
                    // C++ lookupEventByLevId throws on a dangling index entry.
                    let buf = lookup_event_by_levid(txn, lev)?
                        .ok_or_else(|| DbError::msg("unable to lookup event by levId"))?;
                    let other_packed = PackedEventView::new(&buf)?;
                    if is_event_a_before_event_b(packed, other_packed) {
                        evs[i].status = EventWriteStatus::Replaced;
                    } else {
                        lev_ids_to_delete.push(lev);
                    }
                }

                if is_param_replaceable_kind(packed.kind())
                    && evs[i].status == EventWriteStatus::Pending
                {
                    // Hash the raw d-tag bytes, like C++ (no UTF-8 round-trip).
                    let mut a_tag = Vec::with_capacity(24 + 64 + 1 + replace.len());
                    a_tag.extend_from_slice(packed.kind().to_string().as_bytes());
                    a_tag.push(b':');
                    a_tag.extend_from_slice(to_hex(packed.pubkey()).as_bytes());
                    a_tag.push(b':');
                    a_tag.extend_from_slice(&replace);
                    let search_str = sha256(&a_tag);
                    let search_key = make_key_string_u64(&search_str, u64::MAX);
                    let mut scan_err: Option<DbError> = None;
                    txn.foreach_full(
                        txn.env().dbis().event_replace_deletion,
                        &search_key,
                        &u64::MAX.to_ne_bytes(),
                        true,
                        |k, _v| {
                            // C++ ParsedKey_StringUint64 throws on malformed keys.
                            match parse_key_string_u64(k) {
                                Ok((s, n)) => {
                                    if s != search_str.as_slice() {
                                        return false;
                                    }
                                    if n >= packed.created_at() {
                                        evs[i].status = EventWriteStatus::Deleted;
                                    }
                                }
                                Err(e) => {
                                    scan_err = Some(e);
                                }
                            }
                            false
                        },
                    )?;
                    if let Some(e) = scan_err {
                        return Err(e);
                    }
                }
            }
        }

        if packed.kind() == 5 {
            // LMDB errors abort the write like C++; only malformed a-tags are
            // skipped (C++ catch(...)).
            let mut scan_err: Option<DbError> = None;
            packed.foreach_tag(|tag_name, tag_val| {
                if scan_err.is_some() {
                    return false;
                }
                if tag_name == 'e' {
                    match lookup_event_by_id(txn, tag_val) {
                        Ok(Some((lev, buf))) => match PackedEventView::new(&buf) {
                            Ok(other) => {
                                let mut can_delete = other.kind() != VANISH_KIND
                                    && other.pubkey() == packed.pubkey();
                                if !can_delete && GIFT_WRAP_KINDS.contains(&other.kind()) {
                                    other.foreach_tag(|on, ov| {
                                        if on == 'p' && ov == packed.pubkey() {
                                            can_delete = true;
                                            return false;
                                        }
                                        true
                                    });
                                }
                                if can_delete {
                                    lev_ids_to_delete.push(lev);
                                }
                            }
                            Err(e) => scan_err = Some(DbError::msg(e.to_string())),
                        },
                        Ok(None) => {}
                        Err(e) => scan_err = Some(e),
                    }
                } else if tag_name == 'a' {
                    let parsed = std::str::from_utf8(tag_val)
                        .ok()
                        .and_then(|s| parse_a_tag(s).ok());
                    if let Some((kind, pubkey, d_tag)) = parsed {
                        if is_param_replaceable_kind(kind) && pubkey.as_slice() == packed.pubkey() {
                            let mut search = Vec::new();
                            search.extend_from_slice(&pubkey);
                            search.extend_from_slice(d_tag.as_bytes());
                            let search_key = make_key_string_u64(&search, kind);
                            let mut hit: Option<u64> = None;
                            let scan_res = txn.foreach_full(
                                txn.env().dbis().event_replace,
                                &search_key,
                                &u64::MAX.to_ne_bytes(),
                                true,
                                |k, v| {
                                    if k != search_key.as_slice() {
                                        return false;
                                    }
                                    hit = Some(u64::from_ne_bytes(v.try_into().unwrap()));
                                    false
                                },
                            );
                            if let Err(e) = scan_res {
                                scan_err = Some(e);
                                return false;
                            }
                            if let Some(lev) = hit {
                                match lookup_event_by_levid(txn, lev) {
                                    Ok(Some(buf)) => match PackedEventView::new(&buf) {
                                        Ok(other) => {
                                            if other.created_at() <= packed.created_at() {
                                                lev_ids_to_delete.push(lev);
                                            }
                                        }
                                        Err(e) => scan_err = Some(DbError::msg(e.to_string())),
                                    },
                                    Ok(None) => {
                                        scan_err =
                                            Some(DbError::msg("unable to lookup event by levId"));
                                    }
                                    Err(e) => scan_err = Some(e),
                                }
                            }
                        }
                    }
                }
                scan_err.is_none()
            });
            if let Some(e) = scan_err {
                return Err(e);
            }
        }

        if evs[i].status == EventWriteStatus::Pending {
            if is_vanish_request && vanish_policy.enabled {
                mark_vanished(txn, packed.pubkey(), packed.created_at())?;
            }
            let json = evs[i].json.clone();
            let lev_id = insert_event(txn, &packed_bytes, &json)?;
            indexed_through = Some(lev_id);
            evs[i].lev_id = lev_id;
            ne.update(PackedEventView::new(&packed_bytes)?, true)?;
            evs[i].status = EventWriteStatus::Written;

            for lev in lev_ids_to_delete.drain(..) {
                if let Some(buf) = lookup_event_by_levid(txn, lev)? {
                    ne.update(PackedEventView::new(&buf)?, false)?;
                    delete_event_basic(txn, lev)?;
                }
            }
        }

        if !lev_ids_to_delete.is_empty() {
            return Err(DbError::msg("unprocessed deletion"));
        }
    }

    // The search watermark is transaction-level progress. Updating the
    // DUPSORT metadata key after every event needlessly deletes and reinserts
    // the same record throughout a batch.
    if let Some(lev_id) = indexed_through {
        note_search_indexed_through(txn, lev_id)?;
    }

    Ok(())
}

pub fn delete_events<N: NegentropySink>(
    txn: &mut RwTxn<'_>,
    ne: &mut N,
    lev_ids: impl IntoIterator<Item = u64>,
) -> Result<u64, DbError> {
    let mut n = 0u64;
    for lev in lev_ids {
        if let Some(buf) = lookup_event_by_levid(txn, lev)? {
            ne.update(PackedEventView::new(&buf)?, false)?;
            if delete_event_basic(txn, lev)? {
                n += 1;
            }
        }
    }
    Ok(n)
}
