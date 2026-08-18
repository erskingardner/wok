//! Persistent NIP-86 moderation records, listing, and query suppression.
//!
//! All records live in the single `wok_Moderation` DBI with a one-byte record
//! type prefix, so adding record kinds never changes the DBI set. Reasons are
//! stored as raw UTF-8 (possibly empty); roles are stored as JSON.
//!
//! Ban semantics are suppressive, not destructive: banned pubkeys and event
//! ids are rejected on future writes and hidden from query results, but the
//! underlying events stay in the database so an unban restores them.

use crate::txn::{RoTxn, RwTxn};
use crate::DbError;
use lmdb_sys::MDB_dbi;
use std::collections::{BTreeMap, HashMap};
use wok_event::PackedEventView;

const PREFIX_BANNED_PUBKEY: u8 = b'B';
const PREFIX_ALLOWED_PUBKEY: u8 = b'A';
const PREFIX_BANNED_EVENT: u8 = b'E';
const PREFIX_BLOCKED_IP: u8 = b'I';
const PREFIX_REPORTED_EVENT: u8 = b'R';
const PREFIX_ROLE: u8 = b'G';
const PREFIX_PUBKEY_ROLES: u8 = b'P';
const PREFIX_KIND_POLICY: u8 = b'K';

/// Longest stored operator-supplied reason.
pub const MAX_REASON_BYTES: usize = 512;
/// Per-record-type ceiling for ban/allow/block/report lists.
pub const MAX_MODERATION_RECORDS: usize = 100_000;
pub const MAX_ROLES: usize = 1_000;
pub const MAX_ROLES_PER_PUBKEY: usize = 64;
pub const MAX_ROLE_ID_BYTES: usize = 64;
pub const MAX_ROLE_FIELD_BYTES: usize = 256;
pub const MAX_IP_BYTES: usize = 64;

/// Role ids with built-in wok semantics; `createrole` may not reuse them.
pub const BUILTIN_ROLE_ADMIN: &str = "admin";
pub const BUILTIN_ROLE_MODERATOR: &str = "moderator";
pub const BUILTIN_ROLE_MEMBER: &str = "member";
pub const BUILTIN_ROLES: &[&str] = &[
    BUILTIN_ROLE_ADMIN,
    BUILTIN_ROLE_MODERATOR,
    BUILTIN_ROLE_MEMBER,
];

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Role {
    pub id: String,
    pub label: String,
    pub description: String,
    pub color: String,
    pub order: u64,
}

const KIND_POLICY_BYTES: usize = (u16::MAX as usize + 1) / 8;

/// NIP-86 allowed-kind set as a 65536-bit map (8 KiB), stored under a single
/// `K` record. Absent record means every kind is allowed; a present map is
/// authoritative, including the all-zero "nothing allowed" state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KindPolicy(pub Box<[u8; KIND_POLICY_BYTES]>);

impl KindPolicy {
    /// A policy allowing every kind.
    pub fn allow_all() -> Self {
        Self(Box::new([0xff; KIND_POLICY_BYTES]))
    }

    pub fn allows(&self, kind: u64) -> bool {
        let kind = kind as usize;
        self.0
            .get(kind / 8)
            .is_some_and(|byte| byte & (1 << (kind % 8)) != 0)
    }

    pub fn set_allowed(&mut self, kind: u64, allowed: bool) {
        let kind = kind as usize;
        debug_assert!(kind <= u16::MAX as usize);
        if allowed {
            self.0[kind / 8] |= 1 << (kind % 8);
        } else {
            self.0[kind / 8] &= !(1 << (kind % 8));
        }
    }

    /// Enumerate the allowed kinds (used by `listallowedkinds`).
    pub fn allowed_kinds(&self) -> Vec<u64> {
        (0..=u16::MAX as u64)
            .filter(|kind| self.allows(*kind))
            .collect()
    }
}

/// Full in-memory copy of the moderation tables for synchronous checks on
/// hot paths (connection admission, ingest, live broadcast).
#[derive(Debug, Clone, Default)]
pub struct ModerationSnapshot {
    pub banned_pubkeys: HashMap<[u8; 32], String>,
    pub allowed_pubkeys: HashMap<[u8; 32], String>,
    pub banned_events: HashMap<[u8; 32], String>,
    pub blocked_ips: HashMap<String, String>,
    pub reported_events: HashMap<[u8; 32], String>,
    pub roles: BTreeMap<String, Role>,
    pub pubkey_roles: HashMap<[u8; 32], Vec<String>>,
    /// `None` means every kind is allowed (no policy record stored).
    pub kind_policy: Option<KindPolicy>,
}

impl ModerationSnapshot {
    pub fn roles_of(&self, pubkey: &[u8; 32]) -> &[String] {
        self.pubkey_roles
            .get(pubkey)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Write access under `relay.auth.restrict_writes`: allowlisted pubkeys,
    /// and pubkeys holding any role (built-in or custom), may write.
    pub fn write_permitted(&self, pubkey: &[u8; 32]) -> bool {
        self.allowed_pubkeys.contains_key(pubkey) || self.pubkey_roles.contains_key(pubkey)
    }

    /// Kind admission under the NIP-86 kind policy. `None` allows everything.
    pub fn kind_allowed(&self, kind: u64) -> bool {
        self.kind_policy
            .as_ref()
            .is_none_or(|policy| policy.allows(kind))
    }
}

/// Shared read surface so helpers work on both read-only and read-write
/// transactions without duplication.
#[doc(hidden)]
pub trait ReadOps {
    fn moderation_dbi(&self) -> Option<MDB_dbi>;
    fn get_record(&self, dbi: MDB_dbi, key: &[u8]) -> Result<Option<Vec<u8>>, DbError>;
    fn foreach_prefix(
        &self,
        dbi: MDB_dbi,
        prefix: u8,
        cb: &mut dyn FnMut(&[u8], &[u8]) -> bool,
    ) -> Result<(), DbError>;
}

macro_rules! impl_read_ops {
    ($txn:ty) => {
        impl ReadOps for $txn {
            fn moderation_dbi(&self) -> Option<MDB_dbi> {
                self.env().dbis().moderation
            }
            fn get_record(&self, dbi: MDB_dbi, key: &[u8]) -> Result<Option<Vec<u8>>, DbError> {
                Ok(self.get(dbi, key)?.map(<[u8]>::to_vec))
            }
            fn foreach_prefix(
                &self,
                dbi: MDB_dbi,
                prefix: u8,
                cb: &mut dyn FnMut(&[u8], &[u8]) -> bool,
            ) -> Result<(), DbError> {
                self.foreach_full(dbi, &[prefix], &[], false, |key, value| {
                    key.first() == Some(&prefix) && cb(&key[1..], value)
                })?;
                Ok(())
            }
        }
    };
}

impl_read_ops!(RoTxn<'_>);
impl_read_ops!(RwTxn<'_>);

fn prefixed(prefix: u8, payload: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + payload.len());
    key.push(prefix);
    key.extend_from_slice(payload);
    key
}

fn decode_reason(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw).into_owned()
}

fn validate_reason(reason: &str) -> Result<(), DbError> {
    if reason.len() > MAX_REASON_BYTES {
        return Err(DbError::msg(format!(
            "reason exceeds {MAX_REASON_BYTES} bytes"
        )));
    }
    Ok(())
}

fn validate_role_id(id: &str) -> Result<(), DbError> {
    if id.is_empty() || id.len() > MAX_ROLE_ID_BYTES {
        return Err(DbError::msg(format!(
            "role id must be 1..={MAX_ROLE_ID_BYTES} bytes"
        )));
    }
    if id.chars().any(char::is_control) {
        return Err(DbError::msg("role id must not contain control characters"));
    }
    if BUILTIN_ROLES.contains(&id) {
        return Err(DbError::msg(format!("role id {id:?} is reserved")));
    }
    Ok(())
}

/// Parse and canonicalize an IP for use as a moderation key. Connection
/// admission renders peers with `IpAddr::to_string()`, so storing anything
/// but the canonical form (e.g. `2001:0db8::1`) would silently never match.
fn canonicalize_ip(ip: &str) -> Result<String, DbError> {
    let parsed: std::net::IpAddr = ip
        .trim()
        .parse()
        .map_err(|_| DbError::msg(format!("{ip:?} is not a valid IP address")))?;
    let canonical = parsed.to_string();
    if canonical.len() > MAX_IP_BYTES {
        return Err(DbError::msg(format!("ip must be <= {MAX_IP_BYTES} bytes")));
    }
    Ok(canonical)
}

fn count_prefix<T: ReadOps>(txn: &T, dbi: MDB_dbi, prefix: u8) -> Result<usize, DbError> {
    let mut count = 0usize;
    txn.foreach_prefix(dbi, prefix, &mut |_, _| {
        count += 1;
        true
    })?;
    Ok(count)
}

fn list_prefix<T: ReadOps>(
    txn: &T,
    dbi: MDB_dbi,
    prefix: u8,
) -> Result<Vec<(Vec<u8>, String)>, DbError> {
    let mut out = Vec::new();
    txn.foreach_prefix(dbi, prefix, &mut |key, value| {
        out.push((key.to_vec(), decode_reason(value)));
        true
    })?;
    Ok(out)
}

fn get_reason<T: ReadOps>(txn: &T, prefix: u8, payload: &[u8]) -> Result<Option<String>, DbError> {
    let Some(dbi) = txn.moderation_dbi() else {
        return Ok(None);
    };
    Ok(txn
        .get_record(dbi, &prefixed(prefix, payload))?
        .map(|raw| decode_reason(&raw)))
}

fn put_record(
    txn: &mut RwTxn<'_>,
    prefix: u8,
    payload: &[u8],
    value: &[u8],
    cap: usize,
) -> Result<(), DbError> {
    let dbi = txn
        .env()
        .dbis()
        .moderation
        .ok_or_else(|| DbError::msg("NIP-86 moderation database is unavailable"))?;
    let key = prefixed(prefix, payload);
    if txn.get(dbi, &key)?.is_none() && count_prefix(txn, dbi, prefix)? >= cap {
        return Err(DbError::msg("moderation record limit reached"));
    }
    txn.put(dbi, &key, value, 0)?;
    Ok(())
}

fn clear_record(txn: &mut RwTxn<'_>, prefix: u8, payload: &[u8]) -> Result<(), DbError> {
    let dbi = txn
        .env()
        .dbis()
        .moderation
        .ok_or_else(|| DbError::msg("NIP-86 moderation database is unavailable"))?;
    txn.del(dbi, &prefixed(prefix, payload), None)?;
    Ok(())
}

// --- Reads (usable on RoTxn and RwTxn) ---

pub fn banned_pubkey_reason_ro<T: ReadOps>(
    txn: &T,
    pubkey: &[u8; 32],
) -> Result<Option<String>, DbError> {
    get_reason(txn, PREFIX_BANNED_PUBKEY, pubkey)
}

pub fn allowed_pubkey_reason_ro<T: ReadOps>(
    txn: &T,
    pubkey: &[u8; 32],
) -> Result<Option<String>, DbError> {
    get_reason(txn, PREFIX_ALLOWED_PUBKEY, pubkey)
}

pub fn banned_event_reason_ro<T: ReadOps>(
    txn: &T,
    id: &[u8; 32],
) -> Result<Option<String>, DbError> {
    get_reason(txn, PREFIX_BANNED_EVENT, id)
}

pub fn blocked_ip_reason_ro<T: ReadOps>(txn: &T, ip: &str) -> Result<Option<String>, DbError> {
    get_reason(txn, PREFIX_BLOCKED_IP, ip.as_bytes())
}

pub fn pubkey_roles_ro<T: ReadOps>(txn: &T, pubkey: &[u8; 32]) -> Result<Vec<String>, DbError> {
    let Some(dbi) = txn.moderation_dbi() else {
        return Ok(Vec::new());
    };
    let Some(raw) = txn.get_record(dbi, &prefixed(PREFIX_PUBKEY_ROLES, pubkey))? else {
        return Ok(Vec::new());
    };
    Ok(serde_json::from_slice(&raw).unwrap_or_default())
}

/// Load the stored kind policy, if any.
pub fn kind_policy_ro<T: ReadOps>(txn: &T) -> Result<Option<KindPolicy>, DbError> {
    let Some(dbi) = txn.moderation_dbi() else {
        return Ok(None);
    };
    let Some(raw) = txn.get_record(dbi, &[PREFIX_KIND_POLICY])? else {
        return Ok(None);
    };
    let bits: [u8; KIND_POLICY_BYTES] = raw
        .try_into()
        .map_err(|_| DbError::msg("corrupt kind policy record"))?;
    Ok(Some(KindPolicy(Box::new(bits))))
}

/// True when the event id, its author, or its kind is moderated. Used by
/// query scans so moderated events disappear from REQ/COUNT results without
/// deletion.
pub fn is_event_moderated_ro(
    txn: &RoTxn<'_>,
    packed: PackedEventView<'_>,
) -> Result<bool, DbError> {
    let Some(dbi) = txn.env().dbis().moderation else {
        return Ok(false);
    };
    if txn
        .get(dbi, &prefixed(PREFIX_BANNED_EVENT, packed.id()))?
        .is_some()
    {
        return Ok(true);
    }
    if txn
        .get(dbi, &prefixed(PREFIX_BANNED_PUBKEY, packed.pubkey()))?
        .is_some()
    {
        return Ok(true);
    }
    if let Some(policy) = kind_policy_ro(txn)? {
        return Ok(!policy.allows(packed.kind()));
    }
    Ok(false)
}

pub fn load_moderation_snapshot_ro(txn: &RoTxn<'_>) -> Result<ModerationSnapshot, DbError> {
    let mut snap = ModerationSnapshot::default();
    let Some(dbi) = txn.env().dbis().moderation else {
        return Ok(snap);
    };
    let mut error = None;
    txn.foreach_full(dbi, &[], &[], false, |key, value| {
        let (prefix, payload) = match key.split_first() {
            Some(parts) => parts,
            None => return true,
        };
        match *prefix {
            PREFIX_BANNED_PUBKEY
            | PREFIX_ALLOWED_PUBKEY
            | PREFIX_BANNED_EVENT
            | PREFIX_REPORTED_EVENT
            | PREFIX_PUBKEY_ROLES
                if payload.len() == 32 =>
            {
                let mut id = [0u8; 32];
                id.copy_from_slice(payload);
                match *prefix {
                    PREFIX_BANNED_PUBKEY => {
                        snap.banned_pubkeys.insert(id, decode_reason(value));
                    }
                    PREFIX_ALLOWED_PUBKEY => {
                        snap.allowed_pubkeys.insert(id, decode_reason(value));
                    }
                    PREFIX_BANNED_EVENT => {
                        snap.banned_events.insert(id, decode_reason(value));
                    }
                    PREFIX_REPORTED_EVENT => {
                        snap.reported_events.insert(id, decode_reason(value));
                    }
                    _ => {
                        let roles: Vec<String> = serde_json::from_slice(value).unwrap_or_default();
                        snap.pubkey_roles.insert(id, roles);
                    }
                }
            }
            PREFIX_BLOCKED_IP => {
                if let Ok(ip) = std::str::from_utf8(payload) {
                    snap.blocked_ips
                        .insert(ip.to_string(), decode_reason(value));
                }
            }
            PREFIX_ROLE => match serde_json::from_slice::<Role>(value) {
                Ok(role) => {
                    snap.roles.insert(role.id.clone(), role);
                }
                Err(err) => {
                    error = Some(DbError::msg(format!("corrupt role record: {err}")));
                    return false;
                }
            },
            PREFIX_KIND_POLICY if payload.is_empty() => {
                let bits: Result<[u8; KIND_POLICY_BYTES], _> = value.try_into();
                match bits {
                    Ok(bits) => snap.kind_policy = Some(KindPolicy(Box::new(bits))),
                    Err(_) => {
                        error = Some(DbError::msg("corrupt kind policy record"));
                        return false;
                    }
                }
            }
            _ => {}
        }
        true
    })?;
    if let Some(error) = error {
        return Err(error);
    }
    Ok(snap)
}

// --- Mutations (RwTxn only) ---

pub fn ban_pubkey(txn: &mut RwTxn<'_>, pubkey: &[u8; 32], reason: &str) -> Result<(), DbError> {
    validate_reason(reason)?;
    put_record(
        txn,
        PREFIX_BANNED_PUBKEY,
        pubkey,
        reason.as_bytes(),
        MAX_MODERATION_RECORDS,
    )
}

pub fn unban_pubkey(txn: &mut RwTxn<'_>, pubkey: &[u8; 32]) -> Result<(), DbError> {
    clear_record(txn, PREFIX_BANNED_PUBKEY, pubkey)
}

pub fn allow_pubkey(txn: &mut RwTxn<'_>, pubkey: &[u8; 32], reason: &str) -> Result<(), DbError> {
    validate_reason(reason)?;
    put_record(
        txn,
        PREFIX_ALLOWED_PUBKEY,
        pubkey,
        reason.as_bytes(),
        MAX_MODERATION_RECORDS,
    )
}

pub fn unallow_pubkey(txn: &mut RwTxn<'_>, pubkey: &[u8; 32]) -> Result<(), DbError> {
    clear_record(txn, PREFIX_ALLOWED_PUBKEY, pubkey)
}

pub fn ban_event(txn: &mut RwTxn<'_>, id: &[u8; 32], reason: &str) -> Result<(), DbError> {
    validate_reason(reason)?;
    put_record(
        txn,
        PREFIX_BANNED_EVENT,
        id,
        reason.as_bytes(),
        MAX_MODERATION_RECORDS,
    )?;
    // A banned event no longer needs moderation.
    clear_record(txn, PREFIX_REPORTED_EVENT, id)
}

/// NIP-86 `allowevent`: lift a ban and clear any moderation queue entry.
pub fn allow_event(txn: &mut RwTxn<'_>, id: &[u8; 32]) -> Result<(), DbError> {
    clear_record(txn, PREFIX_BANNED_EVENT, id)?;
    clear_record(txn, PREFIX_REPORTED_EVENT, id)
}

fn store_kind_policy(txn: &mut RwTxn<'_>, policy: &KindPolicy) -> Result<(), DbError> {
    let dbi = txn
        .env()
        .dbis()
        .moderation
        .ok_or_else(|| DbError::msg("NIP-86 moderation database is unavailable"))?;
    txn.put(dbi, &[PREFIX_KIND_POLICY], policy.0.as_slice(), 0)?;
    Ok(())
}

/// NIP-86 `allowkind`. A no-op when no policy exists (every kind is already
/// allowed); otherwise sets the kind's bit in the stored map.
pub fn allow_kind(txn: &mut RwTxn<'_>, kind: u64) -> Result<(), DbError> {
    if kind > u16::MAX as u64 {
        return Err(DbError::msg("kind must be between 0 and 65535"));
    }
    let Some(mut policy) = kind_policy_ro(txn)? else {
        return Ok(());
    };
    policy.set_allowed(kind, true);
    store_kind_policy(txn, &policy)
}

/// NIP-86 `disallowkind`. With no stored policy this materializes the
/// allow-all map and clears the kind's bit, so one exclusion does not
/// enumerate 65,535 config entries. The all-zero map (no kinds allowed) is
/// representable and intentional.
pub fn disallow_kind(txn: &mut RwTxn<'_>, kind: u64) -> Result<(), DbError> {
    if kind > u16::MAX as u64 {
        return Err(DbError::msg("kind must be between 0 and 65535"));
    }
    let mut policy = kind_policy_ro(txn)?.unwrap_or_else(KindPolicy::allow_all);
    policy.set_allowed(kind, false);
    store_kind_policy(txn, &policy)
}

pub fn block_ip(txn: &mut RwTxn<'_>, ip: &str, reason: &str) -> Result<(), DbError> {
    let canonical = canonicalize_ip(ip)?;
    validate_reason(reason)?;
    put_record(
        txn,
        PREFIX_BLOCKED_IP,
        canonical.as_bytes(),
        reason.as_bytes(),
        MAX_MODERATION_RECORDS,
    )
}

pub fn unblock_ip(txn: &mut RwTxn<'_>, ip: &str) -> Result<(), DbError> {
    let canonical = canonicalize_ip(ip)?;
    clear_record(txn, PREFIX_BLOCKED_IP, canonical.as_bytes())
}

/// Record an event id as needing moderation (from a NIP-56 kind 1984 report).
pub fn report_event(txn: &mut RwTxn<'_>, id: &[u8; 32], reason: &str) -> Result<(), DbError> {
    validate_reason(reason)?;
    put_record(
        txn,
        PREFIX_REPORTED_EVENT,
        id,
        reason.as_bytes(),
        MAX_MODERATION_RECORDS,
    )
}

pub fn clear_reported_event(txn: &mut RwTxn<'_>, id: &[u8; 32]) -> Result<(), DbError> {
    clear_record(txn, PREFIX_REPORTED_EVENT, id)
}

pub fn put_role(txn: &mut RwTxn<'_>, role: &Role) -> Result<(), DbError> {
    validate_role_id(&role.id)?;
    for field in [&role.label, &role.description, &role.color] {
        if field.len() > MAX_ROLE_FIELD_BYTES {
            return Err(DbError::msg(format!(
                "role field exceeds {MAX_ROLE_FIELD_BYTES} bytes"
            )));
        }
    }
    let value = serde_json::to_vec(role).map_err(|e| DbError::msg(e.to_string()))?;
    put_record(txn, PREFIX_ROLE, role.id.as_bytes(), &value, MAX_ROLES)
}

/// Delete a role and strip it from every pubkey assignment.
pub fn delete_role(txn: &mut RwTxn<'_>, id: &str) -> Result<(), DbError> {
    validate_role_id(id)?;
    clear_record(txn, PREFIX_ROLE, id.as_bytes())?;
    let dbi = txn
        .env()
        .dbis()
        .moderation
        .ok_or_else(|| DbError::msg("NIP-86 moderation database is unavailable"))?;
    let mut affected: Vec<[u8; 32]> = Vec::new();
    txn.foreach_prefix(dbi, PREFIX_PUBKEY_ROLES, &mut |payload, value| {
        if payload.len() == 32 {
            let roles: Vec<String> = serde_json::from_slice(value).unwrap_or_default();
            if roles.iter().any(|role| role == id) {
                let mut pubkey = [0u8; 32];
                pubkey.copy_from_slice(payload);
                affected.push(pubkey);
            }
        }
        true
    })?;
    for pubkey in affected {
        let mut roles = pubkey_roles_ro(txn, &pubkey)?;
        roles.retain(|role| role != id);
        write_pubkey_roles(txn, &pubkey, &roles)?;
    }
    Ok(())
}

fn write_pubkey_roles(
    txn: &mut RwTxn<'_>,
    pubkey: &[u8; 32],
    roles: &[String],
) -> Result<(), DbError> {
    if roles.is_empty() {
        return clear_record(txn, PREFIX_PUBKEY_ROLES, pubkey);
    }
    let value = serde_json::to_vec(roles).map_err(|e| DbError::msg(e.to_string()))?;
    put_record(
        txn,
        PREFIX_PUBKEY_ROLES,
        pubkey,
        &value,
        MAX_MODERATION_RECORDS,
    )
}

pub fn assign_role(txn: &mut RwTxn<'_>, pubkey: &[u8; 32], role_id: &str) -> Result<(), DbError> {
    if !BUILTIN_ROLES.contains(&role_id) {
        let dbi = txn
            .env()
            .dbis()
            .moderation
            .ok_or_else(|| DbError::msg("NIP-86 moderation database is unavailable"))?;
        if txn
            .get(dbi, &prefixed(PREFIX_ROLE, role_id.as_bytes()))?
            .is_none()
        {
            return Err(DbError::msg(format!("unknown role {role_id:?}")));
        }
    }
    let mut roles = pubkey_roles_ro(txn, pubkey)?;
    if roles.iter().any(|role| role == role_id) {
        return Ok(());
    }
    if roles.len() >= MAX_ROLES_PER_PUBKEY {
        return Err(DbError::msg("role assignment limit reached"));
    }
    roles.push(role_id.to_string());
    write_pubkey_roles(txn, pubkey, &roles)
}

pub fn unassign_role(txn: &mut RwTxn<'_>, pubkey: &[u8; 32], role_id: &str) -> Result<(), DbError> {
    let mut roles = pubkey_roles_ro(txn, pubkey)?;
    roles.retain(|role| role != role_id);
    write_pubkey_roles(txn, pubkey, &roles)
}

// --- Listings for the management API ---

pub fn list_banned_pubkeys_ro(txn: &RoTxn<'_>) -> Result<Vec<([u8; 32], String)>, DbError> {
    list_binary_records(txn, PREFIX_BANNED_PUBKEY)
}

pub fn list_allowed_pubkeys_ro(txn: &RoTxn<'_>) -> Result<Vec<([u8; 32], String)>, DbError> {
    list_binary_records(txn, PREFIX_ALLOWED_PUBKEY)
}

pub fn list_banned_events_ro(txn: &RoTxn<'_>) -> Result<Vec<([u8; 32], String)>, DbError> {
    list_binary_records(txn, PREFIX_BANNED_EVENT)
}

pub fn list_reported_events_ro(txn: &RoTxn<'_>) -> Result<Vec<([u8; 32], String)>, DbError> {
    list_binary_records(txn, PREFIX_REPORTED_EVENT)
}

fn list_binary_records(txn: &RoTxn<'_>, prefix: u8) -> Result<Vec<([u8; 32], String)>, DbError> {
    let Some(dbi) = txn.env().dbis().moderation else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    txn.foreach_prefix(dbi, prefix, &mut |payload, value| {
        if payload.len() == 32 {
            let mut id = [0u8; 32];
            id.copy_from_slice(payload);
            out.push((id, decode_reason(value)));
        }
        true
    })?;
    Ok(out)
}

pub fn list_blocked_ips_ro(txn: &RoTxn<'_>) -> Result<Vec<(String, String)>, DbError> {
    let Some(dbi) = txn.env().dbis().moderation else {
        return Ok(Vec::new());
    };
    Ok(list_prefix(txn, dbi, PREFIX_BLOCKED_IP)?
        .into_iter()
        .filter_map(|(ip, reason)| String::from_utf8(ip).ok().map(|ip| (ip, reason)))
        .collect())
}

pub fn list_roles_ro(txn: &RoTxn<'_>) -> Result<Vec<Role>, DbError> {
    let Some(dbi) = txn.env().dbis().moderation else {
        return Ok(Vec::new());
    };
    let mut roles = Vec::new();
    let mut error = None;
    txn.foreach_prefix(dbi, PREFIX_ROLE, &mut |_, value| {
        match serde_json::from_slice::<Role>(value) {
            Ok(role) => roles.push(role),
            Err(err) => {
                error = Some(DbError::msg(format!("corrupt role record: {err}")));
                return false;
            }
        }
        true
    })?;
    if let Some(error) = error {
        return Err(error);
    }
    roles.sort_by_key(|role| role.order);
    Ok(roles)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Env, EnvOptions};

    fn test_env() -> (tempfile::TempDir, Env) {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::default()).unwrap();
        (dir, env)
    }

    #[test]
    fn ban_allow_block_report_roundtrip_and_snapshot() {
        let (_dir, env) = test_env();
        let pk = [7u8; 32];
        let id = [9u8; 32];
        let mut txn = env.begin_rw().unwrap();
        ban_pubkey(&mut txn, &pk, "spam").unwrap();
        allow_pubkey(&mut txn, &[8u8; 32], "").unwrap();
        ban_event(&mut txn, &id, "illegal").unwrap();
        block_ip(&mut txn, "203.0.113.7", "botnet").unwrap();
        report_event(&mut txn, &[4u8; 32], "reported by alice").unwrap();
        put_role(
            &mut txn,
            &Role {
                id: "vip".into(),
                label: "VIP".into(),
                description: "d".into(),
                color: "#fff".into(),
                order: 3,
            },
        )
        .unwrap();
        assign_role(&mut txn, &pk, "vip").unwrap();
        assign_role(&mut txn, &pk, BUILTIN_ROLE_MEMBER).unwrap();
        txn.commit().unwrap();

        let txn = env.begin_ro().unwrap();
        assert_eq!(
            banned_pubkey_reason_ro(&txn, &pk).unwrap().as_deref(),
            Some("spam")
        );
        assert_eq!(
            blocked_ip_reason_ro(&txn, "203.0.113.7")
                .unwrap()
                .as_deref(),
            Some("botnet")
        );
        assert_eq!(pubkey_roles_ro(&txn, &pk).unwrap(), vec!["vip", "member"]);
        let snap = load_moderation_snapshot_ro(&txn).unwrap();
        assert!(snap.banned_pubkeys.contains_key(&pk));
        assert!(snap.allowed_pubkeys.contains_key(&[8u8; 32]));
        assert!(snap.banned_events.contains_key(&id));
        assert!(snap.blocked_ips.contains_key("203.0.113.7"));
        assert!(snap.reported_events.contains_key(&[4u8; 32]));
        assert!(snap.roles.contains_key("vip"));
        assert!(snap.write_permitted(&pk));
        assert!(!snap.write_permitted(&[1u8; 32]));
        drop(txn);

        // Unban / delete-role paths.
        let mut txn = env.begin_rw().unwrap();
        unban_pubkey(&mut txn, &pk).unwrap();
        delete_role(&mut txn, "vip").unwrap();
        txn.commit().unwrap();
        let txn = env.begin_ro().unwrap();
        assert!(banned_pubkey_reason_ro(&txn, &pk).unwrap().is_none());
        assert_eq!(pubkey_roles_ro(&txn, &pk).unwrap(), vec!["member"]);
    }

    #[test]
    fn visibility_check_marks_banned_events_and_authors() {
        let (_dir, env) = test_env();
        let pk = [1u8; 32];
        let id = [2u8; 32];
        let mut txn = env.begin_rw().unwrap();
        ban_pubkey(&mut txn, &pk, "").unwrap();
        ban_event(&mut txn, &id, "").unwrap();
        txn.commit().unwrap();

        let txn = env.begin_ro().unwrap();
        let tags = wok_event::PackedEventTagBuilder::default();
        let by_banned_author =
            wok_event::PackedEventBuilder::build(&[3u8; 32], &pk, 1, 1, 0, &tags).unwrap();
        let banned_id =
            wok_event::PackedEventBuilder::build(&id, &[5u8; 32], 1, 1, 0, &tags).unwrap();
        let clean =
            wok_event::PackedEventBuilder::build(&[6u8; 32], &[5u8; 32], 1, 1, 0, &tags).unwrap();
        assert!(is_event_moderated_ro(&txn, by_banned_author.view()).unwrap());
        assert!(is_event_moderated_ro(&txn, banned_id.view()).unwrap());
        assert!(!is_event_moderated_ro(&txn, clean.view()).unwrap());
    }

    #[test]
    fn reserved_role_ids_and_caps_are_enforced() {
        let (_dir, env) = test_env();
        let mut txn = env.begin_rw().unwrap();
        assert!(put_role(
            &mut txn,
            &Role {
                id: BUILTIN_ROLE_ADMIN.into(),
                label: String::new(),
                description: String::new(),
                color: String::new(),
                order: 0,
            },
        )
        .is_err());
        assert!(assign_role(&mut txn, &[1u8; 32], "nonexistent").is_err());
        let long = "x".repeat(MAX_REASON_BYTES + 1);
        assert!(ban_pubkey(&mut txn, &[1u8; 32], &long).is_err());
        txn.abort();
    }

    #[test]
    fn blocked_ips_are_canonicalized_at_storage() {
        let (_dir, env) = test_env();
        let mut txn = env.begin_rw().unwrap();
        // Non-canonical input is stored in the canonical form admission uses.
        block_ip(&mut txn, "2001:0db8:0000::0001", "botnet").unwrap();
        assert!(block_ip(&mut txn, "not-an-ip", "").is_err());
        txn.commit().unwrap();

        let txn = env.begin_ro().unwrap();
        assert_eq!(
            blocked_ip_reason_ro(&txn, "2001:db8::1")
                .unwrap()
                .as_deref(),
            Some("botnet")
        );
        assert!(blocked_ip_reason_ro(&txn, "2001:0db8:0000::0001")
            .unwrap()
            .is_none());
        drop(txn);

        // Unblock also canonicalizes its input.
        let mut txn = env.begin_rw().unwrap();
        unblock_ip(&mut txn, "2001:0DB8::1").unwrap();
        txn.commit().unwrap();
        let txn = env.begin_ro().unwrap();
        assert!(blocked_ip_reason_ro(&txn, "2001:db8::1").unwrap().is_none());
    }

    #[test]
    fn kind_policy_gates_visibility_and_roundtrips() {
        let (_dir, env) = test_env();
        let tags = wok_event::PackedEventTagBuilder::default();
        let kind1 =
            wok_event::PackedEventBuilder::build(&[1u8; 32], &[2u8; 32], 1, 1, 0, &tags).unwrap();
        let kind2 =
            wok_event::PackedEventBuilder::build(&[3u8; 32], &[2u8; 32], 1, 2, 0, &tags).unwrap();

        // No policy: everything allowed.
        let txn = env.begin_ro().unwrap();
        assert!(kind_policy_ro(&txn).unwrap().is_none());
        assert!(!is_event_moderated_ro(&txn, kind1.view()).unwrap());
        drop(txn);

        // disallowkind from the default materializes the map with one bit off.
        let mut txn = env.begin_rw().unwrap();
        disallow_kind(&mut txn, 1).unwrap();
        txn.commit().unwrap();
        let txn = env.begin_ro().unwrap();
        let policy = kind_policy_ro(&txn).unwrap().unwrap();
        assert!(!policy.allows(1));
        assert!(policy.allows(2));
        assert!(is_event_moderated_ro(&txn, kind1.view()).unwrap());
        assert!(!is_event_moderated_ro(&txn, kind2.view()).unwrap());
        drop(txn);

        // allowkind restores the kind; the map itself persists.
        let mut txn = env.begin_rw().unwrap();
        allow_kind(&mut txn, 1).unwrap();
        txn.commit().unwrap();
        let txn = env.begin_ro().unwrap();
        assert!(!is_event_moderated_ro(&txn, kind1.view()).unwrap());
        drop(txn);

        // The all-zero map (no kinds allowed) is representable.
        let mut txn = env.begin_rw().unwrap();
        for kind in 0..=u16::MAX as u64 {
            disallow_kind(&mut txn, kind).unwrap();
        }
        txn.commit().unwrap();
        let txn = env.begin_ro().unwrap();
        let policy = kind_policy_ro(&txn).unwrap().unwrap();
        assert!(policy.allowed_kinds().is_empty());
        assert!(is_event_moderated_ro(&txn, kind2.view()).unwrap());
    }

    #[test]
    fn snapshot_carries_kind_policy() {
        let (_dir, env) = test_env();
        let mut txn = env.begin_rw().unwrap();
        disallow_kind(&mut txn, 7).unwrap();
        txn.commit().unwrap();
        let txn = env.begin_ro().unwrap();
        let snap = load_moderation_snapshot_ro(&txn).unwrap();
        assert!(!snap.kind_allowed(7));
        assert!(snap.kind_allowed(8));
    }
}
