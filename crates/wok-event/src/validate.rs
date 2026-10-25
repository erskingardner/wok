use std::borrow::Cow;
use std::collections::HashSet;

use serde_json::Value;

use crate::hash::{verify_id, verify_id_allowing_legacy, verify_sig};
use crate::packed::PackedEventView;
use crate::parse::{
    from_hex_exact, from_lower_hex_array, normalize_event_json, pack_event, parse_uint64, to_hex,
    EventLimits, ParsedEvent,
};
use crate::{
    indexed_tag_value, is_ephemeral_kind, is_param_replaceable_kind, is_replaceable_kind,
    parse_canonical_a_tag, EventError, EventLimit, DELETION_KIND, MAX_INDEXED_TAG_VAL_SIZE,
};

// Re-export helper used by validate; keep json_get_string crate-private in parse
// by duplicating the small accessor here for sig field.

fn json_string<'a>(v: &'a Value, err: &str) -> Result<&'a str, EventError> {
    v.as_str().ok_or_else(|| EventError::msg(err.to_string()))
}

/// Which event id preimages verification accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdPreimage {
    /// NIP-01 only. For events published to this relay.
    Nip01,
    /// NIP-01, or the legacy tao preimage that strfry and earlier Wok
    /// releases hashed (U+007F escaped). Only for events a relay has already
    /// stored: imports, sync and router downloads.
    Nip01OrLegacy,
}

/// NIP-42 suggests relays accept AUTH events whose `created_at` is within
/// about ten minutes of their clock, in either direction.
pub const AUTH_TIMESTAMP_WINDOW_SECS: u64 = 600;

/// How long before publication a kind 21059 ephemeral gift wrap may be dated.
/// NIP-59 backdates wraps by up to two days; the third day is slack.
pub const GIFT_WRAP_BACKDATE_SECS: u64 = 3 * 86_400;

#[derive(Debug, Clone)]
pub struct TimestampPolicy {
    pub now_secs: u64,
    pub reject_newer_than_secs: u64,
    /// Oldest a non-ephemeral event may be; 0 means no lower bound.
    pub reject_older_than_secs: u64,
    pub reject_ephemeral_older_than_secs: u64,
}

impl TimestampPolicy {
    pub fn from_now(
        reject_newer_than_secs: u64,
        reject_older_than_secs: u64,
        reject_ephemeral_older_than_secs: u64,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            now_secs: now,
            reject_newer_than_secs,
            reject_older_than_secs,
            reject_ephemeral_older_than_secs,
        }
    }
}

pub fn verify_nostr_event(packed: PackedEventView<'_>, orig: &Value) -> Result<(), EventError> {
    verify_nostr_event_with(packed, orig, IdPreimage::Nip01)
}

fn verify_nostr_event_with(
    packed: PackedEventView<'_>,
    orig: &Value,
    ids: IdPreimage,
) -> Result<(), EventError> {
    match ids {
        IdPreimage::Nip01 => verify_id(orig, packed.id())?,
        IdPreimage::Nip01OrLegacy => verify_id_allowing_legacy(orig, packed.id())?,
    }
    let sig_hex = json_string(
        orig.get("sig")
            .ok_or_else(|| EventError::msg("missing sig"))?,
        "event sig was not a string",
    )?;
    if sig_hex.len() != 128 {
        return Err(EventError::msg("unexpected signature size"));
    }
    let sig = from_lower_hex_array::<64>(sig_hex)?;
    let valid = verify_sig(&sig, packed.id(), packed.pubkey())?;
    if !valid {
        return Err(EventError::msg("bad signature"));
    }
    Ok(())
}

/// Verify an event a strfry v3 database stores: the payload `orig` must name
/// the id, pubkey, kind and created_at of its PackedEvent `packed`, which
/// must index nothing the payload does not carry ([`check_packed_tags`]).
/// The payload must hash to that id with either preimage
/// ([`IdPreimage::Nip01OrLegacy`]) and carry a valid signature by that
/// pubkey. Hex is decoded as strfry decoded it on ingest, in either case and
/// with an optional `0x`, and no limit strfry's config set is applied, so
/// every event strfry verified and packed passes.
pub fn verify_strfry_event(packed: PackedEventView<'_>, orig: &Value) -> Result<(), EventError> {
    let field = |key: &str| {
        orig.get(key)
            .ok_or_else(|| EventError::msg(format!("missing {key}")))
    };
    let bytes = |key: &str, len: usize| -> Result<Vec<u8>, EventError> {
        let decoded = from_hex_exact(json_string(
            field(key)?,
            &format!("event {key} was not a string"),
        )?)?;
        if decoded.len() != len {
            return Err(EventError::msg(format!("unexpected {key} size")));
        }
        Ok(decoded)
    };
    let unsigned = |key: &str| {
        field(key)?
            .as_u64()
            .ok_or_else(|| EventError::msg(format!("event {key} was not an integer")))
    };
    if bytes("id", 32)? != packed.id() {
        return Err(EventError::msg("payload id differs from the packed record"));
    }
    if bytes("pubkey", 32)? != packed.pubkey() {
        return Err(EventError::msg(
            "payload pubkey differs from the packed record",
        ));
    }
    if unsigned("kind")? != packed.kind() {
        return Err(EventError::msg(
            "payload kind differs from the packed record",
        ));
    }
    if unsigned("created_at")? != packed.created_at() {
        return Err(EventError::msg(
            "payload created_at differs from the packed record",
        ));
    }
    check_packed_tags(packed, orig)?;
    verify_id_allowing_legacy(orig, packed.id())?;
    if !verify_sig(&bytes("sig", 64)?, packed.id(), packed.pubkey())? {
        return Err(EventError::msg("bad signature"));
    }
    Ok(())
}

/// Check that PackedEvent `packed` indexes, replaces, deletes and expires by
/// nothing its payload `orig` does not carry, as strfry's database version 3
/// packs a payload (052c56e through the pinned 9acdaeb):
///
/// - Every packed tag is a single-letter payload tag: `e` and `p` values as
///   the bytes their 64 hex characters decode to (either case, after an
///   optional `0x`), others as written up to 255 bytes, or longer ones as
///   [`indexed_tag_value`] hashes them. The exception is the empty `d`
///   strfry adds to kinds 0, 3, 41, 10000-19999 and 30000-39999. A payload
///   tag may be left out, as strfry left out values longer than 255 bytes.
/// - The first packed `d`, which keys replacement, is the payload's address:
///   empty for replaceable kinds, and for addressable kinds the first `d`,
///   hashed when long. strfry skipped a long one, so then the next `d` of up
///   to 255 bytes, or empty, is accepted too.
/// - The first 32-byte packed `p`, the only one recipient-only reads admit,
///   is the payload's first `p` that decodes to 32 bytes, or neither has one.
/// - The expiration is what strfry wrote: 1 for ephemeral kinds, otherwise
///   the payload's first `expiration` tag, or 0 when it has none. strfry
///   refused an event whose first `expiration` tag is not a time of at least
///   100, so such a payload is refused too: 0 and 1 are the markers for no
///   expiry and for an ephemeral event.
fn check_packed_tags(packed: PackedEventView<'_>, orig: &Value) -> Result<(), EventError> {
    let kind = packed.kind();
    let mut carried = HashSet::new();
    // The first `d` as Wok packs it, and as strfry did.
    let (mut address, mut strfry_address) = (None, None);
    let mut recipient = None;
    let tags = orig.get("tags").and_then(Value::as_array);
    for tag in tags.into_iter().flatten().filter_map(Value::as_array) {
        let Some(name) = tag.first().and_then(Value::as_str) else {
            continue;
        };
        let value = match tag.get(1) {
            Some(value) => match value.as_str() {
                Some(value) => value,
                None => continue,
            },
            None => "",
        };
        // One byte, as packed: a one-character name like `é` is not.
        let &[name] = name.as_bytes() else {
            continue;
        };
        let name = name as char;
        let packed_value = if name == 'e' || name == 'p' {
            if value.len() != 64 {
                continue;
            }
            let Ok(raw) = from_hex_exact(value) else {
                continue;
            };
            Cow::Owned(raw)
        } else {
            indexed_tag_value(value.as_bytes())
        };
        if name == 'p' && packed_value.len() == 32 && recipient.is_none() {
            recipient = Some(packed_value.clone());
        }
        if name == 'd' {
            address.get_or_insert_with(|| packed_value.clone());
            if strfry_address.is_none() && value.len() <= MAX_INDEXED_TAG_VAL_SIZE {
                strfry_address = Some(packed_value.clone());
            }
        }
        carried.insert((name, packed_value));
    }

    let virtual_d = kind == 41 || is_replaceable_kind(kind) || is_param_replaceable_kind(kind);
    let (mut first_d, mut first_p) = (None, None);
    let mut stray = None;
    packed.foreach_tag(|name, value| {
        if name == 'd' && first_d.is_none() {
            first_d = Some(value.to_vec());
        }
        if name == 'p' && value.len() == 32 && first_p.is_none() {
            first_p = Some(value.to_vec());
        }
        if (name == 'd' && value.is_empty() && virtual_d)
            || carried.contains(&(name, Cow::Borrowed(value)))
        {
            return true;
        }
        stray = Some(if name == 'e' || name == 'p' {
            format!("packed {name} tag {} is not in the payload", to_hex(value))
        } else {
            format!(
                "packed {name} tag {:?} is not in the payload",
                String::from_utf8_lossy(value)
            )
        });
        false
    });
    if let Some(stray) = stray {
        return Err(EventError::msg(stray));
    }

    if first_p.as_deref() != recipient.as_deref() {
        let shown = |p: Option<&[u8]>| p.map_or("none".into(), to_hex);
        return Err(EventError::msg(format!(
            "packed recipient {} differs from the payload's {}",
            shown(first_p.as_deref()),
            shown(recipient.as_deref()),
        )));
    }

    let empty = Cow::Borrowed(&b""[..]);
    let addresses = if is_replaceable_kind(kind) {
        Some((empty.clone(), empty))
    } else if is_param_replaceable_kind(kind) {
        Some((
            strfry_address.unwrap_or_else(|| empty.clone()),
            address.unwrap_or(empty),
        ))
    } else {
        None
    };
    if let Some((strfry, wok)) = addresses {
        let first_d = first_d.as_deref();
        if first_d != Some(&strfry[..]) && first_d != Some(&wok[..]) {
            let shown = |d: Option<&[u8]>| {
                d.map_or("none".into(), |d| {
                    format!("{:?}", String::from_utf8_lossy(d))
                })
            };
            return Err(EventError::msg(format!(
                "packed address {} differs from the payload's {}",
                shown(first_d),
                shown(Some(&strfry)),
            )));
        }
    }

    let own = strfry_expiration(orig)?;
    let expected = if is_ephemeral_kind(kind) {
        1
    } else {
        own.unwrap_or(0)
    };
    if packed.expiration() != expected {
        return Err(EventError::msg(format!(
            "packed expiration {} differs from the {expected} strfry packs from the payload",
            packed.expiration()
        )));
    }
    Ok(())
}

/// The time in `orig`'s first `expiration` tag, as strfry's packer read it:
/// none without one, and an error for one it refused, which is not digits or
/// below 100.
fn strfry_expiration(orig: &Value) -> Result<Option<u64>, EventError> {
    let tags = orig.get("tags").and_then(Value::as_array);
    let Some(tag) = tags
        .into_iter()
        .flatten()
        .filter_map(Value::as_array)
        .find(|tag| tag.first().and_then(Value::as_str) == Some("expiration"))
    else {
        return Ok(None);
    };
    let value = match tag.get(1) {
        Some(value) => value.as_str(),
        None => Some(""),
    };
    match value.map(|value| (value, parse_uint64(value))) {
        Some((_, Ok(expiration))) if expiration >= 100 => Ok(Some(expiration)),
        Some((value, _)) => Err(EventError::msg(format!(
            "payload expiration {value:?} is not a time strfry packs"
        ))),
        None => Err(EventError::msg("payload expiration is not a string")),
    }
}

pub fn verify_event_json_size(json_str: &str, max_event_size: usize) -> Result<(), EventError> {
    if json_str.len() > max_event_size {
        return Err(EventError::limit(
            EventLimit::EventSize,
            format!("event too large: {}", json_str.len()),
        ));
    }
    Ok(())
}

pub fn verify_event_timestamp(
    packed: PackedEventView<'_>,
    policy: &TimestampPolicy,
) -> Result<(), EventError> {
    let now = policy.now_secs;
    let ts = packed.created_at();
    let is_ephemeral = packed.expiration() == 1;

    let max_age = if is_ephemeral {
        policy.reject_ephemeral_older_than_secs
    } else if policy.reject_older_than_secs == 0 {
        u64::MAX
    } else {
        policy.reject_older_than_secs
    };
    let mut earliest = now.saturating_sub(max_age);
    let mut latest = now.saturating_add(policy.reject_newer_than_secs);

    // Match C++ overflow handling.
    if earliest > now {
        earliest = 0;
    }
    if latest < now {
        latest = u64::MAX - 1;
    }

    if ts < earliest {
        return Err(if is_ephemeral {
            EventError::limit(EventLimit::EphemeralTooOld, "ephemeral event expired")
        } else {
            EventError::limit(EventLimit::TooOld, "created_at too early")
        });
    }
    if ts > latest {
        return Err(EventError::limit(EventLimit::TooNew, "created_at too late"));
    }
    if packed.expiration() > 1 && packed.expiration() <= now {
        return Err(EventError::msg("event expired"));
    }
    Ok(())
}

/// Refuse a deletion, the event JSON `orig`, whose `a` tag spells its kind
/// with leading zeros. Wok tombstones an address by the hash of the tag, and
/// looks it up by the canonical spelling. Packing accepts such tags, which
/// strfry and earlier releases stored; every path that stores new events
/// must call this, as [`parse_and_verify_event_with`] does.
pub fn require_canonical_addresses(orig: &Value) -> Result<(), EventError> {
    let tags = orig
        .get("tags")
        .and_then(Value::as_array)
        .into_iter()
        .flatten();
    for tag in tags.filter_map(Value::as_array) {
        if tag.first().and_then(Value::as_str) == Some("a") {
            if let Some(address) = tag.get(1).and_then(Value::as_str) {
                parse_canonical_a_tag(address)?;
            }
        }
    }
    Ok(())
}

/// Parse and verify an event published to this relay. Its id must use the
/// NIP-01 preimage.
pub fn parse_and_verify_event(
    orig: &Value,
    limits: &EventLimits,
    policy: Option<&TimestampPolicy>,
    verify_msg: bool,
    verify_time: bool,
) -> Result<ParsedEvent, EventError> {
    parse_and_verify_event_with(
        orig,
        limits,
        policy,
        verify_msg,
        verify_time,
        IdPreimage::Nip01,
    )
}

/// `parse_and_verify_event` with a choice of accepted id preimages.
pub fn parse_and_verify_event_with(
    orig: &Value,
    limits: &EventLimits,
    policy: Option<&TimestampPolicy>,
    verify_msg: bool,
    verify_time: bool,
    ids: IdPreimage,
) -> Result<ParsedEvent, EventError> {
    if !orig.is_object() {
        return Err(EventError::msg("event is not an object"));
    }
    let (packed, expiration) = pack_event(orig, limits)?;
    if packed.view().kind() == DELETION_KIND {
        require_canonical_addresses(orig)?;
    }
    let json = normalize_event_json(orig)?;
    if verify_msg {
        // Reject oversized events before hashing their content or performing
        // Schnorr verification. Transport limits bound the preceding JSON
        // parse and structural conversion.
        verify_event_json_size(&json, limits.max_event_size)?;
    }
    if verify_time {
        let p = policy.ok_or_else(|| EventError::msg("timestamp policy required"))?;
        verify_event_timestamp(packed.view(), p)?;
        // NIP-40: an ephemeral event packs the ephemeral marker instead of
        // its expiration, which the packed check above cannot see.
        if expiration != 0 && expiration <= p.now_secs {
            return Err(EventError::msg("event expired"));
        }
    }
    if verify_msg {
        verify_nostr_event_with(packed.view(), orig, ids)?;
    }
    Ok(ParsedEvent { packed, json })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packed::{PackedEvent, PackedEventBuilder};
    use crate::{indexed_tag_value, PackedEventTagBuilder, MAX_INDEXED_TAG_VAL_SIZE};
    use secp256k1::{Keypair, SECP256K1};
    use serde_json::json;

    fn sign_event(mut ev: Value) -> Value {
        let mut rng = rand::thread_rng();
        let kp = Keypair::new(SECP256K1, &mut rng);
        let (xonly, _) = kp.x_only_public_key();
        ev["pubkey"] = json!(hex::encode(xonly.serialize()));
        let id = crate::event_id_hash(&ev).unwrap();
        ev["id"] = json!(hex::encode(id));
        let sig = SECP256K1.sign_schnorr(&id, &kp);
        ev["sig"] = json!(hex::encode(sig.as_ref()));
        ev
    }

    #[test]
    fn deletion_a_tags_need_canonical_kinds_at_ingest() {
        let pubkey = "22".repeat(32);
        let event = |kind: u64, address: String| {
            json!({
                "id": "11".repeat(32),
                "pubkey": pubkey,
                "created_at": 1,
                "kind": kind,
                "content": "",
                "tags": [["a", address]],
                "sig": "00".repeat(64),
            })
        };
        let limits = EventLimits::default();
        let ingest = |event: &Value| parse_and_verify_event(event, &limits, None, false, false);
        for address in [format!("0:{pubkey}:"), format!("30000:{pubkey}:d")] {
            ingest(&event(5, address)).unwrap();
        }
        for address in [format!("00:{pubkey}:"), format!("030000:{pubkey}:d")] {
            let deletion = event(5, address);
            let error = ingest(&deletion).unwrap_err();
            assert_eq!(error.to_string(), "a tag kind has leading zeros");
            // strfry and earlier releases stored such requests; reindex packs
            // them again.
            crate::nostr_json_to_packed_event(&deletion, &limits).unwrap();
        }
        // Other events may reference an address however they spell it.
        ingest(&event(1, format!("030000:{pubkey}:d"))).unwrap();
    }

    #[test]
    fn valid_signed_event() {
        let ev = sign_event(json!({
            "created_at": 1_700_000_000u64,
            "kind": 1,
            "tags": [],
            "content": "hi",
        }));
        let parsed =
            parse_and_verify_event(&ev, &EventLimits::default(), None, true, false).unwrap();
        assert_eq!(parsed.packed.view().kind(), 1);
        assert!(parsed.json.contains("\"content\":\"hi\""));
    }

    #[test]
    fn rejects_bad_id() {
        let mut ev = sign_event(json!({
            "created_at": 1,
            "kind": 1,
            "tags": [],
            "content": "hi",
        }));
        ev["id"] = json!("11".repeat(32));
        assert!(parse_and_verify_event(&ev, &EventLimits::default(), None, true, false).is_err());
    }

    #[test]
    fn stored_events_verify_against_their_packed_record() {
        let ev = sign_event(json!({
            "created_at": 1_700_000_000u64,
            "kind": 1,
            "tags": [["p", "22".repeat(32)]],
            "content": "stored",
        }));
        let packed = crate::nostr_json_to_packed_event(&ev, &EventLimits::default()).unwrap();
        verify_strfry_event(packed.view(), &ev).unwrap();

        let refused = |key: &str, value: Value| {
            let mut changed = ev.clone();
            changed[key] = value;
            verify_strfry_event(packed.view(), &changed)
                .unwrap_err()
                .to_string()
        };
        let other = || hex::encode([0x33; 32]);
        assert_eq!(
            refused("id", json!(other())),
            "payload id differs from the packed record"
        );
        assert_eq!(
            refused("pubkey", json!(other())),
            "payload pubkey differs from the packed record"
        );
        assert_eq!(
            refused("kind", json!(7)),
            "payload kind differs from the packed record"
        );
        assert_eq!(
            refused("created_at", json!(1)),
            "payload created_at differs from the packed record"
        );
        assert_eq!(refused("content", json!("edited")), "bad event id");
        assert_eq!(
            refused("tags", json!([])),
            format!("packed p tag {} is not in the payload", "22".repeat(32))
        );
        assert_eq!(
            refused(
                "tags",
                json!([["p", "22".repeat(32)], ["client", "edited"]])
            ),
            "bad event id"
        );
        let mut sig = ev["sig"].as_str().unwrap().to_owned();
        sig.replace_range(..2, if sig.starts_with("00") { "01" } else { "00" });
        assert_eq!(refused("sig", json!(sig)), "bad signature");
        assert_eq!(
            refused("sig", json!("00".repeat(32))),
            "unexpected sig size"
        );
        assert_eq!(refused("kind", json!("1")), "event kind was not an integer");
        let mut missing = ev.clone();
        missing.as_object_mut().unwrap().remove("sig");
        assert_eq!(
            verify_strfry_event(packed.view(), &missing)
                .unwrap_err()
                .to_string(),
            "missing sig"
        );
    }

    #[test]
    fn stored_events_accept_the_legacy_preimage() {
        // strfry hashed U+007F escaped; NIP-01 writes it verbatim.
        let mut rng = rand::thread_rng();
        let kp = Keypair::new(SECP256K1, &mut rng);
        let mut ev = json!({
            "created_at": 1_700_000_000u64,
            "kind": 1,
            "tags": [],
            "content": "del \u{7f}",
            "pubkey": hex::encode(kp.x_only_public_key().0.serialize()),
        });
        let id = crate::legacy_event_id_hash(&ev).unwrap();
        assert_ne!(id, crate::event_id_hash(&ev).unwrap());
        ev["id"] = json!(hex::encode(id));
        ev["sig"] = json!(hex::encode(SECP256K1.sign_schnorr(&id, &kp).as_ref()));
        let packed = crate::nostr_json_to_packed_event(&ev, &EventLimits::default()).unwrap();
        verify_strfry_event(packed.view(), &ev).unwrap();
        assert!(verify_nostr_event(packed.view(), &ev).is_err());
    }

    #[test]
    fn stored_events_accept_hex_as_strfry_decoded_it() {
        // strfry decoded hex in either case, after an optional `0x`, and
        // stored the JSON as sent. The id hashes the pubkey as written.
        let mut rng = rand::thread_rng();
        let kp = Keypair::new(SECP256K1, &mut rng);
        let pubkey = kp.x_only_public_key().0.serialize();
        let mut ev = json!({
            "created_at": 1_700_000_000u64,
            "kind": 1,
            "tags": [],
            "content": "upper",
            "pubkey": hex::encode_upper(pubkey),
        });
        let id = crate::event_id_hash(&ev).unwrap();
        ev["id"] = json!(format!("0x{}", hex::encode_upper(id)));
        ev["sig"] = json!(hex::encode_upper(SECP256K1.sign_schnorr(&id, &kp).as_ref()));
        let tags = PackedEventTagBuilder::default();
        let packed = PackedEventBuilder::build(&id, &pubkey, 1_700_000_000, 1, 0, &tags).unwrap();
        verify_strfry_event(packed.view(), &ev).unwrap();
        // Lowercasing the pubkey changes the preimage.
        ev["pubkey"] = json!(hex::encode(pubkey));
        assert_eq!(
            verify_strfry_event(packed.view(), &ev)
                .unwrap_err()
                .to_string(),
            "bad event id"
        );
    }

    /// The record strfry stores for `ev`, with these tags and expiration.
    fn strfry_record(ev: &Value, expiration: u64, tags: &[(char, &[u8])]) -> PackedEvent {
        let mut builder = PackedEventTagBuilder::default();
        for (name, value) in tags {
            builder.add(*name, value).unwrap();
        }
        let hex = |key: &str| from_hex_exact(ev[key].as_str().unwrap()).unwrap();
        PackedEventBuilder::build(
            &hex("id"),
            &hex("pubkey"),
            ev["created_at"].as_u64().unwrap(),
            ev["kind"].as_u64().unwrap(),
            expiration,
            &builder,
        )
        .unwrap()
    }

    #[test]
    fn stored_events_index_only_what_their_payload_carries() {
        let long = "z".repeat(MAX_INDEXED_TAG_VAL_SIZE + 1);
        let (p, e) = ([0x22; 32], [0xab; 32]);
        let ev = sign_event(json!({
            "created_at": 1_700_000_000u64,
            "kind": 1,
            "tags": [
                ["p", hex::encode(p), "wss://relay.example"],
                ["e", hex::encode_upper(e)],
                ["t", long],
                ["t"],
                ["client", "wok"],
                ["expiration", "0200"],
                ["expiration", "300"],
            ],
            "content": "tagged",
        }));
        let packed = |expiration, tags: &[(char, &[u8])]| strfry_record(&ev, expiration, tags);
        let verify = |expiration, tags: &[(char, &[u8])]| {
            verify_strfry_event(packed(expiration, tags).view(), &ev).map_err(|e| e.to_string())
        };
        // As strfry packed it: e and p decoded in either case, the long
        // value dropped, the first expiration.
        verify(200, &[('p', &p), ('e', &e), ('t', b"")]).unwrap();
        // Tags left out, or in another order.
        verify(200, &[('t', b""), ('p', &p)]).unwrap();

        let forged = [0x33; 32];
        let stray = |tags: &[(char, &[u8])], error: String| {
            assert_eq!(verify(200, tags).unwrap_err(), error);
        };
        // Another recipient for recipient-only reads, another deletion target.
        stray(
            &[('p', &forged)],
            format!("packed p tag {} is not in the payload", "33".repeat(32)),
        );
        stray(
            &[('p', &p), ('e', &forged)],
            format!("packed e tag {} is not in the payload", "33".repeat(32)),
        );
        // A value the payload does not carry.
        stray(
            &[('p', &p), ('t', b"wok")],
            r#"packed t tag "wok" is not in the payload"#.into(),
        );
        // A long value as Wok's ingest packs it, hashed, but not another's
        // hash.
        verify(
            200,
            &[('p', &p), ('t', &indexed_tag_value(long.as_bytes()))],
        )
        .unwrap();
        let other = indexed_tag_value(&[b'z'; MAX_INDEXED_TAG_VAL_SIZE + 2]).into_owned();
        assert!(verify(200, &[('t', &other)])
            .unwrap_err()
            .starts_with("packed t tag "));
        // A multi-letter tag is not indexed.
        stray(
            &[('c', b"wok")],
            r#"packed c tag "wok" is not in the payload"#.into(),
        );

        // The expiration strfry packed and no other: clearing it would keep
        // an expired event served.
        for expiration in [0, 1, 300] {
            assert_eq!(
                verify(expiration, &[('p', &p)]).unwrap_err(),
                format!(
                    "packed expiration {expiration} differs from the 200 strfry packs from the payload"
                )
            );
        }
        let mut plain = ev.clone();
        plain["tags"] = json!([]);
        let plain = sign_event(plain);
        assert_eq!(
            verify_strfry_event(strfry_record(&plain, 1_700_000_100, &[]).view(), &plain)
                .unwrap_err()
                .to_string(),
            "packed expiration 1700000100 differs from the 0 strfry packs from the payload"
        );
    }

    #[test]
    fn stored_events_whose_expiration_strfry_refused_are_refused() {
        // 0 and 1 mean no expiry and ephemeral to Wok, so a payload whose
        // first expiration is not a time strfry packed must not verify with
        // either.
        for (kind, tags, value) in [
            (1, json!([["expiration", "0"]]), r#""0""#),
            (1, json!([["expiration", "1"]]), r#""1""#),
            (1, json!([["expiration", "99"]]), r#""99""#),
            (
                1,
                json!([["expiration", "soon"], ["expiration", "1700000100"]]),
                r#""soon""#,
            ),
            (1, json!([["expiration"]]), r#""""#),
            (20001, json!([["expiration", "0"]]), r#""0""#),
        ] {
            let ev = sign_event(json!({
                "created_at": 1_700_000_000u64,
                "kind": kind,
                "tags": tags,
                "content": "",
            }));
            for expiration in [0, 1, 1_700_000_100] {
                assert_eq!(
                    verify_strfry_event(strfry_record(&ev, expiration, &[]).view(), &ev)
                        .unwrap_err()
                        .to_string(),
                    format!("payload expiration {value} is not a time strfry packs"),
                    "{tags} packed with {expiration}"
                );
            }
        }
        let ev = sign_event(json!({
            "created_at": 1_700_000_000u64,
            "kind": 1,
            "tags": [["expiration", 5]],
            "content": "",
        }));
        assert_eq!(
            verify_strfry_event(strfry_record(&ev, 0, &[]).view(), &ev)
                .unwrap_err()
                .to_string(),
            "payload expiration is not a string"
        );
    }

    #[test]
    fn stored_events_keep_their_first_recipient() {
        // Recipient-only reads admit the first 32-byte packed p.
        let (a, b) = ([0xaa; 32], [0xbb; 32]);
        let ev = sign_event(json!({
            "created_at": 1_700_000_000u64,
            "kind": 4,
            "tags": [
                ["p", format!("0x{}", "cc".repeat(31))],
                ["p", hex::encode(a)],
                ["p", hex::encode(b)],
            ],
            "content": "dm",
        }));
        let short = [0xcc; 31];
        let verify = |tags: &[(char, &[u8])]| {
            verify_strfry_event(strfry_record(&ev, 0, tags).view(), &ev)
                .map_err(|error| error.to_string())
        };
        // As strfry packed it, a 31-byte p from `0x` hex included.
        verify(&[('p', &short), ('p', &a), ('p', &b)]).unwrap();
        // Later or shorter p tags left out.
        verify(&[('p', &a)]).unwrap();
        verify(&[('p', &short), ('p', &a)]).unwrap();
        // The first recipient swapped or left out.
        let differs = |first: &str| {
            format!(
                "packed recipient {first} differs from the payload's {}",
                "aa".repeat(32)
            )
        };
        assert_eq!(
            verify(&[('p', &b), ('p', &a)]).unwrap_err(),
            differs(&"bb".repeat(32))
        );
        assert_eq!(verify(&[('p', &b)]).unwrap_err(), differs(&"bb".repeat(32)));
        assert_eq!(verify(&[('p', &short)]).unwrap_err(), differs("none"));
        assert_eq!(verify(&[]).unwrap_err(), differs("none"));
    }

    #[test]
    fn stored_events_keep_the_address_their_payload_names() {
        let event = |kind: u64, tags: Value| {
            sign_event(json!({
                "created_at": 1_700_000_000u64,
                "kind": kind,
                "tags": tags,
                "content": "",
            }))
        };
        let verify = |ev: &Value, expiration, tags: &[(char, &[u8])]| {
            verify_strfry_event(strfry_record(ev, expiration, tags).view(), ev)
                .map_err(|error| error.to_string())
        };
        let long = "y".repeat(MAX_INDEXED_TAG_VAL_SIZE + 1);
        let tagged = json!([["d", long], ["d", "x"], ["expiration", "1000"]]);
        // As strfry packed them: an empty d first for replaceable kinds, kind
        // 41 among them, and last for addressable ones; a long d dropped;
        // the ephemeral marker.
        for (kind, expiration, tags) in [
            (0, 1000, &[('d', &b""[..]), ('d', b"x")][..]),
            (41, 1000, &[('d', b""), ('d', b"x")]),
            (10002, 1000, &[('d', b""), ('d', b"x")]),
            (30023, 1000, &[('d', b"x"), ('d', b"")]),
            (20001, 1, &[('d', b"x")]),
            (1, 1000, &[('d', b"x")]),
        ] {
            let ev = event(kind, tagged.clone());
            verify(&ev, expiration, tags).unwrap_or_else(|error| panic!("kind {kind}: {error}"));
        }
        // Kind 41 is regular to Wok, so its empty d is allowed, not needed.
        verify(&event(41, tagged.clone()), 1000, &[('d', b"x")]).unwrap();
        // Wok's ingest packs a long first d hashed, as the address.
        let hashed = indexed_tag_value(long.as_bytes());
        verify(
            &event(30023, tagged.clone()),
            1000,
            &[('d', &hashed), ('d', b"x"), ('d', b"")],
        )
        .unwrap();
        // Without a d of its own, an addressable event's address is empty.
        verify(&event(30023, json!([])), 0, &[('d', b"")]).unwrap();
        // A payload d listed first moves a replaceable event's address, and
        // a leading empty d moves an addressable one's.
        for (kind, tags, error) in [
            (
                10002,
                &[('d', &b"x"[..]), ('d', b"")][..],
                r#"packed address "x" differs from the payload's """#,
            ),
            (
                30023,
                &[('d', b""), ('d', b"x")],
                r#"packed address "" differs from the payload's "x""#,
            ),
            (
                30023,
                &[],
                r#"packed address none differs from the payload's "x""#,
            ),
            (
                0,
                &[],
                r#"packed address none differs from the payload's """#,
            ),
        ] {
            let ev = event(kind, tagged.clone());
            assert_eq!(verify(&ev, 1000, tags).unwrap_err(), error, "kind {kind}");
        }
        // Only the kinds strfry gave one carry an empty d.
        assert_eq!(
            verify(&event(1, json!([])), 0, &[('d', b"")]).unwrap_err(),
            r#"packed d tag "" is not in the payload"#
        );
        // The ephemeral marker is for ephemeral kinds, and an ephemeral
        // record carries it, not 0 or its own expiration.
        assert_eq!(
            verify(&event(1, json!([])), 1, &[]).unwrap_err(),
            "packed expiration 1 differs from the 0 strfry packs from the payload"
        );
        for expiration in [0, 1000] {
            assert_eq!(
                verify(&event(20001, tagged.clone()), expiration, &[('d', b"x")]).unwrap_err(),
                format!(
                    "packed expiration {expiration} differs from the 1 strfry packs from the payload"
                )
            );
        }
    }

    #[test]
    fn payload_tags_strfry_could_not_pack_vouch_for_nothing() {
        for (tags, packed) in [
            (json!([["p", "22"]]), ('p', &b"\x22"[..])),
            (
                json!([["p", "22".repeat(32), "x"], ["p", "2".repeat(63)]]),
                ('p', &[0x22; 31][..]),
            ),
            (json!([["t", 1]]), ('t', b"1")),
            (json!([["\u{e9}", "x"]]), ('\u{e9}', b"x")),
            (json!({"t": "x"}), ('t', b"x")),
        ] {
            let ev = sign_event(json!({
                "created_at": 1_700_000_000u64,
                "kind": 1,
                "tags": tags,
                "content": "",
            }));
            let error = verify_strfry_event(strfry_record(&ev, 0, &[packed]).view(), &ev)
                .unwrap_err()
                .to_string();
            assert!(error.ends_with("is not in the payload"), "{tags}: {error}");
        }
    }

    #[test]
    fn accepts_extended_length_encrypted_carriers_with_default_limits() {
        let content = "x".repeat(256 * 1024);
        for kind in [445, 1059] {
            let ev = sign_event(json!({
                "created_at": 1_700_000_000u64,
                "kind": kind,
                "tags": [],
                "content": content,
            }));
            let parsed =
                parse_and_verify_event(&ev, &EventLimits::default(), None, true, false).unwrap();
            assert_eq!(parsed.packed.view().kind(), kind);
            assert!(parsed.json.len() > 65_536);
        }
    }

    #[test]
    fn rejects_oversized_event_before_bad_signature() {
        let mut ev = sign_event(json!({
            "created_at": 1_700_000_000u64,
            "kind": 445,
            "tags": [],
            "content": "x".repeat(crate::DEFAULT_MAX_EVENT_SIZE),
        }));
        ev["sig"] = json!("00".repeat(64));
        let err = parse_and_verify_event(&ev, &EventLimits::default(), None, true, false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("event too large"), "{err}");
    }

    #[test]
    fn limit_errors_name_the_limit_they_broke() {
        let now = 1_700_000_000u64;
        let policy = TimestampPolicy {
            now_secs: now,
            reject_newer_than_secs: 900,
            reject_older_than_secs: 3600,
            reject_ephemeral_older_than_secs: 60,
        };
        let limits = EventLimits {
            max_event_size: 1024,
            max_num_tags: 2,
            max_tag_val_size: 80,
        };
        let refused = |kind: u64, created_at: u64, tags: Value, content: &str| {
            let ev = sign_event(json!({
                "created_at": created_at, "kind": kind, "tags": tags, "content": content,
            }));
            parse_and_verify_event(&ev, &limits, Some(&policy), true, true)
                .unwrap_err()
                .broken_limit()
        };
        let long = "x".repeat(81);
        let cases = [
            (
                refused(1, now, json!([]), &"x".repeat(1024)),
                EventLimit::EventSize,
            ),
            (
                refused(1, now, json!([["t"], ["t"], ["t"]]), ""),
                EventLimit::NumTags,
            ),
            (
                refused(1, now, json!([["t", long]]), ""),
                EventLimit::TagValSize,
            ),
            (
                refused(30000, now, json!([["d", "x".repeat(10)]]), ""),
                EventLimit::TagValSize,
            ),
            (refused(1, now - 3601, json!([]), ""), EventLimit::TooOld),
            (refused(1, now + 901, json!([]), ""), EventLimit::TooNew),
            (
                refused(20001, now - 61, json!([]), ""),
                EventLimit::EphemeralTooOld,
            ),
        ];
        for (index, (refused, limit)) in cases.into_iter().enumerate() {
            assert_eq!(refused, Some(limit), "case {index}");
        }
        // Other refusals are not limits the caller chose.
        assert_eq!(refused(1, now, json!([["expiration", "1"]]), ""), None);
        assert_eq!(refused(1, now, json!([[]]), ""), None);
    }

    #[test]
    fn timestamp_bounds() {
        let tags = PackedEventTagBuilder::default();
        let packed = PackedEventBuilder::build(&[1u8; 32], &[2u8; 32], 50, 1, 0, &tags).unwrap();
        let policy = TimestampPolicy {
            now_secs: 100,
            reject_newer_than_secs: 10,
            reject_older_than_secs: 20,
            reject_ephemeral_older_than_secs: 5,
        };
        assert!(verify_event_timestamp(packed.view(), &policy).is_err());
        let packed = PackedEventBuilder::build(&[1u8; 32], &[2u8; 32], 95, 1, 0, &tags).unwrap();
        assert!(verify_event_timestamp(packed.view(), &policy).is_ok());
        let packed = PackedEventBuilder::build(&[1u8; 32], &[2u8; 32], 95, 1, 90, &tags).unwrap();
        assert!(verify_event_timestamp(packed.view(), &policy).is_err());
    }

    #[test]
    fn zero_means_no_lower_bound_for_non_ephemeral_events() {
        let tags = PackedEventTagBuilder::default();
        let now = 1_700_000_000;
        let policy = TimestampPolicy {
            now_secs: now,
            reject_newer_than_secs: 900,
            reject_older_than_secs: 0,
            reject_ephemeral_older_than_secs: 60,
        };
        for created_at in [0, 1_577_836_800, now] {
            let packed =
                PackedEventBuilder::build(&[1u8; 32], &[2u8; 32], created_at, 0, 0, &tags).unwrap();
            verify_event_timestamp(packed.view(), &policy).unwrap();
        }
        let packed =
            PackedEventBuilder::build(&[1u8; 32], &[2u8; 32], now + 901, 0, 0, &tags).unwrap();
        let err = verify_event_timestamp(packed.view(), &policy).unwrap_err();
        assert_eq!(err.to_string(), "created_at too late");
        // The ephemeral window has its own bound.
        let packed =
            PackedEventBuilder::build(&[1u8; 32], &[2u8; 32], now - 61, 20_001, 1, &tags).unwrap();
        let err = verify_event_timestamp(packed.view(), &policy).unwrap_err();
        assert_eq!(err.to_string(), "ephemeral event expired");
    }

    #[test]
    fn expired_events_are_refused_whatever_their_kind() {
        // NIP-40: relays SHOULD drop expired events published to them. An
        // ephemeral event packs the ephemeral marker, not its expiration.
        let now = 1_700_000_000u64;
        let policy = TimestampPolicy {
            now_secs: now,
            reject_newer_than_secs: 900,
            reject_older_than_secs: 3600,
            reject_ephemeral_older_than_secs: 60,
        };
        for kind in [1, 20001, 30000] {
            for (expiration, expired) in [(now - 1, true), (now, true), (now + 60, false)] {
                let ev = sign_event(json!({
                    "created_at": now,
                    "kind": kind,
                    "tags": [["expiration", expiration.to_string()]],
                    "content": "",
                }));
                let parsed =
                    parse_and_verify_event(&ev, &EventLimits::default(), Some(&policy), true, true);
                if expired {
                    assert_eq!(
                        parsed.unwrap_err().to_string(),
                        "event expired",
                        "kind {kind}"
                    );
                } else {
                    parsed.unwrap();
                }
            }
        }
    }
}
