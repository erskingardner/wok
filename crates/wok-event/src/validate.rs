use serde_json::Value;

use crate::hash::{verify_id, verify_id_allowing_legacy, verify_sig};
use crate::packed::PackedEventView;
use crate::parse::{
    from_lower_hex_array, normalize_event_json, pack_event, EventLimits, ParsedEvent,
};
use crate::{parse_canonical_a_tag, EventError, DELETION_KIND};

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

pub fn verify_event_json_size(json_str: &str, max_event_size: usize) -> Result<(), EventError> {
    if json_str.len() > max_event_size {
        return Err(EventError::msg(format!(
            "event too large: {}",
            json_str.len()
        )));
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
        return Err(EventError::msg(if is_ephemeral {
            "ephemeral event expired"
        } else {
            "created_at too early"
        }));
    }
    if ts > latest {
        return Err(EventError::msg("created_at too late"));
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
    use crate::packed::PackedEventBuilder;
    use crate::PackedEventTagBuilder;
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
