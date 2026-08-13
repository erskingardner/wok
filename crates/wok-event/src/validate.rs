use serde_json::Value;

use crate::hash::{verify_id, verify_sig};
use crate::packed::PackedEventView;
use crate::parse::{normalize_event_json, nostr_json_to_packed_event, EventLimits, ParsedEvent};
use crate::EventError;

// Re-export helper used by validate; keep json_get_string crate-private in parse
// by duplicating the small accessor here for sig field.

fn json_string<'a>(v: &'a Value, err: &str) -> Result<&'a str, EventError> {
    v.as_str().ok_or_else(|| EventError::msg(err.to_string()))
}

#[derive(Debug, Clone)]
pub struct TimestampPolicy {
    pub now_secs: u64,
    pub reject_newer_than_secs: u64,
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
    verify_id(orig, packed.id())?;
    let sig_hex = json_string(
        orig.get("sig")
            .ok_or_else(|| EventError::msg("missing sig"))?,
        "event sig was not a string",
    )?;
    if sig_hex.len() != 128 {
        return Err(EventError::msg("unexpected signature size"));
    }
    let sig = crate::from_lower_hex_exact(sig_hex)?;
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

    let mut earliest = now.saturating_sub(if is_ephemeral {
        policy.reject_ephemeral_older_than_secs
    } else {
        policy.reject_older_than_secs
    });
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

pub fn parse_and_verify_event(
    orig: &Value,
    limits: &EventLimits,
    policy: Option<&TimestampPolicy>,
    verify_msg: bool,
    verify_time: bool,
) -> Result<ParsedEvent, EventError> {
    if !orig.is_object() {
        return Err(EventError::msg("event is not an object"));
    }
    let packed = nostr_json_to_packed_event(orig, limits)?;
    if verify_time {
        let p = policy.ok_or_else(|| EventError::msg("timestamp policy required"))?;
        verify_event_timestamp(packed.view(), p)?;
    }
    if verify_msg {
        verify_nostr_event(packed.view(), orig)?;
    }
    let json = normalize_event_json(orig)?;
    if verify_msg {
        verify_event_json_size(&json, limits.max_event_size)?;
    }
    Ok(ParsedEvent {
        packed,
        json,
        value: orig.clone(),
    })
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
}
