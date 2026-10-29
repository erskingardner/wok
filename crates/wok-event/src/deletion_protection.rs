//! NIP-D9 deletion-request-protection metadata rules.

use serde_json::Value;

use crate::{is_ephemeral_kind, is_param_replaceable_kind, is_replaceable_kind, EventError};

/// The signed, case-sensitive opt-in marker (distinct from NIP-70's `-`).
pub const NO_DELETE_TAG: &str = "no_delete";
/// NIP-D9's literal NIP-11 identifier; named NIPs are not converted to integers.
pub const DELETION_PROTECTION_NIP: &str = "D9";

/// Validate deletion-protection metadata. `true` means the metadata opts in;
/// the caller must still verify the event's NIP-01 identity and signature.
/// Expiration is intentionally independent of the current time: even a
/// retained expired copy keeps its exception to author deletion.
pub fn deletion_protection(event: &Value) -> Result<bool, EventError> {
    let Some(tags) = event.get("tags").and_then(Value::as_array) else {
        return Ok(false);
    };
    let named = |tag: &&Value, name: &str| {
        tag.as_array()
            .and_then(|tag| tag.first())
            .and_then(Value::as_str)
            == Some(name)
    };
    let mut markers = tags.iter().filter(|tag| named(tag, NO_DELETE_TAG));
    let Some(marker) = markers.next() else {
        return Ok(false);
    };
    if marker.as_array().unwrap().len() != 1 || markers.next().is_some() {
        return Err(EventError::msg("expected exactly one [\"no_delete\"] tag"));
    }

    let mut expirations = tags.iter().filter(|tag| named(tag, "expiration"));
    if let Some(expiration) = expirations.next() {
        let tag = expiration.as_array().unwrap();
        let value = tag.get(1).and_then(Value::as_str).unwrap_or("");
        if tag.len() != 2
            || expirations.next().is_some()
            || value.is_empty()
            || !value.bytes().all(|byte| byte.is_ascii_digit())
            || (value.len() > 1 && value.starts_with('0'))
            || value.parse::<u64>().is_err()
        {
            return Err(EventError::msg(
                "no_delete requires one canonical u64 expiration value",
            ));
        }
    }

    let kind = event
        .get("kind")
        .and_then(Value::as_u64)
        .ok_or_else(|| EventError::msg("event kind field was not an integer"))?;
    if is_replaceable_kind(kind) || is_param_replaceable_kind(kind) || is_ephemeral_kind(kind) {
        return Err(EventError::restricted(
            "no_delete is only allowed on regular event kinds",
        ));
    }
    Ok(true)
}
