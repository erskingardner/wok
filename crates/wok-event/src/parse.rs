use serde_json::{Map, Value};

use crate::kinds::{
    is_ephemeral_kind, is_param_replaceable_kind, is_replaceable_kind, parse_a_tag,
};
use crate::packed::{PackedEvent, PackedEventBuilder, PackedEventTagBuilder};
use crate::{EventError, MAX_INDEXED_TAG_VAL_SIZE};

#[derive(Debug, Clone)]
pub struct EventLimits {
    pub max_event_size: usize,
    pub max_num_tags: usize,
    pub max_tag_val_size: usize,
}

impl Default for EventLimits {
    fn default() -> Self {
        Self {
            max_event_size: 65536,
            max_num_tags: 2000,
            max_tag_val_size: 1024,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ParsedEvent {
    pub packed: PackedEvent,
    pub json: String,
    pub value: Value,
}

pub fn from_hex(s: &str) -> Result<Vec<u8>, EventError> {
    if !s.len().is_multiple_of(2) {
        return Err(EventError::msg("odd hex length"));
    }
    hex::decode(s).map_err(|e| EventError::msg(format!("hex decode: {e}")))
}

pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn json_get_string<'a>(v: &'a Value, err: &str) -> Result<&'a str, EventError> {
    v.as_str().ok_or_else(|| EventError::msg(err.to_string()))
}

fn json_get_unsigned(v: &Value, err: &str) -> Result<u64, EventError> {
    match v {
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                Ok(u)
            } else {
                Err(EventError::msg(err.to_string()))
            }
        }
        _ => Err(EventError::msg(err.to_string())),
    }
}

fn json_get_array<'a>(v: &'a Value, err: &str) -> Result<&'a Vec<Value>, EventError> {
    v.as_array().ok_or_else(|| EventError::msg(err.to_string()))
}

/// Convert nostr JSON to PackedEvent. Matches `nostrJsonToPackedEvent`.
pub fn nostr_json_to_packed_event(
    v: &Value,
    limits: &EventLimits,
) -> Result<PackedEvent, EventError> {
    if !v.is_object() {
        return Err(EventError::msg("event is not an object"));
    }
    let id = from_hex(json_get_string(
        v.get("id").ok_or_else(|| EventError::msg("missing id"))?,
        "event id field was not a string",
    )?)?;
    let pubkey = from_hex(json_get_string(
        v.get("pubkey")
            .ok_or_else(|| EventError::msg("missing pubkey"))?,
        "event pubkey field was not a string",
    )?)?;
    let created_at = json_get_unsigned(
        v.get("created_at")
            .ok_or_else(|| EventError::msg("missing created_at"))?,
        "event created_at field was not an integer",
    )?;
    let kind = json_get_unsigned(
        v.get("kind")
            .ok_or_else(|| EventError::msg("missing kind"))?,
        "event kind field was not an integer",
    )?;
    json_get_string(
        v.get("content")
            .ok_or_else(|| EventError::msg("missing content"))?,
        "event content field was not a string",
    )?;

    if id.len() != 32 {
        return Err(EventError::msg("unexpected id size"));
    }
    if pubkey.len() != 32 {
        return Err(EventError::msg("unexpected pubkey size"));
    }

    let mut tag_builder = PackedEventTagBuilder::default();
    let mut expiration = 0u64;

    if is_replaceable_kind(kind) {
        // Prepend virtual d-tag. Any later d-tags will be ignored during indexing.
        tag_builder.add('d', b"")?;
    }

    let tags = json_get_array(
        v.get("tags")
            .ok_or_else(|| EventError::msg("missing tags"))?,
        "tags field not an array",
    )?;
    if tags.len() > limits.max_num_tags {
        return Err(EventError::msg(format!("too many tags: {}", tags.len())));
    }

    for tag_arr in tags {
        let tag = json_get_array(tag_arr, "tag in tags field was not an array")?;
        if tag.is_empty() {
            return Err(EventError::msg("too few fields in tag"));
        }
        let tag_name = json_get_string(&tag[0], "tag name was not a string")?;
        let tag_val = if tag.len() >= 2 {
            json_get_string(&tag[1], "tag val was not a string")?.to_string()
        } else {
            String::new()
        };

        if tag_name.len() == 1 {
            if tag_val.len() > limits.max_tag_val_size {
                return Err(EventError::msg(format!(
                    "tag val too large: {}",
                    tag_val.len()
                )));
            }
            if tag_name == "e" || tag_name == "p" {
                if tag_val.len() != 64 {
                    return Err(EventError::msg(format!(
                        "unexpected size for fixed-size tag: {tag_name}"
                    )));
                }
                let raw = from_hex(&tag_val)?;
                if raw.len() <= MAX_INDEXED_TAG_VAL_SIZE {
                    tag_builder.add(tag_name.chars().next().unwrap(), &raw)?;
                }
                continue;
            } else if tag_name == "a" && kind == 5 {
                let (tag_kind, tag_pubkey, _d) = parse_a_tag(&tag_val)?;
                let _ = tag_kind;
                if tag_pubkey.as_slice() != pubkey.as_slice() {
                    return Err(EventError::msg("can't delete other user's events"));
                }
            }

            if tag_val.len() <= MAX_INDEXED_TAG_VAL_SIZE {
                tag_builder.add(tag_name.chars().next().unwrap(), tag_val.as_bytes())?;
            }
        } else if tag_name == "expiration" && expiration == 0 {
            expiration = parse_uint64(&tag_val)?;
            if expiration < 100 {
                return Err(EventError::msg("invalid expiration"));
            }
        }
    }

    if is_param_replaceable_kind(kind) {
        // Append virtual d-tag. Overridden by any previous d-tags during indexing
        // (first d-tag wins).
        tag_builder.add('d', b"")?;
    }

    if is_ephemeral_kind(kind) {
        expiration = 1;
    }

    PackedEventBuilder::build(&id, &pubkey, created_at, kind, expiration, &tag_builder)
}

fn parse_uint64(s: &str) -> Result<u64, EventError> {
    s.parse::<u64>()
        .map_err(|_| EventError::msg(format!("invalid uint64: {s}")))
}

/// Rebuild JSON with only authenticated top-level fields, keys in insertion
/// order matching C++ `tao::json` initializer which uses a sorted map:
/// content, created_at, id, kind, pubkey, sig, tags.
pub fn normalize_event_json(orig: &Value) -> Result<String, EventError> {
    let mut map = Map::new();
    for key in [
        "content",
        "created_at",
        "id",
        "kind",
        "pubkey",
        "sig",
        "tags",
    ] {
        let v = orig
            .get(key)
            .ok_or_else(|| EventError::msg(format!("missing {key}")))?;
        map.insert(key.to_string(), v.clone());
    }
    serde_json::to_string(&Value::Object(map)).map_err(|e| EventError::msg(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hex_roundtrip() {
        assert_eq!(to_hex(&from_hex("0a0b").unwrap()), "0a0b");
        assert!(from_hex("zz").is_err());
        assert!(from_hex("a").is_err());
    }

    #[test]
    fn packed_e_tag_is_raw_32() {
        let id = "11".repeat(32);
        let pk = "22".repeat(32);
        let e = "33".repeat(32);
        let v = json!({
            "id": id,
            "pubkey": pk,
            "created_at": 1,
            "kind": 1,
            "content": "",
            "tags": [["e", e]],
            "sig": "00".repeat(64),
        });
        let packed = nostr_json_to_packed_event(&v, &EventLimits::default()).unwrap();
        let tags = packed.view().tags();
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].name, 'e');
        assert_eq!(tags[0].value.len(), 32);
    }

    #[test]
    fn replaceable_gets_virtual_d() {
        let v = json!({
            "id": "11".repeat(32),
            "pubkey": "22".repeat(32),
            "created_at": 1,
            "kind": 0,
            "content": "",
            "tags": [],
            "sig": "00".repeat(64),
        });
        let packed = nostr_json_to_packed_event(&v, &EventLimits::default()).unwrap();
        assert_eq!(packed.view().first_d_tag().unwrap(), b"");
    }

    #[test]
    fn normalize_strips_unknown_fields() {
        let v = json!({
            "id": "aa",
            "pubkey": "bb",
            "created_at": 1,
            "kind": 1,
            "content": "x",
            "sig": "cc",
            "tags": [],
            "fried": "nope",
        });
        let s = normalize_event_json(&v).unwrap();
        assert!(!s.contains("fried"));
        assert!(s.starts_with("{\"content\":"));
    }
}
