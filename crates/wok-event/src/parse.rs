use serde_json::Value;

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
}

/// Matches hoytech `from_hex` with the default `allowUnevenSize = true`:
/// strips a `"0x"` prefix and left-pads a single `0` nibble on odd length.
pub fn from_hex(s: &str) -> Result<Vec<u8>, EventError> {
    from_hex_impl(s, true)
}

/// Matches hoytech `from_hex(s, false)`: strips a `"0x"` prefix but rejects
/// odd-length input.
pub fn from_hex_exact(s: &str) -> Result<Vec<u8>, EventError> {
    from_hex_impl(s, false)
}

/// Decode an even-length hex string without accepting a `0x` prefix.
pub fn from_hex_strict(s: &str) -> Result<Vec<u8>, EventError> {
    if s.starts_with("0x") || !s.len().is_multiple_of(2) {
        return Err(EventError::msg(
            "hex must have an even length and no prefix",
        ));
    }
    hex::decode(s).map_err(|e| EventError::msg(format!("hex decode: {e}")))
}

/// Decode the lowercase, even-length form required for NIP-01 identifiers.
pub fn from_lower_hex_exact(s: &str) -> Result<Vec<u8>, EventError> {
    if !s
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(EventError::msg("hex must be lowercase ASCII"));
    }
    from_hex_strict(s)
}

pub(crate) fn from_lower_hex_array<const N: usize>(s: &str) -> Result<[u8; N], EventError> {
    if !s
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(EventError::msg("hex must be lowercase ASCII"));
    }
    let mut decoded = [0u8; N];
    hex::decode_to_slice(s, &mut decoded)
        .map_err(|error| EventError::msg(format!("hex decode: {error}")))?;
    Ok(decoded)
}

fn from_hex_impl(s: &str, allow_uneven: bool) -> Result<Vec<u8>, EventError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if !s.len().is_multiple_of(2) {
        if !allow_uneven {
            return Err(EventError::msg("uneven size input to from_hex"));
        }
        let mut padded = String::with_capacity(s.len() + 1);
        padded.push('0');
        padded.push_str(s);
        return hex::decode(padded).map_err(|e| EventError::msg(format!("hex decode: {e}")));
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
    let id_hex = json_get_string(
        v.get("id").ok_or_else(|| EventError::msg("missing id"))?,
        "event id field was not a string",
    )?;
    if id_hex.len() != 64 {
        return Err(EventError::msg("unexpected id size"));
    }
    let id = from_lower_hex_array::<32>(id_hex)?;
    let pubkey_hex = json_get_string(
        v.get("pubkey")
            .ok_or_else(|| EventError::msg("missing pubkey"))?,
        "event pubkey field was not a string",
    )?;
    if pubkey_hex.len() != 64 {
        return Err(EventError::msg("unexpected pubkey size"));
    }
    let pubkey = from_lower_hex_array::<32>(pubkey_hex)?;
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
    if kind > u16::MAX as u64 {
        return Err(EventError::msg("event kind must be between 0 and 65535"));
    }
    json_get_string(
        v.get("content")
            .ok_or_else(|| EventError::msg("missing content"))?,
        "event content field was not a string",
    )?;

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
        if tag.iter().any(|element| !element.is_string()) {
            return Err(EventError::msg("all tag elements must be strings"));
        }
        let tag_name = json_get_string(&tag[0], "tag name was not a string")?;
        let tag_val = if tag.len() >= 2 {
            json_get_string(&tag[1], "tag val was not a string")?
        } else {
            ""
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
                let raw = from_lower_hex_array::<32>(tag_val)?;
                if raw.len() <= MAX_INDEXED_TAG_VAL_SIZE {
                    tag_builder.add(tag_name.chars().next().unwrap(), &raw)?;
                }
                continue;
            } else if tag_name == "a" && kind == 5 {
                let (tag_kind, tag_pubkey, _d) = parse_a_tag(tag_val)?;
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

/// Matches C++ `parseUint64`: every character must be an ASCII digit and the
/// value must fit in u64 (so `+100` and whitespace are rejected).
fn parse_uint64(s: &str) -> Result<u64, EventError> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(EventError::msg(format!("invalid uint64: {s}")));
    }
    s.parse::<u64>()
        .map_err(|_| EventError::msg(format!("invalid uint64: {s}")))
}

/// Rebuild JSON with only authenticated top-level fields, keys in
/// alphabetical order, serialized exactly like C++ `tao::json`.
pub fn normalize_event_json(orig: &Value) -> Result<String, EventError> {
    let mut json = String::with_capacity(512);
    json.push('{');
    for (index, key) in [
        "content",
        "created_at",
        "id",
        "kind",
        "pubkey",
        "sig",
        "tags",
    ]
    .into_iter()
    .enumerate()
    {
        let v = orig
            .get(key)
            .ok_or_else(|| EventError::msg(format!("missing {key}")))?;
        if index != 0 {
            json.push(',');
        }
        json.push('"');
        json.push_str(key);
        json.push_str("\":");
        crate::json::write_tao(v, &mut json);
    }
    json.push('}');
    Ok(json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hex_roundtrip() {
        assert_eq!(to_hex(&from_hex("0a0b").unwrap()), "0a0b");
        assert!(from_hex("zz").is_err());
        // hoytech semantics: uneven input is left-padded, "0x" is stripped.
        assert_eq!(from_hex("a").unwrap(), vec![0x0a]);
        assert_eq!(from_hex("0x0a0b").unwrap(), vec![0x0a, 0x0b]);
        assert!(from_hex_exact("a").is_err());
        assert_eq!(from_hex_exact("0x0a0b").unwrap(), vec![0x0a, 0x0b]);
        assert_eq!(from_hex_strict("0A0b").unwrap(), vec![0x0a, 0x0b]);
        assert!(from_hex_strict("0x0a").is_err());
        assert!(from_hex_strict("a").is_err());
        assert_eq!(from_lower_hex_exact("0a0b").unwrap(), vec![0x0a, 0x0b]);
        assert!(from_lower_hex_exact("0A0b").is_err());
    }

    #[test]
    fn uint64_digits_only() {
        let tags = serde_json::json!([["expiration", "+100"]]);
        let v = serde_json::json!({
            "id": "11".repeat(32),
            "pubkey": "22".repeat(32),
            "created_at": 1,
            "kind": 1,
            "content": "",
            "tags": tags,
            "sig": "00".repeat(64),
        });
        // C++ parseUint64 rejects the '+' sign.
        assert!(nostr_json_to_packed_event(&v, &EventLimits::default()).is_err());
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
