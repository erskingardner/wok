use serde_json::Value;

use crate::kinds::{
    is_ephemeral_kind, is_param_replaceable_kind, is_replaceable_kind, parse_a_tag,
};
use crate::packed::{indexed_tag_value, PackedEvent, PackedEventBuilder, PackedEventTagBuilder};
use crate::{EventError, EventLimit, MAX_INDEXED_TAG_VAL_SIZE};

/// Default ceiling for normalized event JSON. This is intentionally far below
/// NIP-44's protocol maximum while leaving room for extended-length encrypted
/// gift wraps and MLS group events.
pub const DEFAULT_MAX_EVENT_SIZE: usize = 1024 * 1024;

/// Default ceiling for tags on one event: room for the kind-3 follow lists
/// and kind-10000/30000 lists of heavy users.
pub const DEFAULT_MAX_NUM_TAGS: usize = 5_000;

#[derive(Debug, Clone)]
pub struct EventLimits {
    pub max_event_size: usize,
    pub max_num_tags: usize,
    pub max_tag_val_size: usize,
}

impl Default for EventLimits {
    fn default() -> Self {
        Self {
            max_event_size: DEFAULT_MAX_EVENT_SIZE,
            max_num_tags: DEFAULT_MAX_NUM_TAGS,
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
    if s.starts_with("0x") || s.len() % 2 != 0 {
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
    if s.len() % 2 != 0 {
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
    pack_event(v, limits).map(|(packed, _)| packed)
}

/// The NIP-40 expiration of event JSON `v`: its first `expiration` tag, as
/// packing reads it. `None` when it has none or the value is malformed.
pub fn expiration_tag(v: &Value) -> Option<u64> {
    let tag = v
        .get("tags")?
        .as_array()?
        .iter()
        .filter_map(Value::as_array)
        .find(|tag| tag.first().and_then(Value::as_str) == Some("expiration"))?;
    parse_uint64(tag.get(1)?.as_str()?).ok()
}

/// [`nostr_json_to_packed_event`], also returning the NIP-40 expiration tag's
/// value (0 when there is none). An ephemeral event packs the ephemeral
/// marker in its place, so ingest checks expiry against this value.
pub(crate) fn pack_event(
    v: &Value,
    limits: &EventLimits,
) -> Result<(PackedEvent, u64), EventError> {
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
    let mut address_d_seen = !is_param_replaceable_kind(kind);

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
        return Err(EventError::limit(
            EventLimit::NumTags,
            format!("too many tags: {}", tags.len()),
        ));
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
                return Err(EventError::limit(
                    EventLimit::TagValSize,
                    format!("tag val too large: {}", tag_val.len()),
                ));
            }
            // An address must fit the a tag that names it, `kind:pubkey:d`,
            // under the same limit, or no event could reference or delete it.
            if tag_name == "d" && !address_d_seen {
                address_d_seen = true;
                let a_tag_len = kind.to_string().len() + 1 + 64 + 1 + tag_val.len();
                if a_tag_len > limits.max_tag_val_size {
                    return Err(EventError::limit(
                        EventLimit::TagValSize,
                        format!("d tag too large: its a tag would be {a_tag_len} bytes"),
                    ));
                }
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
                // Ingest also requires the canonical kind spelling
                // (`parse_and_verify_event`). Packing accepts the leading
                // zeros strfry and earlier releases stored, so reindex can
                // pack such a record again.
                let (_, tag_pubkey, _) = parse_a_tag(tag_val)?;
                if tag_pubkey.as_slice() != pubkey.as_slice() {
                    return Err(EventError::msg("can't delete other user's events"));
                }
            }

            // Long values are packed by hash, so an address with a long d or a
            // long deletion a tag stays distinct and can be matched.
            tag_builder.add(
                tag_name.chars().next().unwrap(),
                &indexed_tag_value(tag_val.as_bytes()),
            )?;
        } else if tag_name == "expiration" && expiration == 0 {
            expiration = parse_uint64(tag_val)?;
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

    let packed_expiration = if is_ephemeral_kind(kind) {
        1
    } else {
        expiration
    };
    let packed = PackedEventBuilder::build(
        &id,
        &pubkey,
        created_at,
        kind,
        packed_expiration,
        &tag_builder,
    )?;
    Ok((packed, expiration))
}

/// Matches C++ `parseUint64`: every character must be an ASCII digit and the
/// value must fit in u64 (so `+100` and whitespace are rejected).
pub(crate) fn parse_uint64(s: &str) -> Result<u64, EventError> {
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
    fn filter_tags_leave_out_the_added_d() {
        let filter_tags = |kind: u64, tags: Value| {
            let v = json!({
                "id": "11".repeat(32),
                "pubkey": "22".repeat(32),
                "created_at": 1,
                "kind": kind,
                "content": "",
                "tags": tags,
                "sig": "00".repeat(64),
            });
            let packed = nostr_json_to_packed_event(&v, &EventLimits::default()).unwrap();
            let mut out = Vec::new();
            packed.view().foreach_filter_tag(|name, value| {
                out.push(format!("{name}={}", String::from_utf8_lossy(value)));
                true
            });
            out
        };
        // Replaceable: the leading empty d is added, a d of the event's own
        // is kept.
        assert!(filter_tags(0, json!([])).is_empty());
        assert_eq!(filter_tags(10002, json!([["r", "x"]])), ["r=x"]);
        assert_eq!(filter_tags(10002, json!([["d", ""]])), ["d="]);
        assert_eq!(
            filter_tags(3, json!([["d", "x"], ["d", ""]])),
            ["d=x", "d="]
        );
        // Addressable: the trailing empty d is the address of an event
        // without a d, and added otherwise.
        assert_eq!(filter_tags(30023, json!([["t", "x"]])), ["t=x", "d="]);
        assert_eq!(filter_tags(30023, json!([["d", "intro"]])), ["d=intro"]);
        assert_eq!(filter_tags(30023, json!([["d", ""]])), ["d="]);
        assert_eq!(
            filter_tags(30023, json!([["d", "intro"], ["d", ""], ["t", "x"]])),
            ["d=intro", "d=", "t=x"]
        );
        // Other kinds add nothing.
        assert_eq!(filter_tags(1, json!([["d", ""]])), ["d="]);
        assert!(filter_tags(1, json!([])).is_empty());
    }

    #[test]
    fn long_tag_values_are_packed_by_hash() {
        let event = |kind: u64, tags: Value| {
            json!({
                "id": "11".repeat(32),
                "pubkey": "22".repeat(32),
                "created_at": 1,
                "kind": kind,
                "content": "",
                "tags": tags,
                "sig": "00".repeat(64),
            })
        };
        let pack = |kind: u64, tags: Value| {
            nostr_json_to_packed_event(&event(kind, tags), &EventLimits::default()).unwrap()
        };
        let longest = "z".repeat(MAX_INDEXED_TAG_VAL_SIZE);
        let long = "z".repeat(MAX_INDEXED_TAG_VAL_SIZE + 1);
        let hashed = indexed_tag_value(long.as_bytes()).into_owned();
        assert_eq!(hashed.len(), 33);

        let packed = pack(30000, json!([["d", longest]]));
        assert_eq!(packed.view().first_d_tag().unwrap(), longest.as_bytes());
        // The first d is the address even when it is long, and the virtual
        // empty d stays last.
        for tags in [json!([["d", long]]), json!([["d", long], ["d", "short"]])] {
            let packed = pack(30000, tags);
            assert_eq!(packed.view().first_d_tag().unwrap(), hashed);
            assert_eq!(packed.view().tags().last().unwrap().value, b"");
        }
        let packed = pack(30000, json!([["d", "short"], ["d", long]]));
        assert_eq!(packed.view().first_d_tag().unwrap(), b"short");
        // Replaceable kinds keep their leading virtual empty d.
        let packed = pack(10002, json!([["d", long]]));
        assert_eq!(packed.view().first_d_tag().unwrap(), b"");
        let packed = pack(1, json!([["r", long], ["t", "short"], ["title", long]]));
        let tags = packed.view().tags();
        assert_eq!(tags.len(), 2);
        assert_eq!((tags[0].name, &tags[0].value), ('r', &hashed));
        assert_eq!((tags[1].name, &tags[1].value[..]), ('t', &b"short"[..]));

        // An address must fit the a tag that names it: `30000:` plus 64 hex
        // digits and `:` leave max_tag_val_size - 71 bytes for the first d.
        let limits = EventLimits::default();
        let fits = "z".repeat(limits.max_tag_val_size - 71);
        let too_long = "z".repeat(limits.max_tag_val_size - 70);
        let packed = pack(30000, json!([["d", fits]]));
        assert_eq!(
            packed.view().first_d_tag().unwrap(),
            indexed_tag_value(fits.as_bytes()).into_owned()
        );
        for tags in [
            json!([["d", too_long]]),
            json!([["d", "z".repeat(limits.max_tag_val_size)]]),
        ] {
            assert!(nostr_json_to_packed_event(&event(30000, tags), &limits).is_err());
        }
        // Only the address is held to that: later d tags and other kinds are
        // not named by an a tag.
        pack(30000, json!([["d", "short"], ["d", too_long]]));
        pack(1, json!([["d", too_long]]));
        pack(10002, json!([["d", too_long]]));

        let pubkey = "22".repeat(32);
        let deletion = format!("30000:{pubkey}:{fits}");
        assert_eq!(deletion.len(), limits.max_tag_val_size);
        pack(5, json!([["a", deletion]]));
        let address = format!("30000:{pubkey}:{long}");
        let packed = pack(5, json!([["a", address]]));
        assert_eq!(
            packed.view().tags()[0].value,
            indexed_tag_value(address.as_bytes()).into_owned()
        );
        // A long address must still name the author of the deletion.
        let other = format!("30000:{}:{long}", "33".repeat(32));
        assert!(nostr_json_to_packed_event(
            &event(5, json!([["a", other]])),
            &EventLimits::default()
        )
        .is_err());
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
