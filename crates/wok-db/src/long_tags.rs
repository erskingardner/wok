//! Records packed before long tag values were indexed.
//!
//! strfry and Wok releases before hashed tag values dropped every single-letter
//! tag value longer than [`MAX_INDEXED_TAG_VAL_SIZE`] from PackedEvent, so
//! filters cannot match it and an addressable record whose first `d` was
//! dropped is keyed by the address it fell back to. The payload still holds
//! those values, so reindex packs such a record again. The result is accepted
//! only if removing its hashed values gives the stored bytes back: nothing
//! else about the record changes, and the repair loses no information.

use crate::DbError;
use serde::de::{self, Deserializer, IgnoredAny, SeqAccess, Visitor};
use serde::Deserialize;
use std::borrow::Cow;
use std::fmt;
use wok_event::{
    hashed_tag_value_digest, nostr_json_to_packed_event, EventLimits, PackedEventView,
    MAX_INDEXED_TAG_VAL_SIZE, PACKED_HEADER_LEN,
};

/// The unescaped length of a JSON string, which is not kept.
struct StrLen(usize);

impl<'de> Deserialize<'de> for StrLen {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrLenVisitor;
        impl Visitor<'_> for StrLenVisitor {
            type Value = StrLen;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string")
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<StrLen, E> {
                Ok(StrLen(value.len()))
            }
        }
        deserializer.deserialize_str(StrLenVisitor)
    }
}

/// How many tags have a one-byte name and a value longer than
/// [`MAX_INDEXED_TAG_VAL_SIZE`], counted without building the tags.
#[derive(Default)]
struct LongTagValues(u64);

impl<'de> Deserialize<'de> for LongTagValues {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct LongTag(bool);
        impl<'de> Deserialize<'de> for LongTag {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                struct TagVisitor;
                impl<'de> Visitor<'de> for TagVisitor {
                    type Value = LongTag;
                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str("a tag array")
                    }
                    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<LongTag, A::Error> {
                        let name = seq.next_element::<StrLen>()?;
                        let value = seq.next_element::<StrLen>()?;
                        while seq.next_element::<IgnoredAny>()?.is_some() {}
                        Ok(LongTag(
                            name.is_some_and(|name| name.0 == 1)
                                && value.is_some_and(|value| value.0 > MAX_INDEXED_TAG_VAL_SIZE),
                        ))
                    }
                }
                deserializer.deserialize_seq(TagVisitor)
            }
        }

        struct TagsVisitor;
        impl<'de> Visitor<'de> for TagsVisitor {
            type Value = LongTagValues;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a tags array")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<LongTagValues, A::Error> {
                let mut count = 0;
                while let Some(LongTag(long)) = seq.next_element()? {
                    count += u64::from(long);
                }
                Ok(LongTagValues(count))
            }
        }
        deserializer.deserialize_seq(TagsVisitor)
    }
}

#[derive(Deserialize)]
struct EventTags {
    #[serde(default)]
    tags: LongTagValues,
}

/// Whether `packed` lacks single-letter tag values longer than
/// [`MAX_INDEXED_TAG_VAL_SIZE`] that its payload `json` holds. Wok packs each
/// such value hashed; strfry and earlier Wok releases dropped them.
pub fn lacks_long_tag_values(packed: PackedEventView<'_>, json: &str) -> Result<bool, DbError> {
    let long = serde_json::from_str::<EventTags>(json)
        .map_err(|error| DbError::msg(format!("event JSON parse failed: {error}")))?
        .tags
        .0;
    if long == 0 {
        return Ok(false);
    }
    let mut hashed = 0u64;
    packed.foreach_tag(|_, value| {
        hashed += u64::from(hashed_tag_value_digest(value).is_some());
        true
    });
    Ok(hashed < long)
}

/// What packing a record's payload again would give.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LongTagPacking {
    /// PackedEvent already holds every long single-letter tag value.
    Complete,
    /// PackedEvent bytes with the dropped values restored, hashed.
    Repack(Vec<u8>),
    /// Packing the payload again changes more than the long values, as for
    /// kind 41 records packed with a virtual `d` by older releases, or fails.
    /// The record must be kept as it is.
    Mismatch,
}

/// `packed` without its hashed tag values. Every other byte, including a
/// truncated tail, is kept as it is.
pub fn without_hashed_tag_values(packed: &[u8]) -> Cow<'_, [u8]> {
    let mut stripped: Option<Vec<u8>> = None;
    let mut offset = PACKED_HEADER_LEN.min(packed.len());
    while packed.len() - offset >= 2 {
        let end = offset + 2 + usize::from(packed[offset + 1]);
        if end > packed.len() {
            break;
        }
        if hashed_tag_value_digest(&packed[offset + 2..end]).is_some() {
            stripped.get_or_insert_with(|| packed[..offset].to_vec());
        } else if let Some(kept) = &mut stripped {
            kept.extend_from_slice(&packed[offset..end]);
        }
        offset = end;
    }
    match stripped {
        Some(mut kept) => {
            kept.extend_from_slice(&packed[offset..]);
            Cow::Owned(kept)
        }
        None => Cow::Borrowed(packed),
    }
}

/// Pack the payload `json` of the record `packed` again, with every limit
/// lifted since the record was accepted under its own. The result must equal
/// `packed` once its hashed values are removed.
pub fn long_tag_packing(packed: &[u8], json: &str) -> Result<LongTagPacking, DbError> {
    if !lacks_long_tag_values(PackedEventView::new(packed)?, json)? {
        return Ok(LongTagPacking::Complete);
    }
    let limits = EventLimits {
        max_event_size: usize::MAX,
        max_num_tags: usize::MAX,
        max_tag_val_size: usize::MAX,
    };
    let Some(repacked) = wok_event::json::parse_strict(json)
        .ok()
        .and_then(|event| nostr_json_to_packed_event(&event, &limits).ok())
    else {
        return Ok(LongTagPacking::Mismatch);
    };
    if *without_hashed_tag_values(repacked.as_bytes()) != *packed {
        return Ok(LongTagPacking::Mismatch);
    }
    Ok(LongTagPacking::Repack(repacked.into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use wok_event::{PackedEventBuilder, PackedEventTagBuilder};

    fn event(kind: u64, tags: Value) -> String {
        wok_event::json::to_tao_string(&json!({
            "content": "",
            "created_at": 1,
            "id": "11".repeat(32),
            "kind": kind,
            "pubkey": "22".repeat(32),
            "sig": "00".repeat(64),
            "tags": tags,
        }))
    }

    fn pack(json: &str) -> Vec<u8> {
        let event = wok_event::json::parse_strict(json).unwrap();
        nostr_json_to_packed_event(&event, &EventLimits::default())
            .unwrap()
            .into_bytes()
    }

    /// What strfry and earlier Wok releases stored: the long values dropped.
    fn legacy(packed: &[u8]) -> Vec<u8> {
        let view = PackedEventView::new(packed).unwrap();
        let mut tags = PackedEventTagBuilder::default();
        for tag in view.tags() {
            if tag.value.len() <= MAX_INDEXED_TAG_VAL_SIZE
                && hashed_tag_value_digest(&tag.value).is_none()
            {
                tags.add(tag.name, &tag.value).unwrap();
            }
        }
        PackedEventBuilder::build(
            view.id(),
            view.pubkey(),
            view.created_at(),
            view.kind(),
            view.expiration(),
            &tags,
        )
        .unwrap()
        .into_bytes()
    }

    #[test]
    fn records_lacking_long_values_repack_to_the_current_packing() {
        let long = "z".repeat(MAX_INDEXED_TAG_VAL_SIZE + 1);
        let address = format!("30000:{}:{long}", "22".repeat(32));
        for (kind, tags) in [
            // The long first d becomes the address; the virtual d stays last.
            (30000, json!([["d", &long], ["r", &long], ["t", "short"]])),
            (30000, json!([["d", "short"], ["d", &long]])),
            (10002, json!([["r", &long], ["expiration", "1000"]])),
            (5, json!([["a", &address], ["e", "33".repeat(32)]])),
            (1, json!([["r", &long], ["r", &long], ["title", &long]])),
        ] {
            let json = event(kind, tags.clone());
            let current = pack(&json);
            let legacy = legacy(&current);
            assert_ne!(legacy, current, "{tags}");
            assert!(lacks_long_tag_values(PackedEventView::new(&legacy).unwrap(), &json).unwrap());
            assert_eq!(
                long_tag_packing(&legacy, &json).unwrap(),
                LongTagPacking::Repack(current.clone()),
                "{tags}"
            );
            assert!(
                !lacks_long_tag_values(PackedEventView::new(&current).unwrap(), &json).unwrap()
            );
            assert_eq!(
                long_tag_packing(&current, &json).unwrap(),
                LongTagPacking::Complete
            );
        }
    }

    #[test]
    fn addresses_new_events_may_no_longer_use_still_repack() {
        // A first d too long for the a tag naming it is refused for new
        // events, but legacy rows may hold one.
        let json = event(30000, json!([["d", "z".repeat(1000)]]));
        let event_json = wok_event::json::parse_strict(&json).unwrap();
        assert!(nostr_json_to_packed_event(&event_json, &EventLimits::default()).is_err());
        let limits = EventLimits {
            max_event_size: usize::MAX,
            max_num_tags: usize::MAX,
            max_tag_val_size: usize::MAX,
        };
        let current = nostr_json_to_packed_event(&event_json, &limits)
            .unwrap()
            .into_bytes();
        assert_eq!(
            long_tag_packing(&legacy(&current), &json).unwrap(),
            LongTagPacking::Repack(current)
        );
    }

    #[test]
    fn records_without_long_single_letter_values_are_complete() {
        let longest = "z".repeat(MAX_INDEXED_TAG_VAL_SIZE);
        // Escaped, this value is longer than the limit in JSON but not in bytes.
        let escaped = "\n".repeat(MAX_INDEXED_TAG_VAL_SIZE);
        let long = "z".repeat(MAX_INDEXED_TAG_VAL_SIZE + 1);
        for tags in [
            json!([]),
            json!([["r", &longest], ["r", &escaped]]),
            json!([["title", &long], ["r", "short", &long], ["r"]]),
        ] {
            let json = event(1, tags.clone());
            let packed = pack(&json);
            assert!(!lacks_long_tag_values(PackedEventView::new(&packed).unwrap(), &json).unwrap());
            assert_eq!(
                long_tag_packing(&packed, &json).unwrap(),
                LongTagPacking::Complete,
                "{tags}"
            );
        }
    }

    #[test]
    fn records_that_pack_differently_are_kept() {
        let long = "z".repeat(MAX_INDEXED_TAG_VAL_SIZE + 1);

        // Older releases packed kind 41 as replaceable, with a virtual d.
        let json = event(41, json!([["e", "33".repeat(32)], ["r", &long]]));
        let mut tags = PackedEventTagBuilder::default();
        tags.add('d', b"").unwrap();
        tags.add('e', &[0x33; 32]).unwrap();
        let kind41 = PackedEventBuilder::build(&[0x11; 32], &[0x22; 32], 1, 41, 0, &tags)
            .unwrap()
            .into_bytes();
        assert_eq!(
            long_tag_packing(&kind41, &json).unwrap(),
            LongTagPacking::Mismatch
        );

        let json = event(1, json!([["r", &long], ["t", "short"]]));
        let legacy = legacy(&pack(&json));
        let mut other_expiration = legacy.clone();
        other_expiration[80] = 9;
        let mut trailing = legacy.clone();
        trailing.push(b't');
        for packed in [other_expiration, trailing] {
            assert_eq!(
                long_tag_packing(&packed, &json).unwrap(),
                LongTagPacking::Mismatch
            );
        }

        // strfry dropped a long e tag; Wok refuses it, so nothing repacks.
        let json = event(1, json!([["e", "ab".repeat(200)]]));
        let tags = PackedEventTagBuilder::default();
        let packed = PackedEventBuilder::build(&[0x11; 32], &[0x22; 32], 1, 1, 0, &tags)
            .unwrap()
            .into_bytes();
        assert_eq!(
            long_tag_packing(&packed, &json).unwrap(),
            LongTagPacking::Mismatch
        );
    }

    #[test]
    fn stripping_hashed_values_keeps_every_other_byte() {
        let long = "z".repeat(MAX_INDEXED_TAG_VAL_SIZE + 1);
        let json = event(
            30000,
            json!([["r", &long], ["t", "a"], ["d", &long], ["t", "b"]]),
        );
        let current = pack(&json);
        let expected = legacy(&current);
        assert_eq!(*without_hashed_tag_values(&current), expected[..]);
        // A truncated tail is not a tag, and is kept.
        let (mut current, mut expected) = (current, expected);
        current.extend_from_slice(b"t\x09ab");
        expected.extend_from_slice(b"t\x09ab");
        assert_eq!(*without_hashed_tag_values(&current), expected[..]);
        assert!(matches!(
            without_hashed_tag_values(&expected),
            Cow::Borrowed(_)
        ));
        assert!(matches!(
            without_hashed_tag_values(&[0; 10]),
            Cow::Borrowed(_)
        ));
    }
}
