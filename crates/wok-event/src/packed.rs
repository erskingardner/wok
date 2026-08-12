//! PackedEvent layout matching `src/PackedEvent.h` and `docs/fried.md`.
//!
//! ```text
//!   0: id (32)
//!  32: pubkey (32)
//!  64: created_at (8, native endian)
//!  72: kind (8, native endian)
//!  80: expiration (8, native endian)
//!  88: tags[] (variable)
//! each tag: char (1) + len (1) + value
//! ```
//!
//! Integers use native endian, identical to C++ `lmdb::to_sv<uint64_t>`.
//! Fried import/export is documented as little-endian-only in C++.

use crate::EventError;

pub const PACKED_HEADER_LEN: usize = 88;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackedEventTag {
    pub name: char,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackedEvent {
    buf: Vec<u8>,
}

impl PackedEvent {
    pub fn from_bytes(buf: Vec<u8>) -> Result<Self, EventError> {
        PackedEventView::new(&buf)?;
        Ok(Self { buf })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn view(&self) -> PackedEventView<'_> {
        PackedEventView { buf: &self.buf }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PackedEventView<'a> {
    buf: &'a [u8],
}

impl<'a> PackedEventView<'a> {
    pub fn new(buf: &'a [u8]) -> Result<Self, EventError> {
        if buf.len() < PACKED_HEADER_LEN {
            return Err(EventError::msg("PackedEventView too short"));
        }
        Ok(Self { buf })
    }

    /// Best-effort parse that never panics. Truncated tags are ignored.
    pub fn from_bytes_lossy(buf: &'a [u8]) -> Result<Self, EventError> {
        Self::new(buf)
    }

    pub fn as_bytes(&self) -> &'a [u8] {
        self.buf
    }

    pub fn id(&self) -> &'a [u8] {
        &self.buf[0..32]
    }

    pub fn pubkey(&self) -> &'a [u8] {
        &self.buf[32..64]
    }

    pub fn created_at(&self) -> u64 {
        u64::from_ne_bytes(self.buf[64..72].try_into().unwrap())
    }

    pub fn kind(&self) -> u64 {
        u64::from_ne_bytes(self.buf[72..80].try_into().unwrap())
    }

    pub fn expiration(&self) -> u64 {
        u64::from_ne_bytes(self.buf[80..88].try_into().unwrap())
    }

    /// Iterate indexable tags. Stops on truncated records without panicking.
    pub fn foreach_tag<F>(&self, mut cb: F)
    where
        F: FnMut(char, &[u8]) -> bool,
    {
        let mut b = &self.buf[PACKED_HEADER_LEN..];
        while b.len() >= 2 {
            let tag_name = b[0] as char;
            let tag_len = b[1] as usize;
            if tag_len > b.len() - 2 {
                break;
            }
            let val = &b[2..2 + tag_len];
            if !cb(tag_name, val) {
                break;
            }
            b = &b[2 + tag_len..];
        }
    }

    pub fn tags(&self) -> Vec<PackedEventTag> {
        let mut out = Vec::new();
        self.foreach_tag(|name, value| {
            out.push(PackedEventTag {
                name,
                value: value.to_vec(),
            });
            true
        });
        out
    }

    pub fn first_d_tag(&self) -> Option<Vec<u8>> {
        let mut found = None;
        self.foreach_tag(|name, val| {
            if name == 'd' {
                found = Some(val.to_vec());
                false
            } else {
                true
            }
        });
        found
    }
}

#[derive(Debug, Default)]
pub struct PackedEventTagBuilder {
    buf: Vec<u8>,
}

impl PackedEventTagBuilder {
    pub fn add(&mut self, tag_key: char, tag_val: &[u8]) -> Result<(), EventError> {
        if tag_val.len() > 255 {
            return Err(EventError::msg("tagVal too long"));
        }
        self.buf.push(tag_key as u8);
        self.buf.push(tag_val.len() as u8);
        self.buf.extend_from_slice(tag_val);
        Ok(())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }
}

pub struct PackedEventBuilder;

impl PackedEventBuilder {
    pub fn build(
        id: &[u8],
        pubkey: &[u8],
        created_at: u64,
        kind: u64,
        expiration: u64,
        tags: &PackedEventTagBuilder,
    ) -> Result<PackedEvent, EventError> {
        if id.len() != 32 {
            return Err(EventError::msg("unexpected id size"));
        }
        if pubkey.len() != 32 {
            return Err(EventError::msg("unexpected pubkey size"));
        }
        let mut buf = Vec::with_capacity(PACKED_HEADER_LEN + tags.buf.len());
        buf.extend_from_slice(id);
        buf.extend_from_slice(pubkey);
        buf.extend_from_slice(&created_at.to_ne_bytes());
        buf.extend_from_slice(&kind.to_ne_bytes());
        buf.extend_from_slice(&expiration.to_ne_bytes());
        buf.extend_from_slice(&tags.buf);
        Ok(PackedEvent { buf })
    }
}

/// NIP-01 replacement tie-break: if timestamps are equal, the event with the
/// *greatest* lexical id is considered earlier (discarded).
pub fn is_event_a_before_event_b(a: PackedEventView<'_>, b: PackedEventView<'_>) -> bool {
    a.created_at() < b.created_at() || (a.created_at() == b.created_at() && a.id() > b.id())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_tags() {
        let mut tags = PackedEventTagBuilder::default();
        tags.add('e', &[1u8; 32]).unwrap();
        tags.add('d', b"hello").unwrap();
        let packed = PackedEventBuilder::build(&[2u8; 32], &[3u8; 32], 100, 1, 0, &tags).unwrap();
        let v = packed.view();
        assert_eq!(v.id(), &[2u8; 32]);
        assert_eq!(v.pubkey(), &[3u8; 32]);
        assert_eq!(v.created_at(), 100);
        assert_eq!(v.kind(), 1);
        assert_eq!(v.expiration(), 0);
        let t = v.tags();
        assert_eq!(t.len(), 2);
        assert_eq!(t[0].name, 'e');
        assert_eq!(t[1].value, b"hello");
        assert_eq!(v.first_d_tag().unwrap(), b"hello");
    }

    #[test]
    fn truncated_tags_do_not_panic() {
        let mut buf = vec![0u8; 90];
        buf[88] = b'p';
        buf[89] = 50; // claims 50 bytes that are not present
        let v = PackedEventView::new(&buf).unwrap();
        let mut n = 0;
        v.foreach_tag(|_, _| {
            n += 1;
            true
        });
        assert_eq!(n, 0);
    }

    #[test]
    fn too_short_is_error() {
        assert!(PackedEventView::new(&[0u8; 87]).is_err());
    }

    #[test]
    fn equal_timestamp_greater_id_is_earlier() {
        let tags = PackedEventTagBuilder::default();
        let a = PackedEventBuilder::build(&[2u8; 32], &[1u8; 32], 10, 1, 0, &tags).unwrap();
        let b = PackedEventBuilder::build(&[1u8; 32], &[1u8; 32], 10, 1, 0, &tags).unwrap();
        assert!(is_event_a_before_event_b(a.view(), b.view()));
        assert!(!is_event_a_before_event_b(b.view(), a.view()));
    }
}
