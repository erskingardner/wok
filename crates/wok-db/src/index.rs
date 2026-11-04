//! Typed, short-lived historical-index entries. The entry borrows the cursor's
//! current record; only an owned resume key may outlive the callback.
//!
//! RocksDB reads the timestamp and local ID directly from its ordered key. It
//! neither reconstructs a logical key nor retains candidate bytes in the
//! transaction arena. The generic cursor API remains available to other users.

use crate::keys::{parse_key_string_u64, u64_from_ne_checked};
use crate::txn::Cursor;
use crate::DbError;

enum Prefix<'a> {
    Logical(&'a [u8]),
    #[cfg(feature = "rocksdb-backend")]
    InvertedEscaped(&'a [u8]),
}

enum LocalId<'a> {
    #[cfg(feature = "rocksdb-backend")]
    Integer(u64),
    Logical(&'a [u8]),
}

/// One historical-index posting, valid only during its reader callback.
pub struct IndexEntry<'a> {
    /// Missing only for a malformed logical key shorter than a timestamp. It
    /// still reaches the callback so a scan can stop at a prefix boundary.
    pub created_at: Option<u64>,
    local_id: LocalId<'a>,
    prefix: Prefix<'a>,
    kind: Option<u64>,
}

impl<'a> IndexEntry<'a> {
    pub(crate) fn from_logical(key: &'a [u8], value: &'a [u8]) -> Self {
        let (prefix, created_at) = match parse_key_string_u64(key) {
            Ok((prefix, time)) => (prefix, Some(time)),
            Err(_) => (key, None),
        };
        Self {
            created_at,
            local_id: LocalId::Logical(value),
            prefix: Prefix::Logical(prefix),
            kind: None,
        }
    }

    /// Validate a generic duplicate only when it is consumed. A scan must be
    /// able to reject an unrelated prefix/time before examining its duplicate.
    pub fn local_id(&self) -> Result<u64, DbError> {
        match self.local_id {
            #[cfg(feature = "rocksdb-backend")]
            LocalId::Integer(id) => Ok(id),
            LocalId::Logical(bytes) => u64_from_ne_checked(bytes),
        }
    }

    fn prefix_bytes(&self) -> impl Iterator<Item = u8> + '_ {
        let mut offset = 0;
        let prefix = std::iter::from_fn(move || match self.prefix {
            Prefix::Logical(bytes) => {
                let byte = bytes.get(offset).copied()?;
                offset += 1;
                Some(byte)
            }
            #[cfg(feature = "rocksdb-backend")]
            Prefix::InvertedEscaped(bytes) => {
                let byte = !*bytes.get(offset)?;
                offset += 1;
                if byte == 0 {
                    // The constructor validated every escape and removed the
                    // terminator. An escaped zero occupies two physical bytes.
                    offset += 1;
                }
                Some(byte)
            }
        });
        prefix.chain(self.kind.into_iter().flat_map(u64::to_ne_bytes))
    }

    /// Match the logical key without materializing it. `exact_len` requires
    /// exactly one timestamp after the prefix, as variable tag values need.
    pub fn prefix_matches(&self, search: &[u8], exact_len: bool) -> bool {
        if exact_len && self.created_at.is_none() {
            return false;
        }
        match self.prefix {
            Prefix::Logical(prefix) if self.kind.is_none() => {
                if exact_len || search.len() <= prefix.len() {
                    return prefix.starts_with(search)
                        && (!exact_len || prefix.len() == search.len());
                }
                return search.starts_with(prefix)
                    && self.created_at.is_some_and(|time| {
                        time.to_ne_bytes().starts_with(&search[prefix.len()..])
                    });
            }
            _ => {}
        }
        if exact_len {
            self.prefix_bytes().eq(search.iter().copied())
        } else {
            let mut bytes = self
                .prefix_bytes()
                .chain(self.created_at.into_iter().flat_map(u64::to_ne_bytes));
            search.iter().all(|byte| bytes.next() == Some(*byte))
        }
    }

    /// Match the first native integer in a kind-index key.
    pub fn matches_kind(&self, kind: u64) -> bool {
        self.prefix_bytes()
            .chain(self.created_at.into_iter().flat_map(u64::to_ne_bytes))
            .take(8)
            .eq(kind.to_ne_bytes())
    }

    /// Materialize only a resume boundary, rather than every candidate key.
    pub fn to_key(&self) -> Vec<u8> {
        self.prefix_bytes()
            .chain(self.created_at.into_iter().flat_map(u64::to_ne_bytes))
            .collect()
    }

    #[cfg(feature = "rocksdb-backend")]
    pub(crate) fn from_matching_rocks(
        dbi: u32,
        raw: &[u8],
        start_key: &'a [u8],
        bound: &[u8],
    ) -> Option<Self> {
        let valid = match dbi {
            4 | 6 | 10 | 23 => start_key.len() >= 8,
            5 | 21 => start_key.len() >= 16,
            9 => start_key.len() == 8,
            12 => start_key.len() == 16,
            _ => false,
        };
        let time_at = raw.len().checked_sub(17)?;
        if !valid
            || raw.len() != bound.len()
            || raw.get(..time_at) != bound.get(..time_at)
            || raw.get(raw.len() - 9) != Some(&!1u8)
        {
            return None;
        }
        let integer = |bytes: &[u8]| {
            let bytes: [u8; 8] = bytes.try_into().ok()?;
            Some(u64::from_be_bytes(bytes.map(|byte| !byte)))
        };
        // Equal canonical physical prefixes imply equal logical prefixes. Use
        // the existing seek key's bytes; never unescape or rebuild them per row.
        Some(Self {
            created_at: Some(integer(&raw[time_at..time_at + 8])?),
            local_id: LocalId::Integer(integer(&raw[raw.len() - 8..])?),
            prefix: Prefix::Logical(&start_key[..start_key.len() - 8]),
            kind: None,
        })
    }

    #[cfg(feature = "rocksdb-backend")]
    pub(crate) fn from_rocks(dbi: u32, raw: &'a [u8]) -> Option<Self> {
        fn integer(raw: &[u8]) -> Option<u64> {
            let bytes: [u8; 8] = raw.try_into().ok()?;
            Some(u64::from_be_bytes(bytes.map(|byte| !byte)))
        }
        // All supported indexes have a valid composite/integer key followed
        // by an integer duplicate. Every physical byte is complemented.
        let time_at = raw.len().checked_sub(17)?;
        if raw.first() != Some(&!1u8) || raw.get(raw.len() - 9) != Some(&!1u8) {
            return None;
        }
        let created_at = integer(raw.get(time_at..time_at + 8)?)?;
        let local_id = integer(raw.get(raw.len() - 8..)?)?;
        let (prefix, kind) = match dbi {
            9 if time_at == 1 => (Prefix::Logical(&[]), None),
            12 if time_at == 9 => (Prefix::Logical(&[]), Some(integer(&raw[1..9])?)),
            4 | 5 | 6 | 10 | 21 | 23 => {
                let head_end = if matches!(dbi, 5 | 21) {
                    time_at.checked_sub(8)?
                } else {
                    time_at
                };
                let head = raw.get(1..head_end)?;
                let escaped = head.strip_suffix(&[255, 255])?;
                let mut at = 0;
                while at < escaped.len() {
                    if escaped[at] == 255 {
                        if escaped.get(at + 1) != Some(&0) {
                            return None;
                        }
                        at += 1;
                    }
                    at += 1;
                }
                let kind = if matches!(dbi, 5 | 21) {
                    Some(integer(&raw[head_end..time_at])?)
                } else {
                    None
                };
                (Prefix::InvertedEscaped(escaped), kind)
            }
            _ => return None,
        };
        Some(Self {
            created_at: Some(created_at),
            local_id: LocalId::Integer(local_id),
            prefix,
            kind,
        })
    }
}

/// Generic and writer-overlay fallback. It retains the ordinary comparator,
/// positioning, malformed-key and duplicate validation behavior.
pub(crate) fn foreach_logical<F>(
    cursor: &mut Cursor<'_>,
    start_key: &[u8],
    start_dup: u64,
    mut callback: F,
) -> Result<bool, DbError>
where
    F: FnMut(IndexEntry<'_>) -> bool,
{
    cursor.foreach_full(start_key, &start_dup.to_ne_bytes(), true, |key, value| {
        callback(IndexEntry::from_logical(key, value))
    })
}

#[cfg(not(feature = "rocksdb-backend"))]
impl Cursor<'_> {
    /// Independently position and scan newest-first index postings. Returned
    /// entries borrow the current cursor record only for the callback.
    pub fn foreach_index<F>(
        &mut self,
        start_key: &[u8],
        start_dup: u64,
        callback: F,
    ) -> Result<bool, DbError>
    where
        F: FnMut(IndexEntry<'_>) -> bool,
    {
        foreach_logical(self, start_key, start_dup, callback)
    }
}
