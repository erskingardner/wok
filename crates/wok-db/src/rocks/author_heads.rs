//! Derived newest two canonical thin-author postings. This is not a visibility or
//! query-window cache; callers fall back when a head cannot seed their range.
#![forbid(unsafe_code)]

use super::err;
use crate::DbError;

/// Full-width chronological position of an author posting.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AuthorPosition {
    pub created_at: u64,
    pub local_id: u64,
}

impl AuthorPosition {
    pub(crate) fn encode(self) -> [u8; 16] {
        let mut bytes = [0; 16];
        bytes[..8].copy_from_slice(&self.created_at.to_be_bytes());
        bytes[8..].copy_from_slice(&self.local_id.to_be_bytes());
        bytes
    }
}

/// First candidate and exact second-row resume endpoint for an author.
/// The second position, when present, is strictly older. Missing heads require
/// ordinary-index fallback unless the caller separately trusts an exact audit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorHead {
    pub first: AuthorPosition,
    pub next: Option<AuthorPosition>,
}

impl AuthorHead {
    pub(crate) fn decode(raw: &[u8]) -> Result<Self, DbError> {
        if !matches!(raw.len(), 16 | 32) {
            return Err(err("invalid author head: expected 16 or 32 bytes"));
        }
        let position = |bytes: &[u8]| AuthorPosition {
            created_at: u64::from_be_bytes(bytes[..8].try_into().unwrap()),
            local_id: u64::from_be_bytes(bytes[8..16].try_into().unwrap()),
        };
        let first = position(&raw[..16]);
        let next = (raw.len() == 32).then(|| position(&raw[16..]));
        if next.is_some_and(|next| next >= first) {
            return Err(err(
                "invalid author head: next position must be strictly older",
            ));
        }
        Ok(Self { first, next })
    }

    pub(crate) fn encode(self) -> Vec<u8> {
        let mut raw = Vec::with_capacity(if self.next.is_some() { 32 } else { 16 });
        raw.extend_from_slice(&self.first.encode());
        if let Some(next) = self.next {
            raw.extend_from_slice(&next.encode());
        }
        raw
    }
}

pub(crate) type HeadUpdate = ([u8; 32], Option<Vec<u8>>);
