use thiserror::Error;
use wok_event::MAX_SUBID_CHARS;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum QueryError {
    #[error("{0}")]
    Message(String),
    /// The request uses something this relay does not implement, such as a
    /// filter key NIP-01 does not define: NIP-01's `unsupported:` rather
    /// than `invalid:`.
    #[error("{0}")]
    Unsupported(String),
}

impl QueryError {
    pub fn msg(m: impl Into<String>) -> Self {
        Self::Message(m.into())
    }

    pub fn unsupported(m: impl Into<String>) -> Self {
        Self::Unsupported(m.into())
    }

    /// NIP-01 machine-readable prefix for refusing a request with this error.
    pub fn reason_prefix(&self) -> &'static str {
        match self {
            Self::Message(_) => "invalid",
            Self::Unsupported(_) => "unsupported",
        }
    }
}

#[derive(Clone, Debug, Eq)]
pub struct SubId {
    inner: String,
}

impl SubId {
    /// NIP-01: "an arbitrary, non-empty string of max length 64 chars". Any
    /// character is allowed, since frames JSON-escape the id; the length is
    /// counted in characters, so a non-ASCII id gets all 64.
    pub fn new(val: &str) -> Result<Self, QueryError> {
        if val.is_empty() || val.chars().count() > MAX_SUBID_CHARS {
            return Err(QueryError::msg("invalid subscription id length"));
        }
        Ok(Self {
            inner: val.to_string(),
        })
    }

    pub fn as_str(&self) -> &str {
        &self.inner
    }
}

impl PartialEq for SubId {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl std::hash::Hash for SubId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.inner.hash(state);
    }
}

impl std::fmt::Display for SubId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.inner)
    }
}

#[derive(Clone, Debug)]
pub struct Subscription {
    pub conn_id: u64,
    pub sub_id: SubId,
    pub filter_group: crate::filter::NostrFilterGroup,
    pub count_only: bool,
    /// The newest local event id the history scan may return, then the live
    /// monitor's cursor. `u64::MAX` until set: `QueryScheduler::add_sub`
    /// takes a snapshot for queries that arrive without one.
    pub latest_event_id: u64,
    /// Distinguishes successive REQs that reuse one subscription id, so a
    /// stage can ignore work left over from a replaced one.
    pub generation: u64,
    /// The connection was sent a NIP-42 challenge before this REQ was
    /// admitted, so its EOSE may carry NIP-67's `auth` hint.
    pub auth_challenged: bool,
}

impl Subscription {
    pub fn new(
        conn_id: u64,
        sub_id: SubId,
        filter_group: crate::filter::NostrFilterGroup,
        count_only: bool,
    ) -> Self {
        Self {
            conn_id,
            sub_id,
            filter_group,
            count_only,
            latest_event_id: u64::MAX,
            generation: 0,
            auth_challenged: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subids_are_any_string_of_1_to_64_characters() {
        assert!(SubId::new("").is_err());
        assert!(SubId::new("ok").is_ok());
        assert!(SubId::new(&"x".repeat(64)).is_ok());
        assert!(SubId::new(&"x".repeat(65)).is_err());
        // Counted in characters: 64 two-byte and four-byte characters fit.
        assert!(SubId::new(&"é".repeat(64)).is_ok());
        assert!(SubId::new(&"é".repeat(65)).is_err());
        assert!(SubId::new(&"😀".repeat(64)).is_ok());
        assert!(SubId::new(&"😀".repeat(65)).is_err());
        for id in [
            "has\"quote",
            "has\\slash",
            "tab\there",
            "nul\0",
            "del\u{7f}",
        ] {
            assert_eq!(SubId::new(id).unwrap().as_str(), id);
        }
    }
}
