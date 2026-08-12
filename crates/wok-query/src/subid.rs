use thiserror::Error;
use wok_event::MAX_SUBID_SIZE;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum QueryError {
    #[error("{0}")]
    Message(String),
}

impl QueryError {
    pub fn msg(m: impl Into<String>) -> Self {
        Self::Message(m.into())
    }
}

#[derive(Clone, Debug, Eq)]
pub struct SubId {
    inner: String,
}

impl SubId {
    pub fn new(val: &str) -> Result<Self, QueryError> {
        if val.is_empty() || val.len() > MAX_SUBID_SIZE {
            return Err(QueryError::msg("invalid subscription id length"));
        }
        if val
            .bytes()
            .any(|c| c < 0x20 || c == b'\\' || c == b'"' || c >= 0x7F)
        {
            return Err(QueryError::msg("invalid character in subscription id"));
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
    pub latest_event_id: u64,
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_subids() {
        assert!(SubId::new("").is_err());
        assert!(SubId::new(&"x".repeat(65)).is_err());
        assert!(SubId::new("ok").is_ok());
        assert!(SubId::new("has\"quote").is_err());
        assert!(SubId::new("has\\slash").is_err());
    }
}
