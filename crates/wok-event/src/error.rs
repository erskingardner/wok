use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EventError {
    #[error("{0}")]
    Message(String),
    /// Valid protocol metadata that this relay cannot accept under policy.
    #[error("{0}")]
    Restricted(Box<str>),
    /// The event is over a limit the caller chose, in [`EventLimits`] or a
    /// [`TimestampPolicy`], so a relay can say which of its settings
    /// refused it. Boxed, so the error and every `Result` that carries it
    /// stay the size of a `String`.
    ///
    /// [`EventLimits`]: crate::EventLimits
    /// [`TimestampPolicy`]: crate::TimestampPolicy
    #[error("{}", .0.1)]
    Limit(Box<(EventLimit, String)>),
}

/// The bound an [`EventError::Limit`] broke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventLimit {
    /// `EventLimits::max_event_size`.
    EventSize,
    /// `EventLimits::max_num_tags`.
    NumTags,
    /// `EventLimits::max_tag_val_size`, for a tag value or the `a` tag a
    /// `d` tag would make.
    TagValSize,
    /// `TimestampPolicy::reject_older_than_secs`.
    TooOld,
    /// `TimestampPolicy::reject_newer_than_secs`.
    TooNew,
    /// `TimestampPolicy::reject_ephemeral_older_than_secs`.
    EphemeralTooOld,
}

impl EventError {
    pub fn msg(msg: impl Into<String>) -> Self {
        Self::Message(msg.into())
    }

    pub fn limit(limit: EventLimit, msg: impl Into<String>) -> Self {
        Self::Limit(Box::new((limit, msg.into())))
    }

    pub fn restricted(msg: impl Into<String>) -> Self {
        Self::Restricted(msg.into().into_boxed_str())
    }

    /// NIP-01 rejection category, without the trailing colon.
    pub fn rejection_prefix(&self) -> &'static str {
        match self {
            Self::Restricted(_) => "restricted",
            _ => "invalid",
        }
    }

    /// The limit this error reports, when it is one.
    pub fn broken_limit(&self) -> Option<EventLimit> {
        match self {
            Self::Message(_) | Self::Restricted(_) => None,
            Self::Limit(limit) => Some(limit.0),
        }
    }
}

// `DbError` and the query scheduler's errors carry this one.
const _: () = assert!(std::mem::size_of::<EventError>() == std::mem::size_of::<String>());

impl From<String> for EventError {
    fn from(value: String) -> Self {
        Self::Message(value)
    }
}
