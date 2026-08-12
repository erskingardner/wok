use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EventError {
    #[error("{0}")]
    Message(String),
}

impl EventError {
    pub fn msg(msg: impl Into<String>) -> Self {
        Self::Message(msg.into())
    }
}

impl From<String> for EventError {
    fn from(value: String) -> Self {
        Self::Message(value)
    }
}
