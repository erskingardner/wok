use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NegError {
    #[error("{0}")]
    Message(String),
}

impl NegError {
    pub fn msg(m: impl Into<String>) -> Self {
        Self::Message(m.into())
    }
}

impl From<wok_db::DbError> for NegError {
    fn from(value: wok_db::DbError) -> Self {
        Self::Message(value.to_string())
    }
}
