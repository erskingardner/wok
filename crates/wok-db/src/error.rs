#![allow(unsafe_code)]

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("lmdb error {0}: {1}")]
    Lmdb(i32, String),
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Event(#[from] wok_event::EventError),
}

impl DbError {
    pub fn msg(msg: impl Into<String>) -> Self {
        Self::Message(msg.into())
    }

    pub fn from_rc(rc: i32) -> Self {
        let cstr = unsafe { std::ffi::CStr::from_ptr(lmdb_sys::mdb_strerror(rc)) };
        Self::Lmdb(rc, cstr.to_string_lossy().into_owned())
    }
}

pub fn check(rc: i32) -> Result<(), DbError> {
    if rc == 0 {
        Ok(())
    } else {
        Err(DbError::from_rc(rc))
    }
}
