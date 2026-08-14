//! Negentropy protocol, Vector storage, and persistent BTreeLMDB.
//!
//! Byte-compatible with C++ strfry's `external/negentropy` at the pinned
//! reference commit. Protocol version `0x61` (NIP-77 v1).

#![forbid(unsafe_code)]

mod btree;
mod cache;
mod encoding;
mod error;
mod lmdb_store;
mod protocol;
mod storage;
mod types;
mod vector;

pub use cache::{DeferredSink, NegentropyFilterCache};
pub use error::NegError;
pub use lmdb_store::{open_ro, open_rw, BTreeLmdbRo, BTreeLmdbRw};
pub use protocol::Negentropy;
pub use storage::Storage;
pub use types::{Bound, Item, MAX_U64, PROTOCOL_VERSION};
pub use vector::{SubRange, Vector};

pub use btree::{MAX_ITEMS, NODE_SIZE};
