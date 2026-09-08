//! Negentropy protocol, Vector storage, and persistent BTreeLMDB.
//!
//! Byte-compatible with C++ strfry's `external/negentropy` at the pinned
//! reference commit. Protocol version `0x61` (NIP-77 v1).

#![forbid(unsafe_code)]

mod btree;
mod cache;
mod encoding;
mod error;
mod integrity;
mod lmdb_store;
mod protocol;
mod storage;
mod types;
mod vector;

pub use cache::{DeferredSink, NegentropyFilterCache};
pub use error::NegError;
pub use integrity::verify_tree;
pub use lmdb_store::{open_ro, open_rw, BTreeLmdbRo, BTreeLmdbRw};
pub use protocol::Negentropy;
pub use storage::Storage;
pub use types::{Bound, Item, MAX_U64, PROTOCOL_VERSION};
pub use vector::{SubRange, Vector};

pub use btree::{BTreeBackend, BTreeCore, Key, Node, NodePtr, MAX_ITEMS, NODE_SIZE};

/// Conservative reservation for protocol rounds, shared by relay and CLI sync.
pub const ROUND_MEMORY_BYTES: u64 = 4 * 1024 * 1024;

/// Construction peak per filtered event, including query dedup and vector growth.
pub fn memory_view_item_bytes(has_search: bool) -> u64 {
    if has_search {
        1024
    } else {
        256
    }
}
