//! Exact LMDB v3 compatibility for strfry databases.
//!
//! # Transaction safety
//!
//! LMDB transactions, cursors, and mmap-backed slices obtained from this crate
//! must never cross a Tokio `.await` point. Callers should run database work on
//! dedicated OS threads and copy results into owned values before awaiting.

pub mod comparators;
pub mod env;
pub mod error;
pub mod fbs;
pub mod integrity;
pub mod keys;
pub mod payload;
pub mod schema;
pub mod txn;
pub mod write;

pub use env::{Env, EnvOptions};
pub use error::DbError;
pub use fbs::{decode_meta, Meta};
pub use integrity::{check_integrity, IntegrityReport};
pub use payload::{encode_raw_payload, parse_payload, Decompressor, PayloadView};
pub use schema::{dbi_specs, DBI_NAMES};
pub use txn::{RoTxn, RwTxn};
pub use write::{
    delete_event_basic, delete_events, lookup_event_by_id, most_recent_levid, write_events,
    EventToWrite, EventWriteStatus, NegentropySink, NoopNegentropy,
};
