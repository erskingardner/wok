//! Wok's LMDB storage and the read-only strfry v3 migration boundary.
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
pub mod lookup;
pub mod migration;
pub mod payload;
pub mod schema;
pub mod txn;
pub mod write;

pub use env::{Env, EnvOptions};
pub use error::DbError;
pub use fbs::{
    decode_compression_dictionary, decode_meta, decode_negentropy_filter,
    encode_compression_dictionary, encode_meta, encode_negentropy_filter, CompressionDictionaryRec,
    Meta, NegentropyFilterRec,
};
pub use integrity::{check_integrity, IntegrityIssue, IntegrityReport};
pub use lookup::{
    bump_negentropy_mod_counter, foreach_created_at, foreach_event_from, foreach_negentropy_filter,
    foreach_negentropy_filter_rw, get_compression_dictionary_ro, get_packed_ro, get_payload_ro,
    insert_compression_dictionary, insert_negentropy_filter, lookup_event_by_id_ro,
    most_recent_levid_ro,
};
pub use migration::{event_fingerprint, snapshot_lmdb_readonly, EventFingerprint};
pub use payload::{
    encode_raw_payload, encode_zstd_payload, event_json_owned, get_event_json, parse_payload,
    Decompressor, PayloadView, PAYLOAD_RAW, PAYLOAD_ZSTD,
};
pub use schema::{dbi_specs, DBI_NAMES};
pub use txn::{RoTxn, RwTxn};
pub use write::{
    delete_event_basic, delete_events, lookup_event_by_id, most_recent_levid, write_events,
    EventToWrite, EventWriteStatus, NegentropySink, NoopNegentropy,
};
