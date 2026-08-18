//! Wok's LMDB storage and the read-only strfry v3 migration boundary.
//!
//! # Transaction safety
//!
//! LMDB transactions, cursors, and mmap-backed slices obtained from this crate
//! must never cross a Tokio `.await` point. Callers should run database work on
//! dedicated OS threads and copy results into owned values before awaiting.

#![deny(unsafe_code, unsafe_op_in_unsafe_fn)]

pub mod comparators;
pub mod env;
pub mod error;
pub mod fbs;
pub mod integrity;
pub mod keys;
pub mod lookup;
pub mod migration;
pub mod moderation;
pub mod payload;
pub mod reindex;
pub mod schema;
pub mod search;
pub mod txn;
pub mod vanish;
pub mod write;

pub use env::{Env, EnvOptions, EnvironmentStats};
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
pub use moderation::{
    allow_event, allow_kind, allow_pubkey, allowed_pubkey_reason_ro, assign_role, ban_event,
    ban_pubkey, banned_event_reason_ro, banned_pubkey_reason_ro, block_ip, blocked_ip_reason_ro,
    clear_reported_event, delete_role, disallow_kind, is_event_moderated_ro, kind_policy_ro,
    list_allowed_pubkeys_ro, list_banned_events_ro, list_banned_pubkeys_ro, list_blocked_ips_ro,
    list_reported_events_ro, list_roles_ro, load_moderation_snapshot_ro, moderation_reason_ro,
    pubkey_roles_ro, put_role, report_event, unallow_pubkey, unassign_role, unban_pubkey,
    unblock_ip, KindPolicy, ModerationReason, ModerationSnapshot, Role, BUILTIN_ROLES,
    BUILTIN_ROLE_ADMIN, BUILTIN_ROLE_MEMBER, BUILTIN_ROLE_MODERATOR, MAX_REASON_BYTES,
};
pub use payload::{
    encode_raw_payload, encode_zstd_payload, event_json_owned, get_event_json, parse_payload,
    Decompressor, PayloadView, PAYLOAD_RAW, PAYLOAD_ZSTD,
};
pub use reindex::{rebuild_primary_and_event_indices, ReindexStats};
pub use schema::{dbi_specs, DBI_NAMES};
pub use search::{
    event_content, event_search_terms, index_event_search, normalize_search_terms,
    parse_search_query, remove_event_search, search_bigram_posting_exists, search_posting_count,
    search_posting_exists, search_postings, search_term_set, SearchQuery, SearchTermSet,
    MAX_SEARCH_QUERY_BYTES, MAX_SEARCH_TERMS,
};
pub use txn::{RoTxn, RwTxn};
pub use vanish::{
    backfill_vanish_markers, is_event_vanished_ro, is_event_vanished_rw, mark_vanished,
    sweep_vanished_events, vanish_timestamp_ro, vanish_timestamp_rw, VanishPolicy, ALL_RELAYS,
    VANISH_KIND,
};
pub use write::{
    delete_event_basic, delete_events, lookup_event_by_id, most_recent_levid, write_events,
    write_events_with_policy, EventToWrite, EventWriteStatus, NegentropySink, NoopNegentropy,
};
