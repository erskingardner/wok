//! Event models, NIP-01 canonical hashing, Schnorr verification, and PackedEvent.
//!
//! Byte layouts and validation rules follow C++ strfry at
//! `9acdaeb1f63919184ece5f2dd67af21f1ed62f1b`.

mod error;
mod hash;
mod kinds;
mod packed;
mod parse;
mod validate;

pub use error::EventError;
pub use hash::{event_id_hash, sha256, verify_id, verify_sig};
pub use kinds::{is_ephemeral_kind, is_param_replaceable_kind, is_replaceable_kind, parse_a_tag};
pub use packed::{
    is_event_a_before_event_b, PackedEvent, PackedEventBuilder, PackedEventTag, PackedEventTagBuilder,
    PackedEventView,
};
pub use parse::{from_hex, normalize_event_json, nostr_json_to_packed_event, to_hex, EventLimits, ParsedEvent};
pub use validate::{
    parse_and_verify_event, verify_event_json_size, verify_event_timestamp, verify_nostr_event,
    TimestampPolicy,
};

pub const MAX_SUBID_SIZE: usize = 64;
pub const MAX_INDEXED_TAG_VAL_SIZE: usize = 255;
pub const CURR_DB_VERSION: u64 = 3;
pub const AUTH_KIND: u64 = 22242;
pub const DELETION_KIND: u64 = 5;
pub const GIFT_WRAP_KINDS: [u64; 2] = [1059, 21059];
pub const REPOST_KINDS: [u64; 2] = [6, 16];
pub const PROTECTED_TAG: char = '-';
pub const AUTH_CHALLENGE_LEN: usize = 22;
