//! Rebuildable, transactionally maintained NIP-50 search postings.
//!
//! An event is searched by its `search_document`: the text of a kind the
//! allow-list names, and nothing for any other kind. Each normalized term of
//! it is a DUPSORT key whose duplicate values are local event ids. Query
//! execution can therefore start with the rarest term and use exact duplicate
//! lookups to intersect the remaining terms without scanning event payloads
//! that cannot match. Word adjacency, which only ranks matches, is read from
//! a matching event's text at query time.
//!
//! Two markers, with keys that no term key matches, describe the table:
//!
//! - `schema` is the key layout. A writable open that finds another layout
//!   empties the table and starts again from local id 0.
//! - `indexed-through` is a local id: every event at or below it has its
//!   postings, and no event above it has any. A search reads the postings for
//!   the events at or below it and reads the events above it directly.
//!
//! Publishing writes no postings: [`build_search_index`] indexes the events
//! above the marker in later, bounded steps, in local-id order, and moves the
//! marker past them. Each step puts a common term's postings for many events
//! at once, so it rewrites that term's pages once rather than once per
//! publication. The relay's writer takes the steps; `wok import` and `wok
//! migrate strfry` finish the index before they exit.

use crate::{DbError, Decompressor, Env, RoTxn, RwTxn};
use lmdb_sys::{MDB_GET_BOTH, MDB_NODUPDATA, MDB_SET};
use serde::de::IgnoredAny;
use serde::Deserialize;
use serde::Serialize;
use std::borrow::Cow;
use std::collections::{BTreeSet, HashSet};
use std::time::{Duration, Instant};
use wok_event::PackedEventView;

const TERM_PREFIX: u8 = 1;
const INDEXED_THROUGH_KEY: &[u8] = b"\0indexed-through";
const SEARCH_SCHEMA_KEY: &[u8] = b"\0schema";
/// 3 dropped the adjacent-term postings (prefix 2) that version 2 kept. 4
/// indexes only the kinds [`TEXT_KINDS`] names, and profiles.
const SEARCH_SCHEMA_VERSION: u64 = 4;
const MAX_INDEXED_TERM_BYTES: usize = 64;
const BACKFILL_BATCH_SIZE: usize = 10_000;
/// The largest stored payload a build step decompresses, as for `wok doctor`.
const BUILD_PAYLOAD_BOUND: usize = 16 * 1024 * 1024;
/// Events a build step reads ahead of indexing them.
const BUILD_CHUNK: usize = 64;

/// Events one build step indexes at most.
pub const SEARCH_BUILD_STEP_EVENTS: usize = 10_000;
/// How long one build step indexes before it commits.
pub const SEARCH_BUILD_STEP_BUDGET: Duration = Duration::from_millis(10);
/// A writer with messages waiting takes a build step only once this many
/// events are unindexed, so that a step indexes many events at once and
/// publications wait behind one step per this many events at most. Every
/// search reads up to this many events directly.
pub const SEARCH_BUILD_BUSY_LAG: u64 = 1_000;

pub const MAX_SEARCH_QUERY_BYTES: usize = 1_024;
pub const MAX_SEARCH_TERMS: usize = 16;
pub const MAX_INDEXED_UNIQUE_TERMS: usize = 256;

/// The kinds whose title tags and content search indexes, in ascending order:
/// the text kinds of the pinned NIPs. Ciphertext, embedded events, lists and
/// other structured content are not indexed. See docs/nip50-search.md.
const TEXT_KINDS: [u64; 31] = [
    1, 9, 11, 20, 21, 22, 42, 54, 1063, 1068, 1111, 1311, 1337, 1618, 1621, 2003, 2004, 7516, 9041,
    9802, 30023, 30402, 30818, 31922, 31923, 31924, 34235, 34236, 37516, 37517, 39701,
];
/// Tags that name a text event, then tags that summarize one. Their values
/// are indexed ahead of its content, names first, so a long summary or
/// content cannot push a title past the unique-term cap. `alt` is in neither:
/// it describes the event for clients that cannot show its kind.
const NAME_TAGS: [&str; 3] = ["title", "subject", "name"];
const SUMMARY_TAGS: [&str; 2] = ["summary", "description"];
/// A profile's metadata fields that search indexes, in indexing order.
const PROFILE_FIELDS: [&str; 4] = ["name", "display_name", "nip05", "about"];

type SearchIndexEntry = (Vec<u8>, Vec<u8>);
pub type SearchTermSet = HashSet<String>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchQuery {
    pub terms: Vec<String>,
    pub phrase_terms: Vec<String>,
    /// Normalized free-text terms in user order, used for phrase-quality boost.
    pub phrase: String,
}

fn normalize_search_terms_with_overflow(text: &str) -> (Vec<String>, bool) {
    let mut terms = Vec::new();
    let mut overflow = false;
    for_each_term(text, |term| {
        match term {
            Some(term) => terms.push(term.to_owned()),
            None => overflow = true,
        }
        true
    });
    (terms, overflow)
}

/// Unicode-aware, case-insensitive word normalization shared by indexing,
/// query parsing, live matching, and scoring.
pub fn normalize_search_terms(text: &str) -> Vec<String> {
    normalize_search_terms_with_overflow(text).0
}

/// The terms of `content` a search can find: its first
/// `MAX_INDEXED_UNIQUE_TERMS` unique terms, in document order, as the index
/// stores them for an event whose search text is `content` alone.
pub fn search_term_set(content: &str) -> SearchTermSet {
    indexed_terms(&[Cow::Borrowed(content)])
}

/// Parse the free-text portion of a NIP-50 query. `key:value` extension words
/// are intentionally ignored, including extensions Wok does not implement.
pub fn parse_search_query(input: &str) -> Result<SearchQuery, DbError> {
    if input.len() > MAX_SEARCH_QUERY_BYTES {
        return Err(DbError::msg(format!(
            "search query exceeds {MAX_SEARCH_QUERY_BYTES} bytes"
        )));
    }
    let free_text = input
        .split_whitespace()
        .filter(|word| {
            let Some((key, value)) = word.split_once(':') else {
                return true;
            };
            key.is_empty() || value.is_empty()
        })
        .collect::<Vec<_>>()
        .join(" ");
    let (ordered, term_overflow) = normalize_search_terms_with_overflow(&free_text);
    if term_overflow {
        return Err(DbError::msg(format!(
            "search term exceeds {MAX_INDEXED_TERM_BYTES} bytes"
        )));
    }
    if ordered.is_empty() {
        return Err(DbError::msg("search query has no searchable terms"));
    }
    if ordered.len() > MAX_SEARCH_TERMS {
        return Err(DbError::msg(format!(
            "search query exceeds {MAX_SEARCH_TERMS} terms"
        )));
    }
    let mut terms = ordered.clone();
    terms.sort();
    terms.dedup();
    Ok(SearchQuery {
        terms,
        phrase_terms: ordered.clone(),
        phrase: ordered.join(" "),
    })
}

#[derive(Deserialize)]
struct EventContent<'a> {
    #[serde(borrow)]
    content: Cow<'a, str>,
}

#[derive(Deserialize)]
struct EventText<'a> {
    #[serde(borrow, default)]
    tags: Vec<Tag<'a>>,
    #[serde(borrow)]
    content: Cow<'a, str>,
}

/// A tag as search reads it. strfry stores tags whose elements are not all
/// strings, such as a NIP-13 nonce's numeric difficulty: search skips what it
/// does not read rather than fail the event.
#[derive(Deserialize)]
#[serde(untagged)]
enum Tag<'a> {
    Elements(#[serde(borrow)] Vec<TagElement<'a>>),
    Other(IgnoredAny),
}

#[derive(Deserialize)]
#[serde(untagged)]
enum TagElement<'a> {
    Text(#[serde(borrow)] Cow<'a, str>),
    Other(IgnoredAny),
}

impl<'a> Tag<'a> {
    /// The tag's name and first value, when both are strings.
    fn name_and_value(self) -> Option<(Cow<'a, str>, Cow<'a, str>)> {
        let Tag::Elements(elements) = self else {
            return None;
        };
        let mut elements = elements.into_iter();
        match (elements.next()?, elements.next()?) {
            (TagElement::Text(name), TagElement::Text(value)) => Some((name, value)),
            _ => None,
        }
    }
}

#[derive(Deserialize)]
struct EventKind {
    kind: u64,
}

fn parse_event<'a, T: Deserialize<'a>>(json: &'a str) -> Result<T, DbError> {
    serde_json::from_str(json)
        .map_err(|error| DbError::msg(format!("event JSON parse failed: {error}")))
}

/// The text an event of `kind` is searched by, in indexing order: for a text
/// kind, its name tags, its summary tags, then its content; for a profile, the metadata fields
/// a person is looked up by. Nothing for any other kind. The index, removal,
/// `wok doctor`, reindex, live matching and the phrase boost all read this,
/// so a stored event and a live one match the same searches.
fn search_document(kind: u64, json: &str) -> Result<Vec<Cow<'_, str>>, DbError> {
    if kind == 0 {
        let content = parse_event::<EventContent<'_>>(json)?.content;
        // Metadata that is not a JSON object has nothing to search.
        let fields: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&content).unwrap_or_default();
        return Ok(PROFILE_FIELDS
            .iter()
            .filter_map(|field| fields.get(*field)?.as_str())
            .map(|value| Cow::Owned(value.to_owned()))
            .collect());
    }
    if TEXT_KINDS.binary_search(&kind).is_err() {
        return Ok(Vec::new());
    }
    let event = parse_event::<EventText<'_>>(json)?;
    let (names, summaries): (Vec<_>, Vec<_>) = event
        .tags
        .into_iter()
        .filter_map(Tag::name_and_value)
        .filter(|(name, _)| {
            NAME_TAGS.contains(&name.as_ref()) || SUMMARY_TAGS.contains(&name.as_ref())
        })
        .partition(|(name, _)| NAME_TAGS.contains(&name.as_ref()));
    let mut document: Vec<_> = names
        .into_iter()
        .chain(summaries)
        .map(|(_, value)| value)
        .collect();
    document.push(event.content);
    Ok(document)
}

/// Parse `json` as far as search reads an event of a text kind, whatever its
/// kind. `wok doctor` reports every payload that fails, not only those of the
/// kinds search indexes.
pub(crate) fn check_event_text(json: &str) -> Result<(), DbError> {
    parse_event::<EventText<'_>>(json).map(drop)
}

/// The `kind` of a stored payload, for one whose PackedEvent cannot be read.
pub(crate) fn payload_kind(json: &str) -> Option<u64> {
    parse_event::<EventKind>(json).ok().map(|event| event.kind)
}

/// The terms an event of `kind` is indexed by, which a live search matches
/// it by too.
pub fn event_search_terms(kind: u64, json: &str) -> Result<SearchTermSet, DbError> {
    Ok(indexed_terms(&search_document(kind, json)?))
}

fn term_key(term: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + term.len());
    key.push(TERM_PREFIX);
    key.extend_from_slice(term.as_bytes());
    key
}

pub(crate) fn search_index_entries(
    lev_id: u64,
    kind: u64,
    json: &str,
) -> Result<Vec<SearchIndexEntry>, DbError> {
    let value = lev_id.to_ne_bytes().to_vec();
    let keys: BTreeSet<_> = indexed_terms(&search_document(kind, json)?)
        .iter()
        .map(|term| term_key(term))
        .collect();
    Ok(keys.into_iter().map(|key| (key, value.clone())).collect())
}

/// Build a deterministic, bounded index for untrusted event text.
///
/// The event itself remains bounded by `events.max_event_size`, but without
/// this separate limit one small event containing many distinct words can
/// amplify into thousands of LMDB writes. We retain the first unique terms in
/// document order and stop adding postings after that.
fn indexed_terms(document: &[Cow<'_, str>]) -> SearchTermSet {
    let mut terms = SearchTermSet::new();
    for_each_document_term(document, |term| {
        if let Some(term) = term {
            if !terms.contains(term) {
                terms.insert(term.to_owned());
            }
        }
        terms.len() < MAX_INDEXED_UNIQUE_TERMS
    });
    terms
}

/// [`for_each_term`] over each piece of `document` in turn. Words in
/// different pieces are not adjacent: `f` sees `None` between them.
fn for_each_document_term(document: &[Cow<'_, str>], mut f: impl FnMut(Option<&str>) -> bool) {
    for text in document {
        if !for_each_term(text, &mut f) || !f(None) {
            return;
        }
    }
}

/// Calls `f` with each normalized term of `text` in document order, or with
/// `None` for a word longer than [`MAX_INDEXED_TERM_BYTES`]: it is never
/// indexed, and it separates the words on either side. Stops once `f`
/// returns false, and returns false if it did.
fn for_each_term(text: &str, mut f: impl FnMut(Option<&str>) -> bool) -> bool {
    let mut current = String::new();
    let mut finish = |current: &mut String| {
        if current.is_empty() {
            return true;
        }
        let more = f((current.len() <= MAX_INDEXED_TERM_BYTES).then_some(current.as_str()));
        current.clear();
        more
    };
    for ch in text.chars() {
        if ch.is_alphanumeric() {
            current.extend(ch.to_lowercase());
        } else if !finish(&mut current) {
            return false;
        }
    }
    finish(&mut current)
}

/// How many of `pairs` occur in the `search_document` of an event of `kind`
/// as adjacent words: the phrase boost a search ranks a match by. A pair
/// listed twice counts twice, as the query named it twice.
pub fn count_phrase_pairs(
    kind: u64,
    json: &str,
    pairs: &[(String, String)],
) -> Result<usize, DbError> {
    if pairs.is_empty() {
        return Ok(0);
    }
    let document = search_document(kind, json)?;
    let mut found = vec![false; pairs.len()];
    let mut remaining = pairs.len();
    let mut previous = String::new();
    for_each_document_term(&document, |term| {
        let Some(term) = term else {
            previous.clear();
            return true;
        };
        if !previous.is_empty() {
            for (seen, (first, second)) in found.iter_mut().zip(pairs) {
                if !*seen && *first == previous && second == term {
                    *seen = true;
                    remaining -= 1;
                }
            }
        }
        previous.clear();
        previous.push_str(term);
        remaining > 0
    });
    Ok(pairs.len() - remaining)
}

pub(crate) fn search_term_from_key(key: &[u8]) -> Option<&str> {
    (key.first() == Some(&TERM_PREFIX))
        .then(|| std::str::from_utf8(&key[1..]).ok())
        .flatten()
}

pub(crate) fn is_search_marker(key: &[u8]) -> bool {
    key == INDEXED_THROUGH_KEY || key == SEARCH_SCHEMA_KEY
}

fn search_dbi_ro(txn: &RoTxn<'_>) -> Result<lmdb_sys::MDB_dbi, DbError> {
    txn.env()
        .dbis()
        .event_search
        .ok_or_else(|| DbError::msg("NIP-50 search index is unavailable"))
}

fn search_dbi_rw(txn: &RwTxn<'_>) -> Result<lmdb_sys::MDB_dbi, DbError> {
    txn.env()
        .dbis()
        .event_search
        .ok_or_else(|| DbError::msg("NIP-50 search index is unavailable"))
}

pub fn index_event_search(
    txn: &mut RwTxn<'_>,
    lev_id: u64,
    kind: u64,
    json: &str,
) -> Result<(), DbError> {
    let dbi = search_dbi_rw(txn)?;
    for (key, value) in search_index_entries(lev_id, kind, json)? {
        txn.put(dbi, &key, &value, MDB_NODUPDATA)?;
    }
    Ok(())
}

pub fn remove_event_search(
    txn: &mut RwTxn<'_>,
    lev_id: u64,
    kind: u64,
    json: &str,
) -> Result<(), DbError> {
    let dbi = search_dbi_rw(txn)?;
    for (key, value) in search_index_entries(lev_id, kind, json)? {
        txn.del(dbi, &key, Some(&value))?;
    }
    Ok(())
}

pub fn search_posting_count(txn: &RoTxn<'_>, term: &str) -> Result<usize, DbError> {
    let dbi = search_dbi_ro(txn)?;
    let key = term_key(term);
    let mut cursor = txn.cursor(dbi)?;
    if cursor.get(Some(&key), None, MDB_SET)?.is_none() {
        return Ok(0);
    }
    cursor.count()
}

pub fn search_posting_exists(txn: &RoTxn<'_>, term: &str, lev_id: u64) -> Result<bool, DbError> {
    let dbi = search_dbi_ro(txn)?;
    let key = term_key(term);
    let value = lev_id.to_ne_bytes();
    let mut cursor = txn.cursor(dbi)?;
    Ok(cursor
        .get(Some(&key), Some(&value), MDB_GET_BOTH)?
        .is_some())
}

/// Visit postings for one exact term from `start_lev_id` in ascending local-id
/// order. Returns true if all postings were visited.
pub fn search_postings<F>(
    txn: &RoTxn<'_>,
    term: &str,
    start_lev_id: u64,
    mut cb: F,
) -> Result<bool, DbError>
where
    F: FnMut(u64) -> bool,
{
    let dbi = search_dbi_ro(txn)?;
    let key = term_key(term);
    let mut callback_stopped = false;
    txn.foreach_full(
        dbi,
        &key,
        &start_lev_id.to_ne_bytes(),
        false,
        |found_key, value| {
            if found_key != key || value.len() != 8 {
                return false;
            }
            let keep_going = cb(u64::from_ne_bytes(value.try_into().unwrap()));
            if !keep_going {
                callback_stopped = true;
            }
            keep_going
        },
    )?;
    Ok(!callback_stopped)
}

fn set_search_schema(txn: &mut RwTxn<'_>) -> Result<(), DbError> {
    let dbi = search_dbi_rw(txn)?;
    txn.del(dbi, SEARCH_SCHEMA_KEY, None)?;
    txn.put(
        dbi,
        SEARCH_SCHEMA_KEY,
        &SEARCH_SCHEMA_VERSION.to_ne_bytes(),
        0,
    )?;
    Ok(())
}

fn set_indexed_through(txn: &mut RwTxn<'_>, lev_id: u64) -> Result<(), DbError> {
    let dbi = search_dbi_rw(txn)?;
    txn.del(dbi, INDEXED_THROUGH_KEY, None)?;
    txn.put(dbi, INDEXED_THROUGH_KEY, &lev_id.to_ne_bytes(), 0)?;
    Ok(())
}

pub(crate) fn initialize_search_index_state(
    txn: &mut RwTxn<'_>,
    lev_id: u64,
) -> Result<(), DbError> {
    set_search_schema(txn)?;
    set_indexed_through(txn, lev_id)
}

fn marker(value: Option<&[u8]>) -> Option<u64> {
    Some(u64::from_ne_bytes(value?.try_into().ok()?))
}

/// Where the search index stands in one snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SearchIndexState {
    /// Every event with a local id at or below this one has its postings, and
    /// no event above it has any.
    pub indexed_through: u64,
    /// The greatest local id ever allocated.
    pub high_water: u64,
}

impl SearchIndexState {
    /// Local ids above the marker: at most this many events are unindexed.
    pub fn lag(&self) -> u64 {
        self.high_water.saturating_sub(self.indexed_through)
    }
}

/// The index's state, or `None` when the database has no search index.
pub fn search_index_state_ro(txn: &RoTxn<'_>) -> Result<Option<SearchIndexState>, DbError> {
    let dbis = txn.env().dbis();
    if dbis.event_search.is_none() {
        return Ok(None);
    }
    let sequence = match dbis.state {
        Some(state) => txn.get(state, crate::state::HIGH_WATER)?,
        None => None,
    };
    Ok(Some(SearchIndexState {
        indexed_through: search_indexed_through_ro(txn)?,
        high_water: crate::tag_kind::high_water(sequence, txn.largest_integer_key(dbis.event)?),
    }))
}

/// The marker in this snapshot: a search reads postings for the events at or
/// below it and reads the events above it.
pub fn search_indexed_through_ro(txn: &RoTxn<'_>) -> Result<u64, DbError> {
    let dbi = search_dbi_ro(txn)?;
    Ok(marker(txn.get(dbi, INDEXED_THROUGH_KEY)?).unwrap_or(0))
}

/// The marker in this write transaction, or `None` when the database has no
/// search index.
pub(crate) fn search_indexed_through_rw(txn: &RwTxn<'_>) -> Result<Option<u64>, DbError> {
    let Some(dbi) = txn.env().dbis().event_search else {
        return Ok(None);
    };
    Ok(Some(
        marker(txn.get(dbi, INDEXED_THROUGH_KEY)?).unwrap_or(0),
    ))
}

/// Empty the index and restart its marker at 0, so that build steps index
/// every stored event again.
pub fn reset_search_index(txn: &mut RwTxn<'_>) -> Result<(), DbError> {
    let Some(dbi) = txn.env().dbis().event_search else {
        return Ok(());
    };
    txn.clear(dbi)?;
    initialize_search_index_state(txn, 0)
}

/// What one build step did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchBuildStep {
    /// Events the step indexed, whether or not their kind is searched.
    pub events: u64,
    /// The index's state once the step commits.
    pub state: SearchIndexState,
}

/// Index, in `txn`, the events above the marker in local-id order, and move
/// the marker past them. A step stops after `max_events` events, or once it
/// has run for `budget`, whichever comes first, and always makes some
/// progress. Once it passes the newest event the marker takes the high-water
/// mark. An event whose postings cannot be derived, with no payload or one
/// that does not decode, is passed over: `wok doctor` reports it. `None` when
/// the database has no search index.
pub fn build_search_index(
    txn: &mut RwTxn<'_>,
    max_events: usize,
    budget: Duration,
) -> Result<Option<SearchBuildStep>, DbError> {
    let started = Instant::now();
    let dbis = txn.env().dbis();
    let Some(dbi) = dbis.event_search else {
        return Ok(None);
    };
    let through = marker(txn.get(dbi, INDEXED_THROUGH_KEY)?).unwrap_or(0);
    let sequence = match dbis.state {
        Some(state) => txn.get(state, crate::state::HIGH_WATER)?,
        None => None,
    };
    let high_water = crate::tag_kind::high_water(sequence, txn.largest_integer_key(dbis.event)?)
        .max(txn.event_sequence.unwrap_or(0));
    let max_events = u64::try_from(max_events.max(1)).unwrap_or(u64::MAX);
    let mut events = 0;
    let mut done = through;
    let mut walked_to_end = through >= high_water;
    let mut decompressor = Decompressor::new();
    'step: while !walked_to_end {
        let mut chunk = Vec::with_capacity(BUILD_CHUNK);
        let at_end = txn.foreach_full(
            dbis.event,
            &done.saturating_add(1).to_ne_bytes(),
            &[],
            false,
            |key, packed| {
                if let Ok(key) = <[u8; 8]>::try_from(key) {
                    // `wok doctor` reports a PackedEvent too short to read.
                    let kind = PackedEventView::new(packed)
                        .ok()
                        .map(|packed| packed.kind());
                    chunk.push((u64::from_ne_bytes(key), kind));
                }
                chunk.len() < BUILD_CHUNK
            },
        )?;
        for (lev_id, kind) in chunk {
            let payload = txn.get_u64(dbis.event_payload, lev_id)?.map(<[u8]>::to_vec);
            if let (Some(kind), Some(payload)) = (kind, payload) {
                if let Ok(json) = decompressor.decode_rw(txn, &payload, BUILD_PAYLOAD_BOUND) {
                    let entries = search_index_entries(lev_id, kind, json);
                    for (key, value) in entries.into_iter().flatten() {
                        txn.put(dbi, &key, &value, MDB_NODUPDATA)?;
                    }
                }
            }
            events += 1;
            done = lev_id;
            if events >= max_events || started.elapsed() >= budget {
                break 'step;
            }
        }
        walked_to_end = at_end;
    }
    let indexed_through = if walked_to_end { high_water } else { done }.max(through);
    if indexed_through != through {
        set_indexed_through(txn, indexed_through)?;
    }
    Ok(Some(SearchBuildStep {
        events,
        state: SearchIndexState {
            indexed_through,
            high_water,
        },
    }))
}

/// On a writable open, empty an index in another layout and restart its
/// marker at 0. Opening does not build it: the relay's writer does, in the
/// background, and [`finish_search_index`] does for a bulk load.
pub(crate) fn ensure_search_index(env: &Env) -> Result<(), DbError> {
    let Some(dbi) = env.dbis().event_search else {
        return Ok(());
    };
    let schema_version = marker(env.begin_ro()?.get(dbi, SEARCH_SCHEMA_KEY)?);
    if schema_version != Some(SEARCH_SCHEMA_VERSION) {
        let mut txn = env.begin_rw()?;
        reset_search_index(&mut txn)?;
        txn.commit()?;
    }
    Ok(())
}

/// Index every event above the marker, committing every 10,000 events so a
/// large database needs no unbounded write transaction. For a process that
/// loaded events in bulk with no relay running: `wok import` and `wok migrate
/// strfry`. Returns the events indexed.
pub fn finish_search_index(env: &Env) -> Result<u64, DbError> {
    let mut events = 0;
    loop {
        let mut txn = env.begin_rw()?;
        let step = build_search_index(&mut txn, BACKFILL_BATCH_SIZE, Duration::MAX)?;
        txn.commit()?;
        match step {
            Some(step) => {
                events += step.events;
                if step.state.lag() == 0 {
                    return Ok(events);
                }
            }
            None => return Ok(events),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EnvOptions;

    #[test]
    fn normalization_is_unicode_case_insensitive() {
        assert_eq!(
            normalize_search_terms("Rust, NOSTR — Café!"),
            vec!["rust", "nostr", "café"]
        );
    }

    #[test]
    fn unsupported_extensions_are_ignored() {
        let query = parse_search_query("best domain:example.com Nostr include:spam").unwrap();
        assert_eq!(query.terms, vec!["best", "nostr"]);
        assert_eq!(query.phrase, "best nostr");
    }

    #[test]
    fn adversarial_term_counts_and_lengths_are_rejected() {
        assert!(parse_search_query(&vec!["term"; MAX_SEARCH_TERMS + 1].join(" ")).is_err());
        assert!(parse_search_query(&"x".repeat(MAX_INDEXED_TERM_BYTES + 1)).is_err());
    }

    #[test]
    fn event_terms_parse_only_content_and_handle_escapes() {
        let terms = event_search_terms(
            1,
            r#"{"content":"A CAF\u00c9\nNostr","ignored":{"nested":[1,2,3]}}"#,
        )
        .unwrap();
        assert_eq!(terms, search_term_set("A CAFÉ\nNostr"));
    }

    #[test]
    fn only_text_kinds_and_profiles_are_searched() {
        assert!(TEXT_KINDS.windows(2).all(|pair| pair[0] < pair[1]));
        let json = serde_json::json!({"content": "plain words"}).to_string();
        for kind in TEXT_KINDS {
            assert_eq!(
                event_search_terms(kind, &json).unwrap(),
                search_term_set("plain words"),
                "kind {kind}"
            );
        }
        // Ciphertext, a repost's embedded event, a follow list, a reaction.
        for kind in [4, 6, 3, 7, 1059, 30000] {
            assert!(
                event_search_terms(kind, &json).unwrap().is_empty(),
                "kind {kind}"
            );
            assert!(search_index_entries(9, kind, &json).unwrap().is_empty());
        }
        // A kind search does not read is not even parsed.
        assert!(event_search_terms(3, "not json").unwrap().is_empty());
        assert!(event_search_terms(1, "not json").is_err());
    }

    #[test]
    fn title_tags_come_before_content_and_alt_is_not_indexed() {
        let content = (0..1_000)
            .map(|n| format!("word{n}"))
            .collect::<Vec<_>>()
            .join(" ");
        let json = serde_json::json!({
            "tags": [
                ["d", "slug"],
                ["summary", format!("Why LMDB {content}")],
                ["alt", "Long-form article: fallback"],
                ["title", "Relay Design"],
                ["t", "hashtag"],
            ],
            "content": "body",
        })
        .to_string();
        // The title is indexed first, though a long summary comes before it.
        let terms = event_search_terms(30023, &json).unwrap();
        assert_eq!(terms.len(), MAX_INDEXED_UNIQUE_TERMS);
        for term in ["relay", "design", "why", "lmdb", "word0", "word251"] {
            assert!(terms.contains(term), "{term}");
        }
        for term in ["slug", "fallback", "hashtag", "word252", "body"] {
            assert!(!terms.contains(term), "{term}");
        }
    }

    /// strfry stores tags whose elements are not all strings, such as a
    /// NIP-13 nonce's numeric difficulty. Search skips them: rebuilding the
    /// index on open, deleting and the doctor all handle such a note.
    #[test]
    fn a_tag_element_that_is_not_a_string_is_skipped() {
        let json = |id: u8| {
            serde_json::json!({
                "id": wok_event::to_hex(&[id; 32]),
                "pubkey": wok_event::to_hex(&[9; 32]),
                "created_at": 1,
                "kind": 1,
                "tags": [["nonce", "7", 21], ["title", 3], [5, "x"], 6, ["subject", "Mined"]],
                "content": "hello world",
                "sig": "00".repeat(64),
            })
            .to_string()
        };
        assert_eq!(
            event_search_terms(1, &json(1)).unwrap(),
            search_term_set("mined hello world")
        );
        assert!(check_event_text(&json(1)).is_ok());

        let temp = tempfile::tempdir().unwrap();
        {
            let env = Env::open(temp.path(), EnvOptions::for_tests()).unwrap();
            env.ensure_initialized().unwrap();
            let mut events: Vec<_> = (1..=2)
                .map(|id| {
                    let packed = wok_event::PackedEventBuilder::build(
                        &[id; 32],
                        &[9; 32],
                        1,
                        1,
                        0,
                        &wok_event::PackedEventTagBuilder::default(),
                    )
                    .unwrap();
                    crate::EventToWrite::new(packed.into_bytes(), json(id))
                })
                .collect();
            let mut txn = env.begin_rw().unwrap();
            crate::write_events(&mut txn, &mut crate::NoopNegentropy, &mut events, false).unwrap();
            // An index on another schema is rebuilt on the next open.
            let dbi = env.dbis().event_search.unwrap();
            txn.del(dbi, SEARCH_SCHEMA_KEY, None).unwrap();
            txn.put(dbi, SEARCH_SCHEMA_KEY, &99_u64.to_ne_bytes(), 0)
                .unwrap();
            txn.commit().unwrap();
        }
        let env = Env::open(temp.path(), EnvOptions::for_tests()).unwrap();
        assert_eq!(finish_search_index(&env).unwrap(), 2);
        let txn = env.begin_ro().unwrap();
        assert_eq!(search_posting_count(&txn, "mined").unwrap(), 2);
        let report = crate::check_integrity(&txn).unwrap();
        assert!(report.ok(), "{:?}", report.issues);
        drop(txn);
        let mut txn = env.begin_rw().unwrap();
        assert!(crate::delete_event_basic(&mut txn, 1).unwrap());
        txn.commit().unwrap();
        let txn = env.begin_ro().unwrap();
        assert_eq!(search_posting_count(&txn, "mined").unwrap(), 1);
        let report = crate::check_integrity(&txn).unwrap();
        assert!(report.ok(), "{:?}", report.issues);
    }

    #[test]
    fn profiles_are_searched_by_their_names_and_about() {
        let profile = |content: &str| serde_json::json!({ "content": content }).to_string();
        let json = profile(
            r#"{"name":"satoshi","display_name":"Satoshi N","about":"Bitcoin author",
                "nip05":"sn@example.com","picture":"https://example.com/a.png",
                "website":"https://bitcoin.org","lud16":12}"#,
        );
        assert_eq!(
            event_search_terms(0, &json).unwrap(),
            search_term_set("satoshi n sn example com bitcoin author")
        );
        // Metadata that is not a JSON object, and fields that are not
        // strings, have nothing to search.
        assert!(event_search_terms(0, &profile("satoshi"))
            .unwrap()
            .is_empty());
        assert!(event_search_terms(0, &profile(r#"{"name":7}"#))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn event_index_growth_is_bounded() {
        let content = (0..10_000)
            .map(|n| format!("term{n}"))
            .collect::<Vec<_>>()
            .join(" ");
        let json = serde_json::json!({"content": content}).to_string();
        let entries = search_index_entries(7, 1, &json).unwrap();
        assert_eq!(entries.len(), MAX_INDEXED_UNIQUE_TERMS);
        assert!(entries
            .iter()
            .all(|(key, _)| key.first() == Some(&TERM_PREFIX)));
        assert!(entries.iter().any(|(key, _)| key == &term_key("term255")));
    }

    #[test]
    fn phrase_pairs_are_read_from_the_content() {
        let pairs = |query: &[&str]| {
            query
                .windows(2)
                .map(|pair| (pair[0].to_string(), pair[1].to_string()))
                .collect::<Vec<_>>()
        };
        let event = |content: &str| serde_json::json!({ "content": content }).to_string();
        let json = event("The Best NOSTR apps, best of all");
        assert_eq!(
            count_phrase_pairs(1, &json, &pairs(&["best", "nostr", "apps"])).unwrap(),
            2
        );
        assert_eq!(
            count_phrase_pairs(1, &json, &pairs(&["nostr", "best"])).unwrap(),
            0
        );
        // A pair the query names twice counts twice.
        assert_eq!(
            count_phrase_pairs(1, &json, &pairs(&["best", "nostr", "best", "nostr"])).unwrap(),
            2
        );
        // A word too long to index separates its neighbours.
        let long = "x".repeat(MAX_INDEXED_TERM_BYTES + 1);
        let json = event(&format!("best {long} nostr"));
        assert_eq!(
            count_phrase_pairs(1, &json, &pairs(&["best", "nostr"])).unwrap(),
            0
        );
        // Unlike the old adjacent-term postings, there is no cap: a pair is
        // found however far into the content it is.
        let mut words: Vec<String> = (0..1_000).map(|n| format!("w{n}")).collect();
        words.extend(["late".into(), "pair".into()]);
        let json = event(&words.join(" "));
        assert_eq!(
            count_phrase_pairs(1, &json, &pairs(&["late", "pair"])).unwrap(),
            1
        );
        assert_eq!(count_phrase_pairs(1, &json, &[]).unwrap(), 0);
        // A title and the content are separate: words across them are not
        // adjacent.
        let json = serde_json::json!({
            "tags": [["title", "the best"]],
            "content": "nostr apps",
        })
        .to_string();
        assert_eq!(
            count_phrase_pairs(11, &json, &pairs(&["the", "best", "nostr", "apps"])).unwrap(),
            2
        );
        // A kind search does not read has no phrases.
        assert_eq!(
            count_phrase_pairs(4, &json, &pairs(&["nostr", "apps"])).unwrap(),
            0
        );
    }

    #[test]
    fn live_terms_are_the_indexed_terms() {
        let mut words = vec!["inside".to_string()];
        words.extend((1..MAX_INDEXED_UNIQUE_TERMS).map(|n| format!("filler{n}")));
        words.extend(["inside".into(), "zebra".into()]);
        let json = serde_json::json!({"content": words.join(" ")}).to_string();
        let indexed: SearchTermSet = search_index_entries(9, 1, &json)
            .unwrap()
            .into_iter()
            .filter(|(key, _)| key.first() == Some(&TERM_PREFIX))
            .map(|(key, _)| search_term_from_key(&key).unwrap().to_owned())
            .collect();
        let live = event_search_terms(1, &json).unwrap();
        assert_eq!(live, indexed);
        assert_eq!(live.len(), MAX_INDEXED_UNIQUE_TERMS);
        assert!(live.contains("inside"));
        assert!(!live.contains("zebra"));
    }

    #[test]
    fn duplicate_terms_do_not_consume_the_unique_term_budget() {
        let mut words = vec!["repeat".to_string(); MAX_INDEXED_UNIQUE_TERMS * 2];
        words.push("last".into());
        let json = serde_json::json!({"content": words.join(" ")}).to_string();
        let entries = search_index_entries(8, 1, &json).unwrap();
        assert!(entries.iter().any(|(key, _)| key == &term_key("last")));
    }

    #[test]
    fn progress_updates_do_not_rewrite_the_search_schema() {
        let temp = tempfile::tempdir().unwrap();
        let env = Env::open(temp.path(), EnvOptions::for_tests()).unwrap();
        let dbi = env.dbis().event_search.unwrap();
        let sentinel_schema = 99_u64;

        let mut txn = env.begin_rw().unwrap();
        txn.del(dbi, SEARCH_SCHEMA_KEY, None).unwrap();
        txn.put(dbi, SEARCH_SCHEMA_KEY, &sentinel_schema.to_ne_bytes(), 0)
            .unwrap();
        set_indexed_through(&mut txn, 42).unwrap();
        txn.commit().unwrap();

        let txn = env.begin_ro().unwrap();
        assert_eq!(
            txn.get(dbi, SEARCH_SCHEMA_KEY).unwrap(),
            Some(sentinel_schema.to_ne_bytes().as_slice())
        );
        assert_eq!(
            txn.get(dbi, INDEXED_THROUGH_KEY).unwrap(),
            Some(42_u64.to_ne_bytes().as_slice())
        );
    }

    fn note(time: u64, content: &str) -> crate::EventToWrite {
        use secp256k1::{Keypair, SecretKey, SECP256K1};
        let secret = SecretKey::from_byte_array(&[7; 32]).unwrap();
        let key = Keypair::from_secret_key(SECP256K1, &secret);
        let mut value = serde_json::json!({"pubkey":hex::encode(key.x_only_public_key().0.serialize()),
            "kind":1,"created_at":time,"tags":[],"content":content});
        let id = wok_event::event_id_hash(&value).unwrap();
        value["id"] = serde_json::json!(hex::encode(id));
        value["sig"] = serde_json::json!(hex::encode(
            SECP256K1.sign_schnorr_no_aux_rand(&id, &key).as_ref()
        ));
        let parsed =
            wok_event::parse_and_verify_event(&value, &Default::default(), None, true, false)
                .unwrap();
        crate::EventToWrite::new(parsed.packed.into_bytes(), parsed.json)
    }

    fn notes(contents: &[&str]) -> (tempfile::TempDir, Env) {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), EnvOptions::for_tests()).unwrap();
        env.ensure_initialized().unwrap();
        for (time, content) in (100..).zip(contents) {
            let mut events = [note(time, content)];
            let mut txn = env.begin_rw().unwrap();
            crate::write_events(&mut txn, &mut crate::NoopNegentropy, &mut events, false).unwrap();
            txn.commit().unwrap();
        }
        finish_search_index(&env).unwrap();
        (dir, env)
    }

    fn postings(env: &Env) -> usize {
        let txn = env.begin_ro().unwrap();
        let mut count = 0;
        txn.foreach_full(
            env.dbis().event_search.unwrap(),
            &[],
            &[],
            false,
            |key, _| {
                count += usize::from(!is_search_marker(key));
                true
            },
        )
        .unwrap();
        count
    }

    fn reset(env: &Env) {
        let mut txn = env.begin_rw().unwrap();
        reset_search_index(&mut txn).unwrap();
        txn.commit().unwrap();
    }

    /// One build step of at most `max_events`: events indexed, and the marker.
    fn step(env: &Env, max_events: usize) -> (u64, u64) {
        let mut txn = env.begin_rw().unwrap();
        let step = build_search_index(&mut txn, max_events, Duration::MAX)
            .unwrap()
            .unwrap();
        txn.commit().unwrap();
        (step.events, step.state.indexed_through)
    }

    fn assert_consistent(env: &Env) {
        let report = crate::check_integrity(&env.begin_ro().unwrap()).unwrap();
        assert!(report.ok(), "{:#?}", report.issues);
    }

    #[test]
    fn publishing_leaves_postings_to_build_steps() {
        let (_dir, env) = notes(&["one alpha"]);
        let mut events = [note(200, "two alpha"), note(201, "three alpha")];
        let mut txn = env.begin_rw().unwrap();
        crate::write_events(&mut txn, &mut crate::NoopNegentropy, &mut events, false).unwrap();
        txn.commit().unwrap();
        let txn = env.begin_ro().unwrap();
        assert_eq!(search_posting_count(&txn, "alpha").unwrap(), 1);
        let state = search_index_state_ro(&txn).unwrap().unwrap();
        assert_eq!((state.indexed_through, state.lag()), (1, 2));
        drop(txn);
        assert_consistent(&env);

        // Deleting an event above the marker has no postings to remove, and
        // the build passes over it.
        let mut txn = env.begin_rw().unwrap();
        assert!(crate::delete_event_basic(&mut txn, 3).unwrap());
        txn.commit().unwrap();
        assert_eq!(finish_search_index(&env).unwrap(), 1);
        let txn = env.begin_ro().unwrap();
        assert_eq!(search_posting_count(&txn, "alpha").unwrap(), 2);
        let state = search_index_state_ro(&txn).unwrap().unwrap();
        assert_eq!((state.indexed_through, state.lag()), (3, 0));
        drop(txn);
        assert_eq!(finish_search_index(&env).unwrap(), 0);
        assert_consistent(&env);
    }

    #[test]
    fn build_steps_index_the_events_above_the_marker_up_to_the_high_water_mark() {
        let (_dir, env) = notes(&["one alpha", "two beta", "three gamma", "four", "five"]);
        let mut txn = env.begin_rw().unwrap();
        crate::delete_events(&mut txn, &mut crate::NoopNegentropy, [4, 5]).unwrap();
        txn.commit().unwrap();
        let indexed = postings(&env);
        assert_eq!(indexed, 6);

        reset(&env);
        assert_eq!(postings(&env), 0);
        let state = search_index_state_ro(&env.begin_ro().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!((state.indexed_through, state.lag()), (0, 5));
        // Events above the marker need no postings.
        assert_consistent(&env);

        assert_eq!(step(&env, 2), (2, 2));
        assert_eq!(postings(&env), 4);
        assert_consistent(&env);
        // The last stored event ends the walk at the deleted tail's end.
        assert_eq!(step(&env, 2), (1, 5));
        assert_eq!(postings(&env), indexed);
        assert_consistent(&env);
        assert_eq!(step(&env, 2), (0, 5));
    }

    #[test]
    fn a_posting_above_the_marker_is_unexpected() {
        let (_dir, env) = notes(&["alpha", "beta"]);
        reset(&env);
        let mut txn = env.begin_rw().unwrap();
        index_event_search(&mut txn, 2, 1, r#"{"content":"beta"}"#).unwrap();
        txn.commit().unwrap();
        let report = crate::check_integrity(&env.begin_ro().unwrap()).unwrap();
        assert!(!report.ok());
        assert!(report
            .issues
            .iter()
            .any(|issue| issue.table == "event_search"
                && issue.detail.contains("above indexed-through 0")));
    }

    #[test]
    fn a_build_step_passes_over_an_event_it_cannot_read() {
        let (_dir, env) = notes(&["alpha", "beta"]);
        reset(&env);
        let mut txn = env.begin_rw().unwrap();
        txn.del_u64(env.dbis().event_payload, 1, None).unwrap();
        txn.commit().unwrap();
        assert_eq!(step(&env, 10), (2, 2));
        assert_eq!(postings(&env), 1);
    }
}
