//! Rebuildable, transactionally maintained NIP-50 content search postings.
//!
//! Each normalized content term is a DUPSORT key whose duplicate values are
//! local event ids. Query execution can therefore start with the rarest term
//! and use exact duplicate lookups to intersect the remaining terms without
//! scanning event payloads that cannot match.

use crate::{DbError, Decompressor, Env, RoTxn, RwTxn};
use lmdb_sys::{MDB_GET_BOTH, MDB_NODUPDATA, MDB_SET};
use serde::Deserialize;
use std::borrow::Cow;
use std::collections::{BTreeSet, HashSet};

const TERM_PREFIX: u8 = 1;
const BIGRAM_PREFIX: u8 = 2;
const INDEXED_THROUGH_KEY: &[u8] = b"\0indexed-through";
const SEARCH_SCHEMA_KEY: &[u8] = b"\0schema";
const SEARCH_SCHEMA_VERSION: u64 = 2;
const MAX_INDEXED_TERM_BYTES: usize = 64;
const BACKFILL_BATCH_SIZE: usize = 10_000;

pub const MAX_SEARCH_QUERY_BYTES: usize = 1_024;
pub const MAX_SEARCH_TERMS: usize = 16;
pub const MAX_INDEXED_UNIQUE_TERMS: usize = 256;
pub const MAX_INDEXED_BIGRAMS: usize = 256;

type SearchIndexEntry = (Vec<u8>, Vec<u8>);
pub type SearchTermSet = HashSet<String>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchQuery {
    pub terms: Vec<String>,
    pub phrase_terms: Vec<String>,
    /// Normalized free-text terms in user order, used for phrase-quality boost.
    pub phrase: String,
}

fn finish_term(current: &mut String, terms: &mut Vec<String>) -> bool {
    if current.is_empty() {
        return false;
    }
    if current.len() <= MAX_INDEXED_TERM_BYTES {
        terms.push(std::mem::take(current));
        false
    } else {
        current.clear();
        true
    }
}

fn normalize_search_terms_with_overflow(text: &str) -> (Vec<String>, bool) {
    let mut terms = Vec::new();
    let mut current = String::new();
    let mut overflow = false;
    for ch in text.chars() {
        if ch.is_alphanumeric() {
            current.extend(ch.to_lowercase());
        } else {
            overflow |= finish_term(&mut current, &mut terms);
        }
    }
    overflow |= finish_term(&mut current, &mut terms);
    (terms, overflow)
}

/// Unicode-aware, case-insensitive word normalization shared by indexing,
/// query parsing, live matching, and scoring.
pub fn normalize_search_terms(text: &str) -> Vec<String> {
    normalize_search_terms_with_overflow(text).0
}

pub fn search_term_set(content: &str) -> SearchTermSet {
    normalize_search_terms(content).into_iter().collect()
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

fn parse_event_content(json: &str) -> Result<Cow<'_, str>, DbError> {
    let event: EventContent<'_> = serde_json::from_str(json)
        .map_err(|error| DbError::msg(format!("event JSON parse failed: {error}")))?;
    Ok(event.content)
}

pub fn event_content(json: &str) -> Result<String, DbError> {
    parse_event_content(json).map(Cow::into_owned)
}

/// Extract only the event content field and normalize it once for all live
/// search subscriptions. This avoids building a full JSON DOM per event.
pub fn event_search_terms(json: &str) -> Result<SearchTermSet, DbError> {
    Ok(search_term_set(&parse_event_content(json)?))
}

fn term_key(term: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + term.len());
    key.push(TERM_PREFIX);
    key.extend_from_slice(term.as_bytes());
    key
}

fn bigram_key(first: &str, second: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(2 + first.len() + second.len());
    key.push(BIGRAM_PREFIX);
    key.extend_from_slice(first.as_bytes());
    key.push(0);
    key.extend_from_slice(second.as_bytes());
    key
}

pub(crate) fn search_index_entries(
    lev_id: u64,
    json: &str,
) -> Result<Vec<SearchIndexEntry>, DbError> {
    let content = event_content(json)?;
    let value = lev_id.to_ne_bytes().to_vec();
    let keys = bounded_index_keys(&content);
    Ok(keys.into_iter().map(|key| (key, value.clone())).collect())
}

/// Build a deterministic, bounded index for untrusted event content.
///
/// The event itself remains bounded by `events.max_event_size`, but without
/// these separate limits one small event containing many distinct words can
/// amplify into thousands of LMDB writes. We retain the first unique terms
/// and bigrams in document order, then stop adding new postings while still
/// scanning the bounded input.
fn bounded_index_keys(content: &str) -> BTreeSet<Vec<u8>> {
    let mut keys = BTreeSet::new();
    let mut term_count = 0;
    let mut bigram_count = 0;
    let mut current = String::new();
    let mut previous = String::new();

    let mut finish = |term: &mut String| {
        if term.is_empty() {
            return;
        }
        if term.len() <= MAX_INDEXED_TERM_BYTES {
            if term_count < MAX_INDEXED_UNIQUE_TERMS && keys.insert(term_key(term)) {
                term_count += 1;
            }
            if !previous.is_empty()
                && bigram_count < MAX_INDEXED_BIGRAMS
                && keys.insert(bigram_key(&previous, term))
            {
                bigram_count += 1;
            }
            previous.clear();
            previous.push_str(term);
        } else {
            previous.clear();
        }
        term.clear();
    };

    for ch in content.chars() {
        if ch.is_alphanumeric() {
            current.extend(ch.to_lowercase());
        } else {
            finish(&mut current);
        }
    }
    finish(&mut current);
    keys
}

pub(crate) fn search_term_from_key(key: &[u8]) -> Option<&str> {
    matches!(key.first(), Some(prefix) if *prefix == TERM_PREFIX || *prefix == BIGRAM_PREFIX)
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

pub fn index_event_search(txn: &mut RwTxn<'_>, lev_id: u64, json: &str) -> Result<(), DbError> {
    let dbi = search_dbi_rw(txn)?;
    for (key, value) in search_index_entries(lev_id, json)? {
        txn.put(dbi, &key, &value, MDB_NODUPDATA)?;
    }
    Ok(())
}

pub fn remove_event_search(txn: &mut RwTxn<'_>, lev_id: u64, json: &str) -> Result<(), DbError> {
    let dbi = search_dbi_rw(txn)?;
    for (key, value) in search_index_entries(lev_id, json)? {
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

pub fn search_bigram_posting_exists(
    txn: &RoTxn<'_>,
    first: &str,
    second: &str,
    lev_id: u64,
) -> Result<bool, DbError> {
    let dbi = search_dbi_ro(txn)?;
    let key = bigram_key(first, second);
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

pub(crate) fn note_search_indexed_through(txn: &mut RwTxn<'_>, lev_id: u64) -> Result<(), DbError> {
    set_indexed_through(txn, lev_id)
}

/// Backfill a newly-created derived search DBI before the environment is used.
/// Progress is committed in bounded batches so importing a large strfry
/// database does not require one unbounded write transaction.
pub(crate) fn ensure_search_index(env: &Env) -> Result<(), DbError> {
    let Some(dbi) = env.dbis().event_search else {
        return Ok(());
    };
    let schema_version = {
        let txn = env.begin_ro()?;
        txn.get(dbi, SEARCH_SCHEMA_KEY)?
            .and_then(|value| value.try_into().ok())
            .map(u64::from_ne_bytes)
    };
    if schema_version != Some(SEARCH_SCHEMA_VERSION) {
        let mut txn = env.begin_rw()?;
        txn.clear(dbi)?;
        initialize_search_index_state(&mut txn, 0)?;
        txn.commit()?;
    }
    loop {
        let indexed_through = {
            let txn = env.begin_ro()?;
            txn.get(dbi, INDEXED_THROUGH_KEY)?
                .and_then(|value| value.try_into().ok())
                .map(u64::from_ne_bytes)
                .unwrap_or(0)
        };

        let mut txn = env.begin_rw()?;
        let mut batch = Vec::with_capacity(BACKFILL_BATCH_SIZE);
        let start = indexed_through.saturating_add(1);
        txn.foreach_full(
            txn.env().dbis().event,
            &start.to_ne_bytes(),
            &[],
            false,
            |key, _| {
                if key.len() != 8 {
                    return true;
                }
                batch.push(u64::from_ne_bytes(key.try_into().unwrap()));
                batch.len() < BACKFILL_BATCH_SIZE
            },
        )?;

        if batch.is_empty() {
            set_indexed_through(&mut txn, indexed_through)?;
            txn.commit()?;
            return Ok(());
        }

        let mut decompressor = Decompressor::new();
        for lev_id in &batch {
            let payload = txn
                .get_u64(txn.env().dbis().event_payload, *lev_id)?
                .ok_or_else(|| DbError::msg(format!("event {lev_id} has no payload")))?
                .to_vec();
            let json = decompressor
                .decode_rw(&txn, &payload, 16 * 1024 * 1024)?
                .to_owned();
            index_event_search(&mut txn, *lev_id, &json)?;
        }
        set_indexed_through(&mut txn, *batch.last().unwrap())?;
        let done = batch.len() < BACKFILL_BATCH_SIZE;
        txn.commit()?;
        if done {
            return Ok(());
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
        let terms =
            event_search_terms(r#"{"content":"A CAF\u00c9\nNostr","ignored":{"nested":[1,2,3]}}"#)
                .unwrap();
        assert_eq!(terms, search_term_set("A CAFÉ\nNostr"));
    }

    #[test]
    fn event_index_growth_is_bounded() {
        let content = (0..10_000)
            .map(|n| format!("term{n}"))
            .collect::<Vec<_>>()
            .join(" ");
        let json = serde_json::json!({"content": content}).to_string();
        let entries = search_index_entries(7, &json).unwrap();
        let terms = entries
            .iter()
            .filter(|(key, _)| key.first() == Some(&TERM_PREFIX))
            .count();
        let bigrams = entries
            .iter()
            .filter(|(key, _)| key.first() == Some(&BIGRAM_PREFIX))
            .count();
        assert_eq!(terms, MAX_INDEXED_UNIQUE_TERMS);
        assert_eq!(bigrams, MAX_INDEXED_BIGRAMS);
        assert!(entries.len() <= MAX_INDEXED_UNIQUE_TERMS + MAX_INDEXED_BIGRAMS);
    }

    #[test]
    fn duplicate_terms_do_not_consume_the_unique_term_budget() {
        let mut words = vec!["repeat".to_string(); MAX_INDEXED_UNIQUE_TERMS * 2];
        words.push("last".into());
        let json = serde_json::json!({"content": words.join(" ")}).to_string();
        let entries = search_index_entries(8, &json).unwrap();
        assert!(entries.iter().any(|(key, _)| key == &term_key("last")));
    }

    #[test]
    fn progress_updates_do_not_rewrite_the_search_schema() {
        let temp = tempfile::tempdir().unwrap();
        let env = Env::open(temp.path(), EnvOptions::default()).unwrap();
        let dbi = env.dbis().event_search.unwrap();
        let sentinel_schema = 99_u64;

        let mut txn = env.begin_rw().unwrap();
        txn.del(dbi, SEARCH_SCHEMA_KEY, None).unwrap();
        txn.put(dbi, SEARCH_SCHEMA_KEY, &sentinel_schema.to_ne_bytes(), 0)
            .unwrap();
        note_search_indexed_through(&mut txn, 42).unwrap();
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
}
