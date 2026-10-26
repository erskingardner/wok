//! What the read scenarios (`ws_query_latency`, `deep_history_pagination`
//! and `mixed_read_write`) expect from a relay that imported a corpus.
//!
//! - [`retention`] is what a relay keeps: each id once, no ephemeral event,
//!   the newest version of each replaceable and addressable address, and no
//!   event its author deleted with a kind 5 `e` tag. A social corpus
//!   (`--event-mix social`) exercises all of it; the other mixes are kept
//!   whole.
//! - [`Corpus::expected`] answers a filter as NIP-01 does, newest first. Where
//!   a `limit` cuts through one second, any of that second's events may fill
//!   the reply: strfry and Wok send a second's events in arrival order, not
//!   lowest id first (`docs/known-differences.md`).
//! - [`Corpus::filters`] is the `ws_query_latency` plan. A social corpus gets
//!   the archive reads of #226 scenario B; the other mixes keep the shapes
//!   earlier campaigns measured.
//!
//! [`Corpus::load`] streams the corpus on every core and keeps each event
//! compact: its id, author, kind and `created_at`, a [`digest`] of the
//! whole event, and its single-letter tags as interned keys. That is a
//! couple of hundred bytes an event rather than the event, so #226's
//! 50M-event tier fits a load host.
//!
//! No plan reads a kind that Wok serves only to its authenticated recipient
//! ([`RECIPIENT_ONLY`]) and strfry serves to anyone, and every filter has a
//! `limit` of at most 500, strfry's and Wok 0.7's `maxFilterLimit`.

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::borrow::Cow;
use std::cmp::{Ordering, Reverse};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::BufRead;
use std::path::Path;

use crate::social::Limits;
use crate::EventMix;

/// Kinds Wok serves only to their authenticated recipient (gift wraps and
/// NIP-04 DMs), and so not at all with AUTH off. strfry serves them to
/// anyone (#226 §8).
const RECIPIENT_ONLY: [u64; 3] = [4, 1_059, 21_059];
/// The most events a social filter asks for.
const LIMIT: u64 = 500;
/// A follow list's first authors that an author lookup names. 500 hex keys
/// take 34 KB, within every relay's default filter size.
const AUTHORS: usize = 500;
/// Spreads successive queries of a shape over a pool.
const STRIDE: usize = 7_919;
/// Lines parsed together, split across every core.
const BATCH: usize = 1 << 16;
/// [`Record::d`] of an event that is not addressable.
const NO_D: u32 = u32::MAX;

fn kind(event: &Value) -> u64 {
    event["kind"].as_u64().unwrap_or_default()
}

fn id(event: &Value) -> &str {
    event["id"].as_str().unwrap_or_default()
}

fn pubkey(event: &Value) -> &str {
    event["pubkey"].as_str().unwrap_or_default()
}

fn created_at(event: &Value) -> u64 {
    event["created_at"].as_u64().unwrap_or_default()
}

fn tags(event: &Value) -> &[Value] {
    event["tags"].as_array().map_or(&[][..], Vec::as_slice)
}

/// The first value of each `name` tag.
fn tag_values<'a>(event: &'a Value, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    tags(event)
        .iter()
        .filter(move |tag| tag[0] == name)
        .filter_map(|tag| tag[1].as_str())
}

fn ephemeral(kind: u64) -> bool {
    (20_000..30_000).contains(&kind)
}

fn replaceable(kind: u64) -> bool {
    kind == 0 || kind == 3 || (10_000..20_000).contains(&kind)
}

fn addressable(kind: u64) -> bool {
    (30_000..40_000).contains(&kind)
}

/// 64 lowercase hex characters, as bytes.
fn hex32(value: &str) -> Option<[u8; 32]> {
    let mut bytes = [0; 32];
    let lowercase = value
        .bytes()
        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    (lowercase && hex::decode_to_slice(value, &mut bytes).is_ok()).then_some(bytes)
}

/// A hash of every field of an event, which [`Expected::matches`] compares
/// in place of the event. Each string and list is length-prefixed, so no two
/// events share the input.
fn digest<S: AsRef<str>>(
    id: &str,
    pubkey: &str,
    created_at: u64,
    kind: u64,
    tags: &[Vec<S>],
    content: &str,
    sig: &str,
) -> u64 {
    let mut hasher = DefaultHasher::new();
    let mut text = |value: &str| {
        hasher.write_usize(value.len());
        hasher.write(value.as_bytes());
    };
    text(id);
    text(pubkey);
    text(content);
    text(sig);
    hasher.write_u64(created_at);
    hasher.write_u64(kind);
    hasher.write_usize(tags.len());
    for tag in tags {
        hasher.write_usize(tag.len());
        for value in tag {
            let value = value.as_ref();
            hasher.write_usize(value.len());
            hasher.write(value.as_bytes());
        }
    }
    hasher.finish()
}

/// [`digest`] of an event a relay sent, if it is one: an object of exactly
/// the seven NIP-01 fields.
fn value_digest(event: &Value) -> Option<u64> {
    let object = event.as_object()?;
    if object.len() != 7 {
        return None;
    }
    let tags = event["tags"]
        .as_array()?
        .iter()
        .map(|tag| tag.as_array()?.iter().map(Value::as_str).collect())
        .collect::<Option<Vec<Vec<&str>>>>()?;
    Some(digest(
        event["id"].as_str()?,
        event["pubkey"].as_str()?,
        event["created_at"].as_u64()?,
        event["kind"].as_u64()?,
        &tags,
        event["content"].as_str()?,
        event["sig"].as_str()?,
    ))
}

/// What retention reads of one event.
struct Seen<I, A, D> {
    id: I,
    author: A,
    kind: u64,
    created_at: u64,
    /// An addressable event's first `d` value, or the same value for every
    /// other event of the author and kind.
    d: D,
}

/// Which of `count` events a relay keeps once it has imported them, whatever
/// the order. Replacement keeps the latest `created_at`, and on a tie the
/// lowest id (NIP-01). A kind 5 deletes its author's events named by `e`
/// tags (`deletions`: target and author), except other deletions, as Wok
/// does; strfry deletes those too, but no generated corpus names a deletion.
fn retain<I, A, D>(
    count: usize,
    event: impl Fn(usize) -> Seen<I, A, D>,
    deletions: impl IntoIterator<Item = (I, A)>,
) -> Vec<bool>
where
    I: Copy + Eq + Hash + Ord,
    A: Copy + Eq + Hash,
    D: Copy + Eq + Hash,
{
    let mut kept = vec![false; count];
    let mut ids = HashSet::with_capacity(count);
    let mut newest: HashMap<(A, u64, D), usize> = HashMap::new();
    for (index, kept) in kept.iter_mut().enumerate() {
        let seen = event(index);
        if ephemeral(seen.kind) || !ids.insert(seen.id) {
            continue;
        }
        if !replaceable(seen.kind) && !addressable(seen.kind) {
            *kept = true;
            continue;
        }
        match newest.entry((seen.author, seen.kind, seen.d)) {
            Entry::Vacant(slot) => {
                slot.insert(index);
            }
            Entry::Occupied(mut slot) => {
                let stored = event(*slot.get());
                if (seen.created_at, Reverse(seen.id)) > (stored.created_at, Reverse(stored.id)) {
                    slot.insert(index);
                }
            }
        }
    }
    drop(ids);
    for index in newest.into_values() {
        kept[index] = true;
    }
    let deleted: HashSet<(I, A)> = deletions.into_iter().collect();
    for (index, kept) in kept.iter_mut().enumerate() {
        if *kept {
            let seen = event(index);
            *kept = seen.kind == 5 || !deleted.contains(&(seen.id, seen.author));
        }
    }
    kept
}

/// [`retain`] for events in memory.
pub(crate) fn retention(events: &[Value]) -> Vec<bool> {
    retain(
        events.len(),
        |index| {
            let event = &events[index];
            Seen {
                id: id(event),
                author: pubkey(event),
                kind: kind(event),
                created_at: created_at(event),
                d: if addressable(kind(event)) {
                    tag_values(event, "d").next().unwrap_or_default()
                } else {
                    ""
                },
            }
        },
        events
            .iter()
            .filter(|event| kind(event) == 5)
            .flat_map(|event| tag_values(event, "e").map(|target| (target, pubkey(event)))),
    )
}

/// A corpus line as [`Corpus::load`] reads it. Other fields are refused: a
/// relay would not send them back.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Line<'a> {
    #[serde(borrow)]
    id: Cow<'a, str>,
    #[serde(borrow)]
    pubkey: Cow<'a, str>,
    created_at: u64,
    kind: u64,
    #[serde(borrow)]
    tags: Vec<Vec<Text<'a>>>,
    #[serde(borrow)]
    content: Cow<'a, str>,
    #[serde(borrow)]
    sig: Cow<'a, str>,
}

/// A tag string, borrowed from the line unless it has escapes.
#[derive(Deserialize)]
struct Text<'a>(#[serde(borrow)] Cow<'a, str>);

impl AsRef<str> for Text<'_> {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// A single-letter tag's value.
#[derive(Clone, PartialEq, Eq, Hash)]
enum TagValue {
    Hex([u8; 32]),
    Other(Box<str>),
}

impl TagValue {
    fn new(value: &str) -> Self {
        hex32(value).map_or_else(|| Self::Other(value.into()), Self::Hex)
    }

    fn render(&self) -> String {
        match self {
            Self::Hex(bytes) => hex::encode(bytes),
            Self::Other(text) => text.to_string(),
        }
    }
}

/// One event, parsed off the loading thread.
struct Parsed {
    id: [u8; 32],
    author: [u8; 32],
    kind: u64,
    created_at: u64,
    digest: u64,
    /// Single-letter tags with a value, in order.
    tags: Vec<(char, TagValue)>,
}

impl Parsed {
    fn from_line(line: &str, limits: &mut Limits) -> Result<Self> {
        let event: Line = serde_json::from_str(line)?;
        limits.observe_tags(
            line,
            event.tags.len(),
            event.tags.iter().map(|tag| {
                (
                    tag.first().map_or("", AsRef::as_ref),
                    tag.get(1).map(AsRef::as_ref),
                )
            }),
        );
        let hex = |name: &str, value: &str| {
            hex32(value).with_context(|| format!("{name} is not 64 lowercase hex characters"))
        };
        Ok(Self {
            id: hex("id", &event.id)?,
            author: hex("pubkey", &event.pubkey)?,
            kind: event.kind,
            created_at: event.created_at,
            digest: digest(
                &event.id,
                &event.pubkey,
                event.created_at,
                event.kind,
                &event.tags,
                &event.content,
                &event.sig,
            ),
            tags: event
                .tags
                .iter()
                .filter_map(|tag| {
                    let mut name = tag.first()?.0.chars();
                    let letter = name.next().filter(|_| name.next().is_none())?;
                    Some((letter, TagValue::new(&tag.get(1)?.0)))
                })
                .collect(),
        })
    }
}

/// One event, as the oracle keeps it.
struct Record {
    id: [u8; 32],
    /// [`digest`] of the whole event.
    digest: u64,
    created_at: u64,
    kind: u64,
    author: u32,
    /// An addressable event's first `d` value, as a tag key ([`NO_D`] for
    /// other events).
    d: u32,
}

/// A corpus as a relay holds it once imported, indexed for the oracle.
pub(crate) struct Corpus {
    records: Vec<Record>,
    kept: Vec<bool>,
    retained: u64,
    limits: Limits,
    /// Pubkeys, by author number.
    authors: Vec<[u8; 32]>,
    author_numbers: HashMap<[u8; 32], u32>,
    /// Single-letter tags (`(letter, value)`), by key.
    values: Vec<(char, TagValue)>,
    keys: HashMap<(char, TagValue), u32>,
    /// Each event's tag keys, in order: those of event `i` are
    /// `tag_keys[tag_start[i]..tag_start[i + 1]]`.
    tag_start: Vec<u64>,
    tag_keys: Vec<u32>,
    /// Kept events by id.
    by_id: Vec<u32>,
    /// Kept events by author: those of author `a` are
    /// `by_author[author_start[a]..author_start[a + 1]]`.
    author_start: Vec<u64>,
    by_author: Vec<u32>,
    /// Kept events by tag key, as sorted `(key, event)` pairs.
    by_tag: Vec<(u32, u32)>,
}

/// The events a correct reply holds: all of `required`, and `take` of
/// `tied`, the matches in the second a `limit` cuts through.
pub(crate) struct Expected<'a> {
    corpus: &'a Corpus,
    required: Vec<u32>,
    tied: Vec<u32>,
    take: usize,
}

impl Expected<'_> {
    /// Events in a correct reply.
    pub fn len(&self) -> usize {
        self.required.len() + self.take
    }

    /// The oldest `created_at` in a correct reply, whichever of a cut
    /// second's events it holds.
    pub fn oldest(&self) -> Option<u64> {
        let last = if self.take > 0 {
            self.tied.first()
        } else {
            self.required.last()
        };
        last.map(|&index| self.corpus.record(index).created_at)
    }

    /// Whether `actual` holds exactly the events this allows, each once and
    /// unchanged.
    pub fn matches(&self, actual: &[Value]) -> bool {
        if actual.len() != self.len() {
            return false;
        }
        let wanted: HashMap<&[u8; 32], (u64, bool)> = self
            .required
            .iter()
            .map(|&index| (index, true))
            .chain(self.tied.iter().map(|&index| (index, false)))
            .map(|(index, required)| {
                let record = self.corpus.record(index);
                (&record.id, (record.digest, required))
            })
            .collect();
        let mut seen = HashSet::new();
        let mut required = 0;
        for event in actual {
            let Some(id) = event["id"].as_str().and_then(hex32) else {
                return false;
            };
            let Some(&(digest, is_required)) = wanted.get(&id) else {
                return false;
            };
            if !seen.insert(id) || value_digest(event) != Some(digest) {
                return false;
            }
            required += usize::from(is_required);
        }
        required == self.required.len()
    }
}

/// A filter, in the corpus's terms. Values the corpus lacks are dropped, as
/// they match nothing.
struct Query {
    ids: Option<Vec<[u8; 32]>>,
    authors: Option<Vec<u32>>,
    kinds: Option<Vec<u64>>,
    since: Option<u64>,
    until: Option<u64>,
    /// Each tag condition's keys.
    tags: Vec<Vec<u32>>,
    limit: Option<u64>,
}

/// Loads a corpus an event at a time.
#[derive(Default)]
struct Builder {
    records: Vec<Record>,
    limits: Limits,
    authors: Vec<[u8; 32]>,
    author_numbers: HashMap<[u8; 32], u32>,
    values: Vec<(char, TagValue)>,
    keys: HashMap<(char, TagValue), u32>,
    tag_start: Vec<u64>,
    tag_keys: Vec<u32>,
    /// Each kind 5 `e` tag's target and author.
    deletions: Vec<([u8; 32], u32)>,
}

impl Builder {
    fn author(&mut self, pubkey: [u8; 32]) -> u32 {
        *self.author_numbers.entry(pubkey).or_insert_with(|| {
            self.authors.push(pubkey);
            (self.authors.len() - 1) as u32
        })
    }

    fn key(&mut self, letter: char, value: TagValue) -> u32 {
        match self.keys.entry((letter, value)) {
            Entry::Occupied(slot) => *slot.get(),
            Entry::Vacant(slot) => {
                let key = self.values.len() as u32;
                self.values.push(slot.key().clone());
                *slot.insert(key)
            }
        }
    }

    fn push(&mut self, event: Parsed) -> Result<()> {
        anyhow::ensure!(
            self.records.len() < u32::MAX as usize,
            "the read oracle holds at most {} events",
            u32::MAX
        );
        let author = self.author(event.author);
        self.tag_start.push(self.tag_keys.len() as u64);
        let mut d = None;
        for (letter, value) in event.tags {
            if let (5, 'e', TagValue::Hex(target)) = (event.kind, letter, &value) {
                self.deletions.push((*target, author));
            }
            let key = self.key(letter, value);
            if letter == 'd' {
                d.get_or_insert(key);
            }
            self.tag_keys.push(key);
        }
        let d = if addressable(event.kind) {
            d.unwrap_or_else(|| self.key('d', TagValue::new("")))
        } else {
            NO_D
        };
        self.records.push(Record {
            id: event.id,
            digest: event.digest,
            created_at: event.created_at,
            kind: event.kind,
            author,
            d,
        });
        Ok(())
    }

    fn finish(mut self) -> Corpus {
        self.tag_start.push(self.tag_keys.len() as u64);
        let records = &self.records;
        let kept = retain(
            records.len(),
            |index| {
                let record = &records[index];
                Seen {
                    id: &record.id,
                    author: record.author,
                    kind: record.kind,
                    created_at: record.created_at,
                    d: record.d,
                }
            },
            self.deletions
                .iter()
                .map(|(target, author)| (target, *author)),
        );
        let kept_indices = || (0..records.len() as u32).filter(|&index| kept[index as usize]);
        let mut by_id: Vec<u32> = kept_indices().collect();
        by_id.sort_unstable_by(|&a, &b| records[a as usize].id.cmp(&records[b as usize].id));
        let mut author_start = vec![0u64; self.authors.len() + 1];
        for index in kept_indices() {
            author_start[records[index as usize].author as usize + 1] += 1;
        }
        for author in 0..self.authors.len() {
            author_start[author + 1] += author_start[author];
        }
        let mut by_author = vec![0u32; by_id.len()];
        let mut next = author_start.clone();
        for index in kept_indices() {
            let slot = &mut next[records[index as usize].author as usize];
            by_author[*slot as usize] = index;
            *slot += 1;
        }
        let tag_keys = |index: u32| {
            let index = index as usize;
            &self.tag_keys[self.tag_start[index] as usize..self.tag_start[index + 1] as usize]
        };
        let mut by_tag: Vec<(u32, u32)> = kept_indices()
            .flat_map(|index| tag_keys(index).iter().map(move |&key| (key, index)))
            .collect();
        by_tag.sort_unstable();
        by_tag.dedup();
        Corpus {
            retained: by_id.len() as u64,
            records: self.records,
            kept,
            limits: self.limits,
            authors: self.authors,
            author_numbers: self.author_numbers,
            values: self.values,
            keys: self.keys,
            tag_start: self.tag_start,
            tag_keys: self.tag_keys,
            by_id,
            author_start,
            by_author,
            by_tag,
        }
    }
}

impl Corpus {
    /// Stream a JSONL corpus, parsing [`BATCH`] lines at a time on every
    /// core.
    pub fn load(path: &Path) -> Result<Self> {
        let mut reader = std::io::BufReader::with_capacity(1 << 20, std::fs::File::open(path)?);
        Self::from_lines(|line| {
            line.clear();
            let read = reader.read_line(line)?;
            if line.ends_with('\n') {
                line.pop();
                if line.ends_with('\r') {
                    line.pop();
                }
            }
            Ok(read > 0)
        })
    }

    /// Build a corpus from `next_line`, which fills its buffer with the next
    /// line and says whether there was one.
    fn from_lines(mut next_line: impl FnMut(&mut String) -> Result<bool>) -> Result<Self> {
        let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
        let mut builder = Builder::default();
        let mut number = 0usize;
        let mut done = false;
        while !done {
            let mut lines = Vec::with_capacity(BATCH);
            while lines.len() < BATCH {
                let mut line = String::new();
                if !next_line(&mut line)? {
                    done = true;
                    break;
                }
                number += 1;
                if !line.trim().is_empty() {
                    lines.push((number, line));
                }
            }
            let parts: Vec<Result<(Vec<Parsed>, Limits)>> = std::thread::scope(|scope| {
                let workers: Vec<_> = lines
                    .chunks(lines.len().div_ceil(threads).max(1))
                    .map(|part| {
                        scope.spawn(move || {
                            let mut limits = Limits::default();
                            let parsed = part
                                .iter()
                                .map(|(number, line)| {
                                    Parsed::from_line(line, &mut limits)
                                        .with_context(|| format!("corpus line {number}"))
                                })
                                .collect::<Result<Vec<_>>>()?;
                            Ok((parsed, limits))
                        })
                    })
                    .collect();
                workers
                    .into_iter()
                    .map(|worker| worker.join().expect("corpus parser panicked"))
                    .collect()
            });
            for part in parts {
                let (parsed, limits) = part?;
                builder.limits.merge(limits);
                for event in parsed {
                    builder.push(event)?;
                }
            }
        }
        Ok(builder.finish())
    }

    fn record(&self, index: u32) -> &Record {
        &self.records[index as usize]
    }

    fn tags(&self, index: u32) -> &[u32] {
        let index = index as usize;
        &self.tag_keys[self.tag_start[index] as usize..self.tag_start[index + 1] as usize]
    }

    /// The event's values of `letter` tags, in order.
    fn tag_values(&self, index: u32, letter: char) -> impl Iterator<Item = u32> + '_ {
        self.tags(index)
            .iter()
            .copied()
            .filter(move |&key| self.values[key as usize].0 == letter)
    }

    fn kept_indices(&self) -> impl Iterator<Item = u32> + '_ {
        (0..self.records.len() as u32).filter(|&index| self.kept[index as usize])
    }

    fn hex_id(&self, index: u32) -> String {
        hex::encode(self.record(index).id)
    }

    fn hex_author(&self, index: u32) -> String {
        hex::encode(self.authors[self.record(index).author as usize])
    }

    /// Lines in the corpus.
    pub fn lines(&self) -> u64 {
        self.records.len() as u64
    }

    /// Events a relay keeps.
    pub fn retained(&self) -> u64 {
        self.retained
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// The author of the corpus's first event of `kind`.
    pub fn first_author(&self, kind: u64) -> Option<String> {
        (0..self.records.len() as u32)
            .find(|&index| self.record(index).kind == kind)
            .map(|index| self.hex_author(index))
    }

    /// The author with the most kept events (of `kind`, if given), and how
    /// many. Ties go to the lower pubkey.
    pub fn busiest_author(&self, kind: Option<u64>) -> Option<(String, u64)> {
        let mut counts = vec![0u64; self.authors.len()];
        for index in self.kept_indices() {
            let record = self.record(index);
            if kind.is_none_or(|kind| record.kind == kind) {
                counts[record.author as usize] += 1;
            }
        }
        let (author, count) = counts
            .iter()
            .enumerate()
            .filter(|&(_, &count)| count > 0)
            .max_by_key(|&(author, &count)| (count, Reverse(&self.authors[author])))?;
        Some((hex::encode(self.authors[author]), *count))
    }

    /// `filter` in the corpus's terms. The harness's filters use only
    /// `ids`, `authors`, `kinds`, `since`, `until`, `limit` and
    /// single-letter tags.
    fn query(&self, filter: &Value) -> Query {
        fn strings(condition: &Value) -> Vec<&str> {
            condition
                .as_array()
                .unwrap()
                .iter()
                .filter_map(Value::as_str)
                .collect()
        }
        let mut query = Query {
            ids: None,
            authors: None,
            kinds: None,
            since: None,
            until: None,
            tags: Vec::new(),
            limit: None,
        };
        for (key, condition) in filter.as_object().unwrap() {
            match key.as_str() {
                "ids" => {
                    let mut ids: Vec<_> =
                        strings(condition).into_iter().filter_map(hex32).collect();
                    ids.sort_unstable();
                    query.ids = Some(ids);
                }
                "authors" => {
                    let mut authors: Vec<u32> = strings(condition)
                        .into_iter()
                        .filter_map(|author| self.author_numbers.get(&hex32(author)?).copied())
                        .collect();
                    authors.sort_unstable();
                    query.authors = Some(authors);
                }
                "kinds" => {
                    let kinds = condition.as_array().unwrap().iter();
                    query.kinds = Some(kinds.filter_map(Value::as_u64).collect());
                }
                "since" => query.since = Some(condition.as_u64().unwrap()),
                "until" => query.until = Some(condition.as_u64().unwrap()),
                "limit" => query.limit = Some(condition.as_u64().unwrap()),
                tag if tag.starts_with('#') && tag.chars().count() == 2 => {
                    let letter = tag.chars().nth(1).unwrap();
                    let mut keys: Vec<u32> = strings(condition)
                        .into_iter()
                        .filter_map(|value| self.keys.get(&(letter, TagValue::new(value))).copied())
                        .collect();
                    keys.sort_unstable();
                    query.tags.push(keys);
                }
                _ => panic!("unsupported benchmark oracle filter: {key}"),
            }
        }
        query
    }

    /// Whether kept event `index` matches `query`.
    fn matches(&self, query: &Query, index: u32) -> bool {
        let record = self.record(index);
        query
            .ids
            .as_ref()
            .is_none_or(|ids| ids.binary_search(&record.id).is_ok())
            && query
                .authors
                .as_ref()
                .is_none_or(|authors| authors.binary_search(&record.author).is_ok())
            && query
                .kinds
                .as_ref()
                .is_none_or(|kinds| kinds.contains(&record.kind))
            && query.since.is_none_or(|since| record.created_at >= since)
            && query.until.is_none_or(|until| record.created_at <= until)
            && query.tags.iter().all(|keys| {
                self.tags(index)
                    .iter()
                    .any(|key| keys.binary_search(key).is_ok())
            })
    }

    /// Kept events that may match `query`: those its `ids`, `authors` or
    /// first tag condition name, or all of them.
    fn candidates(&self, query: &Query) -> Vec<u32> {
        let mut indices: Vec<u32> = if let Some(ids) = &query.ids {
            ids.iter()
                .filter_map(|id| {
                    let at = self
                        .by_id
                        .binary_search_by(|&index| self.record(index).id.cmp(id))
                        .ok()?;
                    Some(self.by_id[at])
                })
                .collect()
        } else if let Some(authors) = &query.authors {
            authors
                .iter()
                .flat_map(|&author| {
                    let author = author as usize;
                    let (start, end) = (self.author_start[author], self.author_start[author + 1]);
                    &self.by_author[start as usize..end as usize]
                })
                .copied()
                .collect()
        } else if let Some(keys) = query.tags.first() {
            keys.iter()
                .flat_map(|&key| {
                    let start = self.by_tag.partition_point(|&(k, _)| k < key);
                    let end = self.by_tag.partition_point(|&(k, _)| k <= key);
                    self.by_tag[start..end].iter().map(|&(_, index)| index)
                })
                .collect()
        } else {
            return self.kept_indices().collect();
        };
        indices.sort_unstable();
        indices.dedup();
        indices
    }

    /// The reply a relay that imported this corpus gives to `filter`.
    pub fn expected(&self, filter: &Value) -> Expected<'_> {
        let query = self.query(filter);
        let mut matches: Vec<u32> = self
            .candidates(&query)
            .into_iter()
            .filter(|&index| self.matches(&query, index))
            .collect();
        let newest_first = |a: &u32, b: &u32| -> Ordering {
            let (a, b) = (self.record(*a), self.record(*b));
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| a.id.cmp(&b.id))
        };
        let limit = query
            .limit
            .map_or(usize::MAX, |limit| limit.min(usize::MAX as u64) as usize);
        let expected = |required, tied, take| Expected {
            corpus: self,
            required,
            tied,
            take,
        };
        if matches.len() <= limit {
            matches.sort_unstable_by(newest_first);
            return expected(matches, Vec::new(), 0);
        }
        if limit == 0 {
            return expected(Vec::new(), Vec::new(), 0);
        }
        // Only the newest `limit` and their last second are wanted, so pick
        // them out rather than sort every match.
        matches.select_nth_unstable_by(limit - 1, newest_first);
        let cut = self.record(matches[limit - 1]).created_at;
        let (mut required, mut tied): (Vec<u32>, Vec<u32>) = matches
            .into_iter()
            .filter(|&index| self.record(index).created_at >= cut)
            .partition(|&index| self.record(index).created_at > cut);
        required.sort_unstable_by(newest_first);
        tied.sort_unstable_by(newest_first);
        let take = limit - required.len();
        expected(required, tied, take)
    }

    /// `count` filters for `ws_query_latency`.
    pub fn filters(&self, count: u64, mix: EventMix) -> Result<Vec<Value>> {
        if mix == EventMix::Social {
            self.social_filters(count)
        } else {
            self.mixed_filters(count)
        }
    }

    /// An id, an author's notes, the newest notes, and a `#t` topic: the
    /// shapes campaigns measured before the social corpus.
    fn mixed_filters(&self, count: u64) -> Result<Vec<Value>> {
        let all = self.records.len();
        let notes: Vec<u32> = (0..all as u32)
            .filter(|&index| self.record(index).kind == 1)
            .collect();
        anyhow::ensure!(!notes.is_empty(), "query corpus has no kind 1 events");
        Ok((0..count as usize)
            .map(|q| {
                let event = ((q * 7) % all) as u32;
                let note = notes[(q * 11) % notes.len()];
                match q % 4 {
                    0 => json!({"ids":[self.hex_id(event)]}),
                    1 => json!({"authors":[self.hex_author(note)],"kinds":[1],"limit":50}),
                    2 => json!({"kinds":[1],"since":self.record(note).created_at,"limit":20}),
                    _ => json!({"#t":[format!("tag-{}", q % 64)],"limit":50}),
                }
            })
            .collect())
    }

    /// #226 scenario B's archive reads, in turn:
    /// - an id, of any event a relay serves, kept or not;
    /// - profiles, follow lists and relay lists of a follow list's authors;
    /// - those authors' notes and reposts;
    /// - notes, reposts, reactions and zaps that tag a pubkey;
    /// - the follow lists that name it;
    /// - the replies, reposts, reactions, zaps and comments on a note;
    /// - the newest notes.
    ///
    /// Tagged pubkeys and notes are those reactions name, so popular ones
    /// come up more often.
    fn social_filters(&self, count: u64) -> Result<Vec<Value>> {
        let lookups: Vec<u32> = (0..self.records.len() as u32)
            .filter(|&index| !RECIPIENT_ONLY.contains(&self.record(index).kind))
            .collect();
        let mut follow_lists = Vec::new();
        let mut mentioned = Vec::new();
        let mut threads = Vec::new();
        let mut notes = Vec::new();
        for index in self.kept_indices() {
            let record = self.record(index);
            match record.kind {
                1 => notes.push(record.created_at),
                3 if self.tag_values(index, 'p').next().is_some() => follow_lists.push(index),
                7 => {
                    mentioned.extend(self.tag_values(index, 'p').next());
                    threads.extend(self.tag_values(index, 'e').next());
                }
                _ => {}
            }
        }
        anyhow::ensure!(
            !lookups.is_empty()
                && !follow_lists.is_empty()
                && !mentioned.is_empty()
                && !threads.is_empty()
                && !notes.is_empty(),
            "a social query corpus needs notes, follow lists and reactions"
        );
        let pick = |q: usize, len: usize| (q * STRIDE) % len;
        let value = |key: u32| self.values[key as usize].1.render();
        let follows = |q: usize| -> Vec<String> {
            let list = follow_lists[pick(q, follow_lists.len())];
            self.tag_values(list, 'p')
                .take(AUTHORS)
                .map(value)
                .collect()
        };
        Ok((0..count as usize)
            .map(|q| match q % 7 {
                0 => json!({"ids":[self.hex_id(lookups[pick(q, lookups.len())])]}),
                1 => json!({
                    "authors": follows(q),
                    "kinds": [0, 3, 10_002],
                    "limit": LIMIT,
                }),
                2 => json!({
                    "authors": follows(q),
                    "kinds": [1, 6],
                    "limit": LIMIT,
                }),
                3 => json!({
                    "#p": [value(mentioned[pick(q, mentioned.len())])],
                    "kinds": [1, 6, 7, 9_735],
                    "limit": LIMIT,
                }),
                4 => json!({
                    "#p": [value(mentioned[pick(q, mentioned.len())])],
                    "kinds": [3],
                    "limit": LIMIT,
                }),
                5 => json!({
                    "#e": [value(threads[pick(q, threads.len())])],
                    "kinds": [1, 6, 7, 9_735, 1_111],
                    "limit": LIMIT,
                }),
                _ => json!({
                    "kinds": [1],
                    "since": notes[pick(q, notes.len())],
                    "limit": 20,
                }),
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// The 64-hex value that stands for `name`.
    fn h(name: &str) -> String {
        hex::encode(Sha256::digest(name))
    }

    /// An event whose id and pubkey stand for the names given.
    fn event(id: &str, pubkey: &str, kind: u64, created_at: u64, tags: Value) -> Value {
        json!({
            "id": h(id),
            "pubkey": h(pubkey),
            "kind": kind,
            "created_at": created_at,
            "tags": tags,
            "content": "",
            "sig": "",
        })
    }

    fn corpus(events: &[Value]) -> Corpus {
        let mut lines = events.iter();
        Corpus::from_lines(|line| {
            let Some(event) = lines.next() else {
                return Ok(false);
            };
            *line = event.to_string();
            Ok(true)
        })
        .unwrap()
    }

    fn names(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| h(name)).collect()
    }

    fn ids(events: &[Value], kept: &[bool]) -> Vec<String> {
        events
            .iter()
            .zip(kept)
            .filter(|(_, &kept)| kept)
            .map(|(e, _)| id(e).to_owned())
            .collect()
    }

    #[test]
    fn retention_replaces_deletes_and_drops_ephemeral_and_repeated_events() {
        let events = vec![
            event("note", "alice", 1, 10, json!([])),
            event("reaction", "alice", 7, 11, json!([["e", h("note")]])),
            event("profile-new", "alice", 0, 30, json!([])),
            event("profile-old", "alice", 0, 20, json!([])),
            // Same second: the lower id wins.
            event("list-b", "alice", 10_002, 40, json!([])),
            event("list-a", "alice", 10_002, 40, json!([])),
            event("article-1", "alice", 30_023, 50, json!([["d", "x"]])),
            event("article-2", "alice", 30_023, 60, json!([["d", "x"]])),
            event("article-3", "alice", 30_023, 55, json!([["d", "y"]])),
            // No `d` tag is the empty one.
            event("untitled-1", "alice", 30_023, 56, json!([])),
            event("untitled-2", "alice", 30_023, 57, json!([["d", ""]])),
            // Bob cannot delete Alice's note; Alice deletes her reaction and
            // a deletion, which stays.
            event("bob-delete", "bob", 5, 70, json!([["e", h("note")]])),
            event(
                "delete",
                "alice",
                5,
                80,
                json!([["e", h("reaction")], ["e", h("bob-delete")]]),
            ),
            event("again", "alice", 5, 81, json!([["e", h("delete")]])),
            event("ephemeral", "alice", 20_001, 90, json!([])),
            event("note", "alice", 1, 10, json!([])),
        ];
        let kept = retention(&events);
        let list_a = if h("list-a") < h("list-b") {
            "list-a"
        } else {
            "list-b"
        };
        assert_eq!(
            ids(&events, &kept),
            names(&[
                "note",
                "profile-new",
                list_a,
                "article-2",
                "article-3",
                "untitled-2",
                "bob-delete",
                "delete",
                "again"
            ])
        );
        // The loaded corpus keeps the same events.
        let corpus = corpus(&events);
        assert_eq!(corpus.kept, kept);
        assert_eq!(corpus.retained(), 9);
    }

    #[test]
    fn a_limit_through_a_second_accepts_any_of_its_events() {
        let all = [
            event("a", "p", 1, 30, json!([])),
            event("b", "p", 1, 20, json!([])),
            event("c", "p", 1, 20, json!([])),
            event("d", "p", 1, 20, json!([])),
            event("e", "p", 1, 10, json!([])),
        ];
        let corpus = corpus(&all);
        let expected = corpus.expected(&json!({"kinds":[1],"limit":3}));
        assert_eq!(expected.len(), 3);
        assert!(expected.matches(&[all[0].clone(), all[3].clone(), all[1].clone()]));
        assert!(expected.matches(&[all[2].clone(), all[3].clone(), all[0].clone()]));
        // Missing the newer event, a repeat, an older event, or one short.
        assert!(!expected.matches(&[all[1].clone(), all[2].clone(), all[3].clone()]));
        assert!(!expected.matches(&[all[0].clone(), all[1].clone(), all[1].clone()]));
        assert!(!expected.matches(&[all[0].clone(), all[1].clone(), all[4].clone()]));
        assert!(!expected.matches(&[all[0].clone(), all[1].clone()]));
        // A changed field, tag or extra field is not the event.
        for change in [
            json!({"content": "altered"}),
            json!({"sig": "00"}),
            json!({"tags": [["t", "x"]]}),
            json!({"extra": 1}),
        ] {
            let mut altered = all[1].clone();
            for (key, value) in change.as_object().unwrap() {
                altered[key] = value.clone();
            }
            assert!(!expected.matches(&[all[0].clone(), all[2].clone(), altered]));
        }
        // A page ends in the cut second, whichever of its events it holds.
        assert_eq!(expected.oldest(), Some(20));
        // Nothing cut: the set is exact.
        let whole = corpus.expected(&json!({"kinds":[1],"limit":5}));
        assert!(whole.matches(&all));
        assert_eq!(whole.oldest(), Some(10));
        let none = corpus.expected(&json!({"limit":0}));
        assert!(none.matches(&[]));
        assert_eq!(none.oldest(), None);
    }

    #[test]
    fn the_oracle_answers_from_kept_events_only() {
        let corpus = corpus(&[
            event("note", "alice", 1, 10, json!([["p", h("bob")]])),
            event("gone", "alice", 1, 11, json!([["p", h("bob")]])),
            event("delete", "alice", 5, 12, json!([["e", h("gone")]])),
            event("old", "bob", 3, 13, json!([["p", h("alice")]])),
            event("new", "bob", 3, 14, json!([["p", h("carol")]])),
        ]);
        let reply = |filter: Value| -> Vec<String> {
            let expected = corpus.expected(&filter);
            assert!(expected.tied.is_empty());
            expected
                .required
                .iter()
                .map(|&index| corpus.hex_id(index))
                .collect()
        };
        assert_eq!(reply(json!({"ids":[h("gone")]})), Vec::<String>::new());
        assert_eq!(
            reply(json!({"#p":[h("bob")],"kinds":[1]})),
            names(&["note"])
        );
        assert_eq!(
            reply(json!({"#p":[h("alice")],"kinds":[3]})),
            Vec::<String>::new()
        );
        assert_eq!(
            reply(json!({"authors":[h("bob"),h("alice")]})),
            names(&["new", "delete", "note"])
        );
        assert_eq!(
            reply(json!({"authors":[h("nobody")]})),
            Vec::<String>::new()
        );
        assert_eq!(corpus.retained(), 3);
        assert_eq!(corpus.busiest_author(None), Some((h("alice"), 2)));
        assert_eq!(corpus.busiest_author(Some(3)), Some((h("bob"), 1)));
        assert_eq!(corpus.first_author(3), Some(h("bob")));
    }

    #[test]
    fn a_line_with_other_fields_or_short_ids_is_refused() {
        let line = |event: Value| Parsed::from_line(&event.to_string(), &mut Limits::default());
        let mut extra = event("a", "p", 1, 1, json!([]));
        extra["seen_on"] = json!([]);
        assert!(line(extra).is_err());
        let mut short = event("a", "p", 1, 1, json!([]));
        short["id"] = json!("ab");
        assert!(line(short).is_err());
        let mut upper = event("a", "p", 1, 1, json!([]));
        upper["pubkey"] = json!(h("p").to_uppercase());
        assert!(line(upper).is_err());
    }

    /// The social plan, and the reply to each filter, as the in-memory
    /// oracle (`retention`, `crate::matches_filter`) has them.
    #[test]
    fn social_plans_use_full_values_and_match_the_in_memory_oracle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("corpus.jsonl");
        let opts = crate::social::Options {
            events: 6_000,
            authors: 200,
            seed: 2,
            anchor: 1_760_000_000,
            max_follows: 300,
        };
        let summary = crate::social::generate(&path, &opts).unwrap();
        let corpus = Corpus::load(&path).unwrap();
        assert_eq!(corpus.retained(), summary.retained);
        assert_eq!(corpus.limits(), summary.limits);
        let events: Vec<Value> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let kept: Vec<&Value> = events
            .iter()
            .zip(retention(&events))
            .filter_map(|(event, kept)| kept.then_some(event))
            .collect();
        assert_eq!(kept.len() as u64, corpus.retained());
        let filters = corpus.filters(700, EventMix::Social).unwrap();
        let mut answered = [0usize; 7];
        for (q, filter) in filters.iter().enumerate() {
            assert!(filter["limit"].as_u64().is_none_or(|limit| limit <= LIMIT));
            for key in ["ids", "authors", "#p", "#e"] {
                for value in filter[key].as_array().into_iter().flatten() {
                    assert_eq!(value.as_str().unwrap().len(), 64, "{filter}");
                }
            }
            for id in filter["ids"].as_array().into_iter().flatten() {
                let event = events.iter().find(|e| e["id"] == *id).unwrap();
                assert!(!RECIPIENT_ONLY.contains(&kind(event)));
            }
            if let Some(kinds) = filter["kinds"].as_array() {
                assert!(kinds
                    .iter()
                    .all(|k| !RECIPIENT_ONLY.contains(&k.as_u64().unwrap())));
            }
            let mut matches: Vec<&Value> = kept
                .iter()
                .copied()
                .filter(|event| crate::matches_filter(event, filter))
                .collect();
            matches.sort_by_key(|event| Reverse(created_at(event)));
            let limit = filter["limit"]
                .as_u64()
                .map_or(matches.len(), |l| l as usize);
            let expected = corpus.expected(filter);
            assert_eq!(expected.len(), matches.len().min(limit), "{filter}");
            // The newest `limit` matches are a correct reply.
            let reply: Vec<Value> = matches.into_iter().take(limit).cloned().collect();
            assert!(expected.matches(&reply), "{filter}");
            if expected.len() > 0 {
                answered[q % 7] += 1;
            }
        }
        // Every shape finds events in most of its queries.
        assert!(answered.iter().all(|&n| n > 50), "{answered:?}");
    }
}
