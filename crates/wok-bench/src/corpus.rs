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
//! No plan reads a kind that Wok serves only to its authenticated recipient
//! ([`RECIPIENT_ONLY`]) and strfry serves to anyone, and every filter has a
//! `limit` of at most 500, strfry's and Wok 0.7's `maxFilterLimit`.

use anyhow::Result;
use serde_json::{json, Value};
use std::cmp::Reverse;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
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

/// Which of `events` a relay keeps once it has imported them, whatever the
/// order. Replacement keeps the latest `created_at`, and on a tie the lowest
/// id (NIP-01). A kind 5 deletes its author's events named by `e` tags,
/// except other deletions, as Wok does; strfry deletes those too, but no
/// generated corpus names a deletion.
pub(crate) fn retention(events: &[Value]) -> Vec<bool> {
    let mut kept = vec![false; events.len()];
    let mut ids = HashSet::with_capacity(events.len());
    let mut newest: HashMap<(&str, u64, &str), usize> = HashMap::new();
    let mut deleted: HashSet<(&str, &str)> = HashSet::new();
    for (index, event) in events.iter().enumerate() {
        let kind = kind(event);
        if (20_000..30_000).contains(&kind) || !ids.insert(id(event)) {
            continue;
        }
        if kind == 5 {
            deleted.extend(tag_values(event, "e").map(|target| (target, pubkey(event))));
        }
        let replaceable = kind == 0 || kind == 3 || (10_000..20_000).contains(&kind);
        let addressable = (30_000..40_000).contains(&kind);
        if !replaceable && !addressable {
            kept[index] = true;
            continue;
        }
        let d = if addressable {
            tag_values(event, "d").next().unwrap_or_default()
        } else {
            ""
        };
        match newest.entry((pubkey(event), kind, d)) {
            Entry::Vacant(slot) => {
                slot.insert(index);
            }
            Entry::Occupied(mut slot) => {
                let stored = &events[*slot.get()];
                if (created_at(event), Reverse(id(event)))
                    > (created_at(stored), Reverse(id(stored)))
                {
                    slot.insert(index);
                }
            }
        }
    }
    for index in newest.into_values() {
        kept[index] = true;
    }
    for (index, event) in events.iter().enumerate() {
        if kept[index] && kind(event) != 5 && deleted.contains(&(id(event), pubkey(event))) {
            kept[index] = false;
        }
    }
    kept
}

/// A corpus as a relay holds it once imported, indexed for the oracle.
pub(crate) struct Corpus {
    events: Vec<Value>,
    kept: Vec<bool>,
    retained: u64,
    limits: Limits,
    /// Kept events by id, by author, and by the first value of each
    /// single-letter tag.
    by_id: HashMap<String, usize>,
    by_author: HashMap<String, Vec<usize>>,
    by_tag: HashMap<(String, String), Vec<usize>>,
}

/// The events a correct reply holds: all of `required`, and `take` of
/// `tied`, the matches in the second a `limit` cuts through.
pub(crate) struct Expected<'a> {
    required: Vec<&'a Value>,
    tied: Vec<&'a Value>,
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
        if self.take > 0 {
            self.tied.first().map(|e| created_at(e))
        } else {
            self.required.last().map(|e| created_at(e))
        }
    }

    /// Whether `actual` holds exactly the events this allows, each once and
    /// unchanged.
    pub fn matches(&self, actual: &[Value]) -> bool {
        if actual.len() != self.len() {
            return false;
        }
        let wanted: HashMap<&str, (&Value, bool)> = self
            .required
            .iter()
            .map(|e| (id(e), (*e, true)))
            .chain(self.tied.iter().map(|e| (id(e), (*e, false))))
            .collect();
        let mut seen = HashSet::new();
        let mut required = 0;
        for event in actual {
            let Some(&(want, is_required)) = event["id"].as_str().and_then(|id| wanted.get(id))
            else {
                return false;
            };
            if !seen.insert(id(want)) || want != event {
                return false;
            }
            required += usize::from(is_required);
        }
        required == self.required.len()
    }
}

impl Corpus {
    pub fn load(path: &Path) -> Result<Self> {
        use std::io::BufRead;
        let reader = std::io::BufReader::new(std::fs::File::open(path)?);
        let mut events = Vec::new();
        let mut limits = Limits::default();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let event: Value = serde_json::from_str(&line)?;
            limits.observe(&line, tags(&event));
            events.push(event);
        }
        Ok(Self::new(events, limits))
    }

    pub fn new(events: Vec<Value>, limits: Limits) -> Self {
        let kept = retention(&events);
        let mut corpus = Self {
            retained: kept.iter().filter(|&&k| k).count() as u64,
            events,
            kept,
            limits,
            by_id: HashMap::new(),
            by_author: HashMap::new(),
            by_tag: HashMap::new(),
        };
        for index in corpus.kept_indices().collect::<Vec<_>>() {
            let event = &corpus.events[index];
            corpus.by_id.insert(id(event).to_owned(), index);
            corpus
                .by_author
                .entry(pubkey(event).to_owned())
                .or_default()
                .push(index);
            for tag in tags(event) {
                if let (Some(name), Some(value)) = (tag[0].as_str(), tag[1].as_str()) {
                    if name.chars().count() == 1 {
                        corpus
                            .by_tag
                            .entry((name.to_owned(), value.to_owned()))
                            .or_default()
                            .push(index);
                    }
                }
            }
        }
        corpus
    }

    fn kept_indices(&self) -> impl Iterator<Item = usize> + '_ {
        (0..self.events.len()).filter(|&index| self.kept[index])
    }

    fn kept_events(&self) -> impl Iterator<Item = &Value> + '_ {
        self.kept_indices().map(|index| &self.events[index])
    }

    /// Lines in the corpus.
    pub fn lines(&self) -> u64 {
        self.events.len() as u64
    }

    /// Events a relay keeps.
    pub fn retained(&self) -> u64 {
        self.retained
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// The author of the corpus's first event of `kind`.
    pub fn first_author(&self, kind: u64) -> Option<&str> {
        self.events
            .iter()
            .find(|event| self::kind(event) == kind)
            .map(pubkey)
    }

    /// The author with the most kept events (of `kind`, if given), and how
    /// many. Ties go to the lower pubkey.
    pub fn busiest_author(&self, kind: Option<u64>) -> Option<(&str, u64)> {
        let mut counts: HashMap<&str, u64> = HashMap::new();
        for event in self.kept_events() {
            if kind.is_none_or(|kind| self::kind(event) == kind) {
                *counts.entry(pubkey(event)).or_default() += 1;
            }
        }
        counts
            .into_iter()
            .max_by_key(|&(author, count)| (count, Reverse(author)))
    }

    /// Kept events that may match `filter`: those its `ids`, `authors` or
    /// first tag condition name, or all of them.
    fn candidates(&self, filter: &Value) -> Vec<usize> {
        let values = |key: &str| {
            filter[key]
                .as_array()
                .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        };
        let mut indices: Vec<usize> = if let Some(ids) = values("ids") {
            ids.iter()
                .filter_map(|id| self.by_id.get(*id).copied())
                .collect()
        } else if let Some(authors) = values("authors") {
            authors
                .iter()
                .filter_map(|author| self.by_author.get(*author))
                .flatten()
                .copied()
                .collect()
        } else if let Some(name) = filter
            .as_object()
            .and_then(|object| object.keys().find_map(|key| key.strip_prefix('#')))
        {
            values(&format!("#{name}"))
                .unwrap_or_default()
                .iter()
                .filter_map(|value| self.by_tag.get(&(name.to_owned(), (*value).to_owned())))
                .flatten()
                .copied()
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
        let mut matches: Vec<&Value> = self
            .candidates(filter)
            .into_iter()
            .map(|index| &self.events[index])
            .filter(|event| crate::matches_filter(event, filter))
            .collect();
        matches.sort_by(|a, b| {
            created_at(b)
                .cmp(&created_at(a))
                .then_with(|| id(a).cmp(id(b)))
        });
        let limit = filter["limit"]
            .as_u64()
            .map_or(usize::MAX, |limit| limit.min(usize::MAX as u64) as usize);
        if matches.len() <= limit {
            return Expected {
                required: matches,
                tied: Vec::new(),
                take: 0,
            };
        }
        if limit == 0 {
            return Expected {
                required: Vec::new(),
                tied: Vec::new(),
                take: 0,
            };
        }
        let cut = created_at(matches[limit - 1]);
        let newer = matches.partition_point(|e| created_at(e) > cut);
        let through = matches.partition_point(|e| created_at(e) >= cut);
        Expected {
            tied: matches[newer..through].to_vec(),
            take: limit - newer,
            required: {
                matches.truncate(newer);
                matches
            },
        }
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
        let notes: Vec<&Value> = self.events.iter().filter(|e| kind(e) == 1).collect();
        anyhow::ensure!(!notes.is_empty(), "query corpus has no kind 1 events");
        Ok((0..count as usize)
            .map(|q| {
                let event = &self.events[(q * 7) % self.events.len()];
                let note = notes[(q * 11) % notes.len()];
                match q % 4 {
                    0 => json!({"ids":[id(event)]}),
                    1 => json!({"authors":[pubkey(note)],"kinds":[1],"limit":50}),
                    2 => json!({"kinds":[1],"since":created_at(note),"limit":20}),
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
        let lookups: Vec<&str> = self
            .events
            .iter()
            .filter(|event| !RECIPIENT_ONLY.contains(&kind(event)))
            .map(id)
            .collect();
        let mut follow_lists = Vec::new();
        let mut mentioned = Vec::new();
        let mut threads = Vec::new();
        let mut notes = Vec::new();
        for event in self.kept_events() {
            match kind(event) {
                1 => notes.push(created_at(event)),
                3 => follow_lists.push(tag_values(event, "p").take(AUTHORS).collect::<Vec<_>>()),
                7 => {
                    mentioned.extend(tag_values(event, "p").next());
                    threads.extend(tag_values(event, "e").next());
                }
                _ => {}
            }
        }
        follow_lists.retain(|follows| !follows.is_empty());
        anyhow::ensure!(
            !lookups.is_empty()
                && !follow_lists.is_empty()
                && !mentioned.is_empty()
                && !threads.is_empty()
                && !notes.is_empty(),
            "a social query corpus needs notes, follow lists and reactions"
        );
        let pick = |q: usize, len: usize| (q * STRIDE) % len;
        Ok((0..count as usize)
            .map(|q| match q % 7 {
                0 => json!({"ids":[lookups[pick(q, lookups.len())]]}),
                1 => json!({
                    "authors": follow_lists[pick(q, follow_lists.len())],
                    "kinds": [0, 3, 10_002],
                    "limit": LIMIT,
                }),
                2 => json!({
                    "authors": follow_lists[pick(q, follow_lists.len())],
                    "kinds": [1, 6],
                    "limit": LIMIT,
                }),
                3 => json!({
                    "#p": [mentioned[pick(q, mentioned.len())]],
                    "kinds": [1, 6, 7, 9_735],
                    "limit": LIMIT,
                }),
                4 => json!({
                    "#p": [mentioned[pick(q, mentioned.len())]],
                    "kinds": [3],
                    "limit": LIMIT,
                }),
                5 => json!({
                    "#e": [threads[pick(q, threads.len())]],
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

    fn event(id: &str, pubkey: &str, kind: u64, created_at: u64, tags: Value) -> Value {
        json!({
            "id": id,
            "pubkey": pubkey,
            "kind": kind,
            "created_at": created_at,
            "tags": tags,
            "content": "",
            "sig": "",
        })
    }

    fn corpus(events: Vec<Value>) -> Corpus {
        Corpus::new(events, Limits::default())
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
            event("reaction", "alice", 7, 11, json!([["e", "note"]])),
            event("profile-new", "alice", 0, 30, json!([])),
            event("profile-old", "alice", 0, 20, json!([])),
            // Same second: the lower id wins.
            event("list-b", "alice", 10_002, 40, json!([])),
            event("list-a", "alice", 10_002, 40, json!([])),
            event("article-1", "alice", 30_023, 50, json!([["d", "x"]])),
            event("article-2", "alice", 30_023, 60, json!([["d", "x"]])),
            event("article-3", "alice", 30_023, 55, json!([["d", "y"]])),
            // Bob cannot delete Alice's note; Alice deletes her reaction and
            // a deletion, which stays.
            event("bob-delete", "bob", 5, 70, json!([["e", "note"]])),
            event(
                "delete",
                "alice",
                5,
                80,
                json!([["e", "reaction"], ["e", "bob-delete"]]),
            ),
            event("again", "alice", 5, 81, json!([["e", "delete"]])),
            event("ephemeral", "alice", 20_001, 90, json!([])),
            event("note", "alice", 1, 10, json!([])),
        ];
        let kept = retention(&events);
        assert_eq!(
            ids(&events, &kept),
            [
                "note",
                "profile-new",
                "list-a",
                "article-2",
                "article-3",
                "bob-delete",
                "delete",
                "again"
            ]
        );
    }

    #[test]
    fn a_limit_through_a_second_accepts_any_of_its_events() {
        let corpus = corpus(vec![
            event("a", "p", 1, 30, json!([])),
            event("b", "p", 1, 20, json!([])),
            event("c", "p", 1, 20, json!([])),
            event("d", "p", 1, 20, json!([])),
            event("e", "p", 1, 10, json!([])),
        ]);
        let all = &corpus.events;
        let expected = corpus.expected(&json!({"kinds":[1],"limit":3}));
        assert_eq!(expected.len(), 3);
        assert!(expected.matches(&[all[0].clone(), all[3].clone(), all[1].clone()]));
        assert!(expected.matches(&[all[2].clone(), all[3].clone(), all[0].clone()]));
        // Missing the newer event, a repeat, an older event, or one short.
        assert!(!expected.matches(&[all[1].clone(), all[2].clone(), all[3].clone()]));
        assert!(!expected.matches(&[all[0].clone(), all[1].clone(), all[1].clone()]));
        assert!(!expected.matches(&[all[0].clone(), all[1].clone(), all[4].clone()]));
        assert!(!expected.matches(&[all[0].clone(), all[1].clone()]));
        let mut altered = all[1].clone();
        altered["content"] = json!("altered");
        assert!(!expected.matches(&[all[0].clone(), all[2].clone(), altered]));
        // A page ends in the cut second, whichever of its events it holds.
        assert_eq!(expected.oldest(), Some(20));
        // Nothing cut: the set is exact.
        let whole = corpus.expected(&json!({"kinds":[1],"limit":5}));
        assert!(whole.matches(all));
        assert_eq!(whole.oldest(), Some(10));
        let none = corpus.expected(&json!({"limit":0}));
        assert!(none.matches(&[]));
        assert_eq!(none.oldest(), None);
    }

    #[test]
    fn the_oracle_answers_from_kept_events_only() {
        let corpus = corpus(vec![
            event("note", "alice", 1, 10, json!([["p", "bob"]])),
            event("gone", "alice", 1, 11, json!([["p", "bob"]])),
            event("delete", "alice", 5, 12, json!([["e", "gone"]])),
            event("old", "bob", 3, 13, json!([["p", "alice"]])),
            event("new", "bob", 3, 14, json!([["p", "carol"]])),
        ]);
        let reply = |filter: Value| -> Vec<String> {
            let expected = corpus.expected(&filter);
            assert!(expected.tied.is_empty());
            expected.required.iter().map(|e| id(e).to_owned()).collect()
        };
        assert_eq!(reply(json!({"ids":["gone"]})), Vec::<String>::new());
        assert_eq!(reply(json!({"#p":["bob"],"kinds":[1]})), ["note"]);
        assert_eq!(
            reply(json!({"#p":["alice"],"kinds":[3]})),
            Vec::<String>::new()
        );
        assert_eq!(
            reply(json!({"authors":["bob","alice"]})),
            ["new", "delete", "note"]
        );
        assert_eq!(corpus.retained(), 3);
        assert_eq!(corpus.busiest_author(None), Some(("alice", 2)));
        assert_eq!(corpus.busiest_author(Some(3)), Some(("bob", 1)));
    }

    #[test]
    fn social_plans_use_full_values_and_skip_recipient_only_kinds() {
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
                let event = corpus.events.iter().find(|e| e["id"] == *id).unwrap();
                assert!(!RECIPIENT_ONLY.contains(&kind(event)));
            }
            if let Some(kinds) = filter["kinds"].as_array() {
                assert!(kinds
                    .iter()
                    .all(|k| !RECIPIENT_ONLY.contains(&k.as_u64().unwrap())));
            }
            if corpus.expected(filter).len() > 0 {
                answered[q % 7] += 1;
            }
        }
        // Every shape finds events in most of its queries.
        assert!(answered.iter().all(|&n| n > 50), "{answered:?}");
    }
}
