# NIP-50 search

Wok implements the pinned NIP-50 `search` filter against the text of the
kinds below and advertises NIP-50 through NIP-11. Search filters can be combined with `ids`,
`authors`, `kinds`, tags, `since`, and `until`; every supplied constraint must
match.

`relay.search_enabled = false` turns search off: NIP-11 stops listing NIP-50,
and a REQ, COUNT or NEG-OPEN with a `search` filter is refused with
`blocked:` before its query is parsed. The index below is kept current either
way; see [Search](config.md#search).

## What is searched

NIP-50 says relays "SHOULD perform matching against `content`" and leaves
each kind's details to the relay. Wok searches only kinds whose content is
text a person wrote, from the pinned NIPs' kind table:

| Kinds | What they are | NIP |
| --- | --- | --- |
| 1 | Short text note | 10 |
| 9, 42, 1311 | Chat, channel and live chat messages | C7, 28, 53 |
| 11, 1111 | Forum thread, comment | 7D, 22 |
| 20, 21, 22, 34235, 34236 | Picture, videos | 68, 71 |
| 54 | Podcast episode | F4 |
| 1063 | File metadata | 94 |
| 1068 | Poll | 88 |
| 1337 | Code snippet | C0 |
| 1618, 1621 | Git pull request, issue | 34 |
| 2003, 2004 | Torrent, torrent comment | 35 |
| 7516, 37516, 37517 | Geocache log, listing, curation | CC |
| 9041 | Zap goal | 75 |
| 9802 | Highlight | 84 |
| 30023 | Long-form article | 23 |
| 30402 | Classified listing | 99 |
| 30818 | Wiki article | 54 |
| 31922, 31923, 31924 | Calendar events, calendar | 52 |
| 39701 | Web bookmark | B0 |

For these, the values of `title`, `subject` and `name` tags, then of
`summary` and `description` tags, are searched with `content`, ahead of it,
so a long summary or content cannot push a title past the term limit below. `alt` is not: it
describes the event for clients that cannot show its kind. Words in two
tags, or in a tag and `content`, are not adjacent.

A kind 0 profile is searched by the `name`, `display_name`, `nip05` and
`about` strings of its metadata JSON, in that order. Its other fields, its
JSON keys and URLs, are not. Metadata that is not a JSON object has nothing
to search.

No other kind is searched: not ciphertext (NIP-04, NIP-44, gift wraps,
MLS), reposts and approvals that embed another event, reactions, lists,
or structured content. A search filter that names only such kinds, such as
`{"kinds":[4],"search":"x"}`, matches nothing. Changing this list changes
the index's version, which rebuilds it.

## Query semantics

- Free text is split into Unicode alphanumeric terms and lowercased.
- Every unique free-text term must occur in the event's searched text (AND
  semantics).
- Words containing a non-empty `key:value` pair are treated as extensions and
  ignored. Wok does not currently implement the optional `domain`, `language`,
  `sentiment`, `nsfw`, or `include:spam` extensions.
- Results are ranked by inverse term document frequency, then boosted for each
  adjacent query-term pair found in the searched text, anywhere in it. Ties use
  newer `created_at`, then lexical event id, for deterministic output.
- `limit` is applied only after ranking. Multiple search filters in one REQ are
  evaluated independently and duplicate events are emitted once.
- After historical results and EOSE, matching new events continue to be sent
  through the normal live subscription path. A live event matches by the
  same terms it would be indexed by, so it matches exactly the searches it
  would match once stored.

Queries are limited to 1,024 UTF-8 bytes and 16 searchable terms. Individual
normalized terms are limited to 64 bytes. These
bounds prevent a single REQ from creating unbounded parser or index work.
Events rejected by Wok's admission/write policy never enter the database or
the search index and therefore do not appear in search results.

## Index and recovery

The rebuildable `wok_Event__search` LMDB DBI stores the first 256 unique
normalized terms of each event's searched text, mapped to local event ids.
An event of a kind that is not searched writes no postings. It is
maintained in the same write transaction as Event, EventPayload,
replacement, and deletion changes. Queries count postings, start with the
rarest term, intersect remaining terms with exact LMDB lookups, and retain
only the best `limit` candidates in a bounded heap. For a query of two or
more words, each match's searched text is read once to find which adjacent
pairs it holds; a word too long to index separates the words beside it. Adjacent
pairs are not indexed, so an event writes one posting per unique word.

Existing Wok databases and migrated strfry v3 snapshots are backfilled in
10,000-event transactions on first open. A versioned marker makes index-format
changes rebuild automatically. `wok doctor` verifies missing, dangling, and
semantically incorrect search postings, while `wok reindex` derives the search
index again from authoritative payloads.

## Benchmark

The `nip50_search` scenario uses a deterministic signed corpus and mixes:

1. rare single-term queries;
2. common-plus-rare intersections; and
3. deliberately broad terms matching the entire corpus.

Every returned event is checked for the requested term, every query must reach
EOSE, and no query may exceed its post-ranking limit. Abuse throttling is
disabled only in the disposable benchmark relay so the measurements cover
search execution rather than REQ admission policy.

Broad terms that match most of the corpus score every matching event before
the limit applies, so they dominate the high percentiles; rare and
intersection queries dominate the median.

Run the search workload with:

```bash
cargo build --release -p wok-cli -p wok-bench
./target/release/wok-bench \
  --scenario nip50_search \
  --events 100000 \
  --queries 300 \
  --wok ./target/release/wok \
  --out bench-results
```
