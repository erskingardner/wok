# NIP-50 search

Wok implements the pinned NIP-50 `search` filter against event `content` and
advertises NIP-50 through NIP-11. Search filters can be combined with `ids`,
`authors`, `kinds`, tags, `since`, and `until`; every supplied constraint must
match.

`relay.search_enabled = false` turns search off: NIP-11 stops listing NIP-50,
and a REQ, COUNT or NEG-OPEN with a `search` filter is refused with
`blocked:` before its query is parsed. The index below is kept current either
way; see [Search](config.md#search).

## Query semantics

- Free text is split into Unicode alphanumeric terms and lowercased.
- Every unique free-text term must be one of the event's searchable terms
  (AND semantics): the first 256 unique terms of its `content`, in document
  order. A word an event first uses after that, such as the 300th distinct
  word of a long article, is not searchable, in history, COUNT, NEG-OPEN or a
  live subscription alike.
- Words containing a non-empty `key:value` pair are treated as extensions and
  ignored. Wok does not currently implement the optional `domain`, `language`,
  `sentiment`, `nsfw`, or `include:spam` extensions.
- Results are ranked by inverse term document frequency, then boosted for each
  adjacent query-term pair found in the content, anywhere in it. Ties use
  newer `created_at`, then lexical event id, for deterministic output.
- `limit` is applied only after ranking. Multiple search filters in one REQ are
  evaluated independently and duplicate events are emitted once.
- After historical results and EOSE, matching new events continue to be sent
  through the normal live subscription path.

Queries are limited to 1,024 UTF-8 bytes and 16 searchable terms. Individual
normalized terms are limited to 64 bytes. These
bounds prevent a single REQ from creating unbounded parser or index work.
Each event is searchable by at most 256 unique terms, so one small event of
many distinct words cannot amplify into thousands of index writes. Live matching uses the same bounded
terms the index stores, so a search finds the same events whether it is open
when they arrive or sent later.
Events rejected by Wok's admission/write policy never enter the database or
the search index and therefore do not appear in search results.

## Index and recovery

The rebuildable `wok_Event__search` LMDB DBI stores the first 256 unique
normalized terms of each event's content, mapped to local event ids. It is
maintained in the same write transaction as Event, EventPayload,
replacement, and deletion changes. Queries count postings, start with the
rarest term, intersect remaining terms with exact LMDB lookups, and retain
only the best `limit` candidates in a bounded heap. For a query of two or
more words, each match's content is read once to find which adjacent pairs
it holds; a word too long to index separates the words beside it. Adjacent
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
