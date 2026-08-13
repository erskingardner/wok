# NIP-50 search

Wok implements the pinned NIP-50 `search` filter against event `content` and
advertises NIP-50 through NIP-11. Search filters can be combined with `ids`,
`authors`, `kinds`, tags, `since`, and `until`; every supplied constraint must
match.

## Query semantics

- Free text is split into Unicode alphanumeric terms and lowercased.
- Every unique free-text term must occur in `content` (AND semantics).
- Words containing a non-empty `key:value` pair are treated as extensions and
  ignored. Wok does not currently implement the optional `domain`, `language`,
  `sentiment`, `nsfw`, or `include:spam` extensions.
- Results are ranked by inverse term document frequency, then boosted for each
  adjacent query-term pair found in the content. Ties use newer `created_at`,
  then lexical event id, for deterministic output.
- `limit` is applied only after ranking. Multiple search filters in one REQ are
  evaluated independently and duplicate events are emitted once.
- After historical results and EOSE, matching new events continue to be sent
  through the normal live subscription path.

Queries are limited to 1,024 UTF-8 bytes and 16 searchable terms. Individual
normalized terms are limited to 64 bytes. These
bounds prevent a single REQ from creating unbounded parser or index work.
Events rejected by Wok's admission/write policy never enter the database or
the search index and therefore do not appear in search results.

## Index and recovery

The rebuildable `wok_Event__search` LMDB DBI stores unique normalized terms and
adjacent term pairs mapped to local event ids. It is maintained in the same
write transaction as Event, EventPayload, replacement, and deletion changes.
Queries count postings, start with the rarest term, intersect remaining terms
with exact LMDB lookups, and retain only the best `limit` candidates in a
bounded heap.

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

Apple Silicon macOS results from 2026-08-13, release builds, seed 1:

| corpus | queries | p50 | p90 | p99 | max | correctness |
|---:|---:|---:|---:|---:|---:|---|
| 100,000 | 300 | 0.38 ms | 15.60 ms | 15.82 ms | 15.9 ms | 0 mismatches |
| 1,000,000 | 60 | 2.34 ms | 192.77 ms | 193.79 ms | 193.8 ms | 0 mismatches |

The high-percentile samples are the broad queries that score every event; rare
and intersection queries dominate the median. A separate identical-corpus
100,000-event verified import measured 26,098 events/s for Wok with search
indexing enabled and 18,317 events/s for pinned strfry, which has no search
index. These are single-host observations, not universal performance claims.

Reproduce the search workload with:

```bash
cargo build --release -p wok-cli -p wok-bench
./target/release/wok-bench \
  --scenario nip50_search \
  --events 100000 \
  --queries 300 \
  --wok ./target/release/wok \
  --out bench-results
```
