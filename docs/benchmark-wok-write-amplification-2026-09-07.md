# Wok write amplification investigation — September 7, 2026

Search is the largest measured source of Wok's additional writes. Removing or
changing it would affect useful query behavior; this investigation retained all
indexes, signed events, quota enforcement, and synchronous durability.

A small counter optimization avoids creating author counters until first needed.
It reduced process-attributed writes by 5.3% in the quota-free publication fixture.
The 2.3% median throughput increase is too small to distinguish confidently from
VM variability. Default author quotas still require counters, so this is not a
claim of a 5.3% improvement under the default configuration.

A separate bounded-coalescing experiment reduced writes but made publication
slower. That prototype was not adopted.

## Measurement and attribution

The original two VMs, frozen benchmark binary, 3-CPU/6-GiB relay limit,
6-CPU/12-GiB generator limit, and synchronous LMDB settings were retained.
Each populated trial used a new filesystem copy of the stopped 648,000-event
Wok soak database. All cases ran serially; VM builds and offline checks were
outside workload measurement windows.

The standard case published 10,000 measured events over 32 sockets plus 50
sequential warm-up events. Seed `920260907`, timestamp `1788764100`, realistic
mix, and corpus fingerprint were fixed across those cases. Three single-publisher
controls instead used 1,000 measured events plus 50 warm-up events; they form a
separate matched corpus. No strfry workload was run in this investigation.

A diagnostic-only LMDB helper counted dirty-page bytes before and after each
Wok `put`/`del`, including overflow runs and excluding loose/kept pages. The Rust
wrapper accumulated deltas by table. It also recorded the pre-commit total and
LMDB's final flush total. No event identifiers or content were logged by this
instrumentation. It was not included in the counter-fix performance binary.

This is **incremental dirty-page attribution to operations**, not physical SSD
write amplification or a page-ownership census. Shared/internal pages are
charged to the operation that first dirties them; already-dirty pages are not
charged repeatedly. Attribution depends on operation order and transaction
boundaries. A change to one table can also change allocation/layout costs in
other tables, so subtracting a table's total is not a precise prediction of the
savings from removing it.

Both original diagnostic cases wrote 10,050 events in 676 publication
transactions. No nonzero-keep page spills were observed. Table deltas summed
exactly to pre-commit dirty bytes: 437.354 MB empty and 1,161.859 MB populated.
Including internal commit work and startup activity, LMDB flush totals were
440.488 and 1,167.938 MB. Process write counters were 443.199 and 1,170.653 MB.
All MB figures are decimal. Profiling timing is excluded from performance claims.

| Operations on table | Empty dirty MB | Populated dirty MB |
| --- | ---: | ---: |
| Search | 138.863 | 577.966 |
| Tags | 65.094 | 116.220 |
| Author + kind | 47.866 | 99.389 |
| Event ID | 42.684 | 93.991 |
| Author | 46.047 | 91.996 |
| Author counts + sequence | 27.447 | 78.418 |
| Kind | 15.581 | 25.162 |
| Negentropy | 13.898 | 22.245 |
| Replacement lookup | 9.847 | 18.366 |
| Event JSON payload | 13.521 | 16.912 |
| Packed event | 10.453 | 12.476 |
| Creation time | 6.054 | 8.716 |

Search caused approximately 50% of populated pre-commit dirty bytes and 61% of
the increase between these two cases. Negentropy caused less than 2% of the
populated total. Vanish and moderation records contributed no writes to this
particular ordinary-publication workload; that does not measure their lifecycle
costs.

A second populated diagnostic separated search into 313.164 MB of term postings,
259.207 MB of adjacent-word-pair postings, and 5.423 MB of progress markers.
It had the same event and transaction counts. This split used the observation
patch plus the coalescing prototype with a zero collection delay; its timing is
also excluded. The small differences from the first diagnostic illustrate why
these are measured attribution results, not fixed per-feature constants.

Term postings provide candidate retrieval and intersection. Word-pair postings
provide the phrase-ranking boost without loading and parsing every candidate's
payload. Their cost is substantial, but simply dropping them would change
ranking or shift work to queries. The corpus's repeated benchmark vocabulary,
numbered words, and unique authors for replaceable events also matter; these
percentages are not universal for arbitrary real-world traffic.

## Counter optimization

Previously, inserting or deleting an event called `author_count`, initializing
and persisting a counter even if no quota/count consumer needed it. Now:

- A missing counter remains absent until `author_count` is requested, normally
  by a quota check. That request derives the current count from the author index.
- In-transaction and previously persisted counters continue to track every
  mutation, including while author quotas are disabled.
- Quota activation counts preexisting events before admitting a new event.
  Replacements, deletions, transaction aborts and reopen preserve this behavior.
- Sequence allocation and publication acknowledgements after durable commit are
  unchanged. Existing databases need no migration or counter deletion.

Missing author counters were already a valid state for upgraded/reindexed Wok
databases. The first count request can require a one-time author-index scan; an
operator enabling quotas after unlimited ingestion should account for that cost.

Three baseline/fix pairs alternated order, using fresh populated copies and
uninstrumented binaries:

| Build, author quotas disabled | Events/s | ACK p50 | ACK p99 | Process writes |
| --- | ---: | ---: | ---: | ---: |
| Baseline | 1,406 | 22.30 ms | 45.31 ms | 1,183.875 MB |
| Lazy counters | 1,439 | 21.78 ms | 43.17 ms | 1,121.264 MB |

These are medians of trials, with medians of each trial's latency percentiles.
Every paired fix trial wrote fewer bytes. The principal demonstrated benefit is
reduced writes and unused state growth, not a confidently established throughput
increase. Existing tracked authors continue to incur counter maintenance; savings
depend on how many publishing authors lack counters. In the final verified
copy, the fix avoided creating 2,044 new author-counter records; all 11,541,412
event-derived index entries still matched the baseline.

The benchmark fixture disables abuse protection. **Default Wok enables author
quotas at 100,000 stored events per author**, and still initializes counters as
needed to enforce that limit. A separate quota-enabled baseline/fix pair kept
that quota and the global storage ceiling, disabling only publication/connection
rate buckets to allow the workload. Both accepted all events. Their throughput
was 1,377/1,334 events/s, p99 41.38/40.67 ms, and writes 1,206/1,218 MB. This single
pair is a compatibility control, not evidence of a default-mode speedup or a
precise regression estimate. No protective defaults were changed.

## Coalescing experiment: not adopted

A temporary writer prototype allowed a fixed maximum collection window after
the first queued message. The deadline was not extended by new arrivals, and
the existing batch-size cap and commit-before-acknowledgement rule remained.
Three populated repetitions per setting rotated execution order:

| Collection window | Events/s | ACK p50 | ACK p99 | Process writes |
| --- | ---: | ---: | ---: | ---: |
| 0 ms | 1,369 | 22.85 ms | 44.74 ms | 1,187.746 MB |
| 1 ms | 1,273 | 25.39 ms | 50.94 ms | 1,134.801 MB |
| 3 ms | 1,101 | 28.19 ms | 48.58 ms | 1,034.023 MB |

The zero-delay setting used the same prototype binary for a matched control.
Unmodified frozen controls before and after this phase reached 1,313 and 1,416
events/s. A separate profiled 1-ms case reduced publication transactions from
676 to 531, confirming more grouping, but most search pages still had to change.

With a single publisher, 0/1/3-ms settings reached 291/159/117 events/s, with
p99 5.59/8.42/10.68 ms and essentially identical 401.35 MB write totals. These
single runs are exploratory latency controls, not long-run estimates. The
prototype adds scheduling and collection overhead; its actual end-to-end cost
is not limited to the nominal wait interval. It was kept out of the production
source and configuration. This result supersedes the earlier suggestion to
prioritize a simple fixed batch-collection delay for this workload.

## Validation, provenance and next work

All 26 VM trials passed publication checks: 233,000 measured events, including
23 10,000-event trials and three 1,000-event single-publisher trials. Relay and
load containers exited successfully without OOM kills. Eight populated cases
were additionally exported and checked offline: both attribution variants, the
profiled and unprofiled coalescing controls, baseline/fix, and quota-enabled
baseline/fix. Every export matched exactly at 658,050 signed events, and all
integrity checks passed using the unchanged baseline binary. The original soak
database's SHA-256 was unchanged. Trial containers were left stopped.

Local validation: `cargo test --workspace --locked` passed 367 tests with one
ignored; Clippy with warnings denied, formatting and diff checks passed. Added
regressions cover lazy initialization after same-transaction mutations, abort,
reopen, quota activation over existing events, and counter maintenance after
quotas are disabled. Existing subprocess crash tests explicitly initialize
tracked counters so their atomic flush/recovery assertions remain exercised.

Baseline runtime revision is `76f9a6ac2f872848f32cf14d5b5d7fbd15051975`; source
archive base is `74c7e9e` (documentation-only differences). The performance fix
binary differs only in `crates/wok-db/src/state.rs`; the fix and regression tests
are committed as `eab76a1208b6c7a8685aa3aa110dcf9ad1f9406a`. The accompanying
[`benchmark-wok-write-amplification-2026-09-07.json`](benchmark-wok-write-amplification-2026-09-07.json)
records hashes, patches, trial results, attribution, and offline verification.
Raw scripts, profiling binaries and logs remain in
`bench-results/lab/wok-write-amplification-20260907/`; database copies and full
exports remain on the VMs.

Follow-up: an [event-local phrase index experiment](benchmark-search-layout-2026-09-07.md)
reduced publication writes but produced modest throughput gains and a phrase
query regression. That prototype was parked; the current layout is retained.

The next substantial target identified by this investigation was search posting
representation and locality,
measured against unchanged search results and ranking. A useful experiment must
include rare/common terms, phrase ranking, broad scans, mixed publication/search,
replacement/deletion, rebuild, crash recovery and memory bounds. Changing the
posting layout could require a versioned rebuild and additional code complexity.
Moving word-pair scoring to payload reads is a separate read/write tradeoff;
it should not be adopted solely from these publication numbers. Author quotas,
durability and privacy do not need to be weakened to investigate either option.
