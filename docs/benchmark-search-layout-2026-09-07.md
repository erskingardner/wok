# Event-local phrase index experiment — 2026-09-07

**Decision: park this prototype; keep the current search layout.** Three paired
publication trials showed a 10.9% gain in the ratio of median throughputs and
21.3% fewer process-accounted write bytes. However, a broad search with reversed
phrase order became 17.7% slower. The experiment did not meet the agreed bar of
at least 20% sustained publication improvement without material search
regressions. These short trials are an initial gate, not a sustained-capacity
measurement. No runtime or database-format changes were merged into `master`.

This follows the
[write-amplification investigation](benchmark-wok-write-amplification-2026-09-07.md).
That investigation attributed a substantial part of dirty-page activity to
search word-pair postings, making their representation worth testing.

## What changed in the prototype

Individual-term inverse postings remain unchanged. The prototype replaces
global word-pair postings with one sorted, exact phrase-membership record per
event. Each record contains at most 256 distinct pairs, using the existing
64-byte term limits, with a maximum encoded size of 33,540 bytes. Membership
uses the event's record and binary search; it does not reparse event payloads or
use approximate hashes. Search filters and scoring rules remain unchanged.

This trades fewer scattered writes for per-candidate record reads and
validation. The existing layout can reject a globally absent pair through its
inverse-index lookup. The prototype must inspect candidate records even when
the pair is absent. The observed reversed-phrase regression is consistent with
that tradeoff; it is not a CPU-profile attribution of the individual costs.

The branch includes deletion, rebuild, integrity, bounded-record and malformed
input coverage. It introduces an experimental search-schema version 3 and an
additional Wok-owned table. A production upgrade/rollback policy was not
completed. It must not be deployed against an operational database.

## Matched setup

- Two existing Debian VMs: relay host 4 vCPU / approximately 8 GiB RAM; load host
  8 vCPU / approximately 16 GiB RAM. Relay container limited to 3 CPU / 6 GiB;
  generator to 6 CPU / 12 GiB. SSD-backed storage, no container swap.
- Same synchronous LMDB configuration and 8 GiB map. Abuse handling enabled,
  per-author quota 100,000, existing global quota retained. Rate buckets disabled
  for this isolated load test. No security or durability defaults changed.
- Original stopped soak database: 648,000 events. Both layouts' search indexes
  were cleared and rebuilt before making trial copies. Rebuilding only the
  prototype could otherwise confound representation with a refreshed physical
  index layout. Every trial started from a fresh copy of its rebuilt fixture.
- Three pairs, ordered baseline/prototype, prototype/baseline,
  baseline/prototype. Each trial published the same 10,000 measured events plus
  50 warmup events through 32 WebSocket connections, using the frozen load
  binary, realistic event mix, seed 920260907 and timestamp 1788764100.
- After publication, each trial ran 96 measured historical search requests in
  eight groups, plus eight warmups. The same shuffled query sequence ran on
  both layouts. A kind/time filter restricted results to the original corpus,
  with limit 20. Queries ran sequentially, without concurrent publication.
- Publication process-I/O snapshots exclude the search phase. Search timings
  measure remote REQ-to-EOSE elapsed time and include network/client overhead.
  No syscall tracing was active during these trials.

The synthetic soak corpus has repeated vocabulary and common phrases. There
was no explicit OS page-cache flush. Results apply to these populated fixtures
and workloads; they do not describe every real-world content distribution.

## Publication results

| Pair | Baseline events/s | Prototype events/s | Paired gain |
| --- | ---: | ---: | ---: |
| 1 | 1,649 | 1,785 | 8.2% |
| 2 | 1,587 | 1,839 | 15.9% |
| 3 | 1,609 | 1,666 | 3.5% |

| Metric, median across three trials | Baseline | Prototype |
| --- | ---: | ---: |
| Publication throughput | 1,609 events/s | 1,785 events/s |
| ACK p99 | 45.055 ms | 29.903 ms |
| Process `write_bytes` during publication | 1,215.5 MB | 956.6 MB |
| Process resident high-water mark after search | 1,016.0 MiB | 961.7 MiB |

The ratio of median throughputs is +10.9%; the median paired gain is +8.2%.
Each measured publication burst lasted roughly 5–6 seconds. Three pairs do not
provide a precise population estimate or establish sustained performance.
Process `write_bytes` is Linux I/O accounting, not physical SSD/NAND writes.
Resident high-water marks include mapped database pages; they are not heap
measurements or evidence about long-term memory leaks.

## Search results

Values below are medians of the three trials' within-group median latencies.
Each group had 12 measured requests per trial. The JSON also records per-trial
maxima, explicitly named `max_ms`; twelve observations do not support a useful
tail-percentile estimate.

| Group / search text | Baseline ms | Prototype ms |
| --- | ---: | ---: |
| Rare term, varying `needleN` | 1.892 | 1.955 |
| Intersection, `common needleN` | 2.732 | 3.172 |
| Broad term, `common` | 172.651 | 171.585 |
| Broad phrase, `common benchmark` | 415.481 | 423.640 |
| Reversed phrase, `event benchmark` | 364.281 | 428.878 |
| Multiple pairs, `common benchmark event` | 656.207 | 613.033 |
| Tag-filtered phrase, `benchmark event` | 240.988 | 238.097 |
| Numeric phrase, varying `event N` | 1.954 | 2.142 |

All corresponding queries returned exactly the same ordered event IDs across
all six trials. Multi-pair search improved by 6.6%, but reversed-phrase search
regressed by 17.7%. Rare/intersection/numeric queries remained small in absolute
time, with some regressions. This is result/ranking equivalence against the
baseline for the sampled queries, not an independent exhaustive spec oracle.

## Verification and evidence boundaries

All 60,000 measured publications succeeded without reported errors or
mismatches, plus 300 warmup publications. All 576 measured searches completed.
Relay and load containers exited successfully without OOM kills.

Both rebuilt fixtures were fully exported and matched the original 648,000
events by canonical event fingerprint. The final baseline/prototype pair was
fully exported at 658,050 events each and matched exactly, with no duplicate
IDs. All four offline integrity checks were clean, using the appropriate
binary for each layout. The original soak database's file SHA-256 remained
unchanged. Experimental containers were left stopped and the soak monitor
remains paused.

On the experimental branch, `cargo test --workspace --locked` passed 371 tests
with zero failures and one ignored manual diagnostic. Clippy with warnings
denied, formatting and diff checks passed. Coverage includes exact phrase
membership, Unicode, maximum-sized records, malformed records, schema rebuild,
deletion and existing subprocess crash tests. This is not a new Linux
power-failure campaign. Mixed publication/search, broader content distributions
and a longer soak were not run because the initial adoption gate failed.

## Provenance and disposition

- Baseline source: `001a057` (runtime change last at `eab76a1`, lazy author
  counters). Relay image `wok-write-lab:lazy`, retained from the preceding
  matched-build investigation.
- Prototype runtime/tests: `384bad8e95dbdc5a4f74f61288d6272da84459d9`.
- Disposable-fixture rebuild helper: `78e3486`.
- Both experimental commits remain on `codex/search-posting-prototype`.
  The Linux build archive's 127 source/build files were verified against the
  prototype commit, excluding macOS metadata and instruction files.
- Frozen publication generator: `wok-lab:vm-canary-20260906`.
- [Machine-readable results](benchmark-search-layout-2026-09-07.json) contain
  exact binary and workload hashes, per-trial statistics, verification and
  artifact hashes. Raw scripts, logs and binaries remain under
  `bench-results/lab/search-layout-20260907/`; database copies and full exports
  remain on the VMs.

The main branch retains its current search representation. Fewer writes alone
do not justify this prototype's query tradeoff and added format complexity.
This result does not rule out every alternative posting layout, but it gives
no reason to pursue this particular design further now.
