# Publication slowdown investigation — September 7, 2026

Follow-up: the [strfry comparison](benchmark-strfry-soak-comparison-2026-09-07.md)
reproduced database-growth slowdown in the latest release and development branch,
including controls that align metadata durability with Wok. It also found an
upstream environment-flag collision that matters for interpreting raw throughput.

The 24-hour soak's publication slowdown reproduces with a newly started relay
and a copy of its completed database. The dominant measured cost is committing
the larger database's writes, with approximately 16 events per transaction in
the 32-publisher workload. This finding does not require a long-lived process,
and no correctness failure was reproduced.

## Controlled comparison

The original soak completed 288 rounds and retained 648,000 events. Its first
12 rounds had median publication throughput of 2,146 events/s and median
per-trial p99 of 25.10 ms; the last 12 had 1,015 events/s and 53.38 ms.

The investigation reused the same two Debian VMs, image, configuration, and
container limits: relay 3 CPUs / 6 GiB; generator 6 CPUs / 12 GiB. Every case
started a fresh relay with either an empty directory or a separate filesystem
copy of the stopped soak database. Each published the same deterministic
realistic event mix: 10,000 measured events, 32 connections, and 50 sequential
warm-up events. Synchronous LMDB durability remained enabled.

The six baseline cases ran in order: empty, full, full, empty, empty, full.
The numbers below are medians of three trials, not pooled latency percentiles.

| Measurement | Initially empty | Initially 648,000 events |
| --- | ---: | ---: |
| Publication throughput | 2,766 events/s | 1,315 events/s |
| Per-trial acknowledgement p99 | 16.67 ms | 47.97 ms |
| Relay process write bytes | 446 MB | 1,177 MB |
| Relay process write syscalls | 84,524 | 278,646 |

Byte and syscall counters are deltas from `/proc/<pid>/io`, including warm-up;
MB means decimal megabytes. They are not event payload size, database growth,
or physical flash write amplification. The full-database trials ranged from
1,123–1,316 events/s; empty trials ranged from 2,457–2,988 events/s. An additional
unmodified full-database control after the diagnostic cases reached 1,309
events/s. The original baseline cases recorded no major page faults or host
CPU steal ticks during their measurement windows. VM/storage variability still
limits precision.

## Where the time goes

A separate diagnostic binary added monotonic timers around the writer stages
and one structured log per batch. It changed no event, batching, index, or
durability behavior. These runs are separate from the unmodified baselines.
The table totals the 10,000 measured publications and excludes warm-up.

| Writer stage | Empty database | Full database |
| --- | ---: | ---: |
| Begin transaction and write events/indexes | 0.421 s | 0.666 s |
| Apply/flush negentropy tree batch | 0.097 s | 0.113 s |
| Commit, including cached state flush | 3.689 s | 6.257 s |
| Total measured writer time | 4.208 s | 7.037 s |
| Transactions | 627 | 627 |

Commit accounts for 89% of measured full-database writer time and 91% of the
increase between this diagnostic pair. The commit timer includes Wok's cached
author-counter/sequence flush as well as `mdb_txn_commit`; it is not a timer of
`fdatasync` alone.

The source path matches these observations:

- `crates/wok-relay/src/server/writer.rs` drains currently available messages,
  writes a transaction, commits, then sends publication acknowledgements.
- `crates/wok-db/src/write.rs` updates primary records and multiple indexes;
  search, author state, and persistent negentropy also participate in writes.
- `crates/wok-db/src/txn.rs` flushes cached state before committing LMDB.
- The pinned `lmdb-sys 0.8.0` bundles LMDB 0.9.21. Its `mdb_page_flush` writes
  dirty pages, then commit synchronizes data and writes the transaction metadata.
  `Env::open` does not enable `MDB_NOSYNC`, `MDB_NOMETASYNC`, or `MDB_WRITEMAP`.

Independent syscall traces found the same 676 data synchronizations in both
cases, including warm-up/shutdown activity, but roughly 260,000 single-buffer
data writes for the full case versus 70,000 for the empty case. This is
consistent with more dirty pages and less contiguous writing as the index set
grows. The traces omit `writev`, so those counts are not all database writes.
Tracing slowed the relay substantially; its timings are diagnostic only.

Together, the controlled tests and source inspection point to LMDB
copy-on-write/index maintenance producing more writes per event, and the cost
of durably committing those writes on this VM storage. The investigation does
not apportion dirty bytes to individual indexes. In particular, the small
negentropy preparation time does not exclude its pages from commit cost.

## Additional controls and optimization evidence

- A disposable full-database copy on tmpfs reached 10,332 events/s; an empty
  tmpfs case reached 20,663 events/s. This supports storage cost as the dominant
  wall-time constraint, while showing that database-size costs remain in RAM.
  These were single exploratory runs; a cached Docker build-stage image export
  on the generator overlapped this control period. They are excluded from
  baseline medians. Tmpfs is volatile and is not a durability recommendation.
- Compacting a separate copy reduced the database from about 908 to 903 MiB.
  Two fresh copies of the compacted database reached 1,454 and 1,411 events/s
  and still wrote 1.16–1.19 GB per trial. Compaction did not remove the effect;
  these short runs do not establish a durable compaction benefit.
- Increasing publishers from 32 to 128 in the instrumented full-database case
  raised average batch size from 15.95 to 63.29 events and reduced measured
  transactions from 627 to 158. Two trials reached 2,052 and 1,888 events/s,
  writing 779–786 MB each. However, p99 rose to 112–129 ms versus 34.56 ms in
  the 32-publisher instrumented case. This demonstrates a batching/latency
  tradeoff, not a free speedup. The harness uses 128 warm-up events at this
  concurrency, which also changes its deterministic generated workload slightly.

The next implementation candidate is bounded batch coalescing: a small maximum
collection delay, plus explicit size limits, while retaining acknowledgements
only after durable commit. It needs a matrix of database sizes, concurrency,
low-rate traffic, and mixed reads/writes, with throughput and tail latency
reported together. Merely increasing the existing 512-message batch cap will
not help this 32-in-flight-publication workload.

Before tuning, add inexpensive aggregate writer batch-size, queue-age, and
commit-duration metrics. They need no event IDs, pubkeys, or content. Storage
comparisons should use this synchronous workload rather than sequential disk
bandwidth figures. No relay optimization or durability change was deployed by
this investigation.

## Provenance, validation, and reproduction

Frozen source: `76f9a6ac2f872848f32cf14d5b5d7fbd15051975`.
Image: `wok-lab:vm-canary-20260906` on both VMs. The accompanying
[`benchmark-soak-slowdown-2026-09-07.json`](benchmark-soak-slowdown-2026-09-07.json)
records exact binary/database hashes, every trial, resource deltas, diagnostic
timings and patch, and integrity results.

All 17 trials accepted every measured publication with zero reported errors
or mismatches: 170,000 measured events total. The remote harness checks matching
event IDs and positive acknowledgements; it does not independently export every
stored event. Offline integrity checks additionally passed on the final regular,
128-publisher diagnostic, and compacted copies, checking 658,050, 658,128, and
658,050 events respectively. All trial relay containers exited cleanly without
OOM kills. The original soak database's SHA-256 was verified unchanged.

For each independent case, start the frozen lab relay on a fresh writable data
directory, or a copy of the stopped 648,000-event database. Never write to the
original fixture. Use the limits above and `contrib/lab/wok.toml`, then run:

```bash
wok-bench --scenario ws_publish_scaled \
  --target-url ws://RELAY_IP:7777 --target-label CASE \
  --events 10000 --publish-connections 32 --event-mix realistic \
  --seed 920260907 --base-timestamp 1788764100 --out /results/CASE
```

The fixed timestamp reproduces this campaign only while it remains within the
relay's accepted timestamp window. For a later campaign, choose one fresh
timestamp and retain it across all cases. Stop the relay before switching
directories. Keep the same seed/timestamp across the empty/full comparisons,
and use separate database copies to avoid duplicate-publication shortcuts.

Raw controller scripts, syscall traces, profiling patch/binary, container state,
metrics, integrity output, and trial files remain under
`bench-results/lab/pub-slowdown-20260907/`; original soak evidence remains under
`bench-results/lab/vm-soak-20260906/`. Original volumes, images, and per-case
database copies are retained on the VMs. This publication investigation does
not establish capacity for AUTH, reconciliation, historical queries, Unix
transport, or real-user traffic, and does not prove the absence of unrelated
memory leaks or correctness bugs.
