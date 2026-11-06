# Optional RocksDB relay backend

The optional `rocksdb` feature builds the complete RocksDB relay, selecting the
v3 thin-author/frontier layout and its optimized reader. The default build uses
LMDB. RocksDB currently needs Rust 1.88 or newer for rocksdb 0.25 / RocksDB 11.8.1;
the default LMDB build retains its existing MSRV.

```sh
cargo build --release -p wok-cli --features rocksdb --locked \
  --target-dir target/rocksdb
./target/rocksdb/release/wok storage-backend
./target/rocksdb/release/wok migrate rocksdb --source /var/lib/wok/lmdb-db \
  --output /var/lib/wok/rocks-db --check
```

See [offline LMDB migration, backup and rollback](migration-to-rocksdb.md) for
the complete operator procedure. Event JSON import is available for a fresh
corpus but is not a full-state migration. The lower-level features below retain
separately marked experimental layouts for development and comparisons.

Use a separate database directory in the configuration. The RocksDB binary
refuses LMDB directories and nonempty unrecognized directories. A persistent
layout marker identifies the RocksDB format, independently of Wok's logical
schema version. Neither binary converts an existing database in place.
Retain an ordinary LMDB binary separately when building both variants.

This implementation retains Wok's event validation, write-policy decisions,
replacement/deletion behavior, query planner, visibility checks, scheduler,
monitors, transports and negentropy code. Storage work stays on the existing
OS threads. One application writer owns a transaction overlay; all index,
primary, sequence and count changes commit in one cross-column-family
`WriteBatch`. WAL remains enabled with `sync=true` before successful commit and
before the relay sends positive OK. This is a durable commit policy, not proof
of survival under storage/controller/power failure.

All RocksDB layouts use:

- one combined record per local event ID, preserving the exact PackedEvent and
  payload components, including their independent presence;
- thin author/time postings; the original dual-index layout additionally keeps
  covering author/time records, while v3 keeps compact two-position frontiers;
- bytewise encoded native-integer/composite/duplicate keys, with escaped string
  boundaries so variable-length prefixes remain unambiguous;
- reversed physical index order, so logical newest-first scans advance forward;
- snapshot reads, with transaction-owned buffers and a combined-record cache;
- atomic per-table entry counters, independently checked against physical scans.

Read-only cursors retain their native iterator position and use native next/prev
steps in either direction. After an unsuccessful seek or duplicate-boundary
operation, they verify the physical position before resuming the last returned
logical record. Writer cursors retain the seeking overlay merge. Neither this
fast path nor its transaction-owned returned bytes changes the persistent format.

Historical scans read typed timestamp/local-ID entries through
`Cursor::foreach_index`, borrowing the current physical posting only during its
callback. Consecutive entries sharing a seek prefix reuse the existing logical
prefix bytes: the reader compares physical prefixes and reads the two ordered
integers directly, without reconstructing, unescaping or retaining every logical
key/value. Only resume boundaries become owned keys. Other prefixes and
noncanonical maintenance records retain validated decoding; writer overlays and
ordinary cursor operations retain their existing behavior.

Scans reuse one physical cursor across their logical author/tag/kind ranges and
refills within each scan call. The cursor is dropped before returning to the
scheduler; owned resume endpoints and the next call's transaction still control
resumption. Wide scans start with a small frontier from each logical range and
merge candidates in a heap ordered by timestamp and local ID. Equal candidates
retain their stable insertion order. Only ranges being consumed grow their
refill batches, bounded at 50 entries for multi-range scans; single-range scans
retain their existing batching. Candidate and processing work remains charged
to the scan's budget, including across handler stops and scheduler slices.
Completeness lookahead uses the same ordered scan with collections capped at
one candidate per range. It continues through hidden or already-sent matches
within its existing work and visibility-check budgets, without fetching a normal
delivery batch merely to find one additional visible match.
The cursor can still visit and cache a further entry to retain its resume
boundary; the cap bounds collected candidates, not every physical read or copy.
A read-only duplicate range with a full starting key/value positions
directly at that inclusive endpoint, using one forward seek for newest-first
traversal of the reversed indexes. Other operations retain total logical order;
no prefix-only iterator mode or implicit range truncation is enabled.
The selected scan starts at the filter's inclusive `until` timestamp, including
every duplicate at that time. Bounded planning probes retain their unbounded
history before that endpoint is selected. Queries validate the postings they
visit; corruption strictly above the requested cutoff may be skipped, while
the offline physical audit still checks the complete database.

The two reserved tag/kind progress keys have a small in-memory mirror loaded
with bounded forward scans at open. Each transaction pairs an immutable mirror
version with the same RocksDB snapshot; a commit publishes its new mirror after
the synchronous batch succeeds. This avoids reverse scans through historical
deleted marker values while preserving duplicate ordering, aborts and old reader
snapshots. It changes no persistent record or format and needs no seed rewrite.

A single-author query in the original dual-index layout selects the covering index. Its candidates
populate the transaction's combined-record cache; visibility and payload checks
continue through the ordinary Wok path. Multi-author queries keep thin postings
so unselected candidate payloads are not pulled into a feed merge.

For an isolated comparison of that choice, the experimental
`rocksdb-thin-author-reads` build feature makes single-author `Pubkey` scans use
the thin author index and native primary reads instead. It enables the RocksDB
backend and is off by default:

```sh
cargo build --release --locked -p wok-cli \
  --features rocksdb-thin-author-reads --target-dir target/rocksdb-thin-author
```

Other selected plans retain their indexes. The choice also applies to a
single-author alternative selected by the bounded author-versus-tag probe,
which still checks the complete original filter. With only the read-plan
feature, both author indexes are still written and checked by the physical
audit; this feature changes no persistent
format, writer, cache limit or durability setting. Comparing the read plans
therefore does not measure the write or compaction savings of removing the
covering index. Such a layout experiment needs a separate format and rebuilt
seeds. Record the exact enabled features alongside source and binary hashes,
and compare correctness, read tails, native operations and memory before
choosing a plan.

The separate experimental `rocksdb-coverless` feature removes the full covering
author column family and its writer maintenance. It enables thin author reads
through the DB, query, relay and CLI crates. The combined primary record, thin
postings, logical Wok v5 schema, query policy, snapshot cache and synchronous WAL
commit policy stay the same. It is off by default:

```sh
# Current dual-index layout, reading thin postings (control).
cargo build --release --locked -p wok-cli --features rocksdb-thin-author-reads \
  --target-dir target/rocksdb-dual-thin
# Separate physical layout, reading the same thin postings.
cargo build --release --locked -p wok-cli --features rocksdb-coverless \
  --target-dir target/rocksdb-coverless
```

Use separate new database directories and configurations for these binaries.
The coverless marker is
`wok-rocks-v2:combined:thin-author:reverse-order:sync-wal`; the dual-index marker
remains `wok-rocks-v1:combined:dual-author:reverse-order:sync-wal`. Each binary
checks the exact column family set and reads the marker without a writable
native open before accepting an existing directory. Neither layout opens or
converts the other; do not replace the directory during open. The coverless
author accessor returns the thin index and raw access to removed DBI 23 fails.
The audit requires that the covering column family is absent, verifies each
thin posting's existence and empty value, and checks that its exact count gives
one posting per primary. Both layouts retain the same signature/body checks and
length-framed local-ID, PackedEvent and encoded-payload fingerprint.

No command converts between these RocksDB physical layouts, and the layout
features themselves establish no storage, write or compaction savings.
Verified JSON import into a new database preserves event identity, but is not a
general byte-preserving conversion of local IDs, encoded payloads or kept tables.
Any causal layout comparison needs separately built and verified seeds, the same
thin read plan, configuration and durability, and a budget for the full new
database and temporary files. Keep original seeds unchanged; shared-file copies
or deletion of an old covering column family are not the experiment described
here.

The separate `rocksdb-author-heads` feature extends the coverless layout with
the derived `wok_author_frontiers_v1` column family. Each exact 32-byte author
key stores its newest position and, if present, its second newest position.
Each position uses two big-endian `u64` values, timestamp and local ID; values
are exactly 16 or 32 bytes, with the second position strictly older. The writer
derives changed frontiers from the final transaction overlay and commits them
with their postings in the same synchronous WAL batch. Unchanged frontier
values are not rewritten. The format marker is
`wok-rocks-v3:combined:thin-author-frontiers:reverse-order:sync-wal`. All three
layouts require their own exact column family set and marker before a writable
open. `wok migrate rocksdb` creates this v3 layout from a stopped Wok LMDB
v4/v5 source; it does not convert an existing v1 or v2 RocksDB directory.

That layout feature retains the established range-seek reader as a control.
The additional `rocksdb-author-head-reads` feature enables native batched point
reads for the depth-one initialization of wide, pure-author scans:

```sh
# Same frontier layout and writer, retaining ordinary initial range seeks.
cargo build --release --locked -p wok-cli --features rocksdb-author-heads \
  --target-dir target/rocksdb-author-heads-control
# Same layout, initializing eligible feeds from author frontiers.
cargo build --release --locked -p wok-cli --features rocksdb-author-head-reads \
  --target-dir target/rocksdb-author-heads-reader
```

Both features are off by default and forward through the DB, query, relay and
CLI crates. Use fresh, separate database directories for this format. The typed
read API accepts borrowed author keys and binds each native MultiGet to the
transaction's snapshot. It preserves input order and duplicates, validates
frontier bytes, and returns small owned positions without populating the primary
record cache. Single-author scans, other selected plans, missing frontiers and
frontiers outside the usable query window use ordinary index collection.

An eligible historical scan initializes at most 32 authors per native call. It
immediately consumes and charges every member before checking its pause budget
again, so initialization may overrun by one batch; this is not a wall-clock
bound or identical per-key scheduler state. The existing merge receives each
first candidate and resumes at the stored second position. Keeping that exact
lookahead position preserves which newly backdated records can be encountered
after a snapshot refresh. Later refills, event validation, visibility, latest-ID
checks, deduplication and limits use the established query path. Completeness
peeks always use ordinary collection with their existing work and candidate
budgets, including when beginning an unscanned filter.

If every frontier in the first full batch is present, supported, and newer than
the requested window, the scan stops issuing frontier lookups and initializes
all remaining ranges with ordinary seeks. Unprobed authors are still checked;
none are treated as empty. A mixed first batch retains frontier reads. This
choice can bypass useful later frontiers, and skipped frontier bytes remain the
offline audit's responsibility.

An exhausted author's shortcut can skip malformed neighboring-author rows that
ordinary boundary lookahead would visit. Complete corruption detection remains
the offline audit's responsibility.

The physical audit verifies that both stored positions refer to authoritative
primaries and thin postings of the same author and timestamp. Together with
per-primary ordering checks and the thin-index bijection, this proves that each
frontier contains exactly the newest one or two positions with bounded working
memory. Derived frontier counts are separate from logical table counts. The
new metadata adds writer work and storage; same-format reader comparisons do
not measure the effect of removing the covering index or establish a write,
space or latency improvement.

Primary point reads use stack-encoded local-ID keys and cache native pinned
combined bytes, sharing the same snapshot and cache as owned covering records.
The exact PackedEvent/payload bytes and independent missing/empty components are
preserved. Pins are released with the transaction and can retain complete cache
blocks until then; measure memory as well as latency when evaluating this path.

The initial read-oriented options use a shared 8-GiB hyper-clock block cache,
2-GiB row cache, 4-KiB blocks, Bloom filters, binary/hash data-block indexes,
LZ4 compression, dynamic levels, up to eight background jobs and four
subcompactions, 64-MiB per-CF write buffers, a 2-GiB total write-buffer target and
1-GiB WAL target. These are explicit experimental choices rather than claims of
universal optimality. Iterators preserve total logical ordering across prefixes.

`rocksdb-check` opens the database read-only. Run it offline against a closed
seed/copy. It streams all authoritative records with bounded working memory,
verifies each signature/body against its PackedEvent, checks every event's thin
author record (and covering record in the dual-index layout), and independently
counts every logical table. These counts do not verify the semantic contents of
every other derived index. It
fails on corruption, missing components, cover divergence, counter disagreement
or RocksDB background errors. It does not prove that an input corpus contained
all intended events; compare its event count with the verified import manifest.

RocksDB holds an exclusive writer-process lock. The LMDB workflow in which a
second process imports while the relay is open is unavailable. Stop the relay
before a separate mutating utility. Use `wok migrate rocksdb` for the verified
full-state LMDB copy and `wok backup --output <new-directory>` for a native
directory checkpoint. Legacy LMDB compact-to-file operations are not a RocksDB
backup interface. Keep original databases and follow the
[cutover and rollback procedure](migration-to-rocksdb.md).
Long operator scans still use the existing transaction-lifetime borrow
API and can retain copied data until transaction drop; the dedicated offline
physical audit avoids that accumulation.

For a relay comparison, freeze source/config/binary identities and test both
read and write behavior before measurement. Use the same signed corpus, query
plans, offered arrival deadlines, caps and seed-copy policy across backends.
Acknowledge terminal COUNT or refusal outside measurement; never abandon a
COUNT scan that may still contend with writers. Keep buffered-ACK relays
explicitly separate from synchronous commit policies. Preserve raw outcomes,
correctness/readback counters, final resource accounting and all censored work;
a censored latency histogram is not an eligible latency winner.

The cursor regression suite checks traversal against the seeking writer cursor,
snapshot and borrowed-byte lifetimes, failed positioning and duplicate edges:

```sh
cargo test --release --locked -p wok-db --features rocksdb-backend \
  --target-dir target/rocksdb --test rocks_cursor
```

Its sequential-traversal check uses RocksDB's per-thread performance counters
to require zero seeks after initial positioning. Counter diagnostics demonstrate
which native operations ran; their instrumented elapsed times are not network
latency measurements. Keep profiling separate from matched-arrival timing runs.

The opt-in `rocksdb-read-diagnostics` feature exposes
`wok_db::read_diagnostics::measure` for one synchronous read closure. It records
Wok iterator calls, typed and fallback decoding, resume-key materialization,
selected owned copies, covering-record copies and primary pin/cache operations.
Use a fresh transaction inside the closure to include its cache population.
The byte counters cover the named materializations, not total allocation or
live memory; returned pin bytes do not establish native zero-copy behavior or
the size of retained cache blocks. RocksDB's internal count-level PerfContext
metrics are reported separately, and native block reads may hit the OS cache.
The scope owns, resets and disables that thread's PerfContext, including on
unwind; it cannot restore an unknown previous native perf level. Keep writes,
environment opening and unrelated reads outside the scope. Ordinary builds
exclude both the API and its recording hooks. Its focused regressions run with:

```sh
cargo test --release --locked -p wok-db --features rocksdb-read-diagnostics \
  --target-dir target/rocksdb-diagnostics --lib read_diagnostics::tests
```

The query crate also has ignored, deterministic diagnostics for feed planning:

```sh
cargo test --release --locked -p wok-query --features wok-db/rocksdb-backend \
  --target-dir target/rocksdb --test feed_frontier -- --ignored --nocapture
cargo test --release --locked -p wok-query --features wok-db/rocksdb-backend \
  --target-dir target/rocksdb --test global_probe -- --ignored --nocapture
cargo test --release --locked -p wok-query --features wok-db/rocksdb-backend \
  --target-dir target/rocksdb --lib author_index_causal_diagnostic -- --ignored --nocapture
```

These compare warmed local fixtures with fresh transactions per query, verify
ordered results against stored metadata and report candidate/work counts. The
bounded chronological probe is a diagnostic, not a production planner change:
it includes sparse and adverse histories where probing adds work before the
author merge. Local timings do not establish network latency or a schema change.
The author-index diagnostic forces thin and covering reads in the same binary,
including normal visibility, completeness and payload decoding. Its single-author
fixture has contiguous local IDs and a warm shared native cache, so it does not
represent the primary-record locality of an interleaved multi-author corpus.

The range-initialization diagnostic uses interleaved authors and forces the
legacy newest-first endpoint and the selected `until` endpoint in one binary.
It checks ordered results and logical work while retaining the separate native
operation and named-copy counts:

```sh
cargo test --release --locked -p wok-query --features rocksdb-read-diagnostics \
  --target-dir target/rocksdb-diagnostics --lib range_initialization_native_operations \
  -- --ignored --nocapture
```

The ignored `range_seed_diagnostic::diagnose_existing_seed_ranges` test can run
the same comparison on an existing database. Set `WOK_RANGE_DIAGNOSTIC_DB` to a
verified disposable copy, `WOK_RANGE_DIAGNOSTIC_FILTERS` to an explicit JSON
array of `{"shape":"author|feed500|tag|id","filter":{...}}` records, and
`WOK_RANGE_DIAGNOSTIC_PASSES` to one through four. Each filter needs an explicit
`until`, limit 50 and the selector matching its shape. It opens the copy through
the read-only API, alternates the arms with fresh transactions, and retains
per-pass result/body digests, completeness, chronological work and counters.
The input file and filters have their own identities; representative static
filters must not be described as the matched network pool. Keep pristine seeds
closed, preserve copy provenance, and run this diagnostic separately from clean
network timings.

The ignored `feed_query_diagnostic::diagnose_existing_seed_author_frontiers`
test compares the ordinary author range reader with frontier initialization in
one binary against the same disposable v3 database. Build it with
`rocksdb-author-head-reads,rocksdb-read-diagnostics`. Set
`WOK_AUTHOR_FRONTIER_DIAGNOSTIC_DB` to the verified disposable target,
`WOK_AUTHOR_FRONTIER_DIAGNOSTIC_FILTERS` to the retained range-metadata file and
`WOK_AUTHOR_FRONTIER_DIAGNOSTIC_PASSES` to one through four. It selects only
pure 500-author, limit-50 records while preserving their original indexes and
hashes, alternates the arms, and checks exact ordered IDs, PackedEvent, encoded
payload, decoded bodies and final completeness hints. The separate
`wok-author-frontier-query-diagnostic-v1` report retains incomplete and failed
arms as ineligible. It records actual seeded and fallback outcomes separately
from the 30 wrapper counters and 13 native counters; observing outcomes adds no
header reads. Peeks must issue no header lookup. Reported query operations
exclude transaction creation/drop, environment opening and final stored-byte
verification. Shared native/OS caches remain warm; these counts do not measure
latency, transaction lifecycle savings or physical device I/O.

A private, ignored DB test, `physical_seed_builder::build_disposable_v3_target`,
constructs a disposable v3 diagnostic target from an explicitly supplied v1
copy and retained audit/inventory provenance. It requires
`WOK_PHYSICAL_BUILDER_SOURCE`, `WOK_PHYSICAL_BUILDER_DESTINATION` and
`WOK_PHYSICAL_BUILDER_PROVENANCE`; it has no default database path. It streams
the kept physical column-family bytes unchanged, omits the covering family and
derives the author frontiers. Only the format marker differs in the default
column family. A rejected incomplete marker protects the target through copy
and full signature/body/layout audit; sealing, normal read-only reopen and
normalized byte-hash equality precede its ready report. Partial and failed
outputs remain retained. It is a lab harness, not a general migration command.
Its raw rewrite changes SST layout: compare readers within the generated v3
target, and retain the original pristine database closed. Source, binary,
resource, disk-growth and process-closure checks belong to the host wrapper;
streaming alone does not bound total engine memory or compaction disk peaks.
