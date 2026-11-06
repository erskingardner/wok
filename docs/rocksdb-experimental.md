# RocksDB storage

RocksDB is Wok's sole runtime backend. A normal build includes the thin-author
posting layout, compact author frontiers and the optimized reader. LMDB is
vendored only for registered read-only imports of Wok v4/v5 and strfry v3.
There is no backend or physical-layout build selector. The retained storage
identity `rocksdb-author-heads-experimental` is a historical name; the v3 format
is unchanged so already verified v3 directories remain compatible.

```sh
cargo build --release --locked -p wok-cli
./target/release/wok storage-backend
```

Builds require Rust 1.88+, a C/C++ compiler and libclang. See
[the migration guide](migration-to-rocksdb.md) for offline conversion, checkpoints
and rollback. A runtime open refuses LMDB files, unknown nonempty directories,
incomplete migrations and incompatible RocksDB layouts. No database is
implicitly converted in place.

## Records and commits

The logical schema uses Wok v5. Its separate physical marker is
`wok-rocks-v3:combined:thin-author-frontiers:reverse-order:sync-wal`, with an
exact required column-family set. Older experimental v1 dual-author and v2
coverless directories are not this layout and are refused.

- Each local event ID has one combined record containing the exact PackedEvent
  and encoded payload components, including independent missing/empty states.
- Thin indexes use ordered native-integer/composite/duplicate key encodings,
  escaped string boundaries and reversed physical order, so logical newest-first
  scans advance forward. They preserve full local-ID ordering.
- The derived `wok_author_frontiers_v1` family stores each author's newest and,
  when present, second-newest positions. A position is a big-endian timestamp
  and local ID, both full `u64`s; values are exactly 16 or 32 bytes.
- Logical table counters, primaries, indexes, author frontiers and state changes
  commit in one cross-column-family `WriteBatch`. One application writer owns
  its transaction overlay.

WAL remains enabled and each successful commit uses `sync=true` before the relay
sends a positive OK. This is the commit policy, not proof of survival under every
storage-controller or power failure. Process-crash and acknowledged-write recovery
have separate tests; see [reliability validation](reliability.md).

## Historical reads

Each read transaction binds native iterators, point reads and its combined-record
cache to one RocksDB snapshot. Primary reads use stack-encoded local-ID keys and
cache native pinned bytes. Pins are released with the transaction and can retain
complete cache blocks until then; returned byte counts do not measure retained
memory. Long operator scans can retain data for their transaction lifetime.

Typed `Cursor::foreach_index` entries borrow physical postings during callbacks.
The reader compares prefixes and decodes ordered timestamps/local IDs without
reconstructing a logical row on every step. Only owned resume endpoints outlive
the callback; noncanonical records retain validated fallback decoding. A scan
reuses one physical cursor across ranges/refills within a call, then drops it
before returning to the scheduler. The next call uses owned endpoints and its
new transaction.

Selected ranges start at the inclusive `until` timestamp, preserving ties.
Bounded planner probes keep their established unbounded endpoints before a plan
is selected. A query validates rows it visits; damage strictly above its cutoff
can be skipped. The complete offline audit remains responsible for corruption
outside the requested range.

Wide scans initialize a shallow frontier from each author and merge candidates
by timestamp/local ID in a stable heap. Only consumed ranges grow refill batches,
bounded at 50 entries; single-range scans keep their existing batching.
Completeness lookahead caps new collection at one candidate per range and keeps
its existing work and visibility-check budgets. Hidden and already-sent matches
still consume work. A physical lookahead row may be visited to retain the next
resume endpoint, so one collected candidate is not a one-read guarantee.

For eligible depth-one wide pure-author scans, snapshot-bound native MultiGet
initializes at most 32 authors per call. Every returned member is immediately
charged and consumed before the next pause check; a slice may overrun by one
batch, not by an unbounded initialization. Each usable frontier seeds the first
candidate and the exact stored second endpoint. This preserves which backdated
records can be observed after refreshing a snapshot. Missing or unusable
frontiers fall back to ordinary seeks; single-author and other selected plans
retain their range path. Completeness peeks always use ordinary collection,
including when beginning an unscanned filter.

If the first full batch is entirely present, supported and newer than `until`,
remaining authors use ordinary seeks without further frontier lookups. They are
not assumed empty. A mixed first batch keeps the frontier path. An exhausted
frontier shortcut can skip malformed neighboring-author boundary rows that an
ordinary lookahead would visit; the offline audit checks the full database.

Two reserved tag/kind progress values have a small in-memory mirror bound to the
same snapshot as each transaction. A successful synchronous commit publishes its
new mirror afterward. This avoids repeatedly scanning historical deleted marker
rows while preserving aborts, old snapshots and duplicate ordering.

## Operations and resource limits

RocksDB takes an exclusive writer-process lock. Stop the relay before a separate
mutating utility, backup or rebuild. Use `wok backup --output <new-directory>`
for a native checkpoint; the legacy LMDB compact-file interface is unavailable.
Keep the entire checkpoint directory and its physical format together. New
native directories use `0700`; writable opens remove other-user access from the
directory. Read-only import does not alter source permissions.

The native options use a shared 8-GiB hyper-clock block cache, 2-GiB row cache,
4-KiB blocks, Bloom filters, binary/hash data-block indexes, LZ4 compression,
dynamic levels, up to eight background jobs/four subcompactions, 64-MiB per-family
write buffers, a 2-GiB total write-buffer target and a 1-GiB WAL target. These are
configured engine targets, not total process-RSS caps or universal optimums.
Legacy `database.map_size`, `max_readers` and `no_read_ahead` settings do not tune
RocksDB; the free-disk reserve and application storage quotas still apply.

`wok doctor` combines configuration and storage checks. `wok rocksdb-check` opens
the database read-only for a bounded-memory physical audit of all primaries,
payloads, signatures, thin author postings/frontiers and logical table counts.
It checks both stored author positions are exactly the newest ones, rather than
trusting metadata. It reports native background errors. It does not establish
that an imported corpus contained every intended event, or semantically audit
every other derived index; compare counts with the migration manifest and use
`wok integrity`/`doctor` as appropriate. Run audits against a closed database.

## Read diagnostics

The opt-in `rocksdb-read-diagnostics` feature adds synchronous operation counters
and test-only probes; ordinary release builds omit the recording hooks. It is
not a backend selector or runtime setting.

```sh
cargo test --release --locked -p wok-db --test rocks_cursor
cargo test --release --locked -p wok-db --features rocksdb-read-diagnostics \
  --lib read_diagnostics::tests
```

`wok_db::read_diagnostics::measure` owns, resets and disables that thread's native
PerfContext, including on unwind. Keep writes, environment opening and unrelated
reads outside its scope. Use fresh transactions to make record-cache population
explicit. Wrapper seek/decode/copy/pin/frontier counters and native PerfContext
counts are different units; native block reads can hit the OS cache. Instrumented
elapsed times are not clean network latency measurements. Pin bytes do not prove
zero-copy behavior or account for entire retained cache blocks.

For comparative load, freeze source/config/binary identities, use the same signed
corpus, offered deadlines, query shapes, seed-copy policy and resource caps, and
retain complete correctness/readback/resource outcomes. A terminal COUNT or
refusal must finish outside measurement before moving on. Keep buffered ACKs
separate from synchronous commits, and never rank a censored distribution as an
eligible latency winner. See [benchmark methodology](benchmarks.md).
