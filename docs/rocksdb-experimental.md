# Experimental RocksDB relay backend

The optional `rocksdb-backend` feature builds the real Wok relay on an
experimental RocksDB storage implementation. The default build still uses LMDB.
The feature currently needs Rust 1.88 or newer for rocksdb 0.25 / RocksDB 11.8.1;
the default LMDB build retains its existing MSRV.

```sh
cargo build --release -p wok-cli --features rocksdb-backend --locked
./target/release/wok --config rocks-relay.toml import < events.jsonl
./target/release/wok --config rocks-relay.toml rocksdb-check
./target/release/wok --config rocks-relay.toml relay
```

Use a separate new `db` directory in the configuration. The RocksDB binary
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

The physical schema uses:

- one combined record per local event ID, preserving the exact PackedEvent and
  payload components, including their independent presence;
- a thin author/time posting index for multi-author feeds and a separate
  covering author/time index for single-author queries;
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
resumption. Candidate depths, merge ordering and work accounting are unchanged.
A read-only duplicate range with a full starting key/value positions
directly at that inclusive endpoint, using one forward seek for newest-first
traversal of the reversed indexes. Other operations retain total logical order;
no prefix-only iterator mode or implicit range truncation is enabled.

The two reserved tag/kind progress keys have a small in-memory mirror loaded
with bounded forward scans at open. Each transaction pairs an immutable mirror
version with the same RocksDB snapshot; a commit publishes its new mirror after
the synchronous batch succeeds. This avoids reverse scans through historical
deleted marker values while preserving duplicate ordering, aborts and old reader
snapshots. It changes no persistent record or format and needs no seed rewrite.

A single-author query's existing plan selects the covering index. Its candidates
populate the transaction's combined-record cache; visibility and payload checks
continue through the ordinary Wok path. Multi-author queries keep thin postings
so unselected candidate payloads are not pulled into a feed merge.

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
and covering author records, and independently counts every logical table. It
fails on corruption, missing components, cover divergence, counter disagreement
or RocksDB background errors. It does not prove that an input corpus contained
all intended events; compare its event count with the verified import manifest.

RocksDB holds an exclusive writer-process lock. The LMDB workflow in which a
second process imports while the relay is open is unavailable. Stop the relay
before a separate mutating utility. Legacy LMDB file upgrade, strfry snapshot
migration and LMDB compact-to-file operations are not RocksDB migration or
backup interfaces; keep original databases and use verified JSON export/import.
The feature is intended for isolated comparison and validation, not production
cutover. Long operator scans still use the existing transaction-lifetime borrow
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
