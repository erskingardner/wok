# wok-db/src

RocksDB environment and logical table access. LMDB is only a read-only migration source. Start at `lib.rs` for the public API.

| File | Role |
| --- | --- |
| `lib.rs` | Module graph and re-exports |
| `rocks/env.rs` | Runtime `Env` / `EnvOptions`, physical marker, exclusive process lock |
| `rocks/txn.rs` | `RoTxn` / `RwTxn`, native snapshots, pins, cursors and writer overlay |
| `error.rs` | `DbError` |
| `schema.rs` | DBI names and open flags (`rasgueadb_*`, plus Wok search/tag-kind/vanish/moderation) |
| `keys.rs` | Key encode/decode re-exports |
| `comparators.rs` | C++-compatible composite key comparators |
| `fbs.rs` | FlatBuffers for Meta, NegentropyFilter, CompressionDictionary |
| `payload.rs` | Raw / zstd EventPayload, decompressor |
| `lookup.rs` | Read helpers on Ro/Rw txns (id, created_at, negentropy filters) |
| `write.rs` | Insert/delete/replace matching strfry `events.cpp` |
| `search.rs` | NIP-50 term postings |
| `tag_kind.rs` | `(tag, kind, created_at)` postings, schema and indexed-through markers, bounded backfill steps |
| `vanish.rs` | NIP-62 markers, query suppression, bounded sweep that resumes from its stored progress |
| `moderation.rs` | NIP-86 records (prefix-keyed), snapshot, query suppression |
| `purge.rs` | Count and delete superseded replacement history in bounded batches |
| `long_tags.rs` | Detect and repack (for reindex) records whose PackedEvent lacks long single-letter tag values |
| `integrity.rs` | Primary + every event-derived index check |
| `state.rs` | Transactional sequence, lazy author counters, visibility generation, vanish sweep progress |
| `crash_tests.rs` | Test-only checkpoints and subprocess kill/restart coverage |
| `reindex.rs` | Rebuild indexes from PackedEvent + payload primaries |
| `migration.rs` | Import verification, event fingerprints and read-only source helpers for `wok migrate` |

Unsafe is allowed only at isolated native FFI boundaries (read-only LMDB import and reviewed OS helpers). Do not add new `unsafe` elsewhere without isolating it the same way.
