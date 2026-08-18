# wok-db/src

LMDB environment and table access. Start at `lib.rs` for the public API.

| File | Role |
| --- | --- |
| `lib.rs` | Module graph and re-exports |
| `env.rs` | `Env` / `EnvOptions`; LMDB FFI isolated here |
| `txn.rs` | `RoTxn` / `RwTxn` and cursors; mmap lifetime tied to txn |
| `error.rs` | `DbError` |
| `schema.rs` | DBI names and open flags (`rasgueadb_*`, plus Wok search/vanish/moderation) |
| `keys.rs` | Key encode/decode re-exports |
| `comparators.rs` | C++-compatible composite key comparators |
| `fbs.rs` | FlatBuffers for Meta, NegentropyFilter, CompressionDictionary |
| `payload.rs` | Raw / zstd EventPayload, decompressor |
| `lookup.rs` | Read helpers on Ro/Rw txns (id, created_at, negentropy filters) |
| `write.rs` | Insert/delete/replace matching strfry `events.cpp` |
| `search.rs` | NIP-50 term/bigram postings |
| `vanish.rs` | NIP-62 markers, query suppression, bounded sweep |
| `moderation.rs` | NIP-86 records (prefix-keyed), snapshot, query suppression |
| `integrity.rs` | Primary + every event-derived index check |
| `reindex.rs` | Rebuild indexes from PackedEvent + payload primaries |
| `migration.rs` | Read-only LMDB snapshot + event fingerprint for `wok migrate` |

Unsafe is allowed only at the LMDB FFI boundary (`env`, `txn`, snapshot copy). Do not add new `unsafe` elsewhere without isolating it the same way.
