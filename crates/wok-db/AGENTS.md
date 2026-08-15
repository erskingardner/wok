# wok-db

Wok LMDB storage and the read-only strfry v3 migration boundary.

Runtime databases are Wok-owned (v4 marker). strfry v3 is opened only as a migration source. This crate also owns NIP-50 search postings, NIP-62 vanish markers, payload compression, integrity, and index rebuild.

## Layout

- `Cargo.toml` — crate manifest (`lmdb-sys`, zstd, flatbuffers)
- `src/` — env, schema, transactions, write/read paths
- `tests/` — comparators, recovery, gift-wrap, vanish, optional C++ roundtrip

## Invariants

- Transactions, cursors, and mmap slices must never cross a Tokio `.await`. Callers run DB work on dedicated OS threads and copy results into owned values first.
- `#![deny(unsafe_code)]` with FFI isolated in `env`, `txn`, and migration snapshot helpers.
- Authoritative primary bytes are PackedEvent (`Event`) and payload (`EventPayload`). Secondary indexes are derived and rebuildable (`reindex`).
- `wok_Event__search` and `wok_VanishPubkey` are Wok DBIs (not in strfry v3).

See `docs/lmdb-v3.md` for the import contract and `docs/migration-from-strfry.md` for the operator path.
