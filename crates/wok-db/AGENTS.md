# wok-db

Wok LMDB storage and the read-only strfry v3 migration boundary.

Runtime databases are Wok-owned (v5 marker). strfry v3 is opened only as a migration source. This crate also owns NIP-50 search postings, NIP-62 vanish markers, NIP-86 moderation records, payload compression, integrity, and index rebuild.

## Layout

- `Cargo.toml` — crate manifest (`lmdb-sys`, zstd, flatbuffers)
- `src/` — env, schema, transactions, write/read paths
- `tests/` — comparators, recovery, gift-wrap, vanish, optional C++ roundtrip

## Invariants

- Transactions, cursors, and mmap slices must never cross a Tokio `.await`. Callers run DB work on dedicated OS threads and copy results into owned values first.
- `#![deny(unsafe_code)]` with FFI isolated in `env`, `txn`, and migration snapshot helpers.
- Authoritative primary bytes are PackedEvent (`Event`) and payload (`EventPayload`). Secondary indexes are derived and rebuildable (`reindex`).
- Reindex (`PackedEventRebuild::RepackLongTags`) is the only writer that changes a stored PackedEvent, and only when removing its hashed long tag values gives the stored bytes back (`long_tags`). Migration copies it unchanged.
- That reindex then deletes the versions that deletion requests' repaired `a` tags name (long, replaceable `<kind>:<pubkey>:`, or a kind with leading zeros; `write::is_repaired_address`), through the write path's own `a`-tag lookup and `delete_event_basic`, and reports their local IDs so the CLI can verify the original's fingerprint without them.
- `wok_Event__search`, `wok_Event__tagKind`, `wok_VanishPubkey`, and `wok_Moderation` are Wok DBIs (not in strfry v3).
- `wok_Event__tagKind` is complete only once its `indexed-through` marker reaches the sequence high-water mark (`tag_kind_index_state_ro`). Earlier releases leave stale entries when they delete events; readers must check the event is stored.

See `docs/lmdb-v3.md` for the import contract and `docs/migration-from-strfry.md` for the operator path.
