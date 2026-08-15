# wok-negentropy

NIP-77 Negentropy set reconciliation: protocol, in-memory Vector storage, and persistent LMDB B-tree. Protocol version `0x61` (NIP-77 v1). `#![forbid(unsafe_code)]`.

Byte-compatible with strfry's `external/negentropy` at the pinned C++ commit on little-endian hosts. Node encoding is explicit (no raw struct dumps).

## Layout

- `Cargo.toml`
- `src/` — protocol, encodings, Vector, B-tree, LMDB backend, filter cache
- `tests/` — protocol property tests

Relay sessions and `wok sync` sit above this crate. Persistent trees live in the `negentropy` DBI (`wok-db` schema).
