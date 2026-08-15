# wok-event

Leaf crate: Nostr event JSON, NIP-01 id hashing, Schnorr verification, PackedEvent, and kind helpers. `#![forbid(unsafe_code)]`.

Byte layouts and validation follow pinned strfry for migration/event-identity, but protocol semantics follow the NIPs. Database version constants live here: strfry import `STRFRY_DB_VERSION = 3`, Wok-owned `WOK_DB_VERSION = 4`.

## Layout

- `Cargo.toml` — crate manifest
- `src/` — library modules
- `tests/` — parser and packed-event property/fuzz-style tests

## When changing this crate

- Ingress parsing goes through `json::parse_strict`. Hashing and stored JSON go through `json::to_tao_string` (tao::json byte parity: duplicate keys rejected, U+007F escaped, compact sorted keys).
- JSON nesting is capped at 128 (DoS hardening; documented in `docs/known-differences.md`).
- PackedEvent integers are native endian. Fried import/export is little-endian-only.
- Downstream crates (`wok-db`, `wok-query`, `wok-relay`) depend on the public API in `src/lib.rs`.
