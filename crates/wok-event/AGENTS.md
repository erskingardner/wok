# wok-event

Leaf crate: Nostr event JSON, NIP-01 id hashing, Schnorr verification, PackedEvent, and kind helpers. `#![forbid(unsafe_code)]`.

Byte layouts and validation follow pinned strfry for migration/event-identity, but protocol semantics follow the NIPs. Database version constants live here: strfry import `STRFRY_DB_VERSION = 3`, Wok-owned `WOK_DB_VERSION = 4`.

## Layout

- `Cargo.toml` — crate manifest
- `src/` — library modules
- `tests/` — parser and packed-event property/fuzz-style tests

## When changing this crate

- Ingress parsing goes through `json::parse_strict`. Stored JSON goes through `json::to_tao_string` (tao::json byte parity: duplicate keys rejected, U+007F escaped, compact sorted keys).
- Event ids hash the NIP-01 preimage (`json::write_nip01`), which differs from tao only in writing U+007F verbatim. `legacy_event_id_hash` / `IdPreimage::Nip01OrLegacy` accept the tao preimage strfry hashed, for stored events only; never for published EVENTs.
- JSON nesting is capped at 128 (DoS hardening; documented in `docs/known-differences.md`).
- PackedEvent integers are native endian. Fried import/export is little-endian-only.
- Single-letter tag values over `MAX_INDEXED_TAG_VAL_SIZE` (255 bytes) pack as `indexed_tag_value` (`0xFF` + SHA-256). Build tag, replacement and filter keys from that form; recovering a long original needs the payload JSON.
- Downstream crates (`wok-db`, `wok-query`, `wok-relay`) depend on the public API in `src/lib.rs`.
