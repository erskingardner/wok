# wok-event/tests

Integration tests for the event crate. Fast; no LMDB.

| File | Role |
| --- | --- |
| `parser_prop.rs` | Property tests for JSON parse / canonical encoding |
| `packed_fuzz.rs` | PackedEvent packing/view round-trips |

Unit tests also live next to modules under `src/` via `#[cfg(test)]`. Protocol-level event tests belong in `crates/wok-compat/tests/`.
