# wok-compat

Cross-crate test crate: NIP conformance, transport e2e, plugins, and optional C++ differentials. Not a runtime dependency of the relay.

NIPs pin used by the conformance suite: `656cecc7c0a815b6a2b218d3b5d6f078b3f4dbab` (`nips_commit()` in `src/lib.rs`). C++ diffs need `STRFRY_BIN` (default `/Users/jeff/code/strfry/strfry`).

## Layout

- `Cargo.toml`
- `src/lib.rs` — shared helpers (sign events, temp DB, strfry spawn)
- `tests/` — the actual suites

CI runs every workspace test, including `nip_conformance` and `e2e_transports`. A separate pinned-reference job requires C++ tests with `WOK_REQUIRE_STRFRY=1`; they remain optional locally. `examples/reliability_soak.rs` is the load driver for the Linux soak.
