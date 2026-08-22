# Wok

Rust Nostr relay that began as a reimplementation of [strfry](https://github.com/hoytech/strfry). strfry v3 is a verified, one-way import format. Runtime databases are Wok-owned (v4 marker) and protocol behavior follows pinned NIPs, not every strfry quirk.

License: AGPL-3.0-or-later. Workspace version lives in the root `Cargo.toml`. MSRV is 1.94.1 (`rust-toolchain.toml` pins a newer stable for local builds).

## Layout

| Path | What it is |
| --- | --- |
| `crates/` | Cargo workspace members (relay, storage, transports, CLI, tests) |
| `docs/` | Architecture, NIPs, config, migration, ops, benchmark reports |
| `scripts/` | Release checks and benchmark campaign wrappers |
| `contrib/` | Packaging extras (systemd unit) |
| `fuzz/` | Separate cargo-fuzz workspace for untrusted-input targets |
| `.github/workflows/` | CI, fuzz, security, platforms, release |

Generated or local-only: `target/`, `bench-results/`, `strfry-db/`, `fuzz/artifacts/`, `fuzz/corpus/`. Do not treat those as source.

## Crate map

```
clients ──WS──► wok-ws ──┐
clients ─Unix─► wok-unix─┼─► wok-relay (crossbeam) ─► dedicated OS threads
clients ─FIPS─► wok-fips─┤
                         │     writer / req / monitor / negentropy / cron
                         └ outbound mpsc back to the connection task
```

| Crate | Role |
| --- | --- |
| `wok-event` | Event JSON, NIP-01 hashing, Schnorr, PackedEvent |
| `wok-db` | LMDB storage, v3 snapshot/import, indexes, integrity |
| `wok-query` | Filters, DBScan, QueryScheduler, live monitors |
| `wok-negentropy` | NIP-77 protocol and persistent B-tree |
| `wok-relay` | Transport-neutral dispatcher, AUTH, plugins, config |
| `wok-ws` | HTTP + WebSocket (in-house RFC 6455/7692 codec) |
| `wok-unix` | Length-prefixed Unix `SOCK_STREAM` transport |
| `fips-message` | Wok-independent FIPS V1 framing and reassembly |
| `wok-fips` | Native FIPS datagram transport (Linux/FreeBSD/macOS) |
| `wok-cli` | `wok` binary: relay, migrate, doctor, mesh, dbutils |
| `wok-bench` | Comparative load harness (excluded from default CI tests) |
| `wok-compat` | NIP conformance, e2e, optional C++ differentials |

## Invariants

- Tokio owns network I/O only. LMDB transactions, cursors, and mmap slices must never cross `.await`.
- One application-level LMDB writer; worker pools per stage (`numThreads.*`).
- New databases use Wok v4. strfry v3 is accepted only by `wok migrate strfry`. Never mix writers.
- Event identity (id, sig, tags, content, stored payload) is preserved across migration. Hashing and stored JSON go through `wok_event::json` (`parse_strict` / `to_tao_string`), not stock `serde_json`.
- ID and author filters are exact 32-byte values. Prefix filters are rejected.
- Advertise only NIPs with observable relay behavior and conformance coverage (`wok-relay` capabilities catalog).
- Safe crates `forbid(unsafe_code)`. LMDB/OS FFI is isolated and documented (`wok-db` env/txn, `wok-cli` doctor/migrate, `wok-relay` rlimit).

Source-of-truth order: pinned NIPs → explicit Wok decisions in `docs/` and `PLAN.md` → lossless migration / event identity → pinned strfry as historical/differential reference.

## Commands

```bash
cargo build --release -p wok-cli          # binary: target/release/wok
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --exclude wok-bench --locked
cargo test -p wok-compat --test nip_conformance --test e2e_transports
```

Optional C++ differentials need a strfry binary (`STRFRY_BIN`, default `/Users/jeff/code/strfry/strfry`):

```bash
cargo test -p wok-db --test cpp_roundtrip
cargo test -p wok-compat --test cpp_export --test cpp_negentropy
```

## Where to read next

- This directory's crate map: `crates/AGENTS.md`
- Architecture: `docs/architecture.md` and `docs/AGENTS.md`
- Compatibility: `docs/compatibility-policy.md`, `docs/known-differences.md`
- NIPs: `docs/nips.md` (pin: `656cecc7c0a815b6a2b218d3b5d6f078b3f4dbab`)
- Config sample: `docs/wok.toml`
- Living plan / non-goals: `PLAN.md`
