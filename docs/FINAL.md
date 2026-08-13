# Historical parity report and current migration boundary

This records the original Rust reimplementation parity work. That milestone is
historical evidence, not the current compatibility promise. Wok now supports a
verified one-way migration from strfry v3 into a Wok-owned v4 database and
follows [compatibility-policy.md](compatibility-policy.md).

## Implemented scope

- Historical LMDB v3 differential read/write implementation, now used as the
  read-only migration decoder (`wok-db`).
- Event validation, NIP-01 IDs, Schnorr, PackedEvent (`wok-event`).
- Filters, index scans, query scheduler, live monitors (`wok-query`).
- Negentropy protocol, Vector, persistent BTreeLMDB (`wok-negentropy`).
- Transport-neutral relay core: EVENT/REQ/CLOSE/COUNT/AUTH/NEG-* (`wok-relay`).
- WebSocket + HTTP NIP-11/metrics/landing (`wok-ws`).
- Length-prefixed Unix `SOCK_STREAM` (`wok-unix`).
- CLI relay/database/mesh tools plus `migrate strfry` (`wok-cli`).
- Differential, conformance, e2e, property tests (`wok-compat` and crate tests).
- Comparative bench harness (`wok-bench`).

## Source and specification trace

| Source | Pin |
|---|---|
| C++ strfry | `9acdaeb1f63919184ece5f2dd67af21f1ed62f1b` at `/Users/jeff/code/strfry` |
| nostr-protocol/nips | `656cecc7c0a815b6a2b218d3b5d6f078b3f4dbab` |
| LMDB contract | `golpe.yaml` / generated `defaultDb.h` / `PackedEvent.h` |

When strfry and a NIP disagree, Wok follows the pinned NIP unless migration or
event identity requires compatibility. See `docs/compatibility-policy.md`,
`docs/known-differences.md`, and `PLAN.md`.

## Historical compatibility evidence

- C++-created v3 databases and records remain readable for migration fixtures.
- The former bidirectional tests established the shared layout used by the
  importer. Current tests instead assert that strfry refuses Wok v4 and Wok
  refuses write transactions on strfry v3.
- `wok migrate strfry` proves source `data.mdb` remains unchanged, promotes a
  v4 snapshot, and compares complete event-record fingerprints before/after.
- Integrity tooling verifies metadata, payload envelopes, and every
  event-derived index in both directions. `wok doctor` adds decoded payload-ID
  checks, negentropy traversal, capacity, version/endianness, config, plugin,
  and socket-path diagnostics with human or JSON output.
- `wok reindex` rebuilds event and negentropy indexes in a sibling staging
  database, proves the primary event fingerprint is unchanged, promotes only
  after verification, and retains the original database as rollback material.

C++ reference source was not modified. Final `git status` in `/Users/jeff/code/strfry` was clean at the pin above.

## Nostr conformance evidence

Suite: `crates/wok-compat/tests/nip_conformance.rs` (independent of C++).

Covered relay behavior: NIP-01 structure/ID/sig/filters/EOSE/malformed and
unknown commands; NIP-09 deletion; NIP-11 advertisement; optional NIP-13
proof-of-work admission; NIP-40 expiration;
NIP-42 AUTH (advertised only with `serviceUrl`); NIP-45 COUNT; NIP-59
gift-wrap access/deletion behavior and live-only kind 21059 delivery; NIP-70
protected events; and NIP-77
NEG-OPEN. Client/application NIPs are not advertised merely because Wok can
store their event kinds.

Live NIP-11 HTTP: `e2e_transports::nip11_http_document`.

## Unix-socket evidence

- Framing unit tests including fragmented writes and stale-socket replacement (`wok-unix`).
- `unix_publish_and_subscribe`
- `ws_publish_unix_subscribe`
- `unix_publish_ws_subscribe`

Protocol: 4-byte big-endian length + UTF-8 JSON. Spec: `docs/unix-socket.md`.

## Benchmark methodology and results

Harness launches wok and C++ strfry against independent disposable directories. Smoke profile (seed 1) verified import/export counts and scan counts for both relays.

Sample output (do not rank from one run):

See `docs/sample-bench-summary.md` and `docs/sample-bench-results.jsonl`.

```bash
cargo build --release -p wok-cli -p wok-bench
./target/release/wok-bench --profile smoke --out bench-results \
  --strfry /Users/jeff/code/strfry/strfry \
  --wok ./target/release/wok --seed 1
```

`--profile full` adds the named 18 scenarios, including live WebSocket catch-up. Unix publish/subscribe correctness is in e2e tests; the smoke unix row is an import/scan stand-in.

## Commands run and pass/fail

| Gate | Result |
|---|---|
| `cargo test --workspace --exclude wok-bench` | pass (0 failures) |
| `cargo fmt --all` | applied |
| `cargo clippy --workspace --all-targets -- -D warnings` | pass |
| `cargo build --release -p wok-cli -p wok-bench` | pass |
| `wok-bench --profile smoke` | all trials `ok=true` |
| C++ strfry git status | clean, pin unchanged |

Approximate unit/integration count from the last workspace run: 86 non-empty test results across crates (plus several 0-test lib/doc targets).

## Known limitations

See `docs/known-differences.md` for the full, current list. Highlights:

- Mesh client connections (router/stream/sync) don't offer permessage-deflate (server side supports it).
- NIP-11 software string is wok's URL.
- ID/author filters are exact 32 bytes (C++), not NIP-01 prefixes.
- Historical restricted-kind REQ filtering uses PackedEvent from the Event table (intentional; C++ ReqWorker currently views payload bytes).

## Post-review hardening (second pass)

A full second review against the C++ source produced these fix commits:

- `foreach_full` forward positioning now matches `generic_foreachFull`
  (`MDB_NEXT_NODUP` skip) with regression tests.
- tao::json byte parity: duplicate-key rejection, U+007F escaping, and ryu
  f64 presentation in the id-hash preimage and stored JSON; strict
  `parseUint64`/`stoull`/`from_hex` semantics.
- Relay error routing matches `RelayIngester.cpp` exactly (OK for EVENT/AUTH
  failures, CLOSED for REQ/COUNT failures, prefixed NOTICEs), pinned by an
  e2e conformance test.
- Negentropy stateless (tree-backed) sessions survive multiple NEG-MSG
  rounds; memory-view cleanup, per-conn view caps, and pre-restriction
  `maxSyncEvents` counting match `RelayNegentropy.cpp`.
- Writer closed-connection set is batch-local (no conn-id leak).
- Every strfry.conf key the server reads is parsed (strictly), including
  filterValidation; the real strfry.conf parses cleanly.
- Write-path LMDB errors propagate like C++ instead of being swallowed.
- Transports apply true async backpressure on the ingest queue (no blocking
  Tokio workers) and terminate slow clients at `max_pending_outbound_bytes`
  with byte accounting; WS auto-ping, keepalive, version check, and
  case-insensitive upgrade handling.
- Write-policy plugin I/O enforces `timeoutSeconds` and the 8192-byte record
  cap via a dedicated I/O thread; a hung plugin can no longer wedge the
  single LMDB writer.
- A polling `data.mdb` watcher notifies live subscriptions of writes made by
  other processes (C++ `file_change_monitor` parity).
- CLI: `wok event <levId>`; import/export byte-level fidelity with C++
  (abort-on-error export, import size accounting, fried endianness guards).

## Third pass: remaining gaps closed

- Worker pools per `numThreads.*` with C++ ThreadPool conn-hashed dispatch
  (single LMDB writer preserved).
- Graceful shutdown on SIGUSR1/SIGINT with connection drain and socket
  unlink; `nofiles` rlimit applied; unix socket owner/group chown.
- Config hot-reload on file change with golpe-noReload + listener-bound keys
  frozen.
- `dict train/compress/decompress` (ZDICT training; verified
  cross-implementation with the C++ binary).
- `stream` persists downloads (verified like WriterPipeline), streams uploads,
  and reconnects with non-blocking capped backoff; `sync` does the full C++
  two-phase negentropy transfer (verified 150/150 events both directions
  against the C++ relay).
- `router` with tao-config parsing, per-URL reconnecting clients, hot
  reconfig, and plugin gating (validated live against the C++ relay).
- permessage-deflate via an in-house RFC 6455/7692 codec (the Rust WS
  ecosystem has no extension support); negotiation mirrors uWS, with a
  raw-socket e2e proving compressed frames both directions.

## Recommended production soak and cutover

1. Stop strfry and run `wok migrate strfry` into a new output directory.
2. Review the manifest and translated config.
3. Soak `wok relay` with production-like publish/REQ/COUNT/AUTH/negentropy traffic for at least one retention/expiration cycle.
4. Cut over DNS/proxy; keep the original v3 database and config untouched for rollback (`docs/cutover.md`).
5. Run `wok-bench --profile full` on the target host with a real corpus (`--corpus`) before claiming performance.

## Improvement-program audit (2026-08-13)

The post-parity improvement stack was reviewed again as one combined diff,
rather than relying only on each feature's focused tests. It covers safe
NIP-59 defaults, request-wide query ceilings and stress benchmarks, NIP-62,
canonical NIP-45 HLL values, structured/bounded observability, the NIP-98
operator dashboard, reconnecting stream behavior, and bounded idempotent
negentropy builds.

The final audit rechecked the current upstream NIP-45, NIP-62, and NIP-98 text;
capability advertisement; migration/reindex behavior; reload/frozen settings;
database schema handling; admin authentication and write boundaries; release
workflows; and every stacked PR base. It added canonical browser-visible admin
origins plus a real HTTP test covering the public shell, unauthorized API
access, a valid signature despite a hostile `Host` header, overview data, and
replay rejection.

Final local gates passed with zero failures:

- `cargo fmt --all -- --check`
- `cargo test --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo build --locked --release -p wok-cli`
- `wok-bench --profile smoke` against the local strfry binary: every scenario
  reported `ok=true`, with zero errors and zero mismatches

No `v0.1.0` tag or GitHub Release existed at audit time. Because this is still
the first release, the post-parity `Unreleased` entries were folded into the
dated `0.1.0` section in a dedicated release commit after the complete PR stack
was merged. Only that exact green commit should receive the `v0.1.0` tag.
