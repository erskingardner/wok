# wok final report

Rust reimplementation of C++ strfry. This document is the definition-of-done record.

## Implemented scope

- Exact LMDB v3 open/read/write without migration (`wok-db`).
- Event validation, NIP-01 IDs, Schnorr, PackedEvent (`wok-event`).
- Filters, index scans, query scheduler, live monitors (`wok-query`).
- Negentropy protocol, Vector, persistent BTreeLMDB (`wok-negentropy`).
- Transport-neutral relay core: EVENT/REQ/CLOSE/COUNT/AUTH/NEG-* (`wok-relay`).
- WebSocket + HTTP NIP-11/metrics/landing (`wok-ws`).
- Length-prefixed Unix `SOCK_STREAM` (`wok-unix`).
- CLI parity for relay, import/export/scan/delete/info/compact/monitor/dict/negentropy/integrity and mesh helpers (`wok-cli`).
- Differential, conformance, e2e, property tests (`wok-compat` and crate tests).
- Comparative bench harness (`wok-bench`).

## Source and specification trace

| Source | Pin |
|---|---|
| C++ strfry | `9acdaeb1f63919184ece5f2dd67af21f1ed62f1b` at `/Users/jeff/code/strfry` |
| nostr-protocol/nips | `656cecc7c0a815b6a2b218d3b5d6f078b3f4dbab` |
| LMDB contract | `golpe.yaml` / generated `defaultDb.h` / `PackedEvent.h` |

When C++ and a NIP disagree, wok preserves C++ storage and filter matching, documents the gap, and does not advertise unsupported behavior. See `docs/known-differences.md` and `PLAN.md`.

## Compatibility evidence

- `crates/wok-db/tests/cpp_roundtrip.rs`: C++-created DB opens as v3; Rust-init DB is readable by C++ `info`; Rust write is present in C++ `export`.
- `crates/wok-compat/tests/cpp_export.rs`: Rust write → C++ export; C++ import → Rust query; replacement; deletion; alternating C++/Rust writes; integrity after mixed writers; tag roundtrip.
- Integrity tool: `wok integrity` reports missing payloads, orphans, packed parse errors, and id-index count drift.

C++ reference source was not modified. Final `git status` in `/Users/jeff/code/strfry` was clean at the pin above.

## Nostr conformance evidence

Suite: `crates/wok-compat/tests/nip_conformance.rs` (independent of C++).

Covered: NIP-01 structure/ID/sig/filters/EOSE/malformed/unknown cmds; NIP-02 replaceable kind 3; NIP-09 deletion kind; NIP-11 advertisement; NIP-40 expiration; NIP-42 AUTH kind (advertised only with `serviceUrl`); NIP-45 COUNT encoding; NIP-59 gift-wrap kinds; NIP-70 protected tag; NIP-77 NEG-OPEN parse. Advertised NIP set is a subset of this list.

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

- WebSocket permessage-deflate is not implemented (tungstenite 0.26 has no deflate feature).
- Config file hot-reload is not wired; restart to apply config.
- No graceful-shutdown drain; listeners abort on shutdown.
- `dict train/compress/decompress` reads compressed payloads but does not train dictionaries.
- `router` is a compatibility stub; `stream`/`sync` do not persist events.
- Ingester/req/monitor/negentropy thread *counts* are parsed; this build runs one thread per pool plus a single writer.
- Persistent negentropy B-tree byte identity with C++ is implemented but not proven by a dedicated tree-dump differential.
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
  Tokio workers) and terminate slow clients at `maxPendingOutboundBytes`
  with byte accounting; WS auto-ping, keepalive, version check, and
  case-insensitive upgrade handling.
- Write-policy plugin I/O enforces `timeoutSeconds` and the 8192-byte record
  cap via a dedicated I/O thread; a hung plugin can no longer wedge the
  single LMDB writer.
- A polling `data.mdb` watcher notifies live subscriptions of writes made by
  other processes (C++ `file_change_monitor` parity).
- CLI: `wok event <levId>`; import/export byte-level fidelity with C++
  (abort-on-error export, import size accounting, fried endianness guards).

## Recommended production soak and cutover

1. Copy a v3 `data.mdb` (never the only production file).
2. `wok integrity` on the copy.
3. Soak `wok relay` with production-like publish/REQ/COUNT/AUTH/negentropy traffic for at least one retention/expiration cycle.
4. Compare C++ vs wok export IDs on a disposable snapshot after mixed load.
5. Cut over DNS/proxy; keep C++ binary and original files for rollback (`docs/cutover.md`).
6. Run `wok-bench --profile full` on the target host with a real corpus (`--corpus`) before claiming performance.
