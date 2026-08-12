# wok implementation plan

Rust reimplementation of the C++ [strfry](https://github.com/hoytech/strfry) Nostr relay.
Reference checkout: `/Users/jeff/code/strfry` at `9acdaeb1f63919184ece5f2dd67af21f1ed62f1b`.

This file is the living plan. Update it when discoveries change the work.

## Source-of-truth order

1. Actual C++ behavior at the pinned commit.
2. Canonical NIPs at `656cecc7c0a815b6a2b218d3b5d6f078b3f4dbab` (nostr-protocol/nips HEAD when this plan was written).
3. strfry tests, fixtures, generated DB code, and configuration.
4. Explicit decisions in this file and `docs/`.

## Architecture

Cargo workspace crates:

| Crate | Ownership |
| --- | --- |
| `wok-event` | Event JSON, NIP-01 hashing, Schnorr, PackedEvent, kind helpers |
| `wok-db` | Exact LMDB v3 environment, DBI contract, transactions, integrity |
| `wok-query` | Filters, DBScan, QueryScheduler, ActiveMonitors |
| `wok-negentropy` | NIP-77 protocol, Vector storage, persistent BTreeLMDB |
| `wok-relay` | Transport-neutral commands, write path, AUTH, plugins, cron |
| `wok-ws` | HTTP + WebSocket transport |
| `wok-unix` | Length-prefixed Unix `SOCK_STREAM` transport |
| `wok-cli` | `relay`, dbutils, mesh commands |
| `wok-bench` | Comparative load generation |
| `wok-compat` | C++ differential harnesses and fixtures |

Tokio owns network I/O. Dedicated OS threads own LMDB. Transactions, cursors, and mmap borrows never cross `.await`.

## Phases

1. Workspace + event/packed/filter unit tests.
2. LMDB v3 open/read/write against disposable C++ databases.
3. Query engine + write semantics (replace/delete/expire).
4. Relay core + WebSocket + Unix.
5. Negentropy + CLI parity.
6. Compatibility, conformance, e2e, benches, docs, CI.

## Documented C++ / NIP decisions

See `docs/known-differences.md` as it is filled in. Initial decisions:

- **ID/author filters are exact 32-byte values**, matching C++ `FilterSetBytes(..., 32, 32)`. Historical NIP-01 prefixes are not implemented.
- **Stored event JSON** is compact with alphabetically ordered top-level keys (`content`, `created_at`, `id`, `kind`, `pubkey`, `sig`, `tags`), matching `tao::json` object encoding.
- **PackedEvent integers** use native endian (little-endian on supported hosts). Fried import/export is little-endian-only, matching C++.
- **Historical restricted-kind REQ filtering** uses the Event table PackedEvent, not the JSON payload. C++ `RelayReqWorker` currently constructs `PackedEventView` from EventPayload bytes; that does not match the monitor path or AUTH intent. wok implements the intended PackedEvent check and records the C++ discrepancy.
- **Unix socket** is a wok extension. It is disabled by default and is not advertised as a C++-compatible feature.
- **NIP advertisement** lists only capabilities covered by conformance tests.
- **`foreach_full` must not use `MDB_GET_BOTH_RANGE` on non-`DUPSORT` DBIs.** Integer-key tables (Event, Meta, EventPayload, NegentropyFilter) return `MDB_INCOMPATIBLE` otherwise. This blocked the relay write path once the default `{}` negentropy filter caused `DeferredSink` to scan NegentropyFilter.

## Status

Phases 1–6 are implemented. See `docs/FINAL.md` for gates, evidence, and remaining production soak work.

## Non-goals

No CBOR. No new storage format. No silent DB migration. No mutation of user/production strfry databases.
