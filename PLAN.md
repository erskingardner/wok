# wok implementation plan

Rust reimplementation of the C++ [strfry](https://github.com/hoytech/strfry) Nostr relay.
Reference checkout: `/Users/jeff/code/strfry` at `9acdaeb1f63919184ece5f2dd67af21f1ed62f1b`.

This file is the living plan. Update it when discoveries change the work.

## Source-of-truth order

1. Canonical NIPs at the revision pinned by the conformance suite.
2. Explicit Wok safety, storage, and product decisions in this file and `docs/`.
3. Lossless migration and event-identity requirements.
4. Actual C++ behavior at the pinned commit, plus its tests and fixtures, as a
   historical and differential reference.

## Architecture

Cargo workspace crates:

| Crate | Ownership |
| --- | --- |
| `wok-event` | Event JSON, NIP-01 hashing, Schnorr, PackedEvent, kind helpers |
| `fips-message` | Wok-independent FIPS V1 framing, handshake, chunking, bounded reassembly |
| `wok-db` | Wok-owned LMDB, read-only strfry v3 migration, transactions, integrity |
| `wok-query` | Filters, DBScan, QueryScheduler, ActiveMonitors |
| `wok-negentropy` | NIP-77 protocol, Vector storage, persistent BTreeLMDB |
| `wok-relay` | Transport-neutral commands, write path, AUTH, plugins, cron |
| `wok-ws` | HTTP + WebSocket transport |
| `wok-unix` | Length-prefixed Unix `SOCK_STREAM` transport |
| `wok-fips` | Native FIPS datagram transport on Linux/FreeBSD/macOS |
| `wok-cli` | `relay`, dbutils, mesh commands |
| `wok-bench` | Comparative load generation |
| `wok-compat` | C++ differential harnesses and fixtures |

Tokio owns network I/O. Dedicated OS threads own LMDB. Transactions, cursors, and mmap borrows never cross `.await`.

## Phases

1. Workspace + event/packed/filter unit tests.
2. LMDB v3 differential implementation and fixtures (historical parity phase).
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
- **Native FIPS is a Wok extension.** It consumes the native datagram API,
  never the IPv6/TUN shim. FIPS node identity remains transport metadata and
  does not satisfy NIP-42. V1 DATA delivery is explicitly unreliable.
- **NIP advertisement** lists only capabilities covered by conformance tests.
- **`foreach_full` must not use `MDB_GET_BOTH_RANGE` on non-`DUPSORT` DBIs.** Integer-key tables (Event, Meta, EventPayload, NegentropyFilter) return `MDB_INCOMPATIBLE` otherwise. This blocked the relay write path once the default `{}` negentropy filter caused `DeferredSink` to scan NegentropyFilter.
- **Auth strictness follows intent, not the letter of C++ @9acdaeb.** Fully-restricted REQ/NEG-OPEN require a *completed* auth (C++: any session); `SetAuth` is dispatched to the negentropy worker (C++ defines but never dispatches); one challenge per session vacancy (C++ re-sends an unstored challenge per restricted REQ). See docs/known-differences.md.
- **JSON byte parity is with tao::json, not serde_json.** Duplicate keys rejected, U+007F escaped, ryu d2s f64 formatting. All ingress parsing goes through `wok_event::json::parse_strict`; hashing and stored JSON go through `to_tao_string`.

## Status

Phases 1–6 are implemented, plus all originally-deferred roadmap items:
worker pools, graceful shutdown, config hot-reload, dict training,
stream/sync transfers, router, and permessage-deflate. See `docs/FINAL.md`
for gates, evidence, and remaining production soak work. Two review passes
against the C++ source landed additional correctness fixes; see the
"Post-review hardening" and "Third pass" sections of `docs/FINAL.md`.

The current evolution phase replaces shared writable database compatibility
with `wok migrate strfry`: a read-only v3 snapshot is verified, assigned Wok's
v4 ownership marker, and promoted atomically with translated config and a
manifest. Protocol work now follows the NIPs-first policy in
`docs/compatibility-policy.md`; inherited strfry bugs are candidates for fixes,
not permanent compatibility requirements. Post-migration feature work beyond
the strfry baseline includes NIP-50 search, NIP-45 HLL sketches, and the
NIP-86 management API (`docs/nip86.md`).

## Non-goals

No CBOR. No implicit migration during normal commands. No mutation of
user/production strfry databases. No mixed strfry/Wok writers.
