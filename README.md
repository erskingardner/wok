# wok

A Rust reimplementation of [strfry](https://github.com/hoytech/strfry), the C++
Nostr relay. Drop-in compatible with existing strfry **v3 LMDB databases** and
the public Nostr WebSocket/JSON protocol, with an additional Unix-domain socket
transport.

[![ci](https://github.com/erskingardner/wok/actions/workflows/ci.yml/badge.svg)](https://github.com/erskingardner/wok/actions/workflows/ci.yml)

- Reference C++ commit: `9acdaeb1f63919184ece5f2dd67af21f1ed62f1b`
- NIPs pin used by the conformance suite: `656cecc7c0a815b6a2b218d3b5d6f078b3f4dbab`

## Highlights

- **Database parity, proven by differential tests.** Same named DBIs, flags,
  comparators, native-endian keys, PackedEvent records, FlatBuffers metadata,
  and zstd payload framing. C++ can open/write wok databases and vice versa,
  byte-for-byte (`crates/wok-compat`, including negentropy tree fingerprint
  equality both directions).
- **Protocol parity.** EVENT/REQ/CLOSE/COUNT/EOSE/OK/NOTICE/CLOSED/AUTH and
  NEG-* messages match C++ wire behavior, including error message routing and
  C++ quirks kept deliberately (see
  [docs/known-differences.md](docs/known-differences.md)).
- **NIP-42 AUTH, NIP-45 COUNT, NIP-70 protected events, NIP-59 gift-wrap
  deletion semantics, NIP-77 negentropy set reconciliation** (persistent
  LMDB B-tree, tree-backed multi-round sync sessions).
- **permessage-deflate** via an in-house RFC 6455/7692 codec (no Rust WS
  library offers it); mirrors uWS negotiation as strfry configures it.
- **Unix `SOCK_STREAM` transport** (wok extension): 4-byte big-endian
  length-prefixed JSON, same dispatcher as WebSocket.
- **Mesh tooling**: `router` (multi-connection replication with hot reconfig),
  `stream`, `sync` (NIP-77 two-phase transfer), `upload`, `download`.
- **Operational parity**: worker pools (`numThreads.*`), single LMDB writer,
  bounded queues with backpressure, slow-client termination
  (`maxPendingOutboundBytes`), config hot-reload, graceful shutdown
  (SIGUSR1/SIGINT), write-policy plugins, Prometheus metrics, config compatible
  with `strfry.conf`.

## Build

```bash
cargo build --release -p wok-cli
```

The binary is `target/release/wok`. Requires a recent stable Rust (2021
edition); LMDB and zstd are built from vendored sources by the `lmdb-sys`/`zstd`
crates, so no system libraries are needed beyond a C toolchain.

## Run

```bash
cp docs/wok.conf ./strfry.conf   # or reuse an existing strfry.conf
# Point db= at a *copy* of a v3 database, never your only production file.
./target/release/wok --config strfry.conf relay
```

Unix socket (disabled by default):

```
relay {
    unix {
        enabled = true
        path = "./strfry-db/wok.sock"
        mode = 0600
    }
}
```

## CLI

All C++ subcommands exist:

| Command | Notes |
|---|---|
| `relay` | WS (+ optional Unix) relay |
| `import` / `export` | JSONL, `--fried`, `--since/--until/--reverse`; byte-identical to C++ output |
| `scan`, `event <levId>`, `info`, `delete`, `compact`, `monitor`, `integrity` | DB utilities (`event` is a wok addition) |
| `dict stats/train/compress/decompress` | zstd dictionary management (ZDICT training included) |
| `negentropy list/add/build` | persistent negentropy trees |
| `router <file>` | mesh replication with hot reconfig |
| `stream`, `sync`, `upload`, `download` | mesh transfers |

## Architecture

```
crates/
  wok-event       Event JSON, NIP-01 hashing (tao::json-exact), Schnorr, PackedEvent
  wok-db          Exact LMDB v3 environment, DBI contract, transactions, integrity
  wok-query       Filters, DBScan, QueryScheduler, ActiveMonitors
  wok-negentropy  NIP-77 protocol, Vector storage, persistent BTreeLMDB
  wok-relay       Transport-neutral dispatcher, writer, AUTH, plugins, cron
  wok-ws          HTTP + WebSocket transport (in-house codec, permessage-deflate)
  wok-unix        Length-prefixed Unix SOCK_STREAM transport
  wok-cli         relay, dbutils, mesh commands
  wok-bench       Comparative benchmark harness
  wok-compat      C++ differential harnesses and fixtures
```

Threading model: Tokio only at transport boundaries; dedicated synchronous OS
threads own LMDB. Transactions, cursors, and mmap borrows never cross an
`.await`. One application-level LMDB writer with bounded queues; worker pools
per stage (`numThreads.*`) with connections hashed onto workers like C++
`ThreadPool`.

## Benchmarks

Harness: `wok-bench` (disposable temp dirs, identical deterministic corpus for
both relays, correctness gates before speed). Both binaries optimized
(C++ `-O3`, wok release + thin LTO).

Latest committed run — Apple Silicon (aarch64), 10,000 events, seed 1, single
noisy run (**do not rank from one run**):

| Scenario | wok | strfry | |
|---|---|---|---|
| import (verified) | 34.6k ev/s | 21.6k ev/s | wok 1.6x |
| export | 626k ev/s | 183k ev/s | wok 3.4x |
| negentropy build | 378k ev/s | 164k ev/s | wok 2.3x |
| duplicate import | 170k ev/s | 39k ev/s | wok 4.3x |
| WS publish (1 / 8 conns) | 201 / 192 ev/s | 189 / 182 ev/s | parity (round-trip bound) |
| WS query (mixed REQs) | 9.0k qps | 9.7k qps | within noise |
| live fanout (32 subs x 200) | 6400/6400 | 6400/6400 | parity, complete delivery |
| cold start | 104 ms | 104 ms | parity |

Reproduce:

```bash
cargo build --release -p wok-cli -p wok-bench
./target/release/wok-bench --profile full --out bench-results \
  --strfry /path/to/strfry --wok ./target/release/wok --seed 1
```

Details and methodology: [docs/benchmarks.md](docs/benchmarks.md);
raw data: [docs/sample-bench-results.jsonl](docs/sample-bench-results.jsonl),
[docs/sample-bench-summary.md](docs/sample-bench-summary.md).

## Differences from strfry

Full list with rationale: **[docs/known-differences.md](docs/known-differences.md)**.
Summary:

**wok extensions**
- Unix socket transport (disabled by default).
- `wok event <levId>` prints one event by local event ID.

**Intentional deviations (reviewed, upstream-wart fixes)**
- Restricted-read REQ/NEG-OPEN requires a *completed* NIP-42 auth (C++ only
  checks a session exists); `SetAuth` is dispatched to the negentropy worker
  (C++ defines but never dispatches it); one AUTH challenge per session
  vacancy (C++ re-sends an unstored challenge that can never succeed).
- Historical restricted-kind REQ filtering uses the PackedEvent from the Event
  table (C++ `RelayReqWorker` currently views EventPayload bytes).
- JSON nesting capped at 128 levels (DoS hardening; tao has no limit).
- `wok` creates a missing DB directory; C++ requires it to exist.
- `export`/`info` refuse non-v3 databases (migrate via the C++ binary).
- NIP-11 `software` string is wok's repo URL.

**Deliberate C++ bug-compatibility kept**
- tao::json byte parity: duplicate keys rejected, `U+007F` escaped as `\u007f`,
  ryu f64 formatting — the id-hash preimage and stored JSON bytes match.
- `from_hex` `0x`-prefix/odd-length handling, all-digit `parseUint64`,
  `std::stoull` a-tag parsing.
- Ephemerals stored with `expiration = 1` and cron-purged, exactly like C++.
- C++'s non-NIP-compliant `ERROR: auth-required:` CLOSED prefix.
- Exact 32-byte id/author filters (no NIP-01 prefix matching), like C++.

**Remaining gaps**
- Mesh *client* links (router/stream/sync) don't offer permessage-deflate
  (tungstenite client limitation; bandwidth only). The wok *server* speaks
  deflate like C++.

## Documentation

- [Architecture](docs/architecture.md)
- [LMDB v3 contract](docs/lmdb-v3.md)
- [Unix socket protocol](docs/unix-socket.md)
- [Supported NIPs](docs/nips.md)
- [Configuration](docs/config.md)
- [Cutover / rollback](docs/cutover.md)
- [Security](docs/security.md)
- [Known differences](docs/known-differences.md)
- [Definition-of-done report](docs/FINAL.md)

## Development

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test -p wok-compat --test nip_conformance --test e2e_transports
# Optional C++ differential (requires a strfry binary):
cargo test -p wok-db --test cpp_roundtrip
cargo test -p wok-compat --test cpp_export --test cpp_negentropy
```

Fuzz/property tests live next to the units (`proptest` in `wok-query`).

## License

[GNU Affero General Public License v3.0 or later](LICENSE)
(`AGPL-3.0-or-later`).

wok is an independent Rust implementation compatible with
[strfry](https://github.com/hoytech/strfry) by Doug Hoyte, which is GPL-3.0.
The Nostr protocol is documented by the
[nostr-protocol/nips](https://github.com/nostr-protocol/nips) repository.
