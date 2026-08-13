# wok

A Rust Nostr relay that began as a reimplementation of
[strfry](https://github.com/hoytech/strfry). Wok provides a verified, one-way
migration from strfry v3 databases and configs, then owns its database and
evolves against the Nostr specifications rather than preserving every strfry
quirk. It also provides an additional Unix-domain socket transport.

[![ci](https://github.com/erskingardner/wok/actions/workflows/ci.yml/badge.svg)](https://github.com/erskingardner/wok/actions/workflows/ci.yml)

- Reference C++ commit: `9acdaeb1f63919184ece5f2dd67af21f1ed62f1b`
- NIPs pin used by the conformance suite: `656cecc7c0a815b6a2b218d3b5d6f078b3f4dbab`

## Highlights

- **Verified migration.** `wok migrate strfry` takes a read-only LMDB snapshot,
  checks its integrity, preserves every packed event and payload byte, rewrites
  only the database ownership marker, translates the config's database path,
  translates supported settings into native TOML, and emits a checksummed
  manifest.
- **Independent storage ownership.** strfry v3 is an import format. Wok uses a
  v4 marker so strfry and Wok cannot accidentally become mixed writers, even
  while the initial Wok layout remains structurally close to v3.
- **Nostr-first protocol behavior.** EVENT/REQ/CLOSE/COUNT/EOSE/OK/NOTICE/
  CLOSED/AUTH and NEG-* are tested against pinned NIPs. Differential tests are
  migration and regression evidence, not a promise to retain upstream bugs.
- **NIP-42 AUTH, NIP-45 COUNT, NIP-70 protected events, NIP-59 gift-wrap
  deletion semantics, NIP-77 negentropy set reconciliation** (persistent
  LMDB B-tree, tree-backed multi-round sync sessions).
- **permessage-deflate** via an in-house RFC 6455/7692 codec (no Rust WS
  library offers it); mirrors uWS negotiation as strfry configures it.
- **Unix `SOCK_STREAM` transport** (wok extension): 4-byte big-endian
  length-prefixed JSON, same dispatcher as WebSocket.
- **Mesh tooling**: `router` (multi-connection replication with hot reconfig),
  `stream`, `sync` (NIP-77 two-phase transfer), `upload`, `download`.
- **Operational continuity**: worker pools (`numThreads.*`), single LMDB writer,
  bounded queues with backpressure, slow-client termination
  (`max_pending_outbound_bytes`), config hot-reload, graceful shutdown
  (SIGUSR1/SIGINT), write-policy plugins, Prometheus metrics, and migration of
  the supported `strfry.conf` subset.

## Build

```bash
cargo build --release -p wok-cli
```

The binary is `target/release/wok`. Requires a recent stable Rust (2021
edition); LMDB and zstd are built from vendored sources by the `lmdb-sys`/`zstd`
crates, so no system libraries are needed beyond a C toolchain.

## Migrate from strfry

```bash
./target/release/wok migrate strfry \
  --db /var/lib/strfry \
  --config /etc/strfry.conf \
  --output /var/lib/wok

# Review the generated config and manifest, then start Wok.
./target/release/wok --config /var/lib/wok/wok.toml relay
```

The output contains `db/`, `wok.toml`, and `migration-manifest.json`. The source
database and config are never modified. The output directory must not already
exist. See [Migration from strfry](docs/migration-from-strfry.md) for cutover,
verification, and rollback.

For a new relay, start with [docs/wok.toml](docs/wok.toml) and an empty database
path instead.

Unix socket (disabled by default):

```toml
[relay.unix]
enabled = true
path = "./wok-db/wok.sock"
mode = 0o600
```

## CLI

All C++ subcommands exist:

| Command | Notes |
|---|---|
| `migrate strfry --db <dir> --config <file> --output <dir>` | Verified, one-way migration into a Wok-owned database |
| `relay` | WS (+ optional Unix) relay |
| `import` / `export` | JSONL, `--fried`, `--since/--until/--reverse` |
| `scan`, `event <levId>`, `info`, `delete`, `compact`, `monitor`, `integrity` | DB utilities (`event` is a wok addition) |
| `dict stats/train/compress/decompress` | zstd dictionary management (ZDICT training included) |
| `negentropy list/add/build` | persistent negentropy trees |
| `router <file>` | mesh replication with hot reconfig |
| `stream`, `sync`, `upload`, `download` | mesh transfers |

## Architecture

```
crates/
  wok-event       Event JSON, NIP-01 hashing (tao::json-exact), Schnorr, PackedEvent
  wok-db          Wok storage, strfry v3 snapshot/import, transactions, integrity
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

**Intentional Wok behavior**
- Restricted-read REQ/NEG-OPEN requires a *completed* NIP-42 auth (C++ only
  checks a session exists); `SetAuth` is dispatched to the negentropy worker
  (C++ defines but never dispatches it); one AUTH challenge per session
  vacancy (C++ re-sends an unstored challenge that can never succeed).
- Historical restricted-kind REQ filtering uses the PackedEvent from the Event
  table (C++ `RelayReqWorker` currently views EventPayload bytes).
- JSON nesting capped at 128 levels (DoS hardening; tao has no limit).
- New Wok databases use a Wok-owned v4 marker. strfry v3 is accepted only by
  `wok migrate strfry`.
- `wok` creates a missing database directory for new Wok databases.
- NIP-11 `software` string is wok's repo URL.

**Compatibility is deliberately bounded**
- Migration preserves logical event records and validates their fingerprints;
  Wok does not promise an LMDB file that strfry can reopen.
- Existing strfry-like JSON serialization remains where it affects event IDs or
  lossless migration. Other inherited quirks are candidates for correction.
- Supported config settings are translated into strict Wok TOML. Review
  external plugin, policy, and socket paths; unsupported strfry keys are not
  carried forward.

**Remaining gaps**
- Mesh *client* links (router/stream/sync) don't offer permessage-deflate
  (tungstenite client limitation; bandwidth only). The wok *server* speaks
  deflate like C++.

## Documentation

- [Architecture](docs/architecture.md)
- [Migration from strfry](docs/migration-from-strfry.md)
- [Compatibility policy](docs/compatibility-policy.md)
- [strfry LMDB v3 import contract](docs/lmdb-v3.md)
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
