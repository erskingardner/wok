# wok

<p align="center">
  <img src="docs/wok.svg" alt="Wok logo" width="160">
</p>

A Rust Nostr relay with RocksDB storage, synchronous writes, and WebSocket
and Unix-domain socket transports. Wok follows the Nostr specifications and
provides verified, offline migration from existing Wok and strfry databases.

[![ci](https://github.com/erskingardner/wok/actions/workflows/ci.yml/badge.svg)](https://github.com/erskingardner/wok/actions/workflows/ci.yml)

## Highlights

- **Verified migration.** `wok migrate strfry` imports a stopped strfry v3
  database directly into RocksDB, preserves packed events and encoded payloads,
  translates supported config settings, and emits a checksummed manifest.
  `wok migrate rocksdb` preserves the full state of a Wok LMDB v4/v5 database.
- **RocksDB storage.** Every build uses the same Wok-owned runtime layout,
  snapshot reads, atomic index updates and synchronous WAL commits. LMDB is
  supported only as a read-only migration source; no writers share a database.
- **Nostr protocol conformance.** EVENT/REQ/CLOSE/COUNT/EOSE/OK/NOTICE/
  CLOSED/AUTH and NEG-* are tested against pinned NIPs.
- **NIP-42 AUTH, NIP-45 COUNT with mergeable HyperLogLog sketches, NIP-50
  ranked content search, NIP-62 restart-safe Request to Vanish, NIP-67 EOSE
  completeness hints, NIP-70 protected events, NIP-59 gift-wrap deletion
  semantics, NIP-77 negentropy set reconciliation** (persistent B-tree,
  tree-backed multi-round sync sessions), and **draft NIP-91 AND tag
  filters**.
- **Standards-first ephemeral delivery**: ephemeral kinds are live-only by
  default, with an explicit persisted TTL compatibility mode.
- **permessage-deflate** via an in-house RFC 6455/7692 codec.
- **Unix `SOCK_STREAM` transport**: 4-byte big-endian
  length-prefixed JSON, same dispatcher as WebSocket.
- **Mesh tooling**: `router` (multi-connection replication with hot reconfig),
  `sync` (NIP-77 two-phase transfer), `upload`, `download`.
- **Operational continuity**: worker pools (`numThreads.*`), single application writer,
  bounded queues with backpressure, slow-client termination
  (`max_pending_outbound_bytes`), config hot-reload, graceful shutdown
  (SIGUSR1/SIGINT), write-policy plugins, Prometheus metrics, structured JSON
  tracing for Grafana/Loki pipelines, hard-bounded local chart history, and
  migration of the supported `strfry.conf` subset.
- **Native abuse resistance**: per-connection, per-address and per-author
  token buckets, separate connection/EVENT/REQ/NEG-MSG/COUNT budgets, pre-scan query costing, historical-query
  concurrency limits, bounded NIP-50 index growth, default global and author
  storage quotas, a free-disk reserve, rejection metrics, and optional NIP-13
  proof-of-work enforcement advertised through NIP-11.
- **Hardened untrusted-input boundary**: safe crates forbid unsafe Rust, native
  storage and OS FFI are isolated and documented, and property tests plus scheduled
  AddressSanitizer-backed fuzzing exercise JSON, events, WebSockets, compression,
  Negentropy, and database transaction sequences.

## Build

```bash
cargo build --release --locked -p wok-cli
```

The binary is `target/release/wok`. Requires Rust 1.88 or newer, a C/C++
toolchain and libclang for RocksDB bindings. On Debian/Ubuntu install
`g++ clang libclang-dev`; on macOS use Xcode's command-line tools and LLVM
(`brew install llvm`, with `LIBCLANG_PATH` pointing to its `lib` directory if
needed). RocksDB and zstd build from vendored native sources. LMDB 0.9.37 is
vendored for read-only imports; no system liblmdb is linked. Outbound TLS uses
Rustls and the operating system's native root certificates.

Tagged releases publish one checksummed native archive per target for Linux
x86-64/ARM64 and macOS Intel/Apple Silicon. The 0.8.0 release candidate uses
RocksDB throughout. See [CHANGELOG.md](CHANGELOG.md) for notable changes
and [docs/releases.md](docs/releases.md) for the tag and release process.

## Migrate from strfry

```bash
# Stop strfry and all other source writers; keep them stopped through copying.
# Read-only preflight creates no snapshot or output directory.
./target/release/wok migrate strfry \
  --db /var/lib/strfry \
  --config /etc/strfry.conf \
  --output /var/lib/wok \
  --check

# Review the report, then migrate while the source remains stopped.
./target/release/wok migrate strfry \
  --db /var/lib/strfry \
  --config /etc/strfry.conf \
  --output /var/lib/wok --confirm-relay-stopped

# Review the generated config and manifest, then start Wok.
./target/release/wok --config /var/lib/wok/wok.toml relay
```

The output contains `db/`, `wok.toml`, and `migration-manifest.json`. The source
authoritative data and config are unchanged; registered reader coordination can
update LMDB's `lock.mdb`. The output directory must not already
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

Available operator commands:

| Command | Notes |
|---|---|
| `migrate strfry --db <dir> --config <file> --output <dir> [--check]` | Direct read-only strfry v3 → RocksDB import; copying requires `--confirm-relay-stopped` |
| `migrate rocksdb --source <dir> --output <dir> [--check] [--json]` | Offline full-state Wok LMDB v4/v5 → RocksDB copy; copying requires `--confirm-relay-stopped` |
| `backup --output <new-directory>`, `storage-backend`, `rocksdb-check` | Native checkpoint (relay stopped), runtime identity, offline physical audit |
| `relay` | WS (+ optional Unix) relay |
| `import` / `export` | JSONL, `--fried`, `--since/--until/--reverse` |
| `scan`, `event <levId>`, `info`, `delete`, `monitor`, `integrity` | DB utilities |
| `config show [--overrides \| --defaults]` | Effective configuration with each value's origin: default, preset, or file line (`--overrides`: only values the file changes from its preset; `--defaults`: every setting with the preset's value) |
| `config minimize [--dry-run]` | Remove settings that repeat the preset's values, keeping comments and a `.bak` backup (`--dry-run`: print a diff) |
| `doctor [--json]` | Config, storage, index, payload, negentropy, capacity, and runtime-path diagnostics |
| `purge-superseded [--dry-run] [--json]` | Delete replaceable versions superseded at their address, keeping the version reads serve |
| `reindex --confirm-relay-stopped [--backup <dir>]` | Stage and verify rebuilt indexes, repack records that dropped long tag values, atomically promote them, and retain the original DB |
| `dict stats/train/compress/decompress` | zstd dictionary management (ZDICT training included) |
| `negentropy list/add/build` | persistent trees; build uses bounded, restart-safe batches |
| `router <file>` | mesh replication with hot reconfig |
| `sync`, `upload`, `download` | mesh transfers; sync reports transfer outcomes and set differences |

Before cutover or after an unclean shutdown, run `wok --config wok.toml
doctor`. It validates every event-derived index semantically, decompresses
payloads and matches their IDs to packed records, opens every negentropy tree,
checks the Wok database marker, reports RocksDB health and free disk
capacity, and verifies configured plugin and Unix-socket paths. `--json` emits
the complete machine-readable report; failures exit nonzero.

If `doctor` finds damage confined to derived event indexes or negentropy,
stop every process using the database and run `wok --config wok.toml reindex
--confirm-relay-stopped`. Wok rebuilds a fresh sibling database from exact
PackedEvent and EventPayload primary bytes, recreates all event and negentropy
indexes, verifies integrity and the complete event fingerprint, then promotes
the staged directory. The original database remains in the reported sibling
backup directory and a `reindex-manifest.json` records the operation.

## Architecture

```
crates/
  wok-event       Event JSON, NIP-01 hashing (tao::json-exact), Schnorr, PackedEvent
  wok-db          RocksDB storage, read-only LMDB imports, transactions, integrity
  wok-query       Filters, DBScan, QueryScheduler, ActiveMonitors
  wok-negentropy  NIP-77 protocol, Vector storage, persistent B-tree
  wok-relay       Transport-neutral dispatcher, writer, AUTH, plugins, cron
  wok-ws          HTTP + WebSocket transport (in-house codec, permessage-deflate)
  wok-unix        Length-prefixed Unix SOCK_STREAM transport
  wok-cli         relay, dbutils, mesh commands
  wok-bench       Comparative benchmark harness
  wok-compat      C++ differential harnesses and fixtures
```

Threading model: Tokio only at transport boundaries; dedicated synchronous OS
threads own storage. Transactions, cursors, and borrowed records never cross an
`.await`. One application-level writer with bounded queues; worker pools
per stage (`numThreads.*`) with connections hashed onto workers.

## Benchmarks

We tested Wok RocksDB and strfry over WebSocket during sustained writes on
separate relay and load VMs, starting with 15 million generated, signed events
of kinds 1 and 7.
Queries covered IDs, author history, 500-author feeds and tags at 1,000
queries/second. Each write rate ran twice with reversed relay order: ten
minutes at 1,000 writes/second and five at 4,000. Later fastr runs used the
same workload. All three completed **1.8 million reads and 3.6 million
writes**, with event bodies, ordering and accepted-write readback checked.

**p99 latency, in milliseconds** (lower is better). Read ranges cover all
query shapes and write rates; each range spans trial percentiles without pooling.

| Relay | Reads | Writes: 1k/s | Writes: 4k/s |
| --- | ---: | ---: | ---: |
| Wok RocksDB | 3.2–7.9 | 9.1 | 43.2–46.9 |
| strfry 1.1.3 | 7.2–11.9 | 150.4–159.5 | 430.5–3,724.0 |
| fastr | 52.2–20,300 | 266,900–269,200 | 227,000–227,100 |

Latency includes queueing, client and network delay, from scheduled arrival to
EOSE or write acknowledgement. fastr accumulated queues and acknowledged buffered
writes without an fsync barrier; its durability guarantee differs.
Wok's read p99 was **34–61% lower than strfry across all 16 matched cases**,
but its rare read tail (p99.9) was worse in one run at 4,000 writes/second.

These finite, prewarmed runs used different authors for writes and queries.
They establish neither maximum capacity nor equal power-loss durability.
A separate one-hour correctness soak checked latest feeds between write batches,
live delivery, restart and acknowledged-write process-crash recovery.

Two later attempts stopped before timed traffic and remain **unranked**:

| Relay | Events offered | Outcome |
| --- | ---: | --- |
| nostr-rs-relay 0.10.0 | 15 million | Preflight timeout (120 s) |
| Nostream 3.14.0 (native) | 12,000 | 1,200 import errors |

nostr-rs-relay's stored history passed verification before preflight. Nostream's
importer reported 10,800 inserted; sampled errors rejected reactions missing
target tags (`e`/`a`), which the synthetic kind-7 events lack.

Results describe the measured RocksDB candidate at
[`11fdf70`](https://github.com/erskingardner/wok/commit/11fdf700a9099aa7c8b0af357cce45832bf6c5c8)
and fastr at
[`bdbc0bc`](https://github.com/arx-ccn/fastr/commit/bdbc0bc053ad66df444eb47a02aa468e0109775d),
before the single-runtime release preparation; they do not measure every later
release change. The later attempts used nostr-rs-relay
[`b5c1f64`](https://github.com/scsibug/nostr-rs-relay/commit/b5c1f642e4f4c3b9c54f5d18d66f4c53642076b4)
and Nostream
[`44f2e7b`](https://github.com/Cameri/nostream/commit/44f2e7b1cbc1c47acd469bdb62ad49713f16d552).
[Earlier comparison evidence and limits](https://github.com/erskingardner/wok/pull/294)
· [Matched campaign instructions](https://github.com/erskingardner/wok/tree/master/tools/relay-matched).

For a smaller local comparison with the current RocksDB runtime:

```bash
cargo build --release --locked -p wok-cli -p wok-bench
./target/release/wok-bench --profile full --out bench-results \
  --strfry /path/to/strfry --wok ./target/release/wok --seed 1
```

Build requirements and full-state upgrades: [RocksDB migration guide](docs/migration-to-rocksdb.md).
Harness and methodology: [docs/benchmarks.md](docs/benchmarks.md).
NIP-50 design, semantics, and search workload: [docs/nip50-search.md](docs/nip50-search.md).

## Documentation

- [Architecture](docs/architecture.md)
- [Migration from strfry](docs/migration-from-strfry.md)
- [strfry LMDB v3 import contract](docs/lmdb-v3.md)
- [Unix socket protocol](docs/unix-socket.md)
- [Supported NIPs](docs/nips.md)
- [Configuration](docs/config.md)
- [Production deployment security](docs/production-deployment.md)
- [Observability](docs/observability.md)
- [Operator dashboard](docs/admin-dashboard.md)
- [Benchmark methodology](docs/benchmarks.md)
- [Mesh and maintenance](docs/mesh-and-maintenance.md)
- [Cutover / rollback](docs/cutover.md)
- [Security](docs/security.md)
- [Reliability validation and CI gates](docs/reliability.md)
- [Local and two-VM load lab](docs/load-lab.md)

## Development

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo test -p wok-compat --test nip_conformance --test e2e_transports
# Optional import/interop regression tests (requires a strfry binary):
cargo test -p wok-db --test cpp_roundtrip
cargo test -p wok-compat --test cpp_export --test cpp_negentropy
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, conventions, and what a pull
request needs. Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

Fast property tests live beside the relevant crates. The composed libFuzzer
target and scheduled sanitizer workflow are documented in
[Security](docs/security.md).

## License

[GNU Affero General Public License v3.0 or later](LICENSE)
(`AGPL-3.0-or-later`).

Wok began as an independent Rust reimplementation of
[strfry](https://github.com/hoytech/strfry) by Doug Hoyte, which is GPL-3.0.
The Nostr protocol is documented by the
[nostr-protocol/nips](https://github.com/nostr-protocol/nips) repository.
