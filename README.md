# wok

<p align="center">
  <img src="docs/wok.svg" alt="Wok logo" width="160">
</p>

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
- **NIP-42 AUTH, NIP-45 COUNT with mergeable HyperLogLog sketches, NIP-50
  ranked content search, NIP-62 restart-safe Request to Vanish, NIP-70
  protected events, NIP-59 gift-wrap deletion semantics, NIP-77 negentropy set
  reconciliation** (persistent LMDB B-tree, tree-backed multi-round sync
  sessions), and **draft NIP-91 AND tag filters**.
- **Standards-first ephemeral delivery**: ephemeral kinds are live-only by
  default, with an explicit persisted TTL compatibility mode.
- **permessage-deflate** via an in-house RFC 6455/7692 codec (no Rust WS
  library offers it); mirrors uWS negotiation as strfry configures it.
- **Unix `SOCK_STREAM` transport** (wok extension): 4-byte big-endian
  length-prefixed JSON, same dispatcher as WebSocket.
- **Mesh tooling**: `router` (multi-connection replication with hot reconfig),
  `stream`, `sync` (NIP-77 two-phase transfer), `upload`, `download`.
- **Operational continuity**: worker pools (`numThreads.*`), single LMDB writer,
  bounded queues with backpressure, slow-client termination
  (`max_pending_outbound_bytes`), config hot-reload, graceful shutdown
  (SIGUSR1/SIGINT), write-policy plugins, Prometheus metrics, structured JSON
  tracing for Grafana/Loki pipelines, hard-bounded local chart history, and
  migration of the supported `strfry.conf` subset.
- **Native abuse resistance**: per-IP and per-pubkey token buckets, separate
  connection/EVENT/REQ/COUNT budgets, pre-scan query costing, historical-query
  concurrency limits, bounded NIP-50 index growth, default global and author
  storage quotas, a free-disk reserve, rejection metrics, and optional NIP-13
  proof-of-work enforcement advertised through NIP-11.
- **Hardened untrusted-input boundary**: safe crates forbid unsafe Rust, LMDB
  and OS FFI are isolated and documented, and property tests plus scheduled
  AddressSanitizer-backed fuzzing exercise JSON, events, WebSockets, compression,
  Negentropy, and database transaction sequences.

## Build

```bash
cargo build --release -p wok-cli
```

The binary is `target/release/wok`. Requires a recent stable Rust (2021
edition); LMDB and zstd are built from vendored sources by the `lmdb-sys`/`zstd`
crates, and outbound TLS uses Rustls with the operating system's native root
certificate store, so no system libraries are needed beyond a C toolchain.

Tagged releases publish checksummed native archives for Linux x86-64/ARM64 and
macOS Intel/Apple Silicon. See [CHANGELOG.md](CHANGELOG.md) for notable changes
and [docs/releases.md](docs/releases.md) for the tag and release process.

## Migrate from strfry

```bash
# Read-only preflight: no snapshot or output directory is created.
./target/release/wok migrate strfry \
  --db /var/lib/strfry \
  --config /etc/strfry.conf \
  --output /var/lib/wok \
  --check

# After reviewing the report and stopping strfry, perform the migration.
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
| `migrate strfry --db <dir> --config <file> --output <dir> [--check]` | Read-only preflight or verified, one-way migration into a Wok-owned database (`--json` with `--check`) |
| `relay` | WS (+ optional Unix) relay |
| `import` / `export` | JSONL, `--fried`, `--since/--until/--reverse` |
| `scan`, `event <levId>`, `info`, `delete`, `compact`, `monitor`, `integrity` | DB utilities (`event` is a wok addition) |
| `doctor [--json]` | Config, storage, index, payload, negentropy, capacity, and runtime-path diagnostics |
| `reindex --confirm-relay-stopped [--backup <dir>]` | Stage and verify rebuilt indexes, atomically promote them, and retain the original DB |
| `dict stats/train/compress/decompress` | zstd dictionary management (ZDICT training included) |
| `negentropy list/add/build` | persistent trees; build uses bounded, restart-safe batches |
| `router <file>` | mesh replication with hot reconfig |
| `stream`, `sync`, `upload`, `download` | mesh transfers; stream reconnects with bounded backoff |

Before cutover or after an unclean shutdown, run `wok --config wok.toml
doctor`. It validates every event-derived index semantically, decompresses
payloads and matches their IDs to packed records, opens every negentropy tree,
checks the Wok database marker and host endianness, reports LMDB map/disk
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

Harness: `wok-bench` uses disposable databases, deterministic signed corpora,
rotated relay order, and correctness gates before speed. Local process
comparisons, two-host load campaigns, and same-host Unix/WebSocket comparisons
are separate experiments so network RTT is not confused with transport cost.

Latest controlled post-hardening campaign — Wok `fa9b061`, Linux x86-64,
100,000 realistic events, and three order-rotated repetitions. All 96 two-host
and same-host result rows passed their correctness gates:

| Median scenario | Wok WebSocket | Wok Unix | strfry WebSocket |
|---|---:|---:|---:|
| historical query | 90.6 req/s | **2,909.5 req/s** | 90.6 req/s |
| mixed read/write | 22.8 req/s | **1,005.6 req/s** | 22.8 req/s |
| accepted publication | 2,929 events/s | 2,939 events/s | **4,450 events/s** |
| fanout delivery | **32,865 deliveries/s** | 31,987 deliveries/s | 28,277 deliveries/s |
| connection opens | 4,319 conn/s | **18,469 conn/s** | 3,837 conn/s |
| deep-history pages | 104.7 pages/s | **136.0 pages/s** | 115.6 pages/s |

The table is the same-host transport experiment, not an Internet-facing
capacity claim. In the two-host experiment, Wok WebSocket publication reached
2,963 events/s: 5.1% above the v0.2.0 campaign while the strfry control moved
down 1.4%, narrowing the publication gap from 70.5% to 60.0%. Wok fanout improved
13.7% and ran 15.8% ahead of strfry. At the 10,000-connection same-host peak,
server RSS was 478 MiB for Wok WebSocket, 455 MiB for Wok Unix, and 292 MiB for
strfry WebSocket. Full latency, resource, limitation, and artifact provenance
details are in the [post-hardening benchmark
report](docs/benchmark-security-hardening-2026-08-14.md); the focused A/B is in
the [WebSocket optimization report](docs/websocket-performance-2026-08-14.md).

Reproduce:

```bash
cargo build --release -p wok-cli -p wok-bench
./target/release/wok-bench --profile full --out bench-results \
  --strfry /path/to/strfry --wok ./target/release/wok --seed 1
```

Details and methodology: [docs/benchmarks.md](docs/benchmarks.md);
historical single-run local sample:
[docs/sample-bench-results.jsonl](docs/sample-bench-results.jsonl),
[docs/sample-bench-summary.md](docs/sample-bench-summary.md).
NIP-50 design, semantics, and scale results: [docs/nip50-search.md](docs/nip50-search.md).

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
- [Production deployment security](docs/production-deployment.md)
- [Observability](docs/observability.md)
- [Operator dashboard](docs/admin-dashboard.md)
- [Benchmark methodology](docs/benchmarks.md)
- [Post-hardening benchmark](docs/benchmark-security-hardening-2026-08-14.md)
- [WebSocket optimization report](docs/websocket-performance-2026-08-14.md)
- [Wok v0.2.0 benchmark](docs/benchmark-v0.2.0-2026-08-14.md)
- [2026-08-14 transport benchmark](docs/transport-benchmark-2026-08-14.md)
- [Mesh and maintenance](docs/mesh-and-maintenance.md)
- [Cutover / rollback](docs/cutover.md)
- [Security](docs/security.md)
- [Known differences](docs/known-differences.md)
- [Definition-of-done report](docs/FINAL.md)

## Development

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --exclude wok-bench --locked
cargo test -p wok-compat --test nip_conformance --test e2e_transports
# Optional C++ differential (requires a strfry binary):
cargo test -p wok-db --test cpp_roundtrip
cargo test -p wok-compat --test cpp_export --test cpp_negentropy
```

Fast property tests live beside the relevant crates. The composed libFuzzer
target and scheduled sanitizer workflow are documented in
[Security](docs/security.md).

## License

[GNU Affero General Public License v3.0 or later](LICENSE)
(`AGPL-3.0-or-later`).

wok is an independent Rust implementation compatible with
[strfry](https://github.com/hoytech/strfry) by Doug Hoyte, which is GPL-3.0.
The Nostr protocol is documented by the
[nostr-protocol/nips](https://github.com/nostr-protocol/nips) repository.
