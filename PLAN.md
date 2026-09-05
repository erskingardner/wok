# Wok plan

Wok is a Rust Nostr relay with WebSocket and Unix socket transports and a
Wok-owned LMDB database. strfry v3 is a verified, one-way import format.
This file tracks current priorities; historical implementation and benchmark
evidence lives in [docs/FINAL.md](docs/FINAL.md) and the dated reports in `docs/`.

## Source of truth

1. NIPs at the revision pinned in [docs/nips.md](docs/nips.md).
2. Explicit Wok decisions in this file and `docs/`.
3. Lossless migration and event identity.
4. Pinned strfry behavior as historical/differential evidence.

See [compatibility policy](docs/compatibility-policy.md) and
[known differences](docs/known-differences.md). Inherited strfry bugs are not
compatibility requirements.

## Architecture and constraints

- Tokio owns network I/O. Dedicated OS threads own LMDB work. Transactions,
  cursors, and mmap borrows never cross `.await`.
- One application-level writer commits event records, indexes, author-count
  changes, and the local event sequence together.
- New databases use Wok v5. Writable open upgrades Wok v4 atomically; read-only
  inspection does not upgrade. strfry import always requires `wok migrate strfry`.
- Event IDs, signatures, tags, content, and stored payloads survive migration
  unchanged. Strict parsing and tao-compatible JSON encoding belong to
  `wok_event::json`.
- ID and author filters require exact 32-byte values. Advertised NIPs need
  observable behavior and conformance coverage.
- REQ, COUNT, live delivery, and negentropy share visibility rules. AUTH can add
  multiple identities; it does not grant unrestricted replication access.
- Sync memory is bounded per connection and globally. Active sessions have no
  fixed lifetime; idle timeout, policy changes, and visibility revocations can
  close them. Oversized views fail explicitly instead of returning partial sets.

The crate map is in [AGENTS.md](AGENTS.md); threading and worker ownership are
in [docs/architecture.md](docs/architecture.md).

## Completed baseline

The relay, query engine, negentropy, CLI, worker pools, graceful shutdown,
configuration reload, compression, mesh tooling, search, HLL sketches, management
API, and transport/conformance suites are implemented. Production readiness
still needs the operational validation below.

The [September 5 audit](docs/code-review-2026-09-05.md) records the correctness,
privacy, resource-budget, performance, and simplification fixes. These include
publisher receipt ownership, authorized bounded sync, persistent sequence and
author counters, shared visibility checks, cancellation-safe transport I/O, and
benchmark outcome validation. Benchmark results remain scoped to their recorded
hardware and workload; short local runs are not production soak evidence.

### Storage integrity and recovery follow-up

- [x] Check stored author counters against primary events, independently of the
  author index, while accepting legitimate lazy initialization.
- [x] Validate state encodings and require any stored sequence to cover all
  surviving local IDs. Detect a v5 marker without its state table.
- [x] Allow reindex to rebuild author counts, preserve a valid historical
  sequence, and refuse detected sequence corruption without modifying the source.
- [x] Kill subprocesses around upgrade and write commit boundaries, including
  insertion, replacement, deletion, mixed batches, and lazy state initialization.
  Verify exact primary/payload bytes, integrity, counters, and subsequent IDs.
- [x] Exercise MAP_FULL rollback after staging event and counter changes.

These tests cover abrupt process death with normal LMDB durability settings.
They do not simulate power loss, torn storage writes, or a failed filesystem.
A missing lazy sequence cannot be distinguished from erased historical state
using a single snapshot; deleted-tail history requires a trusted backup.

## Reliability validation follow-up

- [x] Run benchmark correctness tests in CI and native behavioral tests on every
  distribution platform; require the pinned C++ reference in a migration job.
- [x] Expand fuzz triggers to master pushes and all exercised crates; seed size
  and protocol boundaries and reuse the corpus.
- [x] Add generated WebSocket/Unix privacy lifecycle tests and in-flight sync
  revocation checks against an independent expected-set model.
- [x] Add a repeatable Linux soak runner and short CI / longer scheduled jobs.
- [x] Complete and record the initial one-hour Linux container soak; see the
  [dated evidence report](docs/reliability-2026-09-05.md).

See [reliability validation](docs/reliability.md) for the gates, workload,
commands, and evidence limits. New process and real-C++ tests exposed missing
SIGTERM handling and incomplete migration extension-table initialization; both
are now covered by regressions.

## Next priorities

1. **Broader Linux soak and benchmarks.** Use a fixed dataset and declared
   hardware, warmup, durability, and transport settings. Mix publishing,
   subscriptions, deletion/replacement, and long syncs; include slow consumers
   and reconnects. Record latency distributions, RSS, CPU, writer stalls,
   database growth, and correctness outcomes. Keep throughput claims tied to
   reproducible evidence.
2. **Large-sync efficiency.** Measure the cost of temporary authorized views
   and conservative session invalidation. Explore narrower invalidation and
   cheaper public-tree eligibility only with privacy regressions and measured
   benefit. Preserve bounded memory, explicit failure, and support for long
   active syncs; permanent per-user trees are not the default design.

## Deferred and non-goals

- Storage-backend independence is deferred. Keep LMDB until a concrete backend
  or operational requirement justifies an abstraction and comparative benchmark.
- No implicit strfry migration, production strfry mutation, or mixed writers.
  Older Wok writers must be stopped before the v5 upgrade; rollback restores a
  backup rather than lowering the marker. See [storage format](docs/lmdb-v3.md).
- No CBOR transport.
