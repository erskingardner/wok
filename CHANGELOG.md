# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Comprehensive configuration and Prometheus metric references, including a
  complete commented `wok.toml` and documented dashboard edit boundaries.
- A guarded two-host Wok/strfry campaign runner with deterministic reusable
  signed corpora, realistic actor relationships, historical remote queries,
  lifecycle publication workloads, alternating relay order, and captured
  provenance and resource evidence.
- A same-host, order-rotated transport campaign comparing Wok's production
  length-prefixed Unix interface with Wok and strfry WebSockets under identical
  correctness-gated publish, query, fanout, and connection workloads, plus a
  reproducible report of the first 100,000-event, three-repetition campaign.

### Changed

- Event validation no longer clones the complete parsed JSON value after
  producing the packed event and normalized persistence JSON.
- The relay writer skips reparsing normalized event JSON when no write-policy
  plugin is configured.
- NIP-50 search progress bookkeeping is written once per committed event batch
  instead of deleting and reinserting its metadata record for every event.
- Batched database writes borrow packed events and normalized JSON in place,
  avoiding two complete event copies per accepted publication.
- The relay landing page now presents banner/icon media, operator and relay
  npubs, contact and policy links, linked and described supported NIPs, and the
  version with its source revision.
- The operator dashboard now opens on an explicit signed-out screen and
  exposes the broad safe set of live-reloadable identity, event, protocol,
  abuse, filter, NIP-62, and history settings with inline explanations.
- Dashboard charts now include a labeled, automatically scaled value axis.

### Fixed

- Dashboard NIP-98 requests now include a cryptographically random nonce, so
  repeated or save-then-refresh actions signed in the same second cannot
  collide with replay protection.

## [0.1.0] - 2026-08-13

### Added

- NIP-50 content search with transactional Unicode-normalized term and phrase
  indexing, relevance ordering before limits, structured-filter intersection,
  live subscription matching, automatic migration backfill, integrity/reindex
  coverage, and correctness-checked scale benchmarks.
- A reloadable, request-wide EVENT result ceiling across multi-filter REQs,
  independent of COUNT and negentropy limits.
- NIP-62 Request to Vanish with strict relay targeting, persistent
  maximum-timestamp markers, immediate query and rebroadcast suppression,
  recipient gift-wrap cleanup, undeletable request records, and bounded
  restart-safe physical deletion.
- Mergeable NIP-45 HyperLogLog sketches for canonical single-target COUNT
  filters, including hex, address, and arbitrary-string offset derivation.
- Configurable structured JSON tracing for log collectors, richer correlation
  fields, and hard-bounded in-memory operational metric history for the admin
  UI, alongside the existing Prometheus exporter.
- An optional operator dashboard with NIP-98/NIP-07 authentication, bounded
  replay protection, operational charts, and atomic writes for a deliberately
  small, validated subset of live-reloadable TOML settings.
- Bounded, idempotent negentropy tree builds with configurable scan batches,
  short write transactions, and progress checkpoints.
- Initial Wok release: a Rust Nostr relay with WebSocket and optional
  length-prefixed Unix-socket transports.
- Verified, one-way migration from strfry LMDB v3 into a Wok-owned v4
  database, including a no-write preflight, complete config translation audit,
  event fingerprint verification, and a migration manifest.
- Native TOML configuration with strict unknown-key rejection and safe live
  reload of runtime settings.
- Relay support for NIP-01, NIP-09, NIP-11, NIP-40, NIP-42, NIP-45, NIP-59,
  NIP-70, and NIP-77 behavior, with conditional capability advertisement.
- Optional NIP-13 proof-of-work enforcement advertised through NIP-11.
- `doctor` diagnostics and staged, verified `reindex` recovery with retained
  backups.
- Import, export, scan, event, delete, compaction, dictionary, monitoring,
  router, stream, sync, upload, download, and negentropy tooling.
- Native abuse controls covering connection, EVENT, REQ, and COUNT budgets;
  IP and pubkey token buckets; query-cost and historical-query concurrency
  limits; optional author storage quotas; and labeled rejection metrics.
- Differential strfry compatibility tests, independent NIP conformance tests,
  cross-transport end-to-end tests, property tests, and comparative benchmarks.

### Changed

- The comparative benchmark now emits replayable signed corpora and SHA-256
  manifests, supports repeated order-balanced trials, and includes a remote
  load profile for scaled publication, fanout, and idle connections.
- Wok treats strfry compatibility as a verified migration boundary rather than
  an ongoing promise to preserve strfry implementation bugs.
- Ephemeral event kinds are live-only by default, with an explicit persisted
  TTL compatibility mode for migrations that need strfry behavior.
- NIP-11 capabilities are derived from implemented and enabled relay behavior;
  operators cannot supply an arbitrary advertised NIP list.

### Fixed

- Accepted WebSocket connections now enable `TCP_NODELAY`, preventing Linux
  delayed ACKs from adding roughly 40 ms between small EVENT and EOSE frames.
- Historical result bursts no longer hit an undocumented 256-message queue
  and disconnect healthy clients before the configured pending-byte budget;
  deep author pagination and mixed read/write workloads now guard this path.
- Private kinds 4 and 1059 now fail closed by default, broad COUNT requests
  cannot leak restricted-event populations, and NIP-59 is advertised only
  when AUTH, recipient filtering, gift-wrap deletion, and live-only kind 21059
  behavior are all usable.
- `wok stream` now reconnects after connection failures and remote closes with
  non-blocking capped exponential backoff, while retrying the first local event
  whose WebSocket send did not complete.
- Hardened malformed LMDB comparator handling and semantic verification of
  every derived event index.
- Corrected subscription installation ordering so immediate live events cannot
  race ahead of EOSE.
- Corrected strict NIP-01 filter grammar, event validation, AUTH propagation,
  negentropy session lifecycle, error routing, slow-client handling, database
  watching, and write-policy timeout behavior found during differential review.

### Security

- Bounded JSON nesting, frame/message sizes, outbound queues, plugin execution,
  query work, publication rates, and optional per-author storage.
- Protected-event publishing and restricted reads require the appropriate
  authenticated author or recipient relationship.

[Unreleased]: https://github.com/erskingardner/wok/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/erskingardner/wok/releases/tag/v0.1.0
