# Architecture

Tokio owns WebSocket and Unix I/O. Dedicated OS threads own LMDB.

```
clients ──WS──► wok-ws ──┐
clients ─Unix─► wok-unix─┼─► RelayHandle (crossbeam) ─► ingester thread
                         │                              ├ writer (single)
                         │                              ├ req-worker
                         │                              ├ req-monitor
                         │                              ├ negentropy
                         │                              └ cron (queues maintenance to writer)
                         └ outbound mpsc<OutboundFrame> back to the connection task
```

Invariants:

- strfry v3 is a read-only migration source; Wok runtime databases carry a
  Wok-owned version marker and are never shared with a strfry writer.
- LMDB transactions, cursors, and mmap slices never cross `.await`.
- A single application-level writer thread commits events, management changes and
  maintenance deletions together with counters and derived tree/index updates.
- Connection-affine ingest, query, monitor and sync worker pools route by connection ID.
- Outbound queue memory is bounded by byte reservations, retained through in-flight
  writes. The shared connection guard cancels transport I/O on termination or shutdown.

Crate boundaries: `wok-event`, `wok-db`, `wok-query`, `wok-negentropy`, `wok-relay`, `wok-ws`, `wok-unix`, `wok-cli`, `wok-bench`, `wok-compat`.

Read visibility lives in `wok-query::ReadVisibility` and applies before history,
COUNT/HLL and search limits. Live delivery and temporary sync use the same policy.
Direct persistent-tree sync requires an explicit public-visibility proof.
`server/writer.rs` owns mutation and receipts; `server/negentropy.rs` owns sync
sessions and a reservation pool shared across all workers. Unix reader and writer
futures progress independently so outbound traffic cannot cancel partial headers.

Author counts are derived lazily when first requested, normally for quota
enforcement (enabled by default). Publications without quotas do not create unused counters. Once
initialized, a counter stays transactionally current through inserts, replacements
and deletions, including while quotas are disabled. Enabling a quota may therefore
require a one-time author-index scan for an author without a cached count; no
database upgrade or startup-wide scan is required.
