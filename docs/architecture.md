# Architecture

Tokio owns WebSocket and Unix I/O. Dedicated OS threads own LMDB.

```
clients ──WS──► wok-ws ──┐
clients ─Unix─► wok-unix─┼─► RelayHandle (crossbeam) ─► ingester thread
                         │                              ├ writer (single)
                         │                              ├ req-worker
                         │                              ├ req-monitor
                         │                              ├ negentropy
                         │                              └ cron (expiration)
                         └ outbound mpsc<String> back to the connection task
```

Invariants:

- strfry v3 is a read-only migration source; Wok runtime databases carry a
  Wok-owned version marker and are never shared with a strfry writer.
- LMDB transactions, cursors, and mmap slices never cross `.await`.
- A single application-level writer thread commits events.
- Connection-affine ingest uses one ingester in this build (can be sharded later by `conn_id`).
- Outbound channels are bounded; slow clients fail `try_send` and are dropped by the transport when the buffer fills.

Crate boundaries: `wok-event`, `wok-db`, `wok-query`, `wok-negentropy`, `wok-relay`, `wok-ws`, `wok-unix`, `wok-cli`, `wok-bench`, `wok-compat`.
