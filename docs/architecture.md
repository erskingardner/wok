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
- Ingesters never block on a worker queue. A full queue parks that worker's messages
  in order and retries them. Parked messages, CLOSE and NEG-CLOSE included, are only
  dropped when their connection closes. A connection with parked messages has its
  ingress paused: the transport keeps reading the socket, writing outbound and
  handling control frames, Close and EOF, but holds client messages until the parked
  ones move. The hold is charged payload plus a fixed per-message overhead, up to the
  maximum message size; a client that sends past it while paused is disconnected. Once
  ingress resumes the hold is handed over a batch per pass of the transport loop, so
  outbound and control traffic keep flowing; messages read meanwhile queue behind it,
  and the transport stops reading, rather than disconnecting, while those take it past
  its limit. The backlog stays
  bounded by the ingest queue plus one message per paused connection, and a stalled
  worker pauses only the connections that use it. Connection teardown skips the pause:
  it drops the connection's parked and held work, and a worker gets `Close` only if it
  was handed something for that connection, so churn adds no backlog.
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

## REQ lifecycle

A REQ is live before its history is read. When the REQ is admitted, the
newest local event id splits the work: the history sends what was stored up
to it, the live monitor everything stored or published after. Each event is
the job of exactly one of them, so nothing is missed or sent twice, whatever
the history's `limit` keeps out. That includes live-only (ephemeral) events,
which never reach LMDB and so cannot be caught up later. No stage waits on
another along the way.

### The subscription gate

Replies for one subscription id come from three producers on different
threads: the ingester (a refusal's CLOSED), the req worker (history, COUNT
results, its own refusals) and the req monitor (EOSE, live events). What the
client sees for an id is decided in one place, not by coordinating them.

- Every frame for a connection is queued in `ConnTable` under one lock, and
  each connection there has a gate: for REQ ids and, separately, COUNT ids,
  the current generation of each open id. An absent id is closed.
- The ingester gives each REQ and COUNT a generation as it handles it, in
  client order, and moves the gate at that moment: an admitted REQ or COUNT
  makes its generation current, CLOSE removes the id, and a refusal removes
  the id and queues its CLOSED in the same locked step.
- Every subscription frame carries its id and generation, and is queued only
  if that generation is current, checked under the same lock. A CLOSED from a
  worker and a COUNT result are a generation's last frame: queuing one closes
  the id. OK, NOTICE, AUTH and NEG-* are not gated.
- Queued EVENT and EOSE frames keep their id's generation cell, and the
  WebSocket and Unix transports skip any whose generation has since been
  replaced or closed, so a slow link does not carry a replaced filter's
  backlog.

So, per id, no frame of a replaced or closed generation follows the change,
and a CLOSED is the last frame of its generation, however the producers
interleave. The subscription cap (`relay.max_subs_per_connection`) is the
number of open REQ ids in the gate, which counts subscriptions still sending
history as well as live ones; a REQ reusing an open id always fits.

### Stages

1. **Admission, on the ingester.** Before any worker sees the REQ, the ingester
   checks parsing and filter limits, query cost, AUTH and the cap. A refusal is
   `CLOSED`. NIP-01 makes a REQ replace the subscription it names, so a refused
   one still ends it. An admitted REQ gets its generation and history snapshot,
   and the gate opens for it.
2. **Registration, on the req monitor.** The ingester queues `Register` for the
   connection's req monitor, and the history scan for its req worker only once
   `Register` is in the monitor queue, so the scan's `HistoryDone` can never
   reach the monitor first. The monitor replaces any subscription with that id
   and matches the new one against every later event, as for a live
   subscription. Matches are held in a per-subscription buffer instead of being
   sent: stored events by local event id, live-only events in full.
3. **History, on the req worker.** The worker scans up to the snapshot, then
   posts `HistoryDone{generation, snapshot}` to the monitor and moves on. It
   never waits for a reply. A REQ or COUNT it cannot start (a read failure,
   `relay.abuse.max_concurrent_historical_queries`) or whose scan fails gets
   CLOSED through the gate.
4. **Going live, on the req monitor.** For the current generation only, the
   monitor sends EOSE, then the held matches in arrival order, then delivers
   live. NIP-01 defines EOSE as the boundary to "events newly received in
   real-time", so everything held follows it, including stored events
   committed during the scan (strfry sends those first). Held events are
   checked against the read policy again before they are sent.
   - Stored events after the snapshot that the buffer lacks are re-read from
     LMDB after EOSE. That happens when the monitor matched commits past the
     snapshot before it saw `Register`, or when the stored part of the buffer
     outgrew `relay.max_live_buffer_bytes`.
   - Live-only events cannot be re-read. A full buffer drops the oldest and
     counts them (`wok_live_buffer_dropped_ephemeral_total`); one larger than
     the whole bound is dropped alone.
5. **CLOSE, replacement, refusal, disconnect.** These take effect at the gate
   when the ingester handles them. The workers are then told to stop, as
   cleanup only: `Remove{generation}` for the monitor and, behind it, a cancel
   for the worker, each acting only on that generation. A replacing REQ's
   `Register` and scan replace the old ones directly. Disconnect drops the
   connection's gate and everything on every stage.

COUNT never registers with a monitor, and COUNT ids are separate from REQ ids:
neither cancels the other.

Each req monitor drains its queue in batches and applies subscription changes
(`Register`, `Remove`, `HistoryDone`, AUTH, disconnect) before the events
queued with them. A REQ then also sees live-only events published just before
it, and EOSE does not wait behind the batch's fan-out. Each kind keeps its own
order, and per-connection order holds because a connection's subscriptions all
live on one monitor. If the monitor cannot open a read transaction, it keeps
the subscription changes (and one database change) and retries.

## Non-goals

- Storage-backend independence is deferred. LMDB stays until a concrete backend
  or operational requirement justifies an abstraction and a comparative benchmark.
- No implicit strfry migration, production strfry mutation, or mixed writers.
  Older Wok writers must be stopped before the v5 upgrade; rollback restores a
  backup rather than lowering the marker. See [storage format](lmdb-v3.md).
- No CBOR transport.
