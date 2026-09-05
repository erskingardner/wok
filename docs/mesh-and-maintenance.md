# Mesh and maintenance

## Outbound connections

`wok sync`, `wok stream`, `wok router`, `wok upload`, and `wok download`
dial whatever `ws(s)://` URL the operator (or a router config file) supplies.
There is no filtering against loopback, link-local (e.g. `169.254.169.254`),
or private ranges — these commands will happily dial internal addresses, and
up-directions export your local DB to the configured URL. Treat router
configs and sync/upload targets as trusted input. TLS verification is always
on and cannot be disabled.

## Persistent mesh links

Use `wok router` for new long-running replication setups. It supports multiple
named streams, filters, directions, URLs, hot configuration reload, and
per-connection reconnects.

The compatibility-oriented `wok stream` command is deprecated but remains
safe to supervise. After a failed connection or remote close it schedules a
Tokio timer instead of blocking the runtime, reconnects after one second by
default, and doubles failures up to a 30-second ceiling. Both values are
configurable:

```console
wok stream wss://relay.example --dir both \
  --reconnect-delay 1 --max-reconnect-delay 30
```

Upload scans are capped at 1,000 primary rows per runtime tick. The local
cursor advances only after each WebSocket send completes, so the first unsent
event is retried after reconnect. Download batches are verified and committed
before retrying.

Streaming subscriptions cover live traffic; WebSocket delivery is not a
durable acknowledgment protocol. Run `wok sync` periodically (or after a known
outage) for exact NIP-77 reconciliation rather than assuming a reconnect alone
fills a remote-side gap.

## Negentropy tree builds

`wok negentropy build` scans a fixed snapshot of the primary event high-water
mark in bounded batches. Each batch uses a read-only scan followed by a short
write transaction, so a large build does not retain every matching event in
memory or hold LMDB's single writer for the full database scan.

```console
wok negentropy build 1 --batch-size 10000
```

Every committed batch leaves a valid partial tree and inserts are idempotent.
If the process is interrupted, rerun the same command: it safely reconstructs
the intended final tree and ignores records already present. Progress logs
include scanned rows, the fixed high-water mark, matched rows, and new inserts.
Smaller batches reduce writer hold time; larger batches trade more memory and
write latency for throughput. A batch size of zero is rejected.

## Precomputed-tree filters and restricted kinds

`wok negentropy add <filter>` registers a persistent tree for a filter.
The relay uses that tree directly only when it can prove its records are
publicly visible. The current conservative proof checks restricted-kind
presence and requires empty expiration, moderation and vanish tables. A filter
that explicitly excludes restricted kinds can still use the direct path.

Otherwise, synchronization builds a temporary view using the same per-event
visibility predicate as REQ and COUNT. AUTH adds readable identities; it does
not grant permission to enumerate other users' restricted IDs. No permanent
per-user trees or privileged replication credentials are introduced.

Sync sessions reserve memory before construction, with defaults of 256 MiB
per connection and 1 GiB across all workers. Construction reserves conservative
space for query/ranking/deduplication state; after sealing, unused space is
released. A sealed vector uses about 40 bytes per item before allocator slack,
plus a 4 MiB protocol/filter allowance. Budgets cover session allocations, not
the process's total RSS, LMDB mappings, or separately bounded transport queues.
A budget rejection returns NEG-ERR; it never silently reconciles a truncated set.

Sessions expire after 60 seconds waiting for the next client reconciliation
message. Active sessions have no fixed maximum lifetime. AUTH changes, read
policy changes, visibility revocation/deletion or the earliest included expiry
close affected sessions; clients reopen them. Current storage revocations
conservatively invalidate all sessions. Large syncs can use narrower time ranges
or larger configured budgets when a temporary view cannot fit. Lowering a live
budget constrains new reservations; existing ones drain or expire normally.
