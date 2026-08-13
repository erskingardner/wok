# Mesh and maintenance

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
