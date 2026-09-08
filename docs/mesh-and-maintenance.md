# Mesh and maintenance

## Storage checks and repair

`wok integrity` checks primary/index consistency and v5 state encodings, stored
author counts, and the local sequence high-water mark. Counts are verified
against primary events; missing lazy counters are allowed. `wok doctor --json`
includes these checks during read-only inspection.

Integrity JSON also reports `superseded_groups` (replacement addresses with more
than one stored version) and `superseded_events` (versions beyond one per address).
These are advisory counts over structurally valid replacement-index entries,
not corruption. Doctor emits a `replacement-history` warning when nonzero.
The count scan uses constant additional memory. New winning writes remove every
older record at their address transactionally; stale, duplicate, tombstoned, or
quota-rejected writes leave existing records intact. Address-based deletions
remove all matching versions at or before the deletion timestamp. Reindex and
migration continue to preserve physical history.

With the relay stopped, `wok reindex --confirm-relay-stopped` can repair derived
indexes and author counts while retaining the original database as a backup.
It preserves the stored sequence even when the newest events have been deleted.
A malformed or regressed sequence is metadata corruption and blocks reindex:
surviving records cannot establish the lost deletion history. Use a trusted
backup for recovery. See [storage integrity and upgrade](lmdb-v3.md#integrity)
for lazy-initialization limits and process-kill test coverage.

## Outbound connections

`wok sync`, `wok router`, `wok upload`, and `wok download`
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

The legacy `wok stream` command has been removed. Use a router config instead:

```text
connectionTimeout = 20
streams {
    peer {
        dir = "down"
        filter = { "kinds": [0, 3, 5, 445, 1059, 10000, 10002, 10050, 10051, 30443] }
        urls = ["wss://relay.example"]
    }
}
```

```console
wok --config /etc/wok.toml router /etc/wok-router.conf
```

Streaming subscriptions cover live traffic (`limit: 0`); reconnects do not repair
historical gaps. Supervise router and run non-overlapping `wok sync` jobs
periodically and after outages. Start router before the first catch-up.
Outbound router delivery applies global read visibility, including replacement,
moderation, vanish, and expiration, before sending newly stored records.

## Reconciliation results

```console
wok --config /etc/wok.toml sync wss://relay.example --dir down --timeout 60 --json
wok --config /etc/wok.toml sync wss://relay.example --check --json
wok --config /etc/wok.toml sync wss://relay.example --print-missing
```

`--print-missing` implies comparison only and prints `have,<id>` / `need,<id>`
without transferring records. `--check` also compares only, exiting nonzero when
either set has differences. `--dir none --json` reports differences with a zero
exit status when the comparison itself succeeds. All comparisons use the supplied
filter and the remote connection's readable view, not the remote operator's full DB.

`--json` emits one summary on stdout, including transfer/protocol failures; tracing
logs go to stderr. Fields are `ok`, `reconciled`, `have`, `need`, `downloaded`,
`written`, `duplicates`, `superseded`, `rejected`, `unavailable`, `uploaded`,
`upload_rejected`, `upload_superseded`, and `error`. `have` and `need` count unique differences discovered during the run,
not the remaining differences after transfer. `uploaded` counts positive relay
ACKs, not recipient delivery. CLI parsing/config-loading errors may occur before a
summary can be produced. JSON and missing-ID output are mutually exclusive.

A transfer exits nonzero on rejected downloads, rejected uploads, requested IDs
missing at EOSE, closed subscriptions, protocol errors, disconnects or timeout.
Only ACKs matching outstanding upload IDs count. Unsolicited events/EOSE/ACKs
cannot complete a batch. Duplicate records already stored are successful outcomes.
`superseded` counts downloads discarded because a newer local version exists.
`upload_superseded` counts local records superseded before sending and negative
peer ACKs explicitly prefixed `replaced:`. These are terminal successful outcomes;
other policy rejections still fail the transfer.
The client caps combined unique differences at five million; partition larger
comparisons with explicit filters or time windows. The default timeout is 60
seconds without protocol progress; ping traffic does not
extend it. Use an outer service timeout to bound connection setup and total run time.

A successful transfer does not establish a lasting equality of two live databases:
replacement, expiration, deletion and concurrent arrivals may change either set.
Run a subsequent comparison with an explicit observation window, and investigate
residual differences. Timestamp admission limits apply to sync downloads; use the
verified database migration for an exact historical copy. Router's `pluginDown`
is separate from public write policy; sync is an operator DB import and does not
execute that plugin.

Local sync views use the same global visibility rules whether a matching
persistent tree exists or not. A physical tree is used only when it can bypass
those checks safely; otherwise sync builds a filtered view. Replacement kinds
alone do not disable the tree: Wok tracks the number of retained superseded
versions transactionally. First writable initialization of an older database
counts its replacement index once; reindex rebuilds the count. Neither operation
purges signed events. Clearing the last stale version restores the fast path.
Construction is
bounded by `relay.max_sync_events`, `relay.sync_memory_per_connection`, and
`relay.sync_memory_total`, using conservative per-event estimates. Exceeding the
budget fails explicitly before connecting; narrow the filter or review the
budgets. Uploads recheck visibility in case a record changed after reconciliation.
Operator `export` remains a physical archive operation.

## Checking existing tree drift

CLI import and delete now maintain negentropy trees in the same transaction as
primary events. Older versions could leave trees missing imported IDs or retaining
deleted IDs. `wok doctor --json` now compares every registered tree's count and exact
membership/timestamps with primary events, including filtered trees. This uses one
read snapshot and bounded auxiliary memory, with work proportional to the database
and tree sizes. It can be I/O intensive on large databases.

Sync verifies a matching local tree before using it. The remote relay's trees must
also pass operator-side `doctor`. The Wok relay rejects a match-all tree whose count
differs from primary storage; filtered trees require the full operator check.
An empty or partial remote tree is not evidence
of an empty remote database. After a failed check, stop the relay and other writers,
run `wok reindex --confirm-relay-stopped`, then rerun doctor. Reindex retains a backup
and verifies primary event fingerprints. A tree added with `negentropy add` must be
built and verified before relying on it for reconciliation.

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
