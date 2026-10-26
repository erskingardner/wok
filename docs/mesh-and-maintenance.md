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
migration continue to preserve physical history, except that reindex deletes
the versions that a deletion it repairs names (below).

```console
wok --config /etc/wok.toml purge-superseded --dry-run
wok --config /etc/wok.toml purge-superseded --json
```

`wok purge-superseded` deletes every superseded version and keeps the version
that relay reads already serve: the newest `created_at`, then the lowest ID. A
winner hidden by expiration or moderation is kept too, and still removes the
versions it supersedes. A running relay's expiration and vanish sweep may
physically delete such a winner before the purge reaches its address; the
older version then becomes the only one stored and is kept.
`--dry-run` reports the counts from a read-only scan and never writes.
`--json` emits `dry_run`, `superseded_groups`, and `superseded_events`.
The relay can keep running. Each write transaction finishes whole replacement
groups and commits after scanning about 10,000 replacement-index entries, even
when it deletes nothing, so relay writes interleave. Each batch re-evaluates
its groups. Negentropy trees, author counts, and the
retained-history count stay consistent, and the persistent-tree sync fast path
returns once the count reaches zero. Deleted history cannot be recovered
except from a backup.

With the relay stopped, `wok reindex --confirm-relay-stopped` can repair derived
indexes and author counts while retaining the original database as a backup.
It preserves the stored sequence even when the newest events have been deleted.
A malformed or regressed sequence is metadata corruption and blocks reindex:
surviving records cannot establish the lost deletion history. Use a trusted
backup for recovery. See [storage integrity and upgrade](lmdb-v3.md#integrity)
for lazy-initialization limits and process-kill test coverage.

The `(tag, kind, created_at)` index, `wok_Event__tagKind`, records how far it
covers the stored events. Integrity JSON reports it as `tag_kind_index`:
`schema`, `indexed_through` and `high_water` (the greatest local ID
allocated), `complete`, `bulk_pass` (the `target` and `visited` entries of a
key-ordered build in progress), `lease_until` (the Unix time in milliseconds
until which a `wok import` holds the build), `tag_entries` (the `Event__tag`
entries such a build visits), and its expected, actual, missing, unexpected
and stale entries. Doctor's `tag-kind-index` check passes when the index is
complete and every entry matches its event. It warns while the index is
incomplete,
with the build's progress: a database from before the index, which the relay
builds in key order on its first start, an import still loading, which builds
it once its events are written, an import stopped before it built the index,
which the relay finishes the same way, or events an earlier Wok release
inserted, which it indexes in local-ID order. It also warns when stale
entries remain: entries an earlier release left behind when it deleted their
events. Readers skip those. It fails on missing entries, which a query using
the index would miss, and on entries their event does not derive. Reindex
rebuilds the table from every stored event, so the result is complete and
holds no stale entries, and verifies that before promoting it; it also
finishes a build the relay had not. See
[lmdb-v3.md](lmdb-v3.md#wok_event__tagkind).

Reindex also repairs records that lack single-letter tag values longer than
255 bytes. strfry and Wok 0.7.0 and earlier dropped such values from the packed
record, so filters cannot match them and such an addressable record is keyed
by an empty or later `d`. Integrity JSON counts the records reindex would
repack as `legacy_long_tag_records`, and doctor emits a `long-tag-packing`
warning while it is nonzero. Reindex packs each of them again from its payload, as Wok packs
new events, while it builds the staged database. A record whose payload packs
differently in any other way is copied unchanged and counted as skipped; kind
41 history that older releases packed with a virtual `d` is the known case. The
outcome and `reindex-manifest.json` report `repacked_long_tag_records` and
`skipped_long_tag_records`, and the fingerprints of the original
(`source_event_fingerprint_sha256`) and of the result
(`event_fingerprint_sha256`), which differ once a record is repacked. A
repaired addressable record may land beside a newer version of its address,
which makes it superseded history for `wok purge-superseded`.

A deletion request whose `a` tag is longer than 255 bytes tombstones its
address once repaired, and reindex then deletes the versions it names, as the
relay does when such a request arrives: every version of that address by the
request's author with a `created_at` at or before the request's. Newer
versions and the request itself stay. The same applies when the request was
stored with its tag but the versions were keyed by another address until
the repack. A shorter `a` tag is applied again only when it names a
replaceable event or pads the kind (below). The outcome and manifest count the
deleted versions as `deleted_under_repaired_deletions`, and the original
database in the backup still holds them. Verification accounts for them explicitly: the result must
match the original's fingerprint without exactly those versions. Nothing else
changes: removing the hashed values from a repacked record gives its previous
bytes back.
See [lmdb-v3.md](lmdb-v3.md#packedevent).

Reindex applies the same way the deletion requests that strfry or Wok 0.7.0
and earlier stored with an `a` tag naming a replaceable event
(`<kind>:<pubkey>:`), which those releases ignored, or spelling the kind with
leading zeros (`030000:…`), which they tombstoned by that spelling so older
versions came back. It deletes the versions the request names up to its
`created_at`, counted in `deleted_under_repaired_deletions`, and adds the
tombstone of the canonical address. Integrity JSON counts such requests as
`legacy_untombstoned_deletions`, and doctor emits a `deletion-tombstones`
warning while it is nonzero. A padded `a` tag longer than 255 bytes still
deletes, but its tombstone matches nothing. See
[lmdb-v3.md](lmdb-v3.md#eventreplacedeletion).

## Outbound connections

`wok sync`, `wok router`, `wok upload`, and `wok download`
dial whatever `ws(s)://` URL the operator (or a router config file) supplies.
There is no filtering against loopback, link-local (e.g. `169.254.169.254`),
or private ranges — these commands will happily dial internal addresses, and
up-directions export your local DB to the configured URL. Treat router
configs and sync/upload targets as trusted input. TLS verification is always
on and cannot be disabled.

## One-shot downloads

`wok download <url> [--filter <json>]` sends one REQ and prints each event the
relay returns before EOSE as a JSON line on stdout, in the normalized form
`wok export` writes, ready for `wok import`. It checks each event as `wok
import` does: its id (NIP-01 or the legacy tao preimage) and signature, the
local `events.max_event_size`, `max_num_tags` and `max_tag_val_size` limits,
and that a deletion's `a` tags spell their kind canonically and name only
its author's events. An event that fails, or a message that is not JSON, is
skipped and logged on stderr. The command exits nonzero when it skipped
anything or the connection closed before EOSE; the events it printed stay
printed. In `wok download … | wok import` the shell reports import's exit
status unless `pipefail` is set. `--no-verify` skips the id, signature and
`max_event_size` checks; the tag limits and deletion checks still apply.
Unlike `wok import --no-verify`, which still stops at a line of
`max_event_size` bytes or more, it then prints oversized events too.

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
`written`, `duplicates`, `superseded`, `expired`, `rejected`, `unavailable`,
`uploaded`, `upload_rejected`, `upload_superseded`, `upload_expired`, and `error`. `have` and `need` count unique differences discovered during the run,
not the remaining differences after transfer. `uploaded` counts positive relay
ACKs, not recipient delivery. CLI parsing/config-loading errors may occur before a
summary can be produced. JSON and missing-ID output are mutually exclusive.

A transfer exits nonzero on rejected downloads, rejected uploads, requested IDs
missing at EOSE, closed subscriptions, protocol errors, disconnects or timeout.
Only ACKs matching outstanding upload IDs count. Unsolicited events/EOSE/ACKs
cannot complete a batch. Duplicate records already stored are successful outcomes.
`superseded` counts downloads discarded because a newer local version exists.
`upload_superseded` counts local records superseded before sending and negative
peer ACKs whose reason starts with `blocked: have a newer version`, or with
`replaced:` from strfry and earlier Wok releases. `expired` and `upload_expired`
count downloads dropped and local records not sent because their NIP-40
expiration has passed. In `ttl` ephemeral mode a relay keeps serving such an
ephemeral event until its purge, and relays refuse expired events. These are
terminal successful outcomes; other policy rejections still fail the transfer.
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

## Trees while NIP-77 is off

`relay.negentropy_enabled = false` stops the relay answering NEG-OPEN and
NEG-MSG, but its writer keeps updating every registered tree, the default
`{}` tree included, as it stores and deletes events. That costs each write a
B-tree update per tree the event matches, and in return:

- turning NIP-77 back on, which reloads live, serves complete trees at once;
- `wok sync`, which reconciles from a local tree whether or not the relay
  answers NIP-77, finds it consistent;
- no tree can go stale behind the setting. A tree that missed writes would
  lack the events stored meanwhile and keep those deleted or replaced, and
  only `wok reindex --confirm-relay-stopped` repairs that, since
  `wok negentropy build` only adds records. The relay checks the size of the
  `{}` tree before it serves it, but not the contents of a filtered tree.

The writer runs this on stored events' timestamps and ids only, after an
event has passed every check and been stored, so a client chooses nothing
the tree code parses.

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
