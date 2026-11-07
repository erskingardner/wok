# Migration from strfry

Wok treats strfry LMDB v3 as a one-way import format, not as a shared runtime
database. The command converts directly into RocksDB; it never writes an LMDB
intermediate. Migration is designed to be lossless for event records, auditable,
and safe to abandon before cutover.

## Command

Stop strfry and every other source writer before preflight, and keep them
stopped through copying. The read-only check creates no snapshot or output
directory, but verifies source file and transaction identity; active writes can
make it refuse the source:

```bash
wok migrate strfry \
  --db /var/lib/strfry \
  --config /etc/strfry.conf \
  --output /var/lib/wok \
  --check
```

The report includes source version, full integrity results, the verification
of every event against its payload, event count,
source and estimated output sizes, free space and LMDB map utilization, every
translated and ignored config key, external executable/socket path checks, any
process holding `data.mdb` open, and the exact generated TOML. Add `--json` for
machine-readable output.

The process-holding probe shells out to `lsof`; migration resolves it at a
well-known absolute path (`/usr/bin/lsof` etc.) before falling back to `PATH`
lookup. Since migration is the highest-trust operation wok performs, run it
with a clean `PATH` if your system keeps `lsof` elsewhere.

After reviewing the report, keep the source stopped and run:

```bash
wok migrate strfry \
  --db /var/lib/strfry \
  --config /etc/strfry.conf \
  --output /var/lib/wok --confirm-relay-stopped
```

The source paths must exist and the output path must not. Stop every source
writer and pass `--confirm-relay-stopped` for actual conversion. The migration repeats
the preflight before doing any work. Wok builds the result
in a sibling staging directory and renames it into place only after every check
passes.

## What the command guarantees

1. The source is a registered read-only strfry v3 LMDB snapshot. No source
   write transaction or writable LMDB intermediate is used.
2. Integrity checks and each stored event's id, signature, packed fields, tags
   and expiration must agree with its payload. See
   [Events that do not verify](#events-that-do-not-verify).
3. The bounded converter preserves logical tables, local event IDs, PackedEvent,
   encoded payloads and dictionaries; it derives native author frontiers and
   normalizes the destination's ownership marker to Wok v5.
4. Per-table framed hashes/counts and the primary fingerprint verify the copy;
   the sealed target reopens as RocksDB before publication.
5. Supported source settings become native Wok TOML pointing to the new database.
   A checksummed manifest records verification and configuration translation.
6. Sibling staging is retained on failure. Only a verified result is published,
   atomically and without replacing an existing output.

The command does not write source `data.mdb`, logical records or configuration.
LMDB may update `lock.mdb` to coordinate its registered reader. Keep all source
writers stopped until copying finishes; the converter checks source file and
transaction identity again before sealing. No service is switched automatically.

## Events that do not verify

Integrity derives every index from an event's packed record, and the relay
serves its payload. strfry verifies an event's id and signature and packs it
from its JSON as it accepts it, but `strfry import --no-verify` skips the
verification and `--fried` takes the packed record as given. A database
written by those, or edited by hand, can hold a record whose payload is
another event, a record that files a signed event under another recipient,
address, deletion target or expiry, or no event its author signed. Migration
does not trust the source on this. The payload must name the packed record's
id, pubkey, kind and created_at, and the packed tags and expiration must come
from the payload as strfry's database version 3 packs them:

- Every packed tag is one of the payload's single-letter tags, an `e` or `p`
  value as the bytes its 64 hex characters decode to and any other value as
  written up to 255 bytes, or hashed as Wok packs a longer one. The exception
  is the empty `d` strfry adds to replaceable and addressable kinds and kind
  41. A payload tag the record leaves out is accepted, as strfry left out
  values longer than 255 bytes: it only keeps queries from finding the event
  by that tag.
- The first packed `d`, which keys replacement, is the payload's address:
  empty for a replaceable kind, and for an addressable kind the payload's
  first `d`, or empty when it has none. strfry skipped a `d` longer than 255
  bytes, so for one the next `d`, or empty, is accepted as well as its hash.
- The first packed `p` of 32 bytes, the only one recipient-only reads admit,
  is the payload's first `p` that decodes to 32 bytes, or neither has one.
- The packed expiration is the one strfry writes: 1 for an ephemeral kind,
  otherwise the payload's first `expiration` tag, or 0 when it has none. A
  payload whose first `expiration` tag is not a time of at least 100 is
  refused, as strfry refused it: Wok reads 0 as no expiry and 1 as ephemeral.

Migration then checks the event's id and signature, accepting either id
preimage a stored event may use (NIP-01, or the one strfry hashed for events
containing U+007F). Hex is read as strfry read it, in either case and after an
optional `0x`, and no limit from strfry's config is applied, so an event
strfry verified and packed fails only if Wok's JSON parser refuses its
payload, for example for nesting deeper than 128 levels. Conversion also has
hard byte bounds: 64 MiB per source record and 16 MiB per decoded event JSON.
Oversized records refuse conversion and are never skipped.

Any event that fails refuses publication. It is not skipped: the migration
retains an unpublished staging directory instead of publishing a partial copy. The error, like the preflight report, gives the
number that failed and names up to 100 of them by local ID, the id the
indexes hold, and the reason, such as `bad signature` or `packed p tag <hex> is
not in the payload`. To migrate, stop strfry, delete those events (for
example `strfry delete --filter '{"ids":["<id>"]}'`) or restore the database
from a backup, and run the migration again.

Verification performs a tag check, SHA-256 and Schnorr signature check per
event. Preflight and copying read separate snapshots; the converter verifies
the exact snapshot it will publish. Allow downtime for full copying and
verification, and reserve destination/temporary space rather than treating the
preflight duration as a conversion estimate.

## Output

```text
/var/lib/wok/
  db/
    ... native RocksDB files ...
  wok.toml
  migration-manifest.json
  migration-manifest.sha256
```

The manifest records source and target paths and versions, Wok's version,
migration time, event count and fingerprint, config hashes, source `data.mdb`
hash, native-file inventory, logical-table verification hashes, source
preservation and review warnings. The sidecar checksums the exact manifest bytes.
It also records `superseded_groups` and `superseded_events` for retained
replaceable history, and `legacy_long_tag_records` for records that lack long
tag values and that reindex can repack. Preflight warns about these versions and migration reports
the retained counts. This is advisory: all source records are preserved exactly,
while relay queries expose only the newest version per replacement address.
After migration, `wok purge-superseded` can delete the retained versions; see
[mesh and maintenance](mesh-and-maintenance.md#storage-checks-and-repair).

strfry drops single-letter tag values longer than 255 bytes from its packed
records, and migration keeps those records byte for byte. The manifest's
`legacy_long_tag_records` counts them, and migration prints the count when it
is nonzero. `wok reindex` packs them again so filters match those values and
long addresses are their own. A deletion whose long `a` tag strfry dropped then
deletes the versions it names up to its `created_at`, which strfry left stored;
see [lmdb-v3.md](lmdb-v3.md#packedevent). Reindex does the same for a deletion
whose `a` tag names a replaceable event (`<kind>:<pubkey>:`), which strfry
ignores, or spells the kind with leading zeros, which strfry tombstones by that
spelling. Migration prints how many such requests it copied; see
[lmdb-v3.md](lmdb-v3.md#eventreplacedeletion).

## Config review

Migration parses the supported strfry HOCON subset and writes a strict TOML
config. Unsupported keys are not copied, and external integrations may not have
identical semantics. Before starting Wok, review at least:

- write-policy plugin commands, users, permissions, and timeouts. HOCON
  arrays of anonymous objects (for example `plugins.accept = [ { cmd = "..." } ]`)
  parse and appear in the ignored-key list; they are not translated. Wok
  accepts a single `relay.write_policy_plugin` command, which maps from
  `relay.writePolicy.plugin`;
- `relay.info.nips`, which Wok replaces with its runtime capability catalog;
- ephemeral-event policy: migrated records remain intact and age out normally,
  while newly accepted ephemeral kinds are live-only unless you explicitly set
  `events.ephemeral_persistence = "ttl"`;
- native `relay.abuse` budgets, query-cost/concurrency limits, optional storage
  quotas, and NIP-13 difficulty; these are Wok settings with no strfry key to
  translate and are enabled with documented Wok defaults;
- relative filesystem paths, because the generated config has a new location;
- listener, reverse-proxy, AUTH, and NIP-11 settings;
- restricted-read defaults: an explicit source value is preserved, while Wok's
  native default protects kinds 4 and 1059 and reports unusable AUTH during
  preflight;
- Unix socket ownership and access settings if enabling Wok's Unix transport;
- any key not documented in [config.md](config.md).

## Cutover and rollback

Start Wok with the generated config and perform REQ, publish, AUTH, COUNT, and
negentropy smoke tests appropriate to the deployment before moving traffic.

The original strfry database is the rollback point. Wok's v5 database must not
be opened by strfry. If post-cutover events need to move back, stop Wok, export
the required JSONL, and import it into a separate strfry v3 database. Test that
recovery workflow before production cutover if zero event loss is required.

The preserved source is a pre-cutover snapshot. After Wok accepts new events or
administrative changes, restarting strfry on that source omits those changes.
Event JSON transfer does not restore moderation or other complete runtime state;
validate any reconciliation before choosing rollback. Never point strfry at the
RocksDB directory or mutate an import source during conversion.
