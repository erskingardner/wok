# Migration from strfry

Wok treats strfry LMDB v3 as a one-way import format, not as a shared runtime
database. Migration is designed to be lossless for event records, auditable,
and safe to abandon before cutover.

## Command

Run the no-write preflight first; it does not create a snapshot or output
directory and may be run while strfry is serving traffic:

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

After reviewing the report, stop strfry so the cutover has a clear event
boundary, then run:

```bash
wok migrate strfry \
  --db /var/lib/strfry \
  --config /etc/strfry.conf \
  --output /var/lib/wok
```

The source paths must exist and the output path must not. The migration repeats
the preflight before doing any work. Wok builds the result
in a sibling staging directory and renames it into place only after every check
passes.

## What the command guarantees

1. The source LMDB environment is opened read-only and copied with LMDB's
   transactionally consistent compact-copy operation.
2. The copy must be strfry database version 3 and pass Wok's integrity checks.
3. Every event in the copy must verify against its stored payload: the payload
   names the packed record's id, pubkey, kind and created_at, hashes to that
   id, and carries a valid Schnorr signature by that pubkey, and the packed
   record, from which every index is derived, indexes nothing the payload does
   not carry. See
   [Events that do not verify](#events-that-do-not-verify).
4. Every Event and EventPayload record is fingerprinted using its local event
   ID, exact packed bytes, and exact stored payload bytes.
5. Only the copied Meta database ownership marker is changed, from strfry v3
   to Wok v5.
6. The event fingerprint and count must remain identical after that change, and
   the result must reopen as a Wok database.
7. Supported source settings are translated into native Wok TOML, with the
   database path selecting the new Wok database.

The command does not write to the source `data.mdb` or source config. A failed
migration does not promote a partial output.

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
  written, up to 255 bytes. The exception is the empty `d` strfry adds to replaceable and
  addressable kinds and kind 41. A payload tag the record leaves out is
  accepted: it only keeps queries from finding the event by that tag.
- The first packed `d`, which keys replacement, is the payload's address:
  empty for a replaceable kind, and for an addressable kind the payload's
  first `d` of up to 255 bytes, or empty when it has none.
- The packed expiration is 0, 1 for an ephemeral kind, or the payload's first
  `expiration` tag.

Migration then checks the event's id and signature, accepting either id
preimage a stored event may use (NIP-01, or the one strfry hashed for events
containing U+007F). Hex is read as strfry read it, in either case and after an
optional `0x`, and no limit from strfry's config is applied, so an event
strfry verified and packed fails only if Wok's JSON parser refuses its
payload, for example for nesting deeper than 128 levels (see
[known differences](known-differences.md)).

Any event that fails refuses the migration. It is not skipped: migration
copies every record or none. The error, like the preflight report, gives the
number that failed and names up to 100 of them by local ID, the id the
indexes hold, and the reason, such as `bad signature` or `packed p tag <hex> is
not in the payload`. To migrate, stop strfry, delete those events (for
example `strfry delete --filter '{"ids":["<id>"]}'`) or restore the database
from a backup, and run the migration again.

Verification costs a pass over the tags, a SHA-256 and a Schnorr signature
check per event, spread over every core. The preflight, which may run beside strfry, uses half of
them. The migration verifies its own snapshot, not the database the preflight
read, so what it promotes is what it verified.

## Output

```text
/var/lib/wok/
  db/
    data.mdb
    lock.mdb
  wok.toml
  migration-manifest.json
```

The manifest records source and target paths and versions, Wok's version,
migration time, event count and fingerprint, config hashes, the final Wok
`data.mdb` hash, verification results (`source_events_verified` is the check
above), and review warnings.
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

Never run strfry and Wok as writers against the same LMDB environment.
