# strfry LMDB v3 import contract

Derived from C++ `golpe.yaml` / generated `defaultDb.h` at strfry `9acdaeb1f63919184ece5f2dd67af21f1ed62f1b`.

Endianness: native (little-endian on supported hosts). An import source must
have `Meta.endianness = 1` and `Meta.dbVersion = 3`.

Wok never runs directly on that source. `wok migrate strfry` takes a read-only,
transactionally consistent copy, verifies the copied records, and changes the
copy's `Meta.dbVersion` to Wok version 5. Version 4 introduced the ownership boundary;
the first Wok format retains the v3 record layout to make migration lossless,
but future Wok versions may evolve it. There is no implicit migration during
normal `relay`, `info`, or database utility commands.

## DBI names, flags, comparators

| DBI | flags | comparator | key | value |
|---|---|---|---|---|
| `rasgueadb_defaultDb__Meta` | INTEGERKEY | default | u64 levid | FlatBuffer Meta |
| `rasgueadb_defaultDb__NegentropyFilter` | INTEGERKEY | default | u64 | FlatBuffer filter string |
| `rasgueadb_defaultDb__Event` | INTEGERKEY | default | u64 levId | PackedEvent |
| `rasgueadb_defaultDb__Event__id` | — | StringUint64 | id \|\| created_at | levId |
| `rasgueadb_defaultDb__Event__pubkey` | — | StringUint64 | pubkey \|\| created_at | levId |
| `rasgueadb_defaultDb__Event__kind` | — | Uint64Uint64 | kind \|\| created_at | levId |
| `rasgueadb_defaultDb__Event__pubkeyKind` | — | StringUint64Uint64 | pubkey \|\| kind \|\| created_at | levId |
| `rasgueadb_defaultDb__Event__tag` | — | StringUint64 | tagName\|\|tagVal \|\| created_at | levId |
| `rasgueadb_defaultDb__Event__deletion` | — | default | e-id \|\| pubkey | levId |
| `rasgueadb_defaultDb__Event__replace` | — | StringUint64 | pubkey\|\|d \|\| kind | levId |
| `rasgueadb_defaultDb__Event__replaceDeletion` | — | StringUint64 | sha256(a-tag) \|\| created_at | levId |
| `rasgueadb_defaultDb__Event__created_at` | INTEGERKEY | default | created_at | levId |
| `rasgueadb_defaultDb__Event__expiration` | INTEGERKEY | default | expiration | levId |
| `rasgueadb_defaultDb__EventPayload` | INTEGERKEY | default | levId | type byte + payload |
| `rasgueadb_defaultDb__CompressionDictionary` | INTEGERKEY | default | dictId | FlatBuffer dict |
| `negentropy` | REVERSEKEY | default | treeId \|\| nodeId (native u64) | Node / MetaData |

Import/open environment: `max_dbs=64`, mode `0664`; named DBIs use their v3
creation flags on the private snapshot.

## PackedEvent

88-byte header: id(32) pubkey(32) created_at(u64ne) kind(u64ne) expiration(u64ne) then tags `name:u8 len:u8 value`.

`e`/`p` tag values stored as raw 32 bytes. Replaceable kinds prepend virtual `d=""`. Param-replaceable append virtual `d=""`. Ephemeral kinds set expiration=1.

A single-letter tag value longer than 255 bytes does not fit `len`. strfry v3
and earlier Wok releases drop that tag. Wok packs it as `0xFF` followed by the
SHA-256 of the value (33 bytes). Other packed values are UTF-8, which never
contains `0xFF`, or 32-byte `e`/`p` ids, so the hashed form cannot equal a
value packed as is. Keys derived from tags use the packed value, so
`Event__tag` and `Event__replace` hold the hashed form, and filter values are
hashed the same way before they are looked up or matched, in history scans and
live monitors alike. `Event__replaceDeletion` already keys by
`sha256(a-tag)`, which for a hashed `a` tag is the 32 bytes after the marker.
Writing an addressable event with a hashed `d`, or a deletion with a hashed
`a`, reads the original value from the event's payload to form the address.

The database version is unchanged. Values of 255 bytes or fewer pack exactly
as before, so existing records and their index entries stay valid, and
integrity, which derives the expected index entries from PackedEvent, accepts
records of either packing. Migration copies PackedEvent unchanged and opening
a database never repacks it, so records packed by strfry or by earlier Wok
releases keep the values they dropped until `wok reindex` restores them:
filters cannot match those
values, an addressable record whose first `d` was dropped keeps the address it
was keyed by (the virtual empty `d` or a later short `d`), so a new version of
its real address does not replace it and an `a`-tag deletion does not remove
it, and a deletion whose long `a` tag was dropped has no
`Event__replaceDeletion` entry. `wok integrity` counts the records that
`wok reindex` would repack as `legacy_long_tag_records`, and `wok doctor`
warns while any remain. An earlier
Wok release opening a database written by this one derives the same index keys
from hashed values, but does not recognize a hashed deletion `a` tag. If it
deletes such a deletion request, the request's `Event__replaceDeletion` entry
stays behind; `wok integrity` reports it and `wok reindex` removes it. Writers
must still not be mixed.

`wok reindex` repacks legacy records while it copies them into the staging
database (see [Integrity](#integrity)). It already decodes every payload, and
selects the records whose JSON has more single-letter tag values longer than
255 bytes than their PackedEvent has hashed values. It packs each one again from
its payload, with every event limit lifted (a legacy row may hold a first `d`
longer than a new event may use), and accepts the result only if
removing the hashed values gives the stored bytes back. Any other difference
copies the record unchanged and counts it as skipped: kind 41 records that
older releases packed with a virtual `d`, or a long `e` or `p` value, which Wok
refuses. A repacked record keeps its local ID and payload; its indexes, the
superseded-version count and negentropy trees are derived from the new packing
like everything else reindex builds. A legacy addressable record can join a
newer version at its real address, where reads hide it as superseded history,
and a version it hid at the empty `d` becomes visible again. A legacy deletion
gains its tombstone, so older versions of its address are refused from then on,
and reindex deletes the versions already stored at or before it, as the writer
does when such a request arrives. It applies the long `a` tags of every stored
deletion request this way, so a request stored with its tag also deletes the
legacy versions that were keyed by another address until the repack. The
backup keeps the deleted versions. Nothing repacks implicitly. Finding
legacy records means decoding every payload, which at writable open would make
the first start after an upgrade scan the whole database, and migration keeps
strfry records byte for byte. Repacking changes the record's PackedEvent bytes,
and so `event_fingerprint`, but removing the hashed values gives the previous
bytes back, so the repack itself loses nothing.

## EventPayload

- `0x00` + UTF-8 JSON (compact, keys `content,created_at,id,kind,pubkey,sig,tags`)
- `0x01` + dictId u32 native + zstd body

## Integrity

`wok integrity` verifies metadata and payload envelopes and compares every
expected event-derived secondary-index entry with the actual indexes in both
directions. It also validates `wok_State` encodings, compares each stored author
count against primary events (not the derived author index), and checks that a
stored sequence is at least the greatest surviving local ID. Author-count
verification uses temporary memory proportional to the number of distinct
authors during this offline scan; it adds no work to normal event admission.
`wok doctor` additionally decompresses payloads, checks payload ID
identity, opens negentropy trees, and diagnoses version, endianness, capacity,
config, plugin, and socket-path problems.

`wok reindex --confirm-relay-stopped` repairs damage confined to derived
event/negentropy indexes or author counters. It copies authoritative Meta, filter, dictionary,
PackedEvent, and EventPayload records into a sibling staging database,
repacking PackedEvent records that dropped long tag values (see
[PackedEvent](#packedevent)), derives all indexes again, deletes the versions
that repaired deletions name, builds negentropy trees (which hold every stored
record their filter matches), verifies the integrity
report and the event fingerprint, then renames the original to a retained
backup and atomically promotes the staged directory. When it repacks records,
the fingerprint it verifies leaves out hashed tag values, which are the only
bytes a repack adds; otherwise the full fingerprint must be unchanged. When it
deletes versions, it compares against the original's fingerprint without them,
and a tombstone in the result must refuse each one. The manifest records the
fingerprints of the original and of the result, how many records were
repacked and skipped, and how many versions were deleted
(`deleted_under_repaired_deletions`). It preserves a valid sequence, including
when it deletes the newest record, and discards author counters for lazy
reconstruction from the rebuilt indexes. It refuses primary, payload, or
metadata corruption, including a malformed or regressed sequence; the highest
surviving event cannot establish the sequence of a previously deleted tail.

## Wok v4 to v5

Stop all older Wok writers before opening the database with this release and
keep a backup for rollback. A normal writable open creates `wok_State` and
upgrades the marker in one transaction. Read-only inspection does not upgrade
it. Primary PackedEvent and payload bytes remain unchanged. The sequence
initializes from the highest existing local ID; author counters initialize
lazily when requested under the writer transaction, normally before a quota
check. Once initialized, subsequent changes coalesce and commit with the event
batch, including while quotas are disabled.

The `superseded-versions` state counter records the number of physical
replacement versions beyond one per address. Writable initialization derives a
missing counter with one ordered replacement-index scan; event inserts and deletes
maintain it in their transaction, and reindex rebuilds it. Read-only snapshots
without this counter conservatively filter replacement history. A zero count
allows persistent negentropy trees even when profiles or contact lists exist.
Integrity compares the stored counter with the index-derived count. This derived
state does not change signed primary records or the lossless migration contract.

Releases that treated kind 41 as replaceable kept this count under
`superseded-events`, and a writable open by such a release writes that key
again. While it is present, readers treat the count as missing. Writable
initialization deletes both keys and counts again under NIP-01 kind ranges.
Kind 41 records packed by those releases keep their virtual `d=""` tag, so a
`#d` filter for the empty string still matches them.

The sequence never decreases after deleting the newest record. Reindex retains
that high-water mark while rebuilding author counts lazily from authoritative
indexes. An aborted transaction changes neither sequence nor counts. Older Wok
versions refuse v5; rollback requires restoring the backup, not lowering the
version marker or mixing writers.

Missing author keys and a missing sequence are valid before lazy initialization;
a v5 marker with no `wok_State` table is not. A stored zero count is valid for
an author with no surviving events. A sequence above the surviving tail is
expected after deletion. Integrity checks cannot distinguish a legitimately
absent lazy key from an erased key, or prove the historical value of a lost
sequence from a single snapshot. Preserve backups for that recovery case.

`cargo test -p wok-db --lib crash_tests` exercises 43 forced process kills:
three v4 upgrade boundaries, and five write boundaries for insertion,
replacement, deletion, and mixed batches with both initialized and lazy state.
The upgrade fixtures remove the state DBI entirely. Reopening read-only must
show either the previous committed snapshot or the complete new snapshot;
subsequent writes must allocate the expected next ID. Test-only checkpoints
are absent from production builds. These are process-death tests before and
after LMDB commit, not power-loss or torn-write simulations.
