# strfry LMDB v3 import contract

Derived from C++ `golpe.yaml` / generated `defaultDb.h` at strfry `9acdaeb1f63919184ece5f2dd67af21f1ed62f1b`.

Endianness: native (little-endian on supported hosts). An import source must
have `Meta.endianness = 1` and `Meta.dbVersion = 3`.

Wok never runs directly on that source. `wok migrate strfry` takes a read-only,
transactionally consistent copy, verifies the copied records and each event
against its payload (the packed fields, tags and expiration, the id and the
signature), and changes the copy's `Meta.dbVersion` to Wok version 5. Version 4 introduced the ownership boundary;
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

Import/open environment: `max_dbs=64`; named DBIs use their v3 creation flags
on the private snapshot. Files Wok creates (`data.mdb`, `lock.mdb` and compact
copies) get mode `0640`, less the umask; earlier releases used `0664`.

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
legacy versions that were keyed by another address until the repack, and also
the `a` tags that name a replaceable address or pad the kind with leading
zeros (see [Event__replaceDeletion](#eventreplacedeletion)). The
backup keeps the deleted versions. Nothing repacks implicitly. Finding
legacy records means decoding every payload, which at writable open would make
the first start after an upgrade scan the whole database, and migration keeps
strfry records byte for byte. Repacking changes the record's PackedEvent bytes,
and so `event_fingerprint`, but removing the hashed values gives the previous
bytes back, so the repack itself loses nothing.

## Event__replaceDeletion

A kind 5 record keys `Event__replaceDeletion` by `sha256(a tag) || created_at`
for each `a` tag that names an address of its own author: an addressable kind
(30000–39999), or a replaceable kind (0, 3, 10000–19999) with an empty `d`,
`<kind>:<pubkey>:`. A writer refuses an addressable or replaceable event when
the hash of its own canonical `a` tag has an entry at or after its
`created_at`. strfry, and Wok 0.7.0 and earlier, index addressable kinds only,
by the hash of the tag as written. Ingest now refuses a deletion `a` tag whose
kind has leading zeros. For one stored before, the entry of its spelling is
derived as those releases did, and so is the entry of the canonical spelling,
so the request refuses what it deletes. An `a` tag longer than 255 bytes is the
exception: PackedEvent holds only the hash of its spelling, so its entry
matches nothing.

Deletion requests that strfry or an earlier Wok release stored therefore lack
the entries of replaceable addresses and of canonical spellings, and the
versions they name were never deleted or could be published again. Integrity
accepts the missing entries, so migration and older databases still verify, and
counts such records as `legacy_untombstoned_deletions`; `wok doctor` warns
while any remain. `wok reindex` derives the entries and deletes the versions
those requests name up to their `created_at`, as it does for long `a` tags (see
[PackedEvent](#packedevent)). An earlier Wok release opening a database written by this one does not
derive those entries, so its integrity check reports them as unexpected, and
if it deletes such a deletion request the entry stays behind; `wok integrity`
reports it and `wok reindex` removes it.

## wok_Event__tagKind

A Wok table, not part of strfry v3, that keys every single-letter tag by the
event's kind as well:

| DBI | flags | comparator | key | value |
|---|---|---|---|---|
| `wok_Event__tagKind` | DUPSORT, INTEGERDUP, DUPFIXED | StringUint64Uint64 | tagName\|\|tagVal \|\| kind \|\| created_at | levId |

`tagVal` is the packed value, as in `Event__tag`: the raw 32 bytes of an `e`
or `p` id, the hashed form of a value longer than 255 bytes, and nothing for
a value a legacy record dropped. The virtual `d` of replaceable and
addressable kinds has its entry too. The writer puts and deletes an event's
entries in the transaction that inserts or deletes the event, on every path:
replacement, NIP-09 deletion, NIP-40 expiry, the NIP-62 sweep,
`wok purge-superseded`, `wok delete` and the deletions reindex applies.
`wok import` is the exception: into a table that a key-ordered pass would
build anyway, it leaves the entries to that pass (see
[After an import](#after-an-import)).

Two markers share the table. Their keys are shorter than the 16 bytes of a
posting's integers, so the comparator sorts them before every posting, and
their values are native-endian u64s:

- `\0schema` is the key layout, 1 in this release. A writable open that finds
  no layout or another one empties the table and sets both markers again,
  `\0through` to 0.
- `\0through` is a local ID: every event at or below it has its entries.
  The index is complete when it is at least the sequence high-water mark (the
  stored `sequence`, or the newest local ID where none is stored). A write
  that inserts events moves it past them only when it already covered every
  earlier ID, so a gap of unindexed events stops it.

A new database is complete from its first open, and again once an import
into it ends. One written before this
table existed, or migrated from strfry, gets an empty table at marker 0 on
its first writable open. The relay's writer then builds it in the background,
one bounded transaction at a time (see
[Building in the background](#building-in-the-background)), or
`wok reindex` builds it complete. The database version is unchanged. An
earlier Wok release opens neither table: the events it inserts take IDs
above the marker, which stops there until they are indexed, and the events
it deletes leave their entries. Local IDs are never reused, so a leftover
entry names an event that is no longer stored. The scan reads each
candidate's event to check it, which skips such an entry, `wok integrity`
counts these entries as stale, and `wok reindex` drops them. The scan uses
the index only when its read snapshot shows it complete.

### Building in the background

The writer runs one backfill step before each batch of messages it takes,
and keeps going while it is idle, until the index is complete. A step ends
after 5,000 postings or 10 ms of indexing, whichever comes first, then
commits; it reads entries ahead 64 at a time, so the time limit covers
preparing them too. While free disk space is below
`database.min_free_disk_bytes`, the reserve that also refuses publications,
the build waits, and each maintenance tick checks again. Steps come in two
kinds:

- **Key order**, for a table at marker 0 with events stored. The step walks
  `Event__tag` from a cursor, reads each entry's event for its kind and puts
  the posting. The postings of one tag value sit next to each other, so a
  step rewrites few pages. Building in local-ID order would rewrite about one
  16 KiB page per posting: for 1M events it wrote 20.6 GB, against 1.35 GB in
  key order. The pass covers every event stored when it began, so when the
  walk reaches the end the marker takes the high-water mark from that moment.
  Events inserted since are indexed by this release's writer, and by the
  local-ID steps when an earlier release inserted them.
- **Local-ID order**, for any other gap above the marker. The step indexes
  the next stored events above it and moves the marker past them, to the
  high-water mark once it reaches the newest.

A key-ordered pass keeps its progress in `wok_Event__tagKindBuild`, a Wok
table with the default comparator and no flags, empty when no pass runs:

| key | value |
|---|---|
| `target` | u64 local ID: the high-water mark when the pass began |
| `visited` | u64: `Event__tag` entries visited so far |
| `cursor` | the last `Event__tag` key visited, then its local ID as a u64 |

Values are native-endian. The pass resumes after the cursor, so a restart
loses at most the step it interrupted. Emptying `wok_Event__tagKind` (a new
layout, `wok reindex`) empties this table too. A record that does not decode
is a malformed record in integrity, and the next step starts the pass again.

### After an import

A batch of `wok import` that finds the table in this layout, at marker 0, with
no pass running (a new database, or one whose index has not been built)
writes its events without their entries and leaves the marker at 0. That is
the state in which the next step begins a key-ordered pass, and a pass that
begins after the batch commits covers its events. Deletions in the batch
still remove entries. Once the last batch is written, the import runs that
pass to the end, in the writer's steps of 5,000 postings or 10 ms, so the
index is complete when it exits; a database that already held events at
marker 0 gets their entries too. Building in key order after the load writes
a fraction of the pages that entries put in arrival order rewrite. An import
stopped before then leaves the index incomplete, and the relay's writer
finishes it in the background. Batches that find the index complete, a pass
running, or a gap above a nonzero marker write their entries as above, and
the import builds nothing.

Neither happens while another process has the database open, as the LMDB
reader table shows: a process takes a slot there with its first read, and a
relay's writer reads as it starts. Batches then write their entries, because
the writer would begin the pass after the first batch that left them out,
every later batch would write them anyway, and the pass's end would leave
those events to local-ID steps. The import checks again before each step of
its pass and, once another process appears, leaves the rest to the relay. A
process that has opened the database but not yet read from it holds no slot.
Missing one costs only that extra work: the index ends the same.

A batch never moves the marker past events whose entries it left out, and
never changes a running pass's target: a pass covers exactly the events
stored when it began, and raising its target would claim events whose
`Event__tag` entries sort before its cursor.

## EventPayload

- `0x00` + UTF-8 JSON (compact, keys `content,created_at,id,kind,pubkey,sig,tags`)
- `0x01` + dictId u32 native + zstd body

## Integrity

`wok integrity` verifies metadata and payload envelopes and compares every
expected event-derived secondary-index entry with the actual indexes in both
directions. For `wok_Event__tagKind` it expects entries only of the events at
or below `\0through`, and reports under `tag_kind_index` the markers, whether
the index is complete, any key-ordered pass in progress, and entries
missing, stale (the event is no longer stored) or unexpected (the stored event
does not derive them, or a malformed record). Missing and unexpected entries
fail the check; stale entries do not. It derives each event's search and
tag-kind entries once: a posting of either table is checked by looking up the
event it names and balancing it against the entries the event pass found, in
16 MiB of counters whatever the size of the database, and events are derived
again only to name unexpected entries.
It also validates `wok_State` encodings, compares each stored author
count against primary events (not the derived author index), and checks that a
stored sequence is at least the greatest surviving local ID. Author-count
verification uses temporary memory proportional to the number of distinct
authors during this offline scan; it adds no work to normal event admission.
`wok doctor` additionally decompresses payloads, checks payload ID
identity, opens negentropy trees, and diagnoses version, endianness, capacity,
config, plugin, and socket-path problems.

`wok reindex --confirm-relay-stopped` repairs damage confined to derived
event/negentropy indexes or author counters. It copies authoritative Meta, negentropy filter,
compression dictionary, NIP-62 vanish marker, NIP-86 moderation, PackedEvent, and EventPayload
records into a sibling staging database,
repacking PackedEvent records that dropped long tag values (see
[PackedEvent](#packedevent)), derives all indexes again, `wok_Event__tagKind`
included and marked complete, deletes the versions
that repaired deletions name, builds negentropy trees (which hold every stored
record their filter matches), verifies the integrity
report and the event fingerprint, then renames the original to a retained
backup and atomically promotes the staged directory. When it repacks records,
the fingerprint it verifies leaves out hashed tag values, which are the only
bytes a repack adds; otherwise the full fingerprint must be unchanged. When it
deletes versions, it compares against the original's fingerprint without
exactly those records, each of which must be stored. The manifest records the
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

`wok_State` also keeps how far the NIP-62 sweep has carried out each vanish
marker, under `V` and the pubkey: the marker timestamp the pass deletes
through, the `created_at` it started from, and the next author or `p`-tag
index entry to examine, or that it finished. A missing or unreadable record
starts the marker's passes over, so a reindex, which does not copy these
records, costs one more pass per marker. Earlier releases' integrity check
reports them as unknown keys.

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
