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

## EventPayload

- `0x00` + UTF-8 JSON (compact, keys `content,created_at,id,kind,pubkey,sig,tags`)
- `0x01` + dictId u32 native + zstd body

## Integrity

`wok integrity` verifies metadata and payload envelopes and compares every
expected event-derived secondary-index entry with the actual indexes in both
directions. `wok doctor` additionally decompresses payloads, checks payload ID
identity, opens negentropy trees, and diagnoses version, endianness, capacity,
config, plugin, and socket-path problems.

`wok reindex --confirm-relay-stopped` repairs damage confined to derived
event/negentropy indexes. It copies authoritative Meta, filter, dictionary,
PackedEvent, and EventPayload records into a sibling staging database, derives
all indexes again, verifies the event fingerprint and integrity report, then
renames the original to a retained backup and atomically promotes the staged
directory. It refuses primary, payload, or metadata corruption.

## Wok v4 to v5

Stop all older Wok writers before opening the database with this release and
keep a backup for rollback. A normal writable open creates `wok_State` and
upgrades the marker in one transaction. Read-only inspection does not upgrade
it. Primary PackedEvent and payload bytes remain unchanged. The sequence
initializes from the highest existing local ID; author counters initialize
lazily under the writer transaction, before the first insert or deletion for
that author. Subsequent changes coalesce and commit with the event batch.

The sequence never decreases after deleting the newest record. Reindex retains
that high-water mark while rebuilding author counts lazily from authoritative
indexes. An aborted transaction changes neither sequence nor counts. Older Wok
versions refuse v5; rollback requires restoring the backup, not lowering the
version marker or mixing writers.
