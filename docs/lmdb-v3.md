# LMDB v3 byte contract

Derived from C++ `golpe.yaml` / generated `defaultDb.h` at strfry `9acdaeb1f63919184ece5f2dd67af21f1ed62f1b`.

Endianness: native (little-endian on supported hosts). `Meta.endianness` must be `1`. `Meta.dbVersion` must be `3`. No silent migration.

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

Env: `max_dbs=64`, mode `0664`, `MDB_CREATE`.

## PackedEvent

88-byte header: id(32) pubkey(32) created_at(u64ne) kind(u64ne) expiration(u64ne) then tags `name:u8 len:u8 value`.

`e`/`p` tag values stored as raw 32 bytes. Replaceable kinds prepend virtual `d=""`. Param-replaceable append virtual `d=""`. Ephemeral kinds set expiration=1.

## EventPayload

- `0x00` + UTF-8 JSON (compact, keys `content,created_at,id,kind,pubkey,sig,tags`)
- `0x01` + dictId u32 native + zstd body

## Integrity

`wok integrity` reports missing payloads, orphan payloads, packed parse errors, and id-index count drift.
