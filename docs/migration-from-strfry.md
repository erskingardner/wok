# Migration from strfry

Wok treats strfry LMDB v3 as a one-way import format, not as a shared runtime
database. Migration is designed to be lossless for event records, auditable,
and safe to abandon before cutover.

## Command

Stop strfry first so the eventual cutover has a clear event boundary, then run:

```bash
wok migrate strfry \
  --db /var/lib/strfry \
  --config /etc/strfry.conf \
  --output /var/lib/wok
```

The source paths must exist and the output path must not. Wok builds the result
in a sibling staging directory and renames it into place only after every check
passes.

## What the command guarantees

1. The source LMDB environment is opened read-only and copied with LMDB's
   transactionally consistent compact-copy operation.
2. The copy must be strfry database version 3 and pass Wok's integrity checks.
3. Every Event and EventPayload record is fingerprinted using its local event
   ID, exact packed bytes, and exact stored payload bytes.
4. Only the copied Meta database ownership marker is changed, from strfry v3
   to Wok v4.
5. The event fingerprint and count must remain identical after that change, and
   the result must reopen as a Wok database.
6. Supported source settings are translated into native Wok TOML, with the
   database path selecting the new Wok database.

The command does not write to the source `data.mdb` or source config. A failed
migration does not promote a partial output.

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
`data.mdb` hash, verification results, and review warnings.

## Config review

Migration parses the supported strfry HOCON subset and writes a strict TOML
config. Unsupported keys are not copied, and external integrations may not have
identical semantics. Before starting Wok, review at least:

- write-policy plugin commands, users, permissions, and timeouts;
- `relay.info.nips`, which Wok replaces with its runtime capability catalog;
- ephemeral-event policy: migrated records remain intact and age out normally,
  while newly accepted ephemeral kinds are live-only unless you explicitly set
  `events.ephemeral_persistence = "ttl"`;
- relative filesystem paths, because the generated config has a new location;
- listener, reverse-proxy, AUTH, and NIP-11 settings;
- Unix socket ownership and access settings if enabling Wok's Unix transport;
- any key not documented in [config.md](config.md).

## Cutover and rollback

Start Wok with the generated config and perform REQ, publish, AUTH, COUNT, and
negentropy smoke tests appropriate to the deployment before moving traffic.

The original strfry database is the rollback point. Wok's v4 database must not
be opened by strfry. If post-cutover events need to move back, stop Wok, export
the required JSONL, and import it into a separate strfry v3 database. Test that
recovery workflow before production cutover if zero event loss is required.

Never run strfry and Wok as writers against the same LMDB environment.
