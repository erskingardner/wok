# Offline migration from Wok LMDB to RocksDB

`wok migrate rocksdb` copies a stopped Wok LMDB v4 or v5 database into a new
RocksDB directory. It preserves every known logical table, local event ID,
PackedEvent, encoded payload and compression dictionary, including moderation,
vanish markers, negentropy state and unfinished maintenance progress. It derives
the RocksDB author frontiers from the copied records. A v4 source's existing
Meta version field becomes v5 in the destination; the source is unchanged.

This command does not export and reimport event JSON. JSON export/import is not
a full-state backend conversion: it does not preserve local IDs, encoded
payload bytes or administrative state. A strfry v3 source must first go through
the verified [strfry migration](migration-from-strfry.md) using an LMDB build.
Unknown versions, tables or incompatible LMDB flags are refused.

## Choose the binary and reserve space

The default build uses LMDB. Keep that binary for the original database and
build the complete RocksDB variant separately:

```sh
cargo build --release --locked -p wok-cli --target-dir target/lmdb
cargo build --release --locked -p wok-cli --features rocksdb \
  --target-dir target/rocksdb
./target/lmdb/release/wok storage-backend
./target/rocksdb/release/wok storage-backend
```

Each binary opens only its compiled backend and physical layout. The `rocksdb`
feature selects the v3 thin-author/frontier layout and its optimized reader.
Lower-level experimental layout features are documented in
[the backend reference](rocksdb-experimental.md). `--version` is unchanged;
`storage-backend` works without a configuration file or database.

Source and destination paths must be valid UTF-8 for the manifest. The
destination's parent directory must already exist, be writable by the
operator, and be outside the source. The destination itself must not exist,
even as an empty directory or dangling symlink. The source and its locks,
staging, and destination must remain protected from other users and utilities.

Preflight requires free space of at least three times the source `data.mdb`
length plus 2 GiB on the destination filesystem. This is a conservative
estimate, not an upper bound on RocksDB's temporary compaction space. Keep the
original database and any independent backup, allow additional operating
headroom, and monitor the disk throughout conversion. The copy uses bounded
batches and per-record limits; the native engines also have their own caches.

## Stop, check, and copy

Stop the relay and every importer, maintenance command, or other process using
the source. Keep them stopped until conversion finishes. Downtime includes
copying and full verification; preflight does not measure that duration or
verify every event. Both modes use a registered read-only LMDB transaction:
`data.mdb` and logical source state are not written, while LMDB's reader
coordination can update `lock.mdb`.

```sh
./target/rocksdb/release/wok migrate rocksdb \
  --source /var/lib/wok/lmdb-db \
  --output /var/lib/wok/rocks-db --check --json

./target/rocksdb/release/wok migrate rocksdb \
  --source /var/lib/wok/lmdb-db \
  --output /var/lib/wok/rocks-db --confirm-relay-stopped
```

These explicit-path commands do not load `wok.toml`. `--check` creates no output;
it checks version, tables, flags, counts, paths and disk headroom. Add `--json`
to either command for one machine-readable outcome on standard output.
Diagnostics and errors use standard error and failures return a nonzero exit.
The stop acknowledgement is required for copying, but it is not a process lock
or a substitute for stopping source users. The converter checks the source file
identity and latest transaction again before sealing the destination.

The copy is built inside a private sibling `.wok-rocksdb-migrate-*` directory.
The storage layer verifies length-framed hashes, counts and byte totals for
every logical table, primary/payload consistency and signatures, physical counts
and derived author frontiers. It preserves valid stored-event identity, rather
than replaying publication policy or repacking stored records. Only after
verification, a read-only reopen, and synced manifest files does the command
atomically publish the directory without replacing another path.

The published directory contains:

```text
rocks-db/
  ... native RocksDB files ...
  wok-migration-manifest.json
  wok-migration-manifest.sha256
```

The manifest records source and destination, Wok version, source transaction,
physical layout, every logical table's source/expected/target hashes, counts,
verification and any v4 version normalization. The SHA-256 sidecar covers the
exact manifest bytes. A small sibling staging receipt remains after success.
It is not the database and may be removed once the published result is checked.

Failures never replace an output or remove the source. They retain staging and
report its path. An incomplete storage copy has a pending marker and ordinary
relay opens refuse it. A failure after sealing, including a filesystem or
manifest-publication error, can instead leave a valid, unpublished database.
The outcome's `verified_copy` records whether the command confirmed successful
storage verification; `false` is not a claim that retained bytes are unsealed.
`output_published` records whether publication occurred. Do not start a staging
directory or retry into it. Inspect the failure,
retain evidence as needed, resolve the cause and use a fresh output. A failure
after publication, such as a parent-directory sync error, explicitly reports
`output_published: true`; do not assume the output is absent.

## Verify and cut over

Review the manifest, then run the offline physical audit with the same binary:

```sh
./target/rocksdb/release/wok --config /etc/wok/rocks.toml rocksdb-check
```

Set `[database].path` in that configuration to the new directory. Retain the
rest of the relay's policy, identity, plugins and transport configuration. The
migration does not edit configuration, switch a service, or restart the relay.
Check ownership and service filesystem permissions before starting the RocksDB
binary. Confirm a historical query, a publish, visibility policy and any AUTH or
negentropy use before routing clients back to the service.

RocksDB holds an exclusive writer-process lock. A separate importer, backup or
maintenance process cannot open the database while the relay owns that lock;
stop it first. This differs from LMDB's separate reader processes and coordinated
single writer. Never run either backend against the other's directory.

## Back up and roll back

Use the binary matching the database format:

```sh
wok --config /etc/wok/wok.toml backup --output /var/backups/wok/db-snapshot
```

The parent must exist and the output must be a new directory. LMDB creates a
consistent compact snapshot through a read-only open without upgrading a v4
source. RocksDB creates a native checkpoint and requires the relay to be
stopped so the command can take its exclusive open. Source records are not
modified by backup. Keep the complete directory and restore it only while the
relay is stopped, using the matching binary and physical layout. Do not copy
individual live database files or use the legacy `compact <file>` LMDB command
as a RocksDB backup interface. Protect backups as carefully as the live state;
they include administrative and moderation data.

Before any post-cutover writes, rollback can stop RocksDB and restart the LMDB
binary on the preserved source. After new writes, that LMDB directory is only
the pre-cutover snapshot: it does not contain newly accepted events or changed
moderation, vanish, sequence and maintenance state. There is no automatic
reverse converter or state merge. Plan and validate reconciliation or restore
from a suitable backup before choosing rollback; event-only JSON transfer does
not recover the complete administrative history.
