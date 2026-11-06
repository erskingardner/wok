# wok-cli

The `wok` binary. Subcommands cover relay, direct read-only LMDB migration to RocksDB, DB utilities, diagnostics, and mesh tooling.

Build: `cargo build --release -p wok-cli` → `target/release/wok`. Default config path: `wok.toml`.

## Layout

- `Cargo.toml`
- `src/main.rs` — clap CLI and most dbutils (import/export/scan/…)
- `src/migrate.rs` — `wok migrate strfry`
- `src/migrate_rocksdb.rs` — offline full-state Wok LMDB conversion and verified publication
- `src/config_show.rs` — `wok config show` (effective config with per-key origin)
- `src/config_minimize.rs` — `wok config minimize` (drop keys equal to the preset, diff or backup)
- `src/doctor.rs` — `wok doctor`
- `src/reindex.rs` — `wok reindex`
- `src/router.rs` — `wok router`
- `src/sync.rs` — NIP-77 transfer and comparison outcomes
- `src/mesh.rs` — shared outbound WebSocket client helpers for router/sync/upload/download

## Command groups

| Group | Commands |
| --- | --- |
| Migration | `migrate strfry`, `migrate rocksdb` (`--check` preflight) |
| Relay | `relay` |
| Diagnostics | `doctor`, `integrity`, `info`, `storage-backend`, `config show` |
| Maintenance | `backup`, `reindex`, `purge-superseded`, `dict`, `negentropy`, `config minimize` |
| Data | `import`, `export`, `scan`, `event`, `delete`, `monitor` |
| Mesh | `router`, `sync`, `upload`, `download` |

`migrate` preserves authoritative source LMDB data/config; registered reader coordination may update lock.mdb. Runtime is RocksDB only. Stop the relay before backup or mutating utilities. `reindex` requires `--confirm-relay-stopped`. Broken-pipe on stdout is a clean exit (not abort under `panic = "abort"`).
