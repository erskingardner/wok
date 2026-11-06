# wok-cli/src

| File | Role |
| --- | --- |
| `main.rs` | `Cli` / `Command`, relay startup, import/export/scan/event/delete/backup/monitor/dict/negentropy/upload/download |
| `migrate.rs` | Direct registered-read-only strfry v3 → RocksDB conversion, stored-event verification, TOML translation and checksummed manifest |
| `migrate_rocksdb.rs` | Full-state Wok LMDB-to-RocksDB preflight, retained staging, manifest and no-replace publication |
| `config_show.rs` | `wok config show`: effective values with their origin, `--overrides`, `--defaults` |
| `config_minimize.rs` | `wok config minimize`: drop keys equal to the preset, `--dry-run` diff or `.bak` backup |
| `doctor.rs` | Config (including pinned past defaults, and public values kept under another preset), storage, index, payload, negentropy, capacity, runtime-path report (`--json`) |
| `reindex.rs` | Stage rebuilt indexes, verify fingerprint, atomic promote, keep backup + manifest |
| `sync.rs` | NIP-77 operator client, transfer outcomes, JSON and missing-ID checks |
| `router.rs` | Multi-connection mesh client, hot-reload of tao-config router file |
| `mesh.rs` | Bounded tungstenite client config for mesh links |

Keep unsafe FFI in reviewed OS and read-only migration boundaries, never in `main.rs`. Mesh clients do not negotiate permessage-deflate (tungstenite limitation).
