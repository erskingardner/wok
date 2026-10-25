# wok-cli/src

| File | Role |
| --- | --- |
| `main.rs` | `Cli` / `Command`, relay startup, import/export/scan/event/delete/compact/monitor/dict/negentropy/upload/download |
| `migrate.rs` | Read-only v3 snapshot, integrity, event id/signature verification, v5 marker, TOML translation, checksummed manifest |
| `config_show.rs` | `wok config show`: effective values with their origin, `--overrides`, `--defaults` |
| `config_minimize.rs` | `wok config minimize`: drop keys equal to the preset, `--dry-run` diff or `.bak` backup |
| `doctor.rs` | Config (including pinned past defaults), storage, index, payload, negentropy, capacity, runtime-path report (`--json`) |
| `reindex.rs` | Stage rebuilt indexes, verify fingerprint, atomic promote, keep backup + manifest |
| `sync.rs` | NIP-77 operator client, transfer outcomes, JSON and missing-ID checks |
| `router.rs` | Multi-connection mesh client, hot-reload of tao-config router file |
| `mesh.rs` | Bounded tungstenite client config for mesh links |

`doctor.rs` and `migrate.rs` allow `unsafe` for LMDB snapshot/stat FFI; keep new unsafe there, not in `main.rs`. Mesh clients do not negotiate permessage-deflate (tungstenite limitation).
