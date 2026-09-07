# wok-cli/src

| File | Role |
| --- | --- |
| `main.rs` | `Cli` / `Command`, relay startup, import/export/scan/event/delete/compact/monitor/dict/negentropy/upload/download |
| `migrate.rs` | Read-only v3 snapshot, integrity, v5 marker, TOML translation, checksummed manifest |
| `doctor.rs` | Config, storage, index, payload, negentropy, capacity, runtime-path report (`--json`) |
| `reindex.rs` | Stage rebuilt indexes, verify fingerprint, atomic promote, keep backup + manifest |
| `sync.rs` | NIP-77 operator client, transfer outcomes, JSON and missing-ID checks |
| `router.rs` | Multi-connection mesh client, hot-reload of tao-config router file |
| `mesh.rs` | Bounded tungstenite client config for mesh links |

`doctor.rs` and `migrate.rs` allow `unsafe` for LMDB snapshot/stat FFI; keep new unsafe there, not in `main.rs`. Mesh clients do not negotiate permessage-deflate (tungstenite limitation).
