# wok-cli

The `wok` binary. Subcommands cover relay, verified strfry migration, DB utilities, diagnostics, and mesh tooling.

Build: `cargo build --release -p wok-cli` → `target/release/wok`. Default config path: `wok.toml`.

## Layout

- `Cargo.toml`
- `src/main.rs` — clap CLI and most dbutils (import/export/scan/…)
- `src/migrate.rs` — `wok migrate strfry`
- `src/doctor.rs` — `wok doctor`
- `src/reindex.rs` — `wok reindex`
- `src/router.rs` — `wok router`
- `src/mesh.rs` — shared outbound WebSocket client helpers for stream/sync/upload/download

## Command groups

| Group | Commands |
| --- | --- |
| Migration | `migrate strfry` (`--check` preflight) |
| Relay | `relay` |
| Diagnostics | `doctor`, `integrity`, `info` |
| Maintenance | `reindex`, `compact`, `dict`, `negentropy` |
| Data | `import`, `export`, `scan`, `event`, `delete`, `monitor` |
| Mesh | `router`, `stream`, `sync`, `upload`, `download` |

`migrate` never mutates the source strfry DB/config. `reindex` requires `--confirm-relay-stopped`. Broken-pipe on stdout is a clean exit (not abort under `panic = "abort"`).
