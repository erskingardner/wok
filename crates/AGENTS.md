# crates/

Cargo workspace members. Root `Cargo.toml` lists them and shared `[workspace.dependencies]`. Each crate has its own `AGENTS.md`.

## Dependency direction (rough)

```
wok-event
   ↑
wok-db  ←  wok-query  ←  wok-negentropy
   ↑           ↑              ↑
           wok-relay
          ↗         ↖
     wok-ws         wok-unix
          ↖         ↗
           wok-cli
              ↑
     wok-bench, wok-compat
```

`wok-event` is the leaf. Transports talk to `wok-relay` only. CLI and tests sit on top.

## Crates

| Directory | Crate | Start here |
| --- | --- | --- |
| `wok-event/` | Event model, JSON, hashing, PackedEvent | `src/lib.rs` |
| `wok-db/` | LMDB env, schema, write/query indexes | `src/lib.rs` |
| `wok-query/` | Filters, scans, live monitors, HLL | `src/lib.rs` |
| `wok-negentropy/` | NIP-77 reconcile + persistent tree | `src/lib.rs` |
| `wok-relay/` | Dispatcher, config, AUTH, plugins | `src/server.rs` |
| `wok-ws/` | HTTP, NIP-11, WebSocket, admin | `src/lib.rs` |
| `wok-unix/` | Unix socket frames | `src/lib.rs` |
| `wok-cli/` | `wok` binary | `src/main.rs` |
| `wok-bench/` | Comparative harness | `src/main.rs` |
| `wok-compat/` | Conformance / e2e / C++ diffs | `src/lib.rs`, `tests/` |

## Working in this tree

- Prefer changing behavior in the owning crate, not by special-casing in CLI or tests.
- Keep LMDB work off Tokio tasks; copy out of mmap before `.await`.
- `#![forbid(unsafe_code)]` on event/query/negentropy/ws/unix/bench/compat. Exceptions are documented at the FFI boundary.
- Integration and property tests live in each crate's `tests/` (or `#[cfg(test)]` in the module). Cross-crate protocol tests live in `wok-compat`.
