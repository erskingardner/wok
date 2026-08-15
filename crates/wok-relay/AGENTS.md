# wok-relay

Transport-neutral Nostr relay core: command dispatch, writer, REQ/COUNT, AUTH, plugins, abuse limits, config, metrics.

Transports (`wok-ws`, `wok-unix`) hold a `RelayHandle` and send owned strings over bounded outbound channels. This crate owns the dedicated OS threads (ingester, writer, req-worker, req-monitor, negentropy, cron).

## Layout

- `Cargo.toml`
- `src/` — server and supporting modules
- `tests/` — protocol property tests
- `examples/` — empty; not used

## Invariants

- LMDB work stays on OS threads. Outbound messages are owned `String`s; mmap borrows never enter Tokio channels.
- Single application-level writer thread; slow clients fail `try_send` and are dropped when `max_pending_outbound_bytes` is exceeded.
- Restricted-read REQ/NEG-OPEN require a *completed* NIP-42 AUTH when restriction is on (stricter than C++).
- NIP advertisement is the typed catalog in `capabilities.rs`, not an arbitrary config list.
