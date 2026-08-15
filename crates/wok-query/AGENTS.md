# wok-query

Filter compilation, historical scans, live subscription monitors, and NIP-45 HyperLogLog. `#![forbid(unsafe_code)]`.

This crate reads PackedEvent and search postings through `wok-db`; it does not own the environment.

## Layout

- `Cargo.toml`
- `src/` — filter, scan, scheduler, monitors, HLL
- `tests/` — filter properties, kind scans, NIP-50 search

## Notes

- ID/author filters are exact 32-byte hex (matches C++ `FilterSetBytes(..., 32, 32)`). Prefixes are invalid.
- NIP-50 search terms are compiled here but indexed in `wok-db::search`.
- `QueryScheduler` and `ActiveMonitors` are used by the relay req/monitor threads in `wok-relay`.
