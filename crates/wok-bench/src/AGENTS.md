# wok-bench/src

Single binary: `main.rs`, plus `clients.rs` for `--scenario clients` (the only scenario that keeps abuse controls and AUTH on; it can run against a supplied relay TOML with `--relay-config`) and `author_kinds.rs` for `--scenario author_kinds` (a planner sweep on a large, kept dataset, optionally against a second wok binary with `--wok-baseline`). `transport.rs` is `--scenario ws_transport` (per-connection memory, bursts, fan-out, churn and codec levels, with and without permessage-deflate).

`live.rs` holds `--scenario monitor_index` and `--scenario live_subscriptions`: many live subscriptions with distinct author lists, churn and a reconnect storm. `monitor_index` runs `wok_query::ActiveMonitors` in process, so it measures the index compiled into the bench binary, not `--wok`.

Principles at the top of the file: disposable DBs, identical corpus for both relays, warm-up, correctness gates. CLI flags select `--profile smoke|full`, `--scenario`, `--strfry`, `--wok`, `--out`, seed, mix, and scale knobs.

Output is JSONL plus a markdown summary under `--out` (default `bench-results`). Reproduce from the repo README; interpret numbers using `docs/benchmarks.md` rather than a single local run.
