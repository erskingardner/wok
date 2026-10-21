# wok-bench/src

Single binary: `main.rs`, plus `clients.rs` for `--scenario clients` (the only scenario that keeps abuse controls and AUTH on; it can run against a supplied relay TOML with `--relay-config`) and `author_kinds.rs` for `--scenario author_kinds` (a planner sweep on a large, kept dataset, optionally against a second wok binary with `--wok-baseline`).

Principles at the top of the file: disposable DBs, identical corpus for both relays, warm-up, correctness gates. CLI flags select `--profile smoke|full`, `--scenario`, `--strfry`, `--wok`, `--out`, seed, mix, and scale knobs.

Output is JSONL plus a markdown summary under `--out` (default `bench-results`). Reproduce from the repo README; interpret numbers using `docs/benchmarks.md` rather than a single local run.
