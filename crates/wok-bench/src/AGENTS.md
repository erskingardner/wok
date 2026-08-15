# wok-bench/src

Single binary: `main.rs`.

Principles at the top of the file: disposable DBs, identical corpus for both relays, warm-up, correctness gates. CLI flags select `--profile smoke|full`, `--scenario`, `--strfry`, `--wok`, `--out`, seed, mix, and scale knobs.

Output is JSONL plus a markdown summary under `--out` (default `bench-results`). Reproduce from the repo README; interpret numbers using `docs/benchmarks.md` rather than a single local run.
