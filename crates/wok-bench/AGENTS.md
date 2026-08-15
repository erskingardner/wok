# wok-bench

Comparative load harness: Wok vs strfry, correctness before speed. Excluded from default CI (`cargo test --workspace --exclude wok-bench`). `#![forbid(unsafe_code)]`.

Never opens a user database. Each trial uses a disposable temp dir, a deterministic signed corpus, warm-up, and latency histograms. A trial that drops events or deliveries is `ok=false`.

## Layout

- `Cargo.toml`
- `src/main.rs` — entire harness (profiles, scenarios, JSONL + markdown output)

Methodology: `docs/benchmarks.md`. Campaign wrappers: `scripts/benchmark-*.sh`. Do not treat `bench-results/` at the repo root as source.
