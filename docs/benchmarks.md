# Benchmarks

Harness: `wok-bench`. Always uses disposable temp directories and an
identical deterministic corpus for both relays (same seed, same signed
events). Both binaries are optimized builds (C++ `-O3`, wok release + thin
LTO).

```bash
cargo build --release -p wok-cli -p wok-bench
./target/release/wok-bench --profile full --out bench-results \
  --strfry /Users/jeff/code/strfry/strfry \
  --wok ./target/release/wok --seed 1
```

`--profile smoke` is a quick sanity run (2k events); `--profile full` runs
all scenarios (20k events default; use `--events`/`--queries` to tune).

Scenarios: `import` (signature-verifying bulk import), `export`,
`negentropy_build`, `ws_publish_1conn`/`ws_publish_8conn` (per-publish OK
latency + rate), `ws_query_latency` (mixed REQs: id, author+kind, time
window, tag), `live_fanout` (1 publisher x 32 subscribers, delivery
completeness), `duplicate_import`, `cold_start`.

A trial with missing events, unexpected rejections, or dropped deliveries is
`ok=false` — correctness gates come before speed.

Latest committed run (Apple Silicon aarch64, 10k events, single noisy run —
do not rank from one run): `docs/sample-bench-summary.md` and
`docs/sample-bench-results.jsonl`. Headline shape from that run: wok leads
on DB-path CLI scenarios (import/export/negentropy build/dup import), WS
publish is round-trip-bound parity, WS query QPS favors strfry in this run
(~9.1k vs ~6.7k qps; worth re-measuring on your host).
