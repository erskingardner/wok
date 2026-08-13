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
window, tag), `deep_history_pagination` (progressively older 500-event
author+kind+until pages), `mixed_read_write` (historical REQs while another
connection continuously publishes), `live_fanout` (1 publisher x 32 subscribers, delivery
completeness), `duplicate_import`, `cold_start`, and Wok-only
`nip50_search` (rare, intersected, and full-corpus ranked searches with
result/limit verification). Use `--scenario <name>` to isolate one scenario.

A trial with missing events, unexpected rejections, or dropped deliveries is
`ok=false` — correctness gates come before speed.

Latest committed run (Apple Silicon aarch64, 10k events, single noisy run —
do not rank from one run): `docs/sample-bench-summary.md` and
`docs/sample-bench-results.jsonl`. Headline shape: wok leads on DB-path CLI
scenarios (import 1.6x, export 3.4x, negentropy build 2.3x, dup import
4.3x), WS publish is round-trip-bound parity, and WS query QPS is within
run-to-run noise after the req-worker marshalling pass (~9.0k vs ~9.7k qps
for strfry; an earlier revision of this benchmark measured a 35% strfry
lead, which was traced to per-event allocation churn in wok's query path,
not the LMDB scan itself).

See [NIP-50 search](nip50-search.md) for the search workload, exact semantics,
and 100k/1m-event scale results.
