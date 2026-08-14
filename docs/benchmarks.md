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

Use at least three repetitions for comparative results; relay order alternates
on each repetition to reduce order and thermal bias:

```bash
./target/release/wok-bench --profile full --repetitions 5 \
  --base-timestamp 1700000000 --out bench-results \
  --strfry /path/to/strfry --wok ./target/release/wok --seed 1
```

Every campaign writes `corpus.jsonl` (the exact signed input events),
`manifest.json` (corpus and available binary SHA-256 values), `results.jsonl`,
and `summary.md`. The timestamp is selected once per campaign rather than once
per generator. Pass `--base-timestamp` when two machines must create
byte-identical corpora. Remote repetitions use stable, distinct per-scenario
workload seeds so a persistent relay does not receive duplicate event IDs.
The default `--event-mix kind1` preserves the focused historical workload;
`--event-mix realistic` adds a weighted mix of kind 0 metadata, kind 1 notes,
kind 3 contacts, kind 7 reactions, kind 9735 zaps, kind 10002 relay lists, and
kind 30023 long-form content while keeping event IDs and signatures
deterministic.

Scenarios: `import` (signature-verifying bulk import), `export`,
`negentropy_build`, `ws_publish_1conn`/`ws_publish_8conn` (per-publish OK
latency + rate), `ws_query_latency` (mixed REQs: id, author+kind, time
window, tag), `deep_history_pagination` (progressively older 500-event
author+kind+until pages), `mixed_read_write` (historical REQs while another
connection continuously publishes), `live_fanout` (configurable publisher and
subscriber delivery completeness), `ws_publish_scaled` (configurable
connection count), `idle_connections` (open-and-hold connection capacity),
`duplicate_import`, `cold_start`, and Wok-only
`nip50_search` (rare, intersected, and full-corpus ranked searches with
result/limit verification). Use `--scenario <name>` to isolate one scenario.

## Two-host load generation

The `load` profile can run from a separate load-generator VM against an
already-running relay:

```bash
./wok-bench --profile load --target-url ws://RELAY_IP:7777 \
  --target-label wok --out results/wok \
  --events 100000 --publish-connections 128 \
  --fanout-subscribers 256 --fanout-events 1000 \
  --connections 10000 --hold-seconds 30 --repetitions 3 \
  --event-mix realistic --base-timestamp 1700000000 --seed 1
```

Run the same command against one clean relay at a time, changing only the URL
and label. Reset the relay database between Wok and strfry campaigns, preserve
the result directories, and capture server-side CPU, RSS, disk I/O, network
traffic, and database size externally. The remote profile deliberately covers
network publication, fanout, and connection pressure only: historical query
comparisons require a separately controlled, identical preloaded database
snapshot and are not silently run against unknown remote state.

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
