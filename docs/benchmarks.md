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
The default `--event-mix kind1` preserves the focused historical workload.
`--event-mix realistic` uses 32 stable actors and adds a weighted mix of kind 0
metadata, kind 1 notes and replies, kind 3 contacts, kind 7 reactions, kind
9735 zaps, kind 10002 relay lists, and kind 30023 long-form content. Relations
refer to events and authors in the same corpus. Replaceable and addressable
events are assigned so both databases retain exactly the requested corpus
size. `--event-mix lifecycle` adds kind 5 deletion requests and kind 20001
ephemeral events for live publication tests where retained counts are not the
correct assertion.

Generate a signed corpus without running a relay, or reuse one verbatim:

```bash
./target/release/wok-bench --generate-corpus-only --events 100000 \
  --event-mix realistic --seed 4242 --base-timestamp 1700000000 \
  --out benchmark-corpus

./target/release/wok-bench --scenario ws_query_latency \
  --target-url ws://10.0.0.3:7777 --target-label wok \
  --corpus benchmark-corpus/corpus.jsonl --events 100000 \
  --event-mix realistic --queries 400 --out query-results
```

When `--corpus` and `--events` are both supplied, the harness rejects a count
mismatch. Remote historical query scenarios assume the identical corpus has
already been imported into the target relay; they still verify EOSE,
non-empty expected results, publication acknowledgements, and delivery
completeness.

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
and label. Reset the relay database between Wok and strfry campaigns and
preserve the result directories.

### Reproducible two-host campaign

`scripts/benchmark-campaign.sh` automates the project benchmark hosts. It:

1. generates one signed realistic corpus on the load generator;
2. copies and checksum-verifies that exact file on the relay host;
3. stops both relays, resets only the selected benchmark database, imports
   with signature verification, and confirms the exported retained count;
4. starts only the selected relay and captures process, system, socket,
   network, Prometheus, journal, binary/config hash, import, and database-size
   evidence;
5. runs query latency, deep pagination, mixed reads/writes, scaled publication,
   live fanout, idle connections, and lifecycle publication; and
6. alternates relay order between repetitions before leaving both stopped.

The relay-side helper refuses database paths outside the fixed
`/var/lib/relay-bench/{wok,strfry}` roots and artifact paths outside
`/opt/relay-bench/{campaigns,results}`.

```bash
# Defaults: 100k corpus, three order-balanced repetitions, 10k idle sockets.
./scripts/benchmark-campaign.sh

# Short end-to-end validation before a measured campaign.
CAMPAIGN_ID=shakeout EVENTS=2000 REPETITIONS=1 QUERIES=50 \
  DEEP_PAGES=2 PUBLISH_CONNECTIONS=16 FANOUT_SUBSCRIBERS=16 \
  FANOUT_EVENTS=50 IDLE_CONNECTIONS=128 HOLD_SECONDS=2 \
  LIFECYCLE_EVENTS=200 LIFECYCLE_CONNECTIONS=1 COOLDOWN_SECONDS=1 \
  ./scripts/benchmark-campaign.sh
```

The main environment overrides are `RELAY_SSH`, `LOAD_SSH`, `RELAY_URL`,
`BENCH_BIN`, `CAMPAIGN_ID`, `EVENTS`, `QUERIES`, `DEEP_PAGES`, `REPETITIONS`,
`PUBLISH_CONNECTIONS`, `FANOUT_SUBSCRIBERS`, `FANOUT_EVENTS`,
`IDLE_CONNECTIONS`, `HOLD_SECONDS`, `LIFECYCLE_EVENTS`, `NOFILE_LIMIT`,
`LIFECYCLE_CONNECTIONS`, `COOLDOWN_SECONDS`, `SEED`, and `BASE_TIMESTAMP`.

Lifecycle publication defaults to one ordered connection because a deletion
request must follow the event it references. Scaled publication is measured in
the separate realistic workload; increasing `LIFECYCLE_CONNECTIONS` tests
cross-stream ingestion ordering as a distinct experiment. The historical
corpus keeps one fixed timestamp and byte-identical signatures; each lifecycle
phase uses a freshly recorded timestamp so short-lived ephemerals remain valid.

Load-side artifacts live under `/opt/wok-load/results/<campaign-id>` and
contain the corpus, campaign metadata, every harness result, `/usr/bin/time`
output, and a copy of each server-side evidence directory. Server originals
remain under `/opt/relay-bench/campaigns/<campaign-id>`. Do not compare speed
for any phase whose `results.jsonl` has `ok=false`, non-zero `errors`, or
non-zero `mismatches`.

A trial with missing events, unexpected rejections, or dropped deliveries is
`ok=false` — correctness gates come before speed.

## Unix versus WebSocket transports

Wok's Unix transport can run the same publication, query, pagination,
mixed-read/write, fanout, and connection-capacity scenarios as WebSocket:

```bash
./target/release/wok-bench --profile load \
  --target-unix /run/wok/wok.sock --target-label wok-unix \
  --events 100000 --publish-connections 128 \
  --fanout-subscribers 128 --fanout-events 500 \
  --connections 10000 --hold-seconds 15 --out unix-results
```

`--target-unix` and `--target-url` are mutually exclusive. Unix clients use
the production four-byte big-endian length plus UTF-8 JSON framing, not a
benchmark-only protocol.

Do not compare a same-host Unix result directly to a WebSocket client running
on another VM: that mixes transport overhead with network RTT. The guarded
`scripts/benchmark-transports.sh` campaign instead runs all three clients on
the relay VM:

- Wok over WebSocket;
- Wok over its Unix socket; and
- strfry over WebSocket.

Each target receives a fresh database imported from the same checksum-verified
signed corpus. The script rotates the three-target order over its default
three repetitions, applies the same correctness gates, records both client and
server resources, and leaves both services stopped. It requires the benchmark
Wok config to enable `/var/lib/relay-bench/wok/wok.sock`.

```bash
# Defaults: 100k events, three rotated repetitions.
./scripts/benchmark-transports.sh

# Fast end-to-end transport shakeout.
CAMPAIGN_ID=transport-shakeout EVENTS=2000 REPETITIONS=1 QUERIES=40 \
  PUBLISH_CONNECTIONS=8 FANOUT_SUBSCRIBERS=8 FANOUT_EVENTS=30 \
  IDLE_CONNECTIONS=64 HOLD_SECONDS=1 COOLDOWN_SECONDS=1 \
  ./scripts/benchmark-transports.sh
```

Original artifacts remain under `/opt/relay-bench/campaigns/<campaign-id>` and
are copied to `/opt/wok-load/results/<campaign-id>` for analysis with the
two-host campaign results.

### Recorded campaigns

The [v0.2.0 report](benchmark-v0.2.0-2026-08-14.md) records the latest
100,000-event Linux campaign: a two-host Wok/strfry relay comparison and a
same-host Wok Unix/WebSocket transport comparison, each with three
order-rotated repetitions. All 96 result rows passed their correctness gates.
It includes the before/after comparison to the previous controlled Wok build,
median throughput and latency, resources, exact corpus and binary hashes,
limitations, retained artifacts, and next investigations.

The earlier [2026-08-14 transport report](transport-benchmark-2026-08-14.md)
is the baseline for that comparison. It records 54 correct trials against Wok
commit `876bce55671120fc65b9a0844d2f4ae9f1d9d229`.

The older `sample-bench-summary.md` and `sample-bench-results.jsonl` remain a
historical single-run Apple Silicon example of the local process harness. Do
not treat that sample as the current controlled VM result or combine it with
same-host transport and two-host network measurements.

See [NIP-50 search](nip50-search.md) for the search workload, exact semantics,
and 100k/1m-event scale results.
