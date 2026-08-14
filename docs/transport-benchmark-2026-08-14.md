# Transport benchmark: 2026-08-14

This report compares Wok's production Unix-socket transport with the Wok and
strfry WebSocket servers. It is a same-host transport experiment, not a claim
about Internet-facing relay performance.

## Test contract

- Relay host: Debian 13, Linux `6.12.101+deb13-cloud-amd64`, 4 vCPU AMD
  EPYC-Genoa, 8.13 GB RAM.
- Wok: commit `876bce55671120fc65b9a0844d2f4ae9f1d9d229`, release binary SHA-256
  `fd239b925cc34faf4879b5f1b5d772acbc29a8f375c33767c08c42934d7d9a0c`.
- strfry: commit `9acdaeb1f63919184ece5f2dd67af21f1ed62f1b`, binary SHA-256
  `50df6b434b2f7f35f127f9e28fee3fc305602b163235dccfcecb8cb59ea3e7e2`.
- Corpus: 100,000 deterministic, signed events using the `realistic` event mix,
  seed `4242`, base timestamp `1786706848`, SHA-256
  `4d83b08f3bc684c811aec18c6c8bb6e97d6f051cc9b3646430ca286830b538b9`.
- Targets: Wok WebSocket over the host's private IPv4 address, Wok Unix socket
  at `/var/lib/relay-bench/wok/wok.sock`, and strfry WebSocket over the same
  IPv4 address. No external network path, TLS, or reverse proxy was involved.
- Three repetitions with target order rotated on every repetition. Every
  target received a freshly reset database imported from the same corpus.
- Load: 400 mixed historical queries, progressive deep-history pages, 400
  queries concurrent with 400 writes, 100,000 publications over 128
  connections, 128 subscribers receiving 500 events each, and 10,000 idle
  connections held for 15 seconds.

The campaign produced 54 result rows. All had `ok=true`, zero errors, and zero
mismatches. Values below are medians across the three order-rotated
repetitions. Latency cells show p50 / p99.

## Results

| Scenario | Wok WebSocket | Wok Unix | strfry WebSocket |
|---|---:|---:|---:|
| Historical query throughput | 90.3 req/s | **1,859.4 req/s** | 90.5 req/s |
| Historical query latency | 11.25 / 38.59 ms | **0.49 / 1.27 ms** | 11.38 / 33.12 ms |
| Mixed read/write throughput | 22.8 req/s | **848.7 req/s** | 22.7 req/s |
| Mixed read/write latency | 44.03 / 47.07 ms | **0.99 / 2.33 ms** | 44.03 / 48.13 ms |
| Accepted publication rate | 2,887 events/s | 2,873 events/s | **3,470 events/s** |
| Publication OK latency | 44.29 / 58.75 ms | 44.16 / 58.75 ms | **35.90 / 62.27 ms** |
| Fanout delivery rate | 28,983 deliveries/s | **31,839 deliveries/s** | 28,483 deliveries/s |
| Post-publish fanout drain | **41.31 ms** | 365.82 ms | 116.16 ms |
| Connection-open rate | 3,698 conn/s | **16,486 conn/s** | 3,611 conn/s |
| Connection-open latency | 0.251 / 0.462 ms | **0.038 / 0.110 ms** | 0.254 / 0.441 ms |
| Deep-history page rate | 89.1 pages/s | 92.6 pages/s | **106.3 pages/s** |
| Deep-history page latency | 12.06 / 14.58 ms | 11.64 / 12.67 ms | **9.17 / 10.10 ms** |

The fanout latency is the time spent draining subscriber sockets after the
publisher has received every `OK`; it is not a per-event latency histogram.
The faster Unix producer leaves a larger queued backlog at saturation even
though total delivery throughput is higher. A paced-arrival test is needed to
compare fanout latency at equal offered load.

## Resource observations

Each value is the median of the maximum observed value in each repetition.
Process CPU can exceed 100% because the VM has four CPUs.

| Target | Server max CPU | Server max RSS | Load-client max RSS |
|---|---:|---:|---:|
| Wok WebSocket | 107% | 632 MiB | 282 MiB |
| Wok Unix | 114% | 459 MiB | 166 MiB |
| strfry WebSocket | 168% | 292 MiB | 283 MiB |

At 10,000 connections, Wok Unix used about 173 MiB less peak server RSS and
116 MiB less load-client RSS than Wok WebSocket in this campaign.

## Interpretation

- Unix framing materially reduces local request/response and connection-setup
  overhead: query throughput was about 20.6 times Wok WebSocket, mixed
  read/write throughput about 37.2 times, and connection opens about 4.5 times.
- The roughly 44 ms mixed-workload cadence appears with both WebSocket relays
  and disappears over Unix. That points to the shared TCP/WebSocket/client path
  rather than Wok's query engine or LMDB scan; it still needs packet-level and
  client-code isolation before assigning a narrower cause.
- Wok publication throughput was effectively identical over its two
  transports. Improving that workload means looking beyond framing and
  connection setup, particularly admission, signature verification, and the
  single-writer path.
- strfry led deep-history pagination and saturated publication in this run.
  Those are useful optimization targets for Wok, not transport conclusions.

## Reproduction and retained evidence

Run the guarded campaign documented in [benchmarks.md](benchmarks.md):

```bash
CAMPAIGN_ID=transport-full-100k-876bce5 \
  EVENTS=100000 REPETITIONS=3 \
  ./scripts/benchmark-transports.sh
```

The 101 MB evidence bundle contains the corpus and manifest, per-trial JSONL
and summaries, `/usr/bin/time`, `pidstat`, node metrics, socket and network
snapshots, journals, database sizes, configuration and binary hashes, and final
service state. It is retained on the benchmark hosts at:

- relay: `/opt/relay-bench/campaigns/transport-full-100k-876bce5`;
- load generator: `/opt/wok-load/results/transport-full-100k-876bce5`.

Both relay services were inactive after collection; TCP port 7777 was closed
and the Unix socket had been removed.

## Limits and follow-ups

- Client and server shared four CPUs, so client cost and server contention are
  intentionally part of the same-host transport comparison.
- Three repetitions support medians and order balancing, not confidence
  intervals or universal capacity claims.
- Add a paced fanout scenario so transports receive an equal event arrival
  rate before comparing delivery latency.
- Isolate the WebSocket cadence with packet captures and raw TCP, WebSocket,
  and Unix request/response microbenchmarks.
- Use the separate two-host campaign for realistic network, proxy, and TLS
  capacity measurements; do not combine those numbers with this table.
