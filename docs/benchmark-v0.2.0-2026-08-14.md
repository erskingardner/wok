# Wok v0.2.0 benchmark: 2026-08-14

This campaign reruns the controlled relay and transport matrix after the Wok
v0.2.0 performance work. The clearest improvements over the previous Wok
build are Unix request/response throughput, WebSocket connection setup, and
saturated WebSocket fanout. Publication remains the main performance gap to
strfry.

## Test contract

- Relay host: Debian 13, Linux `6.12.101+deb13-cloud-amd64`, 4 vCPU AMD
  EPYC-Genoa, about 8 GB RAM, private address `10.0.0.3`.
- Load host: Debian 13, Linux `6.12.100+deb13-cloud-amd64`, 8 vCPU, about
  16 GB RAM, private address `10.0.0.2`.
- Wok: tag `v0.2.0`, commit
  `a5ea46d8a0bf15d133bd5d34f48f49458fd93563`, release binary SHA-256
  `2037e2f33d77f15f6ed27c0049fcd686f662ee9d5da76542218d7988221eb98b`.
- strfry control: commit `9acdaeb1f63919184ece5f2dd67af21f1ed62f1b`,
  binary SHA-256
  `50df6b434b2f7f35f127f9e28fee3fc305602b163235dccfcecb8cb59ea3e7e2`.
- Harness: built from the Wok v0.2.0 commit, SHA-256
  `25fb4c37196bfa3800c19f715573b5919afbadae5db54652f3cad51e915944bf`
  on both hosts.
- Corpus: 100,000 deterministic signed events, `realistic` mix, seed `4242`,
  base timestamp `1786706848`, SHA-256
  `4d83b08f3bc684c811aec18c6c8bb6e97d6f051cc9b3646430ca286830b538b9`.
- Every target received a fresh database imported from the same byte-identical
  corpus. Target order rotated over three repetitions.

Two separate experiments were run:

1. A two-host relay comparison over the isolated Hetzner private network:
   Wok WebSocket versus strfry WebSocket.
2. A same-host transport comparison: Wok WebSocket, Wok Unix socket, and
   strfry WebSocket.

The two-host campaign produced 42 result rows and the same-host campaign 54.
All 96 rows had `ok=true`, with zero errors and zero mismatches. Values below
are medians across the three order-rotated repetitions. Latency cells are
p50 / p99.

## Two-host relay results

| Scenario | Wok v0.2.0 | strfry |
|---|---:|---:|
| Historical query throughput | **90.3 req/s** | 90.3 req/s |
| Historical query latency | 11.51 / 34.91 ms | **8.75 / 31.41 ms** |
| Mixed read/write throughput | **22.8 req/s** | 22.7 req/s |
| Mixed read/write latency | 44.06 / 47.78 ms | **44.03 / 47.46 ms** |
| Accepted publication rate | 2,820 events/s | **4,808 events/s** |
| Publication OK latency | 45.22 / 69.82 ms | **24.05 / 56.06 ms** |
| Fanout delivery rate | **25,264 deliveries/s** | 23,219 deliveries/s |
| Post-publish fanout drain | **43.42 ms** | 125.76 ms |
| Connection-open rate | 1,153 conn/s | **1,176 conn/s** |
| Connection-open latency | 0.817 / **1.467 ms** | **0.802** / 1.872 ms |
| Deep-history page rate | 115.7 pages/s | **128.6 pages/s** |
| Deep-history page latency | 8.27 / 9.78 ms | **7.83 / 8.54 ms** |
| Lifecycle publication rate | 250 events/s | **320 events/s** |
| Lifecycle publication latency | 4.25 / 6.86 ms | **3.29 / 5.50 ms** |

At saturation Wok delivered fanout about 8.8% faster and drained subscriber
sockets much sooner. strfry accepted the realistic publication workload about
70.5% faster and the single-connection lifecycle workload about 27.6% faster.
Historical query throughput was effectively tied because both WebSocket paths
were paced at about 11 ms per request on this network/client path.

## Same-host transport results

| Scenario | Wok WebSocket | Wok Unix | strfry WebSocket |
|---|---:|---:|---:|
| Historical query throughput | 90.3 req/s | **2,338.7 req/s** | 90.4 req/s |
| Historical query latency | 11.65 / 30.69 ms | **0.41 / 1.07 ms** | 10.79 / 32.93 ms |
| Mixed read/write throughput | 22.7 req/s | **962.1 req/s** | 22.8 req/s |
| Mixed read/write latency | 44.03 / 47.84 ms | **0.92 / 2.29 ms** | 44.03 / 45.44 ms |
| Accepted publication rate | 2,799 events/s | 2,727 events/s | **4,112 events/s** |
| Publication OK latency | 45.38 / 63.90 ms | 44.86 / 84.29 ms | **27.47 / 61.60 ms** |
| Fanout delivery rate | **35,359 deliveries/s** | 32,488 deliveries/s | 29,428 deliveries/s |
| Post-publish fanout drain | **61.25 ms** | 375.55 ms | 88.51 ms |
| Connection-open rate | 4,054 conn/s | **13,950 conn/s** | 3,790 conn/s |
| Connection-open latency | 0.192 / 0.442 ms | **0.046 / 0.117 ms** | 0.227 / 0.428 ms |
| Deep-history page rate | 120.5 pages/s | 113.6 pages/s | **172.1 pages/s** |
| Deep-history page latency | 7.38 / 13.47 ms | 8.77 / 10.22 ms | **5.77 / 6.47 ms** |

The fanout latency value is the time spent draining subscriber sockets after
the publisher received every `OK`; it is not a per-event latency histogram.
A faster producer can leave a larger queued backlog, so a paced-arrival test is
still needed for an equal-offered-load delivery-latency comparison.

## Change from the previous controlled build

The baseline used Wok commit
`876bce55671120fc65b9a0844d2f4ae9f1d9d229`. Both campaigns used the exact same
corpus hash, host, configs, target rotation, and workload sizes. Positive
numbers mean higher throughput.

| Scenario | Wok WebSocket | Wok Unix | Fixed strfry control |
|---|---:|---:|---:|
| Historical query | +0.0% | **+25.8%** | -0.1% |
| Mixed read/write | -0.2% | **+13.4%** | +0.1% |
| Accepted publication | -3.1% | -5.1% | +18.5% |
| Fanout delivery | **+22.0%** | +2.0% | +3.3% |
| Connection opens | **+9.6%** | -15.4% | +5.0% |
| Deep-history pages | +35.3% | +22.7% | +62.0% |

The fixed strfry binary moved by 18.5% on publication and 62.0% on deep
history between campaigns. That is direct evidence of run/environment
variability, especially for short deep-history trials. The Unix query and
mixed-workload gains are the strongest Wok before/after result because the
strfry WebSocket controls for those workloads were essentially unchanged.
WebSocket connection setup is also a useful positive signal, while the Unix
connection regression should be rerun with more repetitions before diagnosis.

Publication did not improve in this campaign. Wok's median declined 3.1% over
WebSocket and 5.1% over Unix while the strfry control improved. The direction
is worth investigating, but three repetitions are not enough to distinguish a
small code regression from host variance. The large two-host gap makes the
signature/admission/single-writer publication path the next optimization
priority regardless.

## Resource and import observations

Each resource value is the median of the maximum observed value in each
same-host repetition. Process CPU can exceed 100% on the four-CPU VM.

| Target | Server max CPU | Server max RSS | Load-client max RSS |
|---|---:|---:|---:|
| Wok WebSocket | 107% | 632 MiB | 282 MiB |
| Wok Unix | 109% | 453 MiB | 166 MiB |
| strfry WebSocket | 173% | 292 MiB | 268 MiB |

Wok server RSS was effectively unchanged from the baseline. The v0.2.0 import
median was 6.74 seconds versus 6.95 seconds for the baseline. After importing
the corpus, Wok's database occupied 192,348,288 bytes and strfry's
163,299,456 bytes.

## Retained evidence and reproduction

The original evidence is retained at:

- relay, same-host: `/opt/relay-bench/campaigns/transport-full-100k-v020-a5ea46d`
  (98 MB);
- load copy, same-host: `/opt/wok-load/results/transport-full-100k-v020-a5ea46d`;
- relay, two-host: `/opt/relay-bench/campaigns/twohost-full-100k-v020-a5ea46d`
  (91 MB);
- load, two-host: `/opt/wok-load/results/twohost-full-100k-v020-a5ea46d`
  (117 MB).

Each bundle contains per-trial JSONL and summaries, import timings, `pidstat`,
node metrics, socket/network snapshots, journals, database sizes, and binary,
config, and corpus hashes. The relay helper's `source_commit` text field
captured the relay host's older Wok source checkout rather than the deployed
release binary. The executed binary is still unambiguous from its exact commit
path and SHA-256 above; the helper was corrected after the campaign to label
source-checkout provenance explicitly.

Reproduce the campaigns described in [benchmarks.md](benchmarks.md):

```bash
CAMPAIGN_ID=twohost-full-100k-v020-a5ea46d \
  EVENTS=100000 REPETITIONS=3 \
  ./scripts/benchmark-campaign.sh

CAMPAIGN_ID=transport-full-100k-v020-a5ea46d \
  EVENTS=100000 REPETITIONS=3 \
  ./scripts/benchmark-transports.sh
```

After collection both relay services were inactive, TCP ports 7777 and 7778
were closed, and the Wok Unix socket had been removed.

## Limits and next measurements

- Three repetitions provide order balancing and medians, not confidence
  intervals or universal capacity claims.
- The same-host transport run intentionally makes the client and relay share
  four CPUs. Do not combine its numbers with the two-host capacity results.
- Add more repetitions and longer deep-history samples to reduce run noise.
- Add paced publication/fanout tests to compare latency at equal offered load.
- Profile signature verification, admission, batching, and the single-writer
  path during the two-host publication workload.
- Isolate the roughly 11/44 ms WebSocket cadence with packet captures and raw
  TCP/WebSocket request-response microbenchmarks.
