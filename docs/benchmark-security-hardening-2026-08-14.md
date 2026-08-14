# Wok post-hardening benchmark: 2026-08-14

This campaign reruns the complete controlled benchmark matrix after the
WebSocket publication optimizations and the security-hardening series through
commit `fa9b061`. The combined head retained or improved most of the prior
performance profile: two-host WebSocket publication rose 5.1%, its p50/p99
acknowledgement latency fell 5.8%/15.9%, two-host fanout rose 13.7%, and
same-host Unix query and connection throughput rose 24.4% and 32.4%.

All 96 measured rows passed their correctness gates with zero errors and zero
mismatches. Wok still trails strfry on saturated publication, but the
two-host gap narrowed from 70.5% to 60.0%. A separate shutdown-cleanup defect
in the new Unix socket race hardening was found after measurement and fixed in
commit `ca64980`; it does not invalidate the transport results.

## Test contract

- Relay host: Debian 13, Linux `6.12.101+deb13-cloud-amd64`, 4 vCPU AMD
  EPYC-Genoa, about 8 GB RAM, private address `10.0.0.3`.
- Load host: Debian 13, Linux `6.12.100+deb13-cloud-amd64`, 8 vCPU, about
  16 GB RAM, private address `10.0.0.2`.
- Wok: commit `fa9b06156bc598ba853d45fba6cec1359c1081e6`, tree
  `06d179b6bd7ed03fe6d1d8d4657af9d57441abec`, built from a clean archive with
  Rust 1.96.1 and the repository release profile. Binary SHA-256:
  `ef3ac2d8ef87abe7b53733e7a0b603f0cc2171648ccb17aef532c9aa7aae2d80`.
- Wok benchmark config SHA-256:
  `ed7202f33239de03d0bb1a422f2677cb669a01f39460ed31be81ebecfda7c599`.
- strfry control: commit `9acdaeb1f63919184ece5f2dd67af21f1ed62f1b`,
  binary SHA-256
  `50df6b434b2f7f35f127f9e28fee3fc305602b163235dccfcecb8cb59ea3e7e2`.
- Harness: built from the same Wok commit, SHA-256
  `9de60c5e69de1be56616d8b3aab15ea8daf64f50067f6592be0cc3882ba9e331`
  on both hosts.
- Corpus: 100,000 deterministic signed events, `realistic` mix, seed `4242`,
  base timestamp `1786731700`, SHA-256
  `528293fba05633b84e85eae91e9f5df592632056d7cda4233adb4303c890dbba`.
- Every target received a fresh database imported from the same byte-identical
  corpus. Target order rotated over three repetitions.

As before, the campaign has two experiments:

1. A two-host Wok WebSocket/strfry WebSocket comparison over the isolated
   private network.
2. A same-host Wok WebSocket/Wok Unix/strfry WebSocket transport comparison.

The two-host campaign produced 42 result rows and the transport campaign 54.
Values below are medians across the three order-rotated repetitions. Latency
cells are p50 / p99. For fanout, the latency cell is the post-publication time
needed to drain all subscriber sockets.

## Two-host relay results

| Scenario | Wok `fa9b061` | strfry |
|---|---:|---:|
| Historical query throughput | **90.5 req/s** | 90.3 req/s |
| Historical query latency | **11.54 / 31.97 ms** | 11.88 / 39.07 ms |
| Mixed read/write throughput | **22.8 req/s** | 22.6 req/s |
| Mixed read/write latency | **44.06 / 47.58 ms** | 44.10 / 48.22 ms |
| Accepted publication rate | 2,963 events/s | **4,742 events/s** |
| Publication OK latency | 42.59 / 58.69 ms | **23.95 / 55.58 ms** |
| Fanout delivery rate | **28,718 deliveries/s** | 24,793 deliveries/s |
| Post-publish fanout drain | **38.75 ms** | 80.00 ms |
| Connection-open rate | 1,189 conn/s | **1,226 conn/s** |
| Connection-open latency | 0.797 / **1.407 ms** | **0.762** / 1.549 ms |
| Deep-history page rate | 127.6 pages/s | **142.0 pages/s** |
| Deep-history page latency | 8.85 / 9.54 ms | **7.24 / 7.54 ms** |
| Lifecycle publication rate | 265.1 events/s | **304.5 events/s** |
| Lifecycle publication latency | 3.92 / 6.14 ms | **3.48 / 5.46 ms** |

Wok's realistic publication repetitions were 3,006, 2,963, and 2,902
events/s; they were stable across target order. strfry's were 5,177, 4,719,
and 4,742 events/s. At the medians, strfry remained 60.0% faster on accepted
publication while Wok was 15.8% faster on fanout delivery and drained the
subscriber backlog in less than half the time.

### Change from the v0.2.0 campaign

Positive numbers mean higher throughput. The strfry column is the fixed
control and helps distinguish Wok changes from host/run movement.

| Scenario | Wok WebSocket | Fixed strfry control |
|---|---:|---:|
| Historical query | +0.2% | -0.0% |
| Mixed read/write | -0.1% | -0.4% |
| Accepted publication | **+5.1%** | -1.4% |
| Fanout delivery | **+13.7%** | +6.8% |
| Connection opens | +3.1% | +4.3% |
| Deep-history pages | +10.3% | +10.4% |
| Lifecycle publication | **+6.1%** | -4.9% |

The two-host publication comparison is the strongest full-campaign evidence
for the retained performance work: Wok improved while the control was nearly
flat, and Wok publication p50/p99 fell from 45.22/69.82 ms to 42.59/58.69 ms.
The full 100,000-event result should not be numerically combined with the
earlier focused 20,000-event A/B, which used a different duration and source
comparison.

## Same-host transport results

| Scenario | Wok WebSocket | Wok Unix | strfry WebSocket |
|---|---:|---:|---:|
| Historical query throughput | 90.6 req/s | **2,909.5 req/s** | 90.6 req/s |
| Historical query latency | 1.67 / 35.46 ms | **0.337 / 0.831 ms** | 11.78 / 32.03 ms |
| Mixed read/write throughput | 22.8 req/s | **1,005.6 req/s** | 22.8 req/s |
| Mixed read/write latency | 44.00 / 48.32 ms | **0.945 / 2.319 ms** | 44.00 / 47.23 ms |
| Accepted publication rate | 2,929 events/s | 2,939 events/s | **4,450 events/s** |
| Publication OK latency | 43.94 / 56.16 ms | 43.46 / **55.94 ms** | **25.33** / 59.14 ms |
| Fanout delivery rate | **32,865 deliveries/s** | 31,987 deliveries/s | 28,277 deliveries/s |
| Post-publish fanout drain | **43.23 ms** | 370.43 ms | 113.47 ms |
| Connection-open rate | 4,319 conn/s | **18,469 conn/s** | 3,837 conn/s |
| Connection-open latency | 0.198 / 0.396 ms | **0.031 / 0.098 ms** | 0.212 / 0.409 ms |
| Deep-history page rate | 104.7 pages/s | **136.0 pages/s** | 115.6 pages/s |
| Deep-history page latency | 8.53 / 14.42 ms | **7.06** / 9.50 ms | 8.73 / **8.87 ms** |

### Change from the v0.2.0 campaign

| Scenario | Wok WebSocket | Wok Unix | Fixed strfry control |
|---|---:|---:|---:|
| Historical query | +0.3% | **+24.4%** | +0.2% |
| Mixed read/write | +0.5% | **+4.5%** | -0.2% |
| Accepted publication | +4.7% | +7.8% | +8.2% |
| Fanout delivery | -7.1% | -1.5% | -3.9% |
| Connection opens | +6.5% | **+32.4%** | +1.2% |
| Deep-history pages | -13.1% | +19.7% | -32.8% |

The same-host publication improvement is directionally positive on both Wok
transports, but the strfry control moved by a similar amount, so it is weaker
evidence than the two-host result. Unix request/response and connection setup
are the clearest same-host gains. Deep-history remains too short and variable
for a cross-campaign conclusion: the fixed control moved by -32.8% while the
three targets moved in different directions.

Same-host fanout throughput fell for every target, while Wok still led strfry
by 16.2%. Wok WebSocket's median drain improved from 61.25 to 43.23 ms. Unix
drain was 461, 370, and 364 ms across its repetitions, so the median remained
close to the prior campaign's 375.55 ms.

## Resource and import observations

Each resource value is the median of the maximum observed value in each
same-host repetition. Parentheses contain the v0.2.0 campaign value.

| Target | Server max CPU | Server max RSS | Load-client max RSS |
|---|---:|---:|---:|
| Wok WebSocket | 109% (107%) | **478 MiB (632 MiB)** | 285 MiB (282 MiB) |
| Wok Unix | 114% (109%) | 455 MiB (453 MiB) | 165 MiB (166 MiB) |
| strfry WebSocket | 173% (173%) | 292 MiB (292 MiB) | 273 MiB (268 MiB) |

Wok WebSocket's peak server RSS fell about 24.4% while the Unix and strfry
controls were effectively unchanged. Peak CPU was broadly stable. The Wok
import median was 6.60 seconds versus 6.74 seconds in v0.2.0. After import,
Wok occupied 192,483,456 bytes and strfry 163,434,624 bytes.

## Unix shutdown-cleanup finding

After the final successful Unix trial, systemd reported a clean stop and no
process was listening, but `/var/lib/relay-bench/wok/wok.sock` remained as a
stale socket pathname. A connection attempt returned `ECONNREFUSED`, and the
next relay start safely replaced it, so no measured request used an incorrect
listener.

The new shutdown guard records `fstat(listener)` and compares it with
`symlink_metadata(path)`. On the Linux host, a live diagnostic showed:

```text
pathname    dev=2049 inode=1282566
listener_fd dev=9    inode=1370691
```

The listener FD is a socketfs object while the pathname is an ext4 directory
entry, so the device/inode equality can never hold and normal shutdown cannot
unlink the path. This is a cleanup regression in commit `2ea2696`, not a
benchmark correctness failure. After preserving the evidence, the confirmed
stale benchmark socket was removed manually; it contained no recoverable data.

Commit `ca64980` fixed the cleanup after the campaign by recording the temp
pathname's filesystem device/inode immediately before its atomic rename, then
rechecking the final pathname against that identity during shutdown. Focused
regressions verify both that the owned socket is removed and that a replacement
socket is preserved. The measured binary and all benchmark values remain from
`fa9b061`; the fix was not mixed into the campaign.

## Retained evidence and reproduction

The full artifacts are retained at:

- relay, two-host:
  `/opt/relay-bench/campaigns/twohost-full-100k-security-fa9b061`;
- load, two-host:
  `/opt/wok-load/results/twohost-full-100k-security-fa9b061`;
- relay, same-host:
  `/opt/relay-bench/campaigns/transport-full-100k-security-fa9b061`;
- load copy, same-host:
  `/opt/wok-load/results/transport-full-100k-security-fa9b061`.

The successful shakeouts remain under the corresponding
`twohost-shakeout-security-fa9b061` and
`transport-shakeout-security-fa9b061` paths. The relay helper records the
relay host's older source checkout separately as `source_checkout_commit`;
the executed Wok binary is unambiguous from its commit-addressed path and
SHA-256 above.

Reproduce the measured workloads with new campaign IDs:

```bash
CAMPAIGN_ID=twohost-full-100k-fa9b061-rerun \
  BASE_TIMESTAMP=1786731700 EVENTS=100000 REPETITIONS=3 \
  ./scripts/benchmark-campaign.sh

CAMPAIGN_ID=transport-full-100k-fa9b061-rerun \
  BASE_TIMESTAMP=1786731700 EVENTS=100000 REPETITIONS=3 \
  ./scripts/benchmark-transports.sh
```

After collection, both relay services were inactive, TCP ports 7777 and 7778
were closed, and the stale Unix pathname described above was removed.

## Limits

- Three repetitions provide order balancing and medians, not confidence
  intervals or universal capacity claims.
- The new corpus has the same seed, mix, and size as the v0.2.0 workload but a
  fresh base timestamp, so cross-campaign inputs are structurally matched
  rather than byte-identical. The fixed strfry control is the main check on
  environmental movement.
- The benchmark config keeps optional abuse protection, authentication, and
  filter-cost enforcement disabled for continuity with the prior campaigns.
  This measures the hardened default fast path, not the cost of enabling every
  optional defense.
- The same-host transport run makes client and relay share four CPUs. Do not
  combine its capacity values with the two-host results.
- Deep-history and fanout-drain phases remain sensitive to short-run and
  producer-timing variance.
