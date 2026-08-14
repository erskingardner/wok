# WebSocket publication optimization, 2026-08-14

This focused follow-up investigated the publication gap in the
[v0.2.0 benchmark campaign](benchmark-v0.2.0-2026-08-14.md). It did not rerun
the full campaign. The final candidate improves the two-host WebSocket
publication workload by 22–24% in two order-balanced comparisons while also
reducing acknowledgement latency and relay CPU time.

## Bottleneck and changes

A local CPU sample of the original writer found 5,778 of its 6,241 active
samples (92.6%) below LMDB transaction commit in `mdb_env_sync`. That made the
single-writer path the first target, but a deliberately delayed batching
experiment proved workload-dependent: it helped the local APFS run and hurt
the Linux VM. The delay was removed before the final measurements below.

The retained changes avoid work without adding a batching wait:

- move parsed EVENT and filter values out of their JSON envelopes instead of
  cloning nested values;
- hash and normalize authenticated event JSON without constructing cloned
  `serde_json::Value` trees;
- decode fixed-size IDs, public keys, signatures, and indexed tags directly
  into fixed arrays;
- read WebSocket bytes directly into the parser's retained buffer, reuse its
  event vector, and mask in four-byte chunks instead of using a modulo per
  byte;
- share each connection's source address and avoid cloning the full live
  configuration for every inbound command;
- retain writer scratch buffers, skip NIP-62 JSON inspection for non-vanish
  kinds, and update the retained negentropy cache in the existing write
  transaction without cloning each packed event into a deferred buffer.

An outbound WebSocket write-coalescing experiment was also removed: repeated
local fanout trials were neutral, so it was not included as an improvement.

## Focused two-host result

The load generator and relay used the existing isolated private network. Each
trial started with an empty Wok database and published 20,000 deterministic
realistic events over 128 WebSocket connections. Both binaries were built
with Rust 1.96.1 and the same release settings. Trial order was reversed in
the second pair.

- control source: `7a195ba`, rebuilt binary SHA-256
  `c4f920112e26dea1644997698bb54fd605b4f68429958507114dc57e7fd4b628`;
- candidate source: `175aa38`, tree
  `9a61cda72a1ea089682aa73ab5135e8d9b22ae8c`;
- measured candidate binary SHA-256
  `f03769c4942fb103f6a52f5a69bbeae1de5fa3cc4f288b72b11556e3101db844`.

The measured binary came from the tree-identical pre-cleanup commit
`3e6a28e`; the three final commits only reorganize that exact tree into
bisectable changes.

| Pair | First target | Control events/s | Candidate events/s | Throughput change | Control p50 | Candidate p50 | Relay CPU change |
|---|---|---:|---:|---:|---:|---:|---:|
| A | candidate | 4,718.9 | 5,831.8 | +23.6% | 27.87 ms | 22.16 ms | -12.5% |
| B | control | 5,243.4 | 6,403.2 | +22.1% | 22.69 ms | 19.61 ms | -10.6% |
| Median | — | 4,981.2 | 6,117.5 | +22.8% | 25.28 ms | 20.89 ms | -11.6% |

All 80,000 publications were accepted with zero errors or mismatches. A
separate 5,000-event `perf stat` diagnostic counted 213 `fdatasync` calls for
both source trees. The final speedup therefore comes from doing less CPU and
allocation work around the existing naturally formed write batches, not from
weakening durability or delaying commits.

## Validation and retained evidence

Local validation covered the event, database, negentropy, relay, WebSocket,
and Unix crates plus all cross-transport compatibility tests. The final full
workspace test command was:

```bash
cargo test --workspace
```

The focused Linux results remain on the load host under:

```text
/opt/wok-load/results/ws-perf-3e6a28e/finalab/
```

The rebuilt control and measured candidate binaries remain in their unique
relay artifact paths. The archived v0.2.0 binary was never overwritten. After
collection, the baseline services and all transient measurement units were
inactive.

These are two focused paired trials, not a replacement for the full campaign.
Before a release, rerun the publication phase with at least three
order-rotated repetitions and retain the normal campaign server artifacts.
