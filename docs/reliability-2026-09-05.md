# Reliability validation — 2026-09-05

The initial one-hour Linux container soak passed. The final code commit
`d10321861ac43ec27206ee96661f6b17ee88bc61` also passed the expanded CI gates,
including native behavior on all four distribution platforms and mandatory
migration from the pinned C++ reference. This is evidence for the specific
contracts and workload below, not a claim that the relay is bug-free.

## Bugs exposed by the added tests

- **SIGTERM bypassed graceful shutdown.** The new CLI subprocess regression
  failed with signal 15 before the fix. SIGTERM now uses the normal shutdown
  path; the test checks successful exit, socket cleanup, and persisted data
  after an acknowledged publication with a connection still open.
- **Real strfry migration omitted Wok extension tables.** A database created by
  strfry exposed a gap hidden by synthetic fixtures: the promoted v5 database
  lacked its state table. Migration now creates extension tables only in the
  private staging copy and verifies integrity before promotion. The regression
  checks source data/config bytes, event fingerprints, full JSON, and read-only
  target integrity, so opening for writing cannot silently repair the test result.

Early canary failures also corrected fixture assumptions: full snapshots needed
sufficient outbound-queue capacity and both per-filter and per-request limits
appropriate to the dataset. Pressure uses separate slow subscriptions. Hosted
fixtures now use `nofiles = 0`
to retain inherited limits instead of requesting 524,288 descriptors on runners
whose hard limit is 65,536. These were harness configuration failures, distinct
from the two runtime bugs above.

## Test and CI evidence

| Check | Result |
| --- | --- |
| Local `WOK_REQUIRE_STRFRY=1 cargo test --workspace --locked` | 360 passed, 0 failed, 1 ignored manual timing diagnostic |
| Formatting, Clippy with warnings denied, Rust 1.85 all-target compilation | Passed locally and in CI |
| [CI, including pinned strfry migration](https://github.com/erskingardner/wok/actions/runs/33973995562) | Passed at `d103218` |
| [Native Linux x86-64/ARM64 and macOS Intel/Apple Silicon](https://github.com/erskingardner/wok/actions/runs/33973995577) | All four passed at `d103218` |
| [Seeded AddressSanitizer ingress fuzz smoke](https://github.com/erskingardner/wok/actions/runs/33973995622) | 10,000 iterations passed at `d103218`; also passed locally |
| [Linux x86-64 hosted canary](https://github.com/erskingardner/wok/actions/runs/33973995583) | 181.1 seconds, 7,128 mixed receipts, 28,512 exact live deliveries, restart and integrity passed |
| [Dependency policy](https://github.com/erskingardner/wok/actions/runs/33973102736) | Passed at `c89d082`; dependencies unchanged in subsequent fixture commits |

The generated suite runs four seeded 40-operation sequences across both real
transports and ten in-flight sync revocation cases. Its independent model
checks exact history, live events, COUNT, and reconciled ID sets through AUTH,
reconnects, replacement, deletion, moderation, and expiration. Separate tests
reject stale AUTH proofs. The C++ job requires the binary rather than accepting
local optional skips; a deliberately missing-reference test was also confirmed
to fail. See [the validation guide](reliability.md) for contracts and commands.

## One-hour soak

The relay and driver ran as separate release processes in an isolated local
Linux ARM64 Docker container: Linux 7.0.12-linuxkit, Rust 1.96.1/bookworm, four
CPU equivalents, 4 GiB memory, and no swap. No host ports were published. The
container shares a macOS host; this is not a bare-metal capacity benchmark.
Normal synchronous LMDB durability was enabled. The driver used seed 4242,
20,000 initial events, eight publisher connections, four fast subscribers, two
slow subscribers, and both WebSocket and Unix sockets. It maintained a bounded
durable set while publishing, replacing, deleting, querying, syncing, and
reconnecting. Separate 512 KiB ephemeral bursts pressured slow subscribers.

| Measurement / assertion | Observed |
| --- | --- |
| Mixed workload duration | 3600.892 seconds |
| Successful mixed-event receipts | 143,168 |
| Additional ephemeral pressure receipts | 3,840 |
| Exact fast-subscriber deliveries | 572,672 |
| Final stored events | 20,324 |
| Negentropy reconciliation rounds | 480 |
| Observed slow-reader closures | 118 |
| Midpoint graceful restart / exact retained history | Passed |
| Midpoint and final offline integrity | Passed, no reported issues |
| Sampled peak relay RSS | 164.96 MiB (budget 768 MiB) |
| Sampled peak anonymous memory | 129.90 MiB |
| Post-warmup anonymous growth, process 1 / 2 | 15.67 MiB / 14.38 MiB (budget 64 MiB each) |
| Final sampled database size | 28.96 MiB (budget 512 MiB) |
| Sampled maximum active connections / threads | 15 / 20 |
| Sampled relay CPU time, both lifetimes | 147.16 CPU seconds |
| ACK latency p50 / p99 / maximum | 5.791 / 16.127 / 112.511 ms |
| Full-history latency p99 / maximum | 323.327 / 375.551 ms |

The 20,000-event preload is additional to the mixed receipt count. ACK latency
includes pressure events but excludes preload; history timings cover full
snapshots, not COUNT or sync. CPU and memory are sampled every five seconds,
so peaks may miss short spikes and CPU totals omit unsampled tails. The hosted
three-minute canary passes absolute budgets but is too short for eligible
post-warmup growth windows around its midpoint restart.

The hour used runtime/driver source at `c89d082`; subsequent `c40a7f2` and
`d103218` changes only made test fixture file limits and startup diagnostics
portable. Its captured config therefore retains the earlier 524,288 file-limit
request, permitted by this container. The hosted canary exercises the final
`nofiles = 0` fixture. Binary, driver, configuration, initial corpus, image, and
archive hashes are in [the machine-readable summary](reliability-2026-09-05.json).

Raw local evidence is retained in `bench-results/reliability-2026-09-05/`, including
`hour-1.tar.gz`, signed initial corpus, resource samples, raw metrics, process
logs, database, integrity output, local checks, and downloaded CI artifacts.
The raw hour archive SHA-256 is `cf357b1fa858049a12e1a11627fa31e13cdd702cc367de31c21afe5c47597ae3`.
Hosted soak artifacts have 30-day retention; the local copy preserves this run beyond that window.

## Limits

The workload is deliberately paced at roughly one mixed round per second.
Latency is descriptive, not a regression threshold or a Wok/strfry comparison.
It verifies periodic multi-round sync; it does not cover a continuously active
multi-hour private sync, saturation, hostile multi-host networking, filesystem
failure, or power loss. The separate privacy suite exercises restricted reads;
this public soak alone does not establish privacy correctness. The initial
corpus is retained, but the entire clock-dependent mixed event stream is not a
byte-for-byte replay artifact. Longer campaigns and production observation
remain useful alongside the stronger CI gates.
