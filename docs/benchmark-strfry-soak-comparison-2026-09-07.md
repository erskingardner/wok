# strfry database-growth comparison — September 7, 2026

Both the latest strfry release and upstream development branch reproduced
substantial publication slowdown as the stored event set grew. The effect
also remained when strfry's metadata synchronization was aligned with Wok's.
Wok's decline was larger in this fixture, and it generated more writes per
publication. The results support investigating that extra I/O, but do not
identify a particular index as the cause or establish a language-level ranking.

## Sources and workload

Upstream refs were refreshed from `https://github.com/hoytech/strfry.git`:

| Build | Exact revision |
| --- | --- |
| [strfry 1.1.3](https://github.com/hoytech/strfry/tree/1.1.3) | `16c00df04e264f4d68db5e10a48127f015c7824b` |
| [strfry master](https://github.com/hoytech/strfry/commit/4cd3cf64850caf47dda46c2a2abbbf3525a64d10) | `4cd3cf64850caf47dda46c2a2abbbf3525a64d10` |
| Frozen Wok soak build | `76f9a6ac2f872848f32cf14d5b5d7fbd15051975` |

The development branch and release have different application changes, despite
sharing the database schema and pinned storage dependencies. Both C++ builds
used their normal optimized Makefile build on Debian bookworm, with dynamically
linked LMDB `0.9.24-1`. The unchanged Wok image embeds LMDB 0.9.21.

All comparisons used the original two VMs and frozen `wok-bench` binary.
Limits matched the preceding investigation: relay 3 CPUs / 6 GiB, generator
6 CPUs / 12 GiB, 65,536 file descriptors, and an 8 GiB database map. The strfry
sample configurations changed only database path, bind address, map size, and
`nofiles=0` so Docker controlled the file-descriptor limit. Other native relay
behavior, including event logging and validation, remained enabled.

strfry 1.1.3 replayed all 288 original publication/fanout rounds, retaining the
original seeds and timestamp. Each round published 2,000 measured events plus
50 warm-up events, then 200 events to 32 fanout subscribers. The 512-connection,
five-minute idle phase was replaced by one connection held for zero seconds.
This **14-minute-29-second accelerated replay is not another 24-hour soak**;
its storage duty cycle is different.

All 864 replay trial checks passed. Exporting and fingerprinting the entire
event set confirmed exactly the same 648,000 signed events as the Wok soak,
including content, tags, signatures, and other JSON values. The fingerprint
sorts by event ID and hashes canonical parsed JSON, so storage/export ordering
does not affect the comparison. Both datasets produced:

`2c8bca542a5bc3f27096661d3457c50fffd7cbd90a7081ad578d840bb065ff9a`

The grown strfry database was about 770 MiB. Each subsequent populated trial
used a separate copy of that database; Wok used separate copies of its preserved
v5 soak database. Wok's runtime database was never opened by strfry.

## Unmodified builds

Each case started a fresh relay and published the same 10,000 measured events
over 32 sockets, with 50 sequential warm-up events. Three repetitions per
engine and database state alternated empty/full order and rotated engine order.
These are medians of trials; p99 values are medians of per-trial p99s.

**The stock strfry rows have weaker metadata durability than Wok**, as explained
below. Their absolute throughputs should not be treated as equal-durability
comparisons.

| Build | Empty events/s | Populated events/s | Throughput decline | Empty → populated ACK p99 |
| --- | ---: | ---: | ---: | ---: |
| strfry 1.1.3 | 2,054 | 1,424 | 31% | 21.38 → 33.12 ms |
| strfry master | 2,863 | 1,789 | 38% | 19.28 → 27.66 ms |
| Wok, unchanged | 2,654 | 1,215 | 54% | 22.13 → 57.79 ms |

Median relay-attributed writes from `/proc/<pid>/io`, including warm-up:

| Build | Empty | Populated | Growth factor |
| --- | ---: | ---: | ---: |
| strfry 1.1.3 | 284 MB | 538 MB | 1.89× |
| strfry master | 284 MB | 537 MB | 1.89× |
| Wok | 449 MB | 1,184 MB | 2.64× |

MB is decimal. These counters are not event payload size, database growth,
or physical flash write amplification. Wok's additional search and state
indexes are a material feature difference, but this experiment does not
apportion its extra writes among individual indexes.

In the accelerated strfry replay, first-12 versus last-12 round medians were
1,742 → 1,120 publication events/s, 23.44 → 46.21 ms publication p99, and
7,929 → 6,485 fanout deliveries/s. The restarted comparisons provide stronger
evidence of a database-growth effect than the replay trajectory alone.

## Durability discrepancy and diagnostic control

Both strfry versions pin rasgueadb commit
`cebe0a567ccfa37a493f091e809a452ad3f9422b`. Its generated environment opener
calls:

```cpp
lmdb_env.open(dir.c_str(), MDB_CREATE | flags, 0664);
```

`MDB_CREATE` is a database-handle flag with value `0x40000`. In the environment
API that bit is `MDB_NOMETASYNC`. The
[pinned wrapper](https://github.com/hoytech/rasgueadb/blob/cebe0a567ccfa37a493f091e809a452ad3f9422b/main.h.tt)
therefore enables weaker metadata synchronization. The
[LMDB API contract](https://github.com/LMDB/lmdb/blob/LMDB_0.9.24/libraries/liblmdb/lmdb.h)
allows the last committed transaction to be lost on a system crash with that
flag. This differs from Wok's normal data-and-metadata synchronization;
`crates/wok-db/src/env.rs` explicitly guards against this flag collision.

This was confirmed rather than inferred solely from timings:

- A diagnostic interposer read back `mdb_env_get_flags` after the native open:
  both strfry binaries returned `0x40000`.
- Native traces synchronized data on fd 4, then wrote transaction metadata
  through the same ordinary descriptor, rather than the separate synchronous
  metadata descriptor.
- A second interposer mode cleared only `MDB_NOMETASYNC` at environment open.
  All diagnostic cases reported requested flags `0x40000`, effective flags `0`,
  and actual flags `0`. No transaction, validation, index, or batching code was
  changed. The original binaries and images were retained.

With metadata synchronization enabled, three more empty/full repetitions per
strfry version still showed the slowdown:

| Diagnostic build | Empty events/s | Populated events/s | Throughput decline | Empty → populated ACK p99 |
| --- | ---: | ---: | ---: | ---: |
| strfry 1.1.3, metadata sync enabled | 1,914 | 1,278 | 33% | 21.34 → 33.95 ms |
| strfry master, metadata sync enabled | 2,650 | 1,619 | 39% | 18.66 → 31.42 ms |

These controls establish that the database-growth effect remains with the
durability flag corrected. They do not precisely measure the cost of that flag:
native and corrected cases ran in separate phases, and VM variability was
substantial. For example, native release empty-database throughput ranged from
1,990 to 2,951 events/s. Every matched empty/full repetition, in both phases,
was slower with the populated database.

Syscall traces independently found approximately 269 → 519 MB of database
writes and 52,725 → 119,105 write calls in the native empty/full cases, with
643 and 640 data synchronizations respectively. This supports increased write
volume and fragmentation of writes as the database grows. Tracing substantially
perturbs execution, so traced throughput is excluded from the comparison tables.
The corrected-mode trace additionally verifies writes through the synchronous
metadata descriptor. These observations do not substitute for power-failure tests.

## Shutdown finding and validation

The replay exposed a separate strfry 1.1.3 shutdown edge case. `SIGUSR1` with
zero WebSocket connections stopped listening but did not exit. The source calls
`exit(0)` when the last connection disconnects during graceful shutdown, without
handling the already-empty case. Docker killed that replay process after its
30-second timeout; it was not OOM-killed. The full exported event fingerprint
passed afterward. Process termination is not a test of power-loss durability.

For subsequent trials, a control WebSocket was opened **after** all timing and
I/O measurements, `SIGUSR1` was sent, and the socket was closed after the relay
logged that graceful shutdown had started. All 33 subsequent relay/load trials
exited 0 without OOM kills. Their publication checks all passed: 30 untraced
trials and three traced diagnostic trials, with 330,000 measured publications.
An earlier setup-only startup failure from the release's default million-file
limit was corrected to the intended `nofiles=0` before any workload ran.

Final exports from Wok, both native strfry builds, and both corrected-durability
variants matched exactly at 658,050 events per populated case. Wok's full
offline integrity check also passed. strfry's export comparison does not audit
every secondary index. Both original source database files were verified
unchanged by SHA-256. Trial containers were left stopped; artifacts were retained.

## Evidence and reproduction

[`benchmark-strfry-soak-comparison-2026-09-07.json`](benchmark-strfry-soak-comparison-2026-09-07.json)
contains every comparison trial, resource deltas, replay trajectory, exact
revisions/binary hashes, flag probes, diagnostic source, and export verification.
Full scripts and logs remain in `bench-results/lab/strfry-slowdown-20260907/`;
large signed corpora, exports, images, and database copies also remain on the VMs.

Use a fresh database directory for every case, preserving the source fixtures:

```bash
wok-bench --scenario ws_publish_scaled \
  --target-url ws://RELAY_IP:7777 --target-label CASE \
  --events 10000 --publish-connections 32 --event-mix realistic \
  --seed 920260907 --base-timestamp 1788764100 --out /results/CASE
```

For a later campaign, choose one timestamp within both relays' acceptance
windows and keep it fixed across cases. Replay inputs and the Docker build,
configuration, comparison, shutdown-control, and fingerprint scripts are retained
with the raw evidence. No Wok runtime code or configuration was changed, and
neither strfry finding was patched or published upstream by this investigation.
