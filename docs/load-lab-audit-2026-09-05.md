# Local load-lab audit — September 5, 2026

Running the lab at larger scales and across the relay's WebSocket heartbeat
window exposed three load-generator defects. Repeating the workspace suite also
exposed a lifecycle-test ordering race. Each has a regression that failed before
its fix and passed afterward. No relay data-loss or integrity defect was
reproduced in these campaigns.

## Fixes and commits

| Commit | Finding and correction |
| --- | --- |
| `4afcc51` | Idle WebSocket clients slept without reading or answering pings. Each client now services the socket throughout setup and the hold, then checks responsiveness before closing. Unix clients retain their cancellation-safe framed-read behavior. |
| `ac7a47b` | Fanout subscribers did not read until all publication finished. Readers now run concurrently with publication, request no historical events, and verify unique IDs and exact payloads using shared expectations and a per-subscriber bitmap. The receive timeout measures inactivity. |
| `be2337d` | Failed benchmark trials were recorded in reports but the process exited successfully. Failed trials now produce a nonzero exit status after preserving all reports. |
| `254590a` | The generated lifecycle test assumed `NEG-CLOSE` had completed before later history queries. It now probes the closed handle through the negentropy worker and consumes any pending visibility revocation before proceeding. Other unexpected replies still fail. |

The fanout histogram now uses the same aggregate publication/delivery interval
as throughput. It contains one duration sample per trial; it does not measure
per-event delivery percentiles. Older fanout histogram values measured only the
drain after publication and are not comparable.

The heartbeat regression uses a real WebSocket peer requiring pongs during the
hold. The fanout regression withholds the publisher acknowledgement until a
subscriber answers a ping, proving that subscriber reads progress concurrently.
The exit-status regression launches the actual CLI with missing relay binaries
and checks both unsuccessful status and retained reports. A scripted peer makes
the lifecycle revocation/close ordering deterministic.

## Campaign results

These are local Docker Desktop Linux arm64 runs, with **2 CPUs and 2 GiB per
container**, no swap, normal LMDB synchronous durability, fresh per-campaign
databases, and admission limiting disabled by the lab fixture. Builds, native
tests, and some campaigns overlapped on the shared host. They establish bounded
workload correctness, not production capacity or a controlled speed comparison.

| Run ID | Workload | Result |
| --- | --- | --- |
| `audit-medium` | Three rounds: 20,000 publications / 64 publishers; 500 events × 64 subscribers; 2,000 idle connections held 5 s | All 9 trials passed |
| `audit-large` | 100,000 publications / 128 publishers; 1,000 events × 128 subscribers; 10,000 idle connections held 15 s | All 3 trials passed |
| `audit-idle-before` | 8 connections held 120 s with the original client | Expected failure; all 8 relay connections terminated for missed pongs |
| `audit-idle-after` | Same 8-connection, 120 s hold after the heartbeat fix | All 3 trials passed |
| `audit-fanout-before` | 50,000 events × 8 subscribers with sequential draining | All 3 trials passed |
| `audit-fanout-after` | Same fanout workload with concurrent readers | All 3 trials passed; fanout ran about 232 s without an inactivity timeout |
| `audit-final` | 20,000 publications / 64 publishers; 5,000 events × 64 subscribers; 2,000 idle connections held 120 s | All 3 trials passed |
| `audit-unix` | Native debug build; realistic and lifecycle mixes, each with 500 publications / 8 publishers, 200 events × 8 subscribers, and 128 connections held 2 s | All 6 trials passed; correctness only |

Every successful campaign also passed graceful relay shutdown and offline
database integrity checks. The final Docker run used the complete generator
fixes at `be2337d`; the later lifecycle correction affects tests only. Earlier
campaigns include dirty worktrees while reproducing/fixing defects: use the
recorded source hashes rather than treating their base revision as exact source.

The fanout controls sampled peak relay container memory at **374.1 MiB before**
and **13.97 MiB after**; generator peaks were 94.94 and 91.14 MiB. This is
consistent with promptly draining subscriber queues. These Docker samples are
neither allocator measurements nor exhaustive peaks. Fanout throughput was
**2,803 deliveries/s before and 1,726 after** in these noisy runs, so they do
not demonstrate a speedup. Repeat on isolated hosts before ranking throughput.
The old generator's 50,000-event control passed; only the deterministic peer
regression proves its inability to service subscribers during publication.

The final campaign sampled peaks of 55.13 MiB for the relay and 276.9 MiB for
the generator. The 10,000-connection campaign peaked around 222 MiB and
1,330 MiB respectively. The load generator's own memory and CPU budget need
monitoring when scaling to many more connections.

## Validation and reproduction

Final workspace validation: **365 passed, 0 failed, 1 deliberately ignored**
manual Nagle timing diagnostic. C++ differentials were required with
`WOK_REQUIRE_STRFRY=1`. Strict workspace Clippy, formatting, and all five Python
lab tests passed. The lifecycle model was additionally repeated three times
after its deterministic regression and full focused suite passed.

```bash
WOK_REQUIRE_STRFRY=1 cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all --check
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/tests -v

LAB_EVENTS=20000 LAB_PUBLISHERS=64 LAB_SUBSCRIBERS=64 \
LAB_FANOUT_EVENTS=5000 LAB_CONNECTIONS=2000 LAB_HOLD_SECONDS=120 \
LAB_RELAY_PORT=7778 LAB_DEADLINE_SECONDS=600 \
python3 scripts/lab.py local --run-id audit-final-repeat
```

Use a fresh run ID for each campaign. Compact Docker results, source hashes,
settings, and sampled memory peaks are checked in as
[`load-lab-audit-2026-09-05.json`](load-lab-audit-2026-09-05.json).
Full local artifacts remain under `bench-results/lab/<run-id>/`: manifests,
corpora, trial reports, image/config/source hashes, resource samples, relay logs,
metrics, shutdown state, and integrity output. Regression failure/success logs
are retained under `bench-results/lab/audit-regressions/`. Lab containers have
been removed; their named database/results volumes remain available for inspection.

This work did not run a new multi-hour soak, independent Linux VMs, packet-loss
campaign, production deployment, or remote CI. Those remain separate evidence
requirements. The corrected generator is ready for a controlled two-VM campaign
using the [load-lab instructions](load-lab.md).
