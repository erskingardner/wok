# Time to EOSE under monitor fan-out — October 20, 2026

Before: `ef4650c` (0.7.0). The req worker scanned a REQ's history, then
blocked until the req monitor caught up and installed the live filter (5 s
timeout), and only then sent EOSE.

After: the REQ lifecycle in [architecture.md](architecture.md#req-lifecycle).
The monitor registers the REQ first. The worker scans, posts `HistoryDone`
without waiting, and the monitor sends EOSE. Each monitor batch applies
subscription changes before its fan-out.

## Method

`crates/wok-compat/tests/eose_latency.rs`, an ignored test that drives an
in-process relay through the public `RelayHandle` API (no transport). The
same file was built against both revisions:

```bash
FANOUT_CONNS=200 FANOUT_SUBS=50 PUBLISH_RATE=400 \
  cargo test --release -p wok-compat --test eose_latency -- --ignored --nocapture
```

- Fan-out: 200 connections, each with 50 live `{"kinds":[1]}`
  subscriptions (10,000 in all, spread over the default 3 req monitors).
  Every stored event fans out to all of them; the frames are drained.
- Load: one connection storing pre-signed kind-1 events at a fixed rate,
  in 10 ms ticks. Each event costs the monitors 10,000 frames.
- Probe: one connection, `{"kinds":[1],"limit":5}`. First 200 sequential
  REQ → EOSE → CLOSE round trips, then 10 bursts of 30 REQs sent at once
  (an app start-up), timed from the burst's first REQ to each EOSE.
- Each probe set runs once on the idle relay, then again after 2 s of load.
- Default config except AUTH and abuse limits off, and
  `max_concurrent_historical_queries = 30` so a burst is not refused.
- Apple M4 Max, 14 cores, 36 GiB, macOS. Revisions alternated, three runs
  each per rate. Other sessions shared the machine.

## Results

Milliseconds. For 200 and 300 events/s, the median of three runs' p90 and
p99. Idle numbers are the same for both revisions (sequential p99 under
0.1 ms, bursts under 0.7 ms) and are omitted.

| Load | Probe | Before p90 | After p90 | Before p99 | After p99 |
| --- | --- | ---: | ---: | ---: | ---: |
| 200 ev/s | sequential | 0.02 | 0.03 | 0.05 | 2.15 |
| 200 ev/s | burst of 30 | 3.51 | 2.74 | 3.82 | 3.04 |
| 300 ev/s | sequential | 0.05 | 0.02 | 5.32 | 2.74 |
| 300 ev/s | burst of 30 | 8.47 | 5.85 | 12.53 | 6.14 |

At 400 events/s (4 million frames a second) the monitors are near
saturation, and runs vary too much for a median to mean much. Each run:

| Run | Probe | Before p50 / p90 / p99 / max | After p50 / p90 / p99 / max |
| --- | --- | --- | --- |
| 1 | sequential | 47 / 239 / 414 / 572 | 2.1 / 27 / 41 / 42 |
| 2 | sequential | 0.16 / 152 / 370 / 503 | 0.04 / 0.10 / 7.3 / 9.0 |
| 3 | sequential | 0.07 / 2,197 / 5,004 / 5,005 | 0.03 / 0.09 / 9.8 / 16 |
| 1 | burst of 30 | 59 / 248 / 447 / 475 | 6.9 / 9.3 / 10 / 10 |
| 2 | burst of 30 | 1.5 / 49 / 94 / 97 | 0.34 / 6.3 / 6.9 / 6.9 |

In "before" run 3 the sequential REQs reached the 5 s handshake timeout:
the worker gave up, sent "live subscription monitor unavailable" and an
EOSE, and that subscription never went live. The probes then took so long
that the load pool (then two minutes' worth, now five) ran out, so that
run's bursts were measured on an idle relay and are left out.

## Reading

- Below saturation the monitor is idle most of the time and both designs
  answer in microseconds. The tails differ by a few milliseconds either way:
  the new design waits for the monitor once, the old one too.
- Near saturation the old worker blocked on the monitor for every REQ, so a
  connection's REQs queued behind each other and behind every other REQ on
  the same worker. One slow monitor batch delayed them all. The new worker
  never waits. An EOSE waits for the monitor batch in progress to finish,
  but not for the fan-out of the batch that carries it.
- The new design also stops the old failure where the 5 s timeout produced
  an EOSE for a subscription that was never live.

These are in-process numbers on one laptop: they show the shape of the
change, not production latency, and exclude transport and client costs.
