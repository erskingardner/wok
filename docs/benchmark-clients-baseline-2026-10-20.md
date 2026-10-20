# Client-realistic baseline at default limits — October 20, 2026

This is the first measurement of Wok's default limits with abuse controls and
AUTH on, under traffic shaped like real clients. It is step 0 of the
[configuration presets proposal](config-presets-proposal.md)
(PR [#89](https://github.com/erskingardner/wok/pull/89))
(§6). The proposal's later steps change defaults and will be measured against
these numbers. Per-trial reports, with every class row and refusal row, are in
the [JSON companion](benchmark-clients-baseline-2026-10-20.json).

Every trial was correct:
- histories matched the oracle;
- no restricted event leaked;
- every live subscription received every event published after its EOSE;
- every NIP-77 pass reported exactly the missing IDs.

What the defaults refuse:
- **The cost gate.** Each outbox client loses three ordinary requests to it.
- **The 64 KiB filter cap.** Clients with large follow lists lose their home
  feed and metadata.
- **Silent cuts at 500 events.** Directory batches and outbox metadata are cut
  with no signal.
- **Marmot clients in 50 or more groups.** They lose most of their group
  subscriptions, NIP-77 passes, and every follow-up `ids` fetch.
- **Large add-member bursts.** A 250-member burst needs 1,579 retries and
  4.3 s.
- **Shared addresses.** Four clients behind one address lose nearly half of
  their subscriptions (487 of 1,067 to the REQ budget).

## Setup

- **Host:** Apple M4 Max (10 performance + 4 efficiency cores), 36 GiB RAM,
  macOS 26.6.2.
- **Topology:** relay and load generator on the same host, over loopback.
  These are shapes and ratios, not production numbers.
- **Build:** source `ef4650c` (0.7.0) plus this scenario, release profile (thin
  LTO), rustc 1.99.0.
- **Relay config:** built-in defaults. The bench changed two keys:
  - `relay.real_ip_header = "x-forwarded-for"`, so each simulated client has
    its own address;
  - `relay.auth.service_url = ws://127.0.0.1:<port>`, so NIP-42 can complete.
- **Run E:** the same, plus `[relay.abuse] enabled = false`.
- **Dataset, per trial:**
  - 100,000 background events (`--event-mix realistic`, seed 1);
  - the scenario corpus of 30,105 (A, D, E), 31,705 (B) or 33,705 (C) events,
    which holds a 2,500-author outbox universe, a 254-user Marmot directory
    and 40 events per group.
- **Load, per trial:**
  - 20 outbox clients with 30 subscriptions each, follow lists log-uniform
    from 100 to 2,000;
  - 4 Marmot clients, each with a receive, directory and publish connection;
  - 20 background publications/s;
  - 15 s of activity plus a 2 s drain;
  - 36 connections, all of which negotiated permessage-deflate.

| Run | Marmot groups (G) / invitees (N) | Variant | Repetitions |
|---|---|---|---:|
| A | 10 / 10 | defaults | 3 |
| B | 50 / 100 | defaults | 2 |
| C | 100 / 250 | defaults | 2 |
| D | 10 / 10 | 4 clients per address (CGNAT) | 1 |
| E | 10 / 10 | abuse controls off | 1 |

## Refusals by reason

Counts are per trial. A range means repetitions differed. Silent truncation is
not a refusal and is counted separately below.

| Refusal | Setting | A | B | C | D | E |
|---|---|---:|---:|---:|---:|---:|
| `rate-limited: EVENT budget exhausted` | `relay.abuse.event_rate_per_second / event_burst` | 0 | 0 | 1,579–1,580 | 0 | 0 |
| `rate-limited: REQ budget exhausted` | `relay.abuse.req_rate_per_second / req_burst` | 0 | 189–193 | 391 | 462 | 0 |
| `rate-limited: NEG-OPEN budget exhausted` | `relay.abuse.req_rate_per_second / req_burst` | 0 | 127–128 | 328 | 25 | 0 |
| `rate-limited: estimated query cost N exceeds N` | `relay.abuse.max_query_cost` | 60 | 60 | 60 | 14 | 0 |
| `error: bad req: filters exceed N serialized bytes` | `relay.max_req_filter_size` | 12–15 | 12–15 | 12–15 | 10 | 15 |
| **Total** | | 72–75 | 392 | 2,371–2,373 | 511 | 15 |

These limits were never hit:
- `max_concurrent_historical_queries` (8);
- `max_subs_per_connection`;
- the connection budget;
- the per-author EVENT budget.

The scenario sends no COUNT.

Every DM subscription needed one NIP-42 round trip (`auth-required:`, AUTH,
then the same REQ again). That came to 40 per trial, and only 20 in D.

## Which subscriptions are refused

Each cell is sent → refused, from the first repetition. "Cut" counts histories
that came back short with no refusal.

| Class | Shape | A | B | C | D |
|---|---|---:|---:|---:|---:|
| `w4.reaction_batch` | 45 × `{"#e":[id],"kinds":[7]}` (cost 1,125) | 20 → 20 | 20 → 20 | 20 → 20 | 20 → 20 |
| `w3.global_kinds` | 11-kind feed, `limit` 50 (cost 1,100) | 20 → 20 | 20 → 20 | 20 → 20 | 20 → 20 |
| `w3.authors_no_kinds` | `{"authors":[150],"limit":20}` (cost 1,500) | 20 → 20 | 20 → 20 | 20 → 20 | 20 → 20 |
| `w2.metadata` | `authors[follows] × kinds[0,3,10002,10050]` | 20 → 5, 11 cut | 20 → 5, 11 cut | 20 → 5, 11 cut | 20 → 12, 6 cut |
| `live.home_feed` | `authors[follows] × kinds[1,6]`, `limit` 100 | 20 → 5 | 20 → 5 | 20 → 5 | 20 → 13 |
| `marmot.directory` | 200 authors × 4 kinds, `limit` 800 | 8 → 0, 8 cut | 8 → 0, 8 cut | 8 → 0, 8 cut | 8 → 0, 8 cut |
| `marmot.group_live` | `{"kinds":[445],"#h":[gid]}` | 40 → 0 | 200 → 124 | 400 → 324 | 40 → 25 |
| `marmot.neg` | NEG-OPEN on the same filter | 40 → 0 | 200 → 128 | 400 → 328 | 40 → 25 |
| `marmot.ids_fetch` | `ids` ≤ 64 after each NIP-77 pass | 40 → 0 | 65 → 65 | 67 → 67 | 15 → 15 |
| `live.dm_nip04`, `live.dm_giftwrap` | `{"kinds":[4 or 1059],"#p":[me]}` | 40 → 0 | 40 → 0 | 40 → 0 | 40 → 40 |
| `publish.marmot_welcome` | 1059 gift wraps of one burst | 40 → 0 | 400 → 0 | 1,000 → 1,579 attempts | 40 → 0 |

- **C4, query cost.** Each of the three cost-refused shapes is ordinary client
  traffic, and the gate refuses it for every client. With abuse off (E) all
  three succeed.
- **C5, filter bytes.** The 4–5 clients with more than about 978 follows lose
  their home feed, outbox metadata and feed page. This cap is not part of
  `[relay.abuse]`, so it applies in E too.
- **C1, silent truncation.** `max_filter_limit = 500` cuts every directory
  batch (500 of 800 requested). It also cuts outbox metadata for 11 of 20
  clients: they get 500 of the 506–2,549 events that match. Nothing tells the
  client.
- **Marmot at G = 10 fits.** One AUTHed receive connection sends 21 REQs and
  NEG-OPENs, plus the `ids` fetches; the directory connection on the same
  address adds 2. That stays inside the 40-token burst.
- **Marmot at G = 50 and G = 100 does not fit.**
  - 62–64% (G = 50) and 81–82% (G = 100) of group subscriptions and NIP-77
    passes are refused.
  - Every `ids` fetch that follows a completed pass is refused too, so even
    the passes that ran do not finish the backfill.
  - The AUTHed connection pays both the per-address and the per-pubkey REQ
    bucket (F1).
- **Add-member bursts.**
  - N = 10 completes in 40 ms and N = 100 in 176 ms.
  - N = 250 exceeds `event_burst = 100`. The 1,000 Welcomes of four bursts
    land only after 1,579 `rate-limited:` refusals and MDK-style retries, and
    each burst takes 4.3 s.
  - In an exploratory run at G = 100, N = 250 with abuse off, the same bursts
    took about 0.5 s.
- **CGNAT (D).**
  - With four clients per address, the REQ budget refuses 462 REQs and 25
    NEG-OPENs across every class. That includes 16% of replacements and 70%
    of thread fetches.
  - All 40 DM subscriptions are refused with `rate-limited:` before they
    reach the AUTH gate, so those clients never learn that AUTH would help.
    This is why D has only 20 NIP-42 round trips.

## Latency

These are times to EOSE across every REQ class (median of repetitions). The
p50 includes each client's 30-REQ startup burst.

| | A | B | C | D | E (abuse off) |
|---|---:|---:|---:|---:|---:|
| EOSE p50 ms | 46.9 | 46.5 | 53.6 | 11.8 | 57.5 |
| EOSE p99 ms | 107.5 | 112.8 | 110.8 | 58.9 | 113.5 |

Selected classes, as time to EOSE (p50 / p99 ms). For `delivery.*`, the time
is from publication to receipt.

| Class | A | C | E |
|---|---:|---:|---:|
| `w2.metadata` | 57.9 / 98.4 | 60.8 / 102.4 | 60.4 / 97.4 |
| `live.home_feed` | 59.3 / 101.1 | 65.8 / 106.0 | 62.1 / 97.6 |
| `w6.scroll_replace` | 17.0 / 100.3 | 11.8 / 105.7 | 14.2 / 111.7 |
| `marmot.group_live` | 76.4 / 92.5 | 89.1 / 94.8 | 89.9 / 104.7 |
| `marmot.neg` (pass complete) | 4.7 / 9.4 | 8.3 / 11.9 | 5.7 / 10.7 |
| `marmot.directory` | 33.0 / 45.1 | 32.2 / 49.0 | 29.6 / 40.7 |
| `delivery.outbox` | 8.5 / 11.1 | 8.7 / 152.0 | 8.1 / 14.1 |
| `delivery.marmot` | 10.9 / 37.9 | 13.6 / 164.0 | 11.1 / 26.2 |

- **Abuse on vs off.** With abuse controls on, the requests that are admitted
  are no slower than with them off: A's EOSE p99 is 107.5 ms and E's is
  113.5 ms. A also runs fewer queries, because the gate refuses 60 of them.
- **D's low latency is not a gain.** D looks fastest only because much of its
  load was refused.
- **Bursts and live delivery.** C's large bursts write about 100 MB of gift
  wraps. While they are written, publication OKs and live delivery rise to a
  p99 of about 150 ms.

## Other findings

- **NIP-77 memory reservations.**
  - A memory-view NEG-OPEN without a `limit` reserves
    `min(max_sync_events + 1, stored events + 1) × 256 B`.
  - In an exploratory abuse-off run with 100 groups and no `limit`, 156 of 400
    NEG-OPENs were refused with `blocked: synchronization memory budget
    exceeded`. That database held 35,000 events, so each session reserved
    about 9 MB.
  - On a database of a million events or more, one such session reserves
    256 MiB, the whole `sync_memory_per_connection`.
  - MDK's `limit: 16385` caps the reservation at about 4 MiB. The scenario
    sends that limit, so the runs above do not hit this budget.
  - The proposal keeps these settings unchanged (§2.6). This needs a decision
    there.
- **Events before EOSE can exceed `limit`.** Events committed while a history
  scan runs reach the subscription just before EOSE, through the monitor's
  catch-up. A REQ can therefore receive more than `limit` EVENTs before EOSE.
  This is by design. The scenario's oracle bounds only the stored part of a
  history by `limit`.
- **The REQ budget runs before the read gate.** Under a shared address,
  restricted subscriptions are refused with `rate-limited:` rather than
  `auth-required:`. The AUTH that would admit them is never prompted.

## What this does not cover

- **MDK is modelled, not run.** The proposal asks for real MDK (§6).
  - Commit and Welcome payloads are random base64 sized from group size.
    The largest were 533,752 B and 98,041 B (C).
  - Real Welcome sizes, which set the marmot preset's `max_event_size`, still
    need an MDK run.
- **Refused REQs are never retried.** Simulated clients do not retry a refused
  REQ. Marmot publications retry `rate-limited:` and authenticate after
  `auth-required:`. A client that retries REQs would turn some refusals into
  latency.
- **Not run yet:**
  - the adversarial runs from §6;
  - IPv6 /64 grouping;
  - colder or larger databases. The concurrency cap may bite there.

## Reproduction

```bash
cargo build --release -p wok-cli -p wok-bench
COMMON=(--scenario clients --wok ./target/release/wok --events 100000
  --event-mix realistic --clients 20 --marmot-clients 4
  --clients-duration-secs 15 --seed 1 --base-timestamp 1792491335)
./target/release/wok-bench $COMMON --marmot-groups 10 --marmot-invitees 10 --repetitions 3 --out results/A
./target/release/wok-bench $COMMON --marmot-groups 50 --marmot-invitees 100 --repetitions 2 --out results/B
./target/release/wok-bench $COMMON --marmot-groups 100 --marmot-invitees 250 --repetitions 2 --out results/C
./target/release/wok-bench $COMMON --marmot-groups 10 --marmot-invitees 10 --clients-per-address 4 --out results/D
printf '[relay.abuse]\nenabled = false\n' > abuse-off.toml
./target/release/wok-bench $COMMON --marmot-groups 10 --marmot-invitees 10 --relay-config abuse-off.toml --out results/E
```

The scenario is described in [benchmarks.md](benchmarks.md#client-realistic-scenario-clients).
