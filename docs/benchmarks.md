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
The command exits unsuccessfully if any trial fails or records errors/mismatches,
after writing the reports; a failed campaign still retains diagnostic artifacts.
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
already been imported into the target relay; they verify parsed EOSE/subscription envelopes, exact expected historical
sets, publication IDs/boolean acceptance, and complete per-subscriber deliveries.
Local publication trials also export and compare the final stored state, including
replacement, deletion and ephemeral semantics; remote storage is explicitly not inspected.

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

## Client-realistic scenario (`clients`)

Every scenario above runs with `[relay.abuse]` and `[relay.auth]` disabled and
sends one REQ at a time, so none of them can say whether a default limit
refuses real clients. Wok-only `--scenario clients` keeps both on. It models
the client traffic shapes W1–W10 that the limits plan cites
([#97](https://github.com/erskingardner/wok/issues/97)):

- **Outbox clients.** Each opens 30 subscriptions at once on connect:
  - 15 fetch-and-close (REQ → EOSE → CLOSE): `authors[follows] ×
    kinds[0,3,10002,10050]` metadata, profile and relay-list lookups, `ids`,
    threads, a 45-filter `#e` reaction batch, notification and feed pages, an
    11-kind global feed, an authors-only feed and long-form;
  - 5 re-REQed with the same ID every `--replace-interval-ms` (scrolling
    pages and profile rotation);
  - 10 live: home feed, notifications, NIP-04 and NIP-17 DM inboxes, own
    replaceables, zaps, three open threads and a hashtag.

  Follow lists are log-uniform from 100 to `--max-follows`. Clients AUTH when
  a DM subscription is answered `auth-required:` and then send it again.
- **Marmot clients**, modelled on MDK:
  - an AUTHed receive connection with a `{"kinds":[1059],"#p":[me]}` inbox;
  - per group, a live `{"kinds":[445],"#h":[gid]}` and a NIP-77 pass on the
    same filter (MDK's `limit` 16,385), then `ids` fetches of at most 64 for
    what the pass reports missing;
  - an anonymous directory connection with two batches of
    `{"authors":[200],"kinds":[0,10002,10050,30443],"limit":800}`;
  - an anonymous publish connection that sends one add-member burst: a 445
    commit plus one 1059 gift wrap per invitee, from throwaway keys, sized
    like an Add commit and a Welcome for that group. As MDK does, it retries
    `rate-limited:` publications with backoff and authenticates after
    `auth-required:`.
- **Background publishing** over four connections: popular authors' notes,
  replies to watched threads, reactions to clients' notes, and 445s into the
  groups.

Each simulated client sends from its own address through `X-Forwarded-For`,
and the trial config sets `relay.real_ip_header` to that header. Connections
negotiate permessage-deflate through wok-ws's codec in client mode. The
scenario imports the `--events` background corpus plus its own deterministic
corpus (about 30,000 events at the defaults) before it starts the relay.

### Options

| Option | Default | Meaning |
|---|---:|---|
| `--relay-config <wok.toml>` | built-in defaults | Relay file to run. Abuse controls and AUTH stay as it sets them. The trial replaces only the database path, bind address and port, the Unix socket, the real-IP header and, when it is empty, `relay.auth.service_url`; the report lists each override |
| `--clients` | 20 | Outbox clients |
| `--max-follows` | 2,000 | Largest outbox follow list |
| `--marmot-clients` | 4 | Marmot clients (three connections each) |
| `--marmot-groups` | 10 | Groups per Marmot client |
| `--marmot-invitees` | 10 | Gift wraps per add-member burst |
| `--clients-duration-secs` | 15 | Activity before a 2 s delivery drain |
| `--replace-interval-ms` | 3,000 | Interval between re-REQs of each replaced subscription |
| `--publish-rate` | 20 | Background publications per second (0 turns them off) |
| `--clients-per-address` | 1 | Clients per source address, e.g. 4 for CGNAT; 0 sends every client from the bench host's own address |
| `--client-deflate` | `true` | Offer permessage-deflate |
| `--expect-no-refusals` | off | Fail the trial on any refusal. This is the acceptance check for proposed defaults in #97 |

```bash
cargo build --release -p wok-cli -p wok-bench
./target/release/wok-bench --scenario clients --wok ./target/release/wok \
  --events 100000 --event-mix realistic --out bench-results/clients \
  --marmot-groups 50 --marmot-invitees 100 [--relay-config preset.toml]
```

### Reading the output

Refusals are the measurement. Each `CLOSED`, `OK false`, `NOTICE`, `NEG-ERR`
and HTTP 429 is grouped by its reason, with digits collapsed.

`summary.md` has one section per trial with two tables:

- **Classes.** One row per subscription or publication class. The W1–W6
  classes are named after the traffic shape they model, for example
  `w2.metadata`, `live.home_feed` and `marmot.neg`. Each row gives:
  - how many requests were sent, completed and refused;
  - how many histories were truncated;
  - events received in history and live;
  - p50 and p99 of time to first EVENT and of time to done.

  "Done" is EOSE for subscriptions, completion for NIP-77, OK for
  publications, completion for a whole burst, and publish-to-receipt for
  `delivery.*`.
- **Refusals.** One row per reason, with the configuration key responsible
  and the classes it refused.

A history that comes back short with no refusal is reported as truncated
when `max_filter_limit` or `max_total_events_per_req` explains the cut. Any
other short history fails the trial. `results.jsonl` holds the same data in
each trial's `clients` field, for comparing a change against an earlier run.

Correctness still decides `ok`, as in every other scenario:

- every history must be the newest events of an independent oracle over the
  imported corpus, allowing for events published during the run;
- no restricted event may reach a connection that is not its recipient. This
  is checked as each EVENT arrives, including on subscriptions refused later;
- every live subscription must receive each accepted, matching event
  published after its EOSE;
- each NIP-77 pass must report exactly the corpus events the client lacked,
  plus only 445s published into that group, and none it already holds.

A subscription that Wok refuses with a NOTICE just before its EOSE (over
`max_subs_per_connection`) is counted as refused and left out of the
live-delivery check. Wok's monitor also sends events committed during a scan
just before EOSE, so a history may hold more than `limit` events; only its
stored part is bounded by `limit`.

CI runs a small version as a unit test against an in-process relay with
default limits (`clients::tests`).

## Live subscriptions (`monitor_index`, `live_subscriptions`)

Two Wok-only scenarios measure the live-subscription monitor under the load
real clients put on it: many subscriptions with distinct author lists, REQ
replacement and CLOSE churn, and reconnect storms. Both build the same
workload from `--seed`:

- `--live-conns` connections hold `--live-subs-per-conn` subscriptions each.
  Of every ten, six are home feeds (`authors` × kinds 1 and 6) with a distinct
  list of `--live-min-authors` to `--live-max-authors` authors. The others are
  a `#p` mentions subscription, a `#p` zap-receipt subscription and two `#e`
  thread subscriptions.
- Authors come from a pool of `--live-authors`, ranked by popularity. Follow
  lists, posts and mentions pick them by a Zipf law (exponent 0.8), so popular
  authors are in most lists, as on a public relay.
- Events: 50% notes (some replies or mentions), 30% reactions, 5% reposts, 10%
  zap receipts, and 5% kind 3 contact lists with 300 to 1,000 `p` tags. No
  subscription wants a contact list, but matching still looks at every tag.

### `monitor_index`

This scenario runs `wok_query::ActiveMonitors`, the req monitor's index, in
process. It starts no relay, so it measures the index compiled into this
`wok-bench` build, not the `--wok` binary. Every time is CPU on one monitor
thread with every subscription on it, as with `relay.numThreads.reqMonitor = 1`.
Subscriptions register the way the monitor registers them, pending until
their history is sent. The steps:

- **REQ (subscribe):** register every subscription.
- **match event:** match `--live-events` events, as the monitor does for each
  stored event. Kind 3 lists get their own row.
- **churn:** `2 × --live-conns` cycles. Each replaces a random feed with a
  new list of `--live-max-authors` (a REQ with the same id), CLOSEs it, then
  REQs the original again.
- **storm:** close every connection, then register all its subscriptions
  again.

The first 500 events matched, and the first 500 of the up to 1,000 matched
after the storm, are checked against an independent matcher; any difference
fails the trial.

The table gives count, mean, p50, p99, max and total time per step. The
trial's latency columns hold the per-event match time in **µs**, not ms.
Throughput is events matched per second of monitor CPU.

To compare two versions of the monitor, build `wok-bench` from each and run
both on the same host:

```bash
git worktree add ../wok-master master
(cd ../wok-master && cargo build --release -p wok-cli -p wok-bench)
cargo build --release -p wok-cli -p wok-bench
../wok-master/target/release/wok-bench --scenario monitor_index \
  --out bench-results/monitor-master --seed 1
./target/release/wok-bench --scenario monitor_index \
  --out bench-results/monitor-branch --seed 1
```

### `live_subscriptions`

This scenario runs the workload against a relay (`--wok`). It first
publishes 2,000 root notes for the thread subscriptions to follow, then
opens every connection and waits for each EOSE. One publisher then sends
`--live-rate` events per second, waiting for each OK, through four phases:

| Phase | What happens |
|---|---|
| Steady | Ingest only, for `--live-phase-secs` |
| Churn | `--live-churners` extra connections each keep feeds of `--live-max-authors` open and cycle through them: replace one (REQ with the same id), CLOSE it, REQ it again. Each REQ waits for its EOSE. Together they aim for `--live-churn-rate` REQs per second |
| Storm | Every stable connection drops at once, reconnects and sends its REQs again. The phase ends when every connection has all its EOSEs |
| Recovered | Ingest only, for `--live-phase-secs` |

Before the storm and at the end the publisher pauses until every stable
connection has received what it is owed, so no checked delivery is in flight
when connections drop. A relay that falls behind makes these waits longer;
the report gives their total.

Every delivery to a stable connection of an event published outside the
storm is checked against the independent matcher: each event exactly once on
every subscription that matches it. Missing or unexpected deliveries fail the
trial, and so does any refused publication other than a kind 3 contact list
(which can lose to a newer list from the same author in the same second). Events published during the storm are not checked, because a
subscription that is reconnecting may miss them.

The table has one row per phase:

- events published and deliveries received, to the stable connections and the
  churners' feeds;
- fan-out latency, from just before the EVENT is sent to its receipt, as p50,
  p90, p99 and max;
- relay CPU seconds for the whole process. On Linux, monitor CPU is the sum of
  the `req-monitor-*` threads. Other systems do not name threads, so it reads
  `n/a`.

Below the table come:

- time from connect to the last EOSE, for the first subscription and for the
  storm, per connection;
- the churn rate the churners reached;
- churn REQ-to-EOSE latency. The monitor sends EOSE after it has applied every
  subscription change queued before it, so a backlog of CLOSEs and
  replacements shows here.

The trial's latency columns hold steady-phase fan-out in ms, and throughput is
steady-phase deliveries per second. Compare two relay binaries with the same
`wok-bench` and `--seed`:

```bash
./target/release/wok-bench --scenario live_subscriptions --seed 1 \
  --wok ../wok-master/target/release/wok --out bench-results/live-master
./target/release/wok-bench --scenario live_subscriptions --seed 1 \
  --wok ./target/release/wok --out bench-results/live-branch
```

| Option | Default | Meaning |
|---|---:|---|
| `--live-authors` | 20,000 | Author pool |
| `--live-conns` | 1,000 | Stable connections |
| `--live-subs-per-conn` | 10 | Subscriptions per connection (at most 100) |
| `--live-min-authors` | 50 | Smallest feed author list |
| `--live-max-authors` | 500 | Largest feed author list, and the size of churn REQs |
| `--live-events` | 20,000 | Events `monitor_index` matches before its churn |
| `--live-rate` | 50 | Publications per second in `live_subscriptions` |
| `--live-phase-secs` | 10 | Length of the steady, churn and recovered phases |
| `--live-churners` | 50 | Churning connections |
| `--live-churn-rate` | 200 | REQs per second, all churners together |

Feeds of 500 authors fit the default `relay.max_req_filter_size` of 64 KiB.
CI runs small versions of both scenarios as unit tests (`live::tests`). The
`live_subscriptions` test uses an in-process relay.

## Portable Docker lab

For a repeatable local setup or fresh two-VM deployment, start with the
[Docker load lab](load-lab.md). It packages `wok-bench` with the relay, preserves
results, and checks shutdown/integrity without fixed host addresses.

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

See [NIP-50 search](nip50-search.md) for the search workload and exact semantics.

## Harness correctness checks

The harness defaults to `--tcp-nodelay true` and records this setting in every
result row. Use explicit true/false runs on the same Linux host before attributing
WebSocket request plateaus to the codec, LMDB, or Nagle.

The mixed read/write scenario queries a fixed corpus author while distinct
authors publish, allowing an exact historical oracle despite concurrent commits.
The search oracle uses the generated equal-score vocabulary. Fanout subscribers
read concurrently with publication and request no historical events
(`limit: 0`). Both throughput and the latency fields use aggregate
publication/delivery duration; the latter contain one sample per trial, not
individual subscriber delivery percentiles. Each subscriber verifies unique IDs
and exact payloads against shared expectations without retaining a second copy
of all received events. Warm-up is excluded from measured search time.

Storage verification accounts for the documented ephemeral difference: Wok's
live-only default must export no ephemeral records. strfry's temporary storage
may export a duplicate-free subset of submitted ephemeral events, each with its
exact original payload. Both must export the exact expected persistent set.

## Time to EOSE under req monitor fan-out

`crates/wok-compat/tests/eose_latency.rs` is an ignored test that times
REQ → EOSE while the req monitors fan stored events out to many live
subscriptions. It drives an in-process relay through the public
`RelayHandle` API, so it measures the relay's own pipeline without transport
or client costs, and the same file runs unchanged against older revisions for
before/after comparisons.

```bash
FANOUT_CONNS=200 FANOUT_SUBS=50 PUBLISH_RATE=400 \
  cargo test --release -p wok-compat --test eose_latency -- --ignored --nocapture
```

- `FANOUT_CONNS` × `FANOUT_SUBS` live `{"kinds":[1]}` subscriptions receive
  every stored event, so each event costs the monitors that many frames.
- `PUBLISH_RATE` stored events per second come from one connection, in 10 ms
  ticks, pre-signed for five minutes of load.
- The probe connection sends `PROBES` sequential REQ → EOSE → CLOSE round
  trips, then `BURSTS` bursts of `BURST` REQs at once, each
  `{"kinds":[1],"limit":5}`.

The output has four lines, `idle` and `fan-out`, each for `sequential` and
`burst of N`, with the sample count and p50/p90/p99/max in milliseconds. Burst
times run from the burst's first REQ to each EOSE, so they show REQs waiting
behind one another. Read the fan-out lines against the idle ones from the same
run. Results swing widely near the monitors' saturation point: raise
`PUBLISH_RATE` until fan-out p90 leaves the idle floor, then run each revision
at least three times, alternating, and compare medians. A run that panics with
"load ran out" lasted longer than its load, so its later lines were measured
without it; discard them.
