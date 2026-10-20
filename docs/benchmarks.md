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
refuses real clients. Wok-only `--scenario clients` keeps both on and models
the traffic shapes from the 2026-10-20 client-workload audit (W1–W10):

- **Outbox clients** (`--clients`, default 20). Each opens 30 subscriptions at
  once on connect:
  - 15 fetch-and-close (REQ → EOSE → CLOSE): `authors[follows] ×
    kinds[0,3,10002,10050]` metadata, profile and relay-list lookups, `ids`,
    threads, a 45-filter `#e` reaction batch, notification and feed pages, an
    11-kind global feed, an authors-only feed and long-form;
  - 5 re-REQed with the same ID every `--replace-interval-ms` (scrolling
    pages and profile rotation);
  - 10 live: home feed, notifications, NIP-04 and NIP-17 DM inboxes, own
    replaceables, zaps, three open threads and a hashtag.

  Follow lists are log-uniform from 100 to `--max-follows` (default 2,000).
  Clients AUTH when a DM subscription is answered `auth-required:` and then
  send it again.
- **Marmot clients** (`--marmot-clients`, default 4), modelled on MDK:
  - an AUTHed receive connection with a `{"kinds":[1059],"#p":[me]}` inbox;
  - per group (`--marmot-groups`), a live `{"kinds":[445],"#h":[gid]}` and a
    NIP-77 pass on the same filter (MDK's `limit` 16,385), then `ids` fetches
    of at most 64 for what the pass reports missing;
  - an anonymous directory connection with two batches of
    `{"authors":[200],"kinds":[0,10002,10050,30443],"limit":800}`;
  - an anonymous publish connection that sends one add-member burst: a 445
    commit plus `--marmot-invitees` 1059 gift wraps from throwaway keys,
    sized like an Add commit and a Welcome for that group. As MDK does, it
    retries `rate-limited:` publications with backoff and authenticates
    after `auth-required:`.
- **Background publishing** (`--publish-rate`, default 20/s over four
  connections): popular authors' notes, replies to watched threads,
  reactions to clients' notes, and 445s into the groups.

Each simulated client sends from its own address through `X-Forwarded-For`.
The trial config sets `relay.real_ip_header` to that header. With
`--clients-per-address N`, N clients share an address (CGNAT, office NAT).
With `--clients-per-address 0`, every client uses the bench host's own address.
Connections negotiate permessage-deflate (`--client-deflate false` turns it
off) through wok-ws's codec in client mode.

`--relay-config <wok.toml>` runs against a supplied file instead of the
built-in defaults; abuse controls and AUTH stay as that file sets them. The
trial replaces only the database path, bind address and port, the Unix
socket, the real-IP header and, when it is empty, `relay.auth.service_url`.
The report lists each override. The scenario imports the `--events`
background corpus plus its own deterministic corpus (about 30,000 events)
before starting the relay.

Refusals are the measurement. Each `CLOSED`, `OK false`, `NOTICE`, `NEG-ERR`
and HTTP 429 is grouped by its reason, with digits collapsed. The report names
the configuration key responsible and lists the subscription classes it
refused. A history that comes back short with no refusal is reported as
silently truncated when `max_filter_limit` or `max_total_events_per_req`
explains the cut. Any other short history fails the trial. Per class, the report gives time to first EVENT and time
to EOSE (for NIP-77, to the first reply and to completion), OK latency for
publications, and publish-to-delivery latency, each at p50 and p99.

Correctness still decides `ok`, as in every other scenario:

- every history must be the newest events of an independent oracle over the
  imported corpus, allowing for events published during the run;
- no restricted event may reach a connection that is not its recipient,
  checked as each EVENT arrives, including for subscriptions later refused;
- every live subscription must receive each accepted, matching event
  published after its EOSE;
- each NIP-77 pass must report exactly the corpus events the client lacked,
  plus only 445s published into that group, and none it already holds.

A subscription that Wok refuses with a NOTICE just before its EOSE (over
`max_subs_per_connection`) is counted as refused and left out of the
live-delivery check.

`--expect-no-refusals` also fails the trial on any refusal. That flag is the
acceptance check for proposed defaults
([configuration presets proposal](config-presets-proposal.md) §6, PR #89).

```bash
cargo build --release -p wok-cli -p wok-bench
./target/release/wok-bench --scenario clients --wok ./target/release/wok \
  --events 100000 --event-mix realistic --out bench-results/clients \
  --marmot-groups 50 --marmot-invitees 100 [--relay-config preset.toml]
```

CI runs a small version as a unit test against an in-process relay with
default limits (`clients::tests`). The
[2026-10-20 baseline](benchmark-clients-baseline-2026-10-20.md) records
today's refusals.

## Portable Docker lab

For a repeatable local setup or fresh two-VM deployment, start with the
[Docker load lab](load-lab.md). It packages `wok-bench` with the relay, preserves
results, and checks shutdown/integrity without fixed host addresses.
The [September 5 local lab audit](load-lab-audit-2026-09-05.md) records larger
campaigns, long-idle validation, generator corrections, and measurement limits.

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

### Recorded campaigns

The [post-hardening report](benchmark-security-hardening-2026-08-14.md)
records the full 100,000-event rerun at Wok commit `fa9b061` after the
WebSocket performance work and security-hardening series. All 96 two-host and
same-host result rows passed. It includes the controlled change from v0.2.0,
resource measurements, retained artifact hashes, and a Unix socket shutdown
cleanup defect found after the transport campaign and subsequently fixed in
commit `ca64980` without changing the measured binary or results.

The [2026-08-14 WebSocket optimization report](websocket-performance-2026-08-14.md)
records the focused profiling and same-build two-host A/B that followed the
v0.2.0 campaign. The final zero-delay candidate improved scaled WebSocket
publication throughput by 22–24% in two order-balanced comparisons.

The [v0.2.0 report](benchmark-v0.2.0-2026-08-14.md) records the previous
100,000-event Linux campaign: a two-host Wok/strfry relay comparison and a
same-host Wok Unix/WebSocket transport comparison, each with three
order-rotated repetitions. All 96 result rows passed their correctness gates.
It includes the before/after comparison to the previous controlled Wok build,
median throughput and latency, resources, exact corpus and binary hashes,
limitations, retained artifacts, and next investigations.

The earlier [2026-08-14 transport report](transport-benchmark-2026-08-14.md)
is the baseline for that comparison. It records 54 correct trials against Wok
commit `876bce55671120fc65b9a0844d2f4ae9f1d9d229`.

The older `sample-bench-summary.md` and `sample-bench-results.jsonl` remain a
historical single-run Apple Silicon example of the local process harness. Do
not treat that sample as the current controlled VM result or combine it with
same-host transport and two-host network measurements.

See [NIP-50 search](nip50-search.md) for the search workload, exact semantics,
and 100k/1m-event scale results.

## September 5 audit corrections

The harness defaults to `--tcp-nodelay true` and records this setting in every
result row. Use explicit true/false runs on the same Linux host before attributing
older WebSocket request plateaus to the codec, LMDB, or Nagle. A Mac loopback
A/B/B/A diagnostic did not demonstrate a consistent Nagle penalty.

Historical reports used weaker correctness checks and a different client TCP
setting. Their zero-mismatch counts do not validate receipt routing or exact
query sets. Preserve them as historical measurements; do not compare their rates
directly with new runs. The mixed read/write scenario now queries a fixed corpus
author while distinct authors publish, allowing an exact historical oracle despite
concurrent commits. The search oracle uses the generated equal-score vocabulary.
Fanout subscribers read concurrently with publication and request no historical
events (`limit: 0`). Both throughput and the latency fields use aggregate
publication/delivery duration; the latter contain one sample per trial, not
individual subscriber delivery percentiles. Older harness versions recorded only
post-publication drain time in those latency fields. Each subscriber verifies
unique IDs and exact payloads against shared expectations without retaining a
second copy of all received events. Warm-up is excluded from measured search time.

Storage verification accounts for the documented ephemeral difference: Wok's
live-only default must export no ephemeral records. strfry's temporary storage
may export a duplicate-free subset of submitted ephemeral events, each with its
exact original payload. Both must export the exact expected persistent set.
The first lifecycle audit control flagged this intentional difference; the oracle
was then corrected and tested, rather than treating it as a strfry defect.
