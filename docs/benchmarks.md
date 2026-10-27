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

`--event-mix social` writes the history of a public social relay, to build
the large databases a campaign reads. `--social-authors` authors (default
100,000) post in proportion to a Zipf law over author rank, across the two
years before `--base-timestamp`, at a rate that grows over that window.
Replies, reactions, reposts, zaps and follows name popular authors more
often. Of every hundred events, about:

| Events | Kinds |
|---:|---|
| 30 | reactions (7) |
| 27 | notes and replies (1) |
| 12 | profiles, follow lists, relay lists, DM relay lists and mute lists (0, 3, 10002, 10050, 10000) |
| 8 | gift wraps (1059), one in twenty a Marmot Welcome |
| 6 | reposts (6) |
| 6 | zap receipts (9735) |
| 3 | comments (1111) |
| 5 | articles, pictures, follow sets and bookmarks (30023, 20, 30000, 10003) |
| 1 | deletion requests (5) |
| 2 | Marmot group messages and KeyPackages, highlights, reports, live events (445, 30443, 9802, 1984, 30311) |

Sizes follow real clients:
- follow lists are log-normal around 150 follows, up to `--max-follows`;
- zap receipts carry their request, and reposts carry the note;
- Marmot Welcomes grow with the group.

Profiles, lists, articles and KeyPackages are replaced, and deletion requests
delete their author's earlier events. So a relay keeps fewer events than the
corpus holds, and `corpus.social.retained` in `manifest.json` gives that
count. The manifest also records the limits a relay needs to accept every
event: `needed_max_event_size`, the smallest `max_event_size` (strfry:
`maxEventSize`) that imports the longest line with its newline, `most_tags`,
and `largest_tag_value_bytes` (single-letter tags). strfry's default
`events.maxEventSize` of 64 KiB refuses the largest follow lists and Welcomes.
The corpus streams to disk and is signed in parallel, and its bytes depend
only on the options. Besides `--generate-corpus-only`, the mix runs only the
read scenarios below.

### Reading a social corpus

`ws_query_latency`, `deep_history_pagination` and `mixed_read_write` read a
social corpus with `--event-mix social`, whether the run generated it or
`--corpus` names it. Their expected results are what a relay keeps of the
corpus:

- each id once, and no ephemeral event;
- the newest version of each replaceable and addressable address: the later
  `created_at`, and on a tie the lower id;
- no event its author deleted with a kind 5 `e` tag. A deletion of a
  deletion does nothing, as in Wok; no generated corpus has one.

The harness checks this count against `corpus.social.retained` when it
generated the corpus, and against the export of a relay it started. It
checks the export, not import's exit status: both relays write an import
batch in `created_at` order, then by id, so a deletion in the same second as
its target, with the lower id, refuses the target instead of deleting it.
The relay ends with the same events either way, but `wok import` exits
nonzero when it refuses any line, and strfry exits 0. A relay the harness
starts also gets `max_event_size`, `max_num_tags` and `max_tag_val_size`
(strfry: `maxEventSize`, `maxNumTags`, `maxTagValSize`) raised to what the
corpus needs, where that is more than strfry's defaults.

Where a `limit` cuts through a second, a reply may hold any of that
second's events. NIP-01 says the lowest id comes first, but strfry and Wok
send a second's events in arrival order
([known-differences.md](known-differences.md)). This holds for every mix.

`ws_query_latency` takes turns between the archive reads of #226 scenario
B:

| Shape | Filter |
|---|---|
| Id lookup | `ids`: one event, which may since have been replaced or deleted |
| Profiles | `authors`: the first 500 of a follow list, `kinds` 0, 3 and 10002 |
| Follow feed | the same authors, `kinds` 1 and 6 |
| Notifications | `#p`: a pubkey a reaction names, `kinds` 1, 6, 7 and 9735 |
| Followers | that `#p`, `kinds` 3 |
| Thread | `#e`: a note a reaction names, `kinds` 1, 6, 7, 9735 and 1111 |
| Newest notes | `kinds` 1, `since`, `limit` 20 |

Ids and pubkeys are always 64 hex characters; Wok refuses prefixes. Every
`limit` is at most 500, strfry's and Wok 0.7's `maxFilterLimit`, and 500
authors fit every relay's default filter size. No filter reads gift wraps
or DMs: Wok serves kinds 4, 1059 and 21059 only to their authenticated
recipient, and strfry serves them to anyone (#226 §8). The corpus has no
ephemeral events, which strfry keeps for a while and Wok never stores.

`deep_history_pagination` pages through the busiest author's history, every
kind, as a mirror reads it; other mixes page notes only. Each page asks for
events older than the last page's oldest, so where a page ends inside a
second, the rest of that second is skipped, as it is for a client paging
that way. `mixed_read_write` reads the first note's author while it
publishes notes by authors of its own.

The harness reads the corpus once, parsing it on every core, and keeps only
what the oracle needs of each event: its id, author, kind and `created_at`,
a hash of the whole event to check replies against, and its single-letter
tags as numbers. Each line must hold exactly the seven NIP-01 fields, with
ids and pubkeys in lowercase hex. On the load host, a 1M-event social
corpus peaks at 0.55 GB and 10M at 2.7 GB, about 250 bytes an event; 50M
comes to about 13 GB. Keeping each event whole took 5.6 GB at 1M, so 50M
would have needed about 285 GB. A historical REQ may take up to 120 s to
reach its EOSE, since deep pages on a large store can take tens of seconds.

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
sets (where a `limit` cuts through a second, any of its events; see
[Reading a social corpus](#reading-a-social-corpus)),
publication IDs/boolean acceptance, and complete per-subscriber deliveries.
`ws_query_latency`, `deep_history_pagination` and `mixed_read_write` work out
each expected reply before the clock starts, since on a large corpus that can
take longer than the relay takes to answer. A latency sample runs from the REQ
to its EOSE, and throughput leaves out the time spent checking replies.
Local publication trials also export and compare the final stored state, including
replacement, deletion and ephemeral semantics; remote storage is explicitly not
inspected, except by `--reconcile` after `ws_publish_rate`.

Scenarios: `import` (signature-verifying bulk import), `export`,
`negentropy_build`, `ws_publish_1conn`/`ws_publish_8conn` (per-publish OK
latency + rate), `ws_query_latency` (mixed REQs: id, author+kind, time
window, tag; on a social corpus, the shapes above), `deep_history_pagination`
(progressively older 500-event author+kind+until pages), `mixed_read_write`
(historical REQs while another
connection continuously publishes), `live_fanout` (delivery completeness and
throughput to configurable subscribers; the publisher keeps up to
`--fanout-window` publications unacknowledged, 256 by default, so delivery
rather than each OK's round trip bounds it; `--fanout-window 1` waits for
each OK, as earlier builds did), `ws_publish_scaled` (configurable
connection count), `ws_publish_rate` (fixed-rate publication with a
per-event outcome log), `idle_connections` (open-and-hold connection capacity),
`duplicate_import`, `cold_start`, and Wok-only
`nip50_search` (rare, intersected, and full-corpus ranked searches with
result/limit verification). Wok-only `clients`, `author_kinds`,
`monitor_index` and `live_subscriptions` have their own sections below, as
do `ws_publish_rate` and `nip77_catchup` (NIP-77 catch-up, then fetching
what the client lacks). Use `--scenario <name>` to isolate one scenario.

## Fixed-rate publication (`ws_publish_rate`)

`ws_publish_scaled` sends a connection's next event only after the last one's
OK, so a relay that slows down slows the sender too, and its backlog never
shows. `ws_publish_rate` keeps a fixed schedule instead: event `n` is due
`n / --send-rate` seconds after the start, on connection
`n % --publish-connections`, and goes out then whether or not earlier events
have been answered. Every event is signed before the clock starts, each
connection with its own keys, and each connection first publishes one
uncounted warm-up event and waits for its OK. Only `--event-mix kind1` and
`realistic` are allowed, since a relay keeps every event of those mixes.

```bash
./target/release/wok-bench --scenario ws_publish_rate \
  --target-url ws://10.0.0.3:7777 --target-label wok-master \
  --send-rate 5000 --send-secs 180 --publish-connections 64 \
  --event-mix realistic --seed 7 --out rate-5000
```

The options are `--send-rate`, events per second over all connections
(default 1,000); `--send-secs` (default 10); `--publish-connections`
(default 32); and `--drain-secs`, how long to wait for replies after the last
send (default 10).

Latency runs from when an event was due to its accepting OK, so time an event
waited behind a slow relay counts. A sent event never answered counts until
the drain ended, so with unanswered events the percentiles are lower bounds;
refusals are left out. Once every event a connection sent is answered, it
reads for another half second, so a repeated or malformed OK queued behind the
last one still fails the trial. The fixed-rate table also gives the
achieved send rate; the send lag, from when an event was due to the end of its
send; and the accepted rate, which is the trial's throughput. Both rates
divide by the schedule's length, or by the time to the last send or the last
accepting OK if that was later, so a backlog and refusals both lower the
accepted rate. A trial is `ok=false` when the achieved rate is below 99% of
`--send-rate`, when a connection fails, when an OK is malformed, names no
event of its connection's or repeats one, or when reconciliation finds a
mismatch. A connection fails when the relay closes it, or when a send is still
pending once `--send-secs` and `--drain-secs` have passed, because the relay
stopped reading.

Each event gets one line, in due order, in `outcomes-<relay>-r<repetition>.jsonl`
under `--out`. Times are microseconds from the start:

```json
{"seq":0,"conn":0,"id":"…","kind":1,"due_us":0,"sent_us":84,"reply_us":1450,"ok":true,"message":""}
```

`sent_us` is null for an event never sent because its connection had failed.
`reply_us`, `ok` and `message` are null for one with no OK when the drain
ended. Reconciliation compares the log with the relay's export and puts each
event in one outcome:

| Outcome | Meaning |
| --- | --- |
| acknowledged, stored | correct |
| acknowledged, missing | a lost write: must be zero |
| refused | counted by the message's prefix, such as `rate-limited` |
| refused, but stored | must be zero |
| no reply, stored | slow, but kept |
| no reply, not stored | a client would have to send it again |

An event never sent counts as unanswered. A relay the harness starts is
exported and reconciled when the run ends. For a remote target, export its
database once the run is over and reconcile anywhere:

```bash
wok --config /etc/relay-bench/wok-master.toml export > export.jsonl
./target/release/wok-bench --reconcile rate-5000/outcomes-wok-master-r1.jsonl \
  --relay-export export.jsonl --out rate-5000
```

`--relay-export -` reads the export from standard input. `--reconcile`
writes `reconciliation.json` under `--out`, prints the counts, and exits
non-zero when an acknowledged event is missing or a refused one was stored.
The export may hold other events, such as an imported corpus; only the log's
events are counted.

Each run signs its events from `--seed`, the repetition and
`--base-timestamp`, which defaults to the start time. Rerun all three against
one database and the relay already has the events: it accepts them as
duplicates, which the table counts.

## NIP-77 catch-up (`nip77_catchup`)

A client that holds part of what a relay has catches up with NIP-77, then
fetches the events it lacks. An archive mirror does this, and so does a
Marmot app for each of its groups when it starts. The relay must hold the
corpus and nothing else: a relay the harness starts imports `--corpus` first,
and a remote one must have been loaded with the same file.

```bash
# An archive mirror: the whole corpus in eight time windows, four at once,
# lacking the newest 10%.
./target/release/wok-bench --scenario nip77_catchup \
  --target-url ws://10.0.0.3:7777 --target-label wok-master \
  --corpus social/corpus.jsonl --sync-filter all --sync-windows 8 \
  --sync-concurrency 4 --out catchup-mirror

# Marmot apps starting: one sync per group, 256 at once, 8 to a connection,
# each lacking a random 20% of the messages.
./target/release/wok-bench --scenario nip77_catchup \
  --target-url ws://10.0.0.3:7777 --target-label wok-master-marmot \
  --corpus social/corpus.jsonl --sync-filter groups \
  --sync-concurrency 256 --sync-per-conn 8 \
  --sync-missing random --sync-missing-pct 20 --out catchup-marmot
```

What it syncs:

- `--sync-filter all` (default) syncs the whole corpus, split into
  `--sync-windows` (default 1) time windows of about equal event counts.
  Windows split at whole seconds; the first has no `since` and the last no
  `until`, and a single window sends `{}`.
- `--sync-filter groups` sends one `{"kinds":[445],"#h":[group]}` filter per
  Marmot group in the corpus, as MDK does at start. It needs a corpus written
  with `--event-mix social`. The `marmot` preset refuses `all`, whose filters
  name no author or tag.
- `--sync-limit` puts a `limit` in every NEG-OPEN filter. The default is
  MDK's 16,385 for groups and none for `all`. No filter may match more
  events than its limit, since relays break ties at the limit differently;
  the run stops before it starts if one does.

The client lacks `--sync-missing-pct` percent (default 10) of the events the
filters match, rounded: the newest ones with `--sync-missing newest`
(default), as after time offline, or a random set with
`--sync-missing random`, drawn from `--seed` and the repetition. It holds the
rest. At 100 it starts empty, as a new mirror does.

Each sync sends NEG-OPEN with the `(created_at, id)` pairs the client holds,
answers each NEG-MSG until the client has nothing more to send, and sends
NEG-CLOSE. It then asks for the ids it lacks in REQs of up to 500 ids, the
`maxFilterLimit` of strfry 1.1.3 and Wok 0.7.0, closing each after its EOSE.
The client's messages stay under 60,000 bytes before hex encoding, so a
NEG-MSG fits the 131,072-byte WebSocket payload limit of strfry 1.1.3, Wok
0.7.0 and Wok's `public` preset; relays answer with up to 500,000 bytes.
`--sync-concurrency` syncs (default 1) run at once, `--sync-per-conn`
(default 1; MDK runs up to 8) on each connection, and a connection that
finishes one sync starts the next. The client builds each sync's first
message and opens its connections before the clock starts. Each connection
sends an `X-Forwarded-For` address in 10.64.0.0/10, one for every
`--clients-per-address` connections (0 sends none), which a relay uses only
when it trusts the header from the load host.

Relays limit what one sync may match. strfry 1.1.3 and Wok refuse a sync
that matches more than 1,000,000 events (`maxSyncEvents`,
`relay.max_sync_events`; 65,536 under the `marmot` preset) unless they answer
it from a stored negentropy tree. Wok master also reserves 256 bytes per
event of a sync's limit, capped at `max_sync_events` and the events it
stores, against `relay.sync_memory_per_connection` and `sync_memory_total`
before it scans.
Windows and `--sync-limit` keep a sync inside these limits.

The trial's throughput is the events fetched per second, from the first
NEG-OPEN to the end of the last sync, and its latency columns give the time
per sync. The catch-up table splits that time into reconciling (NEG-OPEN to
the last NEG-MSG) and fetching (from there to the last EOSE), and counts
events fetched, fetch REQs, NEG-MSG rounds in all and the most in one sync,
and the JSON text sent and received for the NEG and fetch messages, without
WebSocket framing.

A sync is correct when the relay names exactly the events the client lacks,
names none that only the client holds, and returns every event a REQ asks for
once and unchanged. Wok serves gift wraps and its other restricted read
classes (`relay.auth.recipient_only_kinds`, `owner_only_kinds` and
`authenticated_kinds`) only after AUTH, and so leaves them out of a sync,
while strfry serves them. Each such kind must therefore be served in full or
left out in full, and the table lists the kinds left out. A relay's refusal,
a `NEG-ERR` or a `CLOSED` for a fetch, ends that sync and is counted by
reason. A sync refused during its fetch is still checked as far as it got:
its reconciliation and the events it received. Refusals fail the trial only
with `--expect-no-refusals`, which engine-mode runs should pass. A
connection that closes, or that has syncs open and receives nothing for
120 s, fails its syncs. The oracle works out what a relay keeps of the
corpus, after replacements and deletions, and holds that in memory, as the
query scenarios hold their corpus.

## Client-realistic scenario (`clients`)

Every scenario above runs with `[relay.abuse]` and `[relay.auth]` disabled and
sends one REQ at a time, so none of them can say whether a default limit
refuses real clients. `--scenario clients` keeps both on. It runs against a
Wok the harness starts, or against any relay by `--target-url` (see
[Against a remote relay](#against-a-remote-relay)). It models the client
traffic shapes W1–W10 that the limits plan cites
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

Each simulated client, and each background publisher, sends from its own
address through `X-Forwarded-For`, and the trial config sets
`relay.real_ip_header` to that header. `--clients-per-address 0` sends no
header. Connections negotiate permessage-deflate through wok-ws's codec in
client mode. The scenario imports the `--events` background corpus plus its
own deterministic corpus (about 30,000 events at the defaults) before it
starts the relay.

### Arrivals and sessions

By default every client connects at the start and stays to the end. With
`--client-arrival-rate R`, sessions start on a fixed schedule: session `a` is
due `a / R` seconds in and belongs to client `a mod clients`, with outbox and
Marmot clients taking turns in proportion to their numbers. With
`--client-session-secs L` each session ends `L` seconds after it was due,
reads for another 2 s, and its client comes back on its next turn, so the
scenario produces reconnect churn at a steady rate. A client may not come
back before its last session ended, so `--clients + --marmot-clients` must be
at least `R × (L + 2)`. Without `--client-session-secs`, each client arrives
once.

The schedule does not wait for the relay. Connect latency counts from when
the session was due; re-REQs of replaced subscriptions are due every
`--replace-interval-ms`; background publications are due every
`1 / --publish-rate` seconds, spread over the publishers; and a Marmot burst
is due 1.5 s into its session. Each of those counts its latency from when it
was due, as `ws_publish_rate` does, so time spent waiting behind a slow relay
counts. A re-REQ due while the subscription's last REQ is still unfinished
waits for it and keeps its due time, so a slow relay builds a backlog rather
than being offered less. A request still unanswered when its session stops
reading counts as unanswered, with its latency up to then, as does a re-REQ
still waiting. With unanswered requests the percentiles are lower bounds.

A session gives the relay nothing new once its visit ends: no REQ,
publication, NIP-77 pass, Marmot burst or AUTH, and no retry of any of them.
Only what finishes an exchange already under way (NEG-MSG, NEG-CLOSE,
CLOSE) still goes out while the session drains for 2 s. What could not be
sent or retried keeps the relay's last answer: due and not sent, refused by
the reason the relay gave, or unanswered.

What the relay does is a result, not an error. A connect attempt is made
again until the session is due to end when the relay refuses it (any HTTP
status but 101, or a connection refused, reset or closed before the
upgrade) or does not take or upgrade it within 10 s. Refusals are counted
by reason, and each timed-out attempt, and an attempt still waiting at the
end, counts as an unanswered connect. A session that never connects does
nothing. A handshake answer that is not HTTP is the relay's protocol error,
a mismatch. Errors are kept for the load host's own failures, such as
running out of ports or file descriptors, and fail the trial.
The harness's own lateness in starting scheduled work is reported as the
lag; a large lag means the load host, not the relay, is the bottleneck.

Background publishing is held to its rate as in `ws_publish_rate`. A
publication counts as sent once it is written to the socket, and sends over
the run, or to the last send if that was later, must reach 99% of the
publications due, or the trial is `ok=false`. A write that cannot finish for
10 s means the relay stopped reading: the connection is given up and counted
as a disconnect (`write stalled`) and reset, so the relay sees it drop. A
publisher the relay refuses or disconnects keeps connecting until the run
ends and resumes with the slot due then; the slots due while it had no
connection count as due but not sent, and are not flushed in a burst. Writes
still queued 10 s after the drain are abandoned and the connection reset, so
they are neither counted as sent nor reach the relay after the run.

A Marmot receiver waits up to 250 ms for a connect-time AUTH challenge and
authenticates before it subscribes, as MDK does. strfry, and Wok with AUTH
off, never challenge, so the wait is short and the subscriptions exist before
the group's burst on every relay. Once it has sent AUTH it waits for the
answer, until its session ends; an AUTH still unanswered then counts as
unanswered. A NIP-77 pass that Wok closes because the connection
authenticated late is opened again, timed from the first open.

### Against a remote relay

`--target-url ws://host:port` drives a relay the harness did not start: a
strfry, a Wok release, or Wok master with a preset. The harness cannot read
those configs, so the run states what the oracle needs to know:

| Option | Meaning |
|---|---|
| `--target-max-filter-limit` | The relay's per-filter `limit` cap (Wok `max_filter_limit`, strfry `maxFilterLimit`); 0 for none |
| `--target-max-events-per-req` | Its cap on events per REQ (Wok `max_total_events_per_req`); 0 for none |
| `--target-recipient-kinds` | Kinds it serves only to the AUTHed recipient, comma-separated (Wok's default is `4,1059,21059`; empty for strfry) |

A history cut short by one of these caps is reported as truncated rather than
failed, so state them as the relay is configured. In engine mode give every
relay the same limits, and the histories are directly comparable. Clients
AUTH against the `--target-url` itself, so a Wok target's
`relay.auth.service_url` must be that URL.

The relay must already hold both corpora, and nothing an earlier run
published:

```bash
# On the load host: the background corpus and the scenario's own corpus.
./target/release/wok-bench --generate-corpus-only --scenario clients \
  --events 100000 --event-mix realistic --seed 7 --base-timestamp 1792000000 \
  --out clients-corpus
# On the relay host: import both, then snapshot the database.
wok --config wok.toml import --no-verify < clients-corpus/corpus.jsonl
wok --config wok.toml import --no-verify < clients-corpus/clients-corpus.jsonl
# Each run, after restoring the snapshot:
./target/release/wok-bench --scenario clients --target-url ws://10.0.0.3:7777 \
  --target-label wok-master --corpus clients-corpus/corpus.jsonl \
  --seed 7 --base-timestamp 1792000000 \
  --target-max-filter-limit 2000 --target-max-events-per-req 10000 \
  --target-recipient-kinds 4,1059,21059 \
  --client-arrival-rate 20 --client-session-secs 60 --clients-duration-secs 180 \
  --out bench-results/clients-wok-master
```

The run must use the seed, `--base-timestamp` and client options the corpus
was generated with, and one repetition, since what a run publishes changes
what the next one's histories should hold. Before the clock starts it checks
that the relay holds a sample of both corpora and nothing the scenario's
authors, or its Marmot groups, published after `--base-timestamp`, and stops
with an explanation if not. For as-shipped runs, configure the relay to take the client address from
`X-Forwarded-For` when the load host sends it: Wok's `relay.real_ip_header`
and `relay.trusted_proxies`, strfry's `relay.realIpHeader`.

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
| `--clients-per-address` | 1 | Clients per source address, e.g. 4 for CGNAT; 0 sends no `X-Forwarded-For`, so every client and publisher comes from the bench host's own address |
| `--client-deflate` | `true` | Offer permessage-deflate |
| `--client-arrival-rate` | 0 | Client sessions started per second; 0 starts every client at once |
| `--client-session-secs` | 0 | Length of each session; 0 keeps sessions to the end, so each client arrives once |
| `--expect-no-refusals` | off | Fail the trial on any refusal, relay disconnect or unanswered request. This is the acceptance check for proposed defaults in #97 |

```bash
cargo build --release -p wok-cli -p wok-bench
./target/release/wok-bench --scenario clients --wok ./target/release/wok \
  --events 100000 --event-mix realistic --out bench-results/clients \
  --marmot-groups 50 --marmot-invitees 100 [--relay-config preset.toml]
```

### Reading the output

Refusals are the measurement. Each `CLOSED`, `OK false`, `NOTICE`, `NEG-ERR`
and HTTP 429 or 503 is grouped by its reason, with digits collapsed. So is
each connection the relay ended: by its close code and reason, or as closed
without a close frame. Refusals and disconnects are results, not failures,
unless `--expect-no-refusals` is set.

`summary.md` has one section per trial with three tables:

- **Classes.** One row per subscription or publication class. The W1–W6
  classes are named after the traffic shape they model, for example
  `w2.metadata`, `live.home_feed` and `marmot.neg`. Each row gives:
  - how many requests were sent, completed, refused and left unanswered;
  - how many histories were truncated;
  - events received in history and live;
  - p50 and p99 of time to first EVENT, and p50, p99 and max of time to
    done.

  "Done" is EOSE for subscriptions, completion for NIP-77, OK for
  publications, completion for a whole burst, and publish-to-receipt for
  `delivery.*`. `delivery.outbox` and `delivery.marmot` are publish→live
  delivery, counted once per subscription and event.
- **Refusals.** One row per reason, with the configuration key responsible
  and the classes it refused.
- **Disconnects.** One row per reason the relay ended a connection, with the
  roles of the connections it ended.

The summary line above the tables gives sessions, the arrival schedule,
background publications due, sent and the achieved rate, the lag, and the
counts of refusals, disconnects, unanswered requests, missed and duplicate
deliveries.

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
  written to the socket after its EOSE while it was connected, exactly once.
  Events written after its session ended, or in the 2 s before the relay
  disconnected it, may still have been on their way, so they are not
  required;
- each NIP-77 pass must report exactly the corpus events the client lacked,
  plus only 445s published into that group, and none it already holds.

A subscription that Wok refuses with a NOTICE just before its EOSE (over
`max_subs_per_connection`) is counted as refused and left out of the
live-delivery check. Wok's monitor also sends events committed during a scan
just before EOSE, so a history may hold more than `limit` events; only its
stored part is bounded by `limit`.

CI runs a small version as a unit test against an in-process relay with
default limits, and a remote-mode run with arrivals and sessions against one
known only by URL (`clients::tests`).

The scenario does not yet scale live subscribers on their own, or model slow
readers: scenario C's 1k → 20k subscribers with 5% slow readers in
[#226](https://github.com/erskingardner/wok/issues/226) is still to come.

## WebSocket transport costs (`ws_transport`)

Wok-only `--scenario ws_transport` measures what connections cost the relay
process, the way browsers and apps use them. Every phase runs twice against a
fresh relay, once with clients that offer permessage-deflate and once with
clients that do not. Clients drive wok-ws's codec in client mode, so deflate is
really negotiated. The corpus (`--events`/`--event-mix`, or `--corpus`) is
imported first. Every fetch takes its kind-1 events up to its newest, and the
fan-out notes are newer still, so both modes fetch exactly the same events.

1. **Codec.** Compresses corpus EVENT frames (kind 0, kind 1, kind 7, all) and
   EOSE frames in process with wok-ws's deflater at levels 1–6.
2. **Memory.** Opens `--connections` sockets, then each fetches 10 events and
   closes the subscription, then (with `--transport-idle-secs`) all stay
   silent, and a second wave of as many connections opens and fetches beside
   them. Relay RSS is sampled after each step.
3. **Burst.** `--bursts` sequential `{"kinds":[1],"limit":--burst-events}`
   fetches on one connection.
4. **Fan-out.** `--fanout-subscribers` live subscribers receive
   `--fanout-events` fresh notes, published one at a time by a client that
   does not negotiate deflate.
5. **Churn.** `--churn-connections` connect, fetch 10 events, close cycles
   from 16 concurrent clients, like mobile apps reconnecting.

```bash
cargo build --release -p wok-cli -p wok-bench
./target/release/wok-bench --scenario ws_transport --wok ./target/release/wok \
  --events 5000 --event-mix realistic --connections 2000 \
  --transport-idle-secs 65 --bursts 200 --fanout-subscribers 500 \
  --fanout-events 40 --churn-connections 3000 --out bench-results/transport
```

| Option | Default | Meaning |
|---|---:|---|
| `--connections` | 1,000 | Sockets held open in the memory phase |
| `--transport-idle-secs` | 0 | Silence before the last memory sample (0 skips it). Wok releases compression state after 30–60 s without traffic, so use at least 65 to see it |
| `--burst-events` | 500 | Events per burst, at most the relay's default `max_filter_limit` (2,000); fewer if fewer kind-1 events are stored |
| `--bursts` | 40 | Bursts per mode |
| `--fanout-subscribers` | 32 | Live subscribers |
| `--fanout-events` | 200 | Notes published per mode |
| `--churn-connections` | 1,000 | Reconnect cycles per mode |

### Reading the output

`summary.md` has a table per trial with one row per mode (`off`, `offered`)
and a codec table. `results.jsonl` holds the same values in each trial's
`transport` field.

- **KB/conn cold, warm, idle**: relay RSS growth over the warmed-up baseline,
  divided by open connections. It includes everything a connection costs
  (transport, relay bookkeeping, allocator overhead), not only the codec.
  Freed memory leaves RSS only when the allocator returns it to the OS, which
  differs between platforms and allocators, and macOS may compress idle pages
  out of RSS, so read the idle column with care.
- **KB/conn 2nd wave**: what each connection of the second wave adds to RSS
  while the first wave is idle. An allocator that keeps freed memory instead
  of returning it to the OS hides a release from the idle column; a second
  wave that reuses that memory shows it here.
- **burst first EVENT / EOSE**: time from sending the REQ to its first EVENT
  and to its EOSE. **wire KB** is what the client read per burst, so the
  `offered` row shows the compression ratio.
- **CPU** columns are relay process CPU time (user + system) over the phase,
  divided per burst, delivery or cycle. They are sampled from outside the
  process: `/proc/<pid>/stat` on Linux and `ps` elsewhere, both with 10 ms
  resolution, so keep phases long enough for that to be noise.
- The scenario does not count syscalls. To count the relay's socket writes
  on Linux, point `--wok` at an executable script named `wok` that runs the
  real binary under `strace -f -c -o <file>`, and keep the other phases small.
- **Codec**: µs per frame and compressed size over original size. "Takeover"
  compresses each group as one stream, like a burst or a live subscription;
  "fresh" compresses each frame with a new compressor, like a connection's
  first message or its first after the compressor was released.

The trial fails if any connection does not negotiate deflate when offered,
or a fetch, burst, fan-out delivery or churn cycle returns other than the
expected events.

## Author × kind sweep (`author_kinds`)

Wok-only `--scenario author_kinds` measures time to EOSE of historical
`authors` × `kinds` REQs as the author list grows. Those are the outbox-model
fetches of profiles, contact lists and relay lists, and home feeds. The corpus
is large enough for the cost of each query plan to show. With
`--wok-baseline` every query shape also runs against a second wok binary on
the same database files, so a change can be compared before and after.

The dataset has `--authors` authors and `--events` events:

- Every author has one kind 0, 3, 10002 and 10050 event.
- The rest is kind 1, 7 and 6 history, in the ratio 60:30:10. History sizes
  follow a Zipf law over author rank, with exponent 0.8.
- Timestamps spread over two years before a fixed anchor, and events are
  imported in timestamp order, so authors interleave as they do on a relay.
- Mentions, reactions, reposts and follow lists name popular authors more
  often.

The dataset is generated and imported once for each combination of events,
authors and seed. It is kept under `--dataset-dir`, and later runs and both
binaries reuse its database. Delete the directory to rebuild it.

The query shapes:

- `authors` with kinds `[0,3,10002]` or `[0,3,10002,10050]` and no limit, so
  the relay's `max_filter_limit` applies. Also feeds of kinds `[1]` and
  `[1,6]` with limit 50 and `[1,6,7]` with limit 100, and a media feed of
  kinds `[20,21]` with limit 50, which no author in the dataset publishes.
- Each of those for 50, 100, 300, 333, 334, 500, 1,000 and 2,000 authors.
  Author lists sample authors in proportion to their activity, and each list
  extends the smaller ones. So 333 and 334 differ by one author, at strfry's
  1,000-pair bound for the PubkeyKind index.
- Guards that use other plans: `authors` with limit 100, `#p` with kinds,
  kinds alone, and 100 ids.

The relays run the harness's usual configuration, except that
`relay.max_req_filter_size` is raised to 1 MiB. The default is 256 KiB, which
fits 2,000 authors; the 64 KiB default of Wok 0.7 and earlier, which a
`--wok-baseline` build may have, refuses a REQ that names about 970 authors or
more.

Each shape and binary starts a relay on a fresh copy-on-write clone of the
dataset database (`cp -c` on macOS, `cp --reflink=auto` elsewhere). The first
query after the relay starts is the cold run. Warm runs follow, stopping
after `--warm-runs` runs or `--shape-secs` seconds, with at least three. The
binaries alternate which runs first. On a filesystem that cannot clone, the
copy leaves the file's pages cached, so the cold run is not cold.

| Option | Default | Meaning |
|---|---:|---|
| `--events` | 1,000,000 | Events in the dataset |
| `--authors` | 5,000 | Authors in the dataset |
| `--dataset-dir` | `bench-results/datasets` | Where datasets are kept for reuse |
| `--wok-baseline` | none | Second wok binary to measure on the same dataset |
| `--warm-runs` | 15 | Warm runs per shape, after the cold run |
| `--shape-secs` | 30 | Stop a shape's warm runs after this long (at least three run) |

Both binaries must be named `wok`. For example, to compare a change against
master, build master in a separate worktree:

```bash
git worktree add ../wok-master master
(cd ../wok-master && cargo build --release -p wok-cli)
cargo build --release -p wok-cli -p wok-bench
./target/release/wok-bench --scenario author_kinds --events 5000000 \
  --wok ./target/release/wok --wok-baseline ../wok-master/target/release/wok \
  --out bench-results/author_kinds
```

`summary.md` has one row per shape and author count:

- `author events`: the events those authors hold, which is what reading the
  Pubkey index for them costs;
- `events`: the events returned;
- cold, p50, p95, p99 and max time to EOSE for each binary, in milliseconds,
  and the p50 speedup;
- `same results`: whether the SHA-256 of the sorted returned ids matches.
  Any difference is a mismatch and fails the trial.

`results.jsonl` holds every row in the trial's `author_kinds` field.

## Tag × kind fetches (`tag_kinds`)

Wok-only `--scenario tag_kinds` measures time to EOSE of historical `#p` and
`#e` REQs that also name `kinds`: the notification, zap, DM-inbox and reaction
fetches clients send. Through the Tag index, Wok reads each candidate's
event to check its kind, so a pubkey or note that many events tag costs more
when few of those events have a requested kind. Once the `(tag, kind,
created_at)` index is complete, Wok seeks each (value, kind) pair in it
instead. With `--wok-baseline` every shape also runs against a second wok
binary on the same database files, as in `author_kinds`.

The dataset has `--authors` authors and `--events` events:

- Every author has one kind 0, 3, 10002 and 10050 event.
- Authors' histories are kind 1, 7, 6 and 1111 events, in the ratio
  55:31:10:4. History sizes follow a Zipf law over author rank, with exponent
  0.8.
- 4% of the events are zap receipts (kind 9735), signed by 16 zapper keys.
- 5% are gift wraps (kind 1059), each signed by a one-time key. Half
  `p`-tag a recipient drawn by popularity, half one drawn uniformly.
- Replies, reactions, reposts, comments and zaps name a note of a popular
  author and `p`-tag that author. Notes are drawn by a Zipf law over each
  author's 1,000 notes; they are named, not stored. Follow lists also name
  popular authors more often.
- Timestamps spread over two years before a fixed anchor, and events are
  imported in timestamp order.

As in `author_kinds`, the dataset is generated and imported once for each
combination of events, authors and seed, and kept under `--dataset-dir`.

The query shapes, each with limit 50 and limit 500:

- For three pubkeys (the most `p`-tagged, the one nearest 10,000 `p`
  postings, and the median): notifications (`#p` with kinds
  `[1,6,7,9735,1111]`), zaps (`#p` with kinds `[9735]`) and the DM inbox (`#p`
  with kinds `[1059]`).
- For the most tagged pubkey, `#p` alone, which reads the Tag index without
  reading events.
- For the most tagged note, reactions (`#e` with kinds `[7]`) and zaps (`#e`
  with kinds `[9735]`).

Before any relay starts, the bench reads each shape's postings from the
dataset's Tag index in the order Wok's scan reads them. It counts the events
a Tag-index plan reads before it has `limit` matches, and the relay must
return the same events. Any difference is a mismatch and fails the trial.

The relays run the harness's usual configuration, except that
`relay.auth.recipient_only_kinds` is empty. AUTH is off in the bench relay,
and by default gift wraps are readable only by their recipient after AUTH.
The scan is the same either way; AUTH adds a recipient check for each event
returned.

Each shape and binary starts `--cold-runs` relays, each on a fresh
copy-on-write clone of the dataset database, and the first query of each is a
cold run. Warm runs follow on the last relay, stopping after `--warm-runs` runs
or `--shape-secs` seconds, with at least three. The binaries alternate which
runs first. The same caveat as `author_kinds` applies: on a filesystem that
cannot clone, the cold runs are not cold.

| Option | Default | Meaning |
|---|---:|---|
| `--events` | 1,000,000 | Events in the dataset |
| `--authors` | 5,000 | Authors in the dataset |
| `--dataset-dir` | `bench-results/datasets` | Where datasets are kept for reuse |
| `--wok-baseline` | none | Second wok binary to measure on the same dataset |
| `--cold-runs` | 3 | Relay starts per shape and binary, each timing one cold query |
| `--warm-runs` | 15 | Warm runs per shape, after the cold runs |
| `--shape-secs` | 30 | Stop a shape's warm runs after this long (at least three run) |

For example, against a build of master in a separate worktree:

```bash
git worktree add ../wok-master master
(cd ../wok-master && cargo build --release -p wok-cli)
cargo build --release -p wok-cli -p wok-bench
./target/release/wok-bench --scenario tag_kinds --events 5000000 --cold-runs 5 \
  --wok ./target/release/wok --wok-baseline ../wok-master/target/release/wok \
  --out bench-results/tag_kinds
```

The dataset's database is imported by `--wok`. Before anything is timed,
`--wok` builds the `(tag, kind, created_at)` index into it if the database
lacks it or the index is incomplete (a dataset imported by an earlier
release), and the bench waits for the build. Otherwise each relay, started on
a fresh clone, would build the index in the background while its cold query
read the Tag index. A binary without that index, as `--wok` or
`--wok-baseline`, ignores the table. To measure another binary that derives
a new index at import, import the corpus with that binary (the first run with
it as `--wok` and a fresh `--dataset-dir` does this) and compare the other
binary on that database.

`summary.md` has one row per shape and limit:

- `postings`: the tag value's Tag index entries, and `matching` those of a
  requested kind;
- `events`: the events returned;
- `reads`: the events a Tag-index plan reads before EOSE. With `kinds` that
  is every posting until `limit` match, or all of them; without, only the
  events returned. A plan on the `(tag, kind, created_at)` index reads about
  as many entries and events as it returns;
- cold p50, p95 and max, and warm p50, p95, p99 and max time to EOSE, in
  milliseconds. With `--wok-baseline` the table shows cold p50 and warm p50,
  p95, p99 and max for each binary, the warm p50 speedup, and `same results`.

`results.jsonl` holds every row in the trial's `tag_kinds` field.

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

Feeds of 500 authors fit the default `relay.max_req_filter_size` of 256 KiB.
A connection's subscriptions must also fit
`relay.max_filter_bytes_per_connection` (2 MiB), about 31,000 authors in all:
ten feeds always do, but with `--live-subs-per-conn` near 100 and the default
author range, raise it or some subscriptions are refused.
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

### Qualifying the hosts

Before a campaign, and at the start of each day of runs,
`scripts/benchmark-qualify.sh` checks that the relay and load hosts are fit to
measure on. Run it from the operator host while both hosts are idle. With the
default durations it takes about ten minutes:

```bash
RELAY_SSH=root@RELAY LOAD_SSH=root@LOAD RELAY_HOST=10.0.0.2 \
  scripts/benchmark-qualify.sh
```

It records each host's CPU topology, NUMA layout, memory, disks, root
filesystem, transparent huge pages, swap and network interfaces. Then it
measures:

- on the relay's database filesystem: 4 KiB writes with `fdatasync`, which
  every LMDB commit waits on, and 4 KiB direct random reads at depth 1 and
  4×32. They run in a new `qualify.XXXXXX` directory under `DISK_DIR` (default
  `/var/lib/relay-bench`), and only that directory is removed afterwards;
- between the hosts, from the load host to `RELAY_HOST`: ping, and iperf3 with
  1 and 8 streams each way on port 5299;
- on each host: steal time while every CPU is busy.

`FIO_SECONDS`, `IPERF_SECONDS` and `STEAL_SECONDS` set the durations (60 each).
`OUT` (default `qualify-<UTC time>`) receives `summary.txt` with the headline
numbers, next to the raw fio, iperf3 and mpstat output. The script fails when
a measurement gives no result, when the CPU load behind the steal check did not
run, and when either host's average steal is above `STEAL_LIMIT` (1 percent):
a host lending its CPUs out does not give repeatable numbers.
Set `BASELINE` to an earlier run's directory, and it also fails when the
`fdatasync` p99 has moved by more than 2x since then: results from before and
after do not compare. Both hosts need fio, iperf3, sysstat, numactl, openssl and jq, and
the operator host needs jq.

### Reproducible two-host campaign

`scripts/benchmark-campaign.sh` runs a campaign from an operator host over SSH.
Any number of relay targets take turns on one relay host, and a second host
generates the load. It:

1. generates one signed corpus on the load host: realistic, or with
   `CORPUS_MIX=social` a public social relay's history of `SOCIAL_AUTHORS`
   authors;
2. copies and checksum-verifies that exact file on the relay host;
3. for each target, stops every benchmark relay, then restores the target's
   database snapshot or resets the database, imports with signature
   verification and confirms the exported retained count: the whole
   realistic corpus, or the `corpus.social.retained` count from the social
   corpus's `manifest.json`;
4. starts only that target, on an emptied page cache, and captures provenance,
   per-thread process, per-CPU, disk, socket, network, Prometheus, journal,
   binary/config hash, import and database-size evidence;
5. runs query latency, deep pagination and mixed reads/writes against the
   corpus (on a social corpus, the reads in
   [Reading a social corpus](#reading-a-social-corpus)), then scaled
   publication, live fanout, idle connections and lifecycle publication, and
   then the fixed-rate steps of `RATE_STEPS`, recording the load host's
   per-CPU utilization for each phase;
6. stops the relay and reconciles each fixed-rate step's outcome log with
   one export of its database; and
7. rotates the target order each repetition, so over as many repetitions as
   targets each target runs once in each position, and leaves every relay
   stopped.

Each target is a file on the relay host,
`/etc/relay-bench/targets/<name>.env`:

```sh
# wok or strfry
KIND=wok
BINARY=/opt/relay-bench/bin/wok-master/wok
CONFIG=/etc/relay-bench/wok-master.toml
PORT=7777
# Optional: Prometheus endpoint, checkout whose commit is recorded, and
# service account (created if missing).
METRICS_URL=http://10.0.0.2:7777/metrics
SOURCE=/opt/relay-bench/src/wok-master
USER=relay-bench
```

Comments go on their own lines. `CONFIG` must put the database in
`/var/lib/relay-bench/<name>/db`: Wok's `[database] path`, or strfry's `db`.
The helper reads that setting before it checks, imports into or starts a
target, and each relay and its import can write only under its own
`/var/lib/relay-bench/<name>`. Name targets for what they
run, such as `strfry-1.1.3`, `wok-0.7.0` and `wok-master`. Two configurations
of one binary, such as limits off and a preset as shipped, are two targets
with two databases. strfry raises its open-file limit to `relay.nofiles`
(1,000,000 by default) whenever it starts, imports and exports included, and
exits when that is above the unit's limit (`NOFILE_LIMIT`, default 524288).
The helper applies that limit to the relay, its import and the export that
counts what it kept. So set `relay { nofiles = 0 }` in a strfry target's
config, or raise `NOFILE_LIMIT`. The relay host needs systemd with cgroup v2, sysstat
(`pidstat`, `mpstat`, `iostat`), iproute2, curl, GNU time and util-linux's
`fincore`. The load host needs systemd, `wok-bench`, GNU time, jq and
sysstat. The relay-side helper refuses
artifact paths outside `/opt/relay-bench/{campaigns,results}`. Prometheus
evidence needs `observability.metrics_enabled = true` and `METRICS_URL`.

Each relay runs as the transient unit `relay-bench-target-<name>.service`,
and its import runs under the same limits:

- `RELAY_CPUS` pins it with `AllowedCPUs`. On a host with hyperthreads, list
  both threads of each core (`lscpu -e` shows which CPUs share a core): for
  example `0-7,24-31` where each core's second thread is numbered 24 higher,
  or `0-15` where a core's threads are adjacent.
- `RELAY_MEMORY` caps it with `MemoryMax`, for example `64G`. Under cgroup
  v2 the cap includes the page cache the relay reads through, so a database
  larger than the cap stays disk-bound on a host with more memory.
- The helper records the cgroup's `cpuset.cpus.effective` and `memory.max`
  beside each run, and fails the start unless the CPU set is the requested
  one and the smallest `memory.max` of the unit and its parent cgroups is
  the requested size.

Every start drops the page cache first. With `CACHE=cold` (the default) the
relay starts on an empty cache. `CACHE=warm` reads the database files inside
the relay's unit before the relay starts, so warmed pages count against its
cap; raise `READY_TIMEOUT` (seconds, default 120) for a large database. A
warm start fails when the database is at least `RELAY_MEMORY`, or when any
database file is not wholly in the page cache once the relay listens
(`cache-at-start.txt` lists each file's size and cached bytes): a database
larger than the cap can only be measured cold.

With `SNAPSHOTS=1` (the default), a target's first import is copied to
`/var/lib/relay-bench/snapshots/<name>`, reflinked where the filesystem
allows, and later repetitions restore it instead of importing again.
`prepare.txt` in each run's server evidence says which happened. A snapshot is
used only when its kind, binary, config, corpus and event count match the
run's; otherwise the target imports again and replaces it. Each target keeps
one snapshot, so a large corpus over several targets needs room for a copy of
each, or `SNAPSHOTS=0`. Import timing is recorded only for imports.
`benchmark-relay-control drop-snapshot <name>` deletes one.

On the load host, the generator and its `mpstat` sampler run as the transient
units `relay-bench-load-<campaign>` and `relay-bench-load-<campaign>-mpstat`.
A campaign stops every `relay-bench-load-*` unit when it exits or is
interrupted, and again before it starts, in case an earlier campaign lost
its connection. `LOAD_CPUS` pins the generator's unit. To
run the generator beside the relay over loopback, set `LOAD_SSH` to the relay
host's destination, `RELAY_HOST` to `127.0.0.1` and `LOAD_CPUS` to CPUs
outside `RELAY_CPUS`. This suits scenarios whose traffic the network between
the hosts would otherwise limit. Report loopback and network results
separately.

```bash
# Three targets, three rotated repetitions, the relay held to 16 vCPU and 64 GB.
RELAY_SSH=root@RELAY_SSH_IP LOAD_SSH=root@LOAD_SSH_IP RELAY_HOST=RELAY_PRIVATE_IP \
  TARGETS="strfry-1.1.3 wok-0.7.0 wok-master" \
  RELAY_CPUS=0-7,24-31 RELAY_MEMORY=64G \
  ./scripts/benchmark-campaign.sh

# Short end-to-end validation before a measured campaign.
RELAY_SSH=root@RELAY_SSH_IP LOAD_SSH=root@LOAD_SSH_IP RELAY_HOST=RELAY_PRIVATE_IP \
  TARGETS="strfry-1.1.3 wok-master" CAMPAIGN_ID=shakeout EVENTS=2000 \
  REPETITIONS=1 QUERIES=50 DEEP_PAGES=2 PUBLISH_CONNECTIONS=16 \
  FANOUT_SUBSCRIBERS=16 FANOUT_EVENTS=50 IDLE_CONNECTIONS=128 HOLD_SECONDS=2 \
  LIFECYCLE_EVENTS=200 LIFECYCLE_CONNECTIONS=1 COOLDOWN_SECONDS=1 \
  ./scripts/benchmark-campaign.sh
```

`RELAY_SSH`, `LOAD_SSH`, `RELAY_HOST` (the relay host's address as the load
host reaches it) and `TARGETS` are required. The other settings are
`RELAY_CPUS`, `RELAY_MEMORY`, `CACHE`, `SNAPSHOTS`, `READY_TIMEOUT`,
`LOAD_CPUS`, `BENCH_BIN`, `RELAY_BENCH_BIN`, `CAMPAIGN_ID`, `EVENTS`,
`CORPUS_MIX`, `SOCIAL_AUTHORS`, `QUERIES`, `DEEP_PAGES`, `REPETITIONS`,
`PUBLISH_CONNECTIONS`, `FANOUT_SUBSCRIBERS`, `FANOUT_EVENTS`, `FANOUT_WINDOW`,
`IDLE_CONNECTIONS`, `HOLD_SECONDS`, `LIFECYCLE_EVENTS`,
`LIFECYCLE_CONNECTIONS`, `RATE_STEPS`, `RATE_SECS`, `RATE_DRAIN_SECS`,
`RATE_CONNECTIONS`, `RATE_P99_MS`, `NOFILE_LIMIT`, `COOLDOWN_SECONDS`, `SEED`
and `BASE_TIMESTAMP`.

A social corpus needs targets that accept its largest events: its manifest
gives `needed_max_event_size`, and strfry's default `events.maxEventSize` of
64 KiB is too small. A target that refuses some fails the retained-count
check at import.

#### Fixed-rate capacity steps

`RATE_STEPS` lists rising rates in events per second, for example
`"1000 2000 5000 10000 20000"`. After the other phases, each target runs
`ws_publish_rate` at each rate in turn for `RATE_SECS` (default 180) over
`RATE_CONNECTIONS` connections (default 64), waiting up to `RATE_DRAIN_SECS`
(default 10) for the last replies. Each step signs fresh realistic events from
its own seed, `SEED` plus the step's position. A step meets its targets when
the relay kept up with the whole schedule: every event was sent at the
intended rate on connections that stayed open, and each was accepted, none
refused or left unanswered, with publish-to-OK p99 within `RATE_P99_MS`
(default 250). The sweep stops after the first step that misses, and
`rate-capacity.txt` beside the phases records the last step that met its
targets (`capacity`, 0 for none) and the first that missed. A missed step is a
result, not a failed campaign. A step that left no fixed-rate report, and so
no complete outcome log, fails the campaign, as does an OK that names no event
its connection sent.

Once the relay has stopped, the campaign copies each step's outcome log to
the relay host. `benchmark-relay-control reconcile` exports the database
once, under the import's limits, and runs the relay host's `wok-bench`
(`RELAY_BENCH_BIN`, default `/opt/relay-bench/bin/wok-bench/wok-bench`)
with `--reconcile` against each log. Each step's `reconciliation.json` is
copied back beside its results. The campaign fails when a step it started
has no outcome log, when a log holds fewer events than its step planned, or
when an acknowledged event is missing from the export or a refused one was
stored. This runs even when the relay stopped on its own during the run. The relay host's `wok-bench` must
include `--reconcile`.

Lifecycle publication defaults to one ordered connection because a deletion
request must follow the event it references. Scaled publication is measured in
the separate realistic workload; increasing `LIFECYCLE_CONNECTIONS` tests
cross-stream ingestion ordering as a distinct experiment. The historical
corpus keeps one fixed timestamp and byte-identical signatures; each lifecycle
phase uses a freshly recorded timestamp so short-lived ephemerals remain valid.

Load-side artifacts live under `/opt/wok-load/results/<campaign-id>` and
contain the corpus, campaign metadata, every harness result, `/usr/bin/time`
and `mpstat` output, and a copy of each server-side evidence directory.
Server originals remain under `/opt/relay-bench/campaigns/<campaign-id>`. Do
not compare speed for any phase whose `results.jsonl` has `ok=false`, non-zero
`errors`, or non-zero `mismatches`.

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
server resources, and leaves both relays stopped. It runs the relay targets
(see the two-host campaign above) named by `WOK_TARGET` (default `wok`) and
`STRFRY_TARGET` (default `strfry`). Both listen at `WS_URL`, one at a time,
and the Wok target's config must enable the Unix socket at `WOK_UNIX_SOCKET`
(default `/var/lib/relay-bench/<wok target>/wok.sock`).

```bash
# Defaults: 100k events, three rotated repetitions.
RELAY_SSH=root@RELAY_SSH_IP LOAD_SSH=root@LOAD_SSH_IP \
  WS_URL=ws://RELAY_PRIVATE_IP:7777 ./scripts/benchmark-transports.sh

# Fast end-to-end transport shakeout.
RELAY_SSH=root@RELAY_SSH_IP LOAD_SSH=root@LOAD_SSH_IP \
  WS_URL=ws://RELAY_PRIVATE_IP:7777 CAMPAIGN_ID=transport-shakeout \
  EVENTS=2000 REPETITIONS=1 QUERIES=40 PUBLISH_CONNECTIONS=8 \
  FANOUT_SUBSCRIBERS=8 FANOUT_EVENTS=30 IDLE_CONNECTIONS=64 HOLD_SECONDS=1 \
  COOLDOWN_SECONDS=1 ./scripts/benchmark-transports.sh
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

## Time slices of many-filter REQs

`crates/wok-query/tests/timeslice.rs` holds an ignored test that times the
slices of one REQ with many filters, in process, through a `QueryScheduler`
as a req worker runs it. It uses only public `wok-query` API, so the same file
runs unchanged against older revisions.

```bash
cargo test --release -p wok-query --test timeslice -- --ignored --nocapture
```

- `EVENTS` (20000) stored kind-1 notes each mention `FILTERS` (30) accounts.
  The REQ has one filter per account, `{"kinds":[7],"#p":[<account>],
  "limit":500}`, so each filter reads every note and finds no match.
- It runs in slices of `BUDGET_US` (10000). A small REQ,
  `{"kinds":[1],"limit":5}`, arrives every `ARRIVAL_US` (2000) and runs
  before the many-filter REQ's next slice, as a new query does on a req
  worker.

Each of three rounds prints the many-filter REQ's time to its end, then
sample counts and p50/p90/p99/max for its slice lengths and for each small
REQ's time from arrival to its end. The longest slice is how long a query
can wait behind it. Set `EVENTS` large enough that one filter takes longer
than a slice to see each filter's checks; set `ARRIVAL_US` past the run's
length to time the many-filter REQ alone.

## Read visibility cost per event

`crates/wok-query/tests/visibility_cost.rs` holds an ignored test that times
history scans in process, so read visibility is a large share of what it
measures. It uses only public `wok-query` API, so the same file runs unchanged
against older revisions.

```bash
cargo test --release -p wok-query --test visibility_cost -- --ignored --nocapture
```

The database holds `NOTES` (200000) kind-1 notes by `AUTHORS` (1000)
authors, and a kind 0 and kind 3 event for each author. Three queries run
`RUNS` (21) times each:

- `{"kinds":[1],"limit":2000}`;
- every author with kinds `[0,3]`, which are replaceable, so each event also
  gets a replacement check;
- a COUNT of every note.

They run four times, as policy records are added: none, then 1,000 banned
pubkeys and 1,000 banned event ids, then a kind policy without kind 7, then
1,000 NIP-62 vanish markers. None of the records hides an event the queries
match, so each row times only the checks. Each row prints the events sent,
the median time and the time per event.

## REQ path latency for client traffic shapes

`crates/wok-compat/tests/req_path_latency.rs` holds three ignored tests that
time the REQ path the way clients use it. Like `eose_latency.rs`, they drive an
in-process relay through the public `RelayHandle` API, so the same file runs
unchanged against older revisions. The relay has default limits, with abuse
controls and AUTH off. Its corpus of kind-1 events is written straight to
LMDB before it starts.

```bash
cargo test --release -p wok-compat --test req_path_latency -- \
  --ignored --nocapture --test-threads 1
```

- `close_then_req` repeats `ROUNDS` (100) times: open `CLOSE_SUBS` (50) live
  subscriptions, CLOSE them all, then send one `{"kinds":[1],"limit":5}`. It
  times that REQ to its EOSE.
- `req_bursts` has `CONNS` (100) connections each send a burst of small REQs
  at once, `ROUNDS` (5) times: 30, then 60, or only `BURST` when it is set.
  Each sample runs from its connection's first REQ to one EOSE.
- `fanout_many_connections` opens `CONNS` (2000) connections with `SUBS` (5)
  live subscriptions each that match every published event. It publishes
  `RATE` (200) events a second for `SECS` (10) seconds and times each
  delivered frame from publication to receipt. Sequential REQ → EOSE probes
  run alongside.

Both `close_then_req` and `req_bursts` run their probes twice: first idle,
then while every req worker is busy. For the busy run, `HEAVY` (2) connections
per req worker send NIP-50 searches one after another. Each search matches the
whole corpus of `CORPUS` (200,000) events. Two `heavy search` lines follow:
how many searches were sent while the probes ran, and how long each took to
EOSE. A change that helps the probes at the searches' expense shows there.

Each line gives the sample count and p50/p90/p99/max in milliseconds. Read
the heavy lines against the idle ones from the same run. Run each revision at
least three times, alternating, and compare medians.
