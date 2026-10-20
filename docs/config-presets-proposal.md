# Limits, defaults and configuration presets: proposal

Status: **approved plan**. The owner's decisions are recorded in §8. No code
has changed yet. Written on 2026-10-20 against
`ef4650c` (0.7.0).

This builds on the 2026-10-20 NIP compliance and client-workload audit, which
is cited here by finding ID (C2–C7, B3, B13, W1–W10). That audit reproduced the
client collisions on the wire. This document turns them into defaults, a
configuration model and an implementation plan.

The owner's decisions it works from:
- The defaults target a general public relay.
- Running Wok as a Marmot relay is the primary real use case.
- Operators need configuration that is easy to understand, an admin screen
  that explains each trade-off, and preset templates.

Bugs are out of scope here: data loss, the subscription-replacement leak and
NIP-01 MUSTs. Where a default depends on one of those fixes, this document says
so.

## 0. Summary

- **Presets.** Add one top-level key, `preset = "public" | "marmot"`.
  Configuration resolves in three layers: built-in defaults, then the preset,
  then the operator's file. The built-in defaults *are* the public preset. A
  preset is a small TOML overlay that ships in the binary and is published in
  `docs/presets/`.
- **Defaults that break clients today.** These change in the public preset:
  - the 3-year lower bound on `created_at` becomes off;
  - the REQ budget moves from per IP to per connection, with a per-address
    backstop;
  - negentropy rounds get their own budget instead of drawing on the REQ
    budget;
  - the query-cost model counts `limit` and real index work;
  - the filter byte cap rises to 256 KiB;
  - the per-filter `limit` clamp rises to 2,000, so MDK's 1,200-event
    directory batches fit;
  - `max_tags_per_filter` rises to 8;
  - `max_num_tags` rises to 5,000;
  - AUTH and kind 21059 get the timestamp windows their NIPs call for.
- **Access as policy, not flags.** `restricted_read_kinds`,
  `restrict_read_to_involved_pubkey` and `restrict_writes` become:
  - three read classes: recipient-only, owner-only and authenticated-only;
  - a `read_policy` and a `write_policy`, each `open`, `authenticated` or
    `members`;
  - `inbox_kinds`.

  Writes are checked against the AUTHed identity, not the event author (C7).
- **Existing files.** Four problems would otherwise make presets useless:
  - `docs/wok.toml` pins every default;
  - dashboard saves rewrite the whole file;
  - two settings have the same name (`max_filters_per_req`);
  - AUTH currently *lowers* a client's REQ budget.

  This proposal fixes all four.
- **Measurement.** Every changed default gets a client-realistic benchmark
  scenario with abuse controls *on*, plus an adversarial scenario. Today's
  benchmarks disable abuse controls, so they cannot validate any of these
  numbers.

## 1. How limits work today

Order of checks for an EVENT:
1. connection budget (per IP);
2. EVENT budget (per IP);
3. size, tag and timestamp checks (`events.*`);
4. kind policy, bans and `restrict_writes`;
5. proof of work;
6. EVENT budget per author;
7. NIP-70;
8. the writer's storage quotas and disk reserve.

Order of checks for a REQ:
1. REQ budget (per IP, plus a per-pubkey bucket once AUTHed);
2. filter count;
3. serialized filter bytes;
4. parse limits (`max_tags_per_filter`, `max_and_entries`, tag value size);
5. `filter_validation`;
6. query cost;
7. read gate;
8. per-connection scan concurrency;
9. the scan itself (`limit` clamp, `max_total_events_per_req`, timeslice);
10. the live monitor (`max_subs_per_connection`).

The reading for this proposal found these issues in addition to the audit's:

| # | Finding | Where |
|---|---|---|
| F1 | AUTH makes the REQ budget *stricter*. An AUTHed REQ must pass both the per-IP bucket and a per-pubkey bucket with the same rate. | `server.rs:1580-1584`, `:2394-2397` |
| F2 | A REQ over `max_concurrent_historical_queries` (8) is refused with `CLOSED "rate-limited: too many concurrent historical queries"`. It is not queued, so a startup burst on a busy relay loses REQs even within the token budget. | `server.rs:2563-2575`, `scheduler.rs:43` |
| F3 | Two settings share the name `max_filters_per_req`: `relay.max_filters_per_req = 200` and `relay.filter_validation.max_filters_per_req = 3`. Kinds are also filtered in three places: the `filter_validation.allowed_kinds` query filter, the NIP-86 write kind policy, and nothing for writes in config. | `config.rs:380,409` |
| F4 | `docs/wok.toml` writes out every default. Operators who copied it have pinned every value, so changing a default or adding a preset changes nothing for them. Dashboard saves re-serialize the complete config, which flattens comments and would erase a `preset` line. | `docs/wok.toml`, `admin.rs:438-465` |
| F5 | The cost model ignores how many values a tag filter has and how many (author, kind) pairs a filter has. `{"authors":[2000],"kinds":[50 kinds]}` costs 5, yet it opens 100,000 cursors. Above 1,000 pairs it falls back to the Pubkey index (C6). | `filter.rs:467-508` |
| F6 | The per-author quota nets out replacements, so a user at quota can still update a profile. It does count kind-5 deletions, though, so an author at quota cannot delete events to get back under it. | `wok-db/src/write.rs:714-727` |
| F7 | `max_stored_events = 10,000,000` is a global cliff. When it is reached, every write on the relay fails. A busy public relay stores far more than that. | `writer.rs:384` |
| F8 | The memory used by live filters is bounded only by `max_subs_per_connection × max_req_filter_size` (200 × 64 KiB = 12.8 MiB per connection). Raising the per-REQ byte cap without a per-connection budget multiplies that figure. | — |
| F9 | `max_num_tags = 2000` rejects the kind-3 follow lists of heavy users. | `parse.rs:179` |
| F10 | NIP-11 is out of step with the configuration: <ul><li>`created_at_lower_limit` and `max_query_cost` are advertised even when the check is off (0) or `abuse.enabled = false`;</li><li>`max_subid_length`, `restricted_writes` and `auth_required` are missing (B12).</li></ul> | `wok-ws/src/lib.rs:322-345` |
| F11 | The per-author EVENT budget and the storage quota key on the event author. Marmot 445 (fresh key per event) and 1059 (random key) are never charged. | `server.rs:1847`, `write.rs:714` |
| F12 | A filter can list at most 2,047 authors or `#p` values, because each value set is capped at 65,535 decoded bytes. This holds whatever `max_req_filter_size` is set to. | `filter.rs:50-53` |
| F13 | `filter_validation.require_author_or_tag` requires *exactly one* author, `#p` or `#e` value. It refuses `#h` group filters, `ids` fetches and multi-author directory batches, which covers most of what a Marmot client sends. | `filter.rs:544-573` |

## 2. Inventory

Columns:
- **Now:** the current default.
- **Protects:** what the limit actually guards.
- **Collides with:** which normal client behaviour hits it.
- **Public:** the recommended value for a general public relay.

"Keep" means the current value is fine. Hard-coded limits are listed at the end of §2.3 and in the appendix.

### 2.1 Event acceptance (`[events]`)

| Setting | Now | Protects | Collides with | Public |
|---|---|---|---|---|
| `max_event_size` | 1 MiB | Memory per message and per stored record | <ul><li>Marmot Welcomes carry the full ratchet tree.</li><li>Add commits carry every new member's KeyPackage.</li><li>Both grow linearly with group size. MDK accepts single events up to 5 MiB and uses extended-length NIP-44.</li></ul> | Keep 1 MiB. The marmot preset uses 4 MiB (provisional; measure Welcome size at 100, 500 and 1,000 members) |
| `max_num_tags` | 2,000 | Write amplification: each single-letter tag adds a tag-index entry | Kind-3, 10000 and 30000 lists of heavy users (F9) | **5,000** (measure write cost) |
| `max_tag_val_size` | 1,024 B | Bloat from long single-letter tag values | <ul><li>One long `r`, `t` or `a` value rejects the whole event.</li><li>Values of 256–1,024 B are stored but not indexed (A2, bug).</li></ul> | Keep until A2's hashed index lands, then 4,096 |
| `reject_newer_than_secs` | 900 | Future-dated events pinned to the top of feeds | Clocks more than 15 min fast (rare) | Keep |
| `reject_older_than_secs` | 3 years | Nothing meaningful. Old events sort to the bottom, and storage volume is bounded by rates and quotas | Rebroadcasting old kind 0/3/10002, importing history, rebroadcasting kind 5 (C2) | **0 (off)**. If an operator sets a bound, replaceable, addressable, 5 and 62 are always exempt (§3.5) |
| `reject_ephemeral_older_than_secs` | 60 | Replayed ephemeral events (NIP-46) reaching live subscribers | <ul><li>AUTH signed more than 60 s earlier (B3).</li><li>Every spec-built 21059, which is backdated by up to 2 days (B3).</li></ul> | Keep 60 for generic ephemeral kinds. AUTH and 21059 get their NIP windows as constants (§3.5) |
| `ephemeral_persistence` / `ephemeral_lifetime_secs` | `live_only` / 300 | Storage of ephemeral kinds | — | Keep |

### 2.2 Transport and request size (`[relay]`)

| Setting | Now | Protects | Collides with | Public |
|---|---|---|---|---|
| `max_websocket_payload_size` | 2 MiB | Parse memory per message (NIP-11 `max_message_length`) | — | Keep. Validate that it is at least `max_event_size` plus envelope and at least `max_req_filter_size`. Frame buffers grow on demand, so a larger value costs memory only while large frames are actually in flight |
| `max_req_filter_size` | 64 KiB | Parse and live-matching memory per REQ | Outbox author lists above ~978 authors (C5, W2) | **256 KiB** (about 3,900 authors), plus a new per-connection filter budget of 2 MiB (F8) |
| `max_filters_per_req` | 200 | Fan-out per REQ | Nothing seen (NDK batches about 45) | Keep |
| `max_pending_outbound_bytes` | 32 MiB | Memory held for a slow reader | Large backfills on slow links disconnect, which is the intended behaviour | Keep |
| `auto_ping_seconds` | 55 | Dead TCP connections | — | Keep |
| `handshake_timeout_secs` | 10 | Slowloris attacks on upgrade | — | Keep |
| `frame_read_timeout_secs` | 30 | Slow-trickle frames | — | Keep |
| `real_ip_header` | empty | Determines which client every per-address budget charges | Behind a proxy with this empty, every client shares the proxy's budget | Keep empty. Warn at startup when every peer is loopback or private and the header is unset |
| `unix.max_frame_bytes` / `unix.max_pending_outbound_bytes` | 2 MiB / 32 MiB | Same as WebSocket | — | Keep |

### 2.3 Queries (`[relay]`, `[relay.abuse]`, `[relay.filter_validation]`)

| Setting | Now | Protects | Collides with | Public |
|---|---|---|---|---|
| `max_filter_limit` | 500 | Rows per filter (NIP-11 `max_limit` and `default_limit`) | <ul><li>Outbox metadata fetches without `limit` are silently cut to 500 events.</li><li>MDK directory batches ask for `limit = 200 authors × 6 kinds = 1,200` and are cut, so some KeyPackages and relay lists go missing.</li></ul> | **2,000**. Later, replaceable-kind author fetches may return up to authors × kinds (§3.4) |
| `max_total_events_per_req` | 2,000 | Rows per REQ | NDK merged batches and outbox fetches are truncated silently (C1) | **10,000**. Memory stays bounded by the outbound queue |
| `max_tags_per_filter` | 3 | Residual tag checks per candidate | Filters that combine four or more tag letters (NIP-22 `#E`/`#K`/`#P` with `#k`, marketplace `#t`/`#g`/`#d`/`#k`) | **8**. Each extra letter is a cheap per-candidate check |
| `max_and_entries` | 16 | NIP-91 checks per candidate | NIP-91 is still a draft (B12) | Keep |
| `max_filter_limit_count` | 1,000,000 | COUNT de-duplication memory | — | Keep |
| `max_subs_per_connection` | 200 | Live-index memory per connection (NIP-11 `max_subscriptions`) | Nothing seen (clients use 30–100) | Keep |
| `query_timeslice_budget_us` | 10,000 | Fairness between running scans | The W5 latency is structural, not caused by this knob | Keep (advanced) |
| `abuse.max_concurrent_historical_queries` | 8 | Scan fairness per connection | A ninth concurrent scan is refused instead of waiting (F2) | Keep 8, but **queue** the excess (bounded by `max_subs_per_connection`) |
| `abuse.max_query_cost` | 1,000 | Expensive scans, checked before a cursor opens | <ul><li>Rejects `authors[150]`, an 11-kind feed and 45-filter batches.</li><li>Lets 100k-cursor fan-outs through (F5).</li><li>Uses the wrong prefix (C4).</li></ul> | **New model, ceiling 20,000** (§3.4) |
| `filter_validation.enabled` and its rules | off | Optional structural rules, inherited from a strfry plugin | <ul><li>Once enabled, its own `max_filters_per_req = 3` and `max_kinds_per_filter = 3` break most clients.</li><li>`require_author_or_tag` breaks Marmot and outbox clients (F13).</li></ul> | Keep off. Drop the duplicate counts (F3). Add `require_scoped_filters`, which the marmot preset uses (§3.7) |
| *hard:* tag filter value | 255 B | Index key size | `#d`, `#a` and `#r` values over 255 B cannot be queried | Fix with A2 hashing (bug track) |
| *hard:* one filter's value set | 65,535 decoded B | Memory per set | At most 2,047 authors or `#p` per filter (F12) | Keep. Document it, because it caps outbox lists before the byte cap does |

### 2.4 Rates (`[relay.abuse]`)

| Setting | Now | Protects | Collides with | Public |
|---|---|---|---|---|
| `enabled` | true | Turns every guard below on or off | Benchmarks turn it off, so nothing below is measured | Keep |
| `connection_rate_per_second` / `_burst` | 10 / 50 per IP | Connection floods and handshake CPU | <ul><li>CGNAT reconnect storms.</li><li>IPv6 clients evade it by rotating their /128.</li></ul> | Keep the values. **Group IPv6 by /64** |
| `event_rate_per_second` / `_burst` (also AUTH) | 50 / 100 per IP | Signature-verification CPU and write volume | Marmot add-member bursts (a commit plus N Welcomes) in large groups; CGNAT | Keep, per address (/64) |
| `pubkey_event_rate_per_second` / `_burst` | 25 / 50 per author | One key flooding the relay | Never charged for throwaway-key kinds such as 445 and 1059 (F11) | Keep. Charge the connection's AUTHed identity when the author is not one of its identities |
| `req_rate_per_second` / `_burst` (also NEG-OPEN, NEG-MSG, replacements) | 20 / 40 per IP, plus per AUTHed pubkey | Scan CPU and monitor churn | <ul><li>A 60-REQ startup gets 20 `CLOSED` (C3).</li><li>NAT and VPN users share one budget.</li><li>AUTH lowers the budget (F1).</li><li>A Marmot client in G groups sends at startup:<ul><li>about 2G REQs and NEG-OPENs, plus about 2G NEG-MSG rounds;</li><li>up to 16 `ids` fetches per pass.</li></ul></li></ul> | **Per connection 20 / 100. Per-address backstop 200 / 1,000. AUTHed connections ×4. NEG-MSG gets its own per-connection bucket** (§3.3) |
| `count_rate_per_second` / `_burst` | 5 / 10 per IP | COUNT scans, which have no limit | A page of 10 or more counts behind CGNAT | **Per connection 5 / 20**, per-address backstop 20 / 50 |
| `invalid_rate_per_second` / `_burst` | 5 / 20 per IP | Amplification through error replies | Nothing (only malformed messages are dropped) | Keep |

### 2.5 Storage (`[relay.abuse]`, `[database]`)

| Setting | Now | Protects | Collides with | Public |
|---|---|---|---|---|
| `max_stored_events` | 10,000,000 | Disk exhaustion | A busy relay reaches a cliff where every write fails (F7) | **0 (off)**. Rely on `database.min_free_disk_bytes` and `map_size`, which measure the actual resource |
| `max_stored_events_per_pubkey` | 100,000 | One key filling the disk | <ul><li>Heavy users and bots.</li><li>At quota, kind-5 deletions are refused (F6).</li><li>Not charged for throwaway keys (F11).</li></ul> | **1,000,000**, with kind 5 exempt (62 is already exempt) |
| `min_pow_difficulty` | 0 | Spam | Any nonzero value rejects most clients | Keep |
| `database.min_free_disk_bytes` | 1 GiB | Full disk | — | Keep |
| `database.map_size` | 64 GiB | LMDB map ceiling | Depends on the deployment | Keep. Document it as the real storage cap |

### 2.6 Sync (`[relay]`)

| Setting | Now | Protects | Collides with | Public |
|---|---|---|---|---|
| `negentropy_enabled` | true | — | — | Keep |
| `max_sync_events` | 1,000,000 | Size of the temporary view | Very large syncs fail explicitly, as intended | Keep |
| `sync_memory_per_connection` / `sync_memory_total` | 256 MiB / 1 GiB | Memory | Four concurrent full syncs use up the pool | Keep. Revisit with PLAN priority 2 measurements |
| `sync_idle_timeout_secs` | 60 | Idle sessions | — | Keep |

### 2.7 Access (`[relay.auth]`, `[admin]`, NIP-86)

| Setting | Now | Protects | Collides with | Public |
|---|---|---|---|---|
| `auth.enabled` | true | — | — | Keep |
| `auth.service_url` | empty | AUTH cannot complete until this is set, and restricted reads fail closed | DM and gift-wrap clients get `restricted:` with no challenge | Keep empty, because it depends on the deployment. The marmot preset **refuses to start** without it |
| `auth.restricted_read_kinds` | `[4, 1059]` | Metadata of private messages | <ul><li>21059 can be read by anyone (A5).</li><li>78 and 30078 are open (B13).</li></ul> | Becomes `recipient_only_kinds = [4, 1059, 21059]` and `owner_only_kinds = [78, 30078]` (§3.6) |
| `auth.restrict_read_to_involved_pubkey` | true | The per-event delivery filter | Setting it to `false` leaks restricted kinds in mixed REQs | **Remove** the `false` mode. Its intent becomes `authenticated_kinds` (§3.6) |
| `auth.restrict_writes` | false | Allowlist | Checks the event author, so 445 and 1059 from throwaway keys are refused (C7) | **Replace** with `write_policy`, checked against the AUTHed identity |
| AUTH timestamp window (reuses the 60 s ephemeral window) | 60 s | AUTH replay, although each AUTH is already bound to a per-connection challenge | Phone clocks 2 min off (B3) | **±600 s constant** (NIP-42 says "~10 minutes") |
| `admin.auth_window_secs` | 60 | NIP-98 replay | An admin clock off by more than 60 s | Keep |
| `write_policy_timeout_secs` | 10 | Plugin hangs | — | Keep |
| NIP-86 kind policy (stored in LMDB) | all kinds | Kinds written | `listallowedkinds` returns all 65,536 kinds (B14) | A new config key `accepted_kinds` sets the ceiling, and NIP-86 can narrow it |

## 3. Proposed configuration model

### 3.1 Principles

1. Each limit states the resource it protects and the unit it is keyed on:
   per connection, per address, per identity, per author, or global. The key
   name or its section says which.
2. A limit that real clients reach in normal use is a bug in the default. It
   is not a feature of the relay.
3. Refusals use a prefix that tells the client whether a retry can help.
   `rate-limited:` is reserved for buckets that refill.
4. Values that a NIP fixes are constants, not knobs. Examples are the AUTH
   window and the 21059 backdating allowance.
5. Fewer knobs:
   - remove duplicates (F3);
   - remove footgun modes (`restrict_read_to_involved_pubkey = false`);
   - remove cliffs that duplicate a real guard (F7).

### 3.2 Presets: selection, layering, provenance

A complete public relay looks like this:

```toml
# wok.toml
preset = "public"            # optional; "public" is the default

[relay]
bind = "0.0.0.0"
real_ip_header = "x-forwarded-for"

[relay.auth]
service_url = "wss://relay.example.com"

[relay.info]
name = "Example relay"
contact = "mailto:ops@example.com"
```

- **Resolution order:** built-in defaults, then the preset overlay, then this
  file. Each layer replaces individual keys and does not reset whole sections.
  This is the existing `merge_toml` with one more layer. Unknown keys are still
  rejected.
- **Where presets live:** `crates/wok-relay/presets/marmot.toml` (and later ones),
  compiled in with `include_str!` and copied to `docs/presets/`. The public
  preset is the built-in defaults, so `public.toml` is empty apart from
  comments. An overlay contains only the keys it changes, which keeps each one
  readable on a single screen.
- **Provenance:** `wok config show` prints the effective configuration, with
  each value's origin:

  ```text
  events.reject_older_than_secs = 0           # preset public
  relay.abuse.per_connection.req_burst = 100  # preset public
  relay.auth.service_url = "wss://relay…"     # wok.toml:9
  relay.abuse.event_burst = 500               # wok.toml:14 (preset marmot: 300)
  ```

  `wok config show --overrides` prints only what the file changes relative to
  its preset.
- **Reload:** changing `preset` on reload is allowed. Every effective change
  goes through the existing `security_scope_changes` warnings. Changes to read
  or write policy are logged at `warn`, naming the old and new policy.
- **Validation per preset:** `marmot` refuses to start without
  `relay.auth.service_url`, because gift-wrap reads depend on AUTH. `public` keeps today's
  warning.
- **Dashboard writes** patch the file in place with `toml_edit`. The patch
  keeps comments, key order and `preset`, and writes only keys whose value
  differs from the preset. Setting a key back to its preset value removes the
  line. The full config is still serialized and validated before the atomic
  rename.
- **Upgrades:** presets follow releases. Every change to a preset value is a
  release-note item under "Preset changes", and startup logs `preset=public
  wok=0.8.0`. An operator who needs a value to stay fixed sets it in the file.
- **Existing files (F4):** `docs/wok.toml` becomes a short annotated file like
  the example above. The full key reference moves to `docs/config.md` and to
  `wok config show --defaults`. `wok doctor` gains a check that lists keys
  pinned to a value equal to an earlier release's default but different from
  the current preset ("`reject_older_than_secs = 94608000` was the 0.7 default;
  the public preset now uses 0"). `wok config minimize` drops every key that
  equals its preset value.
- **Migration from strfry:** `wok migrate strfry` writes `preset = "public"`
  plus the translated keys. In the preflight report, values that match
  strfry's stock `strfry.conf` are listed under the heading "strfry default,
  replaced by the preset" and are dropped. `--keep-strfry-defaults` keeps them.

### 3.3 Rate limits: per connection first, per address as a backstop

The meaning of the existing per-address keys stays the same, so a file that
already sets them does not silently change scope. A per-connection table is
added:

```toml
[relay.abuse]
enabled = true
ipv6_prefix_len = 64          # new: per-address budgets group IPv6 by this prefix

# Per address (one IPv4 address, or one IPv6 /64). These are backstops against one host.
connection_rate_per_second = 10
connection_burst = 50
event_rate_per_second = 50    # EVENT and AUTH
event_burst = 100
req_rate_per_second = 200     # was 20: the only REQ budget, per IP
req_burst = 1000              # was 40
count_rate_per_second = 20
count_burst = 50
invalid_rate_per_second = 5
invalid_burst = 20

# Per author. When the event's author is not one of the connection's AUTHed
# identities, the connection's first identity is charged instead (F11).
pubkey_event_rate_per_second = 25
pubkey_event_burst = 50

[relay.abuse.per_connection]  # new
req_rate_per_second = 20      # REQ, replacement REQ, NEG-OPEN
req_burst = 100               # fits a 60-REQ startup with headroom
neg_msg_rate_per_second = 50  # NEG-MSG rounds of an already admitted session
neg_msg_burst = 200
count_rate_per_second = 5
count_burst = 20
authenticated_multiplier = 4  # an AUTHed connection gets 4× each per-connection budget
```

- The per-pubkey REQ and COUNT buckets are removed. They are why AUTH lowers
  the budget today (F1). `authenticated_multiplier` takes their place.
- NEG-MSG rounds continue a session that was already admitted. Sync memory
  and the idle timeout already bound the session. Today every round costs a
  REQ token, so a Marmot client that runs a NIP-77 pass per group at startup
  uses up its REQ budget before its live subscriptions open. A separate bucket
  still stops a client from streaming rounds forever.
- The per-address backstop still applies to AUTHed connections on `open`
  relays, because on a public relay AUTH costs nothing (any key works). On
  `members` relays the operator can raise the backstops (see the later
  `private` sketch in §4.3).
- If a connection is over `max_concurrent_historical_queries`, the REQ waits in
  a per-connection FIFO. That FIFO is bounded by `max_subs_per_connection`, and
  a REQ is refused only when the FIFO is full (F2).
- Refusals keep `rate-limited:` here, because these buckets refill.

### 3.4 Query cost: count the planner's work and include `limit`

The pre-scan cost reuses the plan that `DbScan` will choose (`scan.rs:563`),
so the cost model and the planner change together:

```text
seeks(f) = cursors the plan opens:
             ids → |ids|
             tags → number of values in the seed tag (1 for a NIP-91 & seed)
             authors + kinds → |authors| × |kinds|, whichever index the
               planner picks (the Pubkey fallback above 1,000 pairs reads
               every event by those authors, so it never costs less; C6)
             Pubkey (no kinds) → |authors|
             Kind → |kinds|
             CreatedAt → 1
rows(f)  = min(limit or max_filter_limit, max_filter_limit); for ids, ≤ |ids|
cost     = Σ seeks(f) + min(Σ rows(f), max_total_events_per_req)
           + 1,000 per search filter + rows(f) per NIP-91 & value
COUNT    = the same formula × 2, as today
```

The unit is index entries touched. In the audit's C6 table, 999 PubkeyKind
cursors returned in about 2.4 ms on a laptop, which is roughly 2.4 µs per
cursor. The proposed ceiling of **20,000** therefore allows about 50 ms of warm
index work for one REQ.

The examples below use the proposed `max_filter_limit = 2000` and
`max_total_events_per_req = 10000`:

| REQ | Current cost | Proposed cost | Proposed result |
|---|---:|---:|---|
| `{"authors":[150],"limit":20}` | 1,500 ✗ | 170 | ✓ |
| `{"kinds":[11 kinds],"limit":50}` | 1,100 ✗ | 61 | ✓ |
| 45 × `{"#e":[id],"kinds":[7]}`, no limit | 1,125 ✗ | 10,045 | ✓ |
| `{"authors":[1000],"kinds":[0,3,10002,10050]}` | 5 ✓ (but it runs into C6) | 6,000 | ✓ |
| MDK directory: `{"authors":[200],"kinds":[6 kinds],"limit":1200}` | 5 ✓ (but truncated at 500) | 2,400 | ✓ |
| MDK group: `{"kinds":[445],"#h":[gid],"since":…}` | 25 ✓ | 2,001 | ✓ |
| `{}`, no limit | 1,000 ✓ | 2,001 | ✓ |
| `{"authors":[2000],"kinds":[50 kinds]}` | 5 ✓ | 102,000 | ✗ |
| `{"#t":["nostr"],"authors":[x]}` | 25 ✓ | 2,001 | ✓ (see below) |

- A refusal reads `blocked: query too broad (cost 102000 > 20000); split the
  REQ or narrow authors/kinds`. NIP-01 has no "too expensive" prefix.
  `blocked:` tells the client that resending the same request will not help.
- Neither the current model nor the proposed one can see selectivity, which
  depends on the database. The last row seeds from the whole `#nostr` index
  and checks the author on every candidate. The proper guard for that is a
  runtime budget, `max_scan_entries_per_req` (new, provisional default
  100,000). It stops a scan after that many index entries have been examined
  and ends it with EOSE, plus the NIP-67 `more` hint once C1 lands. It is
  listed in step 9 because silent truncation before NIP-67 is worse than
  today's behaviour.
- **Complete replaceable fetches** (later, optional): when every kind in a
  filter is replaceable and the filter has authors, the effective limit
  becomes |authors| × |kinds|, capped by `max_total_events_per_req`. This
  stops outbox metadata fetches from being cut at `max_limit`. It needs the C6
  planner fix to be cheap.

### 3.5 Timestamp windows

- `events.reject_older_than_secs` defaults to 0, and NIP-11 then omits
  `created_at_lower_limit`. When an operator sets a bound, it applies only to
  regular kinds. Replaceable (0, 3, 10000–19999), addressable (30000–39999),
  5 and 62 are always exempt, so rebroadcasts and deletions keep working.
- AUTH (22242) gets a fixed window of ±600 s around the relay clock, as NIP-42
  suggests. It does not use `events.*`. Replay is already prevented by the
  per-connection challenge.
- Kind 21059 is exempt from the ephemeral age check. It may be backdated by up
  to 3 days: NIP-59 tweaks timestamps by up to 2 days, plus 1 day of slack.
  Live delivery is the only effect, and duplicates are dropped by event ID.
- The generic ephemeral window (`reject_ephemeral_older_than_secs = 60`) stays
  for NIP-46 and similar kinds.

### 3.6 Access: read classes and write policy

```toml
[relay.auth]
enabled = true
service_url = ""

read_policy = "open"                     # open | authenticated | members
recipient_only_kinds = [4, 1059, 21059]  # author or first p-tag (was restricted_read_kinds)
owner_only_kinds = [78, 30078]           # author only (NIP-78)
authenticated_kinds = []                 # any AUTHed identity

write_policy = "open"                    # open | authenticated | members
inbox_kinds = [1059, 21059]              # with members: also accept these when the first p-tag is a member
accepted_kinds = []                      # empty = every kind; NIP-86 kind policy can narrow it further
```

- **`read_policy`**
  - `open`: anyone may read any kind that is not in a restricted class.
  - `authenticated`: every REQ, COUNT and NEG-OPEN needs AUTH, as any
    identity.
  - `members`: needs AUTH as an allowlisted, role-holding or admin identity.
  - NIP-11 `auth_required` is `true` whenever `read_policy != "open"`.
- **`write_policy`**
  - `open`: anyone may write. Bans still apply.
  - `authenticated`: the connection must be AUTHed.
  - `members`: one of these must hold:
    - the event author is a member, which keeps today's `restrict_writes`
      behaviour for pre-signed member events;
    - one of the connection's AUTHed identities is a member, which fixes C7;
    - the kind is in `inbox_kinds` and the first `p` tag is a member.

  NIP-62 vanish requests stay exempt. NIP-11 `restricted_writes` is `true`
  when `write_policy != "open"`, when `accepted_kinds` is non-empty, or when
  `min_pow_difficulty > 0`.
- **`accepted_kinds`** is a ceiling in config. NIP-86 `allowkind` cannot raise
  it, and `disallowkind` can lower it. `listallowedkinds` returns the
  effective set (B14).
- **Translating old keys:** each of these is accepted with a deprecation
  warning for one minor release, and `wok config minimize` rewrites it:
  - `restricted_read_kinds` becomes `recipient_only_kinds`;
  - `restrict_writes = true` becomes `write_policy = "members"`;
  - `restrict_read_to_involved_pubkey = false` moves the kinds to
    `authenticated_kinds`, which is the nearest leak-free meaning.

### 3.7 Consolidations

- Remove `filter_validation.max_filters_per_req` and `min_filters_per_req`
  (F3). Keep `allowed_kinds` and `max_kinds_per_filter`, each disabled by its
  zero or empty value, and drop `filter_validation.enabled`.
- Add `filter_validation.require_scoped_filters`. Every filter must then name
  what it wants: `ids`, `authors`, or at least one tag filter, with any number
  of values. That refuses enumeration such as `{"kinds":[445]}` or
  `{"since":…}`. It still accepts Marmot's `#h` group filters, `#p` inbox
  filters, `ids` fetches and directory batches. Keep the strfry-era
  `require_author_or_tag` for compatibility, and document that it breaks
  Marmot and outbox clients (F13). Both rules apply to REQ, COUNT and
  NEG-OPEN. Today `filter_validation` runs only on REQ and COUNT, so
  `NEG-OPEN {"kinds":[445]}` could still list the ID of every group
  message.
- Add `relay.max_filter_bytes_per_connection = 2 MiB` (F8). It caps all live
  filters on one connection, so raising `max_req_filter_size` does not
  multiply memory.
- `max_stored_events` defaults to 0 and leaves the zero-guard warnings (F7).
- Fold the remaining zero-means-unlimited warnings into the dashboard as
  explicit "Off" toggles.

## 4. Presets

### 4.1 `public` (default)

Use this for an open relay that any client can use: feeds, outbox lookups,
DMs and gift-wrap inboxes. It is every "Public" value in §2, with the model
from §3. The overlay file is empty, because these are the built-in defaults.

### 4.2 `marmot`: Marmot relay

Use this for a relay dedicated to Marmot traffic, such as the default relays
a Marmot app ships with. It carries:
- group messages (445);
- Welcomes in gift wraps (1059);
- KeyPackages (30443);
- the profile and relay-list kinds clients look up.

Users also use other relays for everything else.

These facts come from the Marmot spec (`marmot` at `a717f22`,
`transports/nostr.md`) and MDK (`mdk` at `2ff9c142`). The spec states almost
no relay requirements, so several of them describe MDK's behaviour rather
than the spec.

```toml
# presets/marmot.toml: overlay on public
[events]
max_event_size = 4194304                 # 4 MiB: Welcomes and Add commits grow with group size (provisional)

[relay]
max_websocket_payload_size = 8388608     # restart; must cover max_event_size
max_filter_limit = 5000                  # directory batches with KeyPackage slots

[relay.auth]
accepted_kinds = [0, 3, 5, 62, 445, 1059, 10000, 10002, 10050, 30443]
write_policy = "open"                    # see the privacy note

[relay.filter_validation]
require_scoped_filters = true            # refuses {"kinds":[445]} dumps; accepts #h, #p, ids, authors

[relay.abuse]
event_burst = 300                        # a commit plus up to ~250 Welcomes from one inviter

[relay.abuse.per_connection]
req_rate_per_second = 50                 # about 2 REQ/NEG-OPEN per group at startup, plus ids fetches
req_burst = 300
neg_msg_burst = 500
```

- **Kinds:**
  - 445 is regular and signed by a fresh key per event. Its tags are one `h`
    (the 64-hex group ID) plus an optional `expiration`.
  - 1059 is regular and signed by a random key. It has one `p` tag. Its seal
    carries a kind-444 Welcome, or a push or moderation rumor.
  - 30443 is an addressable KeyPackage signed by the account key. Its `d` is
    64-hex.
  - MDK also publishes 0, 3, 10000, 10002 and 10050 for the account, and
    kind 5 (`#e` plus `k=30443`) to retire KeyPackages.
  - Kinds 443 and 10051 have been removed from the spec.
  - Marmot uses no ephemeral kinds.
- **Writes stay open.**
  - Marmot signs 445s with a fresh key per event, so the relay cannot link a
    message to its sender.
  - MDK publishes 445s on an anonymous connection first. It authenticates
    only after an `auth-required:` refusal.
  - So requiring AUTH for writes would work, but it would give the relay the
    one thing the throwaway keys withhold: which account posts to which `#h`.
  - The preset therefore accepts unauthenticated writes for its kinds, and
    gives up per-identity rate limits to do so. Operators who need write
    gating need an allowlisted setup (§4.3).
- **Reads:**
  - 1059 can be read only by its recipient after AUTH. MDK authenticates its
    receive connection with the account key.
  - 30443, 10002 and 10050 are public, because anyone inviting a user must be
    able to fetch them. MDK reads them on an anonymous connection.
  - 445 can be read by anyone who names the group.
- **Timestamps.**
  - 1059s are backdated by up to 2 days, and MDK widens its inbox `since` by
    the same amount.
  - 445s are not randomised, but application 445s carry the inner message's
    compose time. The spec also requires durable retry until the event is
    published, so an event queued offline can arrive days old.
  - `reject_older_than_secs = 0` from the public preset is therefore
    required, not optional.
  - The 900 s future bound fits MDK, which assumes relays allow about 15
    minutes.
- **Proof of work** must stay 0, because MDK never mines.
- **Refusals.**
  - MDK retries `rate-limited:` and, when it can authenticate,
    `auth-required:`.
  - It treats `pow:` and `restricted:` as final.
  - It reads no NIP-11 limits, so the preset has to fit its traffic.
- **Not covered yet:**
  - **Retention for 445.** The spec expects relays to delete expired events.
    Application 445s carry NIP-40 `expiration` when the group enables
    retention, and commits must stay fetchable. MDK reconciles a rolling
    30-day window. Per-kind retention would need a new knob, and it should
    not go below 30 days for 445.
  - **Per-group and per-recipient quotas.** A per-group (`#h`) quota for 445
    and a per-recipient quota for 1059 do not exist in Wok today, and
    per-author quotas never apply to throwaway keys. Until they exist, the
    preset relies on the per-address EVENT budget and on disk guards.
- **Sync.**
  - MDK runs a NIP-77 pass per group (`#h`) and per inbox (`#p`) with
    `limit 16385`, then fetches missing IDs in REQs of at most 64.
  - MDK's documentation makes NIP-77 a hard requirement for White Noise
    relays, so negentropy stays on.
  - Expect several connections per device per relay: authenticated receive,
    anonymous publish, anonymous directory, and short-lived inspection.

### 4.3 Later: `private`, an allowlisted relay

The first round ships `public` and `marmot` only. Other setups become presets
when there is a concrete deployment for them. The access model in §3.6 still
lands in step 7, because allowlisted operators need the C7 fix whatever the
preset. This sketch shows what an allowlisted preset would look like on top of
that model: only members may read or write, and outsiders can still deliver
DMs and Welcomes to members.

```toml
# presets/private.toml (later): overlay on public
[relay.auth]
read_policy = "members"
write_policy = "members"
inbox_kinds = [1059, 21059]             # outsiders can deliver gift wraps (NIP-17 DMs, Marmot Welcomes) to members

[relay.abuse]                           # members are known; backstops stop limiting shared offices and VPNs
req_rate_per_second = 1000
req_burst = 5000
event_rate_per_second = 200
event_burst = 500
```

Members are managed with NIP-86 (`allowpubkey`) or `admin.pubkeys`.
Members' Marmot 445s from throwaway keys are accepted because the connection's
AUTHed identity is checked (C7). The relay therefore learns which members post
to which group, which is inherent to an allowlisted relay. NIP-11 reports
`auth_required: true` and `restricted_writes: true`.

### 4.4 Selecting and overriding

```toml
preset = "marmot"

[relay.auth]
service_url = "wss://relay.example.com"   # required by the marmot preset

[relay.abuse]
event_burst = 500        # override: larger groups than the preset assumes
```

`wok config show` would then print
`relay.abuse.event_burst = 500 # wok.toml:7 (preset marmot: 300)`. The dashboard
shows the same override with a "Reset to preset" control.

### 4.5 Side by side

| Setting | public | marmot |
|---|---|---|
| `read_policy` / `write_policy` | open / open | open / open |
| `accepted_kinds` | all | Marmot set |
| `max_event_size` | 1 MiB | 4 MiB |
| `max_websocket_payload_size` | 2 MiB | 8 MiB |
| `max_filter_limit` | 2,000 | 5,000 |
| `recipient_only_kinds` | 4, 1059, 21059 | 4, 1059, 21059 |
| `owner_only_kinds` | 78, 30078 | 78, 30078 |
| `require_scoped_filters` | off | on |
| per-connection REQ | 20/s, burst 100 | 50/s, burst 300 |
| per-connection NEG-MSG | 50/s, burst 200 | 50/s, burst 500 |
| per-address REQ backstop | 200/s, burst 1,000 | 200/s, burst 1,000 |
| `event_burst` per address | 100 | 300 |
| `reject_older_than_secs` | 0 | 0 |
| `service_url` required | warn | yes |
| NIP-11 `auth_required` / `restricted_writes` | false / false | false / true |

## 5. Explaining the knobs

### 5.1 Dashboard

The dashboard keeps its NIP-98 model and its rule that access-control
settings are file-only. Its layout changes:

1. **Posture card** at the top:
   - the active preset, with a one-paragraph description;
   - the number of overrides;
   - three generated sentences describing the relay's behaviour, for example:
     "Anyone can read and write. DMs and gift wraps are shown only to their
     recipients after login. Each connection can open 20 queries a second."
2. **Groups in operator order:**
   - **Access**, shown read-only with an explanation, because it is file-only;
   - **Events accepted**;
   - **Queries**;
   - **Rates**;
   - **Storage**;
   - **Sync**;
   - **Advanced** (timeslice, plugin timeout, dashboard history).
3. **Each field shows:**
   - the label;
   - one line on what it does;
   - **If too low:** and **If too high:** lines (copy in §5.2);
   - an input that understands units (for example "3 years", "256 KiB",
     "Off");
   - the preset's value, with "Reset to preset";
   - a chip such as `NIP-11: max_limit` when the value is advertised.
4. **Refusals next to each knob.** Add one counter,
   `wok_refusals_total{setting="relay.abuse.per_connection.req_burst"}`,
   labelled by the config key that refused the request. The dashboard shows
   "refused 312 REQs in the last 24 h" beside the knob. The existing
   `abuse_*_rejections` counters map onto these labels. Event-validation and
   filter-parse refusals (`created_at too early`, `too many tags in filter`,
   filter bytes) have no counter today.
5. **Inline warnings.** `zero_guard_warnings` and `auth_configuration_warning`
   appear beside the affected field, as well as in the logs.

`docs/config.md` follows the same order. For each knob it adds three short
items: what the knob protects, what breaks when it is too low, and its NIP-11
field. The inventory in §2 is the source for that text.

### 5.2 Field copy

Format: a label, then **If too low:** and **If too high:** lines.

- **Oldest accepted event** (`reject_older_than_secs`). Off by default.
  - If too low: profiles, follow lists and deletions can't be rebroadcast, and
    history can't be imported.
  - If too high: nothing meaningful, because old events sort below new ones.
  - Profiles, lists and deletions are always accepted, whatever this is set to.
- **Future clock tolerance** (`reject_newer_than_secs`).
  - If too low: users whose clocks run fast can't post.
  - If too high: future-dated posts stay pinned at the top of feeds.
- **Tags per event** (`max_num_tags`).
  - If too low: heavy users can't save follow or mute lists.
  - If too high: every tag is an index entry, so one event can add thousands
    of writes.
- **Filter size per request** (`max_req_filter_size`).
  - If too low: outbox clients can't fetch a large follow list in one request.
  - If too high: more memory per subscription. The connection-wide filter
    budget caps the total.
- **Events per filter** (`max_filter_limit`). Advertised as `max_limit` and
  `default_limit`.
  - If too low: results are silently cut, and clients make extra round trips.
  - If too high: more output per request. The outbound queue still bounds
    memory.
- **Events per request** (`max_total_events_per_req`).
  - If too low: batched requests are silently truncated.
  - If too high: one request can queue many megabytes for a slow client, who
    is then disconnected.
- **Tag letters per filter** (`max_tags_per_filter`).
  - If too low: comment, community and marketplace queries are refused.
  - If too high: small extra checks per candidate.
- **Query cost ceiling** (`max_query_cost`).
  - If too low: normal batched and outbox queries are refused with `blocked:`.
  - If too high: one request can tie up a query worker for longer.
  - Shows the cost of the last refused query.
- **Queries per connection** (`per_connection.req_*`).
  - If too low: apps lose subscriptions at startup.
  - If too high: one connection can keep the query workers busy. The
    per-address backstop and concurrent-query limit still apply.
- **Queries per address** (`req_*` backstop).
  - If too low: users behind the same carrier NAT, office or VPN block each
    other.
  - If too high: one host can open many connections and multiply its share.
- **Connections per address** (`connection_*`).
  - If too low: shared networks fail to reconnect after an outage.
  - If too high: connection floods cost handshake CPU and memory.
- **Events per address / per author** (`event_*`, `pubkey_event_*`).
  - If too low: Marmot group invites and bulk publishing fail.
  - If too high: spam and signature-verification load.
  - Per-author limits never apply to throwaway keys.
- **Stored events per author** (`max_stored_events_per_pubkey`).
  - If too low: active users and bots stop being able to post. Deletions
    always work.
  - If too high: one key can fill the disk.
- **Concurrent historical queries** (`max_concurrent_historical_queries`).
  Extra queries wait their turn.
  - If too low: busy clients see slow first results.
  - If too high: one connection takes more than its share of query workers.
- **Read and write policy** (file-only). The panel names the policy and the
  NIP-11 flags it implies, lists the restricted kinds and why each is
  restricted, and links to `docs/config.md`.

### 5.3 NIP-11 `limitation`

| Field | Source | Advertised | Change |
|---|---|---|---|
| `max_message_length` | `max_websocket_payload_size` | always | — |
| `max_subscriptions` | `max_subs_per_connection` | always | — |
| `max_limit` | `max_filter_limit` | always | — |
| `default_limit` | `max_filter_limit` | always | — |
| `max_subid_length` | constant 64 | always | **add** (B12) |
| `max_event_tags` | `max_num_tags` | always | — |
| `min_pow_difficulty` | `min_pow_difficulty` | when abuse is on | — |
| `created_at_lower_limit` | `reject_older_than_secs` | **only when > 0** | omit when off (F10) |
| `created_at_upper_limit` | `reject_newer_than_secs` | always | — |
| `auth_required` | `read_policy != open` | always | **add** |
| `restricted_writes` | write policy, `accepted_kinds` or PoW | always | **add** (B12) |
| `max_content_length`, `payment_required` | — | never | Wok does not enforce them |
| `max_total_events_per_req`, `max_tags_per_filter`, `max_concurrent_historical_queries` | as named | always | Wok extensions. Clients ignore unknown fields |
| `max_and_entries` | `max_and_entries` | only while NIP-91 is advertised | gated |
| `max_query_cost` | `max_query_cost` | **only when abuse is on and the value is > 0** | units change (§3.4) |

Rate budgets have no standard NIP-11 field. They are documented in
`docs/config.md` and reported only through refusals.

## 6. Measuring the defaults

`wok-bench` and `scripts/reliability-soak.py` run with `[relay.abuse]
enabled = false` and `[relay.auth] enabled = false`, so they cannot validate
any of these numbers. Before any default changes, add a client-realistic
scenario (`wok-bench --scenario clients`) based on the audit's W1–W10:

- **Load shape:**
  - N outbox clients, each with about 30 subscriptions: 15 fetch-and-close,
    5 replaced every few seconds and 10 live;
  - author lists of 100–2,000;
  - background publishing, with deflate on.
- **Marmot shape:** drive real MDK rather than a model of it.
  - Live `445 #h` subscriptions, and `1059 #p` inbox subscriptions on an
    AUTHed connection.
  - A NIP-77 pass per group at startup, for G in 10, 50 and 100.
  - Directory batches of 200 authors with explicit limits.
  - Add-member bursts of one commit plus N Welcomes, for N in 10, 100 and 250.
  - Record the largest Welcome and commit sizes; they set the marmot preset's
    `max_event_size`.
  - MDK refuses loopback relays unless `allow_loopback_relay_endpoints` is
    set.
- **Settings:** each preset, with abuse controls and AUTH on.
- **Reported:**
  - time to first EVENT and time to EOSE, at p50 and p99;
  - refusal counts by `wok_refusals_total{setting}`.

**Acceptance:** every refusal count in that scenario is zero, at p99 latency
no worse than with abuse controls off.

Adversarial runs then show what each guard still bounds:
- one address opening as many connections as the connection budget allows;
- IPv6 clients rotating /128s inside one /64;
- 200 subscriptions × 256 KiB filters on one connection, to measure memory
  and confirm the per-connection budget;
- the refused fan-out from §3.4, and the `#t`+`authors` residual scan;
- floods from throwaway keys.

Record CPU, RSS and the latency other clients see.

## 7. Implementation plan

Each step is one PR and comes with tests. Steps 1–2 change no behaviour.
Each later step updates the public preset for its own family of settings, so
the reviewer sees each default next to its mechanism.

0. **Benchmark scenario** (§6), in `wok-bench`. It has no dependencies and can
   run in parallel with step 1. It gives steps 3–8 their numbers.
1. **Preset mechanism.**
   - Add `preset` to the config.
   - Layer configuration as built-in defaults, then preset, then file.
   - Add `presets/` with `public` as the current defaults, and `wok config
     show` with provenance.
   - Tests: every preset parses and round-trips; provenance is correct; an
     unknown preset name is an error.
2. **File hygiene (F4).**
   - Dashboard writes with `toml_edit`, writing overrides only.
   - A minimal `docs/wok.toml`.
   - `wok config minimize`, the `wok doctor` check for pinned stale defaults,
     and `migrate strfry` emitting `preset`.
3. **Timestamp windows (C2, B3).**
   - `reject_older_than_secs = 0`, with the exempt kinds when it is set.
   - AUTH at ±600 s, and the 21059 exemption.
   - Omit `created_at_lower_limit` when 0.
   - Regression tests reuse the audit's probes: a 2020 kind 0, an AUTH signed
     120 s earlier, and a 21059 backdated by one hour.
4. **Size limits (C5, F8, F9).**
   - `max_req_filter_size` at 256 KiB, plus `max_filter_bytes_per_connection`.
   - `max_tags_per_filter` at 8, `max_num_tags` at 5,000, `max_filter_limit`
     at 2,000 and `max_total_events_per_req` at 10,000.
   - `max_stored_events` at 0, and the per-author quota at 1,000,000 with
     kind 5 exempt (F6, F7).
   - Remove the duplicate `filter_validation` keys (F3).
5. **Cost model (C4, F5).**
   - `estimated_cost` takes the planner's plan, and the new ceiling is set.
   - The refusal prefix becomes `blocked:`, and NIP-11 gating follows.
   - The table in §3.4 becomes the unit test.
6. **Rate keying (C3, F1, F2).**
   - The `per_connection` table, including the NEG-MSG bucket, plus
     `ipv6_prefix_len` and `authenticated_multiplier`.
   - Remove the per-pubkey REQ and COUNT buckets.
   - Charge the AUTHed identity for throwaway-key events (F11).
   - Queue scans over the concurrency cap instead of refusing them.
   - Warn at startup about `real_ip_header`.
7. **Access model (C7, A5, B13, B12).**
   - Read classes, `read_policy`, `write_policy` checked against the AUTHed
     identity, `inbox_kinds` and `accepted_kinds`.
   - Translate the old keys with deprecation warnings.
   - Add `require_scoped_filters` (F13).
   - NIP-11 `auth_required`, `restricted_writes` and `max_subid_length`.
   - Add the `marmot` preset.
   - Privacy and access tests on a `members` relay:
     - a gift wrap or 21059 from a throwaway key, `p`-tagged to a member, is
       accepted;
     - a member's 445 from a throwaway key on the member's AUTHed connection
       is accepted;
     - a non-member's 445 is refused.
   - A 30078 is visible only to its owner.
8. **Dashboard and docs** (§5).
   - The posture card, field copy, override badges and reset.
   - `wok_refusals_total{setting}` and NIP-11 chips.
   - Rewrite `docs/config.md` in operator order, and add `docs/presets/`.
9. **Follow-ups**, each needing its own measurements or spec work:
   - the runtime `max_scan_entries_per_req` (after NIP-67, C1);
   - complete replaceable fetches (after the C6 planner fix);
   - per-group and per-recipient quotas;
   - per-kind retention for the marmot preset;
   - further presets, starting with `private` (§4.3).

Steps 3–6 can be reordered. Step 7 must come before the `marmot` preset
ships.

## 8. Decisions (2026-10-20)

1. **Preset names:** `public` (the default) and `marmot`. The Marmot preset
   is named for what it is, not for a generic "app relay". Other setups,
   such as `private`, become presets later.
2. **Lower `created_at` bound:** off by default. An operator-set bound
   always exempts replaceable, addressable, 5 and 62.
3. **NIP-78:** kinds 78 and 30078 are owner-only in the public default, as
   current NIP-78 recommends. Apps that publish public data in 30078 will no
   longer be readable by others on Wok.
4. **Marmot preset writes:** open. Group membership stays unlinkable at the
   relay, and abuse control relies on per-connection and per-address limits.
5. **Marmot preset scope:** `accepted_kinds` is limited to the Marmot set,
   so it is a narrow relay rather than a general one with Marmot tuning.
6. **Key names:** keep the current names, add new keys, and translate only
   the access keys.
7. **Preset versioning:** presets follow releases. Every change to a
   preset value is listed in the release notes under "Preset changes".
   There are no `preset = "public@0.8"` pins.
8. **Cost-refusal prefix:** `blocked:`, which tells clients that resending
   the same request won't help.
9. **`default_limit` and `max_limit`:** one knob, `max_filter_limit = 2000`,
   drives both. Filters without a `limit`, which are common in outbox
   metadata fetches, are not cut.

## Appendix: hard-coded limits

These are not configuration knobs, and should stay that way. Document them in
`docs/config.md`.

| Limit | Value | Where | Note |
|---|---|---|---|
| Subscription ID | 64 bytes | `wok_event::MAX_SUBID_SIZE` | NIP-01 counts characters (B8, bug) |
| Indexed or queryable tag value | 255 B | `MAX_INDEXED_TAG_VAL_SIZE` | A2, bug |
| One filter value set | 65,535 decoded B | `filter.rs:50` | At most 2,047 authors or `#p` per filter |
| NEG payload | 1 MiB | `server.rs` `ingest_neg` | — |
| AUTH identities per connection | 64 | known-differences | The first identity is the rate-limit identity |
| Event kind | 0–65,535 | parser | — |
| Size-class ceiling | 16 MiB | `MAX_SIZE_CLASS_BYTES` | Clamps event, frame and payload sizes |
