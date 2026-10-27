# Configuration

Wok uses strict TOML configuration. Start from [wok.toml](wok.toml), a short
annotated file showing the settings a relay must or commonly should set, or
from the file produced by `wok migrate strfry`. Omitted settings inherit the
selected [preset](#preset), whose values are the defaults below; unknown keys,
unknown preset names, wrong types, invalid admin URLs, invalid log filters,
and out-of-range history settings are rejected. `wok config show --defaults`
lists every setting with the preset's value.

This page follows the order of the [operator dashboard](admin-dashboard.md):
the preset, then who may use the relay, then what it accepts, how much one
request may ask, how fast clients may send, how much it stores, sync, and
the rest. For each limit it says what the limit protects, what breaks when
it is set too low, and the NIP-11 `limitation` field that advertises it, if
any. Defaults are the `public` preset's; the [`marmot`](presets/marmot.md)
preset changes a few.

The legacy HOCON-subset reader is used only for explicit strfry migration.
It accepts named objects, arrays, and anonymous object blocks inside arrays
(for example `plugins.accept = [ { cmd = "..." } ]`). Those plugin-array
entries are reported as ignored keys; Wok translates only
`relay.writePolicy.plugin` into `relay.write_policy_plugin`. Normal startup,
validation, dashboard writes, and file watching use TOML.

## Reload and dashboard boundaries

Settings are **live** unless a section says otherwise: the configuration
watcher and dashboard saves apply them to the running relay. **Restart**
settings are parsed on reload, but the running process keeps the value it
started with. Some limits apply to connections or subscriptions created after
a reload.

The [dashboard](admin-dashboard.md) edits the live settings of Events
accepted, Queries, Rates, Storage, Sync, Relay information and Advanced, and
needs `admin.allow_config_writes = true` and a relay started from an existing
file. Access settings, the client address header, admin settings, plugin
paths and diagnostic switches are **file-only**: the dashboard shows the
access settings and the client address header read-only, so a remote save
cannot lock anyone out or move a trust boundary. Restart settings are
file-only too.

At startup and on reload, the relay logs a warning for each guard the file
sets to zero, which turns it off, while its preset does not; the dashboard
shows the same warning beside the setting, and `wok doctor` reports it in
its `zero-guards` check. A restart setting, such as
`database.min_free_disk_bytes`, is warned about once it applies. A guard the
preset itself turns off, such as `max_stored_events` in `public`, is not
warned about. Each refusal a setting
makes is counted by `wok_refusals_total{setting="<key>"}`; see
[Refusals by setting](observability.md#refusals-by-setting).

## Preset

| Key | Default | Meaning |
|---|---|---|
| `preset` | `"public"` | Named set of defaults this file overlays. Live. |

Settings resolve in three layers: the built-in defaults, then the preset's
overlay, then this file. Each layer replaces individual keys, not whole
sections. A preset ships in the binary as a small TOML overlay containing
only the keys it changes; [presets/](presets/) has a copy of each and a page
on who it is for, what it changes and what it refuses.

| Preset | Use |
|---|---|
| [`public`](presets/public.md) | A general public relay that any client can read from and write to. Its values are the built-in defaults, so its overlay is empty. |
| [`marmot`](presets/marmot.md) | A relay dedicated to Marmot group messaging, such as one a Marmot app ships as a default: only the Marmot kinds, scoped filters, 4 MiB events, no COUNT or permessage-deflate, NIP-77 limits sized to MDK's syncs, and open writes. It refuses to start without usable NIP-42 AUTH, or with gift wraps readable by anyone but their recipient. |

A preset's requirements are checked when the relay starts and on every
reload: a `marmot` file without a usable `relay.auth.service_url`, or one
that leaves kind 1059 or 21059 out of `relay.auth.recipient_only_kinds` (and
`owner_only_kinds`), is refused, from the file watcher, a dashboard save or a
NIP-86 relay-info method, and the running configuration kept; a save then
answers 409 and writes nothing. `wok doctor` reports it as a failed `preset`
check. Owner-only gift wraps pass, but their recipients cannot read them.

Changing `preset` on reload is allowed. The reload log names the preset
change, and every resulting security-scope change is warn-logged like any
other reload. Presets follow releases: every change to a preset value is
listed in the release notes under "Preset changes". Further presets, such as
an allowlisted `private` one, are planned.

### Set only overrides

A setting in the file pins its value, even when it equals today's default.
When a release improves a default, a relay whose file repeats the old value
keeps it. Set only what the relay needs and leave the rest to the preset.

- **Dashboard and NIP-86 saves** edit the file in place. They change only the
  settings whose value changed, add a new setting to the end of its table,
  and remove a setting set back to its preset value; the dashboard's
  **Reset to preset** does that. Comments, layout and `preset` are kept;
  removing a setting also removes the comment lines directly above it.
- **`wok config minimize`** removes every setting that repeats its preset's
  value, so the relay resolves to the same configuration afterwards. It keeps
  the original beside the file as `<file>.bak`, or `.bak.1` and so on if that
  exists. `--dry-run` prints the change as a unified diff and writes nothing.
- **`wok doctor`** warns, in its `config-defaults` check, about settings
  pinned to a default that an earlier release used and the preset has since
  replaced, such as `events.reject_older_than_secs = 94608000`, the default
  through 0.7.0. The relay keeps the old value. Delete the line to use the
  preset's value, or keep it if you chose that value; `minimize` leaves such
  settings alone because removing them changes behavior. The check also
  counts the settings that `minimize` would remove.
- **`wok doctor`** warns, in its `config-public-values` check, about
  settings pinned to the `public` preset's value when the file selects
  another preset that replaces it. A file written for `public`, such as a
  copy of the 0.7 sample that lists every default, keeps
  `events.max_event_size` at 1 MiB, `relay.max_websocket_payload_size` and
  `relay.unix.max_frame_bytes` at 2 MiB, COUNT
  (`relay.max_filter_limit_count`) and permessage-deflate
  (`relay.compression_enabled`) on, `relay.abuse.event_burst` at 100, and
  `relay.max_sync_events` and `relay.sync_memory_per_connection` at their
  `public` values when it moves to `preset = "marmot"`. None of those is a past default, and
  `minimize` keeps them because they differ from `marmot`'s. Delete the line to use the preset's value, or keep it if
  you chose that value.
- **Deprecated settings** that a release replaced still load, as their
  translation, so the relay behaves as before; see
  [Files from 0.7 and earlier](#files-from-07-and-earlier).

### Show the effective configuration

`wok config show` prints the effective configuration, one dotted key per
line, with the origin of each value: `default`, `preset <name>`, or the file
and line that set it. When the file sets a value other than the preset's,
the preset's value follows in parentheses. `wok config show --overrides`
prints only those keys. The output is itself valid TOML.

```text
preset = "public"                                      # wok.toml:1
relay.abuse.event_burst = 500                          # wok.toml:11 (preset public: 100)
relay.auth.service_url = "wss://relay.example.com"     # wok.toml:8 (preset public: "")
relay.bind = "127.0.0.1"                               # default
```

`wok config show --defaults` prints every setting with the value the file's
preset gives it, ignoring the rest of the file.

## Access

Who may read and write, and which kinds are private. These settings reload
live but are file-only, because they define an access-control boundary; the
dashboard shows them read-only. A reload that changes `read_policy` or
`write_policy` is logged as a warning naming the old and the new policy.

| Key | Default | Protects | If too low | NIP-11 |
|---|---|---|---|---|
| `relay.auth.enabled` | `true` | NIP-42 authentication, which private reads, owner-only writes and the non-open policies need. | Off: nobody can log in, so private kinds cannot be read by anyone, and AUTH is refused with `blocked:`. | NIP-42 in `supported_nips` while AUTH is usable; NIP-59 and NIP-78 need it too, see [Read classes](#read-classes) |
| `relay.auth.service_url` | empty | The relay URL an AUTH event must name, scheme, port and path included, so an AUTH signed for another relay, on this host or another, is refused. The host's case, a query, trailing slashes and the port the scheme implies are ignored; the path's case is not. `https` and `http` count as `wss` and `ws`, and a URL without a scheme as `wss`. Since trailing slashes are ignored, as clients drop them, two relays a proxy routes at `/relay` and `/relay/` accept each other's AUTH: give each its own path. | Empty: AUTH cannot succeed, and the relay logs what fails closed at startup. A `marmot` relay refuses to start. | As `relay.auth.enabled`: AUTH is usable only with both |
| `relay.auth.read_policy` | `"open"` | Who may send REQ, COUNT and NEG-OPEN: `open`, `authenticated` or `members`. See [Read and write policies](#read-and-write-policies). | — | `auth_required` while not `open` and AUTH is usable |
| `relay.auth.write_policy` | `"open"` | Who may publish: `open`, `authenticated` or `members`. NIP-62 vanish requests are always accepted. | — | `restricted_writes` while not `open` |
| `relay.auth.recipient_only_kinds` | `[4, 1059, 21059]` | DMs and gift wraps: read only by their author and first `p`-tag recipient. | Leaving out 1059 or 21059 serves gift wraps, recipient tag included, to anyone, and stops NIP-59 being advertised; the relay warns, and a `marmot` relay refuses to start. | NIP-59 in `supported_nips`, see [Read classes](#read-classes) |
| `relay.auth.owner_only_kinds` | `[78, 30078]` | NIP-78 app data: read only by its author, and accepted only from a connection authenticated as the author. | Leaving them out serves app data to anyone, and stops NIP-78 being advertised. | NIP-78 in `supported_nips`, see [Read classes](#read-classes) |
| `relay.auth.authenticated_kinds` | `[]` | Kinds any authenticated connection may read, whichever pubkey it authenticated as. | — | — |
| `relay.auth.inbox_kinds` | `[1059, 21059]` | Under `write_policy = "members"`, events of these kinds are also accepted when their first `p` tag is a member, so anyone can deliver gift wraps to members. Each should be recipient-only; see [Read and write policies](#read-and-write-policies). | Empty: outsiders cannot deliver DMs or Marmot Welcomes to members. | — |
| `relay.auth.accepted_kinds` | `[]` | The kinds the relay accepts; empty accepts every kind. A ceiling for the NIP-86 kind policy. See [Accepted kinds](#accepted-kinds). | Kinds clients publish are refused with `restricted:`. | `restricted_writes` while set |

While AUTH is usable (`enabled` with a `service_url`), every connection
receives its NIP-42 challenge as soon as it opens.

While it is not, private reads fail closed: those reads, and events of every
restricted kind, which nobody could read, are refused with `restricted:` and
no challenge, so NIP-42 clients do not attempt an AUTH that cannot succeed.
An event of a recipient-only or authenticated kind, such as a gift wrap,
gets `restricted: kind 1059 is read only after AUTH, which this relay does
not offer`, decided by its kind before its signature is verified, and again
by the writer, so one queued before a reload made AUTH unusable is refused
too. NIP-62 vanish requests are accepted whatever their class. With
`enabled = false` the relay refuses AUTH outright.

A reload that makes AUTH unusable ends every login. Each connection is
anonymous from then on, even after a reload makes AUTH usable again, until
it authenticates again with the challenge it holds: its live subscriptions
stop delivering what only its keys may read, and the NEG sessions it opened
while logged in are closed with `closed: authentication changed; reopen
synchronization`.

### Read classes

The three `*_kinds` lists are read classes. A kind in none of them can be
read by anyone. The others are read only by:

| Class | Who may read | For |
|---|---|---|
| `authenticated_kinds` | any connection that authenticated, as any pubkey | Data shared with every logged-in user |
| `recipient_only_kinds` | the author and the first `p`-tag recipient | DMs (4) and gift wraps (1059, 21059) |
| `owner_only_kinds` | the author | NIP-78 app data (78, 30078), which NIP-78 says is private to its user |

A kind listed in more than one class gets the strictest. The classes apply
to historical and live REQs, COUNT and negentropy sync alike, each event
checked against the connection's authenticated pubkeys:
- A REQ or NEG-OPEN whose every filter asks only for restricted kinds needs
  AUTH first: it is refused with `auth-required:` and a challenge.
- Any other REQ is served, and restricted events are left out of it until the
  connection authenticates as a pubkey that may read them.
- A COUNT that may count restricted kinds must be scoped to what the
  connection may read: `authors` or `#p` naming only its pubkey for
  recipient-only kinds, and `authors` alone for owner-only kinds.

A file that gives a kind more readers than its preset does, such as
`recipient_only_kinds = []` or 1059 moved to `authenticated_kinds`, is warned
about when the relay starts, naming each kind with its class in the preset
and in the file, and by `wok doctor` in its `read-classes` check. A reload
names each kind it widens from the running configuration (`read access
WIDENED`).

As NIP-78 recommends, the relay also accepts an event of an owner-only kind
only on a connection authenticated as its author. Without AUTH the EVENT is
refused with `auth-required:` and a challenge; once the connection has
authenticated as another pubkey, with `restricted:`. The writer checks this
again under its own configuration, as it does the author's AUTH that NIP-70
protected events need, so an event queued before a reload made AUTH
unusable, or moved its kind into `owner_only_kinds`, is refused too. A tool that copies
events between relays without the authors' keys, such as `wok sync`, can
therefore neither download nor upload them unless the relay it reads from or
writes to sets `owner_only_kinds = []`. Apps that publish public data in
78 or 30078, which anyone could read through 0.7, can no longer be read by
other users; set `owner_only_kinds = []` to serve them as before.

Wok advertises NIP-59 only while recipients can read their gift wraps and
nobody else can: AUTH is usable, both gift-wrap kinds (1059 and 21059) are
recipient-only, with no stricter class, and `events.ephemeral_persistence` is
`live_only`. It advertises NIP-78 only while AUTH is usable and both app-data
kinds (78 and 30078) are owner-only. The public defaults without a
`service_url` advertise neither.

### Read and write policies

`read_policy` and `write_policy` say who may use the relay at all; the read
classes then apply on top. NIP-11 advertises `auth_required` while
`read_policy` is not `open` and AUTH is usable, and `restricted_writes` while
`write_policy` is not `open` (or `accepted_kinds` is set, or proof of work is
required). Each is one of:

| Policy | Who may read | Who may write |
|---|---|---|
| `open` | anyone | anyone |
| `authenticated` | a connection authenticated with NIP-42, as any pubkey | the same, with an event signed by any key |
| `members` | a connection authenticated as a member | an event a member signed, any event on a connection authenticated as a member, or an `inbox_kinds` event addressed to a member, as below |

A member is a pubkey that is not banned and is NIP-86 allowlisted
(`allowpubkey`), holds any role (`assignrole`, built-in or custom), or is in
`admin.pubkeys`; see [nip86.md](nip86.md).

- **`read_policy`** applies to every REQ, COUNT and NEG-OPEN. One the policy
  does not admit is refused with `auth-required:` and a challenge while
  authenticating could help, and with `restricted:` once the connection has
  authenticated as no member, or while AUTH is unusable. A connection the
  policy stops admitting, such as a member removed, or one that has not
  authenticated after a reload to `authenticated`, gets nothing more on its
  open subscriptions. A REQ or COUNT whose scan is waiting or running is
  refused with CLOSED, and the reason above, at its next time slice, and its
  sync sessions end with `closed: visibility changed; reopen
  synchronization`, as does a NEG-OPEN still queued.
- **`write_policy = "authenticated"`** accepts an event only on an
  authenticated connection, signed by any key.
- **`write_policy = "members"`** accepts an event when one of these is a
  member:
  - its author, so members' events can be published by anyone, from any
    connection;
  - a pubkey the connection authenticated as, so a member's events signed
    by throwaway keys, such as Marmot group messages (445), are accepted on
    the member's connection;
  - for one of `inbox_kinds`, its first `p`-tag recipient, so outsiders can
    deliver NIP-17 DMs and Marmot Welcomes to members.

  The relay then learns which member sent each such event, which is inherent
  to a members-only relay. An inbox kind should be recipient-only, as the
  default gift-wrap kinds are: otherwise outsiders can publish events of it,
  addressed to a member, that others may read, such as notes with
  `inbox_kinds = [1]`. The relay warns about such a kind at startup, a reload
  that makes one warns, and `wok doctor` reports it in its `inbox-kinds`
  check. Whatever the class, an inbox event's `OK true` tells an outsider
  that its first `p` tag is a member that is not banned: anyone can ask
  whether a key is a member by publishing one gift wrap to it. A refusal
  says it is not only when it is the policy's own, below; the kind policy,
  signature, proof-of-work and rate checks refuse without asking, and so,
  while AUTH is unusable, does the refusal of recipient-only and
  authenticated kinds, gift wraps included.

A refused EVENT gets `auth-required:` and a challenge while the connection
has not authenticated, else `restricted: this relay accepts events only from
members` (or `authenticated users`). Bans and the kind policy apply under
every policy, and NIP-62 vanish requests are accepted under all of them. The
writer checks the event again against the policy, the member against the
moderation state it commits under, and an inbox recipient's kind against
`inbox_kinds`, all as they are when it stores the event, so an event whose
member was removed, or whose policy a reload tightened, in the meantime is
refused.

### Accepted kinds

`accepted_kinds` makes a relay that stores only the kinds it is for, such as
a relay for one application's few kinds. An event of another kind is refused
with `restricted: kind N is not allowed by this relay`, and NIP-11 then
advertises `restricted_writes`. The writer checks the kind again under the
configuration it stores with, so a reload that drops a kind also refuses
events of it still queued. NIP-62 vanish requests (kind 62) are accepted
whatever the list says while `relay.nip62.enabled`, because NIP-62 requires
relays that restrict what they store to honor them.

It is a ceiling for the NIP-86 kind policy (see [nip86.md](nip86.md#kind-policy)):
`disallowkind` can refuse a kind it lists, and `allowkind` cannot make the
relay accept a kind it leaves out. `listallowedkinds` reports the effective
set, the kinds it accepts that the policy allows.

Only writes are bounded. Events of other kinds stored earlier stay readable;
`wok delete` removes them. A NIP-86 ban on such a kind still hides them, and
`allowkind` still lifts it.

## Events accepted

What an event must meet to be stored or delivered. All reload live and are on
the dashboard. An event that breaks one is refused with `OK false` and
`invalid:`, except proof of work (`pow:`) and a disabled NIP-62 (`blocked:`).

| Key | Default | Protects | If too low | NIP-11 |
|---|---|---|---|---|
| `events.max_event_size` | `1048576` | Memory per event while it is checked, and its stored size. Measured as normalized JSON, after Base64 and escaping. | Long posts are refused, and so are Marmot Welcomes and Add commits in large groups, which carry the group's ratchet tree. | — |
| `events.max_num_tags` | `5000` | Write amplification: each single-letter tag is an index entry. | Heavy users can't save their follow, mute and other lists. At 2,000, the default through 0.7, a follow list of more than 2,000 accounts was refused. | `max_event_tags` |
| `events.max_tag_val_size` | `1024` | Bloat from long tag values. An addressable event's first `d` must leave room for the `a` tag naming it, so it is at most this minus 71 bytes. | One long `r`, `t` or `a` value gets the whole event refused. | — |
| `events.reject_older_than_secs` | `0` | Nothing meaningful: old events sort below new ones. `0` means no lower bound. A set bound spares replaceable, addressable, deletion and vanish events. | Old posts can't be rebroadcast, and history can't be imported. | `created_at_lower_limit`, only while set |
| `events.reject_newer_than_secs` | `900` | Feeds, from future-dated posts that would stay pinned at the top. | Users whose clocks run fast can't post. | `created_at_upper_limit` |
| `events.reject_ephemeral_older_than_secs` | `60` | Live subscribers, from replayed ephemeral events (kinds 20000–29999, such as NIP-46). AUTH and 21059 use their NIPs' windows. | Ephemeral messages from clients with slow clocks or queues are refused. | — |
| `events.ephemeral_persistence` | `"live_only"` | Storage: `live_only` delivers ephemeral events to live subscribers without storing them; `ttl` stores them for `ephemeral_lifetime_secs`. | — | `ttl` removes NIP-59 from `supported_nips` |
| `events.ephemeral_lifetime_secs` | `300` | How long a stored (`ttl`) ephemeral event stays readable. | Clients that reconnect miss recent ephemeral events. | — |
| `relay.abuse.min_pow_difficulty` | `0` | Spam: the NIP-13 difficulty, in leading zero bits of the id, every event must meet but a NIP-62 vanish request that targets this relay, which NIP-62 requires a relay to honor. `0` is off. | — (too high: most clients can't post; few mine proof of work, and Marmot clients never do.) | `min_pow_difficulty`, always (0 while abuse protection is off); above 0 it also adds NIP-13 to `supported_nips` and sets `restricted_writes` |
| `relay.nip62.enabled` | `true` | NIP-62 Request to Vanish: accept requests to erase everything an author published here. | Off: users can't erase their data from this relay. Deletion markers stored earlier stay enforced. | NIP-62 in `supported_nips` |
| `relay.nip62.service_url` | empty | The relay URL a targeted vanish request must name, compared as for AUTH; empty uses `relay.auth.service_url`. `ALL_RELAYS` always matches. | — | — |

The 1 MiB event ceiling accommodates bounded extended-length NIP-44
payloads, including kind 1059 gift wraps and kind 445 MLS group events. Wok
does not decrypt or identify NIP-44 content, so this remains a global event
limit. The `marmot` preset raises it to 4 MiB. An event must also fit
`relay.max_websocket_payload_size` (or `relay.unix.max_frame_bytes`) with its
envelope, at least 10 bytes (`["EVENT",` and `]`). A message over the cap is
cut off and its connection closed, with no `OK`, so Wok warns at startup, on
reload, beside the field on the dashboard and in `wok doctor`'s
`message-caps` check whenever a cap is too small for `events.max_event_size`
or `relay.max_req_filter_size` (plus 12 bytes for a REQ's envelope, or 14
for a COUNT's while COUNT is on). The caps apply at restart, and both limits
reload live.

Single-letter tag values longer than 255 bytes are indexed by their SHA-256,
so up to `max_tag_val_size` a `#x` filter matches them, an addressable event
whose first `d` tag is that long keeps its own address, and a kind 5 `a` tag
that long deletes its target. Records stored by earlier Wok releases or
migrated from strfry lack long values in their indexes until `wok reindex`
restores them; see [lmdb-v3.md](lmdb-v3.md#packedevent).

### Timestamp windows

A bound an operator sets with `reject_older_than_secs` applies to regular
kinds only. Replaceable (0, 3, 10000–19999) and addressable (30000–39999)
events, deletions (5) and vanish requests (62) are exempt from it.

Two kinds follow their NIPs instead of the `[events]` windows, and their
refusals are not counted against any setting:

- **AUTH (22242)** is accepted within 600 seconds of the relay clock, in
  either direction, as NIP-42 suggests. The per-connection challenge already
  prevents replay.
- **Ephemeral gift wraps (21059)** may be dated up to three days in the
  past, because NIP-59 backdates wraps by up to two days. This allowance is
  fixed; `reject_ephemeral_older_than_secs` does not change it. Future dates
  are still bounded by `reject_newer_than_secs`. In `ttl` mode a wrap older than
  `ephemeral_lifetime_secs` reaches live subscribers, but the next purge
  removes it, so history does not serve it.

An event whose NIP-40 `expiration` has passed is refused, whatever its kind.

## Queries

How much one REQ, COUNT or NEG-OPEN may ask for, and how many a connection
may keep open. All reload live and are on the dashboard.

| Key | Default | Protects | If too low | NIP-11 |
|---|---|---|---|---|
| `relay.max_filters_per_req` | `200` | Fan-out per request. | Clients that batch many filters in one REQ are refused with `invalid: bad req: arr too big`. NDK batches about 45. | — |
| `relay.max_req_filter_size` | `262144` | Parse and live-matching memory per REQ, COUNT or NEG-OPEN, as compact JSON. | Outbox clients can't fetch a large follow list in one request. At 64 KiB, the default through 0.7, a REQ naming about 970 authors or more was refused. | — |
| `relay.max_filter_bytes_per_connection` | `2097152` | Memory for the filters of every subscription open on one connection, and separately of its COUNTs not yet answered and of its NEG-OPEN sessions. `0` is unlimited. | Clients that keep several subscriptions over a long follow list open, such as a home feed and a profile feed, have new ones refused. | — |
| `relay.max_subs_per_connection` | `200` | Live-matching memory per connection. It also bounds the queries waiting for the concurrency cap. | Apps that keep many subscriptions open have some refused with `blocked: too many concurrent REQs`. Clients use 30–100. | `max_subscriptions` |
| `relay.max_filter_limit` | `2000` | Rows per filter: a filter's `limit` is clamped to it, and a filter without one gets it. Operator commands such as `wok scan`, `wok delete` and `wok dict` don't apply it. | Results are cut, and clients make extra round trips. At 500, the default through 0.7, MDK's directory batches (`limit` 1,200) and outbox fetches without a `limit` lost events. | `max_limit`, `default_limit` |
| `relay.max_total_events_per_req` | `10000` | Rows per REQ over all its filters, deduplicated. `0` is unlimited. | Merged batches are cut. At 2,000, the default through 0.7, five filters of 500 lost a fifth of their events. | `max_total_events_per_req` |
| `relay.max_tags_per_filter` | `8` | Residual tag checks on each candidate event: the distinct tag letters across `#` and NIP-91 `&` keys. `0` refuses every filter that names a tag. Negentropy tree filters are not limited. | Comment, community and marketplace queries are refused. At 3, the default through 0.7, a NIP-22 query on `#E`, `#K`, `#P` and `#k` was. | `max_tags_per_filter`; NIP-91 in `supported_nips` while it is above 0 |
| `relay.max_and_entries` | `16` | NIP-91 checks on each candidate event: the values across all `&` keys of one filter. `0` turns NIP-91 off. | NIP-91 queries that require several tags are refused. | `max_and_entries`; NIP-91 in `supported_nips` while it and `max_tags_per_filter` are above 0 |
| `relay.max_filter_limit_count` | `1000000` | COUNT de-duplication memory: the most events one COUNT filter counts. `0` turns COUNT off, as `marmot` does. | Counts of popular events, such as followers or reactions, are capped, and the reply carries `limited: true`. | NIP-45 in `supported_nips` while above 0 |
| `relay.search_enabled` | `true` | Answering NIP-50 `search` filters, and advertising NIP-50. Off, a REQ or COUNT with one is refused with `blocked: bad req: search disabled`, and a NEG-OPEN with `blocked: search disabled`. See [Search](#search). | Off: clients' searches are refused here, and NIP-50 clients look for search on relays that advertise it. | NIP-50 in `supported_nips` while on |
| `relay.abuse.max_query_work` | `20000` | Query workers, from requests whose estimated index work is too large. `0` is unlimited. See [Query work](#query-work). | Batched and outbox queries are refused with `blocked: query too broad`. | `max_query_work`, while abuse protection is on and it is set |
| `relay.abuse.max_concurrent_historical_queries` | `8` | Query workers' fairness: scans one connection runs at once, counted separately for its REQs and COUNTs and its NEG-OPENs. More wait in arrival order. `0` runs none. | Busy clients see slow first results. | `max_concurrent_historical_queries` |
| `relay.filter_validation.require_scoped_filters` | `false` | Enumeration: every filter must name `ids`, `authors`, or a tag filter (`#x` or `&x`), with any number of values. Refuses `{"kinds":[445]}`, `{"since":…}` or a bare `search`. On in `marmot`. | — | — |
| `relay.filter_validation.max_kinds_per_filter` | `0` | The kinds one filter may list; `0` is unlimited. | Clients that ask for many kinds at once are refused. MDK's directory batches list six. | — |
| `relay.filter_validation.allowed_kinds` | empty | The kinds a filter may list, comma-separated; empty allows any. A filter without `kinds` is not checked. | Queries for other kinds are refused, even when the relay stores them. | — |
| `relay.filter_validation.require_author_or_tag` | `false` | strfry's rule: every filter must name exactly one author, `#p` or `#e` value. | — (on, it refuses Marmot's `#h` group filters, `ids` fetches and multi-author outbox and directory batches; prefer `require_scoped_filters`.) | — |

A REQ that would take the connection over its filter budget is refused with
`CLOSED` and `blocked: this connection's filters exceed <budget> bytes`.
Closing a subscription frees its bytes. A REQ that reuses an open
subscription ID is charged only for the difference, so after a reload lowers
the budget, a subscription can still be replaced by filters no larger than
its own, as it can over a lowered subscription cap.

One filter also stops at 65,535 decoded bytes per value list, whatever these
settings are: at most 2,047 `authors`, `ids`, `#e` or `#p` values. 256 KiB
lets one filter reach that ceiling and leaves room for the other filters in
the same REQ.

A history cut by `max_filter_limit` or `max_total_events_per_req` never gets
the NIP-67 `finish` hint, and usually gets `more` (see [nips.md](nips.md)),
so a client can page with `until` for the rest.

A scan over `max_concurrent_historical_queries` waits, in arrival order, for
one of the same kind to end. At most `max_subs_per_connection` wait; past
that a REQ or COUNT is refused with `CLOSED rate-limited: too many
historical queries waiting on this connection`.

### Search

`relay.search_enabled` gates the NIP-50 query parser and the ranked search
scan: while it is off, a request with a `search` filter is refused before its
filters are parsed, whatever else it asks for. Subscriptions already open
when a reload turns it off keep their search filters until they close. The
writer keeps the search index current as it stores and deletes events either
way, so turning search back on, which reloads live, answers from a complete
index at once.

### Filter validation

The `filter_validation` rules apply to REQ, COUNT and NEG-OPEN, each when it
is set; the public preset sets none. A REQ or COUNT with a filter that
breaks one is refused with `CLOSED` and `blocked: bad req: filter validation
failed: ...`, and a NEG-OPEN with `NEG-ERR` and `blocked: filter validation
failed: ...`, so a sync cannot list the ids of events a REQ may not ask for.
A filter with an empty list, which matches nothing, is not checked. The
filters in one REQ are bounded by `relay.max_filters_per_req` alone.

A reload that changes the rules applies them to what is already open: each
REQ subscription or COUNT whose filters they now refuse is closed with the
`CLOSED` it would get if sent now, and each NEG session with the `NEG-ERR`,
so tightening them stops an enumerating subscription such as
`{"kinds":[445]}` at once. One still sending its stored history stops at
its next time slice, before the rest goes out.

### Query work

Before a REQ, COUNT or NEG-OPEN opens a cursor, the relay estimates how many
index entries it would touch and refuses it if the estimate is over
`max_query_work`. A REQ gets `CLOSED blocked: query too broad (cost <n> >
<max>); split the REQ or narrow authors/kinds`, a COUNT the same naming the
COUNT, and a NEG-OPEN `NEG-ERR` naming the NEG-OPEN. `blocked:` tells the
client that sending the same request again won't help.

A filter's estimate follows the plan its scan will run. It counts the
cursors the plan opens:

- one per id for `ids`;
- for tags, one per value of the tag the scan seeds from (one for a NIP-91
  `&` tag). Once the `(tag, kind, created_at)` index is complete, one tag
  with `kinds` costs one per (value, kind) pair;
- one per (author, kind) pair for `authors` with `kinds`, whichever index
  the scan reads;
- one per author for `authors` alone, one per kind for `kinds` alone, and
  one for a filter with neither;
- 1,000 for a NIP-50 `search` filter.

A REQ adds the rows it can return: each filter's `limit`, or
`max_filter_limit` when it has none, and no more than its `ids`. The rows of
all its filters count up to `max_total_events_per_req`. Each NIP-91 `&`
value adds the filter's rows again, for the check on every candidate. A
COUNT costs twice its cursors and a NEG-OPEN its cursors, with no rows:
their scans are not bounded by `limit`. A COUNT's is bounded while it runs,
by `max_filter_limit_count` and the COUNT budget. A NEG-OPEN is refused
before its scan is scheduled when its view would not fit the sync memory
budgets, and its scan stops, refusing the sync, past `max_sync_events`. It
is not priced by rows on purpose: a sync exists to move many events, up to
all a relay holds, so the ceiling leaves a broad one alone (see
[Sync](#sync)).

With the public preset's limits:

| Request | Cost |
|---|---:|
| `{"authors":[150 keys],"limit":20}` | 170 |
| `{"kinds":[11 kinds],"limit":50}` | 61 |
| 45 × `{"#e":[id],"kinds":[7]}` | 10,045 |
| `{"authors":[1000 keys],"kinds":[0,3,10002,10050]}` | 6,000 |
| `{"kinds":[445],"#h":[group id]}` | 2,001 |
| `{}` | 2,001 |
| `{"authors":[2000 keys],"kinds":[50 kinds]}` | 102,000, refused |
| `COUNT {"kinds":[3],"#p":[pubkey]}` | 2 |
| `COUNT {"authors":[2000 keys],"kinds":[50 kinds]}` | 200,000, refused |
| `NEG-OPEN {"kinds":[445],"#h":[group id]}` | 1 |

One unit is about 2–4 µs of warm index work, so the ceiling lets one request
run for about 50–80 ms. If it is too high, one request can hold a query
worker for longer. The estimate cannot see how many entries a cursor reads
before it finds a match: `{"#t":["nostr"],"authors":[key]}` costs 2,001, but
reads the `nostr` tag's entries until the author's events turn up. Past
16,384 (author, kind) pairs, `authors` with `kinds` read the authors'
history until they find those kinds, which takes seconds for kinds they
rarely publish.

## Rates

Token buckets: each refills at its rate per second and holds up to its
burst, how much may be spent at once. A connection has budgets of its own,
under a backstop shared by every connection from one address, and an address
may hold only so many connections open. All reload live and are on the
dashboard, apart from the client address header. `0` in a bucket's rate or
its burst turns that bucket off (unlimited). A refusal by a bucket is
counted under its `_burst` key.

| Key | Default | Protects | If too low | NIP-11 |
|---|---|---|---|---|
| `relay.abuse.enabled` | `true` | Turns every budget here, the storage quotas, the query work ceiling and proof of work on or off. | Off: none of them apply. A `min_pow_difficulty` above 0 is then ignored, which the relay warns about at startup and on reload, and `wok doctor` in its `abuse-limits` check. | — |
| `relay.abuse.per_connection.req_rate_per_second` | `20` | Scan CPU and monitor churn from one connection: REQs, REQs that replace a subscription, and NEG-OPENs. | Apps lose subscriptions at startup. | — |
| `relay.abuse.per_connection.req_burst` | `100` | The same, at once. A client's startup burst of about 60 REQs fits. | As above. | — |
| `relay.abuse.per_connection.neg_msg_rate_per_second` | `50` | Sync worker time: NEG-MSG rounds of sessions already admitted by their NEG-OPEN. | Clients that sync many groups or inboxes at startup are cut off. | — |
| `relay.abuse.per_connection.neg_msg_burst` | `200` | The same, at once. | As above. | — |
| `relay.abuse.per_connection.count_rate_per_second` | `5` | COUNT scans from one connection, which read every match. | Pages that show many counts lose some. | — |
| `relay.abuse.per_connection.count_burst` | `20` | The same, at once. | As above. | — |
| `relay.abuse.per_connection.authenticated_multiplier` | `4` | An AUTHed connection's per-connection rates and bursts are this many times larger; at least 1. The per-address backstops are not multiplied. | Logged-in clients get no more room than anonymous ones. | — |
| `relay.abuse.req_rate_per_second` | `200` | Backstop: REQ, NEG-OPEN and NEG-MSG from all the connections of one address. | Users behind the same carrier NAT, office or VPN block each other. | — |
| `relay.abuse.req_burst` | `1000` | The same, at once. | As above. | — |
| `relay.abuse.count_rate_per_second` | `20` | Backstop: COUNT from all the connections of one address. | Users behind a shared network lose counts. | — |
| `relay.abuse.count_burst` | `50` | The same, at once. | As above. | — |
| `relay.abuse.connection_rate_per_second` | `10` | Handshake CPU and memory: new connections, and plain HTTP requests, from one address. | Shared networks fail to reconnect after an outage. | — |
| `relay.abuse.connection_burst` | `50` | The same, at once. | As above. | — |
| `relay.abuse.max_connections_per_address` | `256` | Memory and file descriptors: the WebSocket connections one address holds open at once. Each has its own queued messages, outbound queue and subscriptions, so this bounds how far one host multiplies them. An upgrade past it gets 429 `rate-limited: too many connections from this address`. `0` is unlimited. | Users behind one carrier NAT, office or VPN are refused new connections. Behind a proxy without `relay.real_ip_header`, every client shares one cap. | — |
| `relay.abuse.event_rate_per_second` | `50` | Signature-check CPU and write volume: EVENT and AUTH from one address. | Marmot group invites (a commit plus a Welcome per new member) and bulk publishing fail. | — |
| `relay.abuse.event_burst` | `100` | The same, at once. `marmot` uses 300, for one inviter's commit plus about 250 Welcomes. | As above. | — |
| `relay.abuse.pubkey_event_rate_per_second` | `25` | One key flooding the relay: events per author, or per AUTHed identity for events from other keys; see [Throwaway keys](#throwaway-keys). | Active users, bots and bulk publishing are throttled. | — |
| `relay.abuse.pubkey_event_burst` | `50` | The same, at once. | As above. | — |
| `relay.abuse.invalid_rate_per_second` | `5` | Error replies to malformed messages from one address, including CLOSE and NEG-CLOSE with an invalid subscription id. Valid CLOSE and NEG-CLOSE are never budgeted. | Clients with bugs get fewer error replies to debug with. | — |
| `relay.abuse.invalid_burst` | `20` | The same, at once. Once spent, the client gets one `rate-limited` NOTICE and further malformed messages are ignored until it refills. | As above. | — |
| `relay.abuse.ipv6_prefix_len` | `64` | Leading bits of an IPv6 address that key its per-address budgets, from 1 to 128. IPv4 addresses are keyed one by one. | Unrelated users on one large network share a budget. (Too high: a host picks a new address in its /64 for each connection and escapes every per-address budget.) | — |
| `relay.real_ip_header` | empty | The client address header: the header in which a reverse proxy passes each client's address, trusted by every per-address budget, NIP-86 IP blocks and the write-policy plugin's `sourceInfo`. Wok reads its last entry, and reads `forwarded` as RFC 7239. See [Addresses](#addresses). File-only. | Empty behind a proxy: every client has the proxy's address and shares one set of budgets. | — |
| `relay.trusted_proxies` | empty | The proxies in front of the relay, as IP addresses or CIDR ranges such as `"192.0.2.0/24"`. With `relay.real_ip_header` set, only a connection from one of them may name a client, and their own addresses are skipped from the header's end, so a CDN in front of the proxy works. Empty: any connection may, and the client is the header's last entry. See [Addresses](#addresses). File-only. | Empty behind two proxies: every client of the first shares its budgets. Empty while clients can reach the relay directly: they can name any address. A range that holds clients lets them name any address. | — |

Rate budgets have no standard NIP-11 field; clients learn them only from
refusals.

### Per connection and per address

A REQ, COUNT, NEG-OPEN or NEG-MSG is charged to two budgets, and refused
when either is spent:

- its connection's own (`per_connection.*`): 20 REQs a second with a burst
  of 100, 50 NEG-MSG rounds a second with a burst of 200, and 5 COUNTs a
  second with a burst of 20;
- its address's backstop (`req_*`, `count_*`), which every connection from
  that address shares: 200 REQs a second with a burst of 1,000, and 20
  COUNTs a second with a burst of 50. NEG-MSG rounds draw on the REQ
  backstop.

The connection is charged only when the backstop admits too, so a client
over its own budget does not spend what its address's other connections
have left. Users behind one NAT, office or VPN therefore no longer share a
single 20-REQ budget, and one host still cannot multiply its share without
bound by opening connections.

A REQ that replaces a subscription and a NEG-OPEN start scans, so they draw
on the REQ budgets. NEG-MSG rounds continue a session its NEG-OPEN paid
for, so they have a per-connection budget of their own: a client that runs
a NIP-77 pass per group at startup does not spend the REQs it opens next.

Once a connection has authenticated with NIP-42, its per-connection rates
and bursts are `authenticated_multiplier` (4) times larger, and the larger
burst applies at once. Any key can authenticate on an open relay, so the
backstop is not multiplied. Before 0.8, an AUTHed connection was also
charged to a per-pubkey REQ and COUNT bucket, which made its budget
stricter; those buckets are gone.

Refusals keep `rate-limited:`, because the buckets refill: `CLOSED
rate-limited: REQ budget exhausted` (or `COUNT`, or a NEG-ERR naming
`NEG-OPEN` or `NEG-MSG`) for the connection's own budget, and the same
reason ending `for this address` for the backstop.

Unix-socket connections carry no network address, so by design they bypass
every rate bucket (connection, EVENT, REQ, COUNT, and the per-connection
budgets) and the cap on open connections. Per-author publication, storage
quotas, the query work ceiling and proof of work still apply to them, except
that NIP-62 vanish requests skip proof of work and the storage quotas (see
[Storage](#storage)), so the disk reserve is what bounds a peer that signs
one with each new key. Keep
the socket on a trusted host with tight `mode`, `auth_uids` and `auth_gids`;
the relay warns at startup, and `wok doctor` in its `unix-access` check, when
the mode lets every local user connect and both allow-lists are empty.

### Throwaway keys

Marmot signs each group message (kind 445) with a fresh key, and a gift
wrap (1059) is signed by a random one, so a budget keyed on the author would
be full for every event. When a connection has authenticated and publishes
an event whose author is not one of its identities, the per-author EVENT
budget (`pubkey_event_*`) of the connection's first identity is charged
instead, and a refusal reads `rate-limited: EVENT budget exhausted for the
authenticated pubkey`. Events the identity signs itself draw on the same
budget, from any connection.

An unauthenticated connection's events are charged to their authors, so a
new key per event starts a new budget each time, and throwaway keys are
bounded there only by the per-address EVENT budget. MDK publishes 445s
anonymously until a relay asks it to authenticate, which keeps group
membership unlinkable at the relay.

### Addresses

A per-address budget is keyed by the client's IPv4 address, or by the
`ipv6_prefix_len` leading bits of its IPv6 address: by default every address
in one /64 shares a budget, as addresses on one host or home network
usually do. An IPv4-mapped IPv6 peer (`::ffff:192.0.2.1`) is its IPv4
address. NIP-86 IP bans and the write-policy plugin's `sourceInfo` still
see the exact address.

Behind a reverse proxy the client's address is the proxy's unless
`relay.real_ip_header` names the header in which the proxy passes it. Wok
reads the header's last entry, the address the proxy in front of it wrote,
so a proxy that replaces the header, appends the client's address to it
(nginx's `$proxy_add_x_forwarded_for`), or adds a line of its own (HAProxy's
`option forwardfor`) all work; an entry may carry a port.

`relay.real_ip_header = "forwarded"` reads the RFC 7239 `Forwarded` header
(HAProxy's `option forwarded`): the client is the `for` parameter of its
last element, such as `for=192.0.2.60;proto=https` or
`for="[2001:db8::1]:4711"`. The syntax follows from the header's name, not
its content. That element must be well formed, with one `for`; whatever
comes before it, which the client may have sent, does not matter. Any other
header is read as a list of addresses.

Behind two proxies in a row, such as a CDN and then nginx, the last entry
is the first proxy's address, so every client of that proxy would share one
set of budgets. `relay.trusted_proxies` lists the proxies, as addresses or
CIDR ranges:

```toml
[relay]
real_ip_header = "x-forwarded-for"
trusted_proxies = ["127.0.0.1", "::1", "192.0.2.0/24"]
```

With it set, a connection from outside those ranges is its own address and
its header is ignored. On a connection from inside them, Wok walks the
header's entries from the end and skips each address in a range; the first
address outside them is the client. Each proxy appends the address it was
reached from, so whatever the client sent stays ahead of its address. When
every address is a proxy's, the first is the client. An IPv4-mapped address
is matched as its IPv4 address. A range of every address (`/0`) is refused.

An entry where the client's should be that names no IP address, such as
`unknown` or an obfuscated `for=_hidden`, leaves the connecting address, is
counted by `wok_real_ip_header_unparsed_total`, and is warned about at most
once a minute.

**The header is fully trusted for every per-address budget**, and for
NIP-86 IP blocks and the write-policy plugin's `sourceInfo`. Without
`relay.trusted_proxies`, if the proxy passes a client's header on without
adding the client's address last, or a client can reach the relay directly,
any client can rotate fake addresses to escape the budgets and IP blocks or
spend another address's. With it, a client can do so only from an address inside a
trusted range, or through a listed proxy that passes the header on without
appending the address it was reached from. So the ranges must hold only your
proxies, and each of them must append. If a CDN adds
addresses the ranges miss, its edge at such an address is taken for the
client, and that edge's clients share one set of budgets until the ranges are
updated. The relay warns at startup whenever the header is set, when
`relay.trusted_proxies` is set without it, and when the header is empty
while the relay listens only on loopback or private addresses, as behind a
proxy. Both settings are read for each connection and request, so a reload
that changes either applies at once: it is logged as a security-scope
change, and the warning it newly causes is logged with it. See [production-deployment.md](production-deployment.md).

## Storage

How much the relay stores. The database's own limits measure the real
resource; the event counts sit on top of them. The quotas reload live and are
on the dashboard; the database limits are restart settings, shown read-only.

| Key | Default | Protects | If too low | NIP-11 |
|---|---|---|---|---|
| `relay.abuse.max_stored_events_per_pubkey` | `1000000` | One key filling the disk. `0` is unlimited. | Active users and bots can no longer post new events. At quota, an author can still replace their own replaceable and addressable events and delete their own events. | — |
| `relay.abuse.max_stored_events` | `0` | The disk, by a count of events in all. `0`, the public preset's value, is unlimited. | Once reached, every write on the relay fails but a NIP-62 vanish request. A busy public relay stores far more than 10,000,000 events, the default through 0.7. | — |
| `database.min_free_disk_bytes` | `1073741824` | The filesystem: writes are refused before free space falls below this reserve. `0` turns the guard off. Restart. | Writes stop while the disk still has room. (Off or too small: the disk can fill, and the database with it.) | — |
| `database.map_size` | `68719476736` | The LMDB map ceiling: writes fail atomically once the database reaches it. Address space only; the file grows as data is written. Restart. | Writes fail while the disk still has room. | — |

A write over a quota is refused with `OK false`: `blocked: author storage
quota exceeded`, or `error: global storage quota of <n> events exceeded` for
the whole writer batch, or `error: disk reserve requires <n> free bytes`. Only a
deletion that removes none of the author's events is refused at quota,
since it would add an event and free none.

A NIP-62 vanish request that targets this relay is exempt from both quotas,
since NIP-62 requires a relay to honor it: it is stored over them, and its
author's events are then deleted. The global quota does not count the vanish
requests in a batch, and when the rest of the batch is over it, they are
written on their own. They are not exempt from the disk reserve, which bounds
storage once the quotas do not (see
[attack-surface.md](attack-surface.md#messages)).

The per-author quota is charged to the event's author, so one throwaway key
is held to it, while a new key per event starts a new count each time; even
on an AUTHed connection, whose identity pays the EVENT budget (see
[Throwaway keys](#throwaway-keys)), storage is counted by author. Per-group
(`#h`) and per-recipient quotas are a planned follow-up.

## Sync

NIP-77 negentropy sessions, which clients such as Marmot's use to find what
they are missing. All reload live and are on the dashboard.

| Key | Default | Protects | If too low | NIP-11 |
|---|---|---|---|---|
| `relay.negentropy_enabled` | `true` | Answering NEG-OPEN, and advertising NIP-77. | Off: Marmot clients, which require NIP-77, and other sync clients fall back or fail. | NIP-77 in `supported_nips` |
| `relay.max_sync_events` | `1000000` | The size of one temporary sync view; direct trees do not build one. `marmot` uses 65,536, four times the 16,384 events an MDK session compares. | Large syncs fail with `blocked: too many query results`, and clients fall back to slower REQs. Below 16,385, MDK's `limit`, an MDK sync fails once its group or inbox holds more events than this. | — |
| `relay.sync_memory_per_connection` | `268435456` | Memory the sync sessions of one connection may reserve. A session reserves 4 MiB, plus 256 bytes (1 KiB with `search`) per event of its `limit`, or of `max_sync_events` + 1 without one, unless a tree serves it. `0` refuses every session. `marmot` uses 128 MiB, 15 of MDK's 8 MiB sessions. | Clients that sync many groups at once are refused. At 64 MiB or less, the eighth of the syncs MDK runs at once is refused. | — |
| `relay.sync_memory_total` | `1073741824` | Memory every sync session together may reserve. `0` refuses every session. | Syncs are refused while several clients sync at once; four full syncs use up the default pool. | — |
| `relay.sync_idle_timeout_secs` | `60` | Memory held by abandoned sessions: the longest wait for the client's next round. Active construction has no fixed lifetime. `0` expires sessions at once. | Slow clients' syncs are closed between rounds. | — |

A NEG-OPEN meets every `filter_validation` rule, the query work ceiling and
the read classes, as a REQ does, and draws on the REQ budgets; its rounds draw
on the NEG-MSG budget.

Broad syncs are intended. A sync exists to move many events, up to every
event a relay holds that the client may read, so the query work ceiling counts
only a NEG-OPEN's index seeks, not the rows it matches, and leaves `{}` or
`{"kinds":[1]}` alone. (`relay.filter_validation.require_scoped_filters`, on
in `marmot`, still refuses filters that name no `ids`, `authors` or tag.)
What bounds a sync instead:

- `relay.max_sync_events`, the size of its view. A scan that matches more
  fails with `blocked: too many query results`. A filter served by a tree
  added with `wok negentropy add` builds no view.
- `relay.sync_memory_per_connection` and `relay.sync_memory_total`, reserved
  for the whole view before its scan is scheduled, so a sync that would not
  fit is refused without scanning.
- `relay.abuse.max_concurrent_historical_queries`, the scans one connection
  runs at once, with its NEG-OPENs counted apart from its REQs and COUNTs.
  More wait their turn, and `relay.query_timeslice_budget_us` shares the
  negentropy workers between running scans.
- The work of one round. A reply reads the client's ranges until its
  lookups and fingerprints have cost 65,536 B-tree descents, or it fills
  500,000 bytes, then answers the rest of the range with one fingerprint,
  which the client splits in its next message. A message is never refused
  for the number of ranges it holds.
- Turns. A session answers one NEG-MSG at a time: one the client sent
  before the reply to its last message closes the session with
  `invalid: NEG-MSG sent before the reply to ...`, so a connection cannot
  queue a burst of rounds on a negentropy worker.

With `negentropy_enabled` off, the relay still keeps its negentropy trees
current as it stores and deletes events. Turning NIP-77 back on, which
reloads live, then answers from complete trees at once, and `wok sync`
reconciles from them whatever this setting says. A tree that missed writes
could not be repaired while the relay runs: `wok negentropy build` only adds
records, and a stale tree needs `wok reindex` with the relay stopped. See
[Trees while NIP-77 is off](mesh-and-maintenance.md#trees-while-nip-77-is-off).

## Relay information

All fields reload live and are on the dashboard. They are returned in NIP-11
and presented on the landing page: banner and icon as media, and identity,
contact, and policy values in the Relay information section.

| Key | Default | Meaning |
|---|---|---|
| `relay.info.name` | `"wok default"` | Relay display name. |
| `relay.info.description` | `"This is a wok instance."` | Public relay description. |
| `relay.info.pubkey` | empty | Operator public key, npub or hex. |
| `relay.info.self_pk` | empty | Relay public key published as NIP-11 `self`. |
| `relay.info.contact` | empty | Operator contact. |
| `relay.info.icon` | empty | Square icon URL. |
| `relay.info.banner` | empty | Wide banner image URL. |
| `relay.info.privacy` | empty | Privacy-policy URL. |
| `relay.info.terms` | empty | Terms-of-service URL. |

`relay.info.nips` intentionally does not exist. Supported NIPs are derived
from compiled behavior and feature settings so metadata cannot claim
unimplemented behavior.

## Advanced

Scheduling, slow clients, the write-policy plugin, vanish deletions and the
dashboard's history. All reload live.

| Key | Default | Protects | If too low | NIP-11 |
|---|---|---|---|---|
| `relay.query_timeslice_budget_us` | `10000` | Fairness between running scans: CPU time a scan runs before it lets others run. Dashboard. | Scans switch more often, which costs overhead. (Too high: short queries wait longer behind long ones.) | — |
| `relay.max_pending_outbound_bytes` | `33554432` | Memory held for a slow reader: output queued for one connection before it is disconnected. `0` never disconnects. New connections; dashboard. | Large backfills on slow links disconnect, counted by `wok_slow_client_terminations_total`. | — |
| `relay.max_live_buffer_bytes` | `262144` | Live matches held for one subscription while its history is sent. Past it, stored events are re-read from the database after the history, and the oldest ephemeral events are dropped (`wok_live_buffer_dropped_ephemeral_total`). `0` is unlimited. New subscriptions; file-only. | Busy subscriptions re-read more from the database, and lose ephemeral events. | — |
| `relay.write_policy_plugin` | empty | An external executable that decides on each event; empty turns it off. Vanish requests skip it. File-only. | — | — |
| `relay.write_policy_timeout_secs` | `10` | Writes, from a hung plugin: the longest wait for its verdict. Dashboard. | A slow plugin's verdicts time out, and its events are refused. | — |
| `relay.nip62.deletion_batch_size` | `1000` | The writer: index entries the vanish sweep examines, and vanished keys it visits, in each maintenance transaction (every 2 s), so also the records it removes. Dashboard. | A vanish request takes more, smaller transactions: at 1000, a key that a million events tag takes about half an hour. | — |

Valid vanish requests are hidden immediately, deletion markers stay enforced
if NIP-62 is later turned off, and physical removal continues in bounded
batches. The sweep examines a vanished key's events, then the events that tag
it, once: it resumes where it stopped, after a restart too, and a later
request from the key sweeps only the events it adds.

## Listener and protocol

Restart settings, unless noted, and file-only.

| Key | Default | Meaning |
|---|---|---|
| `relay.bind` | `"127.0.0.1"` | TCP listen address: an IPv4 or IPv6 literal (`::1` or `[::1]`), or a hostname. A hostname listens on every address it resolves to (`localhost` → `127.0.0.1` and `::1`), skipping resolved addresses that are not assigned on this host or whose family it lacks, as long as one binds. |
| `relay.port` | `7777` | TCP listen port. |
| `relay.nofiles` | `524288` | Requested process file-descriptor limit. |
| `relay.max_websocket_payload_size` | `2097152` | Largest reassembled WebSocket message; it must hold the largest event and its envelope, and the largest REQ and COUNT. Too low: events, REQs and COUNTs that fit their own limits are cut off with their connection, and the `message-caps` warning says so. NIP-11 `max_message_length`. Shown read-only on the dashboard. |
| `relay.auto_ping_seconds` | `55` | WebSocket ping interval; zero disables automatic pings. A ping unanswered for a full interval closes the connection. |
| `relay.enable_tcp_keepalive` | `false` | Enable TCP keepalive on accepted sockets. |
| `relay.handshake_timeout_secs` | `10` | Pre-upgrade HTTP header read deadline (slowloris guard); zero disables it. Live, for new connections. |
| `relay.frame_read_timeout_secs` | `30` | Longest idle gap between socket reads while a partial WebSocket frame or unfinished fragmented message is buffered (slow-trickle guard); zero disables it. Live, for new connections. |
| `relay.message_read_timeout_secs` | `120` | Longest a WebSocket message or control frame may take to arrive, from its first byte to its last, so a client that sends a little at a time within the frame gap cannot keep a message buffered for long; zero disables it. A pause while the relay does not read, because the connection's hold is full, does not count. 120 seconds lets a 2 MiB message arrive at about 140 kbit/s. Live, for new connections. |
| `relay.nodeinfo_enabled` | `false` | Serve [NodeInfo](https://nodeinfo.diaspora.software/) at `/.well-known/nodeinfo` and `/nodeinfo/2.1`, for fediverse-style crawlers; no Nostr client uses it, and NIP-11 carries the same software and version. Off: both paths answer 404. Discovery links to `/nodeinfo/2.1` on the origin of `relay.auth.service_url` (`wss` read as `https`), or else `admin.public_url`, never the request's `Host` header; with neither set it answers 404, and the relay and `wok doctor` warn. Live. |
| `relay.compression_enabled` | `true` | Enable permessage-deflate negotiation. Off in `marmot`. A compressed message may inflate to half of `relay.max_websocket_payload_size` plus 64 KiB, and past that to at most 32 times its compressed size, never past the maximum. |
| `relay.compression_sliding_window` | `true` | Reuse compression context between messages. With context takeover, a connection's compressor can reference bytes from previous messages, the precondition for CRIME/BREACH-style oracles when secret and attacker-influenced bytes share a compression context. Relay traffic is essentially all public data, so practical impact is nil for most operators; if you serve auth-bearing or otherwise secret traffic over the same client connections, prefer `false`. |
| `relay.ingester_threads` | `3` | Event-ingestion worker count. |
| `relay.req_worker_threads` | `3` | Historical query worker count. |
| `relay.req_monitor_threads` | `3` | Query monitor worker count. |
| `relay.negentropy_threads` | `2` | Negentropy worker count. |
| `relay.dump_in_all` | `false` | Diagnostic logging for every inbound client message. Live. |
| `relay.dump_in_events` | `false` | Diagnostic logging for inbound EVENT messages. Live. |
| `relay.dump_in_reqs` | `false` | Diagnostic logging for inbound REQ messages. Live. |
| `relay.db_scan_perf` | `false` | Emit database scan performance diagnostics. Live. |
| `relay.invalid_events` | `true` | Log invalid-event diagnostics. Live. |

## Database

Restart settings, file-only. `database.map_size` and
`database.min_free_disk_bytes` are under [Storage](#storage).

| Key | Default | Meaning |
|---|---|---|
| `database.path` | `"./wok-db/"` | Wok-owned LMDB directory. |
| `database.max_readers` | `256` | LMDB reader-slot ceiling. |
| `database.no_read_ahead` | `false` | Disable LMDB read-ahead for workloads where it is counterproductive. |

## Admin

Live, file-only. A reload that changes any of them is logged as a
security-scope change, naming the keys added to and removed from
`admin.pubkeys`. A key taken out of `admin.pubkeys` that still holds the
NIP-86 `admin` or `moderator` role keeps that level while `admin.enabled`
is on, until the role is unassigned; the reload warns about each one. Each authorized
NIP-86 request is logged at `info` with its signer, level and method.

| Key | Default | Meaning |
|---|---|---|
| `admin.enabled` | `false` | Serve the signed-out shell at `/admin`; APIs still require NIP-98. |
| `admin.public_url` | empty | Exact public HTTP(S) origin used to verify the NIP-98 `u` tag. |
| `admin.pubkeys` | `[]` | Allowed administrator npubs or lowercase hex public keys. They are also [members](#read-and-write-policies) whether or not `admin.enabled` is on. |
| `admin.auth_window_secs` | `60` | Accepted NIP-98 freshness window, from 1 through 300 seconds. |
| `admin.allow_config_writes` | `false` | Permit typed, validated, atomic dashboard writes. |

Each `admin.pubkeys` entry is read as lowercase hex, an npub converted,
whether or not `admin.enabled` is on. While it is on, an entry that is no key
refuses the file. While it is off, the file still loads and the entry grants
nothing; the relay warns about it at startup and on reload, and `wok doctor`
reports it in its `admin-pubkeys` check.

The public URL must have no credentials, path, query, or fragment. Each API
request needs a new kind-27235 event with empty content, exactly one matching
`u` and `method` tag, and, when a body is present, a SHA-256 `payload` tag.
Authorization events are single-use: an event's ID is kept for 300 seconds,
the longest `auth_window_secs` allows, whatever the current window, so a
reload that narrows it and one that widens it again do not let a used event
through twice. The browser delegates signing to NIP-07;
Wok never receives private key material.

## Observability

| Key | Default | Meaning |
|---|---|---|
| `observability.log_format` | `"pretty"` | Human-readable `pretty` or newline-delimited `json`. Restart. |
| `observability.log_filter` | `"wok=info"` | tracing filter; `RUST_LOG` overrides it at startup. Restart. |
| `observability.history_enabled` | `true` | Collect bounded in-memory dashboard samples. Disabling clears them. Live; dashboard. |
| `observability.history_interval_secs` | `15` | Seconds between samples; at least 1. Live; dashboard. |
| `observability.history_max_points` | `5760` | FIFO sample bound, from 0 through 100,000. Live; dashboard. |
| `observability.metrics_enabled` | `false` | Serve Prometheus metrics at `/metrics`. Live. |
| `observability.metrics_listen` | `""` | An IP address and port, such as `"127.0.0.1:9777"`, for a listener that serves only `/metrics`; empty serves it on the relay listener. Restart. |

See [Observability](observability.md) for every exported metric and label.

Metrics are off unless `metrics_enabled` is set. On the relay listener,
`/metrics` is served to anyone who can reach the relay, with
`Access-Control-Allow-Origin: *`, so any web page can read its connection,
event, AUTH and refusal counters cross-origin; the relay warns at startup when
that listener is reachable beyond loopback and private addresses, at startup
and on a reload that turns metrics on. Set `metrics_listen` to a private
address instead: that listener serves only `GET /metrics`, without CORS
headers, and the relay listener answers `/metrics` with 404. Like the relay
listener it refuses NIP-86 IP blocks and charges the per-address connection
budget, and the relay warns when its address is reachable beyond loopback and
private addresses. The listener is bound at startup whenever
`metrics_listen` is set, and answers 404 while `metrics_enabled` is off, so
metrics can be turned on and off with a reload. Turning them on or off is
logged as a security-scope change. A reload that changes `metrics_listen` is
logged too, and the running listener stays until restart; on a relay started
without one, metrics stay off until that restart rather than be served on the
relay listener.

```toml
[observability]
metrics_enabled = true
metrics_listen = "127.0.0.1:9777"
```

## Unix socket

All Unix-socket settings require restart and are file-only.

| Key | Default | Meaning |
|---|---|---|
| `relay.unix.enabled` | `false` | Listen on the local framed-JSON Unix socket. |
| `relay.unix.path` | `"./wok-db/wok.sock"` | Socket filesystem path. |
| `relay.unix.mode` | `0o600` | Permission bits, as TOML octal or decimal. |
| `relay.unix.owner` | empty | User applied with `chown` after bind. |
| `relay.unix.group` | empty | Group applied with `chown` after bind. |
| `relay.unix.auth_uids` | `[]` | Allowed peer UIDs; empty accepts any UID. A peer must pass this list and `auth_gids` both. |
| `relay.unix.auth_gids` | `[]` | Allowed peer GIDs; empty accepts any GID. Only the peer's effective GID is checked, not its supplementary groups. |
| `relay.unix.max_frame_bytes` | `2097152` | Largest length-prefixed JSON frame. Like `relay.max_websocket_payload_size`, it must hold the largest event, REQ and COUNT, and the `message-caps` warning says when it does not while the socket is on. `marmot` uses 8 MiB. |
| `relay.unix.max_pending_outbound_bytes` | `33554432` | Pending output budget before disconnect. |

`auth_uids` and `auth_gids` combine with AND. With either set, the relay
reads the connecting process's effective UID and GID as they were when it
connected (`SO_PEERCRED` on Linux, `getpeereid` elsewhere) and admits it only
if the UID is in `auth_uids` and the GID in `auth_gids`, an empty list
matching anything. Any other peer, or one whose credentials cannot be read,
is disconnected before its first frame is read. So `auth_uids = [1000]` with
`auth_gids = [1001]` admits UID 1000 only while its effective group is 1001,
not "UID 1000 or members of group 1001", and no supplementary group ever
matches `auth_gids`. To admit every member of a group, leave both lists
empty and set `group` with a `mode` such as `0o660`: Linux and macOS check
the socket file's mode against all of a connecting process's groups.

See [Unix socket protocol](unix-socket.md) for framing and peer authorization.

## Limits that are not settings

These are fixed by a NIP or by the storage format.

| Limit | Value | Note |
|---|---|---|
| Subscription id | 64 characters | NIP-01. NIP-11 `max_subid_length`. |
| One filter's value list | 65,535 decoded bytes | At most 2,047 `authors`, `ids`, `#e` or `#p` values per filter. |
| Queryable tag value | 255 bytes indexed as is | Longer values, up to `max_tag_val_size`, are indexed by their SHA-256. |
| NEG-OPEN and NEG-MSG payload | 1 MiB | |
| AUTH identities per connection | 64 | The first is the connection's rate-limit identity. |
| AUTH timestamp window | ±600 s | NIP-42. |
| Gift wrap (21059) backdating | 3 days | NIP-59's two days, plus one. |
| Event kind | 0–65,535 | |
| Size settings | 16 MiB | Event, frame and payload sizes are clamped to it. |

## Files from 0.7 and earlier

Settings a release replaced still load, as their translation, so the relay
behaves as before. Each is warned about at startup, on reload, and in
`wok doctor`'s `config-deprecations` check; `wok config minimize` and
dashboard saves rewrite it as its translation, and `wok migrate strfry`
translates strfry's keys the same way. The translated keys are accepted for
this release and will be removed in a later one.

### Read keys

Through 0.7, `relay.auth.restricted_read_kinds` listed the restricted kinds,
and `restrict_read_to_involved_pubkey` chose how they were restricted:
- **`restricted_read_kinds`** becomes `recipient_only_kinds`, with the same
  kinds and the same readers. A file that sets both keys is refused.
- **`restrict_read_to_involved_pubkey = true`** is dropped: it was the
  default, and recipient-only kinds always work that way.
- **`restrict_read_to_involved_pubkey = false`** is no longer supported. It
  skipped the per-event check, so a REQ that mixed in another kind, such as
  `[{"kinds":[1]},{"kinds":[1059]}]`, returned the restricted kinds without
  AUTH (strfry's behavior). Its kinds, from `restricted_read_kinds` or the
  preset, become `authenticated_kinds`, which any authenticated connection
  may read and no other can, and `recipient_only_kinds` becomes empty.

A kind the old list shares with `owner_only_kinds`, such as 30078 listed to
hide app data, keeps the stricter owner-only class, and the warning names it.

### Write key

Through 0.7, `relay.auth.restrict_writes = true` accepted only events whose
author was a member, so an allowlisted relay refused every Marmot group
message and gift wrap, which are signed by throwaway keys:
- **`restrict_writes = true`** becomes `write_policy = "members"`. Members'
  own events are accepted as before; so are events a member sends on a
  connection authenticated as them, and gift wraps addressed to a member
  (`inbox_kinds`; set it to `[]` to refuse them). A file that also sets
  `write_policy` is refused.
- **`restrict_writes = false`** is dropped: `write_policy = "open"` is the
  default.

### Filter validation section

Through 0.7 the `[relay.filter_validation]` section applied its rules only
with `enabled = true`, and had its own filter counts, `max_filters_per_req`
and `min_filters_per_req`. Those three keys are gone:

- **`enabled = false`**: every rule in the section is ignored, as before.
  This is what copies of the 0.7 `docs/wok.toml` set.
- **`enabled = true`**: the section's rules still apply, with 0.7's default
  of 3 for a `max_kinds_per_filter` it leaves out.
  - Its `max_filters_per_req`, or 0.7's default of 3, becomes
    `relay.max_filters_per_req` when it is lower. Such a REQ is now refused
    with `invalid: bad req: arr too big`.
  - `min_filters_per_req` is dropped. A REQ needs only one filter.
  - `max_kinds_per_filter = 0` refused every filter that lists kinds. Zero
    now means no limit, so those filters are accepted, with a warning at
    startup and in `wok doctor`. To restrict kinds, set `allowed_kinds`.
- **No `enabled`**: the section is read as a current one, so each rule it
  sets applies. Under 0.7 a section without `enabled` was off.

`wok migrate strfry` translates strfry's `relay.filterValidation` the same
way; strfry's section is off unless `enabled = true`.

### Query cost

`relay.abuse.max_query_cost`, which copies of the 0.7 `docs/wok.toml` set to
1000, is ignored, with a warning. Its values would mean something else in
the units of `max_query_work`: 1,000 would refuse every filter without a
`limit`, such as `{"kinds":[1]}` (2,001). `wok config minimize`, or a
dashboard save, removes it. To set a ceiling, set `max_query_work`.

### Rate keys

Copies of the 0.7 `docs/wok.toml` pin `req_rate_per_second = 20`,
`req_burst = 40`, `count_rate_per_second = 5` and `count_burst = 10`. These
keys keep their meaning, a per-address budget, so such a file keeps the old
per-address limits under the new per-connection ones, and `wok doctor`
lists them.
