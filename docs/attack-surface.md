# Attack surface

This page lists every way input reaches Wok: the network listener, the Unix
socket, the files and commands an operator runs, and the relays Wok dials. For
each entry point it names who can send the input, the gate that decides
whether Wok serves it, and the work Wok does before that gate decides. Code
that runs before a gate is reachable by everyone the gate would refuse.

Tests keep the inventory tables in step with the code; see
[Keeping this page current](#keeping-this-page-current). Report a
vulnerability through [SECURITY.md](../SECURITY.md), not by editing this page.

## Using this page

When you add or change an entry point, update its row and ask three
questions:

- **Default configuration.** Is the code reachable with no settings at all
  (the [`default`](#profiles) profile), or with a shipped preset (`marmot`)?
  If no default feature needs it, put it behind a setting that is off by
  default.
- **Work before the gate.** What runs before the gate decides? Parsing,
  decoding, signature verification and allocation all belong after the
  cheapest check that can refuse the request.
- **Setting combinations.** Can another setting make this gate fail open or
  be ignored, without an error at load or a warning? Refuse such a
  combination when the configuration loads, or warn about it there and in
  `wok doctor`, and add the setting to the
  [combinations test](#setting-combinations).

## Who can reach Wok

| Party | Who | Gate |
| --- | --- | --- |
| anonymous | Any client that can connect to `relay.bind` and `relay.port` | Per-address connection budget; NIP-86 IP blocks |
| authenticated | A client that completed NIP-42 AUTH on its connection | `relay.auth.enabled` and `relay.auth.service_url` |
| member | A client authenticated as a pubkey that is NIP-86 allowlisted, holds a role, or is in `admin.pubkeys`, and is not banned | `relay.auth.read_policy` and `write_policy` set to `members` |
| manager | A NIP-98 signer holding the NIP-86 `admin` or `moderator` [role](nip86.md#management-levels) | `admin.enabled` |
| admin | A NIP-98 signer listed in `admin.pubkeys` | `admin.enabled` |
| local peer | A process that can connect to `relay.unix.path` | `relay.unix.enabled`, the socket's file mode, `relay.unix.auth_uids` and `auth_gids` |
| metrics scraper | Whatever can reach `observability.metrics_listen` | The address the operator binds it to |
| operator | Whoever writes the config file, runs `wok` commands, or sets the write-policy plugin | Filesystem permissions |
| remote relay | A relay that `wok sync`, `router`, `upload` or `download` dials | The operator chose its URL |

Unix-socket peers have no network address, so no per-address or
per-connection budget applies to them. The per-author EVENT budget still
does.

## Network listener

Every request on the listener passes these steps before Wok looks at its path:

1. Hyper reads the request head, within `relay.handshake_timeout_secs`.
2. With `relay.real_ip_header` set, the client's address is that header's
   last entry, across all of its lines: the one the proxy in front of Wok
   wrote. An entry may carry a port. A last entry that is not an IP address
   leaves the connecting address and is counted in
   `wok_real_ip_header_unparsed_total`; no header leaves it too.
3. An address blocked with NIP-86 `blockip` gets 429, and so does one whose
   per-address connection budget (`relay.abuse.connection_*`) is spent.

Wok does not check the method on the public paths: every method gets the same
answer, except `OPTIONS`, which gets the CORS preflight (204), and a `POST` to
`/` with `Content-Type: application/nostr+json+rpc`, which goes to the
[management API](#management-api). Any other path gets 404, and so does a
WebSocket upgrade on any path but `/`.

| Path | Party | Gate | What runs |
| --- | --- | --- | --- |
| `/` | anonymous | none | A WebSocket upgrade starts a [message](#messages) connection. A `POST` with `Content-Type: application/nostr+json+rpc` goes to the [management API](#management-api). Anything else gets the NIP-11 document when `Accept` names `application/nostr+json`, and the landing page otherwise. |
| `/metrics` | anonymous | `observability.metrics_enabled` and no `observability.metrics_listen` | Prometheus metrics, with `Access-Control-Allow-Origin: *`. With `metrics_listen` set they move to the [metrics listener](#metrics-listener). See [observability](observability.md). |
| `/.well-known/nodeinfo` | anonymous | none | NodeInfo discovery. The link's host is the request's `Host` header. |
| `/nodeinfo/2.1` | anonymous | none | The NodeInfo document. |
| `/favicon.ico` | anonymous | none | A fixed empty icon. |
| `/admin`, `/admin/` | anonymous | `admin.enabled` | `GET` returns the signed-out [dashboard](admin-dashboard.md) shell, which holds no relay data. Other methods get 404. |
| `/admin/api/*` | admin | `admin.enabled` | Every method and path under the prefix checks its NIP-98 `Authorization: Nostr` header before reading the body: it decodes the header and parses its event strictly; checks its kind, empty content, time window and `u` and `method` tags; checks that the signer it names is in `admin.pubkeys`; and verifies the event and its signature. A request that fails any of these is refused without its body being read. A signer not in the list and a bad signature get the same 401, so a forged event cannot ask which keys are admins. It then reads the body (at most 64 KiB), checks the time window again and the `payload` tag when the request has a body, and claims the event in the replay cache. Only then does it route, to `GET /admin/api/overview` or `PUT /admin/api/config`; configuration writes also need `admin.allow_config_writes`. |

## Metrics listener

With `observability.metrics_listen` set, Wok binds a second listener at that
address when it starts, and warns when the address is reachable beyond
loopback and private networks. It is meant for a private address, so it sends
no CORS headers. Hyper reads the request head within
`relay.handshake_timeout_secs`. Like the relay listener, every request then
passes NIP-86 IP blocks and the per-address connection budget, keyed on the
connecting address, and any path or method but these gets 404.

| Path | Party | Gate | What runs |
| --- | --- | --- | --- |
| `/metrics` | metrics scraper | `observability.metrics_enabled` | `GET` returns the Prometheus metrics; 404 while metrics are off, which a reload can change. |

## Messages

WebSocket and Unix-socket connections carry the same client messages to the
same ingester. Before Wok reads a message's verb:

- **WebSocket:** Wok's own RFC 6455 codec decodes the frames and, when the
  client negotiated permessage-deflate (`relay.compression_enabled`), inflates
  the message, up to `relay.max_websocket_payload_size`. Past half that size
  plus 64 KiB, a message may inflate to at most 32 times its compressed
  size; one past its limit is refused before more of it is inflated. `relay.frame_read_timeout_secs` is the
  longest gap between reads while part of a frame or message is buffered;
  a pause while the relay does not read, because the connection's hold is
  full, does not count against it.
- **Unix socket:** the peer check runs once, when the connection is accepted
  and before any frame is read. Each frame's four-byte length is checked
  against `relay.unix.max_frame_bytes` before its body is read.
- A connection's messages wait for the ingester in a queue it shares with
  other connections. Each connection may have at most the largest message a
  transport accepts there, in bytes, and at most 64 messages, not yet
  handled. The next one is held until there is room and a slot, and the
  transport stops reading once its hold is full, while it keeps writing to
  the client. A WebSocket read is decoded about a maximum message at a time,
  the rest left compressed until the hold has room.
- The whole message is parsed as strict JSON. A malformed message spends the
  invalid-message budget (`relay.abuse.invalid_*`). A message that is exactly
  `"\n"` is a keepalive and does nothing.

| Message | Party | Gate | Checks, in order |
| --- | --- | --- | --- |
| `EVENT` | anonymous | none | Per-address EVENT budget; by the kind the event states, an AUTH event (22242) is refused, and so is a kind `relay.auth.accepted_kinds` (kind 62 is exempt while NIP-62 is on) or the NIP-86 kind policy does not allow; event parse, size and tag limits, timestamp window, id and signature verification; event-id ban, author ban and `relay.auth.write_policy`; a NIP-62 vanish request must name this relay; NIP-13 proof of work; the per-author budget, charged to the connection's first AUTHed identity when another key signed the event; a repost may not embed a protected event; NIP-70 protected events and `relay.auth.owner_only_kinds` need the author's AUTH; an event already stored is answered `duplicate:` and goes no further. The writer then runs the write-policy plugin; only an event it accepts is checked again against stored vanish requests, the bans, the kind policy, `accepted_kinds` and the write policy, then against the storage quotas. A vanish request skips the author ban, the write policy, the plugin, the NIP-70 and owner-only checks and the stored vanish markers, but not the event-id ban, the kind policy, proof of work or the per-author budget. The author ban and the write policy wait for the signature, so an unsigned event cannot ask whether a key is a member or banned. |
| `AUTH` | anonymous | `relay.auth.enabled` and `relay.auth.service_url` | Per-address EVENT budget; the gate; the connection must hold a challenge; kind 22242, this connection's `challenge` and the relay's `relay` tag, as the event states them; event parse and signature verification. |
| `REQ` | anonymous | none | The connection's REQ budget, which is larger once authenticated, then the address's REQ backstop (see [rates](config.md#rates)); a connection over its own budget does not spend the backstop; subscription id; `relay.auth.read_policy`; filter count and bytes; filter parse and validation (`relay.filter_validation`); query-work estimate; AUTH when every filter asks only for restricted [read classes](config.md#read-classes); subscriptions and filter bytes per connection. Each matching event is then checked against the read classes before it is sent. |
| `COUNT` | anonymous | `relay.max_filter_limit_count` above 0 | As `REQ`, with the COUNT budgets, and a COUNT that may count restricted kinds must name only what the connection may read. The gate is checked after the filter count and bytes. |
| `CLOSE` | anonymous | none | A valid `CLOSE` is never budgeted; one with an invalid id spends the invalid-message budget. |
| `NEG-OPEN` | anonymous | `relay.negentropy_enabled` | The REQ budgets, as for `REQ`; subscription id; the gate; `relay.auth.read_policy`; payload size; filter bytes (`relay.max_req_filter_size`); filter parse and validation; query-work estimate; AUTH for restricted kinds; hex decoding of the payload. The negentropy worker then checks the read policy again, sessions per connection, the connection's sessions' filter bytes (`relay.max_filter_bytes_per_connection`) and the sync memory budgets. |
| `NEG-MSG` | anonymous | `relay.negentropy_enabled` | The connection's NEG-MSG budget, then the address's REQ backstop; subscription id; the gate; payload size and hex decoding; the session lookup. |
| `NEG-CLOSE` | anonymous | `relay.negentropy_enabled` | The gate first. It has no budget: the negentropy worker handles a run of them as one removal each, before the snapshot it takes for other messages. |

## Management API

NIP-86 requests are a `POST` to `/` with
`Content-Type: application/nostr+json+rpc`. They get 404 unless
`admin.enabled` is set. Before reading the body, Wok checks the NIP-98
`Authorization: Nostr` header as the dashboard API does, with a required
`payload` tag and the `u` tag compared with `admin.public_url`, and refuses a
request that fails. In place of `admin.pubkeys`, the signer the event names
must hold a management level, checked before the signature is verified; a
signer with none and a bad signature get the same 401, and neither claims a
replay slot. Wok then reads the body (at most 64 KiB), checks the time window
and the signer's level again and the body against the `payload` tag, and
parses it. The body
must name a `method` and a `params` array, refuses a method that is not in
its method table or is above the signer's level, and only then reads the
method's parameters.
[nip86.md](nip86.md#supported-methods) lists every method with the level it
needs. With `relay.auth.accepted_kinds` set, the kind-policy methods work
under that ceiling: `allowkind` cannot make the relay accept a kind the file
does not list.

## Operator inputs

| Input | Read by | Notes |
| --- | --- | --- |
| Config file | `wok relay` and the other commands | Strict TOML. `wok relay` checks the file every second and reloads `Live` settings; a file that fails to parse keeps the running configuration. Without a file at the `--config` path, `wok relay` and the database commands run on the built-in defaults with a warning. |
| Write-policy plugin | The writer | `relay.write_policy_plugin` runs through `sh -c`; event JSON goes to its standard input. See [write-policy plugins](production-deployment.md#write-policy-plugins). |
| Dashboard configuration writes | `PUT /admin/api/config` | Admin only, with `admin.allow_config_writes`. Admin credentials, proxy trust, the access settings (shown read-only), plugin paths and restart-only settings stay file-only; see [config.md](config.md#reload-and-dashboard-boundaries). |
| Management state | NIP-86 | Bans, allow lists, roles, kind policy and IP blocks are stored in the database and apply at once. The relay-info methods edit the config file like a dashboard write. |

### Commands

| Command | Reads | Notes |
| --- | --- | --- |
| `wok relay` | Config file, the network, the Unix socket | Everything on this page. |
| `wok info` | Database | |
| `wok migrate strfry` | strfry LMDB environment and config | Opens the strfry database through LMDB FFI and parses its HOCON-subset config. Runs `lsof` to check that no process has the database open. Writes only a new directory. |
| `wok config show` | Config file | |
| `wok config minimize` | Config file | Rewrites the file and keeps the original as `<file>.bak`. |
| `wok doctor` | Config file, database, runtime paths | |
| `wok reindex` | Database | Needs `--confirm-relay-stopped`; keeps the original as a sibling backup. |
| `wok import` | JSONL events on standard input | Verifies ids and signatures unless `--no-verify`. |
| `wok export` | Database | Writes JSONL to standard output. |
| `wok scan` | Filter argument, database | |
| `wok event` | Database | |
| `wok delete` | Filter argument, database | |
| `wok purge-superseded` | Database | |
| `wok compact` | Database | Writes a copy to the output file, or to standard output for `-`. |
| `wok monitor` | Lines on standard input, database | Each line is bounded by `events.max_event_size`. |
| `wok dict stats` | Filter argument, database | |
| `wok dict train` | Filter argument, database | |
| `wok dict compress` | Filter argument, database | |
| `wok dict decompress` | Filter argument, database | |
| `wok negentropy list` | Database | |
| `wok negentropy add` | Filter argument, database | |
| `wok negentropy build` | Database | |
| `wok integrity` | Database | |
| `wok sync` | A remote relay | Parses its NIP-77 messages; verifies each downloaded event before storing it. |
| `wok upload` | JSONL events on standard input, a remote relay | Sends the events to the URL. |
| `wok download` | A remote relay | Prints the events it receives without verifying them. |
| `wok router` | Router config file, every relay it names | Verifies each downloaded event before storing it. Reloads the router config when it changes. |

Outbound commands dial whatever URL they are given, including loopback and
private addresses; see [outbound connections](mesh-and-maintenance.md#outbound-connections).

## Profiles

The attack-surface tests start relays from a set of configuration files in
[`crates/wok-compat/tests/profiles/`](../crates/wok-compat/tests/profiles/).
Each one is a native TOML file, loaded like any other, and stands for one way
of running Wok. A test only points it at a temporary database and port.

| Profile | Stands for |
| --- | --- |
| `default` | No settings: what a relay runs before its operator configures it. AUTH is unusable, and the dashboard, NIP-86 and the Unix socket are off. |
| `public` | A public relay configured as [wok.toml](wok.toml) asks: AUTH works, so DMs and gift wraps reach their recipients. |
| `marmot` | The `marmot` preset, as a Marmot app's default relay runs it: `relay.auth.accepted_kinds` limits it to the kinds MDK publishes, every filter must be scoped, COUNT and compression are off, and writes stay open. |
| `gated` | A members-only relay: `relay.auth.read_policy` and `write_policy` set to `members`, AUTH, the dashboard and NIP-86. |
| `minimal` | Every optional capability off: negentropy, COUNT, NIP-91, NIP-62, AUTH and compression. |
| `proxied` | Behind a reverse proxy that passes the client's address in `X-Real-IP`. |
| `unix` | The Unix socket on, limited to one UID. |
| `monitored` | A public relay scraped by Prometheus on a private address: metrics on, on a listener of their own. |

A test checks that each profile still has the properties in this table, so a
change of default cannot quietly make a profile stand for something else.
`minimal` must turn off every capability that some setting can turn off.

## Golden transcripts

`wok-compat` `tests/golden_transcripts.rs` sends one fixed script to a relay
of every profile:
- events that are accepted, duplicated, forged, mistimed or refused by a
  gate, and REQs, COUNTs and NEG-* messages that are served or refused;
- malformed messages, and AUTH with right and wrong challenges and
  signatures;
- HTTP requests for NIP-11, the landing page, `OPTIONS /`, `/metrics` and
  `/admin`; the dashboard API and NIP-86 unsigned, signed by a stranger and
  forged; and `/metrics` on the metrics listener when the profile has one.

It saves what the relay answers in `tests/transcripts/<profile>.txt`. Ids,
keys and signatures are numbered in order of first appearance, timestamps are
offsets, and the AUTH challenge and the NIP-11 `version` are placeholders, so a
transcript is the same on every run. HTML pages and the Prometheus text are
recorded by status and content type only, so a change to those bodies, or to
a path the script does not request, does not show here.

A change that moves a check, such as refusing a request before its signature
is verified, changes some answers. Rerun the test with
`WOK_BLESS_TRANSCRIPTS=1` and review the diff of `tests/transcripts/` in the
pull request: lines that change should be the requests the change is meant to
refuse differently, and nothing in the `default` or `public` transcripts
should change unless that is the point of the change.

## Reachability

`scripts/attack-surface-reach.py` measures which relay functions each kind of
caller reaches. It builds the `wok-compat` `tests/reachability.rs` probe with
coverage instrumentation and runs its phases against a relay of every
profile, each phase in a process of its own:

- **startup** starts the relay, and its Unix socket when the profile
  enables it, and stops it;
- **anonymous** sends what a client that never authenticates can: every
  message verb, well formed and malformed, every method on each path of the
  listeners, and NIP-98 requests unsigned, signed by a stranger, and forged
  in a stranger's name and in an admin's; and it connects to the Unix socket
  as a peer the socket refuses;
- **authenticated** authenticates with NIP-42 and sends what AUTH unlocks;
- **admin** calls the dashboard API and every NIP-86 method as an admin;
- **local** sends the anonymous messages over the Unix socket as a peer it
  admits.

A phase the profile closes, such as admin without `admin.enabled`, sends
nothing. The probe shares its process with the relay, so it signs events,
frames Unix messages and builds its NIP-77 message without the relay's
crates: every function counted is one the relay ran.

From each run it keeps the functions of the relay crates (`wok-relay`,
`wok-ws`, `wok-unix`, `wok-event`, `wok-query`, `wok-negentropy` and
`wok-db`) that ran at least once. The anonymous set is what an
unauthenticated client reaches beyond startup, the authenticated set is what
AUTH adds to that, the admin set is what an admin's requests add to that,
and the local set is what an admitted Unix peer adds to that.
`crates/wok-compat/tests/reachability/<profile>.txt` lists each set by
function name, with its size in the phase's heading. A closure is named by
the function that holds it, without its number.

```bash
scripts/attack-surface-reach.py            # print the sizes and what changed
scripts/attack-surface-reach.py --check    # fail on a function newly reached
scripts/attack-surface-reach.py --bless    # rewrite the baseline
```

It needs `cargo-llvm-cov` and the `llvm-tools-preview` rustup component, and
CI does not run it. Run `--check` on a change that adds a path, a message or a
setting, or moves a check. A function the anonymous phase newly reaches is
code an unauthenticated client can now run: it belongs after the cheapest
check that can refuse the request, or the baseline is rewritten with the
reason in the pull request. A phase whose baseline lists functions and that
now reaches none also fails, and so does a profile with no baseline. An
emptied phase is intended when the profile now closes that caller, since the
probe skips a closed caller, or when what that caller added was removed or
now runs for anonymous callers: rewrite the baseline with the reason. When
the caller is still open and the probe did not send, the probe is broken. A
function no longer reached is listed but does not fail. Some functions run on
some runs and not others, such as a query path that depends on timing, so
`--bless` keeps the union of three runs, and the database watcher, which runs
on a timer, is left out.

## Setting combinations

`wok-compat` `tests/setting_combinations.rs` turns on each security setting
in its `SETTINGS` list over the `public` profile, alone and with each other
setting of a different key, and sends every combination the
[golden transcript](#golden-transcripts) script, with the same events in
every run. A reply refuses its step when it carries a refusal (an `OK` that is
false, a `CLOSED`, `NEG-ERR` or `NOTICE`, or an HTTP status of 400 or more)
and no data (no `EVENT`, `COUNT` or `NEG-MSG`). The test fails when:

- a step that one setting refuses for a reason of its own, where `public`
  serves it or refuses it differently, is served with another setting on;
- a step that each of two settings refuses is served with both on;
- a setting changes none of the script's answers other than what NIP-11
  advertises, so a setting that is advertised but not enforced, or that does
  nothing, is noticed.

`OPENS` lists, step by step, where the first rule or the second is meant not
to hold, and why; `UNPROBED` lists the settings the script cannot see, and
why. A combination Wok refuses to load or start is printed and does not fail:
refusing it is the safe outcome. Add a setting to `SETTINGS` when it restricts
or opens an entry point.

`OPENS` records that `relay.abuse.enabled = false` turns
`relay.abuse.min_pow_difficulty` off with the other abuse limits, as
[config.md](config.md) says; that without AUTH, gift wraps and kind 30078
are refused only because they are recipient-only and owner-only, so emptying
those lists serves them; and that `observability.metrics_enabled` is what
serves `/metrics` on the metrics listener.

## Keeping this page current

| Test | Fails when |
| --- | --- |
| `wok-compat` `tests/attack_surface.rs` | A path the listener answers, in any profile, has no row in [Network listener](#network-listener), or a row's path is unreachable while its gate is open, or reachable while it is closed. The same holds for the [metrics listener](#metrics-listener) in profiles that set one. Candidate paths are the tables' own, every path literal in `wok-ws`, and a few decoys. |
| `wok-compat` `tests/attack_surface.rs` | A verb that `ClientCommand::parse` accepts has no row in [Messages](#messages), or a row names a verb it rejects. |
| `wok-compat` `tests/attack_surface.rs` | A message whose [Messages](#messages) row names a gate is served while some profile closes that gate, or refused by it while the profile opens it. Each is sent as a valid message over a WebSocket, and only the gate's own refusal counts. |
| `wok-compat` `tests/attack_surface.rs` | A profile file is added, removed or loses one of its properties, or is missing from [Profiles](#profiles). |
| `wok-ws` `nip86` tests | A NIP-86 method is missing from the [nip86.md](nip86.md#supported-methods) table, or its level there differs from the code's. |
| `wok-cli` tests | A `wok` command has no row in [Commands](#commands), or a row names a command that does not exist. |
| `wok-compat` `tests/golden_transcripts.rs` | A profile's relay answers the script differently from its file in `tests/transcripts/`, or a transcript has no profile. |
| `scripts/attack-surface-reach.py --check`, run by hand | A phase of the [reachability](#reachability) probe reaches a relay function that its profile's file in `tests/reachability/` does not list, a phase whose file lists functions reaches none, or a profile has no file. |
| `wok-compat` `tests/setting_combinations.rs` | With two settings on, a step that one refuses for a reason of its own, or that each refuses, is served, and `OPENS` does not list it; or a setting changes nothing but NIP-11 and is not in `UNPROBED`. |
