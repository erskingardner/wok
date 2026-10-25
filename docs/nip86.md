# NIP-86 Relay Management API

Wok implements the NIP-86 draft at nips
[`62d5fed`](https://github.com/nostr-protocol/nips/blob/62d5fed/86.md), which
is unchanged at the conformance pin: JSON-RPC-like management requests over
HTTP POST to the relay URI with `Content-Type: application/nostr+json+rpc`,
authorized by a NIP-98 event (kind 27235, empty content) whose `payload` tag
is required and whose `u` tag names the relay URL. The endpoint shares the
operator surface with the [admin dashboard](admin-dashboard.md): it is served
only when `admin.enabled` is set, and the signed `u` tag is compared against
`admin.public_url` after normalizing the scheme (`http(s)` and `ws(s)` forms
are accepted) and any trailing slash.

Request and response bodies follow the spec:

```json
{ "method": "banpubkey", "params": ["<pubkey-hex>", "<optional reason>"] }
```

```json
{ "result": true }
{ "error": "method \"changerelayname\" requires the admin role" }
```

Method-level failures return HTTP 200 with an `error` field. Authentication
failures return 401. Every reply carries the NIP-11 CORS headers, and
`OPTIONS /` answers the preflight with 204, so browser management tools can
call the API from another origin. Signed authorization events are single-use:
each ID is kept for 300 seconds, the longest `admin.auth_window_secs` allows,
whatever the current window. Clients must include a unique tag (for example a
random `nonce`) so same-second calls do not collide in the replay cache. An
event is claimed as soon as it is accepted, so a concurrent request reusing it
is refused. A request rejected before it submits a command to the relay writer
(bad parameters, a signer without a management role) releases the claim for a
retry with the same event. Once a command is submitted the event stays used,
even if the client disconnects or the call reports an error, because a queued
command still runs. A full writer queue also keeps the claim, so sign a new
event to retry.

## Supported methods

`supportedmethods` returns the methods the caller may call at its
[management level](#management-levels). Unknown methods return an
`unsupported method` error. Level is the lowest level that may call a
method; admins may call every method.

| Group | Methods | Level |
| --- | --- | --- |
| Discovery | `supportedmethods` | Moderator |
| Pubkey bans | `banpubkey`, `unbanpubkey`, `listbannedpubkeys` | Moderator |
| Write allowlist | `allowpubkey`, `unallowpubkey`, `listallowedpubkeys` | Moderator |
| Event bans | `banevent`, `unbanevent`, `listbannedevents` | Moderator |
| Event allow list | `allowevent`, `unallowevent`, `listallowedevents` | Moderator |
| Moderation queue | `listeventsneedingmoderation` | Moderator |
| IP blocks | `blockip`, `unblockip`, `listblockedips` | Moderator |
| Relay info | `changerelayname`, `changerelaydescription`, `changerelayicon` | Admin |
| Kind policy | `allowkind`, `disallowkind`, `listallowedkinds`, `listdisallowedkinds` | Admin |
| Roles | `createrole`, `editrole`, `deleterole`, `assignrole`, `unassignrole` | Admin |

The NIP-43 invite-code methods (`listclaims`, `createclaim`, `deleteclaim`)
are not implemented, because Wok does not implement NIP-43.

## Management levels

Every call is made by a NIP-98 signer at one of two levels:

- **Admin** — `admin.pubkeys` from the config, or any pubkey holding the
  built-in `admin` role. Admins may call every method.
- **Moderator** — pubkeys holding the built-in `moderator` role. Moderators
  may call the ban, allow-list, queue, and IP-block methods plus
  `supportedmethods`, which lists only those. Relay-info, kind-policy, and
  role methods return a `requires the admin role` error.

`assignrole` / `unassignrole` manage these grants without restarting the
relay or editing the config file. A role is independent of
`admin.pubkeys`: removing a key from the file leaves any role it holds, and
the reload that removes it warns when that role is `admin` or `moderator`.

## Ban and allowlist semantics

Bans are **suppressive, not destructive**. A banned pubkey or event id is
rejected on future writes (`OK false "restricted: ..."`) and hidden from
historical REQ results, live delivery (including monitor catch-up and
queued DB changes), and COUNT, but the stored records remain in the
database, so `unbanpubkey` / `unbanevent` restore them exactly. Negentropy
sync between relays is unaffected by bans, so operators can still mirror a
banned corpus between their own relays.

A pubkey or event is on at most one of its ban list and allow list:
`banpubkey` / `banevent` remove it from the allow list, and `allowpubkey` /
`allowevent` lift its ban. `unbanpubkey` / `unbanevent` and
`unallowpubkey` / `unallowevent` remove it from one list without adding it
to the other. Earlier releases could leave a pubkey on both lists; the ban
wins until the next `banpubkey` or `allowpubkey` for it, and `unbanpubkey`
alone leaves it allowlisted.

`allowpubkey` makes a pubkey a member, as holding any role (built-in or
custom) and being in `admin.pubkeys` do. Membership matters only under
`relay.auth.read_policy = "members"` or `write_policy = "members"`; with the
default `open` policies the allowlist is recorded but gates nothing. See
[read and write policies](config.md#read-and-write-policies).

NIP-62 vanish requests (kind 62) are exempt from pubkey bans and the write
policy: NIP-62 requires relays that restrict who can post to honor them
regardless of the user's status. A banned author's vanish request is stored
and erases their events, but stays hidden from reads while the ban stands.
Event-id bans and the kind policy still apply to vanish requests.

The event allow list records an operator's approval. `allowevent` lifts any
ban on the event and takes it out of the moderation queue. An allowed event
is still hidden while its author is banned or its kind disallowed, and a
later report queues it again.

Blocked IPs are refused at connection admission for both WebSocket upgrades
and plain HTTP — **including the management endpoint itself**. Blocking the
operator's own address locks out remote management until the block is lifted
out of band (restart after editing the database with `wok` tooling, or an
in-process `RelayHandle::manage` call).

## Moderation queue

Stored NIP-56 reports (kind 1984) feed `listeventsneedingmoderation`: each
`e` tag target (up to 64 per report) is recorded with a reason derived from
the reporting pubkey and content. Queue entries are recorded in the same
LMDB transaction as the report itself. `banevent` and `allowevent` both
remove the target from the queue; `unbanevent` and `unallowevent` leave it
alone.

## Roles

Role records (`createrole` / `editrole` with `id`, `label`, `description`,
`color`, `order`) are stored metadata plus two wok-defined effects:

- The built-in ids `admin`, `moderator`, and `member` are reserved and always
  exist. `admin` and `moderator` grant the management levels above;
  `member` makes its holder a member under the `members` policies.
- Custom roles make their holders members too; under the `open` policies
  they are display metadata for management UIs.

`deleterole` strips the role from every assigned pubkey. Role assignments
are capped (1,000 roles, 64 roles per pubkey) like every other moderation
list (100,000 records per type, 512-byte reasons).

## Config-backed methods

`changerelayname`, `changerelaydescription`, and `changerelayicon` edit the
live configuration through the same validated, atomic, in-place `wok.toml`
edit as the admin dashboard, so they require `admin.allow_config_writes` and
a relay started from a writable config file; otherwise they return the
dashboard's error.

## Kind policy

`allowkind` / `disallowkind` maintain a dedicated kind policy in the
moderation table (a 65536-bit map), not the query-filter validation config.
Every kind is allowed until `disallowkind` disallows it, and `allowkind`
allows it again. `listdisallowedkinds` lists the disallowed kinds. While
`relay.auth.accepted_kinds` is empty, `listallowedkinds` lists the kinds
named by `allowkind` since their last `disallowkind`, not every allowed kind,
and with no policy both lists are empty. `allowkind` therefore never
restricts other kinds. A disallowed kind is:

- rejected on write admission (`OK false "restricted: kind N is not allowed
  by this relay"`), and
- hidden from query results like a ban — including REQs without a `kinds`
  field — until `allowkind` restores it.

With `relay.auth.accepted_kinds` set, the policy works under that ceiling.
The relay accepts a kind only if the configuration lists it (vanish requests
aside) and the policy allows it, so `allowkind` of an unlisted kind lifts
its ban on stored events but does not make the relay accept new ones.
`listallowedkinds` returns the effective set, the kinds the relay accepts,
sorted, and `listdisallowedkinds` every kind the policy disallows. See
[accepted kinds](config.md#accepted-kinds).

The all-zero map (no kinds allowed) is representable; `disallowkind` never
refuses an exclusion. IPs given to `blockip` / `unblockip` are parsed and
stored in canonical form, so any equivalent spelling (`2001:0db8::1` vs
`2001:db8::1`) refers to the same record.

## Persistence

Moderation records live in a dedicated Wok-owned LMDB table
(`wok_Moderation`, prefix-keyed by record type) next to the NIP-62 markers.
They survive restarts, are loaded into memory at startup, and are refreshed
after every management mutation and every stored report.
