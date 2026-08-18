# NIP-86 Relay Management API

Wok implements the pinned NIP-86 draft: JSON-RPC-like management requests over
HTTP POST to the relay URI with `Content-Type: application/nostr+json+rpc`,
authorized by a NIP-98 event (kind 27235, empty content) whose `payload` tag
is required and whose `u` tag names the relay URL. The endpoint shares the
operator surface with the [admin dashboard](admin-dashboard.md): it is served
only when `admin.enabled` is set, and the signed `u` tag is compared against
`admin.public_url` after normalizing the scheme (`http(s)` and `ws(s)` forms
are accepted) and any trailing slash.

Request and response bodies follow the pinned spec:

```json
{ "method": "banpubkey", "params": ["<pubkey-hex>", "<optional reason>"] }
```

```json
{ "result": true }
{ "error": "method \"changerelayname\" requires the admin role" }
```

Method-level failures return HTTP 200 with an `error` field. Authentication
failures return 401. Signed authorization events are single-use within
`admin.auth_window_secs`; clients must include a unique tag (for example a
random `nonce`) so same-second calls do not collide in the replay cache.

## Supported methods

`supportedmethods` returns the implemented list. Unknown methods return an
`unsupported method` error.

| Group | Methods |
| --- | --- |
| Pubkey bans | `banpubkey`, `unbanpubkey`, `listbannedpubkeys` |
| Write allowlist | `allowpubkey`, `unallowpubkey`, `listallowedpubkeys` |
| Event bans | `banevent`, `allowevent`, `listbannedevents` |
| Moderation queue | `listeventsneedingmoderation` |
| IP blocks | `blockip`, `unblockip`, `listblockedips` |
| Relay info | `changerelayname`, `changerelaydescription`, `changerelayicon` |
| Kind policy | `allowkind`, `disallowkind`, `listallowedkinds` |
| Roles | `createrole`, `editrole`, `deleterole`, `assignrole`, `unassignrole` |

## Management levels

Every call is made by a NIP-98 signer at one of two levels:

- **Admin** — `admin.pubkeys` from the config, or any pubkey holding the
  built-in `admin` role. Admins may call every method.
- **Moderator** — pubkeys holding the built-in `moderator` role. Moderators
  may call the ban, allowlist, queue, and IP-block methods plus
  `supportedmethods`; relay-info, kind-policy, and role methods return a
  `requires the admin role` error.

`assignrole` / `unassignrole` manage these grants without restarting the
relay or editing the config file.

## Ban and allowlist semantics

Bans are **suppressive, not destructive**. A banned pubkey or event id is
rejected on future writes (`OK false "restricted: ..."`) and hidden from
historical REQ results, live delivery, and COUNT, but the stored records
remain in the database, so `unbanpubkey` / `allowevent` restore them
exactly. Negentropy sync between relays is unaffected by bans, so operators
can still mirror a banned corpus between their own relays.

`allowpubkey` only has an effect when `relay.auth.restrict_writes = true`:
then writes are accepted only from allowlisted pubkeys, pubkeys holding any
role (built-in or custom), and operator admin pubkeys. With
`restrict_writes = false` (the default) the allowlist is recorded but does
not gate writes.

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
remove the target from the queue.

## Roles

Role records (`createrole` / `editrole` with `id`, `label`, `description`,
`color`, `order`) are stored metadata plus two wok-defined effects:

- The built-in ids `admin`, `moderator`, and `member` are reserved and always
  exist. `admin` and `moderator` grant the management levels above;
  `member` grants write access when `restrict_writes` is on.
- Custom roles grant the same write access as `member` when
  `restrict_writes` is on; otherwise they are display metadata for
  management UIs.

`deleterole` strips the role from every assigned pubkey. Role assignments
are capped (1,000 roles, 64 roles per pubkey) like every other moderation
list (100,000 records per type, 512-byte reasons).

## Config-backed methods

`changerelayname`, `changerelaydescription`, `changerelayicon`, and the
kind-policy methods edit the live configuration through the same validated,
atomic `wok.toml` rewrite as the admin dashboard, so they require
`admin.allow_config_writes` and a relay started from a writable config file;
otherwise they return the dashboard's error. `allowkind` / `disallowkind`
maintain `relay.filter_validation.allowed_kinds` and enable filter
validation so the list is enforced; `listallowedkinds` reports the full
0–65535 range when no list is configured. `disallowkind` refuses to empty
the list, since an empty list means "all kinds allowed".

## Persistence

Moderation records live in a dedicated Wok-owned LMDB table
(`wok_Moderation`, prefix-keyed by record type) next to the NIP-62 markers.
They survive restarts, are loaded into memory at startup, and are refreshed
after every management mutation and every stored report.
