# The `marmot` preset

```toml
preset = "marmot"

[relay.auth]
service_url = "wss://relay.example.com"
```

## Who it is for

A relay dedicated to [Marmot](https://github.com/marmot-protocol/marmot)
group messaging (MLS over Nostr), such as one a Marmot app ships as a
default. It carries:

- group messages (kind 445), signed by a fresh key per message;
- Welcomes, in NIP-59 gift wraps (kind 1059);
- KeyPackages (kind 30443);
- the profile and relay-list kinds clients look up (0, 3, 10000, 10002,
  10050), deletions that retire KeyPackages (5), and vanish requests (62).

Users read and write everything else on other relays. For a relay that
serves feeds, outbox lookups and DMs as well, use [`public`](public.md).

The facts behind each value come from the Marmot spec (`a717f22`) and MDK,
its reference implementation (`2ff9c142`). The spec states almost no relay
requirements, so several values follow MDK's behaviour. The overlay itself,
with a reason beside each value, is [marmot.toml](marmot.toml).

## What it changes from `public`

| Setting | `public` | `marmot` | Why |
|---|---|---|---|
| `relay.auth.accepted_kinds` | every kind | `[0, 3, 5, 62, 445, 1059, 10000, 10002, 10050, 30443]` | The kinds Marmot clients publish. Others are refused with `restricted:`, and NIP-11 advertises `restricted_writes`. |
| `relay.filter_validation.require_scoped_filters` | off | on | Each filter must name `ids`, `authors` or a tag. |
| `events.max_event_size` | 1 MiB | 4 MiB | Welcomes carry the group's ratchet tree and Add commits each new member's KeyPackage, so both grow with the group. MDK accepts events up to 5 MiB. Provisional until Welcome sizes are measured at 100, 500 and 1,000 members. |
| `relay.max_websocket_payload_size`, `relay.unix.max_frame_bytes` | 2 MiB | 8 MiB | Room for those events on either transport. |
| `relay.max_filter_limit` | 2,000 | 5,000 | Directory batches with KeyPackage slots. |
| `relay.max_filter_limit_count` | 1,000,000 | 0 | COUNT (NIP-45) off: MDK never sends it. A COUNT is priced at its index seeks, not its rows, so one filter may read up to a million rows. A COUNT is refused with `CLOSED` `blocked: bad req: COUNT disabled`, and NIP-11 no longer lists NIP-45. |
| `relay.compression_enabled` | on | off | permessage-deflate off: MDK's WebSocket client never offers it, and MLS and NIP-44 ciphertext compresses poorly. A client that offers it gets an uncompressed connection. |
| `relay.max_sync_events` | 1,000,000 | 65,536 | Four times the 16,384 events MDK compares in one NIP-77 session: each names one group or inbox with `limit` 16,385. A session without a `limit` reserves 20 MiB of sync memory, not 248 MiB, and scans at most 65,537 events before it is refused. |
| `relay.sync_memory_per_connection` | 256 MiB | 128 MiB | A session reserves 4 MiB plus 256 bytes per event of its `limit`, about 8 MiB for MDK's, so a connection holds 15 of them. MDK runs at most eight at once on a relay connection. `relay.sync_memory_total` keeps its 1 GiB, the room for every client's syncs at once. |
| `relay.abuse.event_burst` | 100 | 300 | One inviter's commit plus up to about 250 Welcomes from one address. |
| `relay.abuse.per_connection.req_rate_per_second`, `relay.abuse.per_connection.req_burst` | 20, 100 | 50, 300 | About two REQs or NEG-OPENs per group at startup, plus `ids` fetches. |
| `relay.abuse.per_connection.neg_msg_burst` | 200 | 500 | A NIP-77 pass per group and per inbox. |

It also refuses to run without NIP-42, or with gift wraps that anyone but
their recipient can read: the relay will not start, or reload into a
`marmot` configuration, unless `relay.auth.service_url` is set,
`relay.auth.enabled` is on, and kinds 1059 and 21059 are in
`relay.auth.recipient_only_kinds`. The stricter `owner_only_kinds` passes
the check too, but only a gift wrap's author can then read it, so recipients
never receive their Welcomes. A dashboard or NIP-86 save that would do so is
refused with nothing written, and `wok doctor` fails its `preset` check.
Recipients read their gift wraps only after logging in.

Everything else keeps its `public` value: the read classes, open read and
write policies, no lower bound on `created_at`, the 900 s future tolerance,
no proof of work, NIP-77 on, and the per-address backstops.

A setting in the file still wins over the preset. A copy of the 0.7
`docs/wok.toml`, which lists every 0.7 default, keeps eight `public` values
after it adds `preset = "marmot"`: `events.max_event_size` at 1 MiB,
`relay.max_websocket_payload_size` and `relay.unix.max_frame_bytes` at
2 MiB, COUNT (`relay.max_filter_limit_count`) and permessage-deflate
(`relay.compression_enabled`) on, `relay.abuse.event_burst` at 100, and
`relay.max_sync_events` and `relay.sync_memory_per_connection` at 1,000,000
events and 256 MiB.
`wok doctor` names those in its `config-public-values` check. The same
file's `relay.max_filter_limit = 500` is the 0.7 default, so the relay stays
at 500 and the `config-defaults` check names it instead. The sample sets no
accepted kinds, scoped filters or per-connection budgets, so those take
`marmot`'s values.

To drop the eight, delete their lines, or run `wok config minimize` while the
file still selects `public`: it removes every setting that repeats
`public`'s value. It keeps `max_filter_limit = 500`, which differs from
`public`'s 2,000; delete that line too unless you chose 500.

## What it deliberately refuses

- **Kinds outside the Marmot set.** Notes, reactions, DMs and every other
  kind are refused, so the relay stays a narrow Marmot relay rather than a
  general one with Marmot tuning.
- **Enumeration.** `{"kinds":[445]}` or `{"since":…}` would list every
  group's messages; with scoped filters each filter must name a group
  (`#h`), a recipient (`#p`), `ids` or `authors`. NEG-OPEN meets the same
  rule, and COUNT is off. MDK's group, inbox, `ids` and directory filters all
  pass.
- **Gift wraps to anyone but their recipient.** A 1059 is served only to the
  connection authenticated as its first `p` tag (or its author), as in
  `public`. A file that takes 1059 or 21059 out of `recipient_only_kinds`,
  or moves it to `authenticated_kinds`, is refused, as above, rather than
  serving Welcomes and their `p` tags to anyone.
- **Write gating.** Writes stay open on purpose. Marmot signs each 445 with a
  fresh key, so the relay cannot tell which account sent a message, and MDK
  publishes 445s anonymously, authenticating only after an `auth-required:`
  refusal. Requiring AUTH to write would give the relay the one thing the
  throwaway keys withhold: which account posts to which group. Abuse control
  relies on the per-connection and per-address budgets instead. On an
  anonymous connection, a new key for each event starts a new per-author
  budget and storage count each time. On a connection logged in as an
  account, events from other keys are charged to that account's per-author
  EVENT budget (`relay.abuse.pubkey_event_burst`, 50 with no AUTH
  multiplier), so a logged-in inviter's burst of Welcomes can hit it before
  the per-address `event_burst` of 300. A key used again is held to the
  per-author storage quota.
- **Proof of work.** It stays 0: MDK never mines, and treats `pow:` as final.

## Not covered yet

- **Retention for 445.** The spec expects relays to delete expired events.
  Application 445s carry NIP-40 `expiration` when the group enables
  retention, and Wok drops those once they expire; there is no per-kind
  retention window for the rest.
- **Per-group and per-recipient quotas.** A quota per `#h` group or per
  gift-wrap recipient does not exist yet, and the per-author storage quota
  counts each event's own key, so a new key per event escapes it. Until
  then the preset relies on the per-address EVENT budget,
  `database.min_free_disk_bytes` and `database.map_size`.
