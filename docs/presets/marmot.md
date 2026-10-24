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
| `relay.abuse.event_burst` | 100 | 300 | One inviter's commit plus up to about 250 Welcomes from one address. |
| `relay.abuse.per_connection.req_rate_per_second`, `relay.abuse.per_connection.req_burst` | 20, 100 | 50, 300 | About two REQs or NEG-OPENs per group at startup, plus `ids` fetches. |
| `relay.abuse.per_connection.neg_msg_burst` | 200 | 500 | A NIP-77 pass per group and per inbox. |

It also refuses to run without NIP-42: the relay will not start, or reload
into a `marmot` configuration, unless `relay.auth.service_url` is set and
`relay.auth.enabled` is on. A dashboard or NIP-86 save that would do so is
refused with nothing written, and `wok doctor` fails its `preset` check.
Recipients read their gift wraps only after logging in.

Everything else keeps its `public` value: the read classes, open read and
write policies, no lower bound on `created_at`, the 900 s future tolerance,
no proof of work, NIP-77 on, and the per-address backstops.

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
  `public`.
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
