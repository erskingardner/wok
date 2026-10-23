# The `public` preset

```toml
preset = "public"   # optional: public is the default

[relay.auth]
service_url = "wss://relay.example.com"
```

## Who it is for

An open relay any client can read from and write to: feeds, outbox lookups,
threads and reactions, DMs and gift-wrap inboxes. It is the default, and its
values are Wok's built-in defaults, so its overlay,
[public.toml](public.toml), sets nothing. Its limits are set so that ordinary
client traffic is not refused (a startup burst of subscriptions, outbox
fetches of large follow lists, feeds, threads, a NIP-77 pass per group) while
every guard stays on. [config.md](../config.md) says what each one protects
and what breaks when it is set too low.

Set `relay.auth.service_url` to the relay's public URL. Without it NIP-42 is
not advertised, nobody can log in, and the private kinds below cannot be read
by anyone; the relay logs a warning at startup.

## What it changes from earlier releases

There is no preset to differ from, so this lists what the defaults chose
rather than inherited from strfry. Every value that changed since 0.7 is
under "Preset changes" in the CHANGELOG.

| Setting | Value | Was | Why |
|---|---|---|---|
| `events.reject_older_than_secs` | off | 3 years | Old profiles, lists and deletions can be rebroadcast. A bound set in the file never applies to replaceable, addressable, deletion or vanish events. |
| `events.max_num_tags` | 5,000 | 2,000 | Heavy users' follow and mute lists fit. |
| `relay.max_req_filter_size` | 256 KiB | 64 KiB | An outbox client can fetch a 2,000-account follow list in one request. |
| `relay.max_filter_bytes_per_connection` | 2 MiB | none | Caps the filters of all a connection's subscriptions, so the larger REQ cap does not multiply memory. |
| `relay.max_filter_limit` | 2,000 | 500 | Directory batches and metadata fetches without a `limit` are no longer cut at 500. NIP-11 `max_limit` and `default_limit`. |
| `relay.max_total_events_per_req` | 10,000 | 2,000 | Merged batches are no longer cut at 2,000 in all. |
| `relay.max_tags_per_filter` | 8 | 3 | Comment, community and marketplace queries with four or more tag letters. |
| `relay.abuse.max_query_work` | 20,000 | `max_query_cost = 1000` | Counts the index entries a request's plan touches, with its `limit`: outbox fetches, feeds and batched reactions are served, and a 2,000 × 50 fan-out is refused. |
| `relay.abuse.per_connection.*` | REQ 20/s, burst 100; NEG-MSG 50/s, 200; COUNT 5/s, 20; ×4 after AUTH | per address only | Each connection has its own budget, so a 60-REQ startup and a NIP-77 pass per group fit, and users behind one NAT no longer share one client's budget. |
| `relay.abuse.req_*`, `count_*` | REQ 200/s, burst 1,000; COUNT 20/s, 50 | 20/40, 5/10 | Now a backstop over all of an address's connections. |
| `relay.abuse.ipv6_prefix_len` | 64 | each address | An IPv6 client is keyed by its /64, so it cannot take a fresh budget with each address it picks. |
| `relay.abuse.max_stored_events` | off | 10,000,000 | No global cliff that fails every write; the disk reserve and map size bound storage. |
| `relay.abuse.max_stored_events_per_pubkey` | 1,000,000 | 100,000 | Active users and bots keep posting. |
| `relay.filter_validation.max_kinds_per_filter` | off | 3 | No filter rule applies until it is set. |
| `relay.auth.recipient_only_kinds` | `[4, 1059, 21059]` | `[4, 1059]` | Ephemeral gift wraps are private too. |
| `relay.auth.owner_only_kinds` | `[78, 30078]` | none | NIP-78 app data is served to, and accepted from, its author only. |

## What it deliberately refuses

- **Private kinds to anyone but their reader.** DMs (4) and gift wraps (1059,
  21059) go only to their author and first `p`-tag recipient, and NIP-78 app
  data (78, 30078) only to its author, each after NIP-42 AUTH.
- **Fan-outs.** A request whose estimated index work is over 20,000 is
  refused with `blocked:`, such as 2,000 authors × 50 kinds.
- **Floods.** Every connection, address and author has a token bucket, and
  a connection's filters, subscriptions and outbound queue are bounded.
- **Future-dated events** more than 15 minutes ahead, which would sit at the
  top of feeds.

It does not gate reads or writes: anyone can read and write
(`read_policy` and `write_policy` are `open`), and every kind is accepted.
For an allowlisted relay, set `write_policy = "members"` (and `read_policy`)
in the file; a `private` preset is planned.
