# Observability

Wok can serve Prometheus text metrics at `/metrics`, writes structured tracing
records, and keeps an optional bounded in-memory history for the authenticated
operator dashboard. Prometheus counters reset at process restart; dashboard
history is also process-local and is never exposed by a public API.

## Prometheus scraping

Metrics are off by default. Turn them on, preferably on a listener of their
own at a private address:

```toml
[observability]
metrics_enabled = true
metrics_listen = "127.0.0.1:9777"
```

That listener serves only `GET /metrics`, and the relay listener answers
`/metrics` with 404. Without `metrics_listen`, `/metrics` is served on the
relay listener to anyone who can reach it, with
`Access-Control-Allow-Origin: *`, so any web page can read it cross-origin;
see [config.md](config.md#observability).

```bash
curl http://127.0.0.1:9777/metrics
```

A minimal Prometheus job is:

```yaml
scrape_configs:
  - job_name: wok
    static_configs:
      - targets: ["127.0.0.1:9777"]
```

## Metric reference

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `wok_active_connections` | gauge | none | Current WebSocket and Unix-socket connections. |
| `wok_authenticated_connections` | gauge | none | Current connections that completed NIP-42 AUTH. |
| `wok_written_events_total` | counter | none | Events committed to durable storage. |
| `wok_ephemeral_events_total` | counter | none | Accepted ephemeral events handled by the live/TTL path. |
| `wok_dup_events_total` | counter | none | Publications already present in the database. |
| `wok_live_buffer_overflows_total` | counter | none | Subscriptions whose stored matches outgrew `relay.max_live_buffer_bytes` while their history was sent; those are re-read from the database after EOSE instead. |
| `wok_live_buffer_dropped_ephemeral_total` | counter | none | Ephemeral events dropped, oldest first, from a full live buffer. They cannot be re-read; a steady rate means the bound is too small for the traffic. |
| `wok_rejected_events_total` | counter | none | Event publications rejected by validation or policy. |
| `wok_auth_challenges_sent_total` | counter | none | NIP-42 AUTH challenges issued. |
| `wok_auth_success_total` | counter | none | Successful NIP-42 authentications. |
| `wok_auth_failure_total` | counter | none | Failed NIP-42 authentication attempts. |
| `wok_slow_client_terminations_total` | counter | none | Connections closed after exceeding their pending-output byte budget. |
| `wok_real_ip_header_unparsed_total` | counter | none | Requests whose `relay.real_ip_header` named no IP address where the client's should be: its last entry or, with `relay.trusted_proxies`, the last one outside them (in `Forwarded`, an element without one `for` naming an address). The connecting address stood in for the client's. Any increase means a proxy does not append the address it was reached from. |
| `wok_refusals_total` | counter | `setting` | Requests and events refused, by the config key that refused them. See [Refusals by setting](#refusals-by-setting). |
| `wok_abuse_rejections_total` | counter | `reason` | Deprecated: removed in the release after 0.8. Requests or events rejected by an abuse guard. |
| `wok_moderation_rejections_total` | counter | `reason` | Events refused by a NIP-86 ban (`banned_event`, `banned_author`), by the write policy (`restricted_writes`), or by `relay.auth.accepted_kinds` or the NIP-86 kind policy (`kind_not_allowed`). |
| `wok_client_messages_total` | counter | `type` | Inbound Nostr protocol messages by type. |
| `wok_relay_messages_total` | counter | `type` | Outbound Nostr protocol messages by type. |
| `wok_tag_kind_index_complete` | gauge | none | 1 once every stored event is in the `(tag, kind, created_at)` index, 0 while the writer still builds it. |
| `wok_tag_kind_index_indexed_through` | gauge | none | The index's progress marker: every event at or below this local ID has its entries. |
| `wok_tag_kind_index_high_water` | gauge | none | The greatest local ID allocated; the index is complete once the marker reaches it. |
| `wok_tag_kind_index_pass_visited` | gauge | none | Tag-index entries a key-ordered build has visited, 0 when none runs. |
| `wok_tag_kind_index_tag_entries` | gauge | none | Tag-index entries stored, which a key-ordered build visits once. |
| `wok_tag_kind_backfill_entries_total` | counter | none | Postings the writer's background build put. |
| `wok_tag_kind_backfill_seconds_total` | counter | none | Time the writer spent in background build transactions, commits included. |

The `wok_tag_kind_*` gauges are updated after each build step and on the
writer's maintenance tick (every 2 seconds). While a key-ordered build runs,
`pass_visited / tag_entries` is its progress; after it, while events an
earlier release inserted are indexed, `indexed_through / high_water` is.

### Refusals by setting

`wok_refusals_total{setting="<config key>"}` counts each refused request or
event once, under the key to change if the refusal should not have
happened. Every label is listed from startup, at 0 until it refuses
something. A token bucket's refusals carry its `_burst` key; raising its
`_rate_per_second` helps too.

| `setting` | Counts |
|---|---|
| `relay.abuse.connection_burst` | Connections and HTTP requests over an address's connection budget. |
| `relay.abuse.max_connections_per_address` | WebSocket upgrades from an address that already holds that many connections open. |
| `relay.abuse.event_burst` | EVENTs and AUTHs over an address's budget. |
| `relay.abuse.pubkey_event_burst` | EVENTs over their author's budget, or over the AUTHed identity's for events from other keys. |
| `events.max_event_size`, `events.max_num_tags`, `events.max_tag_val_size` | Events, and AUTH events, over the size, tag count or tag value limit. |
| `events.reject_older_than_secs`, `events.reject_newer_than_secs`, `events.reject_ephemeral_older_than_secs` | Events outside the `created_at` window. AUTH's ±600 s window and a 21059's 3-day allowance are NIP constants and are not counted. |
| `relay.abuse.min_pow_difficulty` | Events short of the NIP-13 difficulty. |
| `relay.auth.enabled`, `relay.auth.service_url` | AUTH messages while NIP-42 is off, or before the relay URL they must name is set. |
| `relay.auth.accepted_kinds` | Events of a kind outside it. The NIP-86 kind policy is counted only by `wok_moderation_rejections_total`. |
| `relay.auth.write_policy` | Events the write policy does not admit. |
| `relay.auth.owner_only_kinds` | Events of an owner-only kind not sent as their author (a NIP-70 protected one is NIP-70's), and reads of one not scoped to the reader. |
| `relay.nip62.enabled` | Vanish requests while NIP-62 is off. |
| `relay.write_policy_plugin` | Events the plugin rejected or shadow-rejected. |
| `relay.abuse.max_stored_events`, `relay.abuse.max_stored_events_per_pubkey`, `database.min_free_disk_bytes` | Events not written because of a storage quota or the disk reserve. |
| `relay.abuse.per_connection.req_burst`, `neg_msg_burst`, `count_burst` | REQs and NEG-OPENs, NEG-MSGs, and COUNTs over a connection's own budget. |
| `relay.abuse.req_burst`, `relay.abuse.count_burst` | The same over the address's backstop (REQ, NEG-OPEN and NEG-MSG; COUNT). |
| `relay.abuse.invalid_burst` | Malformed messages past the address's budget. The first gets one `rate-limited:` NOTICE, the rest no reply. |
| `relay.max_filters_per_req`, `relay.max_req_filter_size` | REQs and COUNTs with too many filters or filter bytes. |
| `relay.max_tags_per_filter`, `relay.max_and_entries` | Filters over the tag-letter or NIP-91 `&` limit (REQ, COUNT, NEG-OPEN). |
| `relay.max_filter_limit_count` | COUNTs while it is 0. |
| `relay.filter_validation.max_kinds_per_filter`, `allowed_kinds`, `require_author_or_tag`, `require_scoped_filters` | Filters a rule refuses (REQ, COUNT, NEG-OPEN). |
| `relay.abuse.max_query_work` | Requests whose estimated work is over the ceiling. |
| `relay.auth.read_policy` | REQs, COUNTs and NEG-OPENs from a connection the read policy does not admit, when they arrive or, for one still waiting for a scan or sync after a reload or a member's removal, when it would start. |
| `relay.auth.recipient_only_kinds`, `relay.auth.authenticated_kinds` | Reads of those kinds not scoped to the reader. A REQ or NEG-OPEN is counted under the strictest class its filters can match, a COUNT under the strictest class of the filters its reader may not count. |
| `relay.max_subs_per_connection` | New subscriptions or sync sessions over the cap, and queries refused because the connection's queue of waiting scans is full. |
| `relay.max_filter_bytes_per_connection` | Subscriptions and COUNTs over the connection's filter bytes. |
| `relay.abuse.max_concurrent_historical_queries` | Queries while it is 0. |
| `relay.negentropy_enabled` | NEG-OPENs and NEG-MSGs while NIP-77 is off. |
| `relay.max_sync_events`, `relay.sync_memory_per_connection`, `relay.sync_memory_total` | Sync sessions over the size or memory budget. |

Refusals that no setting makes are not counted here: malformed messages
(beyond the invalid budget), bad signatures, NIP-70 protected events,
NIP-86 bans and blocked addresses, duplicate events, and relay errors.
Truncation by `relay.max_filter_limit` or `relay.max_total_events_per_req`
is not a refusal.

### Deprecated: `wok_abuse_rejections_total`

`wok_abuse_rejections_total{reason}` still counts as before for this
release and will be removed in the next. Each `reason` is the sum of these
`wok_refusals_total` settings:

| `reason` | Trigger | `setting` |
|---|---|---|
| `connection_rate` | Network-address connection bucket exhausted, or a NIP-86 blocked address. | `relay.abuse.connection_burst` (blocked addresses are not counted) |
| `event_rate` | Per-address EVENT/AUTH or per-author EVENT budget exhausted. | `relay.abuse.event_burst`, `relay.abuse.pubkey_event_burst` |
| `req_rate` | A connection's REQ or NEG-MSG budget, or its address's REQ backstop, exhausted (REQ, NEG-OPEN, NEG-MSG). | `relay.abuse.per_connection.req_burst`, `relay.abuse.per_connection.neg_msg_burst`, `relay.abuse.req_burst` |
| `count_rate` | A connection's COUNT budget, or its address's COUNT backstop, exhausted. | `relay.abuse.per_connection.count_burst`, `relay.abuse.count_burst` |
| `invalid_rate` | Malformed-message budget exhausted. | `relay.abuse.invalid_burst` |
| `pow` | Event did not meet the configured NIP-13 difficulty. | `relay.abuse.min_pow_difficulty` |
| `query_cost` | Estimated historical-query cost exceeded its ceiling. | `relay.abuse.max_query_work` |
| `query_concurrency` | A connection's queue of historical queries waiting for its concurrency cap was full, or the cap is zero. | `relay.max_subs_per_connection` (also counts other refusals), `relay.abuse.max_concurrent_historical_queries` |
| `pubkey_storage_quota` | Author storage quota reached. | `relay.abuse.max_stored_events_per_pubkey` |
| `global_storage_quota` | Global durable event quota would be exceeded. | `relay.abuse.max_stored_events` |
| `disk_reserve` | Durable writes stopped to preserve configured free disk space. | `database.min_free_disk_bytes` |

`wok_client_messages_total{type=...}` uses `EVENT`, `REQ`, `COUNT`,
`CLOSE`, and `AUTH`. `wok_relay_messages_total{type=...}` uses `EVENT`,
`EOSE`, `OK`, `NOTICE`, and `CLOSED`.

Useful PromQL examples:

```promql
# Current unauthenticated connections
wok_active_connections - wok_authenticated_connections

# Accepted durable publications per second over five minutes
rate(wok_written_events_total[5m])

# Event rejection ratio over five minutes
rate(wok_rejected_events_total[5m])
/
clamp_min(
  rate(wok_written_events_total[5m])
  + rate(wok_ephemeral_events_total[5m])
  + rate(wok_rejected_events_total[5m]),
  1
)

# Refusals over the last hour, by the setting that refused them
sort_desc(increase(wok_refusals_total[1h]) > 0)

# Slow-client disconnects over the last hour
increase(wok_slow_client_terminations_total[1h])
```

## Structured logs

Set JSON output for Loki, Vector, Fluent Bit, Grafana Alloy, or another
collector:

```toml
[observability]
log_format = "json"
log_filter = "wok=info"
```

Wok writes one JSON object per line to stdout/stderr. Run it under a service
manager and ship that stream. Structured records include connection IDs,
transport and peer data, event IDs/pubkeys/kinds, query IDs and result counts,
and maintenance deletion counts. Event content is not included.

`log_filter` uses tracing-subscriber filter syntax. `RUST_LOG` takes
precedence at startup, which is useful for temporary diagnostics:

```bash
RUST_LOG=wok=debug,wok_db=trace wok --config wok.toml relay
```

Log format and filter require restart because the tracing subscriber is
process-global.

The background build of the `(tag, kind, created_at)` index logs at `info`
when it starts (`building the (tag, kind, created_at) index in the
background, in key order`, or `indexing stored events missing from ...` for
events an earlier release inserted), its progress every 10 seconds (`visited`
and `tag_entries`, or `indexed_through` and `high_water`), and its end (`the
(tag, kind, created_at) index is complete`, with `entries`, `seconds` and
`slowest_step_ms`). Each step logs at `debug` on the
`wok_relay::server::writer` target with its `entries`, `prepared` and `ms`.
A step that fails logs at `error`; the writer retries on its next
maintenance tick. While free disk space is below
`database.min_free_disk_bytes`, the build pauses with one `warn` (`pausing
the (tag, kind, created_at) index build`) and logs `resuming ...` once a
maintenance tick finds the space.

## Bounded dashboard history

The authenticated `/admin/api/overview` response includes:

- `history.current`: a fresh aggregate snapshot;
- `history.points`: the retained FIFO snapshots in timestamp order.

Each snapshot contains Unix `timestamp`, `active_connections`,
`authenticated_connections`, `written_events_total`,
`ephemeral_events_total`, `rejected_events_total`,
`client_messages_total`, `relay_messages_total`, and
`abuse_rejections_total`.

```toml
[observability]
history_enabled = true
history_interval_secs = 15
history_max_points = 5760
```

The defaults retain 24 hours at 15-second resolution. New samples evict the
oldest. Disabling history or setting zero points clears it; restart also clears
it. Configuration rejects intervals below one second and more than 100,000
points, so this convenience history cannot grow without bound. Prometheus
scraping is independent of this setting.
