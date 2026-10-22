# Observability

Wok exposes Prometheus text metrics at `/metrics`, writes structured tracing
records, and keeps an optional bounded in-memory history for the authenticated
operator dashboard. Prometheus counters reset at process restart; dashboard
history is also process-local and is never exposed by a public API.

## Prometheus scraping

The endpoint needs no special `Accept` header:

```bash
curl http://127.0.0.1:7777/metrics
```

A minimal Prometheus job is:

```yaml
scrape_configs:
  - job_name: wok
    static_configs:
      - targets: ["127.0.0.1:7777"]
```

If the relay is internet-facing, expose `/metrics` only on a trusted network
or protect it at the reverse proxy. The endpoint is unauthenticated and sends
`Access-Control-Allow-Origin: *`, so any web page can read it cross-origin.

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
| `wok_abuse_rejections_total` | counter | `reason` | Requests or events rejected by an abuse guard. |
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

`wok_abuse_rejections_total` has these `reason` values:

| Value | Trigger |
|---|---|
| `connection_rate` | Network-address connection bucket exhausted. |
| `event_rate` | Per-address EVENT/AUTH or per-author EVENT budget exhausted. |
| `req_rate` | REQ budget exhausted. |
| `count_rate` | COUNT budget exhausted. |
| `invalid_rate` | Malformed-message budget exhausted. |
| `pow` | Event did not meet the configured NIP-13 difficulty. |
| `query_cost` | Estimated historical-query cost exceeded its ceiling. |
| `query_concurrency` | Historical-query concurrency ceiling reached. |
| `pubkey_storage_quota` | Author storage quota reached. |
| `global_storage_quota` | Global durable event quota would be exceeded. |
| `disk_reserve` | Durable writes stopped to preserve configured free disk space. |

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

# Abuse rejections per minute, grouped by cause
sum by (reason) (increase(wok_abuse_rejections_total[1m]))

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
`wok_relay::server::writer` target with its `entries` and `ms`. A step that
fails logs at `error`; the writer retries on its next maintenance tick.

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
