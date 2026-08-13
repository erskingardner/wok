# Observability

Wok exposes Prometheus metrics at `/metrics`, emits structured tracing records,
and keeps a small bounded in-memory history for its authenticated admin UI.
The local history is not persisted and is not exposed by a public endpoint.

## Grafana metrics

Point Prometheus (or Grafana Alloy's Prometheus receiver) at the relay's
`/metrics` endpoint. The exported series cover active and authenticated
connections, accepted/duplicate/rejected events, slow clients, admission
rejections, and protocol messages by type. Grafana can query those series
directly from Prometheus or Mimir.

## Grafana logs

Set:

```toml
[observability]
log_format = "json"
log_filter = "wok=info"
```

Wok then writes one JSON object per line to stdout/stderr. Run it under a
service manager and ship that stream with Grafana Alloy, Vector, Fluent Bit,
or Promtail to Loki. Structured fields include connection IDs, transports,
peer addresses, event IDs/pubkeys/kinds, query IDs and result counts, plus
maintenance deletion counts. Wok never logs event content in these records.

`RUST_LOG` takes precedence over `log_filter`, which is useful for temporary
debugging without editing the service configuration.

## Bounded local history

The relay samples aggregate counters for the admin charts. The default is
5,760 points at 15-second intervals (24 hours). Storage is a FIFO in memory:
new samples evict the oldest, disabling history clears it, restart clears it,
and configuration rejects more than 100,000 points. This prevents an
observability feature from becoming unbounded relay state.
