# wok-query/src

| File | Role |
| --- | --- |
| `lib.rs` | Re-exports |
| `filter.rs` | `NostrFilter` / `NostrFilterGroup`, `dumb_match`, validator |
| `scan.rs` | Resumable `DbScan` / `DbQuery` (C++ `DBQuery.h`) |
| `scheduler.rs` | Per-connection query scheduling |
| `monitor.rs` | Live inverted index (`ActiveMonitors`) |
| `subid.rs` | `SubId`, `Subscription`, `QueryError` |
| `hll.rs` | NIP-45 HyperLogLog registers and filter offset |

Historical restricted-kind filtering uses PackedEvent from the Event table, not EventPayload bytes. That is intentional and documented in `docs/known-differences.md`.
