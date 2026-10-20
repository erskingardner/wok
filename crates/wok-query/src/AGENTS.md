# wok-query/src

| File | Role |
| --- | --- |
| `lib.rs` | Re-exports |
| `filter.rs` | `NostrFilter` / `NostrFilterGroup`, `dumb_match`, validator |
| `scan.rs` | Resumable `DbScan` / `DbQuery` (C++ `DBQuery.h`) |
| `scheduler.rs` | Per-connection query scheduling; REQ and COUNT ids are separate |
| `monitor.rs` | Live inverted index (`ActiveMonitors`), pending or live by generation |
| `pending.rs` | `PendingBuffer`: live matches held while a REQ's history is sent |
| `subid.rs` | `SubId`, `Subscription`, `QueryError` |
| `visibility.rs` | Shared recipient, moderation, vanish and expiration policy |
| `hll.rs` | NIP-45 HyperLogLog registers and filter offset |

Historical restricted-kind filtering uses PackedEvent from the Event table, not EventPayload bytes. That is intentional and documented in `docs/known-differences.md`.
