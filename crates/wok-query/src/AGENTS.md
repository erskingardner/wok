# wok-query/src

| File | Role |
| --- | --- |
| `lib.rs` | Re-exports |
| `filter.rs` | `NostrFilter` / `NostrFilterGroup`, `dumb_match`, validator |
| `scan.rs` | Resumable `DbScan` / `DbQuery` (C++ `DBQuery.h`); NIP-67 `Completeness` |
| `scheduler.rs` | Per-connection query scheduling; REQ and COUNT ids are separate |
| `monitor.rs` | Live inverted index (`ActiveMonitors`) over subscription slots, O(keys) add/remove; pending or live by generation |
| `pending.rs` | `PendingBuffer`: live matches held while a REQ's history is sent |
| `subid.rs` | `SubId`, `Subscription`, `QueryError` |
| `visibility.rs` | Shared recipient, moderation, vanish, expiration and AUTH-kind (22242) policy |
| `hll.rs` | NIP-45 HyperLogLog registers and filter offset |

Historical restricted-kind filtering uses PackedEvent from the Event table, not EventPayload bytes. That is intentional and documented in `docs/known-differences.md`.
