# wok-negentropy/src

| File | Role |
| --- | --- |
| `lib.rs` | Public API (`Negentropy`, `Vector`, `BTreeLmdb*`, types) |
| `protocol.rs` | Reconcile state machine (`negentropy.h`) |
| `encoding.rs` | Varint / byte parsing |
| `types.rs` | `Item`, `Bound`, fingerprint, `PROTOCOL_VERSION` |
| `storage.rs` | `Storage` trait (fallible like C++) |
| `vector.rs` | In-memory storage |
| `btree.rs` | Persistent B-tree core and node encoding |
| `lmdb_store.rs` | Persistent `wok-db` backend (historical filename; logical tree/node keys retain their import encoding) |
| `cache.rs` | `NegentropyFilterCache` / `DeferredSink` |
| `error.rs` | `NegError` |

Storage errors must abort a reconcile session rather than substitute defaults. Fuzzing of protocol/tree bytes is in `fuzz/fuzz_targets/ingress.rs`.

Lookups decode only the nodes on their path. Of each sibling they pass they read just `accum_count` and the accumulator (`BTreeBackend::get_node_summary`), from transaction-bound storage bytes, and the read-only backend keeps those it read for the rest of its snapshot (#254). Decoding whole siblings, each again for every lookup, made one crafted NEG-MSG cost seconds.
