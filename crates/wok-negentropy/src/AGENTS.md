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
| `lmdb_store.rs` | LMDB backend (`tree_id \|\| node_id` keys, `MDB_REVERSEKEY`) |
| `cache.rs` | `NegentropyFilterCache` / `DeferredSink` |
| `error.rs` | `NegError` |

Storage errors must abort a reconcile session rather than substitute defaults. Fuzzing of protocol/tree bytes is in `fuzz/fuzz_targets/ingress.rs`.
