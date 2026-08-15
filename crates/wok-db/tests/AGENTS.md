# wok-db/tests

Storage integration tests. They open disposable LMDB environments.

| File | Role |
| --- | --- |
| `comparator_prop.rs` | Composite key / comparator properties |
| `txn_prop.rs` | Transaction sequences |
| `foreach_full.rs` | Full-table scans; `MDB_GET_BOTH_RANGE` must not be used on non-DUPSORT DBIs |
| `index_drift.rs` | Derived indexes stay consistent with primaries |
| `failure_recovery.rs` | Unclean shutdown / recovery |
| `nip59_gift_wrap.rs` | Gift-wrap deletion / recipient semantics |
| `nip62_vanish.rs` | Request to Vanish markers and sweep |
| `cpp_roundtrip.rs` | Optional differential vs strfry (needs `STRFRY_BIN`) |

`cpp_roundtrip` is skipped when strfry is absent. Query/search behavior is also covered in `crates/wok-query/tests/` and `crates/wok-compat/tests/`.
