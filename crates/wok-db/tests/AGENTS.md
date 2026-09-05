# wok-db/tests

Storage integration tests. They open disposable LMDB environments.

| File | Role |
| --- | --- |
| `comparator_prop.rs` | Composite key / comparator properties |
| `txn_prop.rs` | Transaction sequences |
| `foreach_full.rs` | Full-table scans; `MDB_GET_BOTH_RANGE` must not be used on non-DUPSORT DBIs |
| `index_drift.rs` | Derived indexes stay consistent with primaries |
| `failure_recovery.rs` | Unclean shutdown / recovery |
| `state_integrity.rs` | Corrupt state detection and valid lazy/deleted-tail state |
| `nip59_gift_wrap.rs` | Gift-wrap deletion / recipient semantics |
| `nip62_vanish.rs` | Request to Vanish markers and sweep |
| `cpp_roundtrip.rs` | Optional differential vs strfry (needs `STRFRY_BIN`) |

`cpp_roundtrip` may skip locally when strfry is absent. `WOK_REQUIRE_STRFRY=1` turns a missing reference into a failure; the dedicated CI migration job sets it. Query/search behavior is also covered in `crates/wok-query/tests/` and `crates/wok-compat/tests/`.
