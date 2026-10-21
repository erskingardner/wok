# wok-query/tests

| File | Role |
| --- | --- |
| `completeness.rs` | NIP-67 completeness of finished REQ scans, including peeks past cuts |
| `filter_prop.rs` | Filter compile/match properties |
| `scan_kinds.rs` | Kind-index scan behavior |
| `search.rs` | NIP-50 ranked search against the LMDB term index |
| `timeslice.rs` | Time slices of multi-filter scans |

Wire-level COUNT/search coverage also lives in `crates/wok-compat/tests/nip_conformance.rs`. Design notes: `docs/nip50-search.md`.
