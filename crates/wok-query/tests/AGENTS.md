# wok-query/tests

| File | Role |
| --- | --- |
| `completeness.rs` | NIP-67 completeness of finished REQ scans, including peeks past cuts |
| `filter_prop.rs` | Filter compile/match properties |
| `scan_kinds.rs` | Kind-index scan behavior and plan choice |
| `scan_plan.rs` | `ScanPlan`, which the query-cost gate prices, names the plan `DbScan` runs and counts its cursors |
| `tag_kind_plan.rs` | Property test: the TagKind plan returns what the Tag plan does, stale entries included |
| `search.rs` | NIP-50 ranked search against the LMDB term index |
| `timeslice.rs` | Time slices of multi-filter scans; an ignored slice-length bench |
| `visibility_cost.rs` | Ignored bench: per-event read-visibility cost by policy record |

Wire-level COUNT/search coverage also lives in `crates/wok-compat/tests/nip_conformance.rs`. Design notes: `docs/nip50-search.md`.
