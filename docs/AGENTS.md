# docs/

Operator and design documentation. Code remains the authority for current behavior; these files explain policy, ops, and historical evidence.

## Start here

| File | Read when |
| --- | --- |
| `architecture.md` | Threading, crate boundaries, I/O vs LMDB |
| `nips.md` | Advertised NIPs, pin, what is *not* advertised |
| `compatibility-policy.md` | NIPs-first vs strfry; what migration promises |
| `known-differences.md` | Intentional divergences from C++ |
| `config.md` + `wok.toml` | Native TOML settings and sample |
| `lmdb-v3.md` | strfry v3 import contract |

## Operations

| File | Topic |
| --- | --- |
| `migration-from-strfry.md` | `wok migrate strfry` |
| `cutover.md` | Cutover / rollback |
| `production-deployment.md` | Hardening a live relay |
| `security.md` | Threat model, fuzzing, unsafe policy |
| `observability.md` | Metrics / tracing |
| `admin-dashboard.md` | `/admin` |
| `unix-socket.md` | Length-prefixed Unix protocol |
| `mesh-and-maintenance.md` | router/stream/sync, doctor, reindex |
| `releases.md` | Tag and GitHub release process |
| `nip50-search.md` | Search semantics and scoring |
| `nip86.md` | Management API: methods, levels, ban/role semantics |

## Evidence / reports

Dated benchmark writeups (`benchmark-*.md`, `websocket-performance-*.md`, `transport-benchmark-*.md`), `sample-bench-*.md` / `.jsonl`, and `FINAL.md` (definition-of-done). `wok.svg` is the logo.

When behavior changes, update the relevant doc in the same change: NIPs → `nips.md` + capabilities; strfry diffs → `known-differences.md`; config keys → `config.md` + `wok.toml`.
