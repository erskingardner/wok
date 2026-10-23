# docs/

Operator and design documentation. Code remains the authority for current behavior; these files explain design, policy, and operations.

## Start here

| File | Read when |
| --- | --- |
| `architecture.md` | Threading, crate boundaries, I/O vs LMDB |
| `nips.md` | Advertised NIPs, pin, what is *not* advertised |
| `compatibility-policy.md` | NIPs-first vs strfry; what migration promises |
| `known-differences.md` | Intentional divergences from C++ |
| `config.md` + `wok.toml` | Native TOML settings and sample |
| `presets/` | A page per preset (who it is for, what it changes, what it refuses) and copies of the overlays in `crates/wok-relay/presets/` |
| `lmdb-v3.md` | strfry v3 import contract |

## Operations

| File | Topic |
| --- | --- |
| `migration-from-strfry.md` | `wok migrate strfry` |
| `cutover.md` | Cutover / rollback |
| `production-deployment.md` | Hardening a live relay; macOS LMDB semaphore exhaustion (ENOSPC at `Env::open`) |
| `security.md` | Threat model, fuzzing, unsafe policy |
| `observability.md` | Metrics / tracing |
| `admin-dashboard.md` | `/admin` |
| `unix-socket.md` | Length-prefixed Unix protocol |
| `mesh-and-maintenance.md` | router/sync, doctor, reindex |
| `releases.md` | Tag and GitHub release process |
| `reliability.md` | CI gates, generated integration tests, Linux soak and evidence limits |
| `load-lab.md` | Local / two-VM Docker benchmark lab and SSH setup |
| `nip50-search.md` | Search semantics and scoring |
| `nip86.md` | Management API: methods, levels, ban/role semantics |

## What does not belong here

Docs describe how Wok works and how to run it. Do not commit plans, proposals, audits, code reviews, or dated benchmark, soak, and lab run reports. Put findings and results in the pull request or issue, and keep only the reusable methodology (how to run and read a benchmark) in these files. `wok.svg` is the logo.

When behavior changes, update the relevant doc in the same change: NIPs → `nips.md` + capabilities; strfry diffs → `known-differences.md`; config keys → `config.md` (and `wok.toml` only for settings most operators must set; it holds overrides, not defaults); changed defaults → `PAST_DEFAULTS` in `wok-relay/src/config/history.rs`.
