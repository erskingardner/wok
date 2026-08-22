# .github/workflows

| File | When | What |
| --- | --- | --- |
| `ci.yml` | every push/PR | lean dependency boundary, fmt, clippy/tests with and without `native-fips`, conformance smoke, MSRV 1.94.1 checks |
| `fips-e2e.yml` | FIPS-relevant master/PR changes; manual | Two native Linux FIPS nodes plus Wok, asserting signed event size boundaries and query-back over Compose |
| `platforms.yml` | master, PR | Lean and `native-fips` builds: Linux x86_64/ARM64, macOS Intel/Apple Silicon |
| `security.yml` | Cargo.toml/lock/deny.toml; weekly | `cargo-deny` via `deny.toml` |
| `fuzz.yml` | fuzz/protocol paths; weekly Wednesday | AddressSanitizer ingress fuzz |
| `release.yml` | tags `v*.*.*` | Validate contract, build lean and `native-fips` archives, publish GitHub release |

Local equivalents: `cargo fmt/clippy/test` from the root `AGENTS.md`; `scripts/check-release.sh` before tagging.
