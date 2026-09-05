# .github/workflows

| File | When | What |
| --- | --- | --- |
| `ci.yml` | every push/PR | fmt, clippy `-D warnings`, all workspace tests, mandatory pinned C++ migration, MSRV 1.85 check |
| `platforms.yml` | master, PR | Native builds and behavioral tests: Linux x86_64/ARM64, macOS Intel/Apple Silicon |
| `security.yml` | Cargo.toml/lock/deny.toml; weekly | `cargo-deny` via `deny.toml` |
| `fuzz.yml` | crate/fuzz changes on master/PR; weekly Wednesday | Seeded AddressSanitizer ingress fuzz with corpus reuse |
| `reliability.yml` | crate/soak changes on master/PR; weekly/manual | Three-minute canary; weekly one-hour Linux soak, RSS/CPU and exact data checks |
| `release.yml` | tags `v*.*.*` | Validate contract, build archives, publish GitHub release |

Local equivalents: `cargo fmt/clippy/test` from the root `AGENTS.md`; `scripts/check-release.sh` before tagging.
