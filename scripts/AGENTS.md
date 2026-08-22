# scripts/

Operator/CI helper scripts. Not on the relay runtime path.

| File | Role |
| --- | --- |
| `check-release.sh` | Release contract: version, changelog, lockfile, tests |
| `release-notes.sh` | Extract changelog notes for a tag |
| `benchmark-campaign.sh` | Two-host / full `wok-bench` campaign wrapper |
| `benchmark-transports.sh` | Same-host Unix vs WebSocket comparison |
| `benchmark-relay-control.sh` | Relay control / orchestration for campaigns |
| `test-fips-compose.sh` | Disposable two-node Linux FIPS/Wok signed-event size matrix |

Release process is documented in `docs/releases.md`. Benchmark methodology is `docs/benchmarks.md`. GitHub release workflow calls the release scripts from `.github/workflows/release.yml`.
