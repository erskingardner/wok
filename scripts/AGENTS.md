# scripts/

Operator/CI helper scripts. Not on the relay runtime path.

| File | Role |
| --- | --- |
| `check-release.sh` | Release contract: version, changelog, lockfile, tests |
| `lab.py` | Local / two-VM Compose campaign, artifacts, shutdown and integrity |
| `lab-bootstrap-debian.sh` | Opt-in Docker installation on clean Debian 12/13 |
| `reliability-soak.py` | Disposable Linux relay/load processes, resource samples, restart and integrity gates |
| `release-notes.sh` | Extract changelog notes for a tag |
| `benchmark-campaign.sh` | Two-host / full `wok-bench` campaign wrapper |
| `benchmark-transports.sh` | Same-host Unix vs WebSocket comparison |
| `benchmark-relay-control.sh` | Relay control / orchestration for campaigns |

Release process is documented in `docs/releases.md`. Benchmark methodology is `docs/benchmarks.md`. GitHub release workflow calls the release scripts from `.github/workflows/release.yml`.
