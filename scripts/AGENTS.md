# scripts/

Operator/CI helper scripts. Not on the relay runtime path.

| File | Role |
| --- | --- |
| `check-release.sh` | Release contract: version, changelog, lockfile, tests |
| `lab.py` | Local / two-VM Compose campaign, artifacts, shutdown and integrity |
| `lab-bootstrap-debian.sh` | Opt-in Docker installation on clean Debian 12/13 |
| `reliability-soak.py` | Disposable Linux relay/load processes, resource samples, restart and integrity gates |
| `attack-surface-reach.py` | Relay functions each caller (anonymous, authenticated, admin, admitted Unix peer) reaches per profile, under coverage; `--check` against `crates/wok-compat/tests/reachability/` |
| `release-notes.sh` | Extract changelog notes for a tag |
| `benchmark-campaign.sh` | Two-host `wok-bench` campaign over any number of relay targets, rotating their order each repetition |
| `benchmark-transports.sh` | Same-host Unix vs WebSocket comparison |
| `benchmark-qualify.sh` | Checks two benchmark hosts before a campaign: hardware facts, relay disk sync latency and random reads, network, steal; `BASELINE` compares the sync-write p99 |
| `benchmark-relay-control.sh` | Relay-host helper: target files, transient systemd units with CPU and memory caps, cache drops, database snapshots, evidence |

Release process is documented in `docs/releases.md`. Benchmark methodology is `docs/benchmarks.md`. `tests/` holds unit tests for `lab.py` and the benchmark shell scripts (`python3 -m unittest discover -s scripts/tests`). GitHub release workflow calls the release scripts from `.github/workflows/release.yml`.
