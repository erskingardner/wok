# Repeatable load and benchmark lab

The lab uses one Wok relay container and one `wok-bench` generator container.
Run both locally first, then deploy the same source to two Linux VMs over SSH.
No registry, Kubernetes cluster, or Nix installation is required.

The initial automated workload measures scaled publication, live fanout, and
idle connections. It verifies publication receipts and complete live delivery,
then checks the relay database offline after graceful shutdown. This packages
existing benchmark capabilities; it is not the adversarial overload/recovery
suite or the authenticated large-sync campaign proposed in the plan.

## Local start

Requirements: Docker Engine or Docker Desktop using Linux containers, Docker
Compose with `up --wait` support (2.20+), Git, and Python 3.11+.

From the repository root:

```sh
python3 scripts/lab.py local
```

This builds the release relay and generator image, starts the relay, waits for
HTTP health, runs three benchmark scenarios, collects evidence, stops the
relay, checks integrity, and removes the campaign containers/network. The image
build is cached. `--skip-build` uses an existing `wok-lab:local` image, primarily
for packaging development; it does not establish that the image matches HEAD.

The default campaign uses 2,000 events, eight publisher connections, eight
fanout subscribers, 100 fanout events, and 64 idle connections held for two
seconds. It has a 15-minute workload deadline, excluding image builds and
startup/collection. Each container has a two-CPU, 2 GiB memory limit and a
65,536 file-descriptor limit. Host port 7777 is bound to loopback by default.

Scale the same generator process before adding more processes:

```sh
LAB_EVENTS=100000 LAB_PUBLISHERS=128 LAB_SUBSCRIBERS=128 \
LAB_FANOUT_EVENTS=1000 LAB_CONNECTIONS=10000 LAB_HOLD_SECONDS=30 \
LAB_ROUNDS=3 LAB_DEADLINE_SECONDS=1800 \
LAB_RELAY_CPUS=4 LAB_RELAY_MEMORY=4g \
LAB_LOAD_CPUS=4 LAB_LOAD_MEMORY=4g \
python3 scripts/lab.py local
```

Those settings are an example campaign, not a tested capacity claim. Give
Docker enough memory for both limits and the host overhead; Rust image builds
also need memory outside these runtime service limits. Rounds use distinct
seeds against the same accumulating database. For clean-database comparisons,
run a new campaign for each configuration and use the same `LAB_SEED` and
`LAB_BASE_TIMESTAMP` (a current Unix timestamp). The latter must stay inside the
relay's accepted event-age window. `LAB_RELAY_PORT` changes the published host
port; local containers still communicate on the internal port 7777.

## Two Debian VMs

Use a dedicated relay VM and generator VM, preferably on a private network.
The operator needs Python 3.12+ for safe result-archive extraction, working SSH
access with verified host keys, and a clean committed checkout. Remote hosts
need Docker Engine/Compose and `tar`; they do not need Rust, Git, or Python on
the host. Builds run natively, so AMD64 and ARM64 are both usable. Record the
architecture when comparing results.

```sh
python3 scripts/lab.py remote \
  --relay-ssh root@RELAY_SSH_IP \
  --load-ssh root@LOAD_SSH_IP \
  --relay-bind RELAY_PRIVATE_IP \
  --target-url ws://RELAY_PRIVATE_IP:7777
```

The private address must be assigned to the relay VM and reachable from the
load VM. Allow that port only from the generator using the provider firewall or
an isolated network. The benchmark config disables admission limiting, so it
must not be deployed as a public production relay. Docker-published ports can
bypass ufw rules; see [Docker's Debian prerequisites](https://docs.docker.com/engine/install/debian/#prerequisites).

For fresh Debian 12/13 hosts, append `--bootstrap-debian`. This explicitly
installs Docker from its official apt repository using
[`lab-bootstrap-debian.sh`](../scripts/lab-bootstrap-debian.sh), following
[Docker's installation instructions](https://docs.docker.com/engine/install/debian/#install-using-the-apt-repository).
Bootstrap requires root SSH and refuses to replace existing container runtimes
or repository configuration. An already working Docker/Compose installation is
left in place. Without this flag, the runner only checks the prerequisites.
Non-root SSH works when that account already has Docker access; the script does
not grant group membership or forward SSH agents.

The operator:

1. Archives the exact clean Git commit and stages it under
   `~/wok-lab/<run-id>` on both hosts, refusing existing staging directories.
2. Checks that the SSH destinations refer to distinct Docker daemons and that
   the campaign project has no existing containers, volumes, or networks.
3. Builds both roles from that same source and starts only the relay on its VM.
4. Runs the generator directly against the relay's private WebSocket address.
   Workload traffic does not pass through the operator's SSH connection.
5. Collects generator artifacts over SSH, samples container resources, stops the
   relay, checks integrity, and removes only that campaign's containers/network.

Source staging, images, and named volumes remain on the hosts. The runner does
not stop systemd services, reset an existing database, edit host firewall rules,
or operate the old fixed-host benchmark scripts.

## Direct Compose use

The two files also work independently:

```sh
# Relay VM, from its source checkout:
LAB_RELAY_BIND=RELAY_PRIVATE_IP docker compose -p wok-lab-manual \
  -f contrib/lab/relay.compose.yml up --build -d --wait

# Load VM, from the same source checkout:
LAB_TARGET=ws://RELAY_PRIVATE_IP:7777 docker compose -p wok-load-manual \
  -f contrib/lab/load.compose.yml run --build --name wok-load-manual load

# Copy artifacts before removing the load container:
docker cp wok-load-manual:/results/. ./load-results
```

Direct Compose use does not collect relay evidence or orchestrate shutdown;
prefer `scripts/lab.py` for a complete campaign. A load volume can be used only
once: `/results/run` must not exist. Use a new project name for another run.

The image also contains the unwrapped `wok-bench` binary. Its remote historical
query and mixed-read/write scenarios require a matching preloaded corpus; the
initial lab runner does not import that corpus. See [benchmarks](benchmarks.md)
for those commands and the existing controlled Wok/strfry comparison workflow.
The new lab currently runs Wok only and does not claim Wok/strfry comparisons.

## Evidence and cleanup

The runner writes `bench-results/lab/<run-id>/`, including:

- Source revision/dirty status, source file hashes, explicit workload settings,
  resolved Compose configs, Docker host information, and image IDs/labels.
- Generator binary/corpus hashes, per-round JSONL results and latency summaries,
  logs, and explicit success/failure records.
- Sampled Docker CPU, memory, network/block I/O and process counts for both roles.
  Samples are sequential snapshots about five seconds apart plus collection
  overhead, not continuous peak measurements or LMDB writer-queue timings.
- Relay config, metrics, logs including shutdown, final container exit state,
  and offline integrity output.

All three expected scenarios must occur exactly once per round with `ok=true`,
zero errors, and zero mismatches. Missing results, timeouts, abnormal relay exit,
and failed integrity cause the runner to fail. A benchmark's zero process exit
alone is insufficient. An intentionally exceeded load limit is therefore a
failed correctness trial; it must be analyzed, not reported as a faster result.

Named volumes remain even on failure. They are specific to the printed Compose
project. After inspecting and saving the evidence, remove those volumes
explicitly on their respective hosts; for example, for project
`wok-lab-example`:

```sh
docker volume rm wok-lab-example_relay-data wok-lab-example_load-results
```

On two VMs, each volume exists only on its corresponding host. Do not use
`docker system prune` as lab cleanup. The runner always chooses a fresh run ID
unless one is supplied and refuses an existing artifact directory or project.

## Scaling beyond one generator

A simulated client is a socket/task, not a container. First measure generator
CPU, memory, network bandwidth, and connection limits to establish whether the
generator is the bottleneck. For higher scale, add explicit generator shards
with distinct event namespaces, isolated subscription filters, coordinated
start/stop, and mergeable latency histograms. Simply scaling this Compose load
service is not supported: its result path is single-writer and the current
fanout scenario subscribes broadly, so independent generators would interfere.
A scheduler becomes useful once those worker semantics exist; Kubernetes is
not required to establish them.

CI exercises the local Docker path and result/archive safety tests. The first
local validation passed one round at defaults and two rounds with 4,000 events,
16 publishers/subscribers, and 128 idle connections. An unreachable target
failed within its configured deadline and retained evidence. Labelled and unlabelled existing-volume
collision refusal and real Docker result-archive extraction were also checked. Actual SSH deployment/bootstrap still
requires validation on supplied disposable VMs.
