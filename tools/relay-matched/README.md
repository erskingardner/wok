# Matched network comparison

This retained experimental harness compares explicitly supplied Wok, fastr and
strfry binaries using fixed publication and historical-query arrival deadlines. It uses
disposable database copies, checks returned event bodies and ordering, and
preserves incomplete operations and their raw timestamps.

Current Wok builds use the optimized RocksDB runtime without a backend feature:

```sh
cargo build --release --locked -p wok-bench
cargo build --release --locked -p wok-cli
```

The runtime needs Rust 1.88 or newer and native C++/libclang build
dependencies. See [the backend documentation](../../docs/rocksdb-experimental.md)
for storage format, supported operations and durability behavior.

The controller retains its historical `wok` and optional fourth-arm `rocksdb`
labels for archived campaign identities and predecessor validation. They do not
select a build backend. Reproducing an older LMDB comparison requires its exact
preserved binary/source; an ordinary current build cannot produce an LMDB relay.
This documentation update does not relabel or regenerate old campaign evidence.

The driver exposes `--scenario matched_network_generate` and
`--scenario matched_network`; `target/release/wok-bench --help` lists their shared
options. `python3 tools/relay-matched/run-campaign.py --help` describes the
campaign inputs, including separately supplied relay binaries, configuration
templates, source manifest, load-host paths and SSH identity. No credentials,
databases or campaign output are included here.

For a new qualification that appends to the authors being queried, pass
`--matched-writer-authors queried` to the driver or this controller. Generate
the seed corpus normally with `matched_network_generate`, then reuse that same
`--seed` for the timed run. The driver derives the signing keys for all 64
actual single-author historical plans and cycles them over the unchanged 32
publisher sockets. Every feed500 plan also overlaps those writers. It refuses
a corpus whose selected authors cannot be derived from that seed.

Timed timestamps remain exactly `history_cutoff + 1`. Appends update those
authors' frontiers while every historical query retains its fixed `until`,
ordering and full-body oracle. Arrival schedules, socket counts, drain and
resource caps do not change. Reports add the mode, public-key-set hash/count,
per-shape author intersections, ordered timed-event-ID hash and a versioned
`workload_sha256`. Tag/id plans have no author restriction; their overlap entries
say so. Hashes never expose private signing keys.

The default `disjoint` mode retains the original independent 32-author domain,
signed JSONL, query-pool hashes and serialized report fields; its mode is implicit
when the new fields are absent. The controller omits the default switch and
manifest option. Use a fresh qualification namespace for `queried` and keep it
separate from earlier results; the controller rejects a writer-mode mismatch.

The controller targets isolated Linux relay/load hosts with systemd and cgroup
v2. Its CPU, memory, file-limit and disk guards are explicit; it is not a local
developer-machine smoke benchmark. Supply task-owned paths, units and access
before running it. The controller creates a qualification stage before the
full-size comparison. Completed evidence can be imported only after its hashes
and workload identities pass validation.

Run the controller's offline tests without starting relay or load jobs:

```sh
python3 -B -m unittest discover -s tools/relay-matched -p test_campaign.py -v
python3 -B -m unittest discover -s tools/relay-matched -p test_timestamps.py -v
```

Audit completed trial directories on the host that holds their raw ledgers:

```sh
python3 tools/relay-matched/audit-timestamps.py \
  /path/to/campaign/main/reports/r1-w1000-rocksdb \
  /path/to/campaign/main/reports/r1-w1000-strfry \
  --window-seconds 5 --out /path/to/new-audit.json
```

The audit verifies completion-manifest hashes, reconciles raw read/write
timestamps with report counts and histograms, checks caps and workload
identities, and computes exact nearest-rank latency and arrival-window summaries.
Compare the same timing origin: scheduled arrival to EOSE/OK includes send
lateness; wire timing starts before the socket send. Windows group operations
by their scheduled arrivals. Missing operations retain the fixed censor
deadline and prevent either mixed-load latency distribution from winning.
Client debt and outstanding requests do not measure internal relay queues.
If a controller retained native RocksDB logs after shutdown, the audit also
counts flush/compaction events within the relay process lifetime, excluding
inherited seed history. These wall-clock observations include untimed startup,
preflight, readback and settlement; they cannot be precisely aligned with
individual query windows because the frozen driver records relative time.
Only aggregate audit output needs to leave the benchmark hosts.

Read-queue overflow classification is opt-in and requires external relay-side
proof plus successful write/body checks. It retains the original protocol errors
and incomplete read counts. Such a cell is ineligible for both read and write
mixed-load rankings because early read disconnections change later contention.
Stock fastr buffered acknowledgements must also remain distinguished from
RocksDB synchronous WAL acknowledgements and, in archived comparisons, synchronous
LMDB commits.
