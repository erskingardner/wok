# Matched network comparison

This experimental harness compares Wok LMDB, optional Wok RocksDB, fastr and
strfry using fixed publication and historical-query arrival deadlines. It uses
disposable database copies, checks returned event bodies and ordering, and
preserves incomplete operations and their raw timestamps.

Build the load driver and the two Wok variants into separate target directories
so one backend's binary does not replace the other:

```sh
cargo build --release --locked -p wok-bench
cargo build --release --locked -p wok-cli --target-dir target/lmdb
cargo build --release --locked -p wok-cli --features rocksdb-backend --target-dir target/rocksdb
```

The RocksDB build needs Rust 1.88 or newer and native C++/libclang build
dependencies. See [the backend documentation](../../docs/rocksdb-experimental.md)
for storage format, supported operations and durability behavior.

The driver exposes `--scenario matched_network_generate` and
`--scenario matched_network`; `target/release/wok-bench --help` lists their shared
options. `python3 tools/relay-matched/run-campaign.py --help` describes the
campaign inputs, including separately supplied relay binaries, configuration
templates, source manifest, load-host paths and SSH identity. No credentials,
databases or campaign output are included here.

The controller targets isolated Linux relay/load hosts with systemd and cgroup
v2. Its CPU, memory, file-limit and disk guards are explicit; it is not a local
developer-machine smoke benchmark. Supply task-owned paths, units and access
before running it. The controller creates a qualification stage before the
full-size comparison. Completed evidence can be imported only after its hashes
and workload identities pass validation.

Run the controller's offline tests without starting relay or load jobs:

```sh
python3 -B -m unittest discover -s tools/relay-matched -p test_campaign.py -v
```

Read-queue overflow classification is opt-in and requires external relay-side
proof plus successful write/body checks. It retains the original protocol errors
and incomplete read counts. Such a cell is ineligible for both read and write
mixed-load rankings because early read disconnections change later contention.
Stock fastr buffered acknowledgements must also remain distinguished from
synchronous LMDB commits and RocksDB synchronous WAL acknowledgements.
