# Releases

Wok uses Semantic Versioning and `vMAJOR.MINOR.PATCH` Git tags. The workspace
version in `Cargo.toml`, the tag without its `v` prefix, and the dated section
in `CHANGELOG.md` must agree.

## Preparing a release

1. Move the relevant entries from `Unreleased` into a new dated changelog
   section, then add a fresh `Unreleased` section.
2. Set `[workspace.package].version` in `Cargo.toml`. Every crate inherits this
   single version.
3. Run the normal CI commands and the RocksDB feature gate, then merge or push
   the release commit. LMDB remains the default build; `--features rocksdb`
   selects the optimized RocksDB layout and author-frontier reader.
4. Wait for CI and distribution-platform builds to pass for that exact commit.
5. Tag the exact release commit and push only that tag:

   ```bash
   version=0.2.0
   git tag -a "v$version" <release-commit> -m "Wok $version"
   git push origin "v$version"
   ```

The tag push starts `.github/workflows/release.yml`. It independently validates
the tag/version/changelog contract and tests both backends, builds separate
native Wok binaries for Linux x86-64 and ARM64 plus macOS Intel and Apple Silicon, creates
checksums, and publishes a GitHub Release for that tag. It never moves or
creates a tag itself.

## Release assets

Archives are named `wok-VERSION-BACKEND-TARGET.tar.gz`, with `BACKEND` set to
`lmdb` or `rocksdb`. Each backend has its own build directory and upload name;
RocksDB never replaces an LMDB release asset. The executable inside either
archive is named `wok`. Run `wok storage-backend` to identify its storage build.

Each archive contains `wok`, `BACKEND.json`, `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md`,
`SECURITY.md`, `LICENSE`, the example `wok.toml`, and the complete `docs/` tree
so README links and the Wok logo remain available offline. `BACKEND.json`
records the backend, feature selection, storage identity, version, target,
source commit and compiler. `SHA256SUMS` covers all published archives. Wok
currently uses Unix-specific process, signal, and socket APIs, so Windows
artifacts are not published.

## Backend build gates

The LMDB workspace retains Rust 1.85 as its minimum. The optional RocksDB build
requires Rust 1.88 or newer, a C++ compiler and libclang for native bindings.
The current RocksDB storage identity is `rocksdb-author-heads-experimental`;
the release feature alias is `rocksdb`. The alias does not select RocksDB for
default builds or convert an existing LMDB database in place.

On Debian/Ubuntu, install `g++ clang libclang-dev`. On macOS, install LLVM
(`brew install llvm`) and set `LIBCLANG_PATH="$(brew --prefix llvm)/lib"` if
libclang is not found. Xcode's command-line tools provide the C/C++ compiler.
Native RocksDB compilation is substantial; CI limits parallel build jobs to two.

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked --features wok-cli/rocksdb -- -D warnings
cargo test --workspace --locked --features wok-cli/rocksdb
cargo build --release --locked -p wok-cli --features rocksdb --target-dir target/rocksdb
target/rocksdb/release/wok storage-backend
```

Workspace feature tests include the RocksDB format, migration, author-frontier
and recovery suites. The mandatory pinned C++ differential gate remains an
LMDB import compatibility check; it does not claim that a RocksDB binary can
directly read a strfry LMDB directory. Distribution checks retain all four
LMDB platforms and add native RocksDB canaries on Linux x86-64 and macOS ARM64;
tag builds cover both backends on all four targets.

The reliability workflow runs a three-minute canary for each backend and a
weekly one-hour soak for each. Before changing the default backend, review the
native suite, migration checks and complete soak artifacts for the exact
candidate commit. The soak verifies receipts, stored bodies, a 500-author
feed during same-author appends, graceful restart, and one SIGKILL recovery
after acknowledged work. This is process-crash coverage, not power-loss or
in-flight-write durability proof.

To run the one-hour RocksDB soak locally on Linux:

```sh
cargo build --release --locked -p wok-cli --features rocksdb --target-dir target/relay-rocksdb
cargo build --release --locked -p wok-compat --example reliability_soak --target-dir target/soak-driver
python3 scripts/reliability-soak.py --backend rocksdb \
  --wok target/relay-rocksdb/release/wok \
  --driver target/soak-driver/release/examples/reliability_soak \
  --seconds 3600 --seed 4242 --out /tmp/wok-rocksdb-soak-1
```

Use a new output directory for each run. Artifacts, failed databases and logs
are retained. The runner checks the binary's storage identity, samples all
database files (including RocksDB WAL/SST files), and performs the full offline
RocksDB audit after each stop and at the end. See [reliability.md](reliability.md)
for workload and resource-limit interpretation.

Do not reuse or move a published version tag. If a release needs correction,
prepare a new patch version and changelog entry.
