# Releases

Wok uses Semantic Versioning and `vVERSION` Git tags. The workspace version in
`Cargo.toml`, the tag without `v`, and the dated section in `CHANGELOG.md` must
agree. Release candidates use a SemVer prerelease suffix such as `0.8.0-rc.1`.
Preparing a candidate does not publish it or create a tag.

## Preparing a release

1. Move the relevant `Unreleased` entries into a dated section and set the
   workspace version. Every crate inherits it.
2. Run normal CI, native platform tests, read-only import compatibility and
   recovery checks for that exact candidate.
3. Merge or push the reviewed commit, then wait for all required checks.
4. Only when publishing is authorized, tag the exact commit and push the tag:

   ```sh
   version=0.8.0-rc.1
   git tag -a "v$version" <release-commit> -m "Wok $version"
   git push origin "v$version"
   ```

`scripts/release-version.py` validates strict SemVer, `check-release.sh` checks
version/changelog consistency, and `release-notes.sh` extracts the exact section.
`publish-release.sh` keeps tag verification and chooses prerelease/latest flags.
The tag workflow tests the runtime and
imports, builds native Linux x86-64/ARM64 and macOS Intel/Apple Silicon binaries,
and publishes checksummed assets. Prerelease tags produce GitHub prereleases
without replacing the latest stable release. Stable tags publish stable releases.
The workflow does not create or move tags itself.

## Assets and builds

There is one `wok-VERSION-TARGET.tar.gz` archive per target. Every executable is
named `wok` and uses RocksDB; no backend feature or alternate LMDB asset is built.
`wok storage-backend` identifies the storage layout without opening a database.

Each archive includes `wok`, `BACKEND.json`, README/changelog/contributor/security
files, the license, the sample `wok.toml` and the complete `docs/` tree.
`BACKEND.json` records RocksDB identity, version, target, source commit and compiler;
its feature list is empty for ordinary release builds. `SHA256SUMS` covers all
published archives. Windows is not supported by Wok's Unix process/socket APIs.

Rust 1.88+, a C/C++ toolchain and libclang are required. On Debian/Ubuntu install
`g++ clang libclang-dev`. On macOS use Xcode's command-line tools and LLVM;
set `LIBCLANG_PATH` to LLVM's `lib` directory if bindings cannot locate it.
Native compilation is substantial; CI limits build jobs to two and test
concurrency separately. LMDB is vendored only for read-only source imports.
Prebuilt Linux binaries still need the host's C/C++ runtime (`libstdc++6` on
Debian/Ubuntu); libclang is needed only to build from source.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --release --locked -p wok-cli
target/release/wok storage-backend
```

The pinned C++ differential job verifies direct strfry migration and event
identity. Runtime tests cover the RocksDB format, author frontiers, queries,
transport behavior, backups, full-state Wok LMDB conversion and crash recovery.
Passing these checks is not proof of equal durability under storage power loss.

## Reliability canary

A three-minute Linux canary runs on relevant changes; weekly/manual runs use a
one-hour soak. It checks acknowledged bodies, a 500-author feed during appends
to queried authors, live delivery, graceful restart and forced process death.
Review complete correctness/resource artifacts for the candidate, rather than
using a shared-runner throughput number as a release threshold.

```sh
cargo build --release --locked -p wok-cli
cargo build --release --locked -p wok-compat --example reliability_soak
python3 scripts/reliability-soak.py \
  --wok target/release/wok \
  --driver target/release/examples/reliability_soak \
  --seconds 3600 --seed 4242 --out /tmp/wok-soak-run-1
```

Choose a new output directory each time. Logs, failed databases and resource
samples remain retained. The runner verifies storage identity, samples native
WAL/SST files and performs full offline audits after stops. See
[reliability.md](reliability.md) for workload and evidence limits.

Never reuse or move a published tag. Corrections require a new version and
changelog entry. Existing Wok LMDB operators must use the explicit
[offline migration](migration-to-rocksdb.md); changing the executable alone
cannot convert their database.
