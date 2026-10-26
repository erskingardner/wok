# Contributing to Wok

Thanks for helping. Wok is a Rust Nostr relay. It aims to be the most
spec-compliant and fastest relay it can be for real client traffic. These notes
cover building it, the rules the code follows, and what a pull request needs.

Security problems go through [SECURITY.md](SECURITY.md), not public issues.

## Getting set up

`rust-toolchain.toml` pins the stable toolchain used for local builds and CI.
`rustup` picks it up automatically. The minimum supported Rust version is
1.85, and CI checks it separately, so don't use language or library features
newer than that.

```bash
cargo build --release -p wok-cli          # binary: target/release/wok
./target/release/wok relay -c docs/wok.toml
```

`docs/wok.toml` is the annotated sample configuration, and
[docs/config.md](docs/config.md) explains every setting.

## Checks to run before a pull request

CI runs these on every pull request; run them locally first:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo test -p wok-compat --test nip_conformance --test e2e_transports
```

Some tests compare Wok with strfry. They need a strfry binary in `STRFRY_BIN`:

```bash
cargo test -p wok-db --test cpp_roundtrip
cargo test -p wok-compat --test cpp_export --test cpp_negentropy
```

Other CI jobs:
- strfry migration compatibility
- the MSRV build
- `cargo-deny` (advisories, licenses, sources)
- distribution-platform builds
- a short Linux soak
- an AddressSanitizer fuzz run
- the attack-surface reachability check (`scripts/attack-surface-reach.py --check`)

To fuzz locally, you need nightly and `cargo-fuzz`:

```bash
python3 fuzz/seed-corpus.py
cargo +nightly fuzz run ingress
```

## Where things live

[AGENTS.md](AGENTS.md) has the crate map, and each crate has its own `AGENTS.md`
describing its modules. The short version:

| Crate | Role |
|---|---|
| `wok-event` | Event JSON, NIP-01 hashing, signatures, packed events |
| `wok-db` | LMDB storage, indexes, migration from strfry, integrity |
| `wok-query` | Filters, scans, query scheduling, live subscriptions |
| `wok-negentropy` | NIP-77 sync |
| `wok-relay` | Transport-neutral relay core, AUTH, config |
| `wok-ws` / `wok-unix` | WebSocket and Unix socket transports |
| `wok-cli` | The `wok` binary |
| `wok-bench` / `wok-compat` | Benchmark harness; conformance and end-to-end tests |

Change behavior in the crate that owns it rather than special-casing it in the
CLI or tests.

## Rules the code follows

- Tokio owns network I/O only. LMDB transactions, cursors and mmap slices never
  cross an `.await`. Copy data out before awaiting.
- Inside the relay, one writer thread performs every database mutation.
  Other `wok` commands that change the database, such as `import`, `delete`,
  `purge-superseded` and `negentropy build`, write from their own process,
  and LMDB runs only one write transaction at a time across processes.
  `reindex` needs the relay and every other writer stopped.
- Hashing and stored JSON go through `wok_event::json`, not stock `serde_json`.
  Event identity (id, signature, tags, content, stored payload) must survive
  migration unchanged.
- Safe crates are `#![forbid(unsafe_code)]`. FFI is confined to the documented
  LMDB and OS boundaries.
- Advertise a NIP in NIP-11 only when the relay implements observable behavior
  for it and has conformance tests for it.

When protocol behavior is in question, the order of authority is:
1. the pinned NIPs (see [docs/nips.md](docs/nips.md));
2. Wok's own documented decisions in `docs/`;
3. lossless migration;
4. strfry's behavior.

strfry is a reference point, not a spec. Correcting an inherited strfry quirk
is welcome, as long as it comes with a test and an entry in
[docs/known-differences.md](docs/known-differences.md).

## What a pull request needs

- **Tests.** A bug fix needs a regression test that fails without the fix.
  Protocol behavior is tested end to end in `crates/wok-compat/tests`. Other
  tests live in the owning crate.
- **Docs, in the same change**, when behavior changes:

  | What changed | Update |
  |---|---|
  | A NIP | [docs/nips.md](docs/nips.md) and the capabilities catalog |
  | A difference from strfry | [docs/known-differences.md](docs/known-differences.md) |
  | A config key | [docs/config.md](docs/config.md), plus [docs/wok.toml](docs/wok.toml) if most operators must set it |
  | A default | `Preset changes` in [CHANGELOG.md](CHANGELOG.md), and the old value in `PAST_DEFAULTS` (`crates/wok-relay/src/config/history.rs`) so `wok doctor` can flag files that pin it |
  | Something operators will notice | The `Unreleased` section of [CHANGELOG.md](CHANGELOG.md) |

- **Commits.** Use the form `type(scope): summary`, for example
  `fix(relay,ws): …` or `test(compat): …`.
  - Common types: `fix`, `feat`, `test`, `docs`, `bench`.
  - The scope is the short crate name, or several separated by commas.
  - Keep each commit to one logical change.
- **The description.** Say what problem the change solves and how it fixes it.
  Put benchmark results, audit findings and design discussion in the PR or an
  issue, not in `docs/`.

## Documentation

`docs/` is for people running or building on Wok. It covers architecture,
configuration, operations, security, protocol support, and how to run and read
benchmarks. It does not hold plans, proposals, audits, or dated benchmark and
soak run reports; see [docs/AGENTS.md](docs/AGENTS.md). Code is the authority
for current behavior, so keep docs accurate when you change it.

## Releases

Maintainers cut releases as described in [docs/releases.md](docs/releases.md).

## License

Wok is licensed under AGPL-3.0-or-later. By contributing, you agree that your
contributions are licensed under the same terms.
