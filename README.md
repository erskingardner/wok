# wok

Rust reimplementation of the [strfry](https://github.com/hoytech/strfry) Nostr relay.

Reference C++ commit: `9acdaeb1f63919184ece5f2dd67af21f1ed62f1b`  
NIPs pin used by the conformance suite: `656cecc7c0a815b6a2b218d3b5d6f078b3f4dbab`

## Build

```bash
cargo build --release -p wok-cli
```

The binary is `target/release/wok`.

## Run a relay

```bash
cp docs/wok.conf ./strfry.conf   # or reuse an existing strfry.conf
# Point db= at a *copy* of a v3 database, never a production file during tests.
./target/release/wok --config strfry.conf relay
```

Unix socket (disabled by default):

```
relay {
    unix {
        enabled = true
        path = "./strfry-db/wok.sock"
        mode = 384   # 0o600
    }
}
```

## Developer gates

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test -p wok-compat --test nip_conformance --test e2e_transports
# Optional C++ differential (requires /Users/jeff/code/strfry/strfry):
cargo test -p wok-db --test cpp_roundtrip
cargo test -p wok-compat --test cpp_export
```

Fuzz/property tests live next to the units (`proptest` in `wok-query`). Long fuzz campaigns are manual.

## Benchmarks

```bash
cargo build --release -p wok-cli -p wok-bench
./target/release/wok-bench --profile smoke --out bench-results \
  --strfry /Users/jeff/code/strfry/strfry \
  --wok ./target/release/wok
```

See `docs/benchmarks.md`.

## Final report

[Definition-of-done report](docs/FINAL.md)


## Documentation

- [Architecture](docs/architecture.md)
- [LMDB v3 contract](docs/lmdb-v3.md)
- [Unix socket protocol](docs/unix-socket.md)
- [Supported NIPs](docs/nips.md)
- [Configuration](docs/config.md)
- [Cutover / rollback](docs/cutover.md)
- [Security](docs/security.md)
- [Known differences](docs/known-differences.md)
