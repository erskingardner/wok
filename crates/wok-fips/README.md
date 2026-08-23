# wok-fips

> [!CAUTION]
> **The Wok native FIPS adapter is very experimental and is not
> production-ready.** The upstream API, Wok framing, configuration, and
> interoperability behavior may change incompatibly. Datagrams and relay
> responses can be lost.

`wok-fips` adapts `fips::native::client` flows to Wok's transport-neutral relay
dispatcher on Linux, FreeBSD, and macOS. It does not use the FIPS IPv6/TUN
shim.

The adapter is excluded from the default Wok binary. Build it explicitly with:

```sh
cargo build --release -p wok-cli --features native-fips
```

See [`../../docs/fips-native.md`](../../docs/fips-native.md) for the current
experimental protocol, limitations, and test procedures.
