# wok-fips

**Very experimental; not production-ready.** Native FIPS datagram transport
for Wok. The upstream API, Wok framing, configuration, and interoperability
behavior may change incompatibly, and delivery is unreliable. Do not weaken or
remove warnings and do not make stability or production-readiness claims.

The platform implementation supports Linux, FreeBSD, and macOS and consumes
`fips::native::client`; it must never use the FIPS IPv6/TUN shim or reimplement
the native API setup protocol.

Keep descriptors nonblocking under Tokio `AsyncFd`. `Ok(0)` is an empty
datagram, `EPIPE` means the daemon disappeared, and dropping the sole stream
owner is the only flow close. FIPS node identity is transport metadata only and
must never satisfy NIP-42.
