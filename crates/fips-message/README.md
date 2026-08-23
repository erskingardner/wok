# fips-message

> [!CAUTION]
> **This crate and its wire format are very experimental.** They are not
> production-ready and provide no backward-compatibility guarantee. The frame
> format, limits, handshake, and lifecycle may change incompatibly while native
> FIPS interoperability is being developed.

`fips-message` is Wok-independent framing and bounded reassembly for logical
messages carried over unreliable FIPS datagrams. It deliberately does not
provide delivery acknowledgement or retransmission, and it does not make FIPS
DATA reliable.

The current wire format is documented in
[`../../docs/fips-message-v1.md`](../../docs/fips-message-v1.md). The `V1` name
identifies the current experimental format; it is not a stability promise.
