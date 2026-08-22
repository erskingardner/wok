# fips-message

Transport-independent framing for logical messages over unreliable FIPS
datagrams. This crate deliberately has no Wok dependencies so clients can
extract or publish it separately.

The wire format is specified in `../../docs/fips-message-v1.md`. Keep byte-level
golden vectors synchronized with that document. Payloads remain opaque bytes;
UTF-8 and Nostr parsing belong at an adapter boundary.

