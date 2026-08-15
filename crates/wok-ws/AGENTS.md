# wok-ws

HTTP + WebSocket transport. In-house RFC 6455 + RFC 7692 codec so the server can offer permessage-deflate (no Rust WS library does). `#![forbid(unsafe_code)]`.

Plain HTTP serves NIP-11 (`Accept: application/nostr+json`), the landing page, `/metrics`, nodeinfo, and `/admin`. WebSocket upgrades share `RelayHandle` with Unix.

## Layout

- `Cargo.toml`
- `build.rs` — embeds `WOK_GIT_HASH` for NIP-11 / landing footer
- `src/` — listener, dispatch, frame codec, admin API
- `tests/` — frame property tests

Nagle is disabled (`TCP_NODELAY`) on accepted streams. Outbound is bounded by pending bytes, not message count. Mesh *client* links in the CLI still use tungstenite and do not speak deflate.
