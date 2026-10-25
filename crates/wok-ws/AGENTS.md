# wok-ws

HTTP + WebSocket transport. In-house RFC 6455 + RFC 7692 codec so the server can offer permessage-deflate (no Rust WS library does). `#![forbid(unsafe_code)]`.

Plain HTTP serves NIP-11 (`Accept: application/nostr+json`), the landing page and `/admin`, plus NodeInfo when `relay.nodeinfo_enabled` is set, and `/metrics` when `observability.metrics_enabled` is set and `observability.metrics_listen` is not (`serve_metrics` serves it there otherwise). WebSocket upgrades share `RelayHandle` with Unix.

## Layout

- `Cargo.toml`
- `build.rs` — embeds `WOK_GIT_HASH` for NIP-11 / landing footer
- `src/` — listener, dispatch, client address header, frame codec, admin API
- `tests/` — frame and client address header property tests

Nagle is disabled (`TCP_NODELAY`) on accepted streams. Outbound is bounded by pending bytes, not message count. Mesh *client* links in the CLI still use tungstenite and do not speak deflate.

Per-connection costs are kept low for many idle connections: compression state is created on first use and dropped after 30–60 s without traffic (the inflater keeps the client's 32 KiB history for context takeover), the read buffer shrinks back to 1 KiB between messages, and outbound frames already queued are coalesced into one write of up to about 16 KiB. `wok-bench --scenario ws_transport` measures all of it.
