# wok-unix

Wok-only Unix `SOCK_STREAM` transport. Same `RelayHandle` dispatcher as WebSocket. Disabled by default (`[relay.unix]` in config). `#![forbid(unsafe_code)]`.

Frame: 4-byte big-endian length + UTF-8 JSON Nostr message. Protocol details: `docs/unix-socket.md`.

## Layout

- `Cargo.toml`
- `src/lib.rs` — bind, serve, frame helpers, peer-cred auth (entire crate)

Not advertised as C++-compatible. Bind uses a sibling temp path, chmod/chown, then atomic rename so the final socket never exists with umask permissions.
