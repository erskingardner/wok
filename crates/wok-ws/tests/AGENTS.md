# wok-ws/tests

| File | Role |
| --- | --- |
| `frame_prop.rs` | Frame parse/encode and deflate properties |
| `forwarded_prop.rs` | Client address header: the proxies' entries decide, whatever the client sent ahead; a connection from outside `relay.trusted_proxies` is its own address |

Landing-page and TCP_NODELAY tests live in `src/lib.rs` (`#[cfg(test)]`). Transport e2e and deflate against real clients: `crates/wok-compat/tests/e2e_transports.rs`, `ws_deflate.rs`.
