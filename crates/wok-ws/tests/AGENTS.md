# wok-ws/tests

| File | Role |
| --- | --- |
| `frame_prop.rs` | Frame parse/encode and deflate properties |
| `forwarded_prop.rs` | Client address header: the proxy's last entry decides, whatever the client sent ahead |

Landing-page and TCP_NODELAY tests live in `src/lib.rs` (`#[cfg(test)]`). Transport e2e and deflate against real clients: `crates/wok-compat/tests/e2e_transports.rs`, `ws_deflate.rs`.
