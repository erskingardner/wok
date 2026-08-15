# wok-ws/tests

| File | Role |
| --- | --- |
| `frame_prop.rs` | Frame parse/encode and deflate properties |

Landing-page and TCP_NODELAY tests live in `src/lib.rs` (`#[cfg(test)]`). Transport e2e and deflate against real clients: `crates/wok-compat/tests/e2e_transports.rs`, `ws_deflate.rs`.
