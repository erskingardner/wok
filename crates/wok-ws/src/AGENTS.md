# wok-ws/src

| File | Role |
| --- | --- |
| `lib.rs` | TCP listener, HTTP dispatch (relay on `/` only), WS upgrade, NIP-11, landing HTML |
| `forwarded.rs` | The client address in `relay.real_ip_header`: an address list's last entry, or RFC 7239 `Forwarded`'s last `for`, skipping `relay.trusted_proxies` from the end (`pub mod forwarded`, for the fuzz target) |
| `frame.rs` | RFC 6455 frames + RFC 7692 inflate/deflate (`pub mod frame`) |
| `admin.rs` | `/admin` UI and `/admin/api/*` (NIP-98-style signed auth) |
| `nip86.rs` | NIP-86 management RPC on `POST /` (shares admin NIP-98 auth) |
| `review_regressions.rs`, `transport_tests.rs` | In-crate connection tests (`#[cfg(test)]`, driven through `handle_ws`) |

`serve` / `serve_listener` are the public entry points. Connection admission uses the relay abuse budget for both WS upgrades and plain HTTP (including admin). `relay.realIpHeader` rewrites peer IP behind a reverse proxy.

Deflate negotiation mirrors uWS as strfry configures it: respond `permessage-deflate`, echo `client_no_context_takeover`, sliding-window takeover from config. The sliding window governs only the relay's compressor; the inflater keeps context unless the client agreed to `client_no_context_takeover`. Compression level 1, as uWS uses.
