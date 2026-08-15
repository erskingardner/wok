# wok-ws/src

| File | Role |
| --- | --- |
| `lib.rs` | TCP listener, HTTP dispatch, WS upgrade, NIP-11, landing HTML |
| `frame.rs` | RFC 6455 frames + RFC 7692 inflate/deflate (`pub mod frame`) |
| `admin.rs` | `/admin` UI and `/admin/api/*` (NIP-98-style signed auth) |

`serve` / `serve_listener` are the public entry points. Connection admission uses the relay abuse budget for both WS upgrades and plain HTTP (including admin). `relay.realIpHeader` rewrites peer IP behind a reverse proxy.

Deflate negotiation mirrors uWS as strfry configures it: respond `permessage-deflate`, echo `client_no_context_takeover`, sliding-window takeover from config.
