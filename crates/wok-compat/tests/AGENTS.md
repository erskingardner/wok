# wok-compat/tests

| File | Role |
| --- | --- |
| `nip_conformance.rs` | Advertised NIP relay behavior vs pinned specs |
| `e2e_transports.rs` | WebSocket + Unix end-to-end |
| `ws_deflate.rs` | permessage-deflate negotiation/frames |
| `ws_timeouts.rs` | Handshake/frame-read/pong liveness timeouts |
| `negentropy_e2e.rs` | NEG-* sessions against a live relay |
| `plugin_e2e.rs` | Write-policy plugin child process |
| `error_routing.rs` | CLOSED/NOTICE/OK error paths |
| `db_watch.rs` | Config/DB watch / hot-reload related |
| `non_ascii_event_id.rs` | Non-ASCII / invalid id handling |
| `cpp_export.rs` | Optional strfry export differential |
| `cpp_negentropy.rs` | Optional strfry negentropy differential |

Prefer adding NIP coverage here (and updating `docs/nips.md` + `wok-relay` capabilities) rather than only crate-local tests.
