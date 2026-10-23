# wok-compat/tests

| File | Role |
| --- | --- |
| `nip_conformance.rs` | Advertised NIP relay behavior vs pinned specs |
| `lifecycle_model.rs` | Generated real-transport privacy/lifecycle model and in-flight revocation |
| `support/wire.rs` | Shared framed Unix / WebSocket test and soak client |
| `e2e_transports.rs` | WebSocket + Unix end-to-end |
| `query_cost.rs` | Query-cost gate at the default ceiling: client filters served, fan-outs refused as REQ, COUNT and NEG-OPEN |
| `rate_keying.rs` | What each rate budget is keyed on: per-connection budgets under an address backstop, the AUTH multiplier, NEG-MSG's own bucket, IPv6 networks, and throwaway-key events charged to the AUTHed identity |
| `req_lifecycle.rs` | Live-before-history REQs: no loss, exactly once, replacement, cap, COUNT ids |
| `eose_latency.rs` | Ignored benchmark: REQ→EOSE latency under monitor fan-out |
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
