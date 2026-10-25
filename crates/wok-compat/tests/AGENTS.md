# wok-compat/tests

| File | Role |
| --- | --- |
| `nip_conformance.rs` | Advertised NIP relay behavior vs pinned specs |
| `lifecycle_model.rs` | Generated real-transport privacy/lifecycle model and in-flight revocation |
| `support/wire.rs` | Shared framed Unix / WebSocket test and soak client |
| `e2e_transports.rs` | WebSocket + Unix end-to-end |
| `access_model.rs` | Read classes (recipient-only, owner-only, authenticated) and how 0.7's access keys translate |
| `filter_validation.rs` | `[relay.filter_validation]` on REQ, COUNT and NEG-OPEN, and `require_scoped_filters` against Marmot's filters |
| `marmot_preset.rs` | The `marmot` preset serving MDK's traffic shapes: anonymous 445s, AUTHed inbox reads, anonymous directory reads, NIP-77 per group, refused enumeration and kinds, an inviter's Welcome burst, and its AUTH requirement |
| `query_cost.rs` | Query-cost gate at the default ceiling: client filters served, fan-outs refused as REQ, COUNT and NEG-OPEN |
| `refusal_counts.rs` | `wok_refusals_total{setting}`: each refusal counted once, by the config key that made it, and none for NIP constants or NIP-86 decisions |
| `rate_keying.rs` | What each rate budget is keyed on: per-connection budgets under an address backstop, the AUTH multiplier, NEG-MSG's own bucket, IPv6 networks, and throwaway-key events charged to the AUTHed identity |
| `req_lifecycle.rs` | Live-before-history REQs: no loss, exactly once, replacement, cap, COUNT ids, scans queued over the concurrency cap |
| `eose_latency.rs` | Ignored benchmark: REQ→EOSE latency under monitor fan-out |
| `ws_deflate.rs` | permessage-deflate negotiation/frames |
| `ws_timeouts.rs` | Handshake/frame-read/pong liveness timeouts |
| `negentropy_e2e.rs` | NEG-* sessions against a live relay |
| `plugin_e2e.rs` | Write-policy plugin child process |
| `attack_surface.rs` | HTTP paths and message gates per profile, client verbs, and profiles vs `docs/attack-surface.md` |
| `profiles/` | Configuration profiles the attack-surface tests start relays from |
| `golden_transcripts.rs`, `transcripts/` | One fixed client script per profile, its answers saved; rewrite with `WOK_BLESS_TRANSCRIPTS=1` and review the diff |
| `reachability.rs`, `reachability/` | Ignored probe that `scripts/attack-surface-reach.py` runs under coverage, one phase per process; the baseline of relay functions each phase reaches per profile |
| `setting_combinations.rs` | Each security setting, alone and in pairs over `public`, sent the transcript script: no setting serves what another refuses, and each changes some answer beyond NIP-11 |
| `support/transcript.rs` | The golden transcript script and its normalized transcript |
| `support/surface.rs` | Profiles, a relay serving one, and raw HTTP and WebSocket clients for the attack-surface tests |
| `proxied_client_address.rs` | A client behind a proxy is the last `relay.real_ip_header` address, or `Forwarded`'s last `for`, or behind `relay.trusted_proxies` the last one outside them, so `blockip` holds; a connection from outside them is its own address; an unparsed entry falls back and is counted |
| `error_routing.rs` | CLOSED/NOTICE/OK error paths |
| `db_watch.rs` | Config/DB watch / hot-reload related |
| `non_ascii_event_id.rs` | Non-ASCII / invalid id handling |
| `cpp_export.rs` | Optional strfry export differential |
| `cpp_negentropy.rs` | Optional strfry negentropy differential |

Prefer adding NIP coverage here (and updating `docs/nips.md` + `wok-relay` capabilities) rather than only crate-local tests.
