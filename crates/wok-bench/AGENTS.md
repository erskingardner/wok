# wok-bench

Comparative load harness: Wok vs strfry, correctness before speed. Correctness tests run in normal CI (`cargo test --workspace`); comparative load campaigns run separately. `#![forbid(unsafe_code)]`.

Never opens a user database. Each trial uses a disposable temp dir, a deterministic signed corpus, warm-up, and latency histograms. A trial that drops events or deliveries is `ok=false`.

## Layout

- `Cargo.toml`
- `src/main.rs` — harness, profiles, scenarios, JSONL + markdown output
- `src/clients.rs` — `--scenario clients`: client-realistic load with abuse controls and AUTH on (outbox and MDK-shaped Marmot clients, refusal counts, oracle checks)
- `src/transport.rs` — `--scenario ws_transport`: what WebSocket connections cost the relay (RSS per connection, bursts, fan-out, churn, deflate levels), with and without permessage-deflate
- `src/author_kinds.rs` — `--scenario author_kinds`: `authors` × `kinds` planner sweep on a large, kept dataset, optionally against a second wok binary
- `src/tag_kinds.rs` — `--scenario tag_kinds`: `#p`/`#e` + `kinds` fetches (notifications, zaps, DM inbox, reactions) on a kept dataset with heavily tagged pubkeys and notes, with the events a Tag-index plan reads counted from the dataset's index
- `src/social.rs` — `--event-mix social`: a public social relay's history at campaign scale (Zipf authors, replacements and deletions, real sizes), streamed to disk and signed in parallel, with the count a relay keeps in the manifest
- `src/live.rs` — `--scenario monitor_index` (the req monitor's index in process) and `--scenario live_subscriptions` (fan-out latency under REQ/CLOSE churn and a reconnect storm, deliveries checked against an independent matcher)

Methodology: `docs/benchmarks.md`. Campaign wrappers: `scripts/benchmark-*.sh`. Do not treat `bench-results/` at the repo root as source.
