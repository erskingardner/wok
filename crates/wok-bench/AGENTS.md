# wok-bench

Comparative load harness: Wok vs strfry, correctness before speed. Correctness tests run in normal CI (`cargo test --workspace`); comparative load campaigns run separately. `#![forbid(unsafe_code)]`.

Never opens a user database. Each trial uses a disposable temp dir, a deterministic signed corpus, warm-up, and latency histograms. A trial that drops events or deliveries is `ok=false`.

## Layout

- `Cargo.toml`
- `src/main.rs` — harness, profiles, scenarios, JSONL + markdown output
- `src/clients.rs` — `--scenario clients`: client-realistic load with abuse controls and AUTH on (outbox and MDK-shaped Marmot clients, refusal counts, oracle checks)
- `src/transport.rs` — `--scenario ws_transport`: what WebSocket connections cost the relay (RSS per connection, bursts, fan-out, churn, deflate levels), with and without permessage-deflate
- `src/live.rs` — `--scenario monitor_index` (the req monitor's index in process) and `--scenario live_subscriptions` (fan-out latency under REQ/CLOSE churn and a reconnect storm, deliveries checked against an independent matcher)

Methodology: `docs/benchmarks.md`. Campaign wrappers: `scripts/benchmark-*.sh`. Do not treat `bench-results/` at the repo root as source.
