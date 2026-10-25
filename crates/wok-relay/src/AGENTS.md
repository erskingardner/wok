# wok-relay/src

| File | Role |
| --- | --- |
| `lib.rs` | Crate root and re-exports |
| `server.rs` | Process wiring, transport lifecycle, ingest, req, monitor; `RelayHandle` |
| `server/writer.rs` | Publication batches, management, maintenance and the background tag-kind index build on the single writer |
| `server/negentropy.rs` | Visibility-safe sync sessions and shared memory reservations |
| `protocol.rs` | `ClientCommand` / `RelayMessage` (EVENT/REQ/CLOSE/COUNT/AUTH/NEG-*) |
| `config.rs` | Native TOML `Config` plus strfry HOCON translation for migrate |
| `config/` | Presets, `wok config show` provenance, in-place file edits (`edit.rs`), replaced defaults (`history.rs`), deprecated keys (`legacy.rs`) and the CIDR ranges of `relay.trusted_proxies` (`ip_range.rs`) |
| `capabilities.rs` | NIP-11 capability catalog and `supported_nips` |
| `moderation.rs` | NIP-86 commands, management levels, write-permission decisions |
| `abuse.rs` | Per-IP / per-pubkey token buckets, query cost, PoW bits |
| `restrict.rs` | Read classes: who may read each kind (recipient-only, owner-only, authenticated) |
| `plugin.rs` | Write-policy child process (JSONL stdin/stdout, timeout) |
| `metrics.rs` | Counters, `wok_refusals_total` by `Setting` (config key), and bounded in-process chart history |
| `rlimit.rs` | `relay.nofiles` (`unsafe` isolated here) |

`start()` in `server.rs` is the entry the CLI uses for `wok relay`. Config hot-reload and graceful shutdown (SIGUSR1/SIGINT) are handled at this layer.
