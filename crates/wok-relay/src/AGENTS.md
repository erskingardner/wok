# wok-relay/src

| File | Role |
| --- | --- |
| `lib.rs` | Crate root and re-exports |
| `server.rs` | Process: ingest, writer, req, monitor, negentropy, cron; `RelayHandle` |
| `protocol.rs` | `ClientCommand` / `RelayMessage` (EVENT/REQ/CLOSE/COUNT/AUTH/NEG-*) |
| `config.rs` | Native TOML `Config` plus strfry HOCON translation for migrate |
| `capabilities.rs` | NIP-11 capability catalog and `supported_nips` |
| `abuse.rs` | Per-IP / per-pubkey token buckets, query cost, PoW bits |
| `restrict.rs` | Restricted-kind / involved-pubkey read policy |
| `plugin.rs` | Write-policy child process (JSONL stdin/stdout, timeout) |
| `metrics.rs` | Counters + bounded in-process chart history |
| `rlimit.rs` | `relay.nofiles` (`unsafe` isolated here) |

`start()` in `server.rs` is the entry the CLI uses for `wok relay`. Config hot-reload and graceful shutdown (SIGUSR1/SIGINT) are handled at this layer.
