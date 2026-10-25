# fuzz/

Separate cargo-fuzz workspace (`wok-fuzz`), not a member of the root workspace. Exercises untrusted ingress: JSON/events, client address headers (RFC 7239 `Forwarded` and address lists), WebSocket frames/compression (with and without context takeover, and the takeover history replayed after an idle release), Negentropy, and related parse paths.

## Layout

| Path | Role |
| --- | --- |
| `Cargo.toml` | Fuzz package; depends on path crates |
| `fuzz_targets/` | libFuzzer targets |
| `corpus/` | Seed inputs (generated locally; gitignored as needed) |
| `artifacts/` | Crash artifacts from runs |
| `target/` | Fuzz build output |

Do not add this package to the root workspace. Scheduled AddressSanitizer runs: `.github/workflows/fuzz.yml`. Background: `docs/security.md`.
