# wok-compat/src

Helpers only: `lib.rs`.

| Item | Role |
| --- | --- |
| `strfry_bin` / `strfry_available` | Locate optional C++ binary |
| `sign_event` / `sign_event_with_key` | Deterministic-enough signed fixtures |
| `temp_db` / `write_event_to_env` | Disposable Wok LMDB + insert |
| `strfry_export` | Spawn strfry export for differentials |
| `nips_commit` | Pinned nostr-protocol/nips revision |

Keep this crate free of production logic. New shared test setup belongs here; new protocol assertions belong under `tests/`.
