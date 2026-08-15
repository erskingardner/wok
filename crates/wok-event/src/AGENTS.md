# wok-event/src

Library modules. Public surface is re-exported from `lib.rs`.

| File | Role |
| --- | --- |
| `lib.rs` | Crate root, version/kind constants, re-exports |
| `json.rs` | tao-compatible `parse_strict` / `to_tao_string` |
| `parse.rs` | Hex helpers, `ParsedEvent`, `EventLimits`, JSON → PackedEvent |
| `validate.rs` | Size/timestamp/Schnorr checks; `parse_and_verify_event` |
| `hash.rs` | SHA-256 event id, `verify_id`, `verify_sig` |
| `packed.rs` | PackedEvent bytes, views, tag builder, ordering |
| `kinds.rs` | Replaceable / param-replaceable / ephemeral; `a` tags |
| `bech32.rs` | npub encode/decode |
| `error.rs` | `EventError` |

Start with `lib.rs` for constants (`AUTH_KIND`, `DELETION_KIND`, gift-wrap/repost kinds, `PROTECTED_TAG`). Change JSON encoding only if you intend to change event ids or stored payloads.
