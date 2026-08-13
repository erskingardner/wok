# Supported NIPs

Conformance suite pins nostr-protocol/nips at `656cecc7c0a815b6a2b218d3b5d6f078b3f4dbab`.

Only NIPs for which Wok implements observable **relay behavior** and has
conformance coverage are advertised in NIP-11. The authoritative typed catalog
is `wok-relay/src/capabilities.rs`; configuration cannot replace it with an
arbitrary list.

| NIP | Name | Code | Tests | Advertised when |
|---|---|---|---|---|
| 01 | Basic protocol | `wok-event`, `wok-relay`, `wok-query` | `nip_conformance.rs`, `e2e_transports.rs` | always |
| 09 | Event deletion | `wok-db` write kind 5 | db write tests | always |
| 11 | Relay information | `wok-ws` | `nip_conformance.rs` | always |
| 13 | Proof of work | leading-zero validation + NIP-11 minimum | relay tests | `relay.abuse.enabled` and `min_pow_difficulty > 0` |
| 40 | Expiration | packed expiration + cron | `nip_conformance.rs` | always |
| 42 | AUTH | ingest AUTH | unit + e2e when serviceUrl set | AUTH enabled and serviceUrl set |
| 45 | COUNT | REQ worker | `nip_conformance.rs` | `maxFilterLimitCount > 0` |
| 50 | Search capability | transactional LMDB term/bigram index + ranked query scanner | `nip_conformance.rs`, `search.rs`, `e2e_transports.rs` | always |
| 59 | Gift wrap | recipient-only restricted reads, recipient-authorized deletion, and live-only kind 21059 | restrict + DB/live tests | usable AUTH, restricted kind 1059 with involved-pubkey enforcement, and `events.ephemeral_persistence = "live_only"` |
| 62 | Request to Vanish | persistent maximum-timestamp markers, immediate query/rebroadcast suppression, gift-wrap recipient cleanup, and bounded physical deletion | `nip62_vanish.rs`, relay e2e | `relay.nip62.enabled` |
| 70 | Protected events | `-` tag + AUTH | `nip_conformance.rs` | always |
| 77 | Negentropy | `wok-negentropy` | protocol unit tests | `negentropy.enabled` |

NIP-02, NIP-04, and NIP-28 event kinds are accepted and stored, but those
client/application semantics are deliberately not advertised as relay
capabilities.

ID and author filter values must be exactly 64 lowercase hexadecimal
characters, as required by current NIP-01. Prefix filters are rejected.

NIP-50 matches normalized search terms against event `content`, intersects
them with every other supplied filter field, ranks before applying `limit`,
and supports matching live events after EOSE. See
[NIP-50 search](nip50-search.md) for exact query and scoring semantics.

NIP-62 accepts a signed kind 62 request containing either a matching
`["relay", "<public relay URL>"]` tag or `["relay", "ALL_RELAYS"]`. The
relay immediately suppresses qualifying authored events and gift wraps for the
requesting recipient, prevents rebroadcast, then physically deletes them in
bounded background batches. The request itself remains stored and cannot be
deleted with kind 5. See `relay.nip62` in the sample configuration.
