# Supported NIPs

Conformance suite pins nostr-protocol/nips at `656cecc7c0a815b6a2b218d3b5d6f078b3f4dbab`.

Only NIPs that are implemented **and** covered by tests are advertised in NIP-11 (unless `relay.info.nips` overrides, which is not recommended).

| NIP | Name | Code | Tests | Advertised when |
|---|---|---|---|---|
| 01 | Basic protocol | `wok-event`, `wok-relay`, `wok-query` | `nip_conformance.rs`, `e2e_transports.rs` | always |
| 02 | Contact list (kind 3 replaceable) | `wok-event` kinds / `wok-db` replace | unit replaceable + db write | always |
| 04 | Encrypted DM kind 4 | restrictor default kinds | `restrict.rs` | always (storage/query; read may require AUTH) |
| 09 | Event deletion | `wok-db` write kind 5 | db write tests | always |
| 11 | Relay information | `wok-ws` | `nip_conformance.rs` | always |
| 28 | Public chat | kinds only | NIP-01 event tests | always |
| 40 | Expiration | packed expiration + cron | `nip_conformance.rs` | always |
| 42 | AUTH | ingest AUTH | unit + e2e when serviceUrl set | AUTH enabled and serviceUrl set |
| 45 | COUNT | REQ worker | `nip_conformance.rs` | `maxFilterLimitCount > 0` |
| 59 | Gift wrap deletion | `GIFT_WRAP_KINDS` in write | db write path | always |
| 70 | Protected events | `-` tag + AUTH | `nip_conformance.rs` | always |
| 77 | Negentropy | `wok-negentropy` | protocol unit tests | `negentropy.enabled` |

ID/author filters are **exact 32-byte** values (C++ `FilterSetBytes(..., 32, 32)`). Historical NIP-01 prefixes are not implemented.
