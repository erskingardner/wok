# Known differences vs C++ strfry `9acdaeb1f63919184ece5f2dd67af21f1ed62f1b`

- **Unix socket** is a wok-only transport.
- **ID/author filters** are exact 32 bytes (same as C++). Not NIP-01 prefixes.
- **Historical restricted-kind REQ filtering** uses PackedEvent from the Event table. C++ `RelayReqWorker` currently builds `PackedEventView` from EventPayload bytes (JSON). wok follows the monitor path / AUTH intent. See PLAN.md.
- **WebSocket permessage-deflate**: tungstenite 0.26 in this tree has no deflate feature. C++ uWS supports it. Documented; not advertised as a NIP.
- **Config hot-reload** via file watch is not wired; restart to apply config.
- **dict train/compress** CLI: wok reads zstd dictionary payloads; training still uses C++ strfry or a future libzdict bind.
- **router** is a compatibility stub; use `stream` / `sync`.
- **NIP-11 software** string is wok's URL, not `git+https://github.com/hoytech/strfry.git`.
- Ingester/req/monitor/negentropy thread counts from config are accepted but this build runs one thread per pool (still a single writer).

When C++ and a NIP disagree, wok preserves C++ compatibility for storage and filter matching, documents the gap, and does not advertise unsupported behavior.
