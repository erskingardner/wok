# Security notes

- Treat every EVENT as untrusted. IDs and Schnorr signatures are verified unless `--no-verify` import is explicitly used.
- Input limits: `max_event_size`, tag counts, WebSocket/Unix frame sizes, and
  `max_pending_outbound_bytes`.
- Unix sockets: restrictive mode before accept; refuse to unlink non-sockets; optional UID/GID allow-lists via peer credentials.
- AUTH (NIP-42) requires `relay.auth.serviceUrl`. Protected events (NIP-70) are rejected without matching authenticated pubkey.
- Restricted read kinds (default 4, 1059) are not delivered unless the subscriber is the author or first `p` tag.
- Write-policy plugins run as `sh -c` with a timeout; plugin failure rejects the event.
- `wok reindex` requires the explicit `--confirm-relay-stopped` acknowledgement.
  Stop the relay and all DB utilities first; promotion retains the original
  database as a sibling backup rather than modifying it in place.
- Do not expose the Unix socket on a shared host without UID/GID policy and `0600` mode.
