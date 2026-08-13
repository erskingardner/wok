# Known differences vs C++ strfry `9acdaeb1f63919184ece5f2dd67af21f1ed62f1b`

## wok extensions

- **Unix socket** is a wok-only transport (disabled by default). Write-policy
  plugins see `sourceType: "unix"` for these connections.
- `wok event <levId>` prints one event by local event ID (C++ has no such
  command); `--fried` matches `strfry export --fried` output.

## Intentional deviations (deliberate, reviewed)

- **Restricted-read auth gating is stricter than C++ at this commit.** wok
  requires a *completed* NIP-42 auth before a fully-restricted REQ/NEG-OPEN;
  C++ only requires that an auth session exists. wok also dispatches
  `SetAuth` to the negentropy worker (C++ defines the message but never
  dispatches it, so authed restricted sync is impossible upstream) and sends
  at most one AUTH challenge per session vacancy (C++ re-sends a fresh,
  unstored challenge on each restricted REQ, which can never succeed). These
  read as upstream warts around the just-merged PR #250; wok implements the
  intended behavior.
- **Historical restricted-kind REQ filtering** uses PackedEvent from the
  Event table. C++ `RelayReqWorker` currently builds `PackedEventView` from
  EventPayload bytes (JSON). wok follows the monitor path / AUTH intent. See
  PLAN.md.
- **JSON nesting is capped at 128 levels** (same as serde_json's default).
  C++ tao has no built-in limit. Inputs beyond the cap are rejected.
- **LMDB comparators abort the process on malformed keys** (C++ throws a
  catchable exception). Only reachable with a corrupt/foreign database.
- **`wok export`/`wok info` refuse non-v3 databases.** C++ permits `export`
  and `info` on older DB versions to support migration; wok only implements
  the v3 layout, so migrate via the C++ binary first.
- **`wok` creates the DB directory if missing**; C++ requires it to exist.
- **ID/author filters** are exact 32 bytes (same as C++). Not NIP-01 prefixes.

## Deliberate C++ bug-compatibility kept

- Stored event JSON, id-hash preimage, and all index bytes match tao::json
  output exactly: duplicate object keys rejected, U+007F escaped as ``,
  ryu f64 formatting (`1e300`, `1000.0`, decimal for -6 < exp < 22).
- `from_hex` strips a `0x` prefix and pads odd-length input where C++ does;
  event ids/pubkeys/sigs/e/p tag values and filter byte sets use the strict
  even-length form like C++.
- The expiration tag accepts only all-digit values (C++ `parseUint64`);
  a-tag kinds follow `std::stoull` (leading whitespace/sign).
- Ephemeral events are stored with `expiration = 1` and purged by cron after
  `ephemeralEventsLifetimeSeconds`, exactly like C++ (they are not simply
  dropped at ingest).
- CLOSED messages carry C++'s non-NIP-compliant `ERROR: auth-required: ...`
  prefix where C++ emits it.

## Not yet implemented (documented gaps)

- **WebSocket permessage-deflate**: C++ enables it by default; wok never
  negotiates it (tungstenite 0.26 in this tree has no deflate feature).
  Interop-safe but a bandwidth divergence; the `compression.*` config keys
  parse but have no effect.
- **Config hot-reload** via file watch is not wired; restart to apply config.
- **Graceful shutdown drain** (C++ SIGUSR1 + stopListening) is not
  implemented; shutdown aborts listeners.
- **Worker pools run one thread per stage** (ingester/req-worker/req-monitor/
  negentropy) plus the single LMDB writer; `numThreads.*` is parsed but the
  pools are not scaled out. The sole-writer invariant is preserved.
- **`nofiles`** rlimit is parsed but not applied (no setrlimit call).
- **`dict train/compress/decompress`** are stubs; wok reads zstd-dictionary
  payloads, training uses C++ strfry.
- **`router`** is a compatibility stub. **`stream`** prints received events
  but does not persist them and has no up direction; **`sync`** is
  initiator-only and does not persist results.
- **NIP-11 software** string is wok's URL, not
  `git+https://github.com/hoytech/strfry.git`.

When C++ and a NIP disagree, wok preserves C++ compatibility for storage and
filter matching, documents the gap, and does not advertise unsupported
behavior.
