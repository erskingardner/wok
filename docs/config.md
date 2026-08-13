# Configuration

HOCON-subset parser (nested or inline `{ }`, `key = value`, `#` and `//` comments, quoted strings with escapes). Compatible with strfry.conf keys plus `relay.unix`. The reference `strfry.conf` parses unchanged.

Copy `docs/wok.conf` and edit. Defaults match golpe/strfry where possible. Unknown values for known keys (bad integers, out-of-range ports, non-bools) are hard errors, like golpe.

Unix-only keys:

| key | default | meaning |
|---|---|---|
| `relay.unix.enabled` | false | listen on a Unix socket |
| `relay.unix.path` | `./strfry-db/wok.sock` | socket path |
| `relay.unix.mode` | 384 (`0o600`) | permission bits; octal (`0600`/`0o600`) or decimal |
| `relay.unix.owner` | empty | parsed, not yet applied (no chown) |
| `relay.unix.group` | empty | parsed, not yet applied (no chown) |
| `relay.unix.authUids` | empty | comma-separated UIDs; empty = any |
| `relay.unix.authGids` | empty | comma-separated GIDs; empty = any |
| `relay.unix.maxFrameBytes` | 131072 | max JSON frame |
| `relay.unix.maxPendingOutboundBytes` | 33554432 | slow-client byte cap, then disconnect |

Reload: send the process a new config by restarting. File-watch hot reload is not yet wired; C++ watches the config file. See known-differences.
