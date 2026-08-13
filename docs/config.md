# Configuration

HOCON-subset parser (nested or inline `{ }`, `key = value`, `#` and `//` comments, quoted strings with escapes). Compatible with strfry.conf keys plus `relay.unix`. The reference `strfry.conf` parses unchanged.

Copy `docs/wok.conf` and edit. Defaults match golpe/strfry where possible. Unknown values for known keys (bad integers, out-of-range ports, non-bools) are hard errors, like golpe.

Unix-only keys:

| key | default | meaning |
|---|---|---|
| `relay.unix.enabled` | false | listen on a Unix socket |
| `relay.unix.path` | `./strfry-db/wok.sock` | socket path |
| `relay.unix.mode` | 384 (`0o600`) | permission bits; octal (`0600`/`0o600`) or decimal |
| `relay.unix.owner` | empty | chown socket user after bind |
| `relay.unix.group` | empty | chown socket group after bind |
| `relay.unix.authUids` | empty | comma-separated UIDs; empty = any |
| `relay.unix.authGids` | empty | comma-separated GIDs; empty = any |
| `relay.unix.maxFrameBytes` | 131072 | max JSON frame |
| `relay.unix.maxPendingOutboundBytes` | 33554432 | slow-client byte cap, then disconnect |

Reload: the relay watches the config file and live-reloads everything except the frozen keys (db, dbParams.*, bind, port, unix.*, pool sizes, nofiles, and per-connection socket options), like golpe's noReload set. See known-differences.
