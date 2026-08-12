# Configuration

HOCON-subset parser (nested `{ }`, `key = value`, `#` comments). Compatible with strfry.conf keys plus `relay.unix`.

Copy `docs/wok.conf` and edit. Defaults match golpe/strfry where possible.

Unix-only keys:

| key | default | meaning |
|---|---|---|
| `relay.unix.enabled` | false | listen on a Unix socket |
| `relay.unix.path` | `./strfry-db/wok.sock` | socket path |
| `relay.unix.mode` | 384 (`0o600`) | permission bits |
| `relay.unix.authUids` | empty | comma-separated UIDs; empty = any |
| `relay.unix.authGids` | empty | comma-separated GIDs; empty = any |
| `relay.unix.maxFrameBytes` | 131072 | max JSON frame |

Reload: send the process a new config by restarting. File-watch hot reload is not yet wired; C++ watches the config file. See known-differences.
