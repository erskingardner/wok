# wok-unix/src

Single module: `lib.rs`.

| Item | Role |
| --- | --- |
| `bind_unix` | Safe bind/replace of the socket path |
| `serve` | Accept loop → `handle_conn` → `RelayHandle` |
| `write_frame` / `read_frame` | Length-prefixed IO |
| `connect` | Client helper |
| `peer_allowed` | Optional uid/gid allowlists (`SO_PEERCRED` / `getpeereid`) |

Refuses to replace symlinks or non-sockets. Shutdown unlinks only if the path still names this process's socket (dev/ino check). Tests for bind safety and framing are in `lib.rs` (`#[cfg(test)]`).
