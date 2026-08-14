# Unix socket protocol

Wok extension. Disabled by default. Not a C++ strfry feature.

## Framing

`SOCK_STREAM`. Each message:

1. 4-byte unsigned big-endian payload length
2. UTF-8 JSON Nostr client or relay array (same as WebSocket text frames)

Multiple requests and asynchronous EVENT/EOSE/OK/COUNT/AUTH/NEG-* frames share one connection.

## Safety

- Never unlink a non-socket path.
- Before replacing a path, confirm it is a socket and that `connect()` fails (no live listener).
- Bind at a sibling temp path, apply the configured mode/ownership there, and
  atomically rename it into place before accept.
- Optional UID/GID allow-lists via `getpeereid`.
- On orderly shutdown, unlink only when the final pathname still has the
  filesystem device/inode recorded immediately before the atomic rename.
- Per-connection outbound byte cap (`relay.unix.max_pending_outbound_bytes`);
  slow clients are disconnected, like the WebSocket transport.
- No admin commands on this protocol.

Connections on this transport report `sourceType: "unix"` (with empty `sourceInfo`) to write-policy plugins.

## Client example (Python)

```python
import socket, struct, json
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("./wok-db/wok.sock")
def send(obj):
    b = json.dumps(obj).encode()
    s.sendall(struct.pack("!I", len(b)) + b)
def recv():
    hdr = s.recv(4)
    n = struct.unpack("!I", hdr)[0]
    return json.loads(s.recv(n))
send(["REQ", "s", {"kinds":[1], "limit": 1}])
print(recv())
```

## Config

See `docs/config.md` `relay.unix.*`.
