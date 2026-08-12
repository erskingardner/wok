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
- `chmod` to the configured mode after bind, before accept.
- Optional UID/GID allow-lists via `getpeereid`.
- Unlink the socket on orderly shutdown.
- No admin commands on this protocol.

## Client example (Python)

```python
import socket, struct, json
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("./strfry-db/wok.sock")
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
