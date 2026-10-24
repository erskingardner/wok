#!/usr/bin/env python3
"""Deterministic protocol-shaped seeds; retain previously discovered corpus files."""
import hashlib
import json
from pathlib import Path
import struct
import zlib

root = Path(__file__).resolve().parent / "corpus" / "ingress"
root.mkdir(parents=True, exist_ok=True)
seeds = [b"", b"\x61\x00", b"\xff" * 64]
for command in [
    ["REQ", "s", {}], ["COUNT", "s", {"kinds": [1]}],
    ["REQ", "s", {"ids": ["00" * 32], "#p": ["11" * 32], "&t": ["a", "b"]}],
    ["NEG-OPEN", "s", {}, "6100"], ["NEG-MSG", "s", "6100"],
    ["CLOSE", "s"], ["NEG-CLOSE", "s"],
    ["EVENT", {"id": "00" * 32, "pubkey": "11" * 32, "sig": "22" * 64,
               "kind": 1, "created_at": 1700000000, "content": "seed", "tags": []}],
]:
    seeds.append(json.dumps(command, separators=(",", ":")).encode())
for size in [0, 1, 125, 126, 65535, 65536, 1048576, 2097100]:
    payload = b"x" * size
    prefix = b"\x81" + (bytes([0x80 | size]) if size < 126 else
                         b"\xfe" + struct.pack(">H", size) if size <= 65535 else
                         b"\xff" + struct.pack(">Q", size))
    seeds.append(prefix + b"\0" * 4 + payload)
    compressor = zlib.compressobj(wbits=-15)
    seeds.append(compressor.compress(payload) + compressor.flush(zlib.Z_SYNC_FLUSH))

# Context takeover: messages compressed in one stream, each able to refer back
# into the ones before. As client WebSocket frames (FIN, RSV1, text, masked
# with a zero key), and as the target's takeover records: a control byte (low
# bit set releases the decompressor first), a two-byte little-endian length
# and the payload.
def takeover_messages(texts):
    compressor = zlib.compressobj(wbits=-15)
    messages = []
    for text in texts:
        payload = compressor.compress(text) + compressor.flush(zlib.Z_SYNC_FLUSH)
        messages.append(payload[:-4])  # RFC 7692: without the flush's empty block
    return messages

req = json.dumps(["REQ", "s", {"ids": ["00" * 32], "#p": ["11" * 32]}],
                 separators=(",", ":")).encode()
small = takeover_messages([req + str(n).encode() for n in range(4)])
assert all(len(payload) < 126 for payload in small)
seeds.append(b"".join(b"\xc1" + bytes([0x80 | len(payload)]) + b"\0" * 4 + payload
                      for payload in small))
# A first message past the 32 KiB window, then one that refers back near its
# end, so the replayed history wraps.
noise = b"".join(hashlib.sha256(struct.pack("<H", i)).hexdigest().encode() for i in range(1300))
large = takeover_messages([noise, noise[-30000:-29000] + req])
for messages in [small, large]:
    seeds.append(b"".join(bytes([n & 1]) + struct.pack("<H", len(payload)) + payload
                          for n, payload in enumerate(messages)))

for seed in seeds:
    path = root / hashlib.sha256(seed).hexdigest()
    if not path.exists():
        path.write_bytes(seed)
print(f"seeded {len(seeds)} protocol and size-boundary inputs in {root}")
