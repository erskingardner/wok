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
for seed in seeds:
    path = root / hashlib.sha256(seed).hexdigest()
    if not path.exists():
        path.write_bytes(seed)
print(f"seeded {len(seeds)} protocol and size-boundary inputs in {root}")
