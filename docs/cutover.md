# Cutover and rollback

## Cutover (strfry → wok)

1. Stop C++ strfry.
2. **Copy** `data.mdb` / `lock.mdb` (never test against the only production copy).
3. Run `wok integrity` on the copy.
4. Point `strfry.conf` `db =` at the copy and start `wok relay`.
5. Confirm NIP-11, a REQ, a publish, and (if used) AUTH.
6. Switch clients / reverse proxy to wok.
7. Keep the C++ binary and the original files untouched until soak is done.

## Rollback (wok → strfry)

1. Stop wok.
2. If wok wrote to the copied DB, C++ strfry at the pinned commit can open v3 files wok wrote (verified by `cpp_roundtrip` / `cpp_export`).
3. Start C++ strfry on that same v3 directory.
4. Unix socket clients must be disabled or moved; C++ has no Unix Nostr listener.

Do not mix writers on one LMDB environment.
