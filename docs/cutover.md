# Cutover and rollback

## Cutover (strfry → wok)

1. Stop C++ strfry.
2. Run `wok migrate strfry --db <strfry-db> --config <strfry.conf> --output <new-wok-dir>`.
3. Inspect `<new-wok-dir>/migration-manifest.json` and review the generated
   `wok.toml`, especially plugin, policy, and socket paths.
4. Start `wok --config <new-wok-dir>/wok.toml relay`.
5. Confirm NIP-11, a REQ, a publish, and (if used) AUTH and negentropy.
6. Switch clients / reverse proxy to Wok.
7. Keep the stopped strfry database and config untouched until soak is done.

## Rollback (wok → strfry)

1. Stop wok.
2. For immediate rollback, start strfry on the original, untouched v3
   directory. Events accepted only after the cutover will not be present.
3. If those events must be retained, export them from the stopped Wok database
   and import the JSONL into a separate strfry v3 database; validate this path
   before an operational cutover.
4. Unix socket clients must be disabled or moved; strfry has no Unix Nostr listener.

Do not point strfry at Wok's v4 database and never mix writers on one LMDB
environment. See [migration-from-strfry.md](migration-from-strfry.md).
