# Cutover and rollback

## Cutover (strfry → wok)

1. Run `wok migrate strfry --db <strfry-db> --config <strfry.conf> --output <new-wok-dir> --check` and review every ignored key, path, capacity, and active-process warning.
2. Stop C++ strfry.
3. Rerun the command without `--check` to create the verified Wok-owned output.
4. Inspect `<new-wok-dir>/migration-manifest.json` and review the generated
   `wok.toml`, especially plugin, policy, and socket paths.
5. Start `wok --config <new-wok-dir>/wok.toml relay`.
6. Confirm NIP-11, a REQ, a publish, and (if used) AUTH and negentropy.
7. Switch clients / reverse proxy to Wok.
8. Keep the stopped strfry database and config untouched until soak is done.

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
