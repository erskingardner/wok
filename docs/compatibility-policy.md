# Compatibility policy

Wok should be easy to adopt from strfry without being permanently constrained
by strfry's implementation choices.

## Stable boundaries

- **Migration:** a supported strfry v3 source can be copied into a verified,
  Wok-owned database without changing its logical event records.
- **Nostr wire protocol:** Wok targets the canonical NIPs it advertises. The
  conformance suite pins the specification revision used for each release.
- **Event identity:** migration and normal processing must not silently alter a
  valid event's canonical ID, signature, tags, content, or stored payload.
- **Operational rollback:** migration leaves source files untouched; rollback
  uses that source or an explicit JSONL transfer, never a shared writable DB.

## Not promised

- Ongoing binary compatibility between Wok databases and strfry.
- Mixed strfry/Wok writers or opening a Wok-owned database with strfry.
- Preservation of a strfry behavior that conflicts with a current NIP, creates
  a security or reliability problem, or blocks a Wok feature.
- Identical behavior for undocumented config keys or external plugins.
- Byte-identical JSONL presentation where it does not affect event identity or
  migration correctness.

## How inherited behavior is decided

1. Follow the pinned canonical NIP for public protocol semantics.
2. Preserve data and event identity across migration.
3. Prefer explicit, safe Wok behavior for operations and storage evolution.
4. Use pinned strfry behavior as historical context and a differential test
   oracle, not as the final authority.
5. Document intentional divergences and cover them with a focused test.

Behavior retained solely for compatibility should have a named migration or
interop reason. Otherwise obvious bugs are fixed and missing features can be
designed for Wok on their own merits.
