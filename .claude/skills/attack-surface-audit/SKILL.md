---
name: attack-surface-audit
description: Audit what Wok exposes and shrink it, with the three passes of docs/attack-surface.md (default configuration, work before the gate, setting combinations) and the wok-compat harness that checks them. Use when a change adds or moves an entry point, a gate or a security setting; when reviewing such a change; or for a periodic audit of the relay's attack surface.
---

# Attack-surface audit

Code that no caller can reach cannot be exploited, so making code unreachable
lowers the risk of every bug in it at once. `docs/attack-surface.md` is the
inventory: every entry point, who reaches it, the gate that decides, and the
work done before the gate. Read its "Using this page" section first.

Findings go in GitHub issues, linked from the attack-surface tracking issue
(#156 at the time of writing), except those [step 5](#5-report) sends to a
private advisory.

## 1. Keep the inventory true

Update the rows for every entry point, gate or check order the change touches,
then run the inventory rows of the "Keeping this page current" table in
`docs/attack-surface.md`. The reachability and combination checks that table
also lists are the passes in sections 2 and 4.

```bash
cargo test -p wok-compat --test attack_surface --test golden_transcripts
cargo test -p wok-ws nip86      # NIP-86 methods and levels vs docs/nip86.md
cargo test -p wok-cli           # `wok` commands vs the Commands table
```

`attack_surface` fails when the listener answers a path the inventory does not
list, a gate is open or closed against its row, or a verb or profile drifts.

## 2. Default configuration

Ask of every feature an anonymous client can reach in the `default` and
`public` profiles and the `marmot` preset: does a default feature, or a Marmot
client, need it? If not, put it behind a setting that is off by default, or
off in the preset.

Evidence: `scripts/attack-surface-reach.py` (needs `cargo-llvm-cov` and the
`llvm-tools-preview` component) lists the relay functions each caller
reaches, per profile, in `crates/wok-compat/tests/reachability/`.

```bash
scripts/attack-surface-reach.py --check    # fails on new reach, an emptied phase, or a missing baseline
```

`--check` fails when any phase reaches a function its baseline does not
list, when a phase whose baseline lists functions reaches none, and when a
profile has no baseline. A function the `anonymous` phase newly reaches is
code an unauthenticated client can now run: move it after the cheapest check
that refuses the request, or behind a setting, and rewrite the baseline with
`--bless` only when that reach is the point of the change, with the reason in
the pull request. A phase that went empty is intended when the profile now
closes that caller, since the probe skips a closed caller (AUTH unusable,
`admin.enabled` off, no Unix socket): `--bless` with the reason. The
authenticated, admin and local phases count only what their caller adds, so
one can also shrink to nothing on purpose, when that code was removed or now
runs for anonymous callers: `--bless` with the reason. When the caller is
still open and the probe did not send, the probe is broken: fix it. A
function no longer reached is listed but does not fail.

When you extend the probe (`crates/wok-compat/tests/reachability.rs`), keep it from
calling the relay's crates itself (sign, frame and compress with other
crates), or its own work is counted as the relay's.

## 3. Work before the gate

For each gate the change touches, trace the request from its bytes to the
point where the gate refuses it, and list what runs first: buffering,
decompression, JSON, hex or base64 decoding, signature verification, database
reads, locks, queueing on a worker. Move each after the cheapest check that
refuses the same requests, under two rules Wok has decided:

- **Identity gates on client events stay after signature verification.** An
  author ban, `write_policy` or membership checked on an unsigned EVENT
  would let anyone ask whether a key is a member. Kind, size and shape
  checks can go first. NIP-98 is the exception, on purpose (#147): the
  dashboard and NIP-86 check that the signer may use the endpoint before
  verifying, so a stranger costs no verification, and keep it safe with the
  next rule.
- **Refusals that could name a key are one reply.** A signer that may not use
  an endpoint and a forged signature get the same message, at the same point
  relative to reading a request body.

After a reorder, rerun with `WOK_BLESS_TRANSCRIPTS=1` and review the diff of
`crates/wok-compat/tests/transcripts/`: only the requests the change means to
refuse differently should change, and `default` and `public` not at all
unless that is the point. Check that a check moved earlier still holds when
the request arrives later (a time window, a revoked role): repeat it after
the slow step.

## 4. Setting combinations

Can another setting, a preset overridden by the file, a reload, or a NIP-86
or dashboard change make this gate fail open or be ignored, without an error
at load or a warning? Refuse such a combination when the configuration loads,
or warn about it there and in `wok doctor`.

Add each security setting to `SETTINGS` in
`crates/wok-compat/tests/setting_combinations.rs` and run it:

```bash
cargo test -p wok-compat --test setting_combinations
```

The test sends every setting, alone and in pairs, the golden transcript
script, and fails when:

- a step one setting refuses for a reason of its own, or that each of two
  settings refuses, is served with both on: fix it, or add the step to
  `OPENS` with the reason it is intended;
- a setting changes nothing but what NIP-11 advertises: give the script a
  step that shows it is enforced, or add it to `UNPROBED` with the reason the
  script cannot see it.

The test covers pairs over `public`. Reload sequences, three-way combinations
and runtime changes still need reading: `Config::apply_reload` and
`security_scope_changes`, `moderation.rs`, `nip86.rs` and the dashboard's
`update_config`.

## 5. Report

For each candidate: the entry point, `file:line` of the work and the gate, who
can reach it, what a bug there would expose, the fix, and whether it was
verified by reading the code or a failing test. Prove a finding with a
failing test before fixing it, and keep the test.

Resource exhaustion beyond the documented limits, and anything a client can
use to read or write what it should not, goes to a private advisory
(`SECURITY.md`). Ordering that wastes work within a budget, missing warnings,
and documentation gaps can be public issues. When a finding fits both, ask
who has to act for it to be exploitable: if a client can exploit a relay
whose operator configured it as documented, it is private; if the gate fails
open only because the operator wrote a value the docs do not support, and
Wok accepts it without a warning, it is a configuration bug and can be
public. #162 is one: an `allowed_kinds` value that does not parse is treated
as allowing every kind. An empty list that the docs define as unrestricted is
the operator's choice, not a finding.
