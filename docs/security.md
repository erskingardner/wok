# Security notes

For a least-privilege systemd unit, filesystem layout, reverse-proxy boundary,
plugin isolation guidance, and logging policy, see
[Production deployment security](production-deployment.md).

- Treat every EVENT as untrusted. IDs and Schnorr signatures are verified unless `--no-verify` import is explicitly used.
- Input limits: `max_event_size`, tag counts, WebSocket/Unix frame sizes, and
  `max_pending_outbound_bytes`.
- Unix sockets: bound at a sibling temp path, chmod/chowned there, and
  atomically renamed into place (no bind→chmod window); stale-path replacement
  refuses symlinks and non-sockets; shutdown unlinks only after re-verifying
  the path against the filesystem dev+inode captured before that rename;
  optional UID/GID allow-lists via peer credentials.
- AUTH (NIP-42) requires `relay.auth.serviceUrl`. Protected events (NIP-70) are rejected without matching authenticated pubkey.
- Restricted read kinds (default 4, 1059) are not delivered unless the subscriber is the author or first `p` tag. They fail closed until `relay.auth.service_url` makes NIP-42 usable; broad COUNT requests cannot reveal their population.
- Write-policy plugins run as `sh -c` with a timeout; plugin failure rejects the event.
- `wok reindex` requires the explicit `--confirm-relay-stopped` acknowledgement.
  Stop the relay and all DB utilities first; promotion retains the original
  database as a sibling backup rather than modifying it in place.
- Do not expose the Unix socket on a shared host without UID/GID policy and `0600` mode.

## Memory-safety boundary

Safe crates forbid `unsafe` Rust. Crates that require operating-system or LMDB
FFI deny it by default and allow it only in the explicitly audited modules.
`unsafe_op_in_unsafe_fn` is denied so every pointer dereference and FFI
operation remains visible at the exact call site.

The relay's unavoidable high-risk boundary is LMDB: environment, transaction,
cursor, comparator, and mmap value pointers. Transaction and cursor wrappers
are explicitly neither `Send` nor `Sync`; mmap-backed slices are tied to a
live transaction/cursor anchor and cannot outlive it through the safe API. Raw
transaction pointers are not exposed. Negentropy nodes use explicit native-
endian field encoding rather than copying Rust struct memory.

Release builds use `panic = "abort"`, preventing unwinding across C callback
frames. Comparator functions are total over arbitrary byte strings and have
property tests for malformed database keys.

## Dependency policy

CI and a weekly scheduled job run `cargo-deny` against the locked dependency
graph. Known advisories, yanked packages, unknown registries, unknown Git
sources, and unapproved licenses fail the gate. Duplicate versions are
reported as warnings for deliberate review. Informational advisories are fixed
rather than permanently ignored; the initial audit removed the unmaintained
`instant` dependency by upgrading `notify`.

## Adversarial testing

Fast property tests feed arbitrary data into strict JSON/event validation,
protocol envelopes, WebSocket fragmentation and decompression, Negentropy
frames, and modeled LMDB transaction sequences on every normal test run. A
separate libFuzzer target composes the public ingress parsers. Scheduled and
parser-changing pull-request jobs run a bounded AddressSanitizer-backed smoke
campaign from a fresh corpus. Any crash reproducer is retained as a workflow
artifact for diagnosis and promotion into a permanent regression test. A
long-running campaign with a persistent evolving corpus is intentionally a
separate operational concern from this fast CI gate.

Storage recovery tests exhaust a deliberately small LMDB map and terminate a
separate writer process after the event and secondary indexes have been
modified but before commit. Each fixture reopens the environment and verifies
that the failed transaction left no partial state; the process-crash fixture
also runs the full database integrity checker against a committed baseline.
