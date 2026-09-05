# Wok code review — 2026-09-05

Reviewed source: `cc43c05019cf0ee3cd92f2422bf8d73b0c704a55` (0.5.0), initially clean. This is the pre-fix audit baseline. The subsequent local commits include the remediation described below; historical source-line links in the findings refer to that baseline.

The strongest findings concern acknowledgement ownership, inconsistent read privacy, cancellation, and resource accounting. These deserve attention before a storage-backend refactor. LMDB itself is not the cause of most of them.

## Remediation status

The approved changes are implemented and committed locally in logical groups. R1-R12 and the multi-key AUTH
follow-up have fixes, and the original failing regression tests are enabled.
Storage-backend abstraction remains deferred.

- Publisher context travels with events through sorting, quota outcomes and
  transaction aborts. Durable commit still precedes acceptance receipts.
- Shared visibility covers REQ, COUNT/HLL, ranked search, live delivery and sync.
  Direct trees require a conservative public-data proof; temporary views are
  authorized per event. AUTH retains up to 64 identities and invalidates affected
  sync sessions when the identity set changes.
- Sync reservations default to 256 MiB per connection / 1 GiB across workers,
  with 60-second idle expiry and no active-session maximum lifetime. Overflow
  returns NEG-ERR. Query cancellation immediately drops retained state.
- Cursor seeks return transaction-owned pointers; search misses consume the
  timeslice; Unix frame reads survive outbound traffic; terminal cancellation
  covers blocked writes and ingress waits in both transports.
- Wok v5 adds lazy transactional author counts and a durable local sequence.
  Replacements/deletions use net storage effects. Expiration is enforced on reads
  and maintenance can delete the newest event without reusing committed IDs.
  Reindex preserves the sequence while rebuilding derived counters. Upgrade and
  rollback instructions are in [lmdb-v3.md](lmdb-v3.md).
- Raw payload decode borrows mmap bytes; monitor content requirements use a
  maintained count and relevant candidate checks; tree writes batch timestamp/ID
  deltas within one transaction. Writer and sync responsibilities are split into
  their own modules. Cron queues work to the writer.
- All crates inherit Rust 1.85, the locked graph and source APIs support it, and
  the resolver avoids newer-Rust dependencies on future updates.
- The benchmark harness validates parsed envelopes, exact receipts, query sets,
  full per-subscriber events and local final storage. TCP_NODELAY is explicit.
  Historical README results are labeled accordingly.

A deterministic 10,000-event index diagnostic found that a broad tag plus a
10-event author scanned 120,002 work units (1,261 us in one local release run).
The bounded author-seed check reduced this to 122 scan work units (30 us including
planning in a subsequent run). It probes at most 64 postings and eight cursors
per alternative, retains the old plan when uncertain, and always evaluates the
original filter. The retained regression includes a nonmatching author event to
catch an accidental index-only bypass. This demonstrates reduced candidate work,
not a general relay throughput multiplier.

The fresh small Mac query A/B comparison against `cc43c05` passed exact-set checks
in all six runs, but overlapping host builds make throughput and tail latency
unsuitable for a performance claim. Linux capacity and controlled NODELAY runs
remain future measurement work; no privacy/durability guarantee was relaxed to
produce a speed number.

### Final validation

- `cargo test --workspace --exclude wok-bench --locked`: 335 passed, one manual
  timing diagnostic ignored. Two subsequently added DB regressions also pass
  (all six DB audit regressions were rerun): 337 distinct workspace tests validated.
- `cargo test -p wok-bench --locked`: nine passed, including independent receipt,
  expected-set and ephemeral-storage oracle tests.
- `cargo fmt --all --check`, `git diff --check`, workspace/all-target Clippy with
  warnings denied, release CLI/harness builds, and the explicit Rust 1.85.0
  workspace/all-target check pass.
- Current-lockfile `cargo audit`: zero known vulnerabilities. The pre-existing
  yanked `chacha20 0.10.1` entry remains a warning, not a vulnerability finding.
- All 27 rows in the small full benchmark campaign pass. Final lifecycle and
  cold-start controls add four passing rows. The corrected publication harness
  rejects the unfixed `cc43c05` binary for a misrouted receipt and accepts Wok's
  fixed binary. This negative control is intentionally recorded as `ok=false`.
- [Retained benchmark rows](audit-benchmarks-2026-09-05.jsonl) include phase and
  binary hashes. Baseline A/B rows originally used the harness's `strfry` slot;
  their labels are explicitly corrected to `wok-baseline-cc43c05`, with the original
  label retained. The earlier full run predates the cold-start histogram-unit
  correction; use its cold-start notes or the final control for milliseconds.

Validation used disposable databases on macOS ARM64. No production database was
upgraded. Tests cover ownership, mixed outcomes/aborts, pointer provenance,
expiry, quotas, v4 upgrade/reopen/reindex, multiple AUTH keys, privacy-safe counts
and sync, shared worker budgets/release, idle expiry, search scheduling, Unix
fragmentation and blocked WebSocket cancellation. This is not a new Linux
capacity result or a completed fuzz campaign. Changes are committed locally; nothing has been pushed.

## Historical scope and evidence


I traced transport ingress, event validation, writer batching and acknowledgements, historical queries, live monitors, AUTH, COUNT, negentropy, expiration, quotas, search indexing, and the LMDB transaction/cursor boundary. I also inspected admin authorization, plugin handling, configuration, mesh/maintenance paths, and the benchmark harness. The latter operational paths received less depth than the core relay. This is a source and targeted-test review, not a proof that every path is correct or a long-running fuzz campaign.

Validation on macOS ARM64 with Rust 1.96.1:

- Existing workspace suite: **315 tests reported passed**, excluding `wok-bench`. The final run also passes all 315, with the 11 new manual cases ignored. The local strfry executable was present for optional differential tests; its build provenance was not independently reconstructed.
- **Ten new expected-behavior regression tests fail on the reviewed implementation**, at the assertions described below. They are explicitly ignored in ordinary test runs until fixes land. This preserves runnable evidence without silently treating defective behavior as correct.
- One additional manual timing diagnostic passes. Its timings do not demonstrate a Nagle penalty on this Mac.
- Formatting and workspace Clippy with warnings denied pass.
- `cargo audit` 0.22.0: **zero known vulnerabilities** in the 318-package lockfile against advisory database commit `5a0ebedfe8bdd2e295b171f4162f8c977bcad9a5` (updated September 2). It reports a yanked `chacha20 0.10.1` lockfile entry; `cargo tree --target all -i chacha20` finds no active reverse dependency. Treat that as lockfile hygiene, not a demonstrated runtime vulnerability.
- `cargo deny` 0.18.5 passes bans/licenses/sources. Its advisory check cannot parse a CVSS 4.0 entry in the current advisory database; the separate `cargo audit` result above supplies the vulnerability check, not a claimed all-green cargo-deny run.
- An explicit Rust **1.85.0 compiler** check fails against the locked dependency graph; see R12.

The original README numbers describe `fa9b061`, not the current reviewed head. No new Linux capacity campaign or alternative database benchmark was run.

## Findings

P1 means fix with high priority; P2 means a concrete defect to schedule. Reproduction tests use temporary databases and synthetic events only.

### R1 — P1: Batch sorting sends acknowledgements to the wrong publishers

[Writer metadata and write call](/Users/jeff/code/wok/crates/wok-relay/src/server.rs:2185), [event sorting](/Users/jeff/code/wok/crates/wok-db/src/write.rs:408), [reply routing](/Users/jeff/code/wok/crates/wok-relay/src/server.rs:2254).

`run_writer` splits `(conn_id, event)` into parallel `meta` and `evs` arrays. `write_events_with_policy` sorts `evs` by timestamp and event ID. `meta` is not reordered. Both success and error replies then zip the original connection order with the sorted events.

Two publishers whose events arrive in reverse timestamp order receive each other's event IDs. A client waiting for its own ID can time out despite a successful commit; private publication IDs also cross connection boundaries. Mixed write outcomes can be attributed to the wrong publisher.

**Protocol clarification:** Alice publishes A and Bob subscribes to A. Alice should receive `["OK", A.id, true, ""]`; Bob should receive `["EVENT", Bob.subscription_id, A]`. Bob's subscription does not make him the destination for Alice's OK. To trigger this defect, another publisher (say Carol) publishes C in the same writer batch, and sorting reverses the two records: Alice receives OK for C and Carol receives OK for A. This finding concerns publication receipts, not a demonstrated swap in subscriber EVENT delivery. Pinned [NIP-01](https://raw.githubusercontent.com/nostr-protocol/nips/656cecc7c0a815b6a2b218d3b5d6f078b3f4dbab/01.md) specifies OK as the response to a client's publication and EVENT as subscription delivery. The focused reproduction was rerun during the design follow-up and still fails with the two receipt IDs exchanged.

**Evidence:** `review_writer_acknowledges_each_event_to_its_publisher` preloads one batch with connection 1/timestamp 200 and connection 2/timestamp 100. Connection 1 receives ID `02…02`; connection 2 receives `01…01`.

**Fix direction:** keep publisher context attached to each event through sorting, or return outcomes keyed by an immutable request token. Avoid another parallel-array mapping. Test both success and transaction-failure routing with several publishers and mixed outcomes.

### R2 — P1: The default negentropy tree discloses restricted event IDs

[Tree selection](/Users/jeff/code/wok/crates/wok-relay/src/server.rs:2883), [tree reconciliation](/Users/jeff/code/wok/crates/wok-relay/src/server.rs:3122), [default tree](/Users/jeff/code/wok/crates/wok-db/src/env.rs:325).

Every new database has a persistent `{}` tree. A `NEG-OPEN` matching that tree reconciles it directly, applying only time bounds. It does not apply the per-event read restrictor used by the memory reconciliation path. A broad `{}` filter also avoids the ingest check for a fully restricted-kind filter.

**Evidence:** with default relay policy, a signed kind-4 event is accepted. An unauthenticated `REQ {}` returns only EOSE. The same connection's `NEG-OPEN {}` successfully reconciles the private event ID. The test runs the actual ingester, writer, query workers, and negentropy client protocol.

This leaks IDs/set membership, not decrypted content. The same direct-tree path also lacks moderation and vanish visibility checks; bans leave records physically stored, and vanish cleanup is asynchronous. Those extensions follow from the source, while the restricted-ID leak is directly reproduced.

**Policy clarification from the design follow-up:** [the operations documentation](/Users/jeff/code/wok/docs/mesh-and-maintenance.md:58) explicitly describes this inherited disclosure and advises operators to avoid broad trees when storing restricted kinds. However, initialization automatically creates the broad tree. This is a metadata-privacy policy inconsistency and unsafe default, rather than a claim that NIP-77 itself mandates private IDs. NIP-77 supports both client-relay and relay-relay sync. Wok already challenges unauthenticated explicitly restricted-kind NEG-OPEN filters, while broad filters bypass that challenge; successful AUTH alone does not establish authorization to enumerate everyone's restricted records. A stronger policy should be chosen explicitly and documented as a change from inherited behavior.

**Fix direction:** only use a persistent tree when its contents are provably visible to that session. Otherwise use a policy-filtered view. A longer-term public-only tree can preserve efficient public sync, but requires versioning/rebuilding existing trees and updating them when visibility changes. Simply requiring any successful AUTH would still expose other users' restricted IDs.

### R3 — P1: The safe cursor API can return a dangling key reference

[Cursor::get](/Users/jeff/code/wok/crates/wok-db/src/txn.rs:321).

The cursor accepts a key with an independent, short lifetime but returns both key and value as slices valid for the transaction lifetime. For `MDB_SET`, LMDB leaves the key pointer pointing at the caller's input. The wrapper treats that pointer as transaction-owned. A safe caller can drop the input allocation while retaining the returned reference.

**Evidence:** `review_cursor_key_must_be_owned_by_transaction` confirms that the returned key pointer equals the caller's heap allocation, not an LMDB-owned key. The test deliberately does not free and dereference it, so it demonstrates the invalid lifetime contract without executing a use-after-free. The vendored LMDB implementation rewrites the key for `MDB_SET_KEY`/`MDB_SET_RANGE`, but not `MDB_SET`.

No remote exploit through a current relay caller was demonstrated. This is nevertheless a real Rust soundness defect in the public safe boundary.

**Fix direction:** use typed cursor operations with correct lifetime contracts. Exact-key seeks can use `MDB_SET_KEY`; other operations must ensure output keys really come from the database, copy them, or preserve the input lifetime. Audit all supported cursor operations rather than patching only this test. Keep raw handles/operation flags private where feasible.

### R4 — P1: Search misses bypass query timeslicing

[Search gather loop](/Users/jeff/code/wok/crates/wok-query/src/scan.rs:384), [late deadline check](/Users/jeff/code/wok/crates/wok-query/src/scan.rs:441).

The search scan checks elapsed time only after a candidate matches the other terms and the packed filter. Nonmatching candidates return early before the check. A common search term combined with a nonmatching author, kind, or second term can therefore traverse its entire posting list in one worker turn. A low result limit does not bound this work.

**Evidence:** with 4,096 `common` postings and a zero-microsecond timeslice, the matching-kind control yields. Changing only the kind to one absent from the database causes the query to exhaust the entire list and report completion without yielding.

**Fix direction:** charge work and test the deadline independently of whether a candidate matches. Preserve a correct resume position when yielding. This reduces starvation without weakening search semantics or rejecting legitimate filters.

### R5 — P1: Completed memory sync sessions can retain gigabytes per connection

[Retained views](/Users/jeff/code/wok/crates/wok-relay/src/server.rs:2829), [insertion](/Users/jeff/code/wok/crates/wok-relay/src/server.rs:2910), [Vector](/Users/jeff/code/wok/crates/wok-negentropy/src/vector.rs:9), [defaults](/Users/jeff/code/wok/crates/wok-relay/src/config.rs:371).

The historical-query limit bounds concurrently running scans. Completed memory views remain in `views` until explicitly closed or the connection ends; there is no aggregate byte budget or idle eviction. The default allows 200 views per connection and 1,000,000 events per view. Each `Item` is 40 bytes, giving **8,000,000,000 bytes of item storage** across 200 full views before allocator slack and other state.

A client can build these sequentially with distinct subscription IDs and a non-tree filter such as `{"kinds":[1]}`. That filter's estimated cost is within default admission limits. The query concurrency cap and token buckets slow construction but do not bound retained memory. A sufficiently populated public relay is the prerequisite.

**Evidence level:** direct control-flow, layout, and configured-limit analysis. I did not deliberately exhaust the host's memory.

**Fix direction:** reserve per-connection and global memory budgets before/during view construction, release reservations through ownership/Drop, and expire inactive sessions. Consider sharing immutable equivalent views where policy and snapshot identity permit it. Do not rely solely on lowering the number of concurrent scans.

### R6 — P2: Unix frame headers are corrupted by normal full-duplex traffic

[Unix select loop](/Users/jeff/code/wok/crates/wok-unix/src/lib.rs:217).

`read_exact(&mut len_buf)` is inside `select!`. If it consumes part of the four-byte header and outbound traffic wins the selection, its internal progress is discarded. The next iteration begins a new four-byte read even though part of the header has already been consumed.

**Evidence:** `review_unix_partial_header_survives_outbound_delivery` opens a live subscription, sends two bytes of the next request's header, receives an unrelated live EVENT, then sends the remaining header and body. The valid request is disconnected with EOF instead of receiving EOSE. The separate helper test for fragmented writes did not exercise cancellation by outbound delivery.

**Fix direction:** retain decoder state outside cancellable futures, or use a dedicated reader task that completes frames independently of the writer. [Tokio documents that read_exact is not cancellation safe](https://docs.rs/tokio/1.53.1/tokio/io/trait.AsyncReadExt.html#method.read_exact).

### R7 — P2: A blocked write defeats slow-client termination

[WebSocket write](/Users/jeff/code/wok/crates/wok-ws/src/lib.rs:738), [Unix loop](/Users/jeff/code/wok/crates/wok-unix/src/lib.rs:209).

Once an outbound branch wins, it awaits the entire socket write inside the branch body. During that wait the outer select does not poll the kill notification or WebSocket ping timer. A peer that stops reading can leave the task, socket, queued frames, and subscriptions alive after the relay has already counted it as terminated. Unix also awaits the entire inbound body outside the kill selection.

**Evidence:** `review_kill_interrupts_blocked_websocket_write` uses the actual connection handler with a one-byte duplex capacity and a non-reading peer. The slow-client metric increments and kill is signalled, but the handler remains blocked. The test explicitly aborts its task afterward.

**Fix direction:** make terminal cancellation cover writes, ingress-queue waits, and partial bodies. Dedicated read/write tasks plus one owner for cancellation and cleanup can serve both transports. Preserve byte accounting until an in-flight frame is written or discarded. A partially written connection should be closed rather than resumed from a new frame.

### R8 — P2: Oversized memory reconciliation silently returns a truncated set

[Query cap](/Users/jeff/code/wok/crates/wok-relay/src/server.rs:2857), [overflow test](/Users/jeff/code/wok/crates/wok-relay/src/server.rs:3055).

The parsed filter allows `max_sync_events + 1` results so overflow can be detected, but the query scheduler caps delivered matches at `max_sync_events`. The later `total > max_sync_events` check consequently cannot fire for a positive cap. The relay seals and reconciles an incomplete set as though it were the requested set.

**Evidence:** three matching events with a configured cap of two produce `NEG-MSG` containing two IDs, rather than `NEG-ERR`. Clients can believe synchronization completed while missing data.

**Fix direction:** permit the overflow sentinel in the scheduler and fail the session before reconciling a partial vector. Test both sides of the boundary and use checked/saturating arithmetic. The pinned [NIP-77](https://raw.githubusercontent.com/nostr-protocol/nips/656cecc7c0a815b6a2b218d3b5d6f078b3f4dbab/77.md) provides a blocked error for requests exceeding a relay's processing limit.

### R9 — P2: The newest event stays readable after expiration

[Cron skips the newest local ID](/Users/jeff/code/wok/crates/wok-relay/src/server.rs:3194), [query visibility](/Users/jeff/code/wok/crates/wok-query/src/scan.rs:787).

Expiration cleanup always skips the most recent event, while query visibility does not independently reject expired records. On a quiet relay the last event can therefore be served indefinitely after expiry. COUNT and synchronization need equivalent expiration handling as well.

**Evidence:** publish one event expiring in two seconds, wait five seconds so multiple cleanup passes can run, then query its exact ID. The relay still returns EVENT.

**Fix direction:** enforce expiration during visibility checks regardless of physical cleanup timing. Before removing the newest-event deletion exception, persist a monotonic local-ID high-water mark independently of existing rows: insertion currently derives the next ID from the largest surviving key, and ID reuse can break live cursors. Pinned [NIP-40](https://raw.githubusercontent.com/nostr-protocol/nips/656cecc7c0a815b6a2b218d3b5d6f078b3f4dbab/40.md) permits deferred deletion but says relays should not serve expired events.

### R10 — P2: An author can remain quota-blocked after their data is deleted

[Memo refresh and rejection](/Users/jeff/code/wok/crates/wok-relay/src/server.rs:2068), [refresh threshold](/Users/jeff/code/wok/crates/wok-relay/src/server.rs:2449).

The memo is rechecked only after 4,096 admitted events. Once its baseline reaches the quota, rejected events do not advance that counter. Later expiration or maintenance deletions can free all the author's storage while the writer continues rejecting every new event indefinitely, absent another cache reset or restart. Replacement writes also increment the memo despite potentially leaving the stored count unchanged.

**Evidence:** with author quota one, write an event, remove it through the storage deletion API, verify zero events remain, and publish another signed event from the same author. It is rejected for exceeding the quota.

**Fix direction:** at minimum refresh before rejecting on a cached quota. A stronger and faster steady-state design maintains author counts transactionally with every insert/delete/replace, including maintenance. Permit deletion and replacement operations according to their net storage effect.

### R11 — P1: COUNT and event delivery disagree about recipient privacy

[COUNT authorization](/Users/jeff/code/wok/crates/wok-relay/src/restrict.rs:43), [delivery authorization](/Users/jeff/code/wok/crates/wok-relay/src/restrict.rs:96).

COUNT considers an authenticated `#p` filter safely scoped to that pubkey. The tag index matches any `p` tag, whereas event delivery grants recipient access only through the first `p` tag. A restricted event with several `p` tags can therefore contribute to a user's count and HLL even though that same user's REQ cannot read it.

**Evidence:** authenticate key B, publish a signed kind-4 event with first recipient A and second `p` tag B, then issue the same filter via REQ and COUNT. REQ returns only EOSE; COUNT reports one and includes an HLL.

**Fix direction:** apply the same per-event visibility predicate before counting or updating HLL registers. Filter-level authorization is insufficient unless the storage index expresses exactly the same recipient semantics. Preserve the documented policy while making these paths agree.

### R12 — P2: The declared Rust 1.85 MSRV cannot build the locked workspace

[Workspace declaration](/Users/jeff/code/wok/Cargo.toml:21), [MSRV job](/Users/jeff/code/wok/.github/workflows/ci.yml:31).

With the compiler explicitly set to Rust 1.85.0, `cargo check --workspace --all-targets --locked` fails before compiling Wok: `hdrhistogram 7.6.0` requires 1.88, and ICU 2.2/idna_adapter dependencies require 1.86. The normal Rust 1.96.1 checks pass.

**Fix direction:** either support 1.85 with compatible dependency pins and source APIs, or raise the declaration to a version verified against the whole workspace. Make the CI command select the intended toolchain explicitly and print both Cargo and rustc versions. A successful build using the local newer compiler does not verify MSRV.

## Performance and benchmark interpretation

### Strengthen correctness gates first

[Publication acceptance check](/Users/jeff/code/wok/crates/wok-bench/src/main.rs:1344) accepts the next textual reply containing `"OK"` and then checks whether it contains `true`. It does not validate the returned event ID. R1 can therefore pass the publication benchmark while acknowledgements are misrouted. A rejection message containing the word `true` is another reason substring matching is insufficient.

[Historical query checks](/Users/jeff/code/wok/crates/wok-bench/src/main.rs:1478) mostly count textual EVENT markers and require a nonempty result plus EOSE. They do not prove that all returned events match the requested filter or that the expected set was returned. Tighten these gates using parsed envelopes, exact subscription/event IDs, and an independent expected-set oracle over the deterministic corpus. Validate stored outcomes separately when publication correctness is the claim.

The existing benchmark results still describe measured execution of that harness. “Zero mismatches” should not be interpreted as coverage of invariants the harness never checks.

### Separate client TCP behavior from relay throughput

[connect_retry](/Users/jeff/code/wok/crates/wok-bench/src/main.rs:1233) uses `connect_async`, which leaves Nagle enabled in tokio-tungstenite 0.26.2. REQ/EOSE/CLOSE loops then send a CLOSE with no application response before reusing the connection. Nagle plus delayed acknowledgements is a plausible contributor to the historical Linux plateaus of approximately 90 requests/s across four sockets and 22.8 requests/s on one socket.

The retained diagnostic changes only client TCP_NODELAY and mirrors the four-socket sequence on a fresh local relay. For 80 empty-history requests, the observed A/B/B/A durations were 12.51/11.56/10.13/8.29 ms. **That shows no consistent Nagle penalty on this Mac.** It does not resolve the older Linux results and is not a relay-capacity measurement. Rerun on the benchmark Linux hosts with explicit client NODELAY settings before attributing the large Unix/WebSocket gap to codec or storage cost.

### Low-complexity optimization candidates

These are code-grounded opportunities, not measured speedup claims:

1. **Remove the raw-payload copy in Decompressor.** [decode](/Users/jeff/code/wok/crates/wok-db/src/payload.rs:84) copies uncompressed JSON from mmap into a reusable buffer before the caller copies it again into an outbound frame. Return a borrow for raw payloads and a decoder-buffer borrow for compressed payloads, with lifetimes that end before network awaits. This is particularly relevant after the default event-size increase.
2. **Avoid scanning every subscription to answer “does any need content?”** [ActiveMonitors::requires_content](/Users/jeff/code/wok/crates/wok-query/src/monitor.rs:87) walks all subscriptions. Maintain a count updated on install/remove/replace. Also evaluate content only for relevant candidate subscriptions; one search subscription currently makes a whole monitor worker parse content for otherwise unrelated events.
3. **Amortize persistent-tree updates within writer batches.** [NegentropyFilterCache::apply](/Users/jeff/code/wok/crates/wok-negentropy/src/cache.rs:139) reopens a tree and flushes its dirty nodes for every event. Measure batching operations per tree within the same atomic database transaction. Avoid copying entire event payloads to achieve this.
4. **Replace author-count rescans with transactional counters.** This addresses R10 and avoids cold-cache O(author history) scans on the single writer. Include replacement, vanish, and cron deletion in the counter contract.
5. **Measure index choice, visibility lookups, and allocation before adding worker threads.** Tag selection currently uses the number of filter alternatives rather than posting cardinality. A broad tag can defeat a selective author constraint. The query layer also repeatedly fetches packed records and policy markers. A policy-aware candidate API can reduce repeated reads without creating an unsafe index-only bypass.

The historical profiling report attributed most sampled writer time to durable LMDB commit. Its retained CPU improvements and removed delayed-batching experiment are useful prior evidence, not a measurement of this head. Preserve commit-before-OK durability; instrument validation time, queue delay, batch size, index/tree work, and commit latency separately before changing batching or storage.

## Simplification priorities

The useful reduction in complexity is to reduce the number of independently implemented invariants:

- **One visibility contract** for REQ, COUNT/HLL, live delivery, memory sync, and precomputed sync. It must account for session identity, restricted recipients, moderation, vanish, and expiration *before* result limits or ranking discard other candidates. Fast paths need an explicit proof that they preserve that contract.
- **One transport lifecycle owner**, with persistent decoders, bounded in-flight/queued bytes, cancellation-aware reader/writer tasks, and deterministic registration cleanup. WebSocket and Unix framing remain distinct; their connection lifecycle need not be duplicated.
- **One publication envelope** holding event data, publisher context, and outcome through validation, sorting, persistence, and acknowledgement.
- **One storage mutation boundary** for durable counters, primary records, derived indexes, and negentropy updates. Cron currently opens its own write transactions, so the documentation's “one application-level writer” is stronger than the implementation. LMDB serializes them, but application policy/counter maintenance should be centralized.
- Split `server.rs` by those responsibilities after their contracts are explicit. Moving its 3,776 lines into several files alone would not fix the complexity causing these bugs. Remove obsolete comments about co-resident C++ writers and unimplemented sharding where they conflict with Wok's v4 ownership and current worker pools.

## Storage-backend independence

**Wok can expose a storage abstraction while retaining an LMDB implementation with very little overhead. Whether a different backend matches LMDB is a separate, workload-dependent question. Neither requires sacrificing privacy or durability.**

Current coupling is substantial. `wok-query` chooses raw DBIs and LMDB cursor operations; ordering depends on native-endian composite keys and custom comparators; event writes maintain duplicate indexes and the persistent negentropy tree in one transaction; visibility checks reach into DB tables. `NegentropySink` takes a concrete `RwTxn`. The negentropy protocol already has a useful independent `Storage` trait, but that does not abstract the relay's database.

I would first define a narrow event-store contract around **publication batches, read snapshots/query pages, visible counts, and change checkpoints**, while retaining backend-specific scan/index implementations. Keep strfry import as its own compatibility adapter. Preserve signed JSON bytes and PackedEvent identity where promised; a new backend does not have to reproduce LMDB's physical layout.

The required semantics include:

- Atomic publication outcomes and commit-before-OK durability.
- Replacement, deletion, vanish, moderation, quotas, expiration visibility, and derived-index consistency.
- Stable chronological ordering and an independently monotonic change position, including after deleting the newest event.
- Bounded snapshot/query lifetimes and correct historical-to-live handoff.
- Exact serialization and migration fingerprints.

For the hot inner loops, concrete/generic transaction implementations can retain borrowed reads and static dispatch. If runtime backend selection is useful, dispatch once per batch or query using an enum or trait object, then let the backend execute its scan internally. The expensive design would be forcing every lookup through an async boxed future, allocating an owned event for every candidate, or exposing a generic key-value interface that reconstructs LMDB behavior inefficiently on every backend.

Candidate choices, based on architecture rather than a Wok benchmark:

| Backend | Why evaluate it | Main uncertainty for Wok |
|---|---|---|
| LMDB behind the new contract | Establish that abstraction preserves today's borrowed reads, batching, and durability | Must measure overhead rather than assume it is zero |
| redb | Pure Rust, copy-on-write B+trees, ACID transactions, MVCC, and borrowed access; structurally relevant to a safety/simplicity goal | Wok's multi-index writes, ordered scans, and negentropy need direct measurement; comparable architecture does not establish comparable throughput |
| RocksDB | LSM architecture is worth testing if sustained write throughput or much larger data becomes the main constraint | Compaction, caches, write amplification, tail latency, C++ dependency, and tuning complexity work against the simplicity goal |
| SQLite WAL | Mature transactional engine and SQL could simplify some query/index maintenance | A different execution/indexing model; WAL still permits only one writer at a time, and matching LMDB's range/read path requires measurement |

Primary references: [LMDB introduction](https://github.com/LMDB/lmdb/blob/mdb.master/libraries/liblmdb/intro.doc), [redb documentation](https://docs.rs/redb/latest/redb/), [RocksDB architecture](https://github.com/facebook/rocksdb/wiki/), [SQLite WAL](https://sqlite.org/wal.html). The suitability judgments above are engineering inferences, not benchmark results from those projects.

A useful experiment has two gates. First, compare direct LMDB against the abstracted LMDB implementation on the same release build, corpus, machine, durability settings, and corrected client harness. Then run a second backend against the same conformance and failure-recovery contracts before comparing performance. Cover warm/cold reads, replacement/deletion churn, writer saturation, large payloads, concurrent visibility changes, search misses, sync memory, p95/p99 latency, RSS, disk growth, and fsync/compaction costs. Keep the strfry control and rotate run order.

My recommendation is to fix the reproduced correctness/privacy defects and improve the benchmark gates first, then introduce only the abstraction needed to evaluate one concrete second backend. **redb is the first candidate I would investigate for the Rust/simplicity objective**, while keeping LMDB the production baseline until the evidence justifies a change.

## Reproduce the retained tests

The enabled regression tests now run normally:

```sh
cargo test -p wok-compat -p wok-db -p wok-query \
  --test review_regressions --locked --no-fail-fast -- --nocapture

cargo test -p wok-relay -p wok-ws --lib --locked --no-fail-fast \
  review_ -- --nocapture
```

The manual timing diagnostic remains ignored by default. To run it alone:

```sh
cargo test -p wok-compat --test review_regressions \
  review_benchmark_client_nagle_diagnostic -- --ignored --nocapture
```

Test files: [cross-component/Unix cases](/Users/jeff/code/wok/crates/wok-compat/tests/review_regressions.rs), [LMDB lifetime](/Users/jeff/code/wok/crates/wok-db/tests/review_regressions.rs), [search scheduling](/Users/jeff/code/wok/crates/wok-query/tests/review_regressions.rs), [writer routing](/Users/jeff/code/wok/crates/wok-relay/src/review_regressions.rs), [WebSocket cancellation](/Users/jeff/code/wok/crates/wok-ws/src/review_regressions.rs).

## Additional AUTH conformance detail found during design follow-up

[ingest_auth_inner](/Users/jeff/code/wok/crates/wok-relay/src/server.rs:1469) rejects further authentication after one key succeeds. Pinned [NIP-42](https://raw.githubusercontent.com/nostr-protocol/nips/656cecc7c0a815b6a2b218d3b5d6f078b3f4dbab/42.md) permits sequential authentication of multiple public keys and requires treating them as authenticated. The proposed common visibility/session contract should therefore support authenticated identity sets rather than embedding today's single-key assumption. This is source-confirmed follow-up evidence; it is not one of the ten retained failing regressions. Add a sequential multi-key AUTH conformance test before implementing that change, and invalidate affected sync sessions when their authorization context changes.
