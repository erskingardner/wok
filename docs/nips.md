# Supported NIPs

Conformance suite pins nostr-protocol/nips at `0b5532c0355ab27f447e071a93c09cf3a2b4aad5`.

Only NIPs for which Wok implements observable **relay behavior** and has
conformance coverage are advertised in NIP-11. The authoritative typed catalog
is `wok-relay/src/capabilities.rs`; configuration cannot replace it with an
arbitrary list.

| NIP | Name | Code | Tests | Advertised when |
|---|---|---|---|---|
| 01 | Basic protocol | `wok-event`, `wok-relay`, `wok-query` | `nip_conformance.rs`, `e2e_transports.rs` | always |
| 09 | Event deletion | `wok-db` write kind 5 | db write tests | always |
| 11 | Relay information | `wok-ws` | `nip_conformance.rs` | always |
| 13 | Proof of work | leading-zero validation + NIP-11 minimum | relay tests | `relay.abuse.enabled` and `min_pow_difficulty > 0` |
| 40 | Expiration | packed expiration + cron | `nip_conformance.rs` | always |
| 42 | AUTH | ingest AUTH, multiple authenticated keys per connection, kind 22242 refused as EVENT and by CLI downloads/import, and hidden from every read | unit + multi-key e2e when serviceUrl set, `nip_conformance.rs`, `wok-cli/tests/sync.rs` | AUTH enabled and serviceUrl set |
| 45 | COUNT + mergeable HyperLogLog | REQ worker + `wok-query` HLL | `nip_conformance.rs`, `e2e_transports.rs`, HLL unit vectors | `maxFilterLimitCount > 0` |
| 50 | Search capability | transactional LMDB term index + ranked query scanner | `nip_conformance.rs`, `search.rs`, `e2e_transports.rs`, `response_prefixes.rs` | `relay.search_enabled` |
| 59 | Gift wrap | recipient-only restricted reads, recipient-authorized deletion, and live-only kind 21059 | restrict + DB/live tests | usable AUTH, kinds 1059 and 21059 in `relay.auth.recipient_only_kinds` and no stricter class, and `events.ephemeral_persistence = "live_only"` |
| 62 | Request to Vanish | persistent maximum-timestamp markers, immediate query/rebroadcast suppression, gift-wrap recipient cleanup, and bounded physical deletion | `nip62_vanish.rs`, relay e2e | `relay.nip62.enabled` |
| 67 | EOSE completeness hint | `wok-query` scan completeness and bounded peek, req worker, monitor EOSE | `nip_conformance.rs`, `completeness.rs`, `e2e_transports.rs` | always |
| 70 | Protected events | `-` tag + AUTH | `nip_conformance.rs` | always |
| 77 | Negentropy | `wok-negentropy` | protocol unit tests | `negentropy.enabled` |
| 78 | Arbitrary custom app data | kinds 78 and 30078 served only to, and accepted only from, a connection authenticated as their author | `nip_conformance.rs`, `access_model.rs` | usable AUTH and kinds 78 and 30078 in `relay.auth.owner_only_kinds` |
| 86 | Relay management API | `wok-ws` RPC + `wok-db` moderation tables + `wok-relay` enforcement | `e2e_transports.rs` | `admin.enabled` with operator pubkeys |
| 91 | AND operator in filters | `wok-query` compiled AND tags + full-event verification | matcher property tests, historical/live/COUNT conformance | both tag-filter limits are nonzero |
| D9 | Deletion Request Protection | signed marker validation + `wok-db` deletion and vanish exemptions | `nip_conformance.rs`, `e2e_transports.rs`, `deletion_protection.rs` | always |

Wok uses **NIP-D9** for **Deletion Request Protection**, following
[nostr-protocol/nips#2531](https://github.com/nostr-protocol/nips/pull/2531),
at revision `56fd3677949b9cae3fdaee403adc9e33a8de2921` (whose source still
uses the temporary name XX). NIP-11 advertises the literal string **"D9"**
in `supported_nips`, alongside integers for numeric NIPs. For example:

```json
{"supported_nips": [1, 9, 11, 40, 45, 50, 62, 67, 70, 77, 91, "D9"]}
```

Wok uses strings for lettered NIP identifiers without hexadecimal-to-integer
conversion: `"5A"` and numeric `90` remain different identifiers. This is an
interim extension to NIP-11's currently integer-only schema. Wok's outbound
sync/router discovery accepts mixed integer/string arrays, preserving each
identifier's type and spelling; numeric NIP-91 still requires integer `91`.

The landing page labels the capability NIP-D9 and links to the proposal. Clients
requiring protection must establish relay support; `OK true` alone is
insufficient. This draft is pinned separately from the main NIPs revision.

An event opts in with exactly one `["no_delete"]` tag. The tag must have no
value. Replaceable, addressable, and ephemeral events (kinds 0, 3, and
10000–39999) cannot opt in and are refused with `restricted:`. Repeated or
valued markers are refused with `invalid:`. A marked event may have one
`expiration` tag with exactly one canonical ASCII decimal u64 value, without
leading zeros except `0`; malformed or repeated expiration tags receive
`invalid:`. Wok's existing storage representation accepts explicit expiration
timestamps from 100 through `18446744073709551615`; smaller valid timestamps
on marked events receive `restricted:` rather than being reinterpreted as
the no-expiry or ephemeral sentinel. Unmarked expiration handling is unchanged.

After ID and signature verification, marked events are exempt from their
signing key's kind-5 deletion and kind-62 author purge, including existing
tombstones, events received after a request, imports, republication, live
delivery, REQ, COUNT, and NIP-77. A marker on a request protects only that
request's record, not its targets. Kinds 5 and 62 may themselves be marked.
The marker is read from the signed payload, so existing stored records and
migration bytes need no rewrite. Legacy tao-preimage IDs remain importable
but do not acquire this extension's NIP-01 protection.

Recipient gift-wrap deletion remains effective, even if the recipient and
signer are the same key. A kind-5 recipient request sweeps stored p-tagged
wraps without needing their IDs; kind-62 recipient suppression and cleanup
keep their existing timestamp semantics. Wok does not implement NIP-26
delegation, so this extension adds no delegator authority. Original NIP-40
expiration, NIP-70 `-` authentication, moderation, quotas, operator deletion,
and retention still apply. Expiration does not revoke protection against
author requests for any expired copies still retained; protection does not
promise permanent storage.

NIP-11 `limitation` also says what a client must do before it reads or writes,
as each is enforced:
- `auth_required` is `true` while `relay.auth.read_policy` is not `open` and
  AUTH can succeed, so every REQ, COUNT and NEG-OPEN needs AUTH. While AUTH is
  unusable, NIP-42 is not advertised either, and those reads are refused with
  `restricted:` rather than asking for an AUTH that cannot succeed. With
  `open`, the read classes can still need AUTH for particular kinds, as
  NIP-11 allows.
- `restricted_writes` is `true` while `relay.auth.write_policy` is not `open`,
  `relay.auth.accepted_kinds` lists the only kinds accepted, or proof of work
  is required (`min_pow_difficulty`, with abuse controls on). Rate limits,
  the NIP-86 kind blocklist and the per-kind rule for NIP-78 app data do not
  set it.

NIP-02, NIP-04, and NIP-28 event kinds are accepted and stored, but those
client/application semantics are deliberately not advertised as relay
capabilities.

ID and author filter values must be exactly 64 lowercase hexadecimal
characters, as required by current NIP-01. Prefix filters are rejected.

A subscription id is any non-empty string of at most 64 characters, as NIP-01
says, counted in Unicode characters rather than bytes, and NIP-11 advertises
it as `limitation.max_subid_length`. Frames JSON-escape it.
Subscriptions are told apart by the exact id, so two ids that look alike but
differ in code points, such as a precomposed and a decomposed `é`, are two
subscriptions.

An empty `ids`, `authors`, `kinds` or `#x` list matches no event, as NIP-01
requires; it is not treated as an absent field. Such a filter is skipped and
the request's other filters still apply. A REQ whose filters all have an empty
list gets EOSE and stays open, a COUNT reports 0, and a NEG-OPEN reconciles
against no events. Filter-validation limits still count the skipped filters.

A `#x` filter matches the values of the event's own tags. `#d:[""]` matches
events with a `d` tag of that value, and addressable events without a `d`,
whose address NIP-01 takes to be the empty string. It does not match other
replaceable or addressable events, though Wok packs an empty `d` into them to
key replacement; see [known differences](known-differences.md).

A filter with `limit: 0` returns no stored events. The subscription still gets
EOSE once its other filters have sent theirs, and stays open for new events.

Stored events are sent newest first. Events with the same `created_at` are
sent in local arrival order, not lowest id first as NIP-01 suggests; see
[known differences](known-differences.md).

EOSE carries NIP-67 hints about a REQ's stored events, those stored when it
was admitted; later ones follow EOSE as live events. A hint is sent only when
it holds, and EOSE has two elements when none does.
- `finish`: every filter ran out of matches the connection may read. A filter
  cut by its `limit` (or `relay.max_filter_limit`), or a REQ cut by
  `relay.max_total_events_per_req`, counts when a peek past the cut finds no
  match left unsent. Filters with an empty list count, as they match nothing.
- `more`: a peek past a cut found a readable match that is still unsent when
  the REQ ends (another filter may send it).
- `auth`: a [read class](config.md#read-classes) (`relay.auth`'s
  `recipient_only_kinds`, `owner_only_kinds` and `authenticated_kinds`) hid a
  match from a connection that has not authenticated, while AUTH is usable. The connection is sent its
  challenge first: on connect, or at admission if AUTH became usable later.
  Moderation, vanish, expiry and replacement never give `auth`, and neither
  does a match hidden for another pubkey once the connection has
  authenticated, which is why a refusal then says `restricted:`.
- Neither `finish` nor `more` is sent when a peek runs out of its bound (per
  REQ, about a hundred event reads and 64 read-policy checks), when AUTH, a
  reload, or a moderation, vanish or deletion commit changed the read policy
  between the scan's time slices, or for a REQ with a `limit: 0` filter unless
  another filter's peek proves `more`. `finish` is also withheld when a match
  could not be sent, such as a compressed payload larger than a lowered
  `events.max_event_size`.

NIP-67 also says a relay SHOULD include every event of the boundary
`created_at` in one response. Wok does not, for the same reason as the tie
order above; as `finish` is sent only when nothing is left, a `limit` that cuts
a same-second run never gets it.

NIP-01 replacement is enforced when reading, even if a lossless migration
retained multiple versions. Kinds 0, 3 (contact lists), and 10000–19999 select
the newest event per author and kind; kinds 30000–39999 additionally use the
first `d` tag (missing means empty). Kind 41 (NIP-28 channel metadata) is
regular, as NIP-01 makes every kind from 4 to 44. Equal timestamps select the lowest
lexical event ID. The winner is determined across stored versions before
request filters: an old ID, `until`, tag, or search filter cannot resurrect a
superseded event. An expired or moderated winner does not expose older stored
versions. REQ, COUNT, search, live delivery, and NIP-77 share this visibility
rule; live subscriptions can still receive later updates as they arrive.
Coverage is in `wok-compat/tests/replaceable_events.rs`.
New winning publications remove all older stored versions at that address in
the same transaction, including negentropy and author-quota accounting. An
incoming stale event is rejected against the global winner, independent of
local insertion order. NIP-09 `a`-tag deletions of addressable events, and of
replaceable events (named `<kind>:<pubkey>:`, with an empty `d`), remove every
matching version at or before the deletion timestamp, preserving newer
versions, and refuse such versions that arrive later. A deletion `a` tag whose
kind has leading zeros is refused with `invalid:`, so every tombstone is found
by the canonical spelling of its address.
Databases from strfry or earlier releases can still hold versions under a
deletion whose `a` tag is longer than 255 bytes, names a replaceable event, or
pads the kind with leading zeros; `wok reindex` deletes them.

Persistent negentropy trees represent physical storage. A transactional count
of retained superseded versions keeps clean databases on the persistent-tree
fast path, including databases containing profiles and contact lists. When
retained history exists, filters that can include replaceable events use the
bounded, visibility-filtered memory view, subject to sync event and memory limits. Physical
history remains intact; migration, reindex, and operator export retain their
storage-preservation semantics. A session served from a tree checks again at
each NEG-MSG that the tree is still provably public. An event stored since it
opened, such as one of a restricted kind or one that expires, can end that,
and the session then closes with `closed: visibility changed; reopen
synchronization`. A session opened while no tree is provably public is built
in memory.

NIP-50 matches normalized search terms against the first 256 unique terms of
the text of text kinds and profiles, intersects them with every other supplied
filter field, ranks before applying `limit`, and matches live events after
EOSE against the same terms. See
[NIP-50 search](nip50-search.md) for exact query and scoring semantics.

NIP-45 responses include a 512-character HLL register value for a single
filter containing exactly one tag attribute with one target. Offset derivation
implements all specified target forms: raw event/pubkey hex, an address's
pubkey, or SHA-256 of any other string. Multi-filter, multi-target, and limited
counts omit HLL because their sketches would be ambiguous or incomplete.

NIP-91 support follows the draft in
[nostr-protocol/nips#2252](https://github.com/nostr-protocol/nips/pull/2252)
at head `b93bda29d45998866e81c65e0693616294a78672`. An `&x` filter requires every
listed value to occur in an `x` tag. Values duplicated in the corresponding
`#x` compatibility filter are removed from its OR alternatives; if no OR
alternatives remain, that OR clause is omitted. Historical queries use one
required value as an index seed and verify the complete packed event. COUNT is
exact but omits the optional NIP-45 HLL sketch for filters containing `&`.

Outbound filters are adapted to the upstream. Router `REQ`s and `wok sync`
`NEG-OPEN`s forward `&` clauses only to relays whose NIP-11 document advertises
NIP-91; the document is cached per relay and is not consulted for anything
else. For every other upstream — including one that serves no usable NIP-11
document — each `&x` value set is folded into the `#x` compatibility clause the
draft requires clients to send, so the remote answers a superset. The `&`
keys are never simply dropped, which would turn an `&`-only filter into a
match-all request. The router stores only the events of that superset that
match the exact AND filter. `wok sync` reconciles its local view of the same
superset, so both sides compare like sets, then narrows each difference to the
exact filter: a local event outside it is not uploaded, and a remote one is
fetched and discarded. Those differences are counted as `narrowed`, not in
`have` or `need` (see
[reconciliation results](mesh-and-maintenance.md#reconciliation-results)).

NIP-62 accepts a signed kind 62 request containing either a matching
`["relay", "<public relay URL>"]` tag or `["relay", "ALL_RELAYS"]`. The
relay immediately suppresses the requester's unmarked events and the NIP-59 gift
wraps (kinds 1059 and 21059) that p-tag the requester, refuses them when they
are sent again, then physically deletes them in bounded background batches.
Both are covered only up to the `created_at` of the requester's newest
request: NIP-62 resets what a key published and received until then, and
does not retire the key, so events and wraps dated after it are accepted.
NIP-59 dates a wrap up to two days in the past, so a wrap sent in the two
days after a request can be dated before it and refused. The request itself
remains stored and cannot be deleted with kind 5. NIP-62 says relays MUST
honor a request that targets them, so one is accepted without proof of work,
over both storage quotas, and whatever the write policy, the write-policy
plugin or an author ban says (see
[attack-surface.md](attack-surface.md#messages)). See `relay.nip62` in the
sample configuration.
Marked events are exempt from the author portion of this purge as described
above; recipient-based gift-wrap purges still apply.

NIP-86 management calls are JSON-RPC-like POSTs to the relay URI authorized
by NIP-98 events from operator admins or role-holding moderators. They follow
NIP-86 at nips `62d5fed`, which is unchanged at the pin, without its NIP-43
claim methods. Bans suppress rather than delete; allowlists and roles make
members, who are the only readers or writers under the `members` read or write
policy (`relay.auth.read_policy`, `write_policy`); kind-1984 reports feed the moderation
queue. See [NIP-86 management](nip86.md) for levels, role semantics, and the
method table.
