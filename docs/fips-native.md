# Native FIPS transport

Wok can serve the Nostr relay protocol directly over the experimental FIPS
native datagram API. It does not use the `fips0` IPv6/TUN interface. Native
operation is supported on Linux, FreeBSD, and macOS; other targets keep the
transport disabled and return a platform error if it is configured on.

This integration consumes the `fips` Rust package from commit
`d69325a2a37d419328471883d3dbc21c6f2a5a3d` on the `master` branch. The
package's module is
`fips::native::client`; there is no separately packaged `fips-api` crate at
that revision.

## Configure the two daemons

Enable the native socket in the FIPS node configuration:

```yaml
node:
  native_api:
    enabled: true
```

The packaged socket default is `/run/fips/api.sock` on Linux and
`/var/run/fips/api.sock` on macOS and FreeBSD. FIPS creates it as `root:fips`
with mode `0770`, under a `root:fips` directory with mode `0750`. Give the Wok
service account supplementary membership in the `fips` group. For the sample
systemd unit, use an override rather than editing the installed file:

```ini
[Service]
SupplementaryGroups=fips
```

Then enable the Wok listener:

```toml
[relay.fips]
enabled = true
socket_path = "/run/fips/api.sock"
port = 7777
```

Use `/var/run/fips/api.sock` for packaged macOS and FreeBSD nodes.

Port 7777 is the Wok demo convention and is configurable. All
`relay.fips.*` settings require a Wok restart. FIPS application ports 0 through
1023 are reserved, so Wok rejects them.

## Protocol and lifecycle

Each accepted FIPS flow carries version 1 of the envelope specified in
[FIPS logical-message protocol V1](fips-message-v1.md). A connector retries a
correlated `HELLO` until Wok returns `READY`; it sends no `DATA` before that
response. Wok drains accepted flows promptly, dynamically chunks at
`flow.max_payload()`, bounds reassembly and outbound queues, and passes only
complete UTF-8 messages to the relay dispatcher.

`HELLO`/`READY` proves only that the FIPS flow reached Wok. FIPS V1 does not
acknowledge or retransmit `DATA`; complete Nostr commands and responses can be
lost. A missing earlier logical message expires and fails that logical session
instead of allowing later commands to overtake it.

`CLOSE`, `PING`, and `PONG` values are reserved but have no V1 behavior. Wok
does not invent peer-close or keepalive semantics: a quiet established flow
may remain open. An empty datagram is protocol input, not EOF. `EPIPE` means
the local FIPS daemon disappeared; Wok drops every existing native flow and
recreates the listener with bounded exponential backoff. Normal Wok shutdown
drops the listener and all flow descriptors.

The FIPS peer public key and port are transport metadata and an abuse-budget
principal. They are not a Nostr or Marmot user identity, and they never
satisfy or bypass NIP-42 AUTH.

## Limits

`max_reassembly_bytes`, `max_incomplete_messages`, `max_chunks`, and
`max_completed_messages` bound per-flow receive state. The logical-message
limit remains `relay.max_websocket_payload_size`; `max_reassembly_bytes` must
be at least that large when FIPS is enabled. `max_pending_outbound_bytes`
terminates a slow local flow after its Wok response queue exceeds the byte
budget. `setup_timeout_secs` bounds the initial `HELLO`; compatible connectors
should use `hello_retry_ms` as their initial retry interval.

## Docker Compose Linux integration test

The repository includes a self-contained two-node Linux lab. It builds Wok and
the FIPS daemon from the pinned commit, starts a relay FIPS node, Wok, and a
client FIPS node on a Docker bridge, then drives Wok through the client's
native socket. The test first requires a real Nostr `REQ`/`EOSE` round trip. It
then publishes correctly signed events at the minimum size, around the
negotiated FIPS chunk boundary, at 4, 16, and 32 KiB, and at Wok's 64 KiB event
limit. Every accepted event must return `OK true` and query back byte-for-byte
through Wok's canonical JSON representation. A 65,537-byte event must return
`OK false` and remain absent. This covers real bidirectional routing,
multi-datagram reassembly, storage, and the configured event-size boundary:

```sh
scripts/test-fips-compose.sh
```

The lab sets `node.native_api.pending_per_flow` to FIPS's maximum of 64 on
both nodes. A 64 KiB event is roughly 58 datagrams at the test MTU, so the
default queue of 16 would intentionally drop a burst before the local client
could drain it. Production operators should size this FIPS queue together with
Wok's event limit and expected path payload rather than copying the lab value
blindly.

The script removes its containers, network, and test volumes when it finishes.
Set `KEEP_FIPS_E2E=1` to retain a failed or successful project for inspection.
The first build is substantial because both the Wok library integration and
the FIPS daemon are compiled; Docker caches later builds.

For an interactive lab, leave the three long-running services up and invoke
the request helper with any single Nostr client message:

```sh
docker compose -f compose.fips.yml up --build -d relay-fips wok client-fips

# Default bounded REQ.
docker compose -f compose.fips.yml run --rm request

# Custom request.
docker compose -f compose.fips.yml run --rm request \
  '["REQ","manual",{"kinds":[1],"limit":10}]'

docker compose -f compose.fips.yml down --volumes
```

The lab uses deterministic secret keys committed under
`testing/fips-native/`. They are public test fixtures and must never be reused
outside this isolated Compose network. TUN and FIPS debug commands remain
disabled; the test needs no `/dev/net/tun`, host networking, or `NET_ADMIN`.

## External two-node smoke test

To exercise existing Linux, FreeBSD, or macOS nodes instead, run FIPS on two nodes
with the native API enabled. Start Wok with the listener above on node A. On
node B, use node A's FIPS npub:

```sh
scripts/fips-native-smoke.sh /run/fips/api.sock 'npub1...:7777'
```

The script runs the repository's `native-client` example, performs
`HELLO`/`READY`, sends a bounded Nostr `REQ`, and requires an `EOSE` response.
Unlike the Compose lab, this variant depends on already-running daemons and a
route between them. Success in either lab demonstrates bidirectional relay
framing and ordering for that run; it is not a reliability claim.

The pinned FIPS revision also exposes blocking read and write timeout setters
and getters. Wok deliberately continues to use nonblocking descriptors under
Tokio readiness; the manual client retries local `WouldBlock` sends with a
bounded deadline. These socket timeouts do not add acknowledgment or
retransmission semantics to FIPS V1 DATA.
