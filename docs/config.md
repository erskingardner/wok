# Configuration

Wok uses strict TOML configuration. Copy [wok.toml](wok.toml), or start with
the file produced by `wok migrate strfry`. Omitted settings inherit the
defaults below; unknown keys, wrong types, invalid admin URLs, invalid log
filters, and out-of-range history settings are rejected.

The legacy HOCON-subset reader is used only for explicit strfry migration.
It accepts named objects, arrays, and anonymous object blocks inside arrays
(for example `plugins.accept = [ { cmd = "..." } ]`). Those plugin-array
entries are reported as ignored keys; Wok translates only
`relay.writePolicy.plugin` into `relay.write_policy_plugin`. Normal startup,
validation, dashboard writes, and file watching use TOML.

## Reload and dashboard boundaries

`Live` settings are picked up by the configuration watcher and by dashboard
writes. `Restart` settings are parsed on reload but the running process keeps
the startup value. Limits marked `Live (new connections)` affect connections
created after reload. Dashboard editing additionally requires
`admin.allow_config_writes = true` and a relay started from an existing TOML
file.

The dashboard exposes nearly all safe live operator settings: relay metadata,
event acceptance, query/protocol limits, abuse controls, filter validation,
NIP-62, and local history. Database/listener/thread/socket settings are omitted
because they require restart. Admin credentials, proxy trust, authentication
policy, external plugin paths, and diagnostic logging switches remain
file-only to avoid remote self-lockout or security-boundary changes.

## Admin

| Key | Default | Reload | Dashboard | Meaning |
|---|---:|---|---|---|
| `admin.enabled` | `false` | Live | No | Serve the signed-out shell at `/admin`; APIs still require NIP-98. |
| `admin.public_url` | empty | Live | No | Exact public HTTP(S) origin used to verify the NIP-98 `u` tag. |
| `admin.pubkeys` | `[]` | Live | No | Allowed administrator npubs or lowercase hex public keys. |
| `admin.auth_window_secs` | `60` | Live | No | Accepted NIP-98 freshness window, from 1 through 300 seconds. |
| `admin.allow_config_writes` | `false` | Live | No | Permit typed, validated, atomic dashboard writes. |

The public URL must have no credentials, path, query, or fragment. Each API
request needs a new kind-27235 event with empty content, exactly one matching
`u` and `method` tag, and—when a body is present—a SHA-256 `payload` tag.
Authorization events are single-use. The browser delegates signing to NIP-07;
Wok never receives private key material.

## Database

| Key | Default | Reload | Meaning |
|---|---:|---|---|
| `database.path` | `./wok-db/` | Restart | Wok-owned LMDB directory. |
| `database.max_readers` | `256` | Restart | LMDB reader-slot ceiling. |
| `database.map_size` | `68719476736` | Restart | Maximum LMDB map size in bytes; writes fail atomically at the ceiling. |
| `database.no_read_ahead` | `false` | Restart | Disable LMDB read-ahead for workloads where it is counterproductive. |
| `database.min_free_disk_bytes` | `1073741824` | Restart | Reject durable event batches before free filesystem space falls below this reserve; zero disables the guard. |

## Event acceptance

All event settings reload live and are available in the dashboard.

| Key | Default | Meaning |
|---|---:|---|
| `events.max_event_size` | `65536` | Maximum serialized event size in bytes. |
| `events.reject_newer_than_secs` | `900` | Maximum accepted future clock skew. |
| `events.reject_older_than_secs` | `94608000` | Maximum age for non-ephemeral events. |
| `events.reject_ephemeral_older_than_secs` | `60` | Maximum age for ephemeral events at publication. |
| `events.ephemeral_lifetime_secs` | `300` | Retention window when ephemeral persistence is `ttl`. |
| `events.ephemeral_persistence` | `live_only` | `live_only` broadcasts without storage; `ttl` persists then expires. |
| `events.max_num_tags` | `2000` | Maximum tags on one event. |
| `events.max_tag_val_size` | `1024` | Maximum bytes in one tag value. |

## Observability

| Key | Default | Reload | Dashboard | Meaning |
|---|---:|---|---|---|
| `observability.log_format` | `pretty` | Restart | Human-readable `pretty` or newline-delimited `json`. |
| `observability.log_filter` | `wok=info` | Restart | tracing filter; `RUST_LOG` overrides it at startup. |
| `observability.history_enabled` | `true` | Live | Yes | Collect bounded in-memory dashboard samples. Disabling clears them. |
| `observability.history_interval_secs` | `15` | Live | Yes | Seconds between samples; must be at least 1. |
| `observability.history_max_points` | `5760` | Live | Yes | FIFO sample bound, from 0 through 100,000. |

See [Observability](observability.md) for every exported metric and label.

Note: the Prometheus endpoint `/metrics` is served on the same public
listener as client traffic, with `Access-Control-Allow-Origin: *` — any web
page can read connection, event, auth, and abuse-rejection counters
cross-origin. If the relay is internet-facing, scrape it over a private
interface or protect the path at the reverse proxy.

## Relay listener and protocol

| Key | Default | Reload | Dashboard | Meaning |
|---|---:|---|---|---|
| `relay.bind` | `127.0.0.1` | Restart | TCP listen address. |
| `relay.port` | `7777` | Restart | TCP listen port. |
| `relay.nofiles` | `524288` | Restart | Requested process file-descriptor limit. |
| `relay.real_ip_header` | empty | Live | No | Trusted proxy header containing the client IP; leave empty for direct peers. **The header is fully trusted for every per-IP budget** (connection, EVENT, REQ, COUNT): if the proxy passes the client-supplied value through instead of overwriting it, any client can rotate fake IPs to defeat rate limits and burn other IPs' budgets. A startup warning is logged whenever this is set. |
| `relay.max_websocket_payload_size` | `131072` | Restart | Maximum reassembled WebSocket payload bytes. |
| `relay.max_req_filter_size` | `65536` | Live | Yes | Maximum combined compact-JSON bytes across all filters in one REQ or COUNT. |
| `relay.max_filters_per_req` | `200` | Live | Yes | Unconditional maximum filter objects in one REQ or COUNT. |
| `relay.auto_ping_seconds` | `55` | Restart | WebSocket ping interval; zero disables automatic pings. |
| `relay.enable_tcp_keepalive` | `false` | Restart | Enable TCP keepalive on accepted sockets. |
| `relay.query_timeslice_budget_us` | `10000` | Live | Yes | Query CPU budget before cooperative yielding. |
| `relay.max_filter_limit` | `500` | Live | Yes | Maximum normal REQ filter limit. |
| `relay.max_tags_per_filter` | `3` | Live | Yes | Maximum tag query keys in one filter. |
| `relay.max_filter_limit_count` | `1000000` | Live | Yes | Maximum COUNT filter limit. |
| `relay.max_total_events_per_req` | `2000` | Live | Yes | Deduplicated historical events across a REQ; zero is unlimited. |
| `relay.max_subs_per_connection` | `200` | Live | Yes | Simultaneous subscriptions per connection. |
| `relay.max_pending_outbound_bytes` | `33554432` | Live (new connections) | Yes | Pending output budget before slow-client disconnect. |
| `relay.write_policy_plugin` | empty | Live | No | External executable for publication decisions; empty disables it. |
| `relay.write_policy_timeout_secs` | `10` | Live | Yes | Maximum wait for the configured write-policy plugin. |
| `relay.compression_enabled` | `true` | Restart | Enable permessage-deflate negotiation. |
| `relay.compression_sliding_window` | `true` | Restart | Reuse compression context between messages. With context takeover, a connection's compressor can reference bytes from previous messages — the precondition structure for CRIME/BREACH-style oracles when secret and attacker-influenced bytes share a compression context. Relay traffic is essentially all public data, so practical impact is nil for most operators; if you serve auth-bearing or otherwise secret traffic over the same client connections, prefer `false`. |
| `relay.dump_in_all` | `false` | Live | No | Diagnostic logging for every inbound client message. |
| `relay.dump_in_events` | `false` | Live | No | Diagnostic logging for inbound EVENT messages. |
| `relay.dump_in_reqs` | `false` | Live | No | Diagnostic logging for inbound REQ messages. |
| `relay.db_scan_perf` | `false` | Live | No | Emit database scan performance diagnostics. |
| `relay.invalid_events` | `true` | Live | No | Log invalid-event diagnostics. |
| `relay.ingester_threads` | `3` | Restart | Event-ingestion worker count. |
| `relay.req_worker_threads` | `3` | Restart | Historical query worker count. |
| `relay.req_monitor_threads` | `3` | Restart | Query monitor worker count. |
| `relay.negentropy_threads` | `2` | Restart | Negentropy worker count. |
| `relay.negentropy_enabled` | `true` | Live | Yes | Enable and advertise NIP-77 synchronization. |
| `relay.max_sync_events` | `1000000` | Live | Yes | Event ceiling for one Negentropy synchronization. |

## Authentication and private reads

These settings reload live but stay file-only because they define an access
control boundary.

| Key | Default | Meaning |
|---|---:|---|
| `relay.auth.enabled` | `true` | Enable NIP-42 authentication. |
| `relay.auth.service_url` | empty | Public relay URL placed in and checked against AUTH challenges. |
| `relay.auth.restricted_read_kinds` | `[4, 1059]` | Kinds hidden from unauthenticated historical reads. |
| `relay.auth.restrict_read_to_involved_pubkey` | `true` | Restrict authenticated reads to the author or first `p`-tag recipient. |

Private reads fail closed until `service_url` is configured. Clearing
`restricted_read_kinds` restores unrestricted history, but Wok stops
advertising NIP-59.

Keep `restrict_read_to_involved_pubkey` at `true` unless you understand the
interplay: with `false`, the per-event delivery filter is skipped entirely
and the REQ-level auth gate only fires for filter groups where **every**
filter is restricted. A mixed REQ such as `[{"kinds":[1]},{"kinds":[1059]}]`
then returns gift wraps to an unauthenticated client (strfry-compatible
behavior).

## Relay information

All fields reload live and are dashboard-editable. They are returned in NIP-11
and presented on the landing page: banner and icon as media, and identity,
contact, and policy values in the Relay information section.

| Key | Default | Meaning |
|---|---:|---|
| `relay.info.name` | `wok default` | Relay display name. |
| `relay.info.description` | `This is a wok instance.` | Public relay description. |
| `relay.info.pubkey` | empty | Operator public key. |
| `relay.info.self_pk` | empty | Relay public key published as NIP-11 `self`. |
| `relay.info.contact` | empty | Operator contact. |
| `relay.info.icon` | empty | Square icon URL. |
| `relay.info.banner` | empty | Wide banner image URL. |
| `relay.info.privacy` | empty | Privacy-policy URL. |
| `relay.info.terms` | empty | Terms-of-service URL. |

`relay.info.nips` intentionally does not exist. Supported NIPs are derived
from compiled behavior and feature settings so metadata cannot claim
unimplemented behavior.

## NIP-62

| Key | Default | Reload | Dashboard | Meaning |
|---|---:|---|---|---|
| `relay.nip62.enabled` | `true` | Live | Yes | Advertise and process Request to Vanish. |
| `relay.nip62.service_url` | empty | Live | Yes | Target URL; falls back to `relay.auth.service_url`. |
| `relay.nip62.deletion_batch_size` | `1000` | Live | Yes | Records physically removed per restart-safe transaction. |

`ALL_RELAYS` always matches. Valid requests are hidden immediately, deletion
markers remain enforced if the feature is later disabled, and physical removal
continues in bounded batches.

## Filter validation

| Key | Default | Reload | Dashboard | Meaning |
|---|---:|---|---|---|
| `relay.filter_validation.enabled` | `false` | Live | Yes | Apply the rules in this section. |
| `relay.filter_validation.max_filters_per_req` | `3` | Live | Yes | Maximum filter objects in a REQ. |
| `relay.filter_validation.min_filters_per_req` | `1` | Live | Yes | Minimum filter objects in a REQ. |
| `relay.filter_validation.max_kinds_per_filter` | `3` | Live | Yes | Maximum kinds listed by one filter. |
| `relay.filter_validation.allowed_kinds` | empty | Live | Yes | Comma-separated allowed kinds; empty permits all. |
| `relay.filter_validation.require_author_or_tag` | `false` | Live | Yes | Require an author or tag constraint in each filter. |

## Abuse protection

All abuse settings reload live and are dashboard-editable.

| Key | Default | Meaning |
|---|---:|---|
| `relay.abuse.enabled` | `true` | Enable this protection layer. |
| `relay.abuse.connection_rate_per_second` | `10` | Refilled connection tokens per network address each second. |
| `relay.abuse.connection_burst` | `50` | Connection token-bucket capacity. |
| `relay.abuse.event_rate_per_second` | `50` | Refilled EVENT tokens per connection each second. |
| `relay.abuse.event_burst` | `100` | Per-connection EVENT bucket capacity. |
| `relay.abuse.pubkey_event_rate_per_second` | `25` | Refilled publication tokens per event author each second. |
| `relay.abuse.pubkey_event_burst` | `50` | Per-author publication bucket capacity. |
| `relay.abuse.req_rate_per_second` | `20` | Refilled REQ tokens per connection each second. |
| `relay.abuse.req_burst` | `40` | Per-connection REQ bucket capacity. |
| `relay.abuse.count_rate_per_second` | `5` | Refilled COUNT tokens per connection each second. |
| `relay.abuse.count_burst` | `10` | Per-connection COUNT bucket capacity. |
| `relay.abuse.max_concurrent_historical_queries` | `8` | Historical scans per connection; zero rejects new scans. |
| `relay.abuse.max_query_cost` | `1000` | Conservative pre-scan filter cost ceiling; zero is unlimited. |
| `relay.abuse.max_stored_events` | `10000000` | Global durable event ceiling; the entire write transaction aborts before exceeding it. |
| `relay.abuse.max_stored_events_per_pubkey` | `100000` | Hard author storage quota; zero is unlimited. |
| `relay.abuse.min_pow_difficulty` | `0` | Required NIP-13 leading-zero bits; zero disables it. |

A zero rate or burst disables that individual token bucket. Unix-socket
connections carry no network address (an empty IP), so by design they bypass
every per-IP token bucket — connection, EVENT, REQ, and COUNT. Per-author
publication, storage quotas, query-cost gates, and proof-of-work policies
still apply to them. Keep the socket on a trusted host with tight
`mode`/`auth_uids`/`auth_gids`.

## Unix socket

All Unix-socket settings require restart and are file-only.

| Key | Default | Meaning |
|---|---:|---|
| `relay.unix.enabled` | `false` | Listen on the local framed-JSON Unix socket. |
| `relay.unix.path` | `./wok-db/wok.sock` | Socket filesystem path. |
| `relay.unix.mode` | `0o600` | Permission bits, as TOML octal or decimal. |
| `relay.unix.owner` | empty | User applied with `chown` after bind. |
| `relay.unix.group` | empty | Group applied with `chown` after bind. |
| `relay.unix.auth_uids` | `[]` | Allowed peer UIDs; empty accepts any UID. |
| `relay.unix.auth_gids` | `[]` | Allowed peer GIDs; empty accepts any GID. |
| `relay.unix.max_frame_bytes` | `131072` | Maximum length-prefixed JSON frame. |
| `relay.unix.max_pending_outbound_bytes` | `33554432` | Pending output budget before disconnect. |

See [Unix socket protocol](unix-socket.md) for framing and peer authorization.
