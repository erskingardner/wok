# Production deployment security

Run Wok as a dedicated, unprivileged account and put TLS and public HTTP policy
in a maintained reverse proxy. The example
[`wok.service`](../contrib/systemd/wok.service) limits writable paths to its
state directory, runtime directory, and private temporary directory; removes
Linux capabilities; blocks privilege gain; hides home and device access; and
restricts address families to TCP/IP and Unix sockets.

## Install the service

The following is a reference layout for a Linux host using systemd. Review the
commands and paths for the distribution before running them.

```sh
cargo build --release --locked
sudo useradd --system --home-dir /var/lib/wok --shell /usr/sbin/nologin wok
sudo install -o root -g root -m 0755 target/release/wok /usr/local/bin/wok
sudo install -d -o root -g wok -m 0750 /etc/wok
sudo install -o root -g wok -m 0640 docs/wok.toml /etc/wok/wok.toml
sudo install -d -o wok -g wok -m 0700 /var/lib/wok
sudo install -o root -g root -m 0644 contrib/systemd/wok.service /etc/systemd/system/wok.service
```

The sample selects the preset and shows, commented out, the settings most
relays must set; every other setting comes from the preset, so upgrades
bring improved defaults. Add only the settings
this relay needs, and after an upgrade run `wok doctor`: its
`config-defaults` check names settings pinned to a default the preset has
since replaced, its `config-public-values` check names settings that keep
the `public` preset's value under a preset that replaces it, and its
`config-deprecations` check names settings a release replaced, which
`wok config minimize` rewrites. See
[Set only overrides](config.md#set-only-overrides).

Set at least these deployment-specific values in `/etc/wok/wok.toml`, with
the relay's real public URL and details:

```toml
[database]
path = "/var/lib/wok/db"

[relay]
bind = "127.0.0.1"

[relay.auth]
service_url = "wss://relay.example.com"

[relay.info]
name = "Example relay"
contact = "mailto:ops@example.com"

[relay.unix]
path = "/run/wok/relay.sock"
```

Binding to loopback assumes a local reverse proxy. If the proxy is on another
host, bind to an explicitly firewalled private address. Set
`relay.real_ip_header` only when every direct connection is from a trusted
proxy that writes the client's address as that header's last entry, as one
that replaces the header or appends to it does. For an RFC 7239 `Forwarded`
header, set it to `forwarded`. List the proxy in `relay.trusted_proxies`
(`["127.0.0.1", "::1"]` for one on the same host) so that a connection from
anywhere else is its own address; behind a CDN and then the proxy, add the
CDN's published ranges. Before enabling those features, set
`relay.auth.service_url` to the URL clients connect to, scheme and path
included (`wss://relay.example.com/nostr` when the proxy publishes the relay
under `/nostr`), and `admin.public_url` to the exact external HTTPS origin.
Wok serves the relay only at `/`, NIP-01's single endpoint, so a proxy that
publishes it under a path prefix must strip the prefix before forwarding.

Validate and start the service:

```sh
sudo -u wok /usr/local/bin/wok --config /etc/wok/wok.toml doctor
sudo systemctl daemon-reload
sudo systemctl enable --now wok
sudo systemctl status wok
```

The sample unit deliberately makes `/etc/wok` read-only to Wok. Keep
`admin.allow_config_writes = false` with this layout and deploy configuration
changes as root. Wok's watcher applies supported live settings after the file
is replaced. If dashboard writes are required, move the configuration to a
separately scoped writable path and change `ExecStart`; doing so expands the
impact of a compromised admin credential.

## Filesystem and database policy

- Keep the binary, service unit, configuration, and plugin executables owned
  by root and not writable by the `wok` account.
- Keep `/var/lib/wok` mode `0700` and owned by `wok:wok`. Do not let another
  service open the live LMDB environment for writes.
- Size `database.map_size`, `database.min_free_disk_bytes`, and the global and
  per-pubkey storage ceilings for the host. Alert before the disk reserve or
  map ceiling is reached.
- Back up with a filesystem snapshot or another LMDB-safe procedure. Never
  copy live LMDB files independently and assume the pair is consistent.
- Run `wok doctor` after an unclean stop and before returning the instance to
  service. Run `wok integrity` periodically and retain its exit status.

## LMDB semaphores on macOS

On macOS, lmdb-sys builds LMDB with `MDB_USE_POSIX_SEM`. Every open
environment creates two named POSIX semaphores (`/MDBr<hash>` and
`/MDBw<hash>`, hashed from the `lock.mdb` device and inode). LMDB unlinks them
only in `mdb_env_close` in the last process using the environment, or when a
later exclusive open of the same `lock.mdb` file clears stale names. Linux
builds use robust mutexes inside `lock.mdb` and are not affected.

A process that exits with an `Env` still open leaks both semaphores until
reboot. Causes include `kill -9`, a panic in a release build
(`panic = "abort"`), `process::exit`, and relay threads that are still running
at exit. A live relay database reclaims its own pair the next time it opens.
Leaks accumulate when the lock file is gone: test temp directories, deleted
scratch databases, replaced migration outputs. macOS cannot list these
semaphores, and their names cannot be recomputed once the inode is gone.

The table is system-wide (`sysctl kern.posix.sem.max`, default 10000). When it
fills up, every `Env::open` fails with `Lmdb(28, "No space left on device")`
(ENOSPC from `sem_open`) even when disk and memory are free. Remedies:

- Reboot. This clears all named semaphores.
- Or raise the limit until the next reboot:
  `sudo sysctl -w kern.posix.sem.max=20000`.

Wok closes its environments on a clean stop. `wok relay` joins every relay
thread after SIGINT, SIGTERM, or SIGUSR1
(`RelayHandle::shutdown_and_join`). Dropping the last `RelayHandle` also stops
and joins the threads, so tests that start a relay release their `Env` before
they return. Code that starts a relay must not leak a handle (`mem::forget`,
a detached task that never ends) or keep its own `Env` clone past shutdown.

## Write-policy plugins

The write-policy command is trusted operator configuration and currently runs
through `sh -c` for strfry migration compatibility. Event JSON is sent on the
child's standard input and is never interpolated into that command, but the
child still runs as the `wok` user inside the relay's systemd sandbox.

NIP-62 requires relays that restrict who can post to honor vanish requests
regardless of the user's status. The plugin is not consulted for them, and
neither pubkey bans nor `relay.auth.write_policy` refuse them, so an author
who was rejected by the plugin, dropped from the allowlist, or banned can still
erase what they published. Vanish requests still pay proof of work and the
per-author EVENT budget, and event-id bans, the kind allowlist, and
`relay.nip62.enabled` still apply.

Use an absolute command, keep the executable and its dependencies root-owned,
and avoid shell substitutions or writable script directories. The plugin must
emit one bounded JSON record per decision; malformed output, exit, I/O failure,
or timeout rejects the event. For a plugin that processes complex untrusted
formats or needs additional network/filesystem access, place the policy engine
behind a separately sandboxed local service and keep the relay-side plugin as
a minimal protocol adapter. Extend the unit's sandbox only for the exact path
or address family that adapter requires.

Each request is one JSON line with `type` (`"new"`), `event`, `receivedAt`,
`sourceType` and `sourceInfo`: `IP4` or `IP6` with the client's address, or
`unix` with an empty string. `unix` names the transport, not a trusted
caller: any local user the socket's `mode`, `auth_uids` and `auth_gids` let in
gets it (see [Unix socket](unix-socket.md)). `authed`, the author's pubkey in
hex, is present only for a NIP-70 protected event or a kind in
`relay.auth.owner_only_kinds`, which Wok accepts only from a connection
authenticated as their author and checks before the plugin runs. It is absent
for every other event, even from a connection that authenticated, so it does
not tell a plugin who is logged in: a deny-list keyed on it would let every
other event through. Decide on `event.pubkey`, which the signature proves.
strfry's plugin documentation says `authed` is present whenever the connection
authenticated, but pinned strfry also sets it only for protected events.

A `reject` record's `msg` becomes the OK reason the client sees. Start it with
a NIP-01 prefix such as `blocked:` or `rate-limited:`. Wok sends any other
message as `blocked: <msg>`, and an empty one as
`blocked: rejected by write policy`. A `shadowReject` keeps its `msg` only when
it is prefixed; otherwise the client gets the empty reason of an accepted event.

## Logs and user content

Prefer `observability.log_format = "json"` in production and send stdout/stderr
to a log collector with retention and rate limits. Remote relay notices and
plugin diagnostic fields are recorded as escaped structured values. Diagnostic
payload logging remains disabled by default; enabling `relay.dump_in_all`,
`relay.dump_in_events`, or `relay.dump_in_reqs` can place user content and
sensitive metadata in logs, so use it briefly and restrict access to the
resulting records.

Do not expose the admin page or metrics endpoint directly to the Internet.
Apply authentication and network policy at the reverse proxy in addition to
Wok's NIP-98 admin authorization. Metrics are off by default; to scrape them,
set `observability.metrics_enabled` and serve them on a private address with
`observability.metrics_listen` rather than on the relay listener.
