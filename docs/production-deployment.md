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

Set at least these deployment-specific values in `/etc/wok/wok.toml`:

```toml
[database]
path = "/var/lib/wok/db"

[relay]
bind = "127.0.0.1"

[relay.unix]
path = "/run/wok/relay.sock"
```

Binding to loopback assumes a local reverse proxy. If the proxy is on another
host, bind to an explicitly firewalled private address. Set
`relay.real_ip_header` only when every direct connection is from a trusted
proxy that overwrites that header. Configure `relay.auth.service_url` and
`admin.public_url` with the exact external HTTPS origins before enabling those
features.

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

## Write-policy plugins

The write-policy command is trusted operator configuration and currently runs
through `sh -c` for strfry migration compatibility. Event JSON is sent on the
child's standard input and is never interpolated into that command, but the
child still runs as the `wok` user inside the relay's systemd sandbox.

Use an absolute command, keep the executable and its dependencies root-owned,
and avoid shell substitutions or writable script directories. The plugin must
emit one bounded JSON record per decision; malformed output, exit, I/O failure,
or timeout rejects the event. For a plugin that processes complex untrusted
formats or needs additional network/filesystem access, place the policy engine
behind a separately sandboxed local service and keep the relay-side plugin as
a minimal protocol adapter. Extend the unit's sandbox only for the exact path
or address family that adapter requires.

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
Wok's NIP-98 admin authorization, and scrape metrics over a private interface
or authenticated proxy route.
