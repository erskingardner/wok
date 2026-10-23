# Operator dashboard

Wok can serve an operator dashboard at `/admin`. It is disabled by default.
When enabled, the initial page is an explicit signed-out screen and contains
no operational data. Selecting **Sign in with Nostr** asks a NIP-07 extension
for a fresh NIP-98 signature; only a successful authenticated overview request
reveals the dashboard.

```toml
[admin]
enabled = true
public_url = "https://relay.example"
pubkeys = ["npub1..."]
auth_window_secs = 60
allow_config_writes = false
```

`public_url` must be the exact public HTTP(S) origin, without a path. Wok uses
it to verify the NIP-98 `u` tag instead of trusting a proxy-controlled
`Host` header. Each authorization must have kind 27235, empty content,
exactly one matching `u` and `method` tag, and a timestamp inside the
configured window. Non-empty requests also require the exact SHA-256
`payload` tag. The signer must be an allowed administrator and an
authorization event can be used only once. The dashboard adds a random nonce
tag to every request so two actions signed during the same second still have
different event IDs.

Overview and configuration APIs always require authentication. The shell sets
a restrictive content security policy, does not make cross-origin requests,
and never receives the administrator's private key. Refresh and save are
explicit actions because each API call needs a new signature. **Sign out**
clears the dashboard state in that browser and returns to the signed-out view.

## Posture and access

The top of the dashboard says what the relay lets clients do:

- the active preset, with what it is for;
- how many settings the config file overrides, relative to that preset;
- a few generated sentences: who can read and write, which kinds the relay
  accepts, which kinds it shows only to their recipient or author, whether
  filters must be scoped, and each connection's query budget.

When the file on disk cannot be parsed, or its preset cannot serve it (a
`marmot` file without a usable `relay.auth.service_url`), the card says so:
the relay refused that file and kept its last configuration.

The card also sums what the relay refused over the last 24 hours, by the
setting that refused it (`wok_refusals_total{setting}`, see
[Refusals by setting](observability.md#refusals-by-setting)), and names the
three settings that refused most. The **Refused** tile beside the
connection count shows the same total. Counts restart with the process: for
its first day the window is the time since it started. Refusals that no
setting makes, such as a NIP-86 ban, are not counted.

**Access** comes first among the settings and is read-only: the read and
write policies with what each means, the three read classes and the kinds in
each, `inbox_kinds`, the kinds the relay accepts, whether login (NIP-42) is
available, and the NIP-11 `auth_required` and `restricted_writes` flags they
imply, with what each refused over the last day. Edit these in `wok.toml`;
a remote save cannot change who may use the relay or lock its operator out.

## Configuration writes

Writes require both `allow_config_writes = true` and a relay started with an
existing TOML file. The settings follow in the order an operator decides
them:

- **Events accepted**: size, tags, timestamp windows, ephemeral storage,
  proof of work and NIP-62;
- **Queries**: filter and result sizes, subscriptions, the query work
  ceiling, concurrency and the `filter_validation` rules;
- **Rates**: every token bucket, per connection and per address, and the
  IPv6 network size;
- **Storage**: the per-author and global quotas;
- **Sync**: NIP-77 and its memory and size budgets;
- **Relay information**: NIP-11 metadata;
- **Advanced**: the query time slice, the outbound queue, the write-policy
  plugin's timeout, vanish deletion batches and this dashboard's history.

Each field shows what it does and, for limits, what breaks when it is set too
low and too high. Sizes take B, KiB, MiB or GiB, and durations seconds to
years. A limit that zero turns off has an **Off** switch. A token bucket
shows its rate per second and its burst together. A few values set only in
the file are shown with their running value and marked `wok.toml`: the
client address header (`relay.real_ip_header`), which every per-address
budget trusts, and three restart-only values, the largest WebSocket message,
the disk reserve and the database size limit.
When writes are disabled, values remain visible but inputs and the save
button are disabled.

Below its copy, a field shows:

- **Override**, when the value differs from the preset's, with the preset's
  value and **Reset to preset**, which puts the preset's value back in the
  form; saving then removes the setting from the file;
- a `NIP-11: <field>` chip for each `limitation` field that advertises the
  value right now, so a chip disappears while its limit is off;
- what the setting refused over the last 24 hours, when it refused anything;
- the warning the relay logs on reload when the file sets the guard to zero,
  which turns it off, while its preset does not. A guard with no field of its
  own, such as `relay.handshake_timeout_secs`, is warned about on the posture
  card.

The dashboard deliberately excludes database, bind/port, worker, compression,
and Unix-socket settings because they require restart. It also excludes the
access settings above, admin keys and URLs, reverse-proxy trust, plugin
executable paths, and diagnostic logging switches because changing them
remotely can create a self-lockout, trust-boundary change, or
process-execution risk. Edit those in `wok.toml`; the full inventory and
reload behavior are in [Configuration](config.md).

A save edits the file on disk in place, so hand-written comments and layout
survive. The page sends only the fields changed since it loaded, so a save
from a tab opened earlier does not undo settings changed since. Wok reads the
file, applies those fields to the file's own configuration, and touches only
the settings whose value changed: a changed setting is
rewritten where it is, a new one goes at the end of its table, and one set
back to its preset's value is removed, so the file holds overrides only (see
[Set only overrides](config.md#set-only-overrides)). The file's `preset` is
kept. Wok then parses the edited file through the normal strict validator,
writes it to a temporary file in the same directory with the same
permissions, syncs it, atomically renames it over the configuration, syncs
the directory, and applies normal live-reload rules. A save that changes
nothing leaves the file untouched, and a file that no longer parses is
refused rather than overwritten. A save the relay could not serve, such as
one to a `marmot` file without a usable `relay.auth.service_url`, is refused
with nothing written, and the page shows the reason under **Not saved**.
Keep writes disabled if the dashboard is needed only for visibility.

Terminate TLS at the reverse proxy and keep the relay clock synchronized;
NIP-98 freshness depends on both. Serve the dashboard from the same origin set
in `public_url`.
