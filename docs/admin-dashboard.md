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

## Configuration writes

Writes require both `allow_config_writes = true` and a relay started with an
existing TOML file. The dashboard exposes these safe live-reload groups:

- relay identity and NIP-11 metadata;
- event size, timestamp, tag, and ephemeral persistence policy;
- REQ, COUNT, subscription, queue, plugin-timeout, and Negentropy limits;
- abuse rates, bursts, concurrency, cost, quota, and proof-of-work controls;
- structural filter validation;
- NIP-62 behavior and deletion batch size;
- bounded in-memory dashboard history.

Every control includes a subtitle describing its behavior. When writes are
disabled, values remain visible but inputs and the save button are disabled.

The dashboard deliberately excludes database, bind/port, worker, compression,
and Unix-socket settings because they require restart. It also excludes admin
keys and URLs, reverse-proxy trust, read-auth policy, plugin executable paths,
and diagnostic logging switches because changing them remotely can create a
self-lockout, trust-boundary change, or process-execution risk. Edit those in
`wok.toml`; the full inventory and reload behavior are in
[Configuration](config.md).

Before replacing the file, Wok serializes the complete next configuration and
parses it through the normal strict validator. It writes a temporary file in
the same directory, preserves permissions, syncs it, atomically renames it over
the configuration, syncs the directory, and then applies normal live-reload
rules. Keep writes disabled if the dashboard is needed only for visibility.

Terminate TLS at the reverse proxy and keep the relay clock synchronized;
NIP-98 freshness depends on both. Serve the dashboard from the same origin set
in `public_url`.
