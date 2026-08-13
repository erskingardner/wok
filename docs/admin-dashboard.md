# Operator dashboard

Wok can serve a small operator dashboard at `/admin`. It is disabled by
default and has no password or secret-key storage: the browser asks a NIP-07
extension to sign a fresh NIP-98 authorization event for every API request.

```toml
[admin]
enabled = true
public_url = "https://relay.example"
pubkeys = ["npub1..."]
auth_window_secs = 60
allow_config_writes = false
```

`public_url` must be the exact public HTTP(S) origin, without a path. Wok uses
it to verify the NIP-98 `u` tag instead of trusting a proxy-controlled `Host`
header. Each authorization must have kind 27235, empty content, exactly one
matching `u` and `method` tag, and a timestamp within the configured window.
Non-empty requests also require the exact SHA-256 `payload` tag. The signature
must belong to a configured administrator and an authorization event can be
used only once.

The HTML shell contains no operational data and may be fetched without
authentication. Overview data, metric history, and config APIs all require
NIP-98. The dashboard sets a restrictive content security policy and never
receives the administrator's private key.

## Configuration writes

Writes require both `allow_config_writes = true` and a relay started with an
existing TOML file. The API accepts only relay name/description, documented
request and COUNT ceilings, selected abuse guardrails, and metric-history
bounds. It cannot change database paths, listener addresses, admin keys,
plugins, or arbitrary TOML.

Before replacing the file, Wok serializes the entire next configuration and
parses it through the normal strict validator. It writes a temporary file in
the same directory, syncs it, atomically renames it over the config, and then
applies the normal live-reload rules. Keep writes disabled if the dashboard is
needed only for visibility.

Terminate TLS at Wok's reverse proxy and keep the relay clock synchronized;
NIP-98 freshness depends on both. The dashboard intentionally does not accept
CORS requests, so serve it from the same origin configured in `public_url`.
