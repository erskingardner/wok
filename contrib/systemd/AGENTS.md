# contrib/systemd

| File | Role |
| --- | --- |
| `wok.service` | Hardened systemd unit: User `wok`, `ProtectSystem=strict`, no new privileges, `ReadWritePaths` limited to `/var/lib/wok` and optional `/run/wok` |

`ExecStart=/usr/local/bin/wok --config /etc/wok/wok.toml relay`. Requires a readable config at `/etc/wok/wok.toml`. Tune `LimitNOFILE` with `relay.nofiles`. Unix socket, if enabled, should live under `/run/wok`.
