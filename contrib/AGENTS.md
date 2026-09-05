# contrib/

Packaging and deployment extras that are not part of the Cargo workspace.

| Path | Role |
| --- | --- |
| `systemd/` | Example `wok.service` unit |
| `lab/` | Relay/load Docker image, Compose services, benchmark fixture |

Relay configuration still comes from `/etc/wok/wok.toml` (or `--config`). See `docs/production-deployment.md` and `docs/config.md`.
