#!/usr/bin/env bash
# Explicit opt-in for clean, disposable Debian hosts. Never replace an engine.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Bootstrap requires root SSH; existing Docker hosts need no bootstrap.' >&2; exit 1; }
if command -v docker >/dev/null; then
    docker compose version
    docker info >/dev/null
    exit 0
fi
# shellcheck source=/dev/null
source /etc/os-release
[[ $ID == debian && ($VERSION_CODENAME == bookworm || $VERSION_CODENAME == trixie) ]] || {
    echo 'Bootstrap supports clean Debian 12/13 only.' >&2; exit 1;
}
for package in docker.io docker-compose docker-doc docker-buildx podman-docker containerd runc; do
    if [[ $(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true) == 'install ok installed' ]]; then
        echo "Refusing to replace existing $package; prepare Docker separately." >&2; exit 1
    fi
done
[[ ! -e /etc/apt/sources.list.d/docker.sources && ! -e /etc/apt/keyrings/docker.asc ]] || {
    echo 'Existing Docker repository configuration; inspect it before bootstrap.' >&2; exit 1;
}
apt-get update
apt-get install -y ca-certificates curl
install -m 0755 -d /etc/apt/keyrings
curl --fail --silent --show-error --location https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
cat > /etc/apt/sources.list.d/docker.sources <<SOURCES
Types: deb
URIs: https://download.docker.com/linux/debian
Suites: $VERSION_CODENAME
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
SOURCES
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker
docker compose version
docker info >/dev/null
