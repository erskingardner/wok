#!/usr/bin/env bash
set -euo pipefail

WOK_SERVICE='relay-bench-wok.service'
STRFRY_SERVICE='relay-bench-strfry.service'
WOK_DB_ROOT=/var/lib/relay-bench/wok
STRFRY_DB_ROOT=/var/lib/relay-bench/strfry
WOK_CONFIG=/etc/relay-bench/wok.toml
STRFRY_CONFIG=/etc/relay-bench/strfry.conf
PRIVATE_ENDPOINT=10.0.0.3:7777

require_root() {
    if [[ ${EUID} -ne 0 ]]; then
        echo "benchmark relay control must run as root" >&2
        exit 1
    fi
}

select_relay() {
    local relay=$1
    case "$relay" in
        wok)
            SERVICE=$WOK_SERVICE
            DB_ROOT=$WOK_DB_ROOT
            CONFIG=$WOK_CONFIG
            SERVICE_USER=wokbench
            BINARY=$(service_binary "$SERVICE")
            ;;
        strfry)
            SERVICE=$STRFRY_SERVICE
            DB_ROOT=$STRFRY_DB_ROOT
            CONFIG=$STRFRY_CONFIG
            SERVICE_USER=strfrybench
            BINARY=$(service_binary "$SERVICE")
            ;;
        *)
            echo "relay must be wok or strfry" >&2
            exit 2
            ;;
    esac
    if [[ ! -x $BINARY || ! -f $CONFIG ]]; then
        echo "missing benchmark binary or config for $relay" >&2
        exit 1
    fi
}

service_binary() {
    local service=$1
    systemctl show "$service" -p ExecStart --value | \
        sed -n 's/^.*path=\([^ ;}]*\).*$/\1/p'
}

stop_all() {
    systemctl stop "$WOK_SERVICE" "$STRFRY_SERVICE"
}

assert_benchmark_path() {
    local path=$1
    case "$path" in
        /opt/relay-bench/campaigns/* | /opt/relay-bench/results/*) ;;
        *)
            echo "refusing non-benchmark path: $path" >&2
            exit 1
            ;;
    esac
}

reset_import() {
    local relay=$1
    local corpus=$2
    local expected=$3
    local artifacts=$4
    select_relay "$relay"
    assert_benchmark_path "$corpus"
    assert_benchmark_path "$artifacts"
    if [[ ! -f $corpus || ! $expected =~ ^[1-9][0-9]*$ ]]; then
        echo "invalid corpus or expected event count" >&2
        exit 1
    fi

    stop_all
    install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$DB_ROOT"
    find "$DB_ROOT" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
    # Both benchmark configs place LMDB inside a `db` child. Wok creates it,
    # while strfry requires the directory to exist before mdb_env_open.
    install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$DB_ROOT/db"
    install -d -m 0750 "$artifacts"

    {
        echo "relay=$relay"
        echo "service=$SERVICE"
        echo "binary=$BINARY"
        echo "config=$CONFIG"
        echo "corpus=$corpus"
        echo "expected_events=$expected"
        echo "source_commit=$(git -c safe.directory=/opt/relay-bench/src/wok -C /opt/relay-bench/src/wok rev-parse HEAD 2>/dev/null || true)"
        uname -a
        lscpu
        free -b
        lsblk -b -o NAME,TYPE,SIZE,ROTA,MODEL,MOUNTPOINTS
    } >"$artifacts/provenance.txt"
    sha256sum "$BINARY" "$CONFIG" "$corpus" >"$artifacts/sha256.txt"

    /usr/bin/time -v -o "$artifacts/import-time.txt" \
        runuser -u "$SERVICE_USER" -- "$BINARY" --config "$CONFIG" import \
        <"$corpus" >"$artifacts/import.stdout" 2>"$artifacts/import.stderr"

    local retained
    retained=$(runuser -u "$SERVICE_USER" -- "$BINARY" --config "$CONFIG" export | awk 'NF { count += 1 } END { print count + 0 }')
    echo "$retained" >"$artifacts/retained-events.txt"
    if [[ $retained -ne $expected ]]; then
        echo "$relay retained $retained/$expected events" >&2
        exit 1
    fi
    sync
    du -sb "$DB_ROOT" >"$artifacts/database-size-after-import.txt"
}

start_measurement() {
    local relay=$1
    local artifacts=$2
    select_relay "$relay"
    assert_benchmark_path "$artifacts"
    install -d -m 0750 "$artifacts"
    stop_all
    # Some systemd versions report an inactive, never-failed unit as not
    # loaded here. Clearing stale failure state is useful but not required.
    systemctl reset-failed "$SERVICE" 2>/dev/null || true
    systemctl start "$SERVICE"

    local ready=0
    for _ in $(seq 1 100); do
        if ss -ltn | grep -Fq "$PRIVATE_ENDPOINT"; then
            ready=1
            break
        fi
        sleep 0.1
    done
    if [[ $ready -ne 1 ]]; then
        systemctl status "$SERVICE" --no-pager -l >&2 || true
        exit 1
    fi

    local main_pid
    main_pid=$(systemctl show "$SERVICE" -p MainPID --value)
    echo "$main_pid" >"$artifacts/main.pid"
    systemctl show "$SERVICE" >"$artifacts/systemd-before.properties"
    nstat -az >"$artifacts/nstat-before.txt"
    curl --fail --silent --show-error http://127.0.0.1:9100/metrics \
        >"$artifacts/node-metrics-before.prom" || true
    nohup pidstat -h -r -u -d -w -p "$main_pid" 1 \
        >"$artifacts/pidstat.txt" 2>&1 &
    echo $! >"$artifacts/pidstat.pid"
}

collect_stop() {
    local relay=$1
    local artifacts=$2
    select_relay "$relay"
    assert_benchmark_path "$artifacts"
    if [[ -f $artifacts/pidstat.pid ]]; then
        kill "$(<"$artifacts/pidstat.pid")" 2>/dev/null || true
    fi
    curl --fail --silent --show-error "http://$PRIVATE_ENDPOINT/metrics" \
        >"$artifacts/relay-metrics.prom" || true
    curl --fail --silent --show-error http://127.0.0.1:9100/metrics \
        >"$artifacts/node-metrics-after.prom" || true
    nstat -az >"$artifacts/nstat-after.txt"
    ss -s >"$artifacts/socket-summary.txt"
    systemctl show "$SERVICE" >"$artifacts/systemd-after.properties"
    journalctl -u "$SERVICE" --since "$(systemctl show "$SERVICE" -p ExecMainStartTimestamp --value)" \
        --no-pager >"$artifacts/journal.log"
    du -sb "$DB_ROOT" >"$artifacts/database-size-final.txt"
    systemctl stop "$SERVICE"
    systemctl show "$SERVICE" >"$artifacts/systemd-stopped.properties"
}

status_report() {
    systemctl is-active "$WOK_SERVICE" 2>/dev/null || true
    systemctl is-active "$STRFRY_SERVICE" 2>/dev/null || true
    ss -ltnp | grep -F "$PRIVATE_ENDPOINT" || true
}

require_root
command=${1:-}
case "$command" in
    reset-import)
        [[ $# -eq 5 ]] || { echo "usage: $0 reset-import RELAY CORPUS EVENTS ARTIFACTS" >&2; exit 2; }
        reset_import "$2" "$3" "$4" "$5"
        ;;
    start)
        [[ $# -eq 3 ]] || { echo "usage: $0 start RELAY ARTIFACTS" >&2; exit 2; }
        start_measurement "$2" "$3"
        ;;
    collect-stop)
        [[ $# -eq 3 ]] || { echo "usage: $0 collect-stop RELAY ARTIFACTS" >&2; exit 2; }
        collect_stop "$2" "$3"
        ;;
    stop-all)
        stop_all
        ;;
    status)
        status_report
        ;;
    *)
        echo "usage: $0 {reset-import|start|collect-stop|stop-all|status}" >&2
        exit 2
        ;;
esac
