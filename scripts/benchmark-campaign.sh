#!/usr/bin/env bash
# The command strings below are deliberately rendered on the operator host and
# then executed remotely; quoting is handled by printf %q.
# shellcheck disable=SC2029
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
RELAY_SSH=${RELAY_SSH:-root@62.238.59.22}
LOAD_SSH=${LOAD_SSH:-root@62.238.50.254}
RELAY_URL=${RELAY_URL:-ws://10.0.0.3:7777}
BENCH_BIN=${BENCH_BIN:-/opt/wok-load/bin/current/wok-bench}
EVENTS=${EVENTS:-100000}
QUERIES=${QUERIES:-400}
DEEP_PAGES=${DEEP_PAGES:-20}
REPETITIONS=${REPETITIONS:-3}
PUBLISH_CONNECTIONS=${PUBLISH_CONNECTIONS:-128}
FANOUT_SUBSCRIBERS=${FANOUT_SUBSCRIBERS:-128}
FANOUT_EVENTS=${FANOUT_EVENTS:-500}
IDLE_CONNECTIONS=${IDLE_CONNECTIONS:-10000}
HOLD_SECONDS=${HOLD_SECONDS:-15}
LIFECYCLE_EVENTS=${LIFECYCLE_EVENTS:-10000}
LIFECYCLE_CONNECTIONS=${LIFECYCLE_CONNECTIONS:-1}
NOFILE_LIMIT=${NOFILE_LIMIT:-524288}
COOLDOWN_SECONDS=${COOLDOWN_SECONDS:-10}
SEED=${SEED:-4242}
BASE_TIMESTAMP=${BASE_TIMESTAMP:-$(date -u +%s)}
CAMPAIGN_ID=${CAMPAIGN_ID:-wok-strfry-$(date -u +%Y%m%dT%H%M%SZ)}
LOAD_ROOT=/opt/wok-load/results/$CAMPAIGN_ID
LOAD_CORPUS_DIR=$LOAD_ROOT/corpus
LOAD_CORPUS=$LOAD_CORPUS_DIR/corpus.jsonl
RELAY_ROOT=/opt/relay-bench/campaigns/$CAMPAIGN_ID
RELAY_CORPUS=$RELAY_ROOT/corpus.jsonl
CONTROL_LOCAL=$SCRIPT_DIR/benchmark-relay-control.sh
CONTROL_REMOTE=/opt/relay-bench/bin/benchmark-relay-control
SSH_OPTIONS=(
    -o ControlMaster=auto
    -o ControlPersist=300
    -o 'ControlPath=/tmp/wok-bench-%C'
)

require_local_tools() {
    local tool
    for tool in ssh scp sha256sum; do
        command -v "$tool" >/dev/null || {
            echo "missing local tool: $tool" >&2
            exit 1
        }
    done
    [[ -x $CONTROL_LOCAL ]] || {
        echo "missing executable relay control script: $CONTROL_LOCAL" >&2
        exit 1
    }
    [[ $EVENTS =~ ^[1-9][0-9]*$ && $REPETITIONS =~ ^[1-9][0-9]*$ ]] || {
        echo "EVENTS and REPETITIONS must be positive integers" >&2
        exit 1
    }
}

cleanup() {
    ssh "${SSH_OPTIONS[@]}" "$RELAY_SSH" "$CONTROL_REMOTE stop-all" >/dev/null 2>&1 || true
    ssh "${SSH_OPTIONS[@]}" -O exit "$RELAY_SSH" >/dev/null 2>&1 || true
    ssh "${SSH_OPTIONS[@]}" -O exit "$LOAD_SSH" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

remote_command() {
    local host=$1
    shift
    local rendered
    printf -v rendered '%q ' "$@"
    ssh "${SSH_OPTIONS[@]}" "$host" "$rendered"
}

run_bench() {
    local relay=$1
    local repetition=$2
    local phase=$3
    shift 3
    local output=$LOAD_ROOT/runs/r${repetition}-${relay}/load/$phase
    remote_command "$LOAD_SSH" mkdir -p "$output"
    local command=(
        /usr/bin/time -v -o "$output/time.txt"
        "$BENCH_BIN"
        --target-url "$RELAY_URL"
        --target-label "$relay-r$repetition"
        --seed "$SEED"
        --base-timestamp "$BASE_TIMESTAMP"
        --repetitions 1
        --out "$output"
        "$@"
    )
    local rendered
    printf -v rendered '%q ' "${command[@]}"
    ssh "${SSH_OPTIONS[@]}" "$LOAD_SSH" "ulimit -n $NOFILE_LIMIT; exec $rendered"
    remote_command "$LOAD_SSH" jq -e -s 'all(.ok and (.errors == 0) and (.mismatches == 0))' \
        "$output/results.jsonl" >/dev/null
}

run_one_relay() {
    local relay=$1
    local repetition=$2
    local run_root=$LOAD_ROOT/runs/r${repetition}-${relay}
    local server_artifacts=$RELAY_ROOT/runs/r${repetition}-${relay}/server
    remote_command "$LOAD_SSH" mkdir -p "$run_root/load" "$run_root/server"

    ssh "${SSH_OPTIONS[@]}" "$RELAY_SSH" \
        "$CONTROL_REMOTE reset-import $relay $RELAY_CORPUS $EVENTS $server_artifacts"
    ssh "${SSH_OPTIONS[@]}" "$RELAY_SSH" "$CONTROL_REMOTE start $relay $server_artifacts"

    local status=0
    if ! run_bench "$relay" "$repetition" query \
        --scenario ws_query_latency --corpus "$LOAD_CORPUS" --events "$EVENTS" \
        --queries "$QUERIES" --event-mix realistic; then
        status=1
    fi
    if [[ $status -eq 0 ]] && ! run_bench "$relay" "$repetition" deep-history \
        --scenario deep_history_pagination --corpus "$LOAD_CORPUS" --events "$EVENTS" \
        --queries "$DEEP_PAGES" --event-mix realistic; then
        status=1
    fi
    if [[ $status -eq 0 ]] && ! run_bench "$relay" "$repetition" mixed-read-write \
        --scenario mixed_read_write --corpus "$LOAD_CORPUS" --events "$EVENTS" \
        --queries "$QUERIES" --event-mix realistic; then
        status=1
    fi
    if [[ $status -eq 0 ]] && ! run_bench "$relay" "$repetition" load \
        --profile load --corpus "$LOAD_CORPUS" --events "$EVENTS" \
        --event-mix realistic --publish-connections "$PUBLISH_CONNECTIONS" \
        --fanout-subscribers "$FANOUT_SUBSCRIBERS" --fanout-events "$FANOUT_EVENTS" \
        --connections "$IDLE_CONNECTIONS" --hold-seconds "$HOLD_SECONDS"; then
        status=1
    fi
    if [[ $status -eq 0 ]] && ! run_bench "$relay" "$repetition" lifecycle \
        --scenario ws_publish_scaled --events "$LIFECYCLE_EVENTS" --event-mix lifecycle \
        --publish-connections "$LIFECYCLE_CONNECTIONS"; then
        status=1
    fi

    ssh "${SSH_OPTIONS[@]}" "$RELAY_SSH" "$CONTROL_REMOTE collect-stop $relay $server_artifacts" || status=1
    scp "${SSH_OPTIONS[@]}" -3 -q -r "$RELAY_SSH:$server_artifacts/." "$LOAD_SSH:$run_root/server/" || status=1
    if [[ $status -ne 0 ]]; then
        echo "campaign phase failed for $relay repetition $repetition" >&2
        return "$status"
    fi
}

write_campaign_metadata() {
    local metadata=$LOAD_ROOT/campaign.env
    local lines=(
        "campaign_id=$CAMPAIGN_ID"
        "relay_ssh=$RELAY_SSH"
        "load_ssh=$LOAD_SSH"
        "relay_url=$RELAY_URL"
        "bench_bin=$BENCH_BIN"
        "events=$EVENTS"
        "queries=$QUERIES"
        "deep_pages=$DEEP_PAGES"
        "repetitions=$REPETITIONS"
        "publish_connections=$PUBLISH_CONNECTIONS"
        "fanout_subscribers=$FANOUT_SUBSCRIBERS"
        "fanout_events=$FANOUT_EVENTS"
        "idle_connections=$IDLE_CONNECTIONS"
        "hold_seconds=$HOLD_SECONDS"
        "lifecycle_events=$LIFECYCLE_EVENTS"
        "lifecycle_connections=$LIFECYCLE_CONNECTIONS"
        "seed=$SEED"
        "base_timestamp=$BASE_TIMESTAMP"
    )
    local command=(printf '%s\n' "${lines[@]}")
    local rendered
    printf -v rendered '%q ' "${command[@]}"
    ssh "${SSH_OPTIONS[@]}" "$LOAD_SSH" "$rendered > $(printf '%q' "$metadata")"
    ssh "${SSH_OPTIONS[@]}" "$LOAD_SSH" \
        "{ uname -a; lscpu; free -b; ip -br address; ip route; sysctl fs.file-max net.ipv4.ip_local_port_range net.core.somaxconn; } > $(printf '%q' "$LOAD_ROOT/load-host.txt")"
}

require_local_tools
scp "${SSH_OPTIONS[@]}" -q "$CONTROL_LOCAL" "$RELAY_SSH:$CONTROL_REMOTE"
remote_command "$RELAY_SSH" chmod 0755 "$CONTROL_REMOTE"
remote_command "$RELAY_SSH" mkdir -p "$RELAY_ROOT/runs"
remote_command "$LOAD_SSH" mkdir -p "$LOAD_CORPUS_DIR" "$LOAD_ROOT/runs"
remote_command "$LOAD_SSH" test -x "$BENCH_BIN"
remote_command "$LOAD_SSH" test -x /usr/bin/time
remote_command "$LOAD_SSH" test -x /usr/bin/jq
write_campaign_metadata

remote_command "$LOAD_SSH" "$BENCH_BIN" \
    --generate-corpus-only --events "$EVENTS" --event-mix realistic \
    --seed "$SEED" --base-timestamp "$BASE_TIMESTAMP" --out "$LOAD_CORPUS_DIR"
scp "${SSH_OPTIONS[@]}" -3 -q "$LOAD_SSH:$LOAD_CORPUS" "$RELAY_SSH:$RELAY_CORPUS"

load_sha=$(ssh "${SSH_OPTIONS[@]}" "$LOAD_SSH" "sha256sum $(printf '%q' "$LOAD_CORPUS") | awk '{print \$1}'")
relay_sha=$(ssh "${SSH_OPTIONS[@]}" "$RELAY_SSH" "sha256sum $(printf '%q' "$RELAY_CORPUS") | awk '{print \$1}'")
if [[ $load_sha != "$relay_sha" ]]; then
    echo "corpus checksum mismatch: load=$load_sha relay=$relay_sha" >&2
    exit 1
fi

for repetition in $(seq 1 "$REPETITIONS"); do
    if (( repetition % 2 == 1 )); then
        relays=(wok strfry)
    else
        relays=(strfry wok)
    fi
    for relay in "${relays[@]}"; do
        run_one_relay "$relay" "$repetition"
        sleep "$COOLDOWN_SECONDS"
    done
done

ssh "${SSH_OPTIONS[@]}" "$RELAY_SSH" "$CONTROL_REMOTE status" | \
    ssh "${SSH_OPTIONS[@]}" "$LOAD_SSH" "cat > $(printf '%q' "$LOAD_ROOT/final-relay-status.txt")"
echo "campaign complete: $LOAD_SSH:$LOAD_ROOT"
