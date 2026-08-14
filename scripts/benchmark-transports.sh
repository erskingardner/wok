#!/usr/bin/env bash
# Same-host transport comparison. Commands are deliberately rendered on the
# operator host and executed over one multiplexed SSH connection.
# shellcheck disable=SC2029
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
RELAY_SSH=${RELAY_SSH:-root@62.238.59.22}
LOAD_SSH=${LOAD_SSH:-root@62.238.50.254}
BENCH_BIN=${BENCH_BIN:-/opt/relay-bench/bin/wok-bench/current/wok-bench}
WOK_UNIX_SOCKET=${WOK_UNIX_SOCKET:-/var/lib/relay-bench/wok/wok.sock}
WS_URL=${WS_URL:-ws://10.0.0.3:7777}
EVENTS=${EVENTS:-100000}
QUERIES=${QUERIES:-400}
DEEP_PAGES=${DEEP_PAGES:-20}
REPETITIONS=${REPETITIONS:-3}
PUBLISH_CONNECTIONS=${PUBLISH_CONNECTIONS:-128}
FANOUT_SUBSCRIBERS=${FANOUT_SUBSCRIBERS:-128}
FANOUT_EVENTS=${FANOUT_EVENTS:-500}
IDLE_CONNECTIONS=${IDLE_CONNECTIONS:-10000}
HOLD_SECONDS=${HOLD_SECONDS:-15}
NOFILE_LIMIT=${NOFILE_LIMIT:-524288}
COOLDOWN_SECONDS=${COOLDOWN_SECONDS:-10}
SEED=${SEED:-4242}
BASE_TIMESTAMP=${BASE_TIMESTAMP:-$(date -u +%s)}
CAMPAIGN_ID=${CAMPAIGN_ID:-transport-$(date -u +%Y%m%dT%H%M%SZ)}
CAMPAIGN_ROOT=/opt/relay-bench/campaigns/$CAMPAIGN_ID
CORPUS_DIR=$CAMPAIGN_ROOT/corpus
CORPUS=$CORPUS_DIR/corpus.jsonl
CONTROL_LOCAL=$SCRIPT_DIR/benchmark-relay-control.sh
CONTROL_REMOTE=/opt/relay-bench/bin/benchmark-relay-control
SSH_OPTIONS=(
    -o ControlMaster=auto
    -o ControlPersist=300
    -o 'ControlPath=/tmp/wok-bench-%C'
)

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

target_relay() {
    case "$1" in
        wok-ws | wok-unix) echo wok ;;
        strfry-ws) echo strfry ;;
        *) echo "unknown transport target: $1" >&2; return 2 ;;
    esac
}

target_args() {
    case "$1" in
        wok-unix) TARGET_ARGS=(--target-unix "$WOK_UNIX_SOCKET") ;;
        wok-ws | strfry-ws) TARGET_ARGS=(--target-url "$WS_URL") ;;
        *) echo "unknown transport target: $1" >&2; return 2 ;;
    esac
}

run_bench() {
    local target=$1
    local repetition=$2
    local phase=$3
    shift 3
    local output=$CAMPAIGN_ROOT/runs/r${repetition}-${target}/load/$phase
    target_args "$target"
    remote_command "$RELAY_SSH" mkdir -p "$output"
    local command=(
        /usr/bin/time -v -o "$output/time.txt"
        "$BENCH_BIN"
        "${TARGET_ARGS[@]}"
        --target-label "$target-r$repetition"
        --seed "$SEED"
        --base-timestamp "$BASE_TIMESTAMP"
        --repetitions 1
        --out "$output"
        "$@"
    )
    local rendered
    printf -v rendered '%q ' "${command[@]}"
    ssh "${SSH_OPTIONS[@]}" "$RELAY_SSH" "ulimit -n $NOFILE_LIMIT; exec $rendered"
    remote_command "$RELAY_SSH" jq -e -s \
        'all(.ok and (.errors == 0) and (.mismatches == 0))' \
        "$output/results.jsonl" >/dev/null
}

run_target() {
    local target=$1
    local repetition=$2
    local relay
    relay=$(target_relay "$target")
    local run_root=$CAMPAIGN_ROOT/runs/r${repetition}-${target}
    local server_artifacts=$run_root/server

    ssh "${SSH_OPTIONS[@]}" "$RELAY_SSH" \
        "$CONTROL_REMOTE reset-import $relay $CORPUS $EVENTS $server_artifacts"
    ssh "${SSH_OPTIONS[@]}" "$RELAY_SSH" \
        "$CONTROL_REMOTE start $relay $server_artifacts"
    if [[ $target == wok-unix ]]; then
        local socket_path
        printf -v socket_path '%q' "$WOK_UNIX_SOCKET"
        ssh "${SSH_OPTIONS[@]}" "$RELAY_SSH" \
            "for _ in \$(seq 1 100); do test -S $socket_path && exit 0; sleep 0.1; done; exit 1"
    fi

    local rc=0
    run_bench "$target" "$repetition" query \
        --scenario ws_query_latency --corpus "$CORPUS" --events "$EVENTS" \
        --queries "$QUERIES" --event-mix realistic || rc=1
    if [[ $rc -eq 0 ]]; then
        run_bench "$target" "$repetition" deep-history \
            --scenario deep_history_pagination --corpus "$CORPUS" --events "$EVENTS" \
            --queries "$DEEP_PAGES" --event-mix realistic || rc=1
    fi
    if [[ $rc -eq 0 ]]; then
        run_bench "$target" "$repetition" mixed-read-write \
            --scenario mixed_read_write --corpus "$CORPUS" --events "$EVENTS" \
            --queries "$QUERIES" --event-mix realistic || rc=1
    fi
    if [[ $rc -eq 0 ]]; then
        run_bench "$target" "$repetition" load \
            --profile load --corpus "$CORPUS" --events "$EVENTS" \
            --event-mix realistic --publish-connections "$PUBLISH_CONNECTIONS" \
            --fanout-subscribers "$FANOUT_SUBSCRIBERS" --fanout-events "$FANOUT_EVENTS" \
            --connections "$IDLE_CONNECTIONS" --hold-seconds "$HOLD_SECONDS" || rc=1
    fi

    ssh "${SSH_OPTIONS[@]}" "$RELAY_SSH" \
        "$CONTROL_REMOTE collect-stop $relay $server_artifacts" || rc=1
    if [[ $rc -ne 0 ]]; then
        echo "transport phase failed for $target repetition $repetition" >&2
        return "$rc"
    fi
}

for tool in ssh scp; do
    command -v "$tool" >/dev/null || { echo "missing local tool: $tool" >&2; exit 1; }
done
[[ -x $CONTROL_LOCAL ]] || { echo "missing control helper: $CONTROL_LOCAL" >&2; exit 1; }
[[ $EVENTS =~ ^[1-9][0-9]*$ && $REPETITIONS =~ ^[1-9][0-9]*$ ]] || {
    echo "EVENTS and REPETITIONS must be positive integers" >&2
    exit 1
}

scp "${SSH_OPTIONS[@]}" -q "$CONTROL_LOCAL" "$RELAY_SSH:$CONTROL_REMOTE"
remote_command "$RELAY_SSH" chmod 0755 "$CONTROL_REMOTE"
remote_command "$RELAY_SSH" test -x "$BENCH_BIN"
remote_command "$RELAY_SSH" test -x /usr/bin/time
remote_command "$RELAY_SSH" test -x /usr/bin/jq
remote_command "$RELAY_SSH" mkdir -p "$CORPUS_DIR" "$CAMPAIGN_ROOT/runs"

remote_command "$RELAY_SSH" "$BENCH_BIN" \
    --generate-corpus-only --events "$EVENTS" --event-mix realistic \
    --seed "$SEED" --base-timestamp "$BASE_TIMESTAMP" --out "$CORPUS_DIR"

metadata=(
    "campaign_id=$CAMPAIGN_ID"
    "mode=same-host-transport"
    "events=$EVENTS"
    "queries=$QUERIES"
    "repetitions=$REPETITIONS"
    "publish_connections=$PUBLISH_CONNECTIONS"
    "fanout_subscribers=$FANOUT_SUBSCRIBERS"
    "fanout_events=$FANOUT_EVENTS"
    "idle_connections=$IDLE_CONNECTIONS"
    "hold_seconds=$HOLD_SECONDS"
    "seed=$SEED"
    "base_timestamp=$BASE_TIMESTAMP"
    "wok_unix_socket=$WOK_UNIX_SOCKET"
    "ws_url=$WS_URL"
)
metadata_command=(printf '%s\n' "${metadata[@]}")
printf -v rendered_metadata '%q ' "${metadata_command[@]}"
ssh "${SSH_OPTIONS[@]}" "$RELAY_SSH" \
    "$rendered_metadata > $(printf '%q' "$CAMPAIGN_ROOT/campaign.env")"

for repetition in $(seq 1 "$REPETITIONS"); do
    case $((repetition % 3)) in
        1) targets=(wok-ws wok-unix strfry-ws) ;;
        2) targets=(wok-unix strfry-ws wok-ws) ;;
        0) targets=(strfry-ws wok-ws wok-unix) ;;
    esac
    for target in "${targets[@]}"; do
        run_target "$target" "$repetition"
        sleep "$COOLDOWN_SECONDS"
    done
done

remote_command "$LOAD_SSH" mkdir -p "/opt/wok-load/results/$CAMPAIGN_ID"
scp "${SSH_OPTIONS[@]}" -3 -q -r "$RELAY_SSH:$CAMPAIGN_ROOT/." \
    "$LOAD_SSH:/opt/wok-load/results/$CAMPAIGN_ID/"
ssh "${SSH_OPTIONS[@]}" "$RELAY_SSH" "$CONTROL_REMOTE status" | \
    ssh "${SSH_OPTIONS[@]}" "$LOAD_SSH" \
        "cat > $(printf '%q' "/opt/wok-load/results/$CAMPAIGN_ID/final-relay-status.txt")"
echo "transport campaign complete: $LOAD_SSH:/opt/wok-load/results/$CAMPAIGN_ID"
