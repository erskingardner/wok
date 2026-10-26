#!/usr/bin/env bash
# Two-host benchmark campaign over any number of relay targets: one relay
# host runs each target in turn, a load host drives it. The command strings
# below are deliberately rendered on the operator host and then executed
# remotely; quoting is handled by printf %q.
# shellcheck disable=SC2029
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
RELAY_SSH=${RELAY_SSH:-}
LOAD_SSH=${LOAD_SSH:-}
# The relay host's address as the load host reaches it.
RELAY_HOST=${RELAY_HOST:-}
# Target names, each defined on the relay host by
# /etc/relay-bench/targets/<name>.env (see benchmark-relay-control.sh).
TARGETS=${TARGETS:-}
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
# Relay caps: a CPU list for AllowedCPUs and a size for MemoryMax.
RELAY_CPUS=${RELAY_CPUS:-}
RELAY_MEMORY=${RELAY_MEMORY:-}
CACHE=${CACHE:-cold}
SNAPSHOTS=${SNAPSHOTS:-1}
READY_TIMEOUT=${READY_TIMEOUT:-120}
# Pins the load generator, for example beside the relay on the relay host.
LOAD_CPUS=${LOAD_CPUS:-}
SEED=${SEED:-4242}
BASE_TIMESTAMP=${BASE_TIMESTAMP:-$(date -u +%s)}
CAMPAIGN_ID=${CAMPAIGN_ID:-campaign-$(date -u +%Y%m%dT%H%M%SZ)}
# The generator and its CPU sampler run as transient units with these names
# on the load host, so a campaign can stop them when it is interrupted, and
# the next campaign can stop any that an earlier one lost track of.
LOAD_UNIT=relay-bench-load-$CAMPAIGN_ID
CONTROL_LOCAL=$SCRIPT_DIR/benchmark-relay-control.sh
CONTROL_REMOTE=/opt/relay-bench/bin/benchmark-relay-control
SSH_OPTIONS=(
    -o ControlMaster=auto
    -o ControlPersist=300
    -o 'ControlPath=/tmp/wok-bench-%C'
)

die() {
    echo "benchmark-campaign: $*" >&2
    exit 1
}

validate_settings() {
    local name
    for name in RELAY_SSH LOAD_SSH RELAY_HOST TARGETS; do
        [[ -n ${!name} ]] || die "$name is required"
    done
    [[ $EVENTS =~ ^[1-9][0-9]*$ && $REPETITIONS =~ ^[1-9][0-9]*$ ]] ||
        die "EVENTS and REPETITIONS must be positive integers"
    [[ $CAMPAIGN_ID =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] ||
        die "CAMPAIGN_ID may hold only letters, digits, dot, underscore and hyphen"
    [[ $CACHE == cold || $CACHE == warm ]] || die "CACHE must be cold or warm"
    [[ $SNAPSHOTS == 0 || $SNAPSHOTS == 1 ]] || die "SNAPSHOTS must be 0 or 1"
    local -a targets
    read -r -a targets <<<"$TARGETS"
    local i j
    for ((i = 0; i < ${#targets[@]}; i++)); do
        for ((j = i + 1; j < ${#targets[@]}; j++)); do
            [[ ${targets[i]} != "${targets[j]}" ]] || die "TARGETS names ${targets[i]} twice"
        done
    done
}

# Prints the targets in the order repetition N runs them: the list rotated by
# N - 1, so over as many repetitions as targets each target runs once in
# each position.
rotation() {
    local repetition=$1
    local -a targets
    read -r -a targets <<<"$TARGETS"
    local count=${#targets[@]}
    local offset=$(((repetition - 1) % count))
    local index
    for ((index = 0; index < count; index++)); do
        printf '%s\n' "${targets[(offset + index) % count]}"
    done
}

stop_load_units() {
    ssh "${SSH_OPTIONS[@]}" "$LOAD_SSH" "systemctl stop 'relay-bench-load-*.service'"
}

cleanup() {
    ssh "${SSH_OPTIONS[@]}" "$RELAY_SSH" "$CONTROL_REMOTE stop-all" >/dev/null 2>&1 || true
    stop_load_units >/dev/null 2>&1 || true
    ssh "${SSH_OPTIONS[@]}" -O exit "$RELAY_SSH" >/dev/null 2>&1 || true
    ssh "${SSH_OPTIONS[@]}" -O exit "$LOAD_SSH" >/dev/null 2>&1 || true
}

remote_command() {
    local host=$1
    shift
    local rendered
    printf -v rendered '%q ' "$@"
    ssh "${SSH_OPTIONS[@]}" "$host" "$rendered"
}

# Sets LOAD_UNIT_COMMAND to run a command on the load host as the transient
# unit LOAD_UNIT, pinned to LOAD_CPUS when set, and to wait for it.
load_unit_command() {
    local properties=(-p "LimitNOFILE=$NOFILE_LIMIT")
    if [[ -n $LOAD_CPUS ]]; then
        properties+=(-p "AllowedCPUs=$LOAD_CPUS")
    fi
    LOAD_UNIT_COMMAND=(
        systemd-run --quiet --wait --pipe --collect --unit="$LOAD_UNIT"
        "${properties[@]}" -- "$@"
    )
}

run_bench() {
    local target=$1
    local repetition=$2
    local url=$3
    local phase=$4
    shift 4
    local output=$LOAD_ROOT/runs/r${repetition}-${target}/load/$phase
    local phase_timestamp=$BASE_TIMESTAMP
    if [[ $phase == lifecycle ]]; then
        # Historical inputs use the fixed campaign timestamp. Ephemerals must
        # instead be fresh when each live lifecycle phase actually begins.
        phase_timestamp=$(date -u +%s)
    fi
    remote_command "$LOAD_SSH" mkdir -p "$output"
    load_unit_command /usr/bin/time -v -o "$output/time.txt" \
        "$BENCH_BIN" \
        --target-url "$url" \
        --target-label "$target-r$repetition" \
        --seed "$SEED" \
        --base-timestamp "$phase_timestamp" \
        --repetitions 1 \
        --out "$output" \
        "$@"
    # Per-CPU load-host utilization shows whether the generator, not the
    # relay, was the limit.
    local sampler=(
        systemd-run --quiet --collect --unit="$LOAD_UNIT-mpstat"
        -p "StandardOutput=truncate:$output/load-mpstat.txt" -p StandardError=journal
        -E LC_ALL=C -E S_TIME_FORMAT=ISO -- mpstat -P ALL 1
    )
    local rendered_bench rendered_sampler
    printf -v rendered_bench '%q ' "${LOAD_UNIT_COMMAND[@]}"
    printf -v rendered_sampler '%q ' "${sampler[@]}"
    ssh "${SSH_OPTIONS[@]}" "$LOAD_SSH" "$rendered_sampler
$rendered_bench
rc=\$?
systemctl stop $LOAD_UNIT-mpstat.service
exit \$rc"
    remote_command "$LOAD_SSH" jq -e -s 'all(.ok and (.errors == 0) and (.mismatches == 0))' \
        "$output/results.jsonl" >/dev/null
}

run_target() {
    local target=$1
    local repetition=$2
    local run_root=$LOAD_ROOT/runs/r${repetition}-${target}
    local server_artifacts=$RELAY_ROOT/runs/r${repetition}-${target}/server
    local port
    port=$(remote_command "$RELAY_SSH" "$CONTROL_REMOTE" port "$target")
    local url=ws://$RELAY_HOST:$port
    local snapshot=none
    if [[ $SNAPSHOTS == 1 ]]; then
        snapshot=keep
    fi
    remote_command "$LOAD_SSH" mkdir -p "$run_root/load" "$run_root/server"

    remote_command "$RELAY_SSH" "$CONTROL_REMOTE" prepare "$target" "$RELAY_CORPUS" \
        "$EVENTS" "$server_artifacts" --snapshot "$snapshot" --nofile "$NOFILE_LIMIT" \
        ${CAP_ARGS[@]+"${CAP_ARGS[@]}"}
    remote_command "$RELAY_SSH" "$CONTROL_REMOTE" start "$target" "$server_artifacts" \
        --cache "$CACHE" --ready-timeout "$READY_TIMEOUT" --nofile "$NOFILE_LIMIT" \
        ${CAP_ARGS[@]+"${CAP_ARGS[@]}"}

    local status=0
    if ! run_bench "$target" "$repetition" "$url" query \
        --scenario ws_query_latency --corpus "$LOAD_CORPUS" --events "$EVENTS" \
        --queries "$QUERIES" --event-mix realistic; then
        status=1
    fi
    if [[ $status -eq 0 ]] && ! run_bench "$target" "$repetition" "$url" deep-history \
        --scenario deep_history_pagination --corpus "$LOAD_CORPUS" --events "$EVENTS" \
        --queries "$DEEP_PAGES" --event-mix realistic; then
        status=1
    fi
    if [[ $status -eq 0 ]] && ! run_bench "$target" "$repetition" "$url" mixed-read-write \
        --scenario mixed_read_write --corpus "$LOAD_CORPUS" --events "$EVENTS" \
        --queries "$QUERIES" --event-mix realistic; then
        status=1
    fi
    if [[ $status -eq 0 ]] && ! run_bench "$target" "$repetition" "$url" load \
        --profile load --corpus "$LOAD_CORPUS" --events "$EVENTS" \
        --event-mix realistic --publish-connections "$PUBLISH_CONNECTIONS" \
        --fanout-subscribers "$FANOUT_SUBSCRIBERS" --fanout-events "$FANOUT_EVENTS" \
        --connections "$IDLE_CONNECTIONS" --hold-seconds "$HOLD_SECONDS"; then
        status=1
    fi
    if [[ $status -eq 0 ]] && ! run_bench "$target" "$repetition" "$url" lifecycle \
        --scenario ws_publish_scaled --events "$LIFECYCLE_EVENTS" --event-mix lifecycle \
        --publish-connections "$LIFECYCLE_CONNECTIONS"; then
        status=1
    fi

    remote_command "$RELAY_SSH" "$CONTROL_REMOTE" collect-stop "$target" "$server_artifacts" ||
        status=1
    scp "${SSH_OPTIONS[@]}" -3 -q -r "$RELAY_SSH:$server_artifacts/." "$LOAD_SSH:$run_root/server/" ||
        status=1
    if [[ $status -ne 0 ]]; then
        echo "campaign phase failed for $target repetition $repetition" >&2
        return "$status"
    fi
}

write_campaign_metadata() {
    local metadata=$LOAD_ROOT/campaign.env
    local lines=(
        "campaign_id=$CAMPAIGN_ID"
        "relay_ssh=$RELAY_SSH"
        "load_ssh=$LOAD_SSH"
        "relay_host=$RELAY_HOST"
        "targets=$TARGETS"
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
        "relay_cpus=$RELAY_CPUS"
        "relay_memory=$RELAY_MEMORY"
        "cache=$CACHE"
        "snapshots=$SNAPSHOTS"
        "load_cpus=$LOAD_CPUS"
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

main() {
    validate_settings
    local tool
    for tool in ssh scp; do
        command -v "$tool" >/dev/null || die "missing local tool: $tool"
    done
    [[ -x $CONTROL_LOCAL ]] || die "missing executable relay control script: $CONTROL_LOCAL"

    LOAD_ROOT=/opt/wok-load/results/$CAMPAIGN_ID
    LOAD_CORPUS_DIR=$LOAD_ROOT/corpus
    LOAD_CORPUS=$LOAD_CORPUS_DIR/corpus.jsonl
    RELAY_ROOT=/opt/relay-bench/campaigns/$CAMPAIGN_ID
    RELAY_CORPUS=$RELAY_ROOT/corpus.jsonl
    CAP_ARGS=()
    if [[ -n $RELAY_CPUS ]]; then
        CAP_ARGS+=(--cpus "$RELAY_CPUS")
    fi
    if [[ -n $RELAY_MEMORY ]]; then
        CAP_ARGS+=(--memory "$RELAY_MEMORY")
    fi
    local -a targets
    read -r -a targets <<<"$TARGETS"
    trap cleanup EXIT
    # A trapped signal would otherwise resume the script once cleanup ran.
    trap 'exit 130' INT TERM

    remote_command "$RELAY_SSH" mkdir -p "$(dirname -- "$CONTROL_REMOTE")"
    scp "${SSH_OPTIONS[@]}" -q "$CONTROL_LOCAL" "$RELAY_SSH:$CONTROL_REMOTE"
    remote_command "$RELAY_SSH" chmod 0755 "$CONTROL_REMOTE"
    remote_command "$RELAY_SSH" "$CONTROL_REMOTE" check "${targets[@]}"
    remote_command "$RELAY_SSH" mkdir -p "$RELAY_ROOT/runs"
    remote_command "$LOAD_SSH" mkdir -p "$LOAD_CORPUS_DIR" "$LOAD_ROOT/runs"
    remote_command "$LOAD_SSH" test -x "$BENCH_BIN"
    remote_command "$LOAD_SSH" test -x /usr/bin/time
    remote_command "$LOAD_SSH" test -x /usr/bin/jq
    remote_command "$LOAD_SSH" sh -c 'command -v mpstat >/dev/null' ||
        die "the load host needs mpstat (sysstat)"
    remote_command "$LOAD_SSH" sh -c 'command -v systemd-run >/dev/null' ||
        die "the load host needs systemd-run"
    stop_load_units
    write_campaign_metadata

    load_unit_command "$BENCH_BIN" \
        --generate-corpus-only --events "$EVENTS" --event-mix realistic \
        --seed "$SEED" --base-timestamp "$BASE_TIMESTAMP" --out "$LOAD_CORPUS_DIR"
    remote_command "$LOAD_SSH" "${LOAD_UNIT_COMMAND[@]}"
    scp "${SSH_OPTIONS[@]}" -3 -q "$LOAD_SSH:$LOAD_CORPUS" "$RELAY_SSH:$RELAY_CORPUS"

    local load_sha relay_sha
    load_sha=$(ssh "${SSH_OPTIONS[@]}" "$LOAD_SSH" "sha256sum $(printf '%q' "$LOAD_CORPUS") | awk '{print \$1}'")
    relay_sha=$(ssh "${SSH_OPTIONS[@]}" "$RELAY_SSH" "sha256sum $(printf '%q' "$RELAY_CORPUS") | awk '{print \$1}'")
    [[ $load_sha == "$relay_sha" ]] ||
        die "corpus checksum mismatch: load=$load_sha relay=$relay_sha"

    local repetition target
    for repetition in $(seq 1 "$REPETITIONS"); do
        for target in $(rotation "$repetition"); do
            run_target "$target" "$repetition"
            sleep "$COOLDOWN_SECONDS"
        done
    done

    ssh "${SSH_OPTIONS[@]}" "$RELAY_SSH" "$CONTROL_REMOTE status" |
        ssh "${SSH_OPTIONS[@]}" "$LOAD_SSH" "cat > $(printf '%q' "$LOAD_ROOT/final-relay-status.txt")"
    echo "campaign complete: $LOAD_SSH:$LOAD_ROOT"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
