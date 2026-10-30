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
# The relay host's SSH destination as the load host reaches it. When set, the
# load host copies to and from the relay host directly; otherwise every copy
# between them passes through this host.
RELAY_COPY_SSH=${RELAY_COPY_SSH:-}
# Target names, each defined on the relay host by
# /etc/relay-bench/targets/<name>.env (see benchmark-relay-control.sh).
TARGETS=${TARGETS:-}
BENCH_BIN=${BENCH_BIN:-/opt/wok-load/bin/current/wok-bench}
# The relay host's wok-bench, which reconciles fixed-rate outcome logs with
# each relay's export.
RELAY_BENCH_BIN=${RELAY_BENCH_BIN:-/opt/relay-bench/bin/wok-bench/wok-bench}
EVENTS=${EVENTS:-100000}
# realistic, or social: a public social relay's history, of which a relay
# keeps only part. The query phases read either.
CORPUS_MIX=${CORPUS_MIX:-realistic}
SOCIAL_AUTHORS=${SOCIAL_AUTHORS:-100000}
QUERIES=${QUERIES:-400}
DEEP_PAGES=${DEEP_PAGES:-20}
REPETITIONS=${REPETITIONS:-3}
PUBLISH_CONNECTIONS=${PUBLISH_CONNECTIONS:-128}
FANOUT_SUBSCRIBERS=${FANOUT_SUBSCRIBERS:-128}
FANOUT_EVENTS=${FANOUT_EVENTS:-500}
# Publications live_fanout leaves unacknowledged at once; 1 waits for each OK.
FANOUT_WINDOW=${FANOUT_WINDOW:-256}
IDLE_CONNECTIONS=${IDLE_CONNECTIONS:-10000}
HOLD_SECONDS=${HOLD_SECONDS:-15}
LIFECYCLE_EVENTS=${LIFECYCLE_EVENTS:-10000}
LIFECYCLE_CONNECTIONS=${LIFECYCLE_CONNECTIONS:-1}
NOFILE_LIMIT=${NOFILE_LIMIT:-524288}
COOLDOWN_SECONDS=${COOLDOWN_SECONDS:-10}
# Fixed-rate publication steps in events per second, rising, run after the
# other phases. A target's sweep stops at the first step that misses its
# targets (see rate_sweep). Empty runs none.
RATE_STEPS=${RATE_STEPS:-}
RATE_SECS=${RATE_SECS:-180}
RATE_DRAIN_SECS=${RATE_DRAIN_SECS:-10}
RATE_CONNECTIONS=${RATE_CONNECTIONS:-64}
RATE_P99_MS=${RATE_P99_MS:-250}
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
    [[ $CORPUS_MIX == realistic || $CORPUS_MIX == social ]] ||
        die "CORPUS_MIX must be realistic or social"
    for name in SOCIAL_AUTHORS RATE_SECS RATE_DRAIN_SECS RATE_CONNECTIONS RATE_P99_MS; do
        [[ ${!name} =~ ^[1-9][0-9]*$ ]] || die "$name must be a positive integer"
    done
    local -a steps
    read -r -a steps <<<"$RATE_STEPS"
    local step previous=0
    # Bash before 4.4 calls an empty array unbound under set -u.
    for step in ${steps[@]+"${steps[@]}"}; do
        if [[ ! $step =~ ^[1-9][0-9]*$ ]] || ((step <= previous)); then
            die "RATE_STEPS must list rising positive integers"
        fi
        previous=$step
    done
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

# copy_to_relay LOAD_PATH RELAY_PATH copies a file from the load host to the
# relay host.
copy_to_relay() {
    if [[ -n $RELAY_COPY_SSH ]]; then
        remote_command "$LOAD_SSH" scp -o BatchMode=yes -q "$1" "$RELAY_COPY_SSH:$2"
    else
        scp "${SSH_OPTIONS[@]}" -3 -q "$LOAD_SSH:$1" "$RELAY_SSH:$2"
    fi
}

# copy_to_load [-r] RELAY_PATH LOAD_PATH copies a file, or with -r a
# directory, from the relay host to the load host.
copy_to_load() {
    local recursive=()
    if [[ $1 == -r ]]; then
        recursive=(-r)
        shift
    fi
    if [[ -n $RELAY_COPY_SSH ]]; then
        remote_command "$LOAD_SSH" scp -o BatchMode=yes -q ${recursive[@]+"${recursive[@]}"} \
            "$RELAY_COPY_SSH:$1" "$2"
    else
        scp "${SSH_OPTIONS[@]}" -3 -q ${recursive[@]+"${recursive[@]}"} \
            "$RELAY_SSH:$1" "$LOAD_SSH:$2"
    fi
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

# Asks the relay host to mark the relay's cumulative storage I/O. A missing
# mark leaves that phase's bytes out; it does not fail the phase.
io_mark() {
    local target=$1
    local repetition=$2
    local label=$3
    remote_command "$RELAY_SSH" "$CONTROL_REMOTE" io-mark "$target" \
        "$RELAY_ROOT/runs/r${repetition}-${target}/server" "$label" ||
        echo "$target: could not mark the relay's I/O at $label" >&2
}

# Runs one phase on the load host, signing its workload from the given seed,
# and returns wok-bench's status. Its results go to
# $LOAD_ROOT/runs/r<repetition>-<target>/load/<phase>, and the relay's I/O
# is marked at its start and end.
launch_bench() {
    local target=$1
    local repetition=$2
    local url=$3
    local phase=$4
    local seed=$5
    shift 5
    local output=$LOAD_ROOT/runs/r${repetition}-${target}/load/$phase
    local phase_timestamp=$BASE_TIMESTAMP
    if [[ $phase == lifecycle ]]; then
        # Historical inputs use the fixed campaign timestamp. Ephemerals must
        # instead be fresh when each live lifecycle phase actually begins.
        phase_timestamp=$(date -u +%s)
    fi
    # The phase starts empty: under a reused campaign ID, an earlier run's
    # report or I/O summary must not stand in for one this run never wrote.
    # shellcheck disable=SC2016 # The load host's shell expands it.
    remote_command "$LOAD_SSH" sh -c 'rm -rf -- "$1" && mkdir -p -- "$1"' sh "$output"
    load_unit_command /usr/bin/time -v -o "$output/time.txt" \
        "$BENCH_BIN" \
        --target-url "$url" \
        --target-label "$target-r$repetition" \
        --seed "$seed" \
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
    io_mark "$target" "$repetition" "$phase-start"
    local status=0
    ssh "${SSH_OPTIONS[@]}" "$LOAD_SSH" "$rendered_sampler
$rendered_bench
rc=\$?
systemctl stop $LOAD_UNIT-mpstat.service
exit \$rc" || status=$?
    io_mark "$target" "$repetition" "$phase-end"
    PHASES_LAUNCHED+=("$phase")
    return "$status"
}

# What each phase the run launched made the relay write, from the server
# evidence's io-phases.tsv, as <phase>/relay-io.json beside its results:
# seconds, bytes read and written, and for a fixed-rate step the events it
# newly stored (accepted less duplicates) and bytes written per such event.
# shellcheck disable=SC2016 # $io, $phase and $stored are jq's.
PHASE_IO='($io | split("\n") | map(split("\t")) | map(select(length == 4 and .[0] == $phase)))
    as $rows
    | if ($rows | length) == 0 then empty else
        $rows[0] as $row
        | {phase: $phase, secs: ($row[1] | tonumber), read_bytes: ($row[2] | tonumber),
           write_bytes: ($row[3] | tonumber)}
        | if ($results | length) > 0 and $results[0].publish_rate != null then
            ($results[0].publish_rate | .accepted - .duplicates) as $stored
            | . + {stored_events: $stored,
                   write_bytes_per_stored_event:
                     (if $stored > 0 then .write_bytes / $stored else null end)}
          else . end
      end'

phase_io() {
    local target=$1
    local repetition=$2
    local run_root=$LOAD_ROOT/runs/r${repetition}-${target}
    local io=$run_root/server/io-phases.tsv
    remote_command "$LOAD_SSH" test -s "$io" || return 0
    local phase
    for phase in ${PHASES_LAUNCHED[@]+"${PHASES_LAUNCHED[@]}"}; do
        # shellcheck disable=SC2016 # The load host's shell expands them.
        remote_command "$LOAD_SSH" sh -c \
            'jq -n --rawfile io "$1" --arg phase "$2" --slurpfile results "$3" "$4" \
                >"$5.tmp" || { rm -f -- "$5.tmp"; exit 1; }
            if [ -s "$5.tmp" ]; then mv -- "$5.tmp" "$5"; else rm -f -- "$5.tmp"; fi' \
            sh "$io" "$phase" "$run_root/load/$phase/results.jsonl" "$PHASE_IO" \
            "$run_root/load/$phase/relay-io.json" ||
            echo "$target: could not summarize the relay's I/O for $phase" >&2
    done
}

# Runs one phase and fails unless every trial passed: ok, with no errors or
# mismatches.
run_bench() {
    local target=$1
    local repetition=$2
    local url=$3
    local phase=$4
    shift 4
    # The results decide; a failed trial also makes wok-bench exit non-zero.
    launch_bench "$target" "$repetition" "$url" "$phase" "$SEED" "$@" || true
    remote_command "$LOAD_SSH" jq -e -s 'all(.ok and (.errors == 0) and (.mismatches == 0))' \
        "$LOAD_ROOT/runs/r${repetition}-${target}/load/$phase/results.jsonl" >/dev/null
}

# A fixed-rate step meets its targets when the relay kept up with the whole
# schedule: every event sent at the intended rate on connections that stayed
# open, each accepted, none refused or unanswered, and publish-to-OK p99
# within RATE_P99_MS.
# shellcheck disable=SC2016 # $p99 is jq's.
RATE_TARGETS='all(.ok and .errors == 0 and .latency_p99_ms <= $p99
    and .publish_rate.unsent == 0 and .publish_rate.no_reply == 0
    and (.publish_rate.refused | length) == 0)'

# Publishes at each of RATE_STEPS in turn, RATE_SECS each, and stops after
# the first step that misses its targets. Each step signs fresh events from
# its own seed, so no step repeats another's. Writes rate-capacity.txt beside
# the phases: the last step that met its targets (0 for none) and the first
# that missed. A missed step is a result. This fails when a step left no
# fixed-rate report, which also means no complete outcome log, or an OK
# named no event its connection sent. RATE_LAUNCHED lists the steps it
# started, for reconcile_rate_steps.
rate_sweep() {
    local target=$1
    local repetition=$2
    local url=$3
    local load=$LOAD_ROOT/runs/r${repetition}-${target}/load
    local -a steps
    read -r -a steps <<<"$RATE_STEPS"
    local capacity=0
    local missed=
    local index rate results
    RATE_LAUNCHED=()
    for index in "${!steps[@]}"; do
        rate=${steps[index]}
        RATE_LAUNCHED+=("$rate")
        launch_bench "$target" "$repetition" "$url" "rate-$rate" "$((SEED + index + 1))" \
            --scenario ws_publish_rate --send-rate "$rate" --send-secs "$RATE_SECS" \
            --drain-secs "$RATE_DRAIN_SECS" --publish-connections "$RATE_CONNECTIONS" \
            --event-mix realistic || true
        results=$load/rate-$rate/results.jsonl
        if ! remote_command "$LOAD_SSH" jq -e -s \
            'length > 0 and all(.publish_rate != null and .mismatches == 0)' \
            "$results" >/dev/null; then
            echo "$target step $rate left no fixed-rate report, or an OK named no sent event" >&2
            return 1
        fi
        if remote_command "$LOAD_SSH" jq -e -s --argjson p99 "$RATE_P99_MS" "$RATE_TARGETS" \
            "$results" >/dev/null; then
            capacity=$rate
        else
            missed=$rate
            break
        fi
    done
    # shellcheck disable=SC2016 # The load host's shell expands them.
    remote_command "$LOAD_SSH" sh -c 'printf "capacity=%s\nfirst_missed=%s\n" "$1" "$2" >"$3"' \
        sh "$capacity" "$missed" "$load/rate-capacity.txt"
}

# Copies the outcome log of each step the sweep started (RATE_LAUNCHED) to
# the relay host, reconciles them all against one export of the stopped
# relay's database, and copies each step's reconciliation.json back beside
# its results. Fails when a started step has no outcome log, when a log does
# not account for every event its step planned, or when a step has an
# acknowledged event missing or a refused event stored.
reconcile_rate_steps() {
    local target=$1
    local repetition=$2
    local load=$LOAD_ROOT/runs/r${repetition}-${target}/load
    local relay=$RELAY_ROOT/runs/r${repetition}-${target}/rate
    local -a ran=()
    local rate log
    local status=0
    # The helper reconciles every log under $relay, so none may be left from
    # an earlier run with this campaign ID.
    remote_command "$RELAY_SSH" rm -rf -- "$relay"
    for rate in ${RATE_LAUNCHED[@]+"${RATE_LAUNCHED[@]}"}; do
        # wok-bench names the log for the trial's label and its repetition,
        # which is always 1 here.
        log=$load/rate-$rate/outcomes-$target-r$repetition-r1.jsonl
        if ! remote_command "$LOAD_SSH" test -s "$log"; then
            echo "$target step $rate ran but its outcome log $log is missing" >&2
            status=1
            continue
        fi
        if ! remote_command "$RELAY_SSH" mkdir -p "$relay/rate-$rate" ||
            ! copy_to_relay "$log" "$relay/rate-$rate/outcomes.jsonl"; then
            echo "$target step $rate: could not copy its outcome log to the relay host" >&2
            remote_command "$RELAY_SSH" rm -rf -- "$relay/rate-$rate" || true
            status=1
            continue
        fi
        ran+=("$rate")
    done
    [[ ${#ran[@]} -gt 0 ]] || return "$status"
    remote_command "$RELAY_SSH" "$CONTROL_REMOTE" reconcile "$target" "$RELAY_BENCH_BIN" \
        "$relay" --nofile "$NOFILE_LIMIT" || status=1
    for rate in "${ran[@]}"; do
        if ! copy_to_load "$relay/rate-$rate/reconciliation.json" \
            "$load/rate-$rate/reconciliation.json"; then
            status=1
            continue
        fi
        # A log cut short would reconcile only the events it holds.
        if ! remote_command "$LOAD_SSH" jq -e -s '.[0].publish_rate.events == .[1].events' \
            "$load/rate-$rate/results.jsonl" "$load/rate-$rate/reconciliation.json" >/dev/null; then
            echo "$target step $rate: the outcome log does not hold every planned event" >&2
            status=1
        fi
    done
    return "$status"
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
    # Only this run's evidence may replace it: a rerun under the same
    # campaign ID whose collect fails must leave every phase's bytes out.
    remote_command "$LOAD_SSH" rm -f -- "$run_root/server/io-phases.tsv" \
        "$run_root/server/writer-phases.tsv"
    # Its metrics snapshots too: the copy back overwrites files and keeps the
    # rest, so an earlier run's could pair with this run's.
    remote_command "$LOAD_SSH" rm -rf -- "$run_root/server/metrics-marks"
    RATE_LAUNCHED=()
    PHASES_LAUNCHED=()

    remote_command "$RELAY_SSH" "$CONTROL_REMOTE" prepare "$target" "$RELAY_CORPUS" \
        "$RETAINED" "$server_artifacts" --snapshot "$snapshot" --nofile "$NOFILE_LIMIT" \
        ${CAP_ARGS[@]+"${CAP_ARGS[@]}"}
    remote_command "$RELAY_SSH" "$CONTROL_REMOTE" start "$target" "$server_artifacts" \
        --cache "$CACHE" --ready-timeout "$READY_TIMEOUT" --nofile "$NOFILE_LIMIT" \
        ${CAP_ARGS[@]+"${CAP_ARGS[@]}"}

    local status=0
    if ! run_bench "$target" "$repetition" "$url" query \
        --scenario ws_query_latency --corpus "$LOAD_CORPUS" --events "$EVENTS" \
        --queries "$QUERIES" --event-mix "$CORPUS_MIX"; then
        status=1
    fi
    if [[ $status -eq 0 ]] && ! run_bench "$target" "$repetition" "$url" deep-history \
        --scenario deep_history_pagination --corpus "$LOAD_CORPUS" --events "$EVENTS" \
        --queries "$DEEP_PAGES" --event-mix "$CORPUS_MIX"; then
        status=1
    fi
    if [[ $status -eq 0 ]] && ! run_bench "$target" "$repetition" "$url" mixed-read-write \
        --scenario mixed_read_write --corpus "$LOAD_CORPUS" --events "$EVENTS" \
        --queries "$QUERIES" --event-mix "$CORPUS_MIX"; then
        status=1
    fi
    if [[ $status -eq 0 ]] && ! run_bench "$target" "$repetition" "$url" load \
        --profile load --corpus "$LOAD_CORPUS" --events "$EVENTS" \
        --event-mix realistic --publish-connections "$PUBLISH_CONNECTIONS" \
        --fanout-subscribers "$FANOUT_SUBSCRIBERS" --fanout-events "$FANOUT_EVENTS" \
        --fanout-window "$FANOUT_WINDOW" \
        --connections "$IDLE_CONNECTIONS" --hold-seconds "$HOLD_SECONDS"; then
        status=1
    fi
    if [[ $status -eq 0 ]] && ! run_bench "$target" "$repetition" "$url" lifecycle \
        --scenario ws_publish_scaled --events "$LIFECYCLE_EVENTS" --event-mix lifecycle \
        --publish-connections "$LIFECYCLE_CONNECTIONS"; then
        status=1
    fi
    if [[ $status -eq 0 && -n $RATE_STEPS ]] && ! rate_sweep "$target" "$repetition" "$url"; then
        status=1
    fi

    remote_command "$RELAY_SSH" "$CONTROL_REMOTE" collect-stop "$target" "$server_artifacts" ||
        status=1
    # After the stop, so the export holds everything the relay wrote, even
    # when it failed.
    if [[ -n $RATE_STEPS ]] && ! reconcile_rate_steps "$target" "$repetition"; then
        status=1
    fi
    if copy_to_load -r "$server_artifacts/." "$run_root/server/"; then
        phase_io "$target" "$repetition"
    else
        status=1
    fi
    if [[ $status -ne 0 ]]; then
        echo "campaign phase failed for $target repetition $repetition" >&2
        return "$status"
    fi
}

# Prints how many corpus events each relay must keep: all of a realistic
# corpus, and of a social one the count its manifest gives.
retained_events() {
    if [[ $CORPUS_MIX == realistic ]]; then
        echo "$EVENTS"
        return
    fi
    local retained
    retained=$(remote_command "$LOAD_SSH" jq -er .corpus.social.retained \
        "$LOAD_CORPUS_DIR/manifest.json") || retained=
    [[ $retained =~ ^[1-9][0-9]*$ ]] ||
        die "$LOAD_CORPUS_DIR/manifest.json gives no retained count for the social corpus"
    echo "$retained"
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
        "relay_bench_bin=$RELAY_BENCH_BIN"
        "corpus_mix=$CORPUS_MIX"
        "social_authors=$SOCIAL_AUTHORS"
        "events=$EVENTS"
        "retained=$RETAINED"
        "queries=$QUERIES"
        "deep_pages=$DEEP_PAGES"
        "repetitions=$REPETITIONS"
        "publish_connections=$PUBLISH_CONNECTIONS"
        "fanout_subscribers=$FANOUT_SUBSCRIBERS"
        "fanout_events=$FANOUT_EVENTS"
        "fanout_window=$FANOUT_WINDOW"
        "idle_connections=$IDLE_CONNECTIONS"
        "hold_seconds=$HOLD_SECONDS"
        "lifecycle_events=$LIFECYCLE_EVENTS"
        "lifecycle_connections=$LIFECYCLE_CONNECTIONS"
        "rate_steps=$RATE_STEPS"
        "rate_secs=$RATE_SECS"
        "rate_drain_secs=$RATE_DRAIN_SECS"
        "rate_connections=$RATE_CONNECTIONS"
        "rate_p99_ms=$RATE_P99_MS"
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
    if [[ -n $RELAY_COPY_SSH ]]; then
        remote_command "$LOAD_SSH" ssh -o BatchMode=yes -o ConnectTimeout=10 "$RELAY_COPY_SSH" true ||
            die "the load host cannot reach the relay host over SSH at $RELAY_COPY_SSH"
    fi
    if [[ -n $RATE_STEPS ]]; then
        remote_command "$RELAY_SSH" test -x "$RELAY_BENCH_BIN" ||
            die "RATE_STEPS needs wok-bench on the relay host at $RELAY_BENCH_BIN"
    fi
    stop_load_units

    local corpus_args=(--event-mix "$CORPUS_MIX")
    if [[ $CORPUS_MIX == social ]]; then
        corpus_args+=(--social-authors "$SOCIAL_AUTHORS")
    fi
    load_unit_command "$BENCH_BIN" \
        --generate-corpus-only --events "$EVENTS" "${corpus_args[@]}" \
        --seed "$SEED" --base-timestamp "$BASE_TIMESTAMP" --out "$LOAD_CORPUS_DIR"
    remote_command "$LOAD_SSH" "${LOAD_UNIT_COMMAND[@]}"
    RETAINED=$(retained_events)
    write_campaign_metadata
    copy_to_relay "$LOAD_CORPUS" "$RELAY_CORPUS"

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
