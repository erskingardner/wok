#!/usr/bin/env bash
# Qualifies a relay host and a load host before a benchmark campaign, and
# again at the start of each day of runs: disk sync latency and random reads
# on the relay's database filesystem, the network between the hosts, steal
# time under full CPU load, and the hardware facts results depend on. Run it
# on idle hosts. Commands are rendered here and run over SSH.
# shellcheck disable=SC2029
set -euo pipefail

RELAY_SSH=${RELAY_SSH:-}
LOAD_SSH=${LOAD_SSH:-}
# The relay host's address as the load host reaches it.
RELAY_HOST=${RELAY_HOST:-}
# A directory on the filesystem that will hold the relay databases. The disk
# checks run in a new directory of their own inside it, which is all they remove.
DISK_DIR=${DISK_DIR:-/var/lib/relay-bench}
FIO_SECONDS=${FIO_SECONDS:-60}
IPERF_SECONDS=${IPERF_SECONDS:-60}
STEAL_SECONDS=${STEAL_SECONDS:-60}
# An earlier run's output directory: fail when the sync-write p99 has moved
# by more than 2x since then.
BASELINE=${BASELINE:-}
# Fail when either host's average steal, in percent, is above this.
STEAL_LIMIT=${STEAL_LIMIT:-1}
OUT=${OUT:-qualify-$(date -u +%Y%m%dT%H%M%SZ)}
SCRATCH=
SSH_OPTIONS=(
    -o ControlMaster=auto
    -o ControlPersist=300
    -o 'ControlPath=/tmp/wok-bench-%C'
)

die() {
    echo "benchmark-qualify: $*" >&2
    exit 1
}

remote() {
    local host=$1
    shift
    ssh "${SSH_OPTIONS[@]}" "$host" "$@"
}

validate_settings() {
    local name
    for name in RELAY_SSH LOAD_SSH RELAY_HOST; do
        [[ -n ${!name} ]] || die "$name is required"
    done
    for name in FIO_SECONDS IPERF_SECONDS STEAL_SECONDS; do
        [[ ${!name} =~ ^[1-9][0-9]*$ ]] || die "$name must be a positive integer"
    done
    [[ $DISK_DIR == /* && $DISK_DIR != *..* ]] || die "DISK_DIR must be an absolute path"
    [[ $STEAL_LIMIT =~ ^[0-9]+(\.[0-9]+)?$ ]] || die "STEAL_LIMIT must be a percentage"
    [[ -z $BASELINE || -f $BASELINE/fio-fdatasync.json ]] ||
        die "BASELINE has no fio-fdatasync.json"
    command -v jq >/dev/null || die "missing local tool: jq"
}

# Sets SCRATCH to a new directory under DISK_DIR on the relay host.
create_scratch() {
    local parent
    printf -v parent '%q' "${DISK_DIR%/}"
    SCRATCH=$(remote "$RELAY_SSH" "mkdir -p -- $parent && mktemp -d -- $parent/qualify.XXXXXX")
    [[ $SCRATCH == "${DISK_DIR%/}"/qualify.?????? ]] || die "unexpected scratch directory: $SCRATCH"
}

cleanup() {
    local stop="pkill -f '^iperf3 -s -p 5299' || true"
    if [[ -n $SCRATCH ]]; then
        stop+="; rm -rf -- $(printf '%q' "$SCRATCH")"
    fi
    remote "$RELAY_SSH" "$stop" >/dev/null 2>&1 || true
    ssh "${SSH_OPTIONS[@]}" -O exit "$RELAY_SSH" >/dev/null 2>&1 || true
    ssh "${SSH_OPTIONS[@]}" -O exit "$LOAD_SSH" >/dev/null 2>&1 || true
}

host_facts() {
    # shellcheck disable=SC2016 # expanded on the remote host
    remote "$1" 'for tool in fio iperf3 mpstat numactl openssl jq; do
            command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }
        done
        set -x
        hostname; uname -a; systemd-detect-virt || true; nproc
        lscpu; lscpu -e=CPU,CORE,SOCKET,NODE; numactl -H; free -b
        lsblk -b -o NAME,TYPE,SIZE,ROTA,MODEL,MOUNTPOINTS
        findmnt -no SOURCE,FSTYPE,OPTIONS /
        cat /sys/kernel/mm/transparent_hugepage/enabled /proc/sys/vm/swappiness
        swapon --show
        ip -br link; ip -br addr
        curl -s --max-time 3 http://169.254.169.254/hetzner/v1/metadata || true' 2>&1
}

fio_job() {
    local name=$1
    shift
    remote "$RELAY_SSH" "fio --name=$name --directory=$(printf '%q' "$SCRATCH") \
        --runtime=$FIO_SECONDS --time_based --output-format=json $*" >"$OUT/fio-$name.json"
}

# Saturates every CPU while mpstat samples, so steal shows up if the
# hypervisor lends this host's CPUs to another. One buffer size, since
# -seconds applies to each size openssl tries.
steal_check() {
    local host=$1
    local label=$2
    remote "$host" "openssl speed -multi \$(nproc) -seconds $STEAL_SECONDS -bytes 16384 sha256 \
        >/dev/null 2>&1 &
        LC_ALL=C S_TIME_FORMAT=ISO mpstat -P ALL 1 $STEAL_SECONDS; status=\$?; wait; exit \$status" \
        >"$OUT/mpstat-steal-$label.txt"
}

# Prints the average and the largest per-CPU %steal from mpstat output.
steal_summary() {
    awk '$2 == "CPU" { for (i = 1; i <= NF; i++) if ($i == "%steal") col = i; next }
        $1 == "Average:" && $2 == "all" { avg = $col }
        $1 != "Average:" && $2 ~ /^[0-9]+$/ && col && $col + 0 > max { max = $col + 0 }
        END { printf "average %s%%, worst CPU-second %s%%", avg, max + 0 }' "$1"
}

# Prints the average %steal over every CPU, or fails when mpstat gave none.
steal_average() {
    awk '$2 == "CPU" { for (i = 1; i <= NF; i++) if ($i == "%steal") col = i; next }
        $1 == "Average:" && $2 == "all" && col { avg = $col }
        END { if (avg == "") exit 1; print avg }' "$1"
}

check_steal() {
    local label average
    for label in relay load; do
        average=$(steal_average "$OUT/mpstat-steal-$label.txt") ||
            die "no %steal in $OUT/mpstat-steal-$label.txt"
        awk -v average="$average" -v limit="$STEAL_LIMIT" 'BEGIN { exit !(average <= limit) }' ||
            die "average steal on the $label host is $average%, above STEAL_LIMIT=$STEAL_LIMIT; see #226 on dedicated hardware"
    done
}

check_baseline() {
    local before after
    before=$(jq '.jobs[0].sync.lat_ns.percentile["99.000000"]' "$BASELINE/fio-fdatasync.json")
    after=$(jq '.jobs[0].sync.lat_ns.percentile["99.000000"]' "$OUT/fio-fdatasync.json")
    echo "fdatasync p99 against $BASELINE: $before ns then, $after ns now" | tee -a "$OUT/summary.txt"
    ((after <= 2 * before && before <= 2 * after)) ||
        die "fdatasync p99 moved by more than 2x since $BASELINE; see #226 on dedicated hardware"
}

percentile_ms() {
    jq -r "$1 | (.[\"50.000000\"] / 1e6 | tostring) + \" ms p50, \" +
        (.[\"99.000000\"] / 1e6 | tostring) + \" ms p99, \" +
        (.[\"99.900000\"] / 1e6 | tostring) + \" ms p99.9\"" "$2"
}

iperf_line() {
    jq -r '"\(.end.sum_received.bits_per_second / 1e9 * 100 | round / 100) Gbit/s, \(.end.sum_sent.retransmits // 0) retransmits"' "$1"
}

main() {
    validate_settings
    mkdir -p "$OUT"
    trap cleanup EXIT
    # A trapped signal would otherwise resume the script once cleanup ran.
    trap 'exit 130' INT TERM

    echo "host facts"
    host_facts "$RELAY_SSH" >"$OUT/relay-host.txt"
    host_facts "$LOAD_SSH" >"$OUT/load-host.txt"

    echo "disk: ${FIO_SECONDS}s each of 4 KiB fdatasync writes, and 4 KiB random reads at depth 1 and 4x32"
    create_scratch
    fio_job fdatasync --rw=write --bs=4k --size=256M --ioengine=sync --fdatasync=1
    fio_job randread-qd1 --rw=randread --bs=4k --size=8G --direct=1 --ioengine=libaio --iodepth=1
    fio_job randread-qd128 --rw=randread --bs=4k --size=8G --direct=1 --ioengine=libaio \
        --iodepth=32 --numjobs=4 --group_reporting
    remote "$RELAY_SSH" "rm -rf -- $(printf '%q' "$SCRATCH")"
    SCRATCH=

    echo "network: ping, then iperf3 with 1 and 8 streams each way for ${IPERF_SECONDS}s"
    remote "$LOAD_SSH" "ping -c 100 -i 0.2 -q $(printf '%q' "$RELAY_HOST")" >"$OUT/ping.txt"
    # Only on the address under test; pkill matches this command line's start.
    remote "$RELAY_SSH" "iperf3 -s -p 5299 -B $(printf '%q' "$RELAY_HOST") -D"
    sleep 1
    local streams direction flag
    for streams in 1 8; do
        for direction in load-to-relay relay-to-load; do
            flag=
            [[ $direction == relay-to-load ]] && flag=-R
            remote "$LOAD_SSH" "iperf3 -c $(printf '%q' "$RELAY_HOST") -p 5299 -t $IPERF_SECONDS \
                -P $streams $flag -J" >"$OUT/iperf3-$direction-p$streams.json"
        done
    done
    remote "$RELAY_SSH" "pkill -f '^iperf3 -s -p 5299' || true"

    echo "steal: every CPU busy for ${STEAL_SECONDS}s on each host"
    steal_check "$RELAY_SSH" relay
    steal_check "$LOAD_SSH" load

    {
        echo "qualification $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "relay $RELAY_SSH, load $LOAD_SSH, relay address $RELAY_HOST"
        echo
        echo "fdatasync 4 KiB writes: $(percentile_ms '.jobs[0].sync.lat_ns.percentile' "$OUT/fio-fdatasync.json"), $(jq -r '.jobs[0].write.iops | round' "$OUT/fio-fdatasync.json") writes/s"
        echo "random 4 KiB reads, depth 1: $(jq -r '.jobs[0].read.iops | round' "$OUT/fio-randread-qd1.json") IOPS, $(percentile_ms '.jobs[0].read.clat_ns.percentile' "$OUT/fio-randread-qd1.json")"
        echo "random 4 KiB reads, 4x32: $(jq -r '.jobs[0].read.iops | round' "$OUT/fio-randread-qd128.json") IOPS, $(percentile_ms '.jobs[0].read.clat_ns.percentile' "$OUT/fio-randread-qd128.json")"
        echo "ping: $(tail -1 "$OUT/ping.txt")"
        for streams in 1 8; do
            for direction in load-to-relay relay-to-load; do
                echo "iperf3 $direction, $streams stream(s): $(iperf_line "$OUT/iperf3-$direction-p$streams.json")"
            done
        done
        echo "steal on the relay host: $(steal_summary "$OUT/mpstat-steal-relay.txt")"
        echo "steal on the load host: $(steal_summary "$OUT/mpstat-steal-load.txt")"
    } | tee "$OUT/summary.txt"

    check_steal
    if [[ -n $BASELINE ]]; then
        check_baseline
    fi
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
