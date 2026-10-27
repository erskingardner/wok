#!/usr/bin/env bash
# Relay-host helper for benchmark campaigns. Runs as root.
#
# Each relay under test is a named target, described by
# /etc/relay-bench/targets/<name>.env:
#
#   # wok or strfry
#   KIND=wok
#   BINARY=/opt/relay-bench/bin/wok-master/wok
#   CONFIG=/etc/relay-bench/wok-master.toml
#   PORT=7777
#   # Optional: Prometheus endpoint, checkout whose commit is recorded, and
#   # service account (created if missing).
#   METRICS_URL=http://10.0.0.2:7777/metrics
#   SOURCE=/opt/relay-bench/src/wok-master
#   USER=relay-bench
#
# Comments go on their own lines. CONFIG must put the database in
# /var/lib/relay-bench/<name>/db: Wok's [database] path, or strfry's db. The
# relay runs as the transient unit relay-bench-target-<name>.service, so
# --cpus (AllowedCPUs) and --memory (MemoryMax, which under cgroup v2
# includes the page cache the relay reads through) bound the relay process
# alone, and it can write only under its own /var/lib/relay-bench/<name>.
set -euo pipefail

# Tests relocate every root under RELAY_BENCH_PREFIX.
PREFIX=${RELAY_BENCH_PREFIX:-}
TARGETS_ROOT=$PREFIX/etc/relay-bench/targets
STATE_ROOT=$PREFIX/var/lib/relay-bench
SNAPSHOT_ROOT=$STATE_ROOT/snapshots
OPT_ROOT=$PREFIX/opt/relay-bench
PROC_ROOT=$PREFIX/proc
UNIT_PREFIX=relay-bench-
SLICE=relay-bench.slice
DEFAULT_USER=relay-bench

die() {
    echo "benchmark-relay-control: $*" >&2
    exit 1
}

usage() {
    cat >&2 <<'EOF'
usage: benchmark-relay-control check TARGET...
       benchmark-relay-control port TARGET
       benchmark-relay-control prepare TARGET CORPUS EVENTS ARTIFACTS
           [--snapshot keep|none] [--cpus LIST] [--memory SIZE] [--nofile N]
       benchmark-relay-control start TARGET ARTIFACTS [--cache cold|warm]
           [--cpus LIST] [--memory SIZE] [--nofile N] [--ready-timeout SECS]
       benchmark-relay-control io-mark TARGET ARTIFACTS LABEL
       benchmark-relay-control collect-stop TARGET ARTIFACTS
       benchmark-relay-control reconcile TARGET WOK_BENCH DIR [--nofile N]
       benchmark-relay-control drop-snapshot TARGET
       benchmark-relay-control stop-all
       benchmark-relay-control status
EOF
    exit 2
}

validate_target_name() {
    # "snapshots" is the snapshot directory beside the targets' databases.
    [[ $1 =~ ^[a-z0-9][a-z0-9._-]{0,62}$ && $1 != snapshots ]] ||
        die "invalid target name: $1"
}

unquote() {
    local value=$1
    if [[ ${#value} -ge 2 && ( ( ${value:0:1} == '"' && ${value: -1} == '"' ) ||
        ( ${value:0:1} == "'" && ${value: -1} == "'" ) ) ]]; then
        value=${value:1:${#value}-2}
    fi
    printf '%s' "$value"
}

# Reads a target file as KEY=VALUE lines rather than sourcing it, so it holds
# only the keys below.
load_target() {
    local name=$1
    validate_target_name "$name"
    TARGET_FILE=$TARGETS_ROOT/$name.env
    [[ -f $TARGET_FILE ]] || die "no target file $TARGET_FILE"
    TARGET=$name
    KIND=
    BINARY=
    CONFIG=
    PORT=
    METRICS_URL=
    SOURCE_CHECKOUT=
    SERVICE_USER=$DEFAULT_USER
    local line key value
    while IFS= read -r line || [[ -n $line ]]; do
        [[ $line =~ ^[[:space:]]*(#.*)?$ ]] && continue
        [[ $line =~ ^([A-Z_]+)=(.*)$ ]] || die "$TARGET_FILE: expected KEY=VALUE: $line"
        key=${BASH_REMATCH[1]}
        value=${BASH_REMATCH[2]}
        [[ $value =~ [[:space:]]# ]] && die "$TARGET_FILE: comments go on their own line: $line"
        value=$(unquote "$value")
        case $key in
            KIND) KIND=$value ;;
            BINARY) BINARY=$value ;;
            CONFIG) CONFIG=$value ;;
            PORT) PORT=$value ;;
            METRICS_URL) METRICS_URL=$value ;;
            SOURCE) SOURCE_CHECKOUT=$value ;;
            USER) SERVICE_USER=$value ;;
            *) die "$TARGET_FILE: unknown key $key" ;;
        esac
    done <"$TARGET_FILE"
    [[ $KIND == wok || $KIND == strfry ]] || die "$TARGET_FILE: KIND must be wok or strfry"
    [[ $BINARY == /* && -x $BINARY ]] ||
        die "$TARGET_FILE: BINARY must be the absolute path of an executable"
    [[ $CONFIG == /* && -f $CONFIG ]] ||
        die "$TARGET_FILE: CONFIG must be the absolute path of a file"
    [[ $PORT =~ ^[1-9][0-9]{0,4}$ && $PORT -le 65535 ]] || die "$TARGET_FILE: PORT must be a TCP port"
    [[ $SERVICE_USER =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] ||
        die "$TARGET_FILE: USER must be an account name"
    DB_ROOT=$STATE_ROOT/$name
    UNIT=${UNIT_PREFIX}target-$name.service
    IMPORT_UNIT=${UNIT_PREFIX}import-$name.service
    EXPORT_UNIT=${UNIT_PREFIX}export-$name.service
    SNAPSHOT_DIR=$SNAPSHOT_ROOT/$name
}

# The first argument lists the options the command takes.
parse_run_options() {
    local allowed=" $1 "
    shift
    RUN_CPUS=
    RUN_MEMORY=
    RUN_CACHE=cold
    RUN_NOFILE=524288
    READY_TIMEOUT=120
    SNAPSHOT_POLICY=none
    while [[ $# -gt 0 ]]; do
        [[ $allowed == *" ${1#--} "* ]] || die "unknown option $1"
        [[ $# -ge 2 ]] || die "option $1 needs a value"
        case $1 in
            --cpus) RUN_CPUS=$2 ;;
            --memory) RUN_MEMORY=$2 ;;
            --cache) RUN_CACHE=$2 ;;
            --nofile) RUN_NOFILE=$2 ;;
            --ready-timeout) READY_TIMEOUT=$2 ;;
            --snapshot) SNAPSHOT_POLICY=$2 ;;
        esac
        shift 2
    done
    [[ -z $RUN_CPUS || $RUN_CPUS =~ ^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$ ]] ||
        die "--cpus takes a CPU list such as 0-7,24-31"
    [[ -z $RUN_MEMORY || $RUN_MEMORY =~ ^[1-9][0-9]*[KMGT]?$ ]] ||
        die "--memory takes a size such as 64G"
    [[ $RUN_CACHE == cold || $RUN_CACHE == warm ]] || die "--cache takes cold or warm"
    [[ $RUN_NOFILE =~ ^[1-9][0-9]*$ ]] || die "--nofile takes a positive integer"
    [[ $READY_TIMEOUT =~ ^[1-9][0-9]*$ ]] || die "--ready-timeout takes seconds"
    [[ $SNAPSHOT_POLICY == keep || $SNAPSHOT_POLICY == none ]] ||
        die "--snapshot takes keep or none"
}

unit_properties() {
    UNIT_PROPS=(
        --slice="$SLICE"
        --uid="$SERVICE_USER"
        --gid="$SERVICE_USER"
        --working-directory="$DB_ROOT"
        -p CPUAccounting=yes
        -p MemoryAccounting=yes
        -p IOAccounting=yes
        -p "LimitNOFILE=$RUN_NOFILE"
        # Whatever CONFIG says, the relay writes only its own target's files.
        -p ProtectSystem=strict
        -p "ReadWritePaths=$DB_ROOT"
    )
    if [[ -n $RUN_CPUS ]]; then
        UNIT_PROPS+=(-p "AllowedCPUs=$RUN_CPUS")
    fi
    if [[ -n $RUN_MEMORY ]]; then
        UNIT_PROPS+=(-p "MemoryMax=$RUN_MEMORY" -p MemorySwapMax=0)
    fi
}

# Prints the database path CONFIG sets: Wok's TOML [database] path (or a
# root database.path), or strfry's top-level db. Comments, other tables and
# nested blocks are skipped; a later setting wins, as it would for the relay.
config_db_path() {
    local config=$1
    local line table='' depth=0 found='' opens closes
    local key='[[:space:]]*=[[:space:]]*(.*[^[:space:]])[[:space:]]*$'
    while IFS= read -r line || [[ -n $line ]]; do
        line=${line%%#*}
        if [[ $KIND == wok ]]; then
            if [[ $line =~ ^[[:space:]]*\[+[[:space:]]*([^]]*[^][:space:]])[[:space:]]*\]+[[:space:]]*$ ]]; then
                table=${BASH_REMATCH[1]}
            elif [[ $table == database && $line =~ ^[[:space:]]*path$key ]] ||
                [[ -z $table && $line =~ ^[[:space:]]*database\.path$key ]]; then
                found=$(unquote "${BASH_REMATCH[1]}")
            fi
        else
            if [[ $depth -eq 0 && $line =~ ^[[:space:]]*db[[:space:]]*[=:][[:space:]]*(.*[^[:space:]])[[:space:]]*$ ]]; then
                found=$(unquote "${BASH_REMATCH[1]}")
            fi
            opens=${line//[^\{]/}
            closes=${line//[^\}]/}
            depth=$((depth + ${#opens} - ${#closes}))
        fi
    done <"$config"
    printf '%s' "$found"
}

# Fails unless CONFIG puts the database where this helper resets, snapshots
# and measures it.
assert_db_config() {
    local path
    path=$(config_db_path "$CONFIG")
    while [[ $path == */ ]]; do
        path=${path%/}
    done
    [[ $path == "$DB_ROOT/db" ]] ||
        die "$CONFIG puts $TARGET's database in '${path:-its default}', not $DB_ROOT/db"
}

# Bytes in a size such as 64G, with systemd's 1024-based suffixes.
memory_bytes() {
    [[ $1 =~ ^([1-9][0-9]*)([KMGT]?)$ ]] || die "not a size: $1"
    local bytes=${BASH_REMATCH[1]}
    case ${BASH_REMATCH[2]} in
        K) bytes=$((bytes << 10)) ;;
        M) bytes=$((bytes << 20)) ;;
        G) bytes=$((bytes << 30)) ;;
        T) bytes=$((bytes << 40)) ;;
    esac
    echo "$bytes"
}

# Prints the smallest memory.max of a cgroup and its ancestors below ROOT,
# or max when none is set.
effective_memory_max() {
    local dir=$1
    local root=$2
    local value lowest=max
    while [[ $dir == "$root"/* ]]; do
        if [[ -f $dir/memory.max ]]; then
            value=$(<"$dir/memory.max")
            if [[ $value != max ]] && [[ $lowest == max || $value -lt $lowest ]]; then
                lowest=$value
            fi
        fi
        dir=${dir%/*}
    done
    echo "$lowest"
}

# Apparent size of the database files a warm start reads.
database_bytes() {
    local file total=0
    for file in "$DB_ROOT"/db/*.mdb; do
        total=$((total + $(stat -c %s -- "$file")))
    done
    echo "$total"
}

# Prints "file size resident" for each database file: its size and the bytes
# of it in the page cache, counted in whole pages.
database_residency() {
    local file resident
    for file in "$DB_ROOT"/db/*.mdb; do
        resident=$(fincore --bytes --noheadings --output RES -- "$file")
        printf '%s %s %s\n' "$file" "$(stat -c %s -- "$file")" "${resident//[[:space:]]/}"
    done
}

# Prints the files of a database_residency listing that are not wholly in the
# page cache. Whole pages cover a file only when their bytes reach its size.
uncached_database_files() {
    awk '$3 < $2 { print $1 }' "$1"
}

assert_benchmark_path() {
    local path=$1
    case /$path/ in
        */../* | */./*) die "refusing a path with . or .. components: $path" ;;
    esac
    case $path in
        "$OPT_ROOT"/campaigns/?* | "$OPT_ROOT"/results/?*) ;;
        *) die "refusing non-benchmark path: $path" ;;
    esac
}

sha_of() {
    local sum
    read -r sum _ < <(sha256sum -- "$1")
    printf '%s' "$sum"
}

ensure_service_user() {
    id -u "$SERVICE_USER" >/dev/null 2>&1 ||
        useradd --system --user-group --no-create-home --home-dir /nonexistent \
            --shell /usr/sbin/nologin "$SERVICE_USER"
}

stop_all() {
    # Also stops units named by earlier versions of this script, such as
    # relay-bench-wok.service.
    systemctl stop "${UNIT_PREFIX}*.service"
}

reset_db() {
    ensure_service_user
    install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$DB_ROOT"
    find "$DB_ROOT" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
    # Both relays keep LMDB in a db child. Wok creates it, while strfry
    # requires the directory to exist before mdb_env_open.
    install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$DB_ROOT/db"
}

import_corpus() {
    local corpus=$1
    local artifacts=$2
    systemctl reset-failed "$IMPORT_UNIT" 2>/dev/null || true
    unit_properties
    # systemd opens the corpus and output files as root before it drops to
    # the service user. With --wait, systemd-run reports the unit's runtime,
    # CPU, peak memory and I/O.
    if ! systemd-run --wait --unit="$IMPORT_UNIT" "${UNIT_PROPS[@]}" \
        -p "StandardInput=file:$corpus" \
        -p "StandardOutput=truncate:$artifacts/import.stdout" \
        -p "StandardError=truncate:$artifacts/import.stderr" \
        -- /usr/bin/time -v "$BINARY" --config "$CONFIG" import \
        >"$artifacts/import-unit.txt" 2>&1; then
        die "$TARGET import failed; see $artifacts/import.stderr"
    fi
    [[ -s $DB_ROOT/db/data.mdb ]] ||
        die "$TARGET import wrote no $DB_ROOT/db/data.mdb; CONFIG must put the database there"
}

# Under the import's limits: strfry applies its open-file limit to every
# command.
count_retained() {
    unit_properties
    systemd-run --quiet --wait --pipe --collect --unit="$EXPORT_UNIT" "${UNIT_PROPS[@]}" \
        -- "$BINARY" --config "$CONFIG" export |
        awk 'NF { count += 1 } END { print count + 0 }'
}

snapshot_matches() {
    local identity=$1
    [[ -f $SNAPSHOT_DIR/identity && -f $SNAPSHOT_DIR/retained && -d $SNAPSHOT_DIR/db ]] &&
        [[ $(<"$SNAPSHOT_DIR/identity") == "$identity" ]]
}

take_snapshot() {
    local identity=$1
    local retained=$2
    # Names cannot start with a dot, so staging never collides with a target.
    local staging=$SNAPSHOT_ROOT/.staging-$TARGET
    rm -rf -- "$staging"
    install -d -m 0750 "$staging"
    cp -a --reflink=auto -- "$DB_ROOT/db" "$staging/db"
    printf '%s\n' "$identity" >"$staging/identity"
    printf '%s\n' "$retained" >"$staging/retained"
    rm -rf -- "$SNAPSHOT_DIR"
    mv -- "$staging" "$SNAPSHOT_DIR"
}

restore_snapshot() {
    reset_db
    rm -rf -- "$DB_ROOT/db"
    cp -a --reflink=auto -- "$SNAPSHOT_DIR/db" "$DB_ROOT/db"
    chown -R "$SERVICE_USER:$SERVICE_USER" "$DB_ROOT"
}

write_provenance() {
    local artifacts=$1
    local corpus=$2
    local expected=$3
    local source_commit=
    if [[ -n $SOURCE_CHECKOUT ]]; then
        source_commit=$(git -c "safe.directory=$SOURCE_CHECKOUT" \
            -C "$SOURCE_CHECKOUT" rev-parse HEAD 2>/dev/null || true)
    fi
    cp -- "$TARGET_FILE" "$artifacts/target.env"
    cp -- "$CONFIG" "$artifacts/relay-config"
    {
        echo "target=$TARGET"
        echo "kind=$KIND"
        echo "unit=$UNIT"
        echo "binary=$BINARY"
        echo "config=$CONFIG"
        echo "corpus=$corpus"
        echo "expected_events=$expected"
        echo "source_checkout=$SOURCE_CHECKOUT"
        echo "source_checkout_commit=$source_commit"
        uname -a
        lscpu
        free -b
        lsblk -b -o NAME,TYPE,SIZE,ROTA,MODEL,MOUNTPOINTS
    } >"$artifacts/provenance.txt"
}

# Restores the target's snapshot when it was taken from the same kind,
# binary, config, corpus and event count; otherwise resets the database and
# imports the corpus with signature verification.
prepare() {
    local target=$1
    local corpus=$2
    local expected=$3
    local artifacts=$4
    shift 4
    load_target "$target"
    parse_run_options "snapshot cpus memory nofile" "$@"
    assert_benchmark_path "$corpus"
    assert_benchmark_path "$artifacts"
    assert_db_config
    [[ -f $corpus && $expected =~ ^[1-9][0-9]*$ ]] || die "invalid corpus or expected event count"

    stop_all
    install -d -m 0750 "$artifacts"
    write_provenance "$artifacts" "$corpus" "$expected"
    local binary_sha config_sha corpus_sha
    binary_sha=$(sha_of "$BINARY")
    config_sha=$(sha_of "$CONFIG")
    corpus_sha=$(sha_of "$corpus")
    printf '%s  %s\n' "$binary_sha" "$BINARY" "$config_sha" "$CONFIG" \
        "$corpus_sha" "$corpus" >"$artifacts/sha256.txt"
    local identity
    identity=$(printf 'kind=%s\nbinary_sha256=%s\nconfig_sha256=%s\ncorpus_sha256=%s\nevents=%s' \
        "$KIND" "$binary_sha" "$config_sha" "$corpus_sha" "$expected")

    local retained
    if [[ $SNAPSHOT_POLICY == keep ]] && snapshot_matches "$identity"; then
        restore_snapshot
        retained=$(<"$SNAPSHOT_DIR/retained")
        echo "database=restored-snapshot" >"$artifacts/prepare.txt"
    else
        reset_db
        import_corpus "$corpus" "$artifacts"
        retained=$(count_retained)
        echo "database=imported" >"$artifacts/prepare.txt"
    fi
    echo "$retained" >"$artifacts/retained-events.txt"
    [[ $retained -eq $expected ]] || die "$TARGET retained $retained/$expected events"
    if [[ $SNAPSHOT_POLICY == keep ]] && ! snapshot_matches "$identity"; then
        take_snapshot "$identity" "$retained"
        echo "snapshot=taken" >>"$artifacts/prepare.txt"
    fi
    sync
    du -sb "$DB_ROOT" >"$artifacts/database-size-after-import.txt"
}

drop_page_cache() {
    local artifacts=$1
    grep -E '^(MemFree|Cached|Dirty):' /proc/meminfo >"$artifacts/meminfo-before-drop.txt"
    sync
    echo 3 >/proc/sys/vm/drop_caches
    grep -E '^(MemFree|Cached|Dirty):' /proc/meminfo >"$artifacts/meminfo-after-drop.txt"
}

# Samplers run as transient units too, so stop-all ends them even when a
# campaign is interrupted.
start_sampler() {
    local name=$1
    local output=$2
    shift 2
    systemctl reset-failed "${UNIT_PREFIX}sampler-$name.service" 2>/dev/null || true
    systemd-run --quiet --collect --unit="${UNIT_PREFIX}sampler-$name" \
        -p "StandardOutput=truncate:$output" -p StandardError=journal \
        -E LC_ALL=C -E S_TIME_FORMAT=ISO -- "$@"
}

# For failures after the relay unit started: stop it rather than leave a
# half-started relay running.
stop_and_die() {
    systemctl stop "$UNIT" || true
    die "$@"
}

listening() {
    [[ -n $(ss -Hltn "sport = :$PORT") ]]
}

wait_ready() {
    local deadline=$((SECONDS + READY_TIMEOUT))
    until listening; do
        if ! systemctl is-active --quiet "$UNIT"; then
            systemctl status "$UNIT" --no-pager -l >&2 || true
            die "$UNIT exited before it listened on port $PORT"
        fi
        if ((SECONDS >= deadline)); then
            systemctl status "$UNIT" --no-pager -l >&2 || true
            stop_and_die "$UNIT did not listen on port $PORT within $READY_TIMEOUT s"
        fi
        sleep 0.2
    done
}

# Prints each CPU of a list such as 0-3,8 once, in order.
expand_cpu_list() {
    local part first last cpu
    local -a parts
    IFS=, read -r -a parts <<<"$1"
    for part in "${parts[@]}"; do
        first=${part%-*}
        last=${part#*-}
        for ((cpu = first; cpu <= last; cpu++)); do
            echo "$cpu"
        done
    done | sort -n -u | paste -s -d ' ' -
}

# Records the cgroup limits the relay actually runs under, and what a warm
# start left cached, and fails when either differs from what was requested.
# systemd enables the cpuset controller for the unit only when it sets
# AllowedCPUs; cpuset.cpus.effective already accounts for ancestors, while
# memory.max does not.
check_limits() {
    local artifacts=$1
    local cgroup
    cgroup=/sys/fs/cgroup$(systemctl show "$UNIT" -p ControlGroup --value)
    local cpus=unrestricted
    local memory=max
    if [[ -f $cgroup/cpuset.cpus.effective ]]; then
        cpus=$(<"$cgroup/cpuset.cpus.effective")
    fi
    if [[ -f $cgroup/memory.max ]]; then
        memory=$(<"$cgroup/memory.max")
    fi
    local effective cached
    effective=$(effective_memory_max "$cgroup" /sys/fs/cgroup)
    cached=$(awk '$1 == "file" { print $2 }' "$cgroup/memory.stat" 2>/dev/null)
    printf 'cpuset.cpus.effective=%s\nmemory.max=%s\nmemory.max.effective=%s\nmemory.stat.file=%s\n' \
        "$cpus" "$memory" "$effective" "$cached" >"$artifacts/cgroup-limits.txt"
    database_residency >"$artifacts/cache-at-start.txt"
    if [[ -n $RUN_MEMORY ]]; then
        local page wanted
        page=$(getconf PAGESIZE)
        wanted=$(memory_bytes "$RUN_MEMORY")
        # The kernel rounds memory.max down to whole pages.
        wanted=$((wanted / page * page))
        [[ $effective == "$wanted" ]] ||
            stop_and_die "$UNIT runs under a memory cap of $effective bytes, not the requested $RUN_MEMORY ($wanted)"
    fi
    if [[ -n $RUN_CPUS && ( $cpus == unrestricted ||
        $(expand_cpu_list "$cpus") != "$(expand_cpu_list "$RUN_CPUS")" ) ]]; then
        stop_and_die "$UNIT runs on CPUs $cpus, not the requested $RUN_CPUS"
    fi
    local uncached
    uncached=$(uncached_database_files "$artifacts/cache-at-start.txt")
    if [[ $RUN_CACHE == warm && -n $uncached ]]; then
        stop_and_die "$UNIT is not warm: part of $uncached is not in the page cache; see $artifacts/cache-at-start.txt"
    fi
}

start_measurement() {
    local target=$1
    local artifacts=$2
    shift 2
    load_target "$target"
    parse_run_options "cache cpus memory nofile ready-timeout" "$@"
    assert_benchmark_path "$artifacts"
    [[ -s $DB_ROOT/db/data.mdb ]] || die "$TARGET has no database; run prepare first"
    assert_db_config
    if [[ $RUN_CACHE == warm && -n $RUN_MEMORY ]] &&
        (($(database_bytes) >= $(memory_bytes "$RUN_MEMORY"))); then
        die "the $(database_bytes)-byte database does not fit in --memory $RUN_MEMORY; it cannot start warm"
    fi
    install -d -m 0750 "$artifacts"
    stop_all
    systemctl reset-failed "$UNIT" 2>/dev/null || true
    drop_page_cache "$artifacts"

    local command=("$BINARY" --config "$CONFIG" relay)
    if [[ $RUN_CACHE == warm ]]; then
        # Read the database inside the relay's own unit, so the warmed pages
        # count against its memory cap.
        # shellcheck disable=SC2016
        command=(/bin/sh -c 'for file in "$1"/*.mdb; do cat -- "$file" >/dev/null || exit 1; done; shift; exec "$@"'
            warm "$DB_ROOT/db" "${command[@]}")
    fi
    unit_properties
    systemd-run --unit="$UNIT" "${UNIT_PROPS[@]}" -- "${command[@]}" \
        >"$artifacts/unit-start.txt" 2>&1 ||
        die "could not start $UNIT; see $artifacts/unit-start.txt"
    # Recorded now, so a relay that fails before it is ready still has its
    # journal collected.
    systemctl show "$UNIT" -p InvocationID --value >"$artifacts/invocation-id.txt"
    printf 'cpus=%s\nmemory=%s\ncache=%s\nnofile=%s\n' "${RUN_CPUS:-all}" \
        "${RUN_MEMORY:-unlimited}" "$RUN_CACHE" "$RUN_NOFILE" >"$artifacts/run-options.txt"
    wait_ready
    check_limits "$artifacts"

    local main_pid
    main_pid=$(systemctl show "$UNIT" -p MainPID --value)
    echo "$main_pid" >"$artifacts/main.pid"
    systemctl show "$UNIT" >"$artifacts/systemd-before.properties"
    nstat -az >"$artifacts/nstat-before.txt"
    # node_exporter is optional.
    curl --fail --silent http://127.0.0.1:9100/metrics \
        >"$artifacts/node-metrics-before.prom" || true
    start_sampler pidstat "$artifacts/pidstat.txt" pidstat -h -t -r -u -d -w -p "$main_pid" 1
    start_sampler mpstat "$artifacts/mpstat.txt" mpstat -P ALL 1
    start_sampler iostat "$artifacts/iostat.txt" iostat -x -m -t 1
}

# Appends LABEL, the time, and the running relay's cumulative storage I/O
# (read_bytes and write_bytes of /proc/PID/io, every thread included) to
# ARTIFACTS/io-marks.tsv. The campaign marks each phase's start and end, so
# what a phase made the relay read and write is the difference.
io_mark() {
    local target=$1
    local artifacts=$2
    local label=$3
    load_target "$target"
    assert_benchmark_path "$artifacts"
    [[ $label =~ ^[A-Za-z0-9._-]+$ ]] || die "invalid I/O mark label: $label"
    [[ -s $artifacts/main.pid ]] || die "$TARGET has no recorded main PID in $artifacts"
    local pid
    pid=$(<"$artifacts/main.pid")
    local key value read_bytes='' write_bytes=''
    while read -r key value; do
        case $key in
            read_bytes:) read_bytes=$value ;;
            write_bytes:) write_bytes=$value ;;
        esac
    done <"$PROC_ROOT/$pid/io" || die "cannot read the I/O of $TARGET's process $pid"
    [[ -n $read_bytes && -n $write_bytes ]] || die "no byte counts in $PROC_ROOT/$pid/io"
    printf '%s\t%s\t%s\t%s\n' "$label" "$(date +%s.%N)" "$read_bytes" "$write_bytes" \
        >>"$artifacts/io-marks.tsv"
}

# Writes ARTIFACTS/io-phases.tsv from io-marks.tsv: per phase marked
# PHASE-start and PHASE-end, its seconds and the bytes the relay read and
# wrote in between.
io_phases() {
    local artifacts=$1
    [[ -f $artifacts/io-marks.tsv ]] || return 0
    awk -F '\t' -v OFS='\t' '
        BEGIN { print "phase", "secs", "read_bytes", "write_bytes" }
        $1 ~ /-start$/ {
            phase = substr($1, 1, length($1) - 6)
            started[phase] = $2; read[phase] = $3; written[phase] = $4
            order[++phases] = phase
        }
        $1 ~ /-end$/ {
            phase = substr($1, 1, length($1) - 4)
            if (phase in started) {
                secs[phase] = sprintf("%.3f", $2 - started[phase])
                dread[phase] = $3 - read[phase]; dwrite[phase] = $4 - written[phase]
            }
        }
        END {
            for (i = 1; i <= phases; i++) {
                phase = order[i]
                if (phase in secs) print phase, secs[phase], dread[phase], dwrite[phase]
            }
        }' "$artifacts/io-marks.tsv" >"$artifacts/io-phases.tsv"
}

# Collects evidence even after a failed run, then fails if the relay was no
# longer running when the run ended.
collect_stop() {
    local target=$1
    local artifacts=$2
    load_target "$target"
    assert_benchmark_path "$artifacts"
    install -d -m 0750 "$artifacts"
    local state
    state=$(systemctl show "$UNIT" -p ActiveState --value)
    systemctl stop "${UNIT_PREFIX}sampler-*.service" || true
    if [[ -n $METRICS_URL ]]; then
        curl --fail --silent --show-error "$METRICS_URL" >"$artifacts/relay-metrics.prom" || true
    fi
    curl --fail --silent http://127.0.0.1:9100/metrics \
        >"$artifacts/node-metrics-after.prom" || true
    nstat -az >"$artifacts/nstat-after.txt"
    ss -s >"$artifacts/socket-summary.txt"
    systemctl show "$UNIT" >"$artifacts/systemd-after.properties"
    local invocation=
    if [[ -f $artifacts/invocation-id.txt ]]; then
        invocation=$(<"$artifacts/invocation-id.txt")
    fi
    if [[ -n $invocation ]]; then
        # The relay's own lines, and systemd's about the unit, such as how
        # its process exited.
        journalctl "_SYSTEMD_INVOCATION_ID=$invocation" + "INVOCATION_ID=$invocation" \
            -o short-iso --no-pager >"$artifacts/journal.log" || true
    fi
    du -sb "$DB_ROOT" >"$artifacts/database-size-final.txt"
    io_phases "$artifacts"
    systemctl stop "$UNIT" || true
    [[ $state == active ]] || die "$UNIT was $state, not active, when the run ended"
}

# Exports the stopped target's database once, under the import's limits,
# and reconciles each fixed-rate outcome log DIR/<step>/outcomes.jsonl with
# it, writing DIR/<step>/reconciliation.json. Fails when any step has an
# acknowledged event missing or a refused event stored.
reconcile_steps() {
    local target=$1
    local bench=$2
    local dir=$3
    shift 3
    load_target "$target"
    parse_run_options "nofile" "$@"
    assert_benchmark_path "$dir"
    [[ $bench == /* && -x $bench ]] || die "WOK_BENCH must be the absolute path of an executable"
    [[ $(systemctl show "$UNIT" -p ActiveState --value) != active ]] ||
        die "stop $TARGET before reconciling with its export"
    local logs=("$dir"/*/outcomes.jsonl)
    [[ -f ${logs[0]} ]] || die "no outcome logs under $dir"
    local export=$DB_ROOT/reconcile-export.jsonl
    unit_properties
    if ! systemd-run --quiet --wait --pipe --collect --unit="$EXPORT_UNIT" "${UNIT_PROPS[@]}" \
        -- "$BINARY" --config "$CONFIG" export >"$export"; then
        rm -f -- "$export"
        die "$TARGET export failed"
    fi
    local log step status=0
    for log in "${logs[@]}"; do
        step=$(dirname -- "$log")
        "$bench" --reconcile "$log" --relay-export "$export" --out "$step" \
            >"$step/reconcile.txt" 2>&1 || status=1
    done
    rm -f -- "$export"
    return "$status"
}

check_targets() {
    local tool
    for tool in systemd-run systemctl journalctl ss nstat pidstat mpstat iostat runuser \
        sha256sum curl lscpu lsblk fincore; do
        command -v "$tool" >/dev/null || die "missing tool on the relay host: $tool"
    done
    [[ -x /usr/bin/time ]] || die "missing /usr/bin/time"
    [[ -f /sys/fs/cgroup/cgroup.controllers ]] || die "the relay host must use cgroup v2"
    local target
    for target in "$@"; do
        load_target "$target"
        assert_db_config
        printf '%s kind=%s port=%s binary=%s config=%s\n' \
            "$TARGET" "$KIND" "$PORT" "$BINARY" "$CONFIG"
    done
}

status_report() {
    systemctl list-units --all --no-legend --plain "${UNIT_PREFIX}*" || true
    ss -ltnp || true
}

main() {
    [[ $# -ge 1 ]] || usage
    local action=$1
    shift
    [[ ${EUID} -eq 0 ]] || die "benchmark relay control must run as root"
    case $action in
        check)
            [[ $# -ge 1 ]] || usage
            check_targets "$@"
            ;;
        port)
            [[ $# -eq 1 ]] || usage
            load_target "$1"
            echo "$PORT"
            ;;
        prepare)
            [[ $# -ge 4 ]] || usage
            prepare "$@"
            ;;
        start)
            [[ $# -ge 2 ]] || usage
            start_measurement "$@"
            ;;
        io-mark)
            [[ $# -eq 3 ]] || usage
            io_mark "$@"
            ;;
        collect-stop)
            [[ $# -eq 2 ]] || usage
            collect_stop "$@"
            ;;
        reconcile)
            [[ $# -ge 3 ]] || usage
            reconcile_steps "$@"
            ;;
        drop-snapshot)
            [[ $# -eq 1 ]] || usage
            load_target "$1"
            rm -rf -- "$SNAPSHOT_DIR"
            ;;
        stop-all)
            [[ $# -eq 0 ]] || usage
            stop_all
            ;;
        status)
            [[ $# -eq 0 ]] || usage
            status_report
            ;;
        *)
            usage
            ;;
    esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
