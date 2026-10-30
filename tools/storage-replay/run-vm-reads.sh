#!/usr/bin/env bash
# #257 item 12, read follow-up: replay each recorded log on LMDB and on
# RocksDB variants, then run the read suite on each settled database.
# Databases are kept under <base> for profiling; remove them when done.
#
#   run-vm-reads.sh <commit> <base dir> <log dir> [arm ...]
#
# <log dir> holds realistic.ops.zst and social.ops.zst from run-vm.sh.
# Arms are mix:name, e.g. realistic:rocks-read-nf; all when none are given.
set -u
sha=$1 base=$2 logs=$3
shift 3
src=/opt/relay-bench/src/wok-perf257-replay
status=$base/status
mkdir -p "$base"
git -C /opt/relay-bench/src/wok-perf257 fetch -q origin \
  +bench/storage-replay-reads:refs/remotes/origin/bench/storage-replay-reads
git -C "$src" checkout -q --detach "$sha"
# Debian's libclang1-19 lacks clang's own headers; bindgen takes GCC's.
(cd "$src/tools/storage-replay" && LIBCLANG_PATH=/usr/lib/llvm-19/lib \
  BINDGEN_EXTRA_CLANG_ARGS=-I/usr/lib/gcc/x86_64-linux-gnu/14/include cargo build --release --locked > "$base/build.log" 2>&1) \
  || { echo "replay build failed ($sha)" >> "$status"; exit 1; }
replay=$src/tools/storage-replay/target/release/storage-replay
{ echo "built $sha"; sha256sum "$replay"; } >> "$status"

declare -A arms=(
  [lmdb]="--engine lmdb"
  [rocks-v1]="--engine rocksdb"
  [rocks-v1-nf]="--engine rocksdb --rocks-newest-first"
  [rocks-read-nf]="--engine rocksdb --rocks-newest-first --rocks-profile read"
  [rocks-read-nf-cover]="--engine rocksdb --rocks-newest-first --rocks-profile read --rocks-covering"
  [rocks-v1-nf-x16]="--engine rocksdb --rocks-newest-first --preload-repeat 16"
  [rocks-read-nf-cover-x16]="--engine rocksdb --rocks-newest-first --rocks-profile read --rocks-covering --preload-repeat 16"
)
order=(lmdb rocks-v1 rocks-v1-nf rocks-read-nf rocks-read-nf-cover)
if (($# == 0)); then
  set --
  for mix in realistic social; do
    for arm in "${order[@]}"; do set -- "$@" "$mix:$arm"; done
  done
fi
for item in "$@"; do
  mix=${item%%:*} arm=${item#*:}
  out=$base/$mix-$arm.json
  [[ -s $out ]] && continue
  db=$base/db-$mix-$arm
  rm -rf "$db"
  # shellcheck disable=SC2086
  /usr/bin/time -v "$replay" --log "$logs/$mix.ops.zst" ${arms[$arm]} \
    --read-suite-secs 20 --dir "$db" --out "$out" > "$base/$mix-$arm.log" 2>&1
  echo "$mix $arm exit $? footprint $(du -sb "$db" | cut -f1)" >> "$status"
done
echo done >> "$status"
