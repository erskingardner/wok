#!/usr/bin/env bash
# #257 item 12: record db_write's writes on both corpora, then replay each log
# on LMDB (control), LMDB with MDB_NOMETASYNC, and RocksDB.
#
#   run-vm.sh <commit> <base dir>
#
# Builds in its own worktree of /opt/relay-bench/src/wok-perf257. Each
# database is removed after its run; reports and logs stay under <base>.
set -u
sha=$1 base=$2
src=/opt/relay-bench/src/wok-perf257-replay
status=$base/status
mkdir -p "$base"
git -C /opt/relay-bench/src/wok-perf257 fetch -q origin
[[ -d $src ]] || git -C /opt/relay-bench/src/wok-perf257 worktree add -q --detach "$src" "$sha"
git -C "$src" checkout -q --detach "$sha"
(cd "$src" && cargo build --release --locked -p wok-bench --features op-log > "$base/build-bench.log" 2>&1) \
  || { echo "wok-bench build failed" >> "$status"; exit 1; }
(cd "$src/tools/storage-replay" && LIBCLANG_PATH=/usr/lib/llvm-19/lib cargo build --release --locked > "$base/build-replay.log" 2>&1) \
  || { echo "replay build failed" >> "$status"; exit 1; }
bench=$src/target/release/wok-bench
replay=$src/tools/storage-replay/target/release/storage-replay
{ echo "built $sha"; sha256sum "$bench" "$replay"; } >> "$status"

declare -A corpus=(
  [realistic]=/var/lib/relay-bench/scratch-perf257/combined/corpus.jsonl
  [social]=/var/lib/relay-bench/scratch-social/corpus/corpus.jsonl
)
for mix in realistic social; do
  log=$base/$mix.ops.zst
  if [[ ! -s $log ]]; then
    /usr/bin/time -v "$bench" --scenario db_write --corpus "${corpus[$mix]}" \
      --dataset-dir "$base/datasets" --db-batches 1,8,64,512 --db-step-events 20000 \
      --db-record-ops "$log" --out "$base/record-$mix" > "$base/record-$mix.log" 2>&1
    echo "record $mix exit $? $(stat -c %s "$log") bytes" >> "$status"
  fi
  for engine in lmdb rocksdb lmdb-nometasync; do
    out=$base/replay-$mix-$engine.json
    [[ -s $out ]] && continue
    db=$base/db-$mix-$engine
    rm -rf "$db"
    /usr/bin/time -v "$replay" --log "$log" --engine $engine --dir "$db" --out "$out" \
      > "$base/replay-$mix-$engine.log" 2>&1
    echo "replay $mix $engine exit $? footprint $(du -sb "$db" | cut -f1)" >> "$status"
    rm -rf "$db"
  done
done
echo done >> "$status"
