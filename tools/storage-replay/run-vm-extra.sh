#!/usr/bin/env bash
# #257 item 12, second pass, after run-vm.sh: RocksDB with newest-first keys,
# on the recorded history and on that history committed 16 times (a deeper
# tree, as a larger relay's).
#
#   run-vm-extra.sh <commit> <base dir>
set -u
sha=$1 base=$2
src=/opt/relay-bench/src/wok-perf257-replay
status=$base/status
until grep -qx done "$status"; do sleep 30; done
git -C /opt/relay-bench/src/wok-perf257 fetch -q origin
git -C "$src" checkout -q --detach "$sha"
# Debian's libclang1-19 lacks clang's own headers; bindgen takes GCC's.
(cd "$src/tools/storage-replay" && LIBCLANG_PATH=/usr/lib/llvm-19/lib \
  BINDGEN_EXTRA_CLANG_ARGS=-I/usr/lib/gcc/x86_64-linux-gnu/14/include cargo build --release --locked > "$base/build-replay-extra.log" 2>&1) \
  || { echo "replay build failed ($sha)" >> "$status"; exit 1; }
replay=$src/tools/storage-replay/target/release/storage-replay
{ echo "built replay $sha"; sha256sum "$replay"; } >> "$status"
for mix in realistic social; do
  for variant in nf nf-x16; do
    case $variant in
      nf) flags=(--rocks-newest-first) ;;
      nf-x16) flags=(--rocks-newest-first --preload-repeat 16) ;;
    esac
    out=$base/replay-$mix-rocksdb-$variant.json
    [[ -s $out ]] && continue
    db=$base/db-$mix-rocksdb-$variant
    rm -rf "$db"
    /usr/bin/time -v "$replay" --log "$base/$mix.ops.zst" --engine rocksdb "${flags[@]}" \
      --dir "$db" --out "$out" > "$base/replay-$mix-rocksdb-$variant.log" 2>&1
    echo "replay $mix rocksdb-$variant exit $? footprint $(du -sb "$db" | cut -f1)" >> "$status"
    rm -rf "$db"
  done
done
echo "done extra" >> "$status"
