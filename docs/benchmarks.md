# Benchmarks

Harness: `wok-bench`. Always uses disposable temp directories.

```bash
cargo build --release -p wok-cli -p wok-bench
./target/release/wok-bench --profile smoke --out bench-results \
  --strfry /Users/jeff/code/strfry/strfry \
  --wok ./target/release/wok --seed 1
```

`--profile full` runs the 18 named scenarios. Supply `--corpus path.jsonl` for replay (file is not committed).

A trial with missing events, unexpected rejections, or subscriber drops is `ok=false`. Do not declare a winner from one noisy run.

Sample output from a smoke run is in `docs/sample-bench-summary.md` (regenerate with the command above).
