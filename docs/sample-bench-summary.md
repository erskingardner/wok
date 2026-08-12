# wok vs strfry benchmark summary

profile=smoke seed=1 os=macos arch=aarch64  
Host recorded as `unknown` in this checked-in sample (no HOSTNAME in the harness environment).  
Do not rank relays from a single noisy run. `ok=false` means a correctness failure.

| relay | scenario | ok | accepted/s | delivered/s | p50 ms | errors | mismatches | notes |
|---|---|---|---|---|---|---|---|---|
| wok | bulk_import | true | 1280.9 | 0.0 | 23.0 | 0 | 0 | imported and exported 50 events |
| strfry | bulk_import | true | 403.1 | 0.0 | 65.0 | 0 | 0 | imported and exported 50 events |
| wok | id_lookup | true | 0.0 | 0.0 | 5.0 | 0 | 0 | scan count=10 |
| strfry | id_lookup | true | 0.0 | 0.0 | 49.0 | 0 | 0 | scan count=10 |
| wok | unix_pub_sub | true | 419.7 | 0.0 | 1.0 | 0 | 0 | import/scan stand-in; Unix correctness is in e2e_transports |

Machine-readable companion: [sample-bench-results.jsonl](sample-bench-results.jsonl)

Reproduction:

```bash
cargo build --release -p wok-cli -p wok-bench
./target/release/wok-bench --profile smoke --out bench-results \
  --strfry /Users/jeff/code/strfry/strfry \
  --wok ./target/release/wok --seed 1
```
