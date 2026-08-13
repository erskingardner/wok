# wok vs strfry benchmark summary

profile=full seed=1 host=sixteen os=macos arch=aarch64

Each trial uses an identical deterministic corpus for both relays. `ok=false` means a correctness failure, not slowness. Do not rank relays from a single noisy run.

| relay | scenario | ok | throughput/s | p50 ms | p90 ms | p99 ms | max ms | errors | mismatches | notes |
|---|---|---|---|---|---|---|---|---|---|---|
| wok | import | true | 33017.3 | 303.10 | 303.10 | 303.10 | 303.1 | 0 | 0 | imported+verified 10000 events |
| strfry | import | true | 21245.4 | 470.78 | 470.78 | 470.78 | 470.8 | 0 | 0 | imported+verified 10000 events |
| wok | export | true | 682702.6 | 14.65 | 14.65 | 14.65 | 14.6 | 0 | 0 | exported 10000 events |
| strfry | export | true | 180023.0 | 55.55 | 55.55 | 55.55 | 55.6 | 0 | 0 | exported 10000 events |
| wok | negentropy_build | true | 354389.0 | 28.22 | 28.22 | 28.22 | 28.2 | 0 | 0 | negentropy build 1 (default {} tree) |
| strfry | negentropy_build | true | 162534.2 | 61.53 | 61.53 | 61.53 | 61.5 | 0 | 0 | negentropy build 1 (default {} tree) |
| wok | ws_publish_1conn | true | 200.6 | 4.99 | 5.19 | 6.99 | 25.9 | 0 | 0 | 1 conn(s): accepted 9950, rejected 0 |
| strfry | ws_publish_1conn | true | 191.1 | 5.01 | 5.24 | 12.49 | 24.2 | 0 | 0 | 1 conn(s): accepted 9950, rejected 0 |
| wok | ws_publish_8conn | true | 186.2 | 4.98 | 5.79 | 13.45 | 215.4 | 0 | 0 | 8 conn(s): accepted 9950, rejected 0 |
| strfry | ws_publish_8conn | true | 172.4 | 5.04 | 7.73 | 14.60 | 34.2 | 0 | 0 | 8 conn(s): accepted 9950, rejected 0 |
| wok | ws_query_latency | true | 6722.5 | 0.13 | 0.24 | 0.30 | 0.3 | 0 | 0 | 380 mixed REQs, 6840 events returned |
| strfry | ws_query_latency | true | 9141.3 | 0.09 | 0.17 | 0.29 | 0.3 | 0 | 0 | 380 mixed REQs, 6840 events returned |
| wok | live_fanout | true | 7521.0 | 1.36 | 1.36 | 1.36 | 1.4 | 0 | 0 | 32 subscribers x 200 events: delivered 6400/6400 |
| strfry | live_fanout | true | 6920.7 | 72.13 | 72.13 | 72.13 | 72.1 | 0 | 0 | 32 subscribers x 200 events: delivered 6400/6400 |
| wok | duplicate_import | true | 165912.5 | 30.14 | 30.14 | 30.14 | 30.1 | 0 | 0 | re-import of identical events (dup detection) |
| strfry | duplicate_import | true | 38728.0 | 129.15 | 129.15 | 129.15 | 129.2 | 0 | 0 | re-import of identical events (dup detection) |
| wok | cold_start | true | 9.6 | 0.10 | 0.10 | 0.10 | 0.1 | 0 | 0 | relay ready + first query answered in 104 ms |
| strfry | cold_start | true | 9.7 | 0.10 | 0.10 | 0.10 | 0.1 | 0 | 0 | relay ready + first query answered in 103 ms |

Reproduction:

```bash
cargo build --release -p wok-cli -p wok-bench
./target/release/wok-bench --profile full --out bench-results --strfry /Users/jeff/code/strfry/strfry --wok ./target/release/wok --seed 1
```
