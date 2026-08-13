# wok vs strfry benchmark summary

profile=full seed=1 host=sixteen os=macos arch=aarch64

Each trial uses an identical deterministic corpus for both relays. `ok=false` means a correctness failure, not slowness. Do not rank relays from a single noisy run.

| relay | scenario | ok | throughput/s | p50 ms | p90 ms | p99 ms | max ms | errors | mismatches | notes |
|---|---|---|---|---|---|---|---|---|---|---|
| wok | import | true | 34605.2 | 289.02 | 289.02 | 289.02 | 289.0 | 0 | 0 | imported+verified 10000 events |
| strfry | import | true | 21552.5 | 464.13 | 464.13 | 464.13 | 464.1 | 0 | 0 | imported+verified 10000 events |
| wok | export | true | 626406.2 | 15.97 | 15.97 | 15.97 | 16.0 | 0 | 0 | exported 10000 events |
| strfry | export | true | 182970.3 | 54.66 | 54.66 | 54.66 | 54.7 | 0 | 0 | exported 10000 events |
| wok | negentropy_build | true | 377696.4 | 26.48 | 26.48 | 26.48 | 26.5 | 0 | 0 | negentropy build 1 (default {} tree) |
| strfry | negentropy_build | true | 163702.4 | 61.09 | 61.09 | 61.09 | 61.1 | 0 | 0 | negentropy build 1 (default {} tree) |
| wok | ws_publish_1conn | true | 201.2 | 4.99 | 5.17 | 6.95 | 21.9 | 0 | 0 | 1 conn(s): accepted 9950, rejected 0 |
| strfry | ws_publish_1conn | true | 188.7 | 5.05 | 6.36 | 8.02 | 33.1 | 0 | 0 | 1 conn(s): accepted 9950, rejected 0 |
| wok | ws_publish_8conn | true | 191.9 | 5.01 | 5.79 | 10.06 | 67.4 | 0 | 0 | 8 conn(s): accepted 9950, rejected 0 |
| strfry | ws_publish_8conn | true | 181.6 | 5.02 | 6.36 | 13.62 | 36.8 | 0 | 0 | 8 conn(s): accepted 9950, rejected 0 |
| wok | ws_query_latency | true | 9012.9 | 0.10 | 0.16 | 0.22 | 0.3 | 0 | 0 | 780 mixed REQs, 14040 events returned |
| strfry | ws_query_latency | true | 9666.8 | 0.09 | 0.16 | 0.30 | 0.3 | 0 | 0 | 780 mixed REQs, 14040 events returned |
| wok | live_fanout | true | 4204.2 | 3.13 | 3.13 | 3.13 | 3.1 | 0 | 0 | 32 subscribers x 200 events: delivered 6400/6400 |
| strfry | live_fanout | true | 6887.4 | 26.72 | 26.72 | 26.72 | 26.7 | 0 | 0 | 32 subscribers x 200 events: delivered 6400/6400 |
| wok | duplicate_import | true | 170030.9 | 29.41 | 29.41 | 29.41 | 29.4 | 0 | 0 | re-import of identical events (dup detection) |
| strfry | duplicate_import | true | 39297.1 | 127.30 | 127.30 | 127.30 | 127.3 | 0 | 0 | re-import of identical events (dup detection) |
| wok | cold_start | true | 9.6 | 0.10 | 0.10 | 0.10 | 0.1 | 0 | 0 | relay ready + first query answered in 104 ms |
| strfry | cold_start | true | 9.6 | 0.10 | 0.10 | 0.10 | 0.1 | 0 | 0 | relay ready + first query answered in 104 ms |

Reproduction:

```bash
cargo build --release -p wok-cli -p wok-bench
./target/release/wok-bench --profile full --out bench-results --strfry /Users/jeff/code/strfry/strfry --wok ./target/release/wok --seed 1
```
