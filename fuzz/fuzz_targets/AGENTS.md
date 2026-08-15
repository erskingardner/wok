# fuzz/fuzz_targets

libFuzzer binaries declared in `fuzz/Cargo.toml`.

| File | Role |
| --- | --- |
| `ingress.rs` | Composed target: WS frames/deflate, `ClientCommand` JSON, Negentropy protocol/tree bytes |

The harness looks for panics and sanitizer violations, not "correct" protocol outcomes. Bounded read budgets on fuzz B-tree backends avoid infinite recursion on cyclic nodes. Add new targets here and wire them in `fuzz/Cargo.toml` plus `.github/workflows/fuzz.yml` if they should run on a schedule.
