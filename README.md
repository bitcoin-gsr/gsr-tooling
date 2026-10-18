# gsr-tooling

Tools for Tapleaf 0xC2 scripts (the GSR opcode set: BIP 440 varops, BIP 441 reusable macros), as implemented by
[jmoik/bitcoin `gsr`](https://github.com/jmoik/bitcoin/tree/gsr) @ `ad6c16f`. For now: the macro compressor.

It shrinks a script by searching for a small reusable-macro grammar (`OP_MACRO` declarations, `OP_CALLMACRO`
references) that unrolls to exactly the same script. It minimizes the exact committed size (every declaration
header, CompactSize index and body) and reports the unrolling charge the macros add to the varops cost. The
problem statement, cost model and results are in [docs/macro-optimization.md](docs/macro-optimization.md).

## Command line

```sh
cargo install --git https://github.com/bitcoin-gsr/gsr-tooling
```

Scripts are hex, read from a file or stdin and written to a file or stdout.

```sh
gsr compress script.hex -o out.hex      # summary as JSON on stderr
gsr compress --protect 2949 script.hex  # keep the main script's first 2949 bytes literal at their offsets
gsr unroll out.hex                      # the script it runs
gsr info --bounds out.hex               # sizes, unrolling charge and lower bounds as JSON
```

## Library

```toml
[dependencies]
gsr-tooling = { git = "https://github.com/bitcoin-gsr/gsr-tooling" }
```

```rust
let (out, stats) = gsr_tooling::optimize(&script, 0)?;   // unrolls to exactly `script`
let info = gsr_tooling::info(&out)?;                     // declarations, unrolled size, unrolling charge
```

`optimize` runs six search configurations in parallel; a 160 kB script takes 2–30 s.

## Develop

```sh
cargo test
GSR_REFERENCE_DIR=dir cargo test --release -- --ignored   # larger reference scripts, see tests/reference.rs
```
