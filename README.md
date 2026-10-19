# gsr-tooling

Tools for Tapleaf 0xC2 scripts (GSR: BIP 440 varops, BIP 441 restored opcodes, the reusable macros draft), as
implemented by [jmoik/bitcoin `gsr`](https://github.com/jmoik/bitcoin/tree/gsr) @ `ad6c16f`. The crate is `gsr`.

- **Opcodes** (`gsr::opcodes`): what each byte means in leaf 0xC2: names, class (push, OP_SUCCESSx, failing,
  upgradable NOP, conditional, macro), stack effect and origin. Checked against Bitcoin Core's source.
- **Checks** (`gsr check`): consensus errors, policy warnings and lints, without executing the script. Among them:
  OP_SUCCESSx anywhere (the leaf becomes spendable by anyone; in 0xC2 that includes `OP_1NEGATE`, `OP_NEGATE` and
  `OP_ABS`), malformed macros, the unrolled size limit, opcodes that always fail, unbalanced conditionals, the stack
  depth on every path (how many witness items the script takes, exactly one item at the end), non-minimal pushes,
  upgradable NOPs, unused and single-use macros.
- **Macro compression** (`gsr compress`): a small reusable-macro grammar (`OP_MACRO` declarations, `OP_CALLMACRO`
  references) that unrolls to exactly the same script, minimizing the exact committed size. The problem statement,
  cost model and results are in [docs/macro-optimization.md](docs/macro-optimization.md).
- **Bottom-anchored addressing** (`gsr anchor`): rewrites deep reads `<d> OP_PICK|OP_ROLL` as
  `OP_DEPTH <H-d> OP_SUB OP_PICK|OP_ROLL`, which repeat where the relative depths do not, so the script compresses
  better (RISC Zero verifier: 91,550 → 77,321 bytes compressed). Only when the stack analysis proves that one
  witness item count can succeed and fixes every rewritten read's height; it costs more varops.

## Command line

```sh
cargo install --git https://github.com/bitcoin-gsr/gsr-tooling
```

Scripts are hex, read from a file or stdin and written to a file or stdout.

```sh
gsr check script.hex                    # exit code 1 on errors
gsr check --json --deny warnings script.hex
gsr anchor script.hex -o anchored.hex   # reads at least 320 deep (--min-depth), summary as JSON on stderr
gsr compress script.hex -o out.hex      # summary as JSON on stderr
gsr compress --protect 2949 script.hex  # keep the main script's first 2949 bytes literal at their offsets
gsr unroll out.hex                      # the script it runs
gsr info --bounds out.hex               # sizes, unrolling charge and lower bounds as JSON
```

## Library

```toml
[dependencies]
gsr = { git = "https://github.com/bitcoin-gsr/gsr-tooling", default-features = false }
```

Without the default `cli` feature the library has no dependencies.

```rust
use gsr::opcodes::Opcode;

assert!(Opcode::from_u8(0x4f).is_op_success());          // OP_1NEGATE
let report = gsr::check(&script);                         // diagnostics, witness item counts
let (anchored, _) = gsr::anchor(&script, 320, 0)?;        // or why it cannot prove the rewrite
let (out, stats) = gsr::compress(&anchored, 0)?;          // unrolls to exactly `anchored`
let info = gsr::info(&out)?;                              // declarations, unrolled size, unrolling charge
```

`compress` runs six search configurations in parallel; a 160 kB script takes 2–30 s, an anchored one about two
minutes.

## Develop

```sh
cargo test
GSR_REFERENCE_DIR=dir cargo test --release -- --ignored   # larger reference scripts, see tests/reference.rs
contrib/extract-core.py ~/bitcoin [commit]                # refresh tests/data/core from Bitcoin Core
```
