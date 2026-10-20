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
  witness item count can succeed and fixes every rewritten read's height; it costs more varops. By default it
  chooses how deep a read must be by compressing with each candidate threshold.
- **Analysis**: `gsr disasm` lists a script readably; `gsr attribute` splits a compressed script's bytes over
  labelled parts of the plain script it was made from; `gsr near-duplicates` finds sequences that repeat except
  for a pushed number or two (a depth, an offset), which would compress if the numbers agreed.

## Command line

```sh
cargo install --git https://github.com/bitcoin-gsr/gsr-tooling
```

Scripts are hex, read from a file or stdin and written to a file or stdout.

```sh
gsr check script.hex                    # exit code 1 on errors
gsr check --json --deny warnings script.hex
gsr anchor script.hex -o anchored.hex   # the threshold that compresses best (or --min-depth N); JSON on stderr
gsr compress script.hex -o out.hex      # summary as JSON on stderr
gsr compress --protect 2949 script.hex  # keep the main script's first 2949 bytes literal at their offsets
gsr unroll out.hex                      # the script it runs
gsr info --bounds out.hex               # sizes, unrolling charge and lower bounds as JSON
gsr disasm out.hex                      # one instruction per line with its offset; references as call<k>
gsr attribute out.hex --plain script.hex --labels ranges.txt   # bytes per label (lines `start end label`), JSON
gsr near-duplicates anchored.hex        # repeats that differ in a pushed number, by estimated saving
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
let (anchored, _) = gsr::anchor(&script, 256, 0)?;        // or why it cannot prove the rewrite; anchor_auto
let (out, stats) = gsr::compress(&anchored, 0)?;          // unrolls to exactly `anchored`
let info = gsr::info(&out)?;                              // declarations, unrolled size, unrolling charge
```

`compress` runs six search configurations in parallel; a 160 kB script takes 2–30 s, an anchored one up to two
minutes. `anchor_auto` compresses with each candidate threshold, a few at a time.

## Develop

```sh
cargo test
GSR_REFERENCE_DIR=dir cargo test --release -- --ignored   # larger reference scripts, see tests/reference.rs
contrib/extract-core.py ~/bitcoin [commit]                # refresh tests/data/core from Bitcoin Core
```
