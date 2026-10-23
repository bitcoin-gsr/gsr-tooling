# BIP 441 test vectors

Generates the test vector files of BIP 441 (Tapleaf 0xC2) and its package:

| File | Covers | In Bitcoin Core |
|---|---|---|
| `varops.json` | BIP 440 varops costs | yes |
| `tapleaf_0xc2.json` | Tapleaf 0xC2 execution | yes |
| `op_tx.json` | `OP_TX` | yes |
| `extended_primitives.json` | `OP_CHECKSIGFROMSTACK`, `OP_TWEAKADD`, `OP_BYTEREV` | yes |
| `reusable_macros.json` | reusable macros: decoding, unrolling, execution | yes |
| `extended_primitives_examples.json` | worked examples | no |

Each vector's inputs (comment, script, stack, transaction context) are written in `cases_*.py`; the vectors converted
from gsr's former vector files (gsr `b778e1fa66`) read them from `sources/`, frozen. The results (final stack, varops,
error, unrolling measures) come from the reference implementation: `build.py` writes the inputs to a work directory
and runs Bitcoin Core's `test_bitcoin --run_test=tapleaf_0xc2_vector_tests` with `BIP441_VECTORS_FILL=<dir>`, which
fills them in. `build.py` then checks the results against the expectations in the cases and prints a `PROBLEM` line
for each mismatch (exit code 1).

## Needs

- Python 3.
- A Bitcoin Core checkout of the gsr branch with `build/bin/test_bitcoin` built. Its `src/script` gives the opcode
  names and its `test/functional/test_framework` the transactions, keys and signature hashes.
- The bips repository, for the BIP 340 and BIP 341 vectors that `extended_primitives.json` reuses.

## Use

```sh
contrib/bip441-vectors/build.py --core ~/bitcoin --bips ~/bips                   # writes ~/bips/bip-0441/*.json
contrib/bip441-vectors/build.py --core ~/bitcoin --bips ~/bips --copy-to-core    # and ~/bitcoin/src/test/data/*.json
contrib/bip441-vectors/build.py --core ~/bitcoin --bips ~/bips --out /tmp/v      # elsewhere
```

`--core` and `--bips` can also be given as `BIP441_CORE` and `BIP441_BIPS`; `--work <dir>` keeps the runner's input
and output files. It writes nothing into the Core checkout unless `--copy-to-core` is given (not even Python bytecode).
A run takes a few minutes.

Private fields, those with a leading underscore, are dropped from the published files. `_budget_after_prefix` and
`_budget_rel` set a vector's budget relative to a cost (the helper vectors that measure it run first), so budgets
follow price refits; `_expect`, `_old`, `_expect_top` and `_check_script_pubkey` are checks.

## Keeping the copies in sync

This generator is the source of the vector files in both the bips repository and Bitcoin Core. Whoever edits one of
those JSON files by hand must port the edit into `cases_*.py`, and the generator must reproduce both repositories'
files byte for byte:

```sh
contrib/bip441-vectors/build.py --core ~/bitcoin --bips ~/bips --out /tmp/v
for f in /tmp/v/*.json; do cmp "$f" ~/bips/bip-0441/"${f##*/}"; done
for f in varops tapleaf_0xc2 op_tx extended_primitives reusable_macros; do
    cmp /tmp/v/$f.json ~/bitcoin/src/test/data/$f.json
done
```
