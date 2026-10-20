# Macro optimization for Tapleaf 0xC2 scripts

Reusable macros (`OP_MACRO` 0xd0 declarations, `OP_CALLMACRO` 0xd1 references) let a committed script be shorter
than the script it runs. This note states the choice of macros as an exact optimization problem, under the
consensus rules of jmoik/bitcoin `gsr` @ `ad6c16f` (`src/script/reusable_macros.cpp`, `src/script/varops.h`,
`src/script/interpreter.cpp`), and describes the optimizer of this crate (`gsr compress`), which solves it
heuristically with bounds, and `gsr anchor`, which rewrites deep stack reads so they compress. [Results](#results)
are for the verifier scripts of [gsr-stark-verifier](https://github.com/jmoik/gsr-stark-verifier), where the
optimizer was first written in Python with a C++ core (`macro_opt.py`). This crate reproduces that
implementation's output byte for byte (`tests/reference.rs`). The verifier now calls `gsr compress` and
`gsr check` at a pinned revision of this crate; its greedy `compress.py` and `check_compression.py` were removed,
so the greedy columns and the comparison below are as measured before.

## Model

**Instructions.** An instruction is an opcode with its push data, as a byte string `a` of length `|a|`. The
*target* is the instruction sequence `U = u_1 … u_n` the generator emits, fully unrolled (RISC Zero fixed
statement: `n = 742,362`, `|U| = 3,361,215` B).

**Decision.** A committed script

```
C = D_0 D_1 … D_{m-1} M,    D_i = OP_MACRO ‖ CS(|B_i|) ‖ B_i
```

where every body `B_i` and the main script `M` are sequences of instructions and references
`call_j = OP_CALLMACRO ‖ CS(j)`. `CS` is Bitcoin's CompactSize: `|CS(x)| = 1` for `x < 253`, `3` for `x < 2^16`,
`5` for `x < 2^32`. This is a straight-line grammar with rules `B_0, …, B_{m-1}` and start symbol `M`.

**Constraints** (consensus, `Decode` and `Unroll`):

1. *Well formed.* Declarations come first and each body decodes into whole instructions; `B_i` contains no
   `OP_MACRO` and references only `j < i`; `M` contains no `OP_MACRO` and references only `j < m`; CompactSize is
   canonical; no instruction of `C`, inside or outside bodies, is an `OP_SUCCESSx`.
2. *Same script.* `unroll(C) = U` byte for byte, where `unroll` replaces every `call_j` by `unroll(B_j)`.
3. *Size.* `|U| ≤ 4,000,000` (fixed by the target).
4. *Budget.* `E + K(C) ≤ 10,000 · W(C) − 500,000 · c`, where `E` is the execution varops of `U` with the given
   witness (independent of `C`), `K` the unrolling charge below, `W` the transaction weight without the inputs
   that do not draw on the budget, and `c` the number of Tapleaf 0xC2 inputs (each pays one signature check for its
   commitment check). Execution charges of all inputs share the budget.
5. *Policy.* `W(C) ≤ 400,000` for standardness.

**Size.**

```
|C| = Σ_i (1 + |CS(|B_i|)| + |B_i|) + |M|,
|S| = Σ_{a ∈ S} |a| + Σ_{call_j ∈ S} (1 + |CS(j)|)       for a body or the main script S
```

So a reference costs 2 bytes to one of the first 253 declarations ("hot") and 4 bytes to a later one ("cold"), and
a declaration costs its body plus 2 bytes of header (4 from a 253-byte body on).

**Unrolling charge.**

```
K(C) = 300 · (S + R) + [m > 0] · (800 + 7 · ⌈|U| / 8⌉ · 8)
S = Σ_{call_j ∈ M} ins(j),        R = Σ_{call_j ∈ M} (1 + ref(j)),        ref(j) = Σ_{call_k ∈ B_j} (1 + ref(k))
```

where `ins(j)` is the number of instructions in `unroll(B_j)`. In the derivation tree of `U`, `S` counts the
leaves that are not children of the root (instructions not written literally in `M`) and `R` counts the internal
nodes below the root (reference visits). Instructions written in `M` are not charged: they are funded by weight.
Hence replacing main-script instructions by a reference adds 300 varops per instruction plus 300 for the
reference, while extracting a macro inside an existing body adds only 300 per expansion of that body.

**Objective.** With `W(C) = W_0 + |C| + |CS(|C|)|` (the script is one witness item; `W_0` is everything else),
the weight that must be paid is

```
W*(C) = max( W(C), ⌈(E + K(C) + 500,000 · c) / 10,000⌉ )
```

since an over-budget spend must be padded until its weight funds it. The problem is `min_C W*(C)` subject to
constraints 1–3 and 5.

**When the budget binds.** Let `σ = (E + K)/B` be the budget share of a spend with budget `B`. A change that
saves `ΔW` weight units and adds `ΔK` varops stays funded iff `10,000 · ΔW + ΔK ≤ (1 − σ) · B`: every byte saved
removes 10,000 varops of budget, every substituted instruction adds 300. While this holds at the size optimum,
`min W*` is simply `min |C|`: the smallest grammar under the encoding rules. For the optimized RISC Zero covenant
spend (`σ = 0.603`, `B = 3.07·10^9`) the slack `(1 − σ) · B = 1.22·10^9` varops would absorb `ΔW ≈ 122,000` WU,
five times the 24,133 WU gained here, and its budget floor `⌈(E + K + 500,000)/10,000⌉ = 185,172` WU is far below
its 306,964 WU weight. A spend near its budget is different: SHRINCS at `σ = 0.796` has slack
`0.204 · B`, so compression that removes more than about a fifth of its weight (less the added charge) would
need padding, and past that point the objective trades bytes against charge at 10,000 varops per byte.

**Same behaviour.** The reusable-macros BIP guarantees that a well-formed `C` and its `unroll(C)` give the same
result, final stack and opcode positions for any initial stack and transaction context, except for
(1) anything that depends on the script bytes or their length (the Tapleaf hash, signature messages, OP_TX
fields such as `CURRENT_TAPSCRIPT` and `TX_WEIGHT`), (2) the weight-funded budget and (3) the unrolling charge. So `C` can replace `U` iff
constraints 1–2 hold, `U` reads nothing of kind (1) (or reads it in a way the generator compensates), and
constraint 4 holds. `gsr compress` asserts constraint 2 and the protected prefix, `gsr check` checks constraints 1
and 3, and constraint 4 needs the spend's varops (`gsr-meter`). The rollup leaf is the compensated case: it reads its
own script with OP_TX to splice in the next root, so (a) the root push must stay literal at offset 0 of `M` (the
script offset is then the declarations' length `d`), and (b) the prologue that embeds `d` must stay out of the
declarations, so the declarations do not depend on `d` and the generator's fixed point `d → C(d) → d` converges.
Both hold if a protected prefix `[0, h)` of `M` is never part of a macro.

**Complexity and decomposition.** With unit costs the problem contains the smallest-grammar problem, which is
NP-hard (Charikar et al. 2005; Storer and Szymanski 1982 for macro schemes). It splits into three parts, two of
which are solved exactly here:

- *Dictionary:* which words (rule expansions) exist. NP-hard; searched heuristically.
- *Parse:* given the words and their reference costs, the cheapest parse of every body and of `M` is a shortest
  path over instruction positions (each word occurrence ending at `j` is an edge of its reference cost, each
  instruction an edge of its length); bodies may use only shorter words, which keeps the grammar acyclic. Exact
  for fixed reference costs; the costs depend on the index order, which depends on the parse, so the two are
  iterated.
- *Index order:* given the grammar, choose the hot set: a dependency-closed set `H` (a body may only reference
  earlier declarations) with `|H| ≤ 253` maximizing `Σ_{r ∈ H} uses(r)`, each hot reference saving 2 bytes.
  This is a cardinality-constrained maximum-weight closure. Its Lagrangian relaxation
  `max_H closed Σ_{r ∈ H} (uses(r) − λ)` is a minimum cut, exact whenever some `λ` gives `|H| = 253`.

**Lower bounds.** (a) Each distinct instruction of `U` appears literally at least once: `|C| ≥ Σ_{distinct a} |a|`.
(b) Any grammar maps to an LZ77 parse of `U` (expand the first occurrence of each rule, copy the later ones) whose
symbols cost what the grammar's do (Rytter 2003), so `|C|` is at least the cheapest parse with literals at their
length and copies of any earlier substring at 2 bytes. Both ignore headers and the 253-index limit, so they are
loose.

## Optimizer

The optimizer tokenizes the script (instruction byte strings; protected instructions become unique symbols),
runs the search (`src/irr.rs`, `src/parse.rs`, `src/order.rs`), encodes the grammar and asserts that it unrolls
to the input and keeps the protected prefix.

- **irr** (iterative repeat replacement, most compressive): over the main script and all bodies, a suffix array
  enumerates every repeat of any length; the one with the largest exact saving
  `k · (|w| − c) − (|w| + 1 + |CS(|w|)|)` (non-overlapping occurrences `k`) becomes a rule. The reference cost
  `c` is 2 if the rule would rank among the 253 most used (charging the displaced rule's references 2 bytes each),
  else 4. Repeats that save less than `min` bytes are skipped.
- **mgp** (minimal grammar parsing): re-parses every body and `M` exactly (Aho–Corasick over the rule
  expansions, then the shortest-path parse), recomputes the index order, and removes up to a fifth of the rules
  that do not pay for themselves (`uses · (|B| − c) ≤ |B| + header`) per round, until the size stops falling.
- **loop** alternates irr and mgp; **ls** (local search) drops single rules when the exact re-parse without them
  is smaller.
- **Index order:** the Lagrangian closure (binary search on `λ`, Dinic minimum cut), filled greedily by uses, or
  the plain greedy fill if better; then a topological order with the hot set first.

Six configurations (start from the generator's macros or from the fully unrolled script, `min` ∈ {0, 1, 2}) run
in parallel; the smallest result is kept. The run is deterministic, and the result does not depend on the values
of protected instructions, which the rollup's fixed point needs. About 15 s for the RISC Zero verifier.

## Results

The compressed RISC Zero covenant spend falls from 331,097 WU (greedy `compress.py`) to **306,964 WU** (−24,133 WU,
−7.3%): 9,796 WU from the optimizer and 14,337 WU from addressing deep stack reads from the stack bottom
([below](#bottom-anchored-addressing)), which makes them repeat and compress.

The optimizers compared on the same input, the scripts as generated before (relative addressing). Committed script
bytes (`macro_benchmark.py`; every macro encoding unrolls to the same script, checked). Deflate
and xz are not executable and are listed for scale: they entropy-code bytes, which a grammar of whole instructions
cannot. Deflate (raw zlib -9) is the best of the plain, inline and optimized scripts, xz (-9e) the better of the
plain and inline ones. Re-Pair does not support the rollup's protected prefix.

| Script | plain | greedy `compress.py` | Re-Pair + pruning | **`macro_opt`** | vs greedy | deflate | xz | LZ bound |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| RISC Zero, fixed statement | 160,600 | 101,393 | 93,572 | **91,550** | −9.7% | 48,207 | 29,244 | 60,103 |
| RISC Zero covenant | 160,835 | 101,271 | 93,295 | **91,475** | −9.7% | 48,423 | 29,380 | 59,866 |
| Rollup settlement leaf | 161,252 | 101,688 | – | **92,023** | −9.5% | 48,681 | 29,536 | 60,247 |
| Stwo recursive verifier | 139,129 | 44,345 | 37,086 | **36,109** | −18.6% | 19,950 | 12,328 | 22,309 |
| PLONK (external) | 159,989 | 14,475 | 12,361 | **11,664** | −19.4% | 7,030 | 5,268 | 7,141 |

Spends, measured by `gsr-meter` from the serialized transaction (the covenant spend was also accepted under
standard policy and mined on regtest; the rollup settlement is estimated from the measured gsr-full one):

| Spend | plain | greedy | Re-Pair | **`macro_opt`** | vs greedy | varops, greedy → opt | budget share |
|---|---:|---:|---:|---:|---:|---:|---:|
| RISC Zero fixed, 1-in/1-out | 390,426 WU | 331,219 | 323,398 | **321,376** | −9,843 (−3.0%) | 1.793B → 1.829B | 54.1% → 56.9% |
| RISC Zero covenant | 390,661 WU | 331,097 | 323,121 | **321,301** | −9,796 (−3.0%) | 1.794B → 1.827B | 54.2% → 56.9% |
| Rollup settlement, 1 join-split (est.) | ≈ 393,988 WU | ≈ 334,424 | – | **≈ 324,759** | −9,665 (−2.9%) | not measured | – |
| Stwo | 364,611 WU | 269,825 | 262,566 | **261,589** | −8,236 (−3.1%) | 1.327B → 1.369B | 49.2% → 52.4% |

The varops rise is exactly the unrolling charge (execution of the unrolled RISC Zero script is 1.543B). Greedy
and `macro_opt` substitute about as many instructions (715,019 and 716,647), but the deeper nesting visits four
times as many references (156,744 vs 37,922), 36M varops more. The budget does not bind for any of these spends
(the covenant's floor is 182,799 WU).

### How close to optimal

The LZ bound ignores declarations and the 253-index limit, so it does not certify the
result. The evidence that little is left for search: the six configurations end within 0.3% of each other,
Re-Pair with the same pruning ends 2.2% above, local search gains 0.05%, the index order is within 136 B of the
bound without the dependency constraint, and 58% of the RISC Zero result (53 KB) is main-script instructions left
literal, mostly depth operands that occur in no repeat worth a declaration.

## Bottom-anchored addressing

A deep read `<d> PICK` names its value by its depth `d`, which changes whenever the stack above it grows or
shrinks, so reads of the same value rarely repeat. Its index from the bottom, `H − d − 1` at stack height `H`, stays
the same while the value stays put. `gsr anchor` rewrites each read `<d> PICK|ROLL` of the main script with
`d` at least a threshold (`--min-depth`) as `DEPTH <H − d> SUB PICK|ROLL`, with `H − d` pushed minimally (a direct
push for 0x81, as `OP_1NEGATE` is an OP_SUCCESSx). The script grows, and compresses much better; with the
threshold 320 the generator used:

| Script | plain | anchored | compressed | anchored, compressed |
|---|---:|---:|---:|---:|
| RISC Zero, fixed statement | 160,600 | 177,544 | 91,550 | **77,321** |
| RISC Zero covenant | 160,835 | 177,793 | 91,475 | **77,138** |
| Rollup settlement leaf (`--protect 2702`) | 161,252 | 178,210 | 92,023 | **77,684** |

`H` is the height at run time, so the rewrite needs it fixed in advance. `gsr check`'s stack analysis follows the
depth relative to the witness on every path; `gsr anchor` rewrites a script only if every path that runs to the end
ends at the same depth `δ` (so `1 − δ` witness items is the only count that can leave one item; the item-count
requirements of the paths are ignored, since a rewritten read may succeed where the original failed), the analysis
did not stop, there is no `OP_CODESEPARATOR` (it would move the positions signatures commit to), and the script
checks without errors. It rewrites a read only where all paths reaching it agree on its height and the two extra
items fit under the 32,768-item limit, and leaves the protected prefix (`--protect`) alone. With `1 − δ` witness
items both scripts read the same values; with any other count both end with the wrong number of items. The
rewritten script is checked again for the same witness count. The proof covers the stack depths only, so the
caller must account for the rest: two instructions more per rewritten read (more execution varops: re-check the
budget), up to 4 bytes more on the stack at a rewritten read (a spend within 4 bytes of the 8,000,000-byte total
stack size can fail), anything that depends on the script's bytes or length (signatures, the Tapleaf hash, the
taptree root and output key, `OP_TX`'s tapscript, witness items and transaction weight), and the point at which a
failing witness fails.

On the three verifier scripts `gsr anchor` rewrites every read the generator anchored (8,472–8,479) and gives its
anchored scripts byte for byte.

**Threshold.** A read less than 256 deep pushes its depth in one byte, so anchoring it costs 3 bytes more and
rarely pays; a deeper one pays when its value is read often enough from other heights. The best threshold depends
on the script, and the compressed size is not smooth in it. On the RISC Zero verifier at gsr-stark-verifier
`3000b00` (148,486 bytes plain; 60,966 compressed without anchoring):

| threshold | 192 | 224 | **256** | 288 | 320 | 384 | 512 |
|---|---:|---:|---:|---:|---:|---:|---:|
| compressed | 50,086 | 49,397 | **48,776** | 49,102 | 49,101 | 49,307 | 49,054 |

Choosing per value instead (anchoring only the reads of slots read often) did not do better than the best threshold
(within 13 bytes). So by default (`--min-depth auto`) `gsr anchor` compresses the script anchored with each of these
thresholds, and not anchored, and keeps the smallest; on a tie, the fewest rewrites. That takes about six
times as long as one compression (two minutes for this script on 14 cores); the result is deterministic.

## Reproduce

The comparison of optimizers used gsr-stark-verifier's `macro_benchmark.py`.

```sh
gsr anchor script.hex -o anchored.hex # the best threshold; --min-depth N for a given one
gsr compress anchored.hex -o out.hex
gsr check out.hex                     # witness item count, errors
gsr info --bounds out.hex             # unrolling charge, distinct-instruction and LZ lower bounds
gsr near-duplicates anchored.hex      # what would compress if a pushed depth or offset agreed
```
