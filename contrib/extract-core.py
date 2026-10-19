#!/usr/bin/env python3
"""Extract the fixtures of tests/core.rs from Bitcoin Core's Tapleaf 0xC2 sources.

    contrib/extract-core.py BITCOIN_REPO [COMMIT]

Reads src/script/{script.h,script.cpp,interpreter.cpp} and src/test/data/reusable_macros.json at COMMIT (default
ad6c16f, jmoik/bitcoin `gsr`) with `git show`, and writes tests/data/core/opcodes.tsv (each byte's name, OP_SUCCESSx
status, handling and stack effect in the 0xC2 interpreter, origin) and tests/data/core/macro-vectors.tsv (the
decoding and unrolling vectors). After a consensus change: re-extract, run `cargo test`, update src/opcodes.rs.
"""

import json
import re
import subprocess
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "tests" / "data" / "core"


def show(repo, commit, path):
    return subprocess.run(["git", "-C", repo, "show", f"{commit}:{path}"], check=True, capture_output=True,
                          text=True).stdout


def function(src, signature):
    """The text of the function whose definition starts with signature, up to its closing brace at column 0."""
    start = src.index(signature)
    return src[start:src.index("\n}\n", start) + 2]


def names_and_origins(script_h):
    enum = script_h[script_h.index("enum opcodetype"):]
    enum = enum[:enum.index("};")]
    names, origins, origin = {}, {}, "base"
    for line in enum.splitlines():
        line = line.strip()
        if not line:
            origin = "base"  # a section comment covers the opcodes up to the next blank line
        if line.startswith("//"):
            for key, origin_name in (("BIP 342", "tapscript"), ("Extended Primitives", "extended-primitives"),
                                     ("OP_TX", "op-tx"), ("reusable macros", "reusable-macros")):
                if key in line:
                    origin = origin_name
        m = re.match(r"(OP_\w+)\s*=\s*(0x[0-9a-fA-F]+)", line)
        if m:
            byte = int(m.group(2), 16)
            names[byte], origins[byte] = m.group(1), origin
    return names, origins


def op_success(script_cpp, names):
    value = {name: byte for byte, name in names.items()}
    base = function(script_cpp, "bool IsOpSuccess(")
    expr = re.search(r"return (.*?);", base, re.S).group(1)
    expr = " ".join(expr.replace("&&", " and ").replace("||", " or ").split())
    tapleaf = function(script_cpp, "bool IsTapleaf0xC2OpSuccess(")
    fixed, labels, reenabled, section = {}, [], set(), None
    for line in tapleaf.splitlines():
        line = line.strip()
        if line.startswith("//"):
            section = line
        for name in re.findall(r"case (OP_\w+)\s*:", line):
            labels.append(value[name])
            if section and "re-enabled by BIP 441" in section:
                reenabled.add(value[name])
        if line.startswith("return true;") or line.startswith("return false;"):
            for byte in labels:
                fixed[byte] = line.startswith("return true;")
            labels = []
    return {b: fixed[b] if b in fixed else eval(expr, {"opcode": b}) for b in range(256)}, reenabled


def stack_effect(comment, name):
    """(pop, push) from a comment like `(x1 x2 -- out)`, or None when the effect varies."""
    # each alternative is the text inside its outer parentheses, if any: `(x1 x2 - ) for OP_EQUALVERIFY`
    alternatives = [a[a.index("(") + 1:a.rindex(")")] if "(" in a else a for a in comment.split(", or")]
    alt = alternatives[-1] if name.endswith("VERIFY") else alternatives[0]
    sep = " -- " if " -- " in f" {alt} " else " - "
    left, _, right = f" {alt} ".partition(sep)
    right = right.replace(" || ", "||")
    if "..." in alt or "|" in right.replace("||", ""):
        return None
    return len(left.split()), len(right.split())


def interpreter(interpreter_cpp, names):
    value = {name: byte for byte, name in names.items()}
    body = interpreter_cpp[interpreter_cpp.index("static bool EvalTapleaf0xC2Impl("):]
    body = body[:body.index("bool EvalTapleaf0xC2(")]
    handled, fails, effects = set(), set(), {}
    group, lines_after = [], []

    def close():
        if not group:
            return
        statements = [line for line in lines_after if line and not line.startswith("//") and line != "{"]
        comments = [line[2:].strip() for line in lines_after if line.startswith("//")]
        comment = next((c for c in comments if c.startswith("(") or c.startswith("--")), None)
        for byte in group:
            if byte in handled:
                continue  # a nested switch over the same opcodes
            handled.add(byte)
            if statements and statements[0].startswith("return set_error"):
                fails.add(byte)
            if comment:
                effects[byte] = stack_effect(comment, names[byte])

    for raw in body.splitlines():
        line = raw.strip()
        labels = re.findall(r"case (OP_\w+)\s*:", line)
        if labels or line.startswith("default:"):
            if lines_after:
                close()
                group, lines_after = [], []
            group += [value[n] for n in labels]
        elif group:
            lines_after.append(line)
    close()
    return handled, fails, effects


def notation(tokens):
    return " ".join(tokens)


def main():
    if len(sys.argv) not in (2, 3):
        sys.exit(__doc__)
    repo, commit = sys.argv[1], sys.argv[2] if len(sys.argv) == 3 else "ad6c16f"
    full = subprocess.run(["git", "-C", repo, "rev-parse", "--short=10", commit], check=True, capture_output=True,
                          text=True).stdout.strip()
    names, origins = names_and_origins(show(repo, commit, "src/script/script.h"))
    success, reenabled = op_success(show(repo, commit, "src/script/script.cpp"), names)
    handled, fails, effects = interpreter(show(repo, commit, "src/script/interpreter.cpp"), names)
    OUT.mkdir(parents=True, exist_ok=True)

    rows = [f"# Extracted from jmoik/bitcoin @ {full} by contrib/extract-core.py",
            "# byte\tname\top_success\thandled\tfails\tpop\tpush\torigin"]
    for b in range(256):
        name = names.get(b, "-")
        is_handled = b <= 0x4E or b in handled  # pushes are decoded before the opcode switch
        pop, push = effects.get(b) or ("-", "-")
        origin = "bip441" if b in reenabled else origins.get(b, "-")
        rows.append(f"{b:02x}\t{name}\t{int(success[b])}\t{int(is_handled)}\t{int(b in fails)}\t{pop}\t{push}\t{origin}")
    (OUT / "opcodes.tsv").write_text("\n".join(rows) + "\n")

    vectors = json.loads(show(repo, commit, "src/test/data/reusable_macros.json"))
    rows = [f"# Extracted from jmoik/bitcoin @ {full} src/test/data/reusable_macros.json by contrib/extract-core.py",
            "# decoding\tresult\tdeclarations\tscript\tcomment",
            "# unrolling\tdeclarations\tunrolled_length\tsubstituted\treferences\twithin_limit\tunrolling_charge"
            "\tunrolled\tscript\tcomment",
            "# Scripts are tokens: OP_ names, and 0x hex whose last byte {n} repeats n times."]
    for category in vectors["decoding"]:
        for v in category["vectors"]:
            rows.append("\t".join(["decoding", v["result"], str(v.get("declarations", "-")), notation(v["script"]),
                                   v["comment"]]))
    for category in vectors["unrolling"]:
        for v in category["vectors"]:
            unrolled = notation(v["unrolled"]) if "unrolled" in v else "-"
            rows.append("\t".join(["unrolling", str(v["declarations"]), str(v["unrolled_length"]),
                                   str(v["substituted_instructions"]), str(v["references_visited"]),
                                   str(int(v["within_limit"])), str(v.get("unrolling_charge", "-")),
                                   unrolled or "(empty)", notation(v["script"]), v["comment"]]))
    (OUT / "macro-vectors.tsv").write_text("\n".join(rows) + "\n")


if __name__ == "__main__":
    main()
