#!/usr/bin/env python3
"""Write the bip-0441 test vectors.

Case inputs come from cases_*.py; results are computed by the reference
implementation (a Bitcoin Core gsr checkout's test_bitcoin with
BIP441_VECTORS_FILL). Writes <out>/<name>.json, by default
<bips>/bip-0441/<name>.json, and with --copy-to-core copies the files Core
carries to <core>/src/test/data.
"""
import argparse
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True

NAMES = ['varops', 'tapleaf_0xc2', 'op_tx', 'extended_primitives', 'reusable_macros', 'extended_primitives_examples']
GROUPS = ['primitives', 'scripts', 'transactions', 'signing', 'decoding', 'unrolling']
KEY_ORDER = [
    'comment', 'primitive', 'n', 'm', 'k', 'internal_key', 'leaves', 'spend_leaf', 'context', 'tx',
    'spent_outputs', 'hash_type', 'codesep_pos', 'stack', 'script', 'budget', 'final',
    # results
    'final_stack', 'varops', 'error', 'result', 'declarations', 'unrolled_length', 'substituted_instructions',
    'references_visited', 'unrolling_charge', 'unrolled_sha256', 'unrolled', 'script_pubkey',
    'leaf_hash', 'control_block', 'sighash',
]
# Files that Core does not carry, filled through another file's test case.
FILL_AS = {'extended_primitives_examples': 'extended_primitives'}


def vectors(data):
    for group in GROUPS:
        for cat in data.get(group, []):
            for v in cat['vectors']:
                yield group, cat, v


def public(data):
    """The data without private fields (leading underscore)."""
    out = copy.deepcopy(data)
    for _, _, v in vectors(out):
        for key in [k for k in v if k.startswith('_')]:
            del v[key]
    return out


def fill(files):
    """Compute the result fields with Core's runner. A file Core does not carry
    is filled in its own directory through the test case named in FILL_AS."""
    runs = {WORK: ['tapleaf_0xc2_vector_tests', {}]}
    test_bitcoin = os.path.join(CORE, 'build/bin/test_bitcoin')
    for name in files:
        if name in FILL_AS:
            runs[os.path.join(WORK, name)] = [f'tapleaf_0xc2_vector_tests/{FILL_AS[name]}', {name: FILL_AS[name]}]
        else:
            runs[WORK][1][name] = name
    paths = {}
    for directory, (test, names) in runs.items():
        if not names:
            continue
        os.makedirs(directory, exist_ok=True)
        for name, as_name in names.items():
            with open(os.path.join(directory, as_name + '.json'), 'w') as f:
                json.dump(public(files[name]), f)
            paths[name] = os.path.join(directory, as_name + '.filled.json')
        env = dict(os.environ, BIP441_VECTORS_FILL=directory)
        r = subprocess.run([test_bitcoin, f'--run_test={test}', '--log_level=error'], env=env, capture_output=True,
                           text=True)
        if r.returncode:
            sys.exit(r.stdout[-4000:] + r.stderr[-4000:])
    filled = {}
    for name, data in files.items():
        with open(paths[name]) as f:
            result = json.load(f)
        # Carry private fields over to the filled vectors.
        merged = copy.deepcopy(result)
        for (_, _, src), (_, _, dst) in zip(vectors(data), vectors(merged)):
            assert src['comment'] == dst['comment'], (src['comment'], dst['comment'])
            for key, value in src.items():
                if key.startswith('_'):
                    dst[key] = value
        filled[name] = merged
    return filled


def resolve_budgets(files):
    """Budgets given relative to a cost: fill helper vectors first."""
    helpers = {name: {'bip': data['bip'], 'scripts': [], 'unrolling': []} for name, data in files.items()}
    pending = []
    for name, data in files.items():
        for group, cat, v in vectors(data):
            if '_budget_after_prefix' in v:
                helper = {k: v[k] for k in ('comment', 'context', 'stack') if k in v}
                helper['script'] = v['script'][:-1]
                pending.append((name, v, 'scripts', helper, lambda r, v=v: r['varops'] + v['_budget_after_prefix']))
            if '_budget_rel' in v:
                kind, delta = v['_budget_rel']
                if kind == 'varops':
                    helper = {k: v[k] for k in ('comment', 'context', 'stack', 'script') if k in v}
                    pending.append((name, v, 'scripts', helper, lambda r, d=delta: r['varops'] + d))
                else:
                    helper = {'comment': v['comment'], 'script': v['script']}
                    pending.append((name, v, 'unrolling', helper, lambda r, d=delta: r['unrolling_charge'] + d))
    if not pending:
        return
    for name, _, group, helper, _ in pending:
        groups = helpers[name][group]
        if not groups:
            groups.append({'category': 'helpers', 'vectors': []})
        groups[0]['vectors'].append(helper)
    results = fill(helpers)
    counters = {}
    for name, v, group, helper, compute in pending:
        i = counters.get((name, group), 0)
        counters[(name, group)] = i + 1
        r = results[name][group][0]['vectors'][i]
        v['budget'] = compute(r)


def ordered(v):
    keys = sorted(v, key=lambda k: KEY_ORDER.index(k) if k in KEY_ORDER else len(KEY_ORDER))
    return {k: v[k] for k in keys}


def dump(data):
    lines = ['{']
    keys = list(data)
    for i, key in enumerate(keys):
        comma = ',' if i < len(keys) - 1 else ''
        if key not in GROUPS:
            lines.append(f'  {json.dumps(key)}: {json.dumps(data[key])}{comma}')
            continue
        lines.append(f'  {json.dumps(key)}: [')
        cats = data[key]
        for ci, cat in enumerate(cats):
            lines.append('    {')
            lines.append(f'      "category": {json.dumps(cat["category"])},')
            lines.append('      "vectors": [')
            for vi, v in enumerate(cat['vectors']):
                end = ',' if vi < len(cat['vectors']) - 1 else ''
                lines.append('        ' + json.dumps(ordered(v), separators=(', ', ': ')) + end)
            lines.append('      ]')
            lines.append('    }' + (',' if ci < len(cats) - 1 else ''))
        lines.append('  ]' + comma)
    lines.append('}')
    return '\n'.join(lines) + '\n'


OLD_ERROR_NAMES = {'MINIMALIF': 'TAPSCRIPT_MINIMALIF'}


def check(files):
    problems = []
    for name, data in files.items():
        for group, cat, v in vectors(data):
            where = f'{name}/{cat["category"]}/{v["comment"]}'
            old = v.get('_old')
            if old is not None:
                if 'error' in old:
                    if v.get('error') != OLD_ERROR_NAMES.get(old['error'], old['error']):
                        problems.append(f'{where}: error {v.get("error")} != {old["error"]}')
                else:
                    # Costs follow the current prices; the result must not change.
                    if [unhex(x) for x in old['final stack']] != expand(v.get('final_stack')):
                        problems.append(f'{where}: result changed')
            expect = v.get('_expect')
            if expect is not None:
                got = v.get('result') if group == 'decoding' else 'valid' if 'error' not in v else v['error']
                if got != expect:
                    problems.append(f'{where}: {got} != expected {expect}')
            spk = v.get('_check_script_pubkey')
            if spk is not None and spk != v.get('script_pubkey'):
                problems.append(f'{where}: script_pubkey {v.get("script_pubkey")} != {spk}')
            top = v.get('_expect_top')
            if top is not None and (v.get('final_stack') or [None])[-1] != top:
                problems.append(f'{where}: top {v.get("final_stack")} != {top}')
            if v.get('error') == 'UNKNOWN_ERROR':
                problems.append(f'{where}: UNKNOWN_ERROR')
    return problems


def expand(stack):
    if stack is None:
        return None
    out = []
    for item in stack:
        if isinstance(item, dict):
            out += [unhex(item['element'])] * item['count']
        else:
            out.append(unhex(item))
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--core', default=os.environ.get('BIP441_CORE'), required='BIP441_CORE' not in os.environ,
                        help='Bitcoin Core gsr checkout with build/bin/test_bitcoin built (env BIP441_CORE)')
    parser.add_argument('--bips', default=os.environ.get('BIP441_BIPS'), required='BIP441_BIPS' not in os.environ,
                        help='bips repository, for the BIP 340 and 341 vectors (env BIP441_BIPS)')
    parser.add_argument('--out', help='where to write the vector files (default: <bips>/bip-0441)')
    parser.add_argument('--copy-to-core', action='store_true',
                        help='also copy the files Core carries to <core>/src/test/data')
    parser.add_argument('--work', help='keep the runner\'s input and output files here (default: a temporary directory)')
    args = parser.parse_args()

    # common and the cases read these when imported
    global CORE, WORK, unhex
    CORE = os.environ['BIP441_CORE'] = os.path.abspath(args.core)
    os.environ['BIP441_BIPS'] = os.path.abspath(args.bips)
    out = args.out or os.path.join(args.bips, 'bip-0441')
    import cases_examples
    import cases_extprim
    import cases_macros
    import cases_optx
    import cases_tapleaf
    import cases_varops
    from common import unhex

    with tempfile.TemporaryDirectory(prefix='bip441-') as tmp:
        WORK = os.path.abspath(args.work) if args.work else tmp
        tapleaf, moved = cases_tapleaf.build()
        files = {
            'varops': cases_varops.build(),
            'tapleaf_0xc2': tapleaf,
            'op_tx': cases_optx.build(),
            'extended_primitives': cases_extprim.build(),
            'reusable_macros': cases_macros.build(moved),
            'extended_primitives_examples': cases_examples.build(),
        }
        resolve_budgets(files)
        filled = fill(files)
    problems = check(filled)
    for p in problems:
        print('PROBLEM', p)
    os.makedirs(out, exist_ok=True)
    for name in NAMES:
        text = dump(public(filled[name]))
        json.loads(text)
        with open(os.path.join(out, name + '.json'), 'w') as f:
            f.write(text)
        if args.copy_to_core and name not in FILL_AS:
            shutil.copy(os.path.join(out, name + '.json'), os.path.join(CORE, 'src/test/data', name + '.json'))
        count = sum(1 for _ in vectors(filled[name]))
        print(f'{name}: {count} vectors, {len(text):,} bytes')
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
