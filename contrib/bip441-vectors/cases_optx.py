"""OP_TX vectors."""
import hashlib
import json
import os

from common import (
    CScript, CTxOut, LEAF_VERSION_0XC2, category, context, default_context, hexruns, ops, push,
    raw, repeated, script_bytes, spending_tx, stack, vector, leaf_sighash,
)
from test_framework.script import TaggedHash
from test_framework.messages import COutPoint, ser_string

# gsr's former vector files (b778e1fa66), the source of the converted vectors.
SOURCES = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sources')


def decode(value):
    if isinstance(value, dict):
        return bytes.fromhex(value['repeat']) * value['count']
    return bytes.fromhex(value)


def decode_stack(values):
    out = []
    for value in values or []:
        if isinstance(value, dict) and 'items' in value:
            out.append(repeated(decode(value['element']), value['items']))
        else:
            out.append(hexruns(decode(value)))
    return out


# Former vectors whose context a spend cannot have: a tapscript above the
# element size limit, or no code separator position.
UNREALIZABLE = {'element_size_limit_exceeded', 'unavailable_codesep_position'}
# Instructions before OP_CODESEPARATOR, where OP_NOPs would not show the
# difference between opcode positions and byte offsets.
CODESEP_PREFIX = {'codesep_opcode_position_default': [push(b'\xaa' * 32), 'OP_DROP']}

# Former vectors that others cover: TX_VERSION and TX_LOCKTIME are in the
# every-field vectors and their unsigned and zero cases; a version-1 selector
# in 'A future selector version succeeds immediately'; a scope operand wider
# than four bytes in 'A scope operand of 2^32 or more is invalid'; and a budget
# one varop short of a vector's varops fails like any other (one such pair is
# kept).
COVERED = {'version_default', 'locktime_default', 'future_version_01', 'amount_totals_budget_exhausted',
           'empty_witness_items_budget_exhausted', 'zero_length_witness_item_budget_exhausted',
           'single_oversized_operand'}

# Former vectors whose expectation changed: scope operands are BIP 441
# arbitrary-length unsigned integers.
RENAMED = {'single_nonminimal_operand': 'A scope operand with a trailing zero byte is accepted.'}

# Former vectors whose scope RANGE_OR_EMPTY defined: the next scope value is
# the undefined one.
RESELECTED = {'unknown_scope': ('Scope value 6 is invalid.', '000000600400')}

# Former exact-budget vectors kept for their selection, without the budget.
WITHOUT_BUDGET = {
    'templatehash_like_collated_annex_exact_budget': 'The TemplateHash-like collated selection with an annex.',
    'amount_totals_exact_budget': 'Input and output total amounts in the default output format.',
    'zero_length_witness_item_exact_budget': None,
}


def converted():
    """The former OP_TX vectors: OP_TX runs as the last opcode of the
    script, on a stack holding its operands and selector. Altstack values are
    moved there by OP_TOALTSTACK; of a repeated altstack value, one copy is
    moved and the others sit at the bottom of the stack, which counts the
    same toward the stack limits. OP_CODESEPARATOR sits at the position the
    vector names. A tapscript of the former vector's length ends with a push
    and OP_DROP before OP_TX. Vectors without a tapscript, control block or
    spent outputs cannot occur in a spend and are dropped."""
    text = open(os.path.join(SOURCES, 'op_tx.json')).read()
    vs = []
    seen = set()
    for t in json.loads(text):
        ctx = t['context']
        if ctx.get('tapscript') is None or ctx.get('control_block') is None or not t['spent_outputs']:
            continue
        if t['id'] in UNREALIZABLE or t['id'] in COVERED:
            continue
        if t['id'] in RESELECTED:
            comment, selector = RESELECTED[t['id']]
            t = {**t, 'comment': comment, 'selector': selector}
        bottom, altstack = [], []
        for value in t.get('initial_altstack') or []:
            if isinstance(value, dict) and 'items' in value:
                bottom += [repeated(decode(value['element']), value['items'] - 1)] if value['items'] > 1 else []
                altstack.append(hexruns(decode(value['element'])))
            else:
                altstack.append(hexruns(decode(value)))
        items = bottom + decode_stack(t.get('initial_stack')) + decode_stack(t.get('scope_operands'))
        if t['selector'] is not None:
            items.append(hexruns(decode(t['selector'])))
        items += list(reversed(altstack))
        moves = len(altstack)
        script = []
        codesep = ctx.get('codesep_pos')
        if t['id'] in CODESEP_PREFIX:
            # The former tapscript's own prefix, which its comment describes.
            assert moves == 0 and len(CODESEP_PREFIX[t['id']]) == codesep
            script += CODESEP_PREFIX[t['id']] + ['OP_CODESEPARATOR']
        elif codesep is not None and codesep != 0xffffffff:
            before = min(moves, codesep)
            script += ['OP_TOALTSTACK'] * before + ['OP_NOP'] * (codesep - before) + ['OP_CODESEPARATOR']
            moves -= before
        script += ['OP_TOALTSTACK'] * moves
        length = len(decode(ctx['tapscript']))
        if length > 10_000:
            # 0x4e, a four-byte length, the push, OP_DROP and OP_TX.
            size = length - len(script) - 7
            script += [raw(b'\x4e' + size.to_bytes(4, 'little') + decode(ctx['tapscript'])[:1] * size), 'OP_DROP']
        script += ['OP_TX']
        annex = decode(ctx['annex']) if ctx.get('annex') is not None else None
        c = {'tx': hexruns(decode(t['spending_tx'])), 'spent_outputs': [hexruns(decode(o)) for o in t['spent_outputs']],
             'input_index': t['input_index']}
        if annex is not None:
            c['annex'] = annex.hex()
        c['control_block'] = decode(ctx['control_block']).hex()
        comment = RENAMED.get(t['id']) or WITHOUT_BUDGET.get(t['id']) or t['comment']
        comment = comment if comment not in seen else f"{comment} ({t['id']})"
        seen.add(comment)
        v = vector(comment, script, items, context=c)
        if 'available_varops' in t and t['id'] not in WITHOUT_BUDGET:
            # The former budget was the vector's exact cost, or one varop
            # short of it; it follows the vector's cost under current prices.
            v['_budget_rel'] = ('varops', 0 if t['expected']['success'] else -1)
        vs.append(v)
        if t['id'] == 'range_overflow_safe_failure':
            vs += range_or_empty(c)
    return vs


def range_or_empty(ctx):
    """RANGE_OR_EMPTY on the former vectors' transaction of two inputs and two
    outputs, after its RANGE vectors."""
    def case(comment, operands, selector, expect):
        items = [hexruns(x) for x in operands + [bytes.fromhex(selector)]]
        return vector(comment, ['OP_CODESEPARATOR', 'OP_TX'], items, context=dict(ctx), _expect=expect)
    amounts = '000000500400'
    return [
        case('RANGE_OR_EMPTY(0,5) pushes both input amounts, then an empty element for each of the three missing '
             'inputs.', [b'', b'\x05'], amounts, 'valid'),
        case('A RANGE_OR_EMPTY start past the last input selects only missing inputs.', [b'\x05', b'\x02'], amounts,
             'valid'),
        case('A missing output pushes an empty element for each selected field.', [b'\x01', b'\x02'], '000000050003',
             'valid'),
        case("RANGE_OR_EMPTY selects INPUT_WITNESS_ITEM_COUNT; a missing input's count is an empty element.",
             [b'\x01', b'\x02'], '000000504000', 'valid'),
        case('With COLLATE, a missing input contributes no bytes; the input count shows how many inputs are present.',
             [b'\x01', b'\x03'], '001100500400', 'valid'),
        vector('RANGE_OR_EMPTY sums the amounts of up to five inputs.',
               ops('OP_0', 'OP_5', bytes.fromhex(amounts), 'OP_TX', 'OP_ADD', 'OP_ADD', 'OP_ADD', 'OP_ADD'),
               context=dict(ctx), _expect='valid'),
        case('A RANGE_OR_EMPTY count of 32768 is valid; each missing input is charged but adds no collated bytes.',
             [b'', b'\x00\x80'], '000100500400', 'valid'),
        case('A RANGE_OR_EMPTY count above 32768 is invalid, even with COLLATE.', [b'', b'\x01\x80'], '000100500400',
             'TX_SELECTOR'),
        case('RANGE_OR_EMPTY count zero is invalid.', [b'', b''], amounts, 'TX_SELECTOR'),
        case('An input scope of RANGE_OR_EMPTY cannot select INPUT_WITNESS_ITEMS.', [b'', b'\x01'], '000000508000',
             'TX_SELECTOR'),
    ]


def tagged_prefix(tag):
    h = hashlib.sha256(tag.encode()).digest()
    return h + h


def sighash_constructions():
    """OP_TX selects exactly the fields BIP 341 and BIP 118 sign."""
    globals_ = bytes([0x00, 0x07, 0x00, 0x00, 0x00, 0x00])
    prevouts = bytes([0x00, 0x01, 0x00, 0x20, 0x03, 0x00])
    amounts = bytes([0x00, 0x01, 0x00, 0x20, 0x04, 0x00])
    scriptpubkeys = bytes([0x00, 0x01, 0x00, 0x20, 0x08, 0x00])
    sequences = bytes([0x00, 0x01, 0x00, 0x20, 0x20, 0x00])
    outputs = bytes([0x00, 0x01, 0x00, 0x02, 0x00, 0x03])
    input_index = bytes([0x00, 0x01, 0x01, 0x00, 0x00, 0x00])
    tapscript = bytes([0x00, 0x01, 0x04, 0x00, 0x00, 0x00])
    codesep_position = bytes([0x00, 0x01, 0x80, 0x00, 0x00, 0x00])

    def value(selector):
        return [push(selector), 'OP_TX', 'OP_CAT']

    def hashed(selector):
        return [push(selector), 'OP_TX', 'OP_SHA256', 'OP_CAT']

    leaf_prefix = tagged_prefix('TapLeaf') + bytes([LEAF_VERSION_0XC2])
    script = [push(tagged_prefix('TapSighash') + b'\x00\x00')]
    script += value(globals_) + hashed(prevouts) + hashed(amounts) + hashed(scriptpubkeys) + hashed(sequences)
    script += hashed(outputs) + [push(b'\x02'), 'OP_CAT'] + value(input_index)
    script += [push(leaf_prefix), push(tapscript), 'OP_TX', 'OP_CAT', 'OP_SHA256', 'OP_CAT']
    script += [push(b'\x00'), 'OP_CAT'] + value(codesep_position) + ['OP_SHA256', 'OP_EQUAL']

    tx = spending_tx(2, locktime=500_000, sequences=[0xfffffffd, 0xfffffffc],
                     outputs=[CTxOut(80_000, CScript(b'\x51')), CTxOut(39_000, CScript(b'\x02\xaa\xbb'))])
    spent = [CTxOut(50_000, CScript(b'\x51')), CTxOut(70_000, CScript(b'\x02\x51\x52'))]
    sighash = leaf_sighash(tx, spent, 1, script)
    vs = [vector('The BIP 341 signature message of the input', script, stack(sighash), context=context(tx, spent, 1))]

    # BIP 118 ANYPREVOUT|ALL: no outpoints; the current amount, script and sequence.
    amount_scriptpubkey = bytes([0x00, 0x01, 0x00, 0x10, 0x0c, 0x00])
    sequence = bytes([0x00, 0x01, 0x00, 0x10, 0x20, 0x00])
    apo = [push(tagged_prefix('TapSighash') + b'\x00\x41')]
    apo += value(globals_) + hashed(outputs) + [push(b'\x02'), 'OP_CAT'] + value(amount_scriptpubkey) + value(sequence)
    apo += [push(leaf_prefix), push(tapscript), 'OP_TX', 'OP_CAT', 'OP_SHA256', 'OP_CAT']
    apo += [push(b'\x01'), 'OP_CAT'] + value(codesep_position) + ['OP_SHA256', 'OP_EQUAL']
    key_spk = CScript(b'\x51\x20' + bytes([5]) * 32)
    apo_spent = [CTxOut(120_000, key_spk)]

    def apo_message(tx):
        outputs_hash = hashlib.sha256(b''.join(o.serialize() for o in tx.vout)).digest()
        leaf_hash = TaggedHash('TapLeaf', bytes([LEAF_VERSION_0XC2]) + ser_string(script_bytes(apo)))
        msg = b'\x00\x41' + tx.version.to_bytes(4, 'little') + tx.nLockTime.to_bytes(4, 'little') + outputs_hash
        msg += b'\x02' + apo_spent[0].nValue.to_bytes(8, 'little') + ser_string(bytes(apo_spent[0].scriptPubKey))
        msg += tx.vin[0].nSequence.to_bytes(4, 'little') + leaf_hash + b'\x01' + b'\xff\xff\xff\xff'
        return TaggedHash('TapSighash', msg)

    apo_tx = spending_tx(1, locktime=500_000, sequences=[0xfffffffd], outputs=[CTxOut(119_000, CScript(b'\x51'))])
    expected = apo_message(apo_tx)
    vs.append(vector('A BIP 118 ANYPREVOUT|ALL message', apo, stack(expected), context=context(apo_tx, apo_spent)))
    apo_tx.vin[0].prevout = COutPoint(0, 7)
    vs.append(vector('The ANYPREVOUT message does not commit to the outpoint', apo, stack(expected),
                     context=context(apo_tx, apo_spent)))
    apo_tx.vin[0].nSequence -= 1
    vs.append(vector('The ANYPREVOUT message commits to the sequence', apo, stack(expected),
                     context=context(apo_tx, apo_spent)))
    return vs


def selector_cases():
    output_scope_6 = bytes([0x00, 0x00, 0x00, 0x06, 0x00, 0x01])
    output_range_amounts = bytes([0x00, 0x00, 0x00, 0x04, 0x00, 0x01])
    return [
        vector('An output scope above RANGE_OR_EMPTY is invalid.', ops(output_scope_6, 'OP_TX'),
               context=default_context(), _expect='TX_SELECTOR'),
        # Start 0, then count 1 with a trailing zero byte.
        vector('A RANGE count with a trailing zero byte is accepted.', ops(b'', b'\x01\x00', output_range_amounts, 'OP_TX'),
               context=default_context(), _expect='valid'),
        # Start 0, then count 1 padded to 1,000 bytes; READ follows its length.
        vector('A long zero-padded scope operand is accepted.',
               ops(b'', b'\x01' + bytes(999), output_range_amounts, 'OP_TX'), context=default_context(), _expect='valid'),
        vector('A scope operand of 2^32 or more is invalid.',
               ops(b'', (1 << 32).to_bytes(5, 'little'), output_range_amounts, 'OP_TX'), context=default_context(),
               _expect='TX_SELECTOR'),
    ]


def unit_cases():
    tx = spending_tx(1, outputs=[CTxOut(10, CScript(b'')), CTxOut(20, CScript(b'')), CTxOut(30, CScript(b''))])
    spent = [CTxOut(40, CScript(b''))]
    output_count = bytes([0x00, 0x40, 0x00, 0x00, 0x00, 0x00])
    output_range_amounts = bytes([0x00, 0x00, 0x00, 0x04, 0x00, 0x01])
    return [
        vector('Range operands computed at runtime',
               ops(b'\xaa', 'OP_1', output_count, 'OP_TX', 'OP_1', 'OP_SUB', output_range_amounts, 'OP_TX'),
               context=context(tx, spent)),
        vector('A future selector version succeeds immediately', ops(b'\x01', 'OP_TX', 'OP_RETURN'),
               context=default_context()),
        # OP_CHECKSIGADD checks the budget, then adds the WRITE of its result 06, a
        # future selector version.
        vector('A future selector version still deducts the charges the previous opcode added after its budget check',
               ops(b'', b'\x06', b'\x02' * 32, 'OP_CHECKSIGADD', 'OP_TX'), context=default_context(), _expect='valid'),
        # A future selector version pays BASE (300) alone.
        vector('A future selector version with exactly BASE left succeeds', ops(b'\x01', 'OP_TX'),
               context=default_context(), _budget_after_prefix=300, _expect='valid'),
        vector('A future selector version with less than BASE left fails', ops(b'\x01', 'OP_TX'),
               context=default_context(), _budget_after_prefix=299, _expect='VAROP_COUNT'),
        vector('A future selector version cannot rescue a decoding failure', ops(b'\x01', 'OP_TX', raw(b'\x4c')),
               context=default_context()),
    ]


def build():
    return {
        'bip': 'op_tx',
        'active': ['440', '441', 'op_tx'],
        'scripts': [
            category('Selectors', converted() + selector_cases()),
            category('Runtime operands and selector versions', unit_cases()),
            category('Signature messages', sighash_constructions()),
        ],
    }
