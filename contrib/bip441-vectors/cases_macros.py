"""Reusable macros vectors."""
import json
import os

from common import (
    CScript, CTxOut, category, compact_size, context, disassemble, hexruns, leaf_sighash, ops, push, raw,
    script_bytes, sign, spending_tx, stack, vector, xonly,
)

# gsr's former vector files (b778e1fa66), the source of the converted vectors.
SOURCES = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sources')


def tokens(hex_script):
    return disassemble(bytes.fromhex(hex_script), macros=True)


def capitalized(text):
    return text[:1].upper() + text[1:]


def define(body):
    """Tokens declaring a body given as raw bytes."""
    return ['OP_MACRO', raw(compact_size(len(body))), raw(body)] if body else ['OP_MACRO', raw(b'\x00')]


def reference(index):
    return ['OP_CALLMACRO', raw(compact_size(index))]


# Converted vectors that others cover, by group. The OP_TX one depends on
# OP_TX and is in op_tx.json.
COVERED = {
    'decoding': {
        # The unrolling vectors of the same scripts imply well-formed decoding.
        'no declarations', 'repeated arithmetic', 'nested reference to an earlier body',
        # 'A three-byte length of 252 is not canonical'; 'Second declaration
        # length exceeds script' and 'A canonical length beyond the script'.
        'noncanonical declaration length', 'declaration length exceeds script',
        'reserved OP_TX selector cannot rescue a decoding failure',
        # The size limit is part of the scan; size_limit_decoding() has it.
        'OP_SUCCESS precedes an unrolled length over the limit',
    },
    # No longer well-formed: size_limit_decoding() has them as scan failures.
    'unrolling': {'unrolled length one byte over the limit', 'doubling past the limit'},
    'execution': {
        # 'Unrolling charge and execution'; 'A 1-byte push referenced in an
        # inactive branch' and 'A 100000-byte push ...'; 'Nested doubling
        # executed'; 'Body opens a conditional closed by main'.
        'reference in inactive branch', 'large pushes in inactive branch', 'nested doubling in an inactive branch',
        'OP_NOTIF inside a body',
    },
}


def converted():
    text = open(os.path.join(SOURCES, 'tapscript_v2_macros.json')).read()
    old = json.loads(text)
    for group in ('decoding', 'unrolling', 'execution'):
        old[group] = [v for v in old[group] if v['comment'] not in COVERED[group]]
    decoding = [{'comment': capitalized(v['comment']), 'script': tokens(v['script'])} for v in old['decoding']]
    unrolling = [{'comment': capitalized(v['comment']), 'script': tokens(v['script'])} for v in old['unrolling']]
    execution = [vector(capitalized(v['comment']), tokens(v['script']), [hexruns(bytes.fromhex(x)) for x in v['initial_stack']])
                 for v in old['execution']]
    return decoding, unrolling, execution


def length_encodings():
    def declare(length, body_size):
        return {'comment': '', 'script': ['OP_MACRO', raw(bytes(length))] + ([raw(b'\x61' * body_size)] if body_size else [])}

    cases = [
        ('A one-byte length of 252', [0xfc], 252),
        ('A three-byte length of 253', [0xfd, 0xfd, 0x00], 253),
        ('A five-byte length of 65536', [0xfe, 0x00, 0x00, 0x01, 0x00], 65_536),
        ('A three-byte length of 252 is not canonical', [0xfd, 0xfc, 0x00], 252),
        ('A five-byte length of 65535 is not canonical', [0xfe, 0xff, 0xff, 0x00, 0x00], 65_535),
        ('A nine-byte length of 65536 is not canonical', [0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00], 65_536),
        ('A truncated three-byte length', [0xfd, 0x01], 0),
        ('A truncated nine-byte length', [0xff, 0x00, 0x00, 0x00, 0x00], 0),
        ('A canonical length beyond the script', [0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00], 0),
    ]
    out = []
    for comment, length, size in cases:
        v = declare(length, size)
        v['comment'] = comment
        out.append(v)
    return out


def payload_unrolling():
    out = []
    for size in (0, 1, 100_000):
        body = bytes(CScript([b'\x42' * size])) if size else b'\x00'
        script = define(body) + ['OP_0', 'OP_IF'] + reference(0) + ['OP_ENDIF', 'OP_1']
        out.append({'comment': f'A {size}-byte push referenced in an inactive branch', 'script': script})
    return out


def limit_bodies(extra=b'', before=b''):
    """Body 0 is a 4,000-byte push; body 1 references it 1,000 times, so it
    unrolls to exactly the size limit, plus the bytes before and extra."""
    body0 = bytes(CScript([b'\x42' * 3997]))
    body1 = before + b'\xd1\x00' * 1000 + extra
    return define(body0) + define(body1)


def limit_script():
    return limit_bodies() + reference(1)


def size_limit_decoding():
    """The scan fails at the instruction that takes a body or the main script
    past the size limit, so the first success or failure still decides."""
    def case(comment, script, expect):
        return {'comment': comment, 'script': script, '_expect': expect}

    doubling_past = define(b'\x61')
    for i in range(22):
        doubling_past += define(b'\xd1' + compact_size(i) + b'\xd1' + compact_size(i))
    return [
        case('An unreferenced body at the limit', limit_bodies() + ['OP_1'], 'well-formed'),
        case('An unreferenced body one byte over the limit', limit_bodies(b'\x61') + ['OP_1'], 'failure'),
        case('A main script one byte over the limit', limit_script() + ['OP_NOP'], 'failure'),
        case('Doubling fails at the first body over the limit', doubling_past + reference(22), 'failure'),
        case('The limit in a body precedes a later OP_SUCCESS in that body', limit_bodies(b'\x61\x50') + ['OP_1'],
             'failure'),
        case('The limit in a body precedes a later OP_SUCCESS in main', limit_bodies(b'\x61') + ['OP_RESERVED'],
             'failure'),
        case('The limit in main precedes a later OP_SUCCESS', limit_script() + ['OP_NOP', 'OP_RESERVED'], 'failure'),
        case('The limit without declarations precedes a later OP_SUCCESS', [push(b'\x42' * 3_999_996), 'OP_RESERVED'],
             'failure'),
        case('OP_SUCCESS precedes the limit in the same body', limit_bodies(b'\x61', before=b'\x50') + ['OP_1'],
             'success'),
        case('An OP_SUCCESS that would cross the limit succeeds', limit_bodies(b'\x50') + ['OP_1'], 'success'),
        case('OP_SUCCESS in main precedes the limit', limit_bodies() + ['OP_RESERVED'] + reference(1) + ['OP_NOP'],
             'success'),
    ]


def doubling(leaf):
    script = define(leaf)
    for i in range(70):
        script += define(b'\xd1' + compact_size(i) + b'\xd1' + compact_size(i))
    return script + reference(70) + ['OP_1']


def charge_script():
    return ['OP_MACRO', '0x02', 'OP_DUP', 'OP_DROP', 'OP_0', 'OP_IF'] + reference(0) + ['OP_ENDIF', 'OP_1']


def scripts_from_unit_tests():
    vs = [
        vector('Unrolling charge and execution', charge_script()),
        vector('One varop short of the complete charge', charge_script(), _budget_rel=('varops', -1)),
        vector('Unreferenced declarations', ['OP_MACRO', '0x03', 'OP_DUP', 'OP_DUP', 'OP_DROP',
                                             'OP_MACRO', '0x01', 'OP_1', 'OP_1']),
        vector('An unrolled script at the size limit', limit_script()),
        vector('An unrolled script one byte over the size limit', limit_script() + ['OP_0', 'OP_IF', 'OP_ENDIF'],
               _expect='SCRIPT_SIZE'),
        vector('An unreferenced body one byte over the size limit', limit_bodies(b'\x61') + ['OP_1'],
               _expect='SCRIPT_SIZE'),
        vector('The size limit precedes a later OP_SUCCESS', limit_script() + ['OP_NOP', 'OP_RESERVED'],
               _expect='SCRIPT_SIZE'),
        vector('The size limit precedes a later decoding failure',
               limit_script() + ['OP_0', 'OP_IF', 'OP_ENDIF', raw(b'\x4c')], _expect='SCRIPT_SIZE'),
        vector('A decoding failure precedes the size limit', limit_bodies() + reference(2) + reference(1) + ['OP_NOP'],
               _expect='BAD_OPCODE'),
        vector('Doubling stops at the first body over the size limit', doubling(b'\x61'), _expect='SCRIPT_SIZE'),
        vector('A charge beyond 64 bits exhausts any budget', doubling(b'')),
    ]
    chain = define(b'\x51')
    for i in range(1, 2048):
        chain += define(b'\xd1' + compact_size(i - 1))
    vs.append(vector('References nested 2,048 deep', chain + reference(2047)))
    vs += [stack_limit_after_condition('OP_IF'), stack_limit_after_condition('OP_NOTIF')]
    return vs


def stack_limit_after_condition(opcode):
    """opcode consumes a one-byte condition, leaving room for seven copies of a
    1,000,000-byte value: the stack peaks at exactly 8,000,000 bytes."""
    branch = ['OP_IF'] if opcode == 'OP_IF' else ['OP_NOTIF', 'OP_ELSE']
    script = ['OP_MACRO', '0x01', 'OP_DUP'] + branch + reference(0) * 7 + ['OP_ENDIF'] + ['OP_DROP'] * 8 + ['OP_1']
    return vector(f'{opcode} consumes its condition before the stack peaks at the total size limit', script,
                  stack(b'\x01' * 1_000_000, b'\x01'), _expect='valid')


def op_tx_fields():
    """OP_TX in a macro script: the committed script, and positions in the
    unrolled script."""
    tx = spending_tx()
    spent = [CTxOut(5000, CScript(b'\x51\x20' + bytes([8]) * 32))]
    tapscript = ['OP_MACRO', '0x01', 'OP_NOP'] + reference(0) + [push(bytes.fromhex('000004000000')), 'OP_TX']
    position = ['OP_MACRO', '0x02', 'OP_NOP', 'OP_CODESEPARATOR'] + reference(0) + reference(0) + [push(bytes.fromhex('000080000000')), 'OP_TX']
    return [
        vector('CURRENT_TAPSCRIPT is the committed script, with its declarations', tapscript,
               context=context(tx, spent), _expect_top=hexruns(script_bytes(tapscript))),
        # Unrolled: OP_NOP OP_CODESEPARATOR OP_NOP OP_CODESEPARATOR <selector> OP_TX.
        vector('CURRENT_CODESEPARATOR_POSITION counts opcodes of the unrolled script', position,
               context=context(tx, spent), _expect_top='03'),
    ]


def codeseparators():
    """Signatures commit to OP_CODESEPARATOR's position in the unrolled script."""
    tx = spending_tx()
    spent = [CTxOut(5000, CScript(b'\x51\x20' + bytes([8]) * 32))]
    key = xonly(30)
    script = define(b'\xab') + ['OP_1', 'OP_DROP'] + reference(0) + ops(key, 'OP_CHECKSIG')
    vs = []
    for comment, position in (('Signed with the unrolled position', 2), ('Signed with the committed position', 4),
                              ('Signed without a position', -1)):
        sig = sign(30, leaf_sighash(tx, spent, 0, script, codesep_pos=position))
        vs.append(vector(comment, script, stack(sig), context=context(tx, spent)))
    return vs


def build(moved):
    decoding, unrolling, execution = converted()
    limit = [vector(v['comment'], v['script'], v['stack']) for v in moved]
    return {
        'bip': 'reusable_macros',
        'active': ['440', '441', 'op_tx', 'reusable_macros'],
        'decoding': [category('Decoding', decoding), category('Declaration lengths', length_encodings()),
                     category('Unrolled size limit', size_limit_decoding())],
        'unrolling': [category('Unrolling', unrolling), category('Push payloads', payload_unrolling())],
        'scripts': [
            category('Execution', execution),
            category('Charges and limits', scripts_from_unit_tests()),
            category('Pushes at the unrolled size limit', limit),
            category('OP_CODESEPARATOR positions', codeseparators()),
            category('OP_TX fields', op_tx_fields()),
        ],
    }
