"""BIP 441 vectors: Tapleaf 0xc2 execution."""
import json
import os

from common import (
    LEAF_VERSION_TAPSCRIPT, LEAF_VERSION_0XC2, MAX_ELEMENT, MAX_STACK_ITEMS, OPCODES, OPNAMES,
    CScript, CTxOut, category, context, control_block_bytes, disassemble, hexruns,
    leaf_sighash, num, ops, push, raw, repeated, script_bytes, sign, spending_tx, stack, taproot_construct,
    tx_hex, txout_hex, unhex, vector, xonly,
)

# gsr's former vector files (b778e1fa66), the source of the converted vectors.
SOURCES = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sources')

# Vectors that depend on the unrolled size limit of the reusable macros draft.
MACRO_DEPENDENT = {
    'Largest push at the script size limit',
    'Push of a 4000000-byte element exceeds the script size limit',
    'Largest skipped push at the script size limit',
    'Skipped push above the element size limit',
    'Truncated push in a skipped branch',
}

# Converted vectors that another vector covers: varops.json's sweep (the
# same opcode, operand sizes and kind of result) or a vector here.
COVERED = {
    "OP_VERIFY simple success (non-zero)",
    "OP_VERIFY stack presence test (zero followed by 01)",
    "OP_NOT success (non-zero becomes empty string)",
    "OP_NOT success (explicit empty string)",
    "OP_0NOTEQUAL success (non-zero becomes 01)",
    "OP_0NOTEQUAL success (explicit empty string becomes empty)",
    "OP_EQUAL success (equal non-empty strings)",
    "OP_EQUAL success (equal empty strings)",
    "OP_EQUAL fail (non-equal same length)",
    "OP_EQUAL fail (different lengths)",
    "OP_EQUALVERIFY success (equal non-empty strings)",
    "OP_EQUALVERIFY success (equal empty strings)",
    "OP_2DUP success (two small items)",
    "OP_2DUP success (stack total size exactly 8000000)",
    "OP_3DUP success (three small items)",
    "OP_3DUP success (stack total size exactly 8000000)",
    "OP_2OVER success (four small items)",
    "OP_2OVER success (stack total size exactly 8000000)",
    "OP_IFDUP success (non-zero one-byte)",
    "OP_IFDUP success (non-zero multi-byte)",
    "OP_IFDUP success (empty string is zero)",
    "OP_DUP success (one-byte item)",
    "OP_DUP success (multi-byte item)",
    "OP_DUP success (empty string)",
    "OP_DUP failure (copy of a 4000000-byte element over 8000000)",
    "OP_OVER success (two small items)",
    "OP_OVER success (multi-byte item copied)",
    "OP_OVER success (empty string copied)",
    "OP_TUCK success (two small items)",
    "OP_TUCK success (multi-byte duplication)",
    "OP_TUCK success (empty string duplicated)",
    "OP_PICK success (pick index 0 = top)",
    "OP_PICK success (pick index 1 = second)",
    "OP_PICK success (multi-byte target and index)",
    "OP_PICK success (zero-length target)",
    "OP_PICK success (non-minimal encoding of 0)",
    "OP_ROLL success (roll 0 = no change)",
    "OP_ROLL success (roll 1 = swap)",
    "OP_ROLL success (non-minimally encoded 0)",
    "OP_BOOLAND success (both one-byte non-zero)",
    "OP_BOOLAND success (multi-byte non-zero + single byte)",
    "OP_BOOLAND success (both empty)",
    "OP_BOOLOR success (both one-byte non-zero)",
    "OP_BOOLOR success (one empty, one non-zero)",
    "OP_BOOLOR success (both empty)",
    "OP_NUMEQUAL success (equal one-byte numbers)",
    "OP_NUMEQUAL fail (different values)",
    "OP_NUMEQUAL success (equal long values with trailing zeros)",
    "OP_NUMEQUALVERIFY success (equal one-byte)",
    "OP_NUMEQUALVERIFY success (equal with trailing zeros)",
    "OP_NUMEQUALVERIFY success (both zero)",
    "OP_NUMEQUALVERIFY success (long equal with trailing zeros)",
    "OP_NUMNOTEQUAL success (different one-byte values)",
    "OP_NUMNOTEQUAL success (both empty = equal)",
    "OP_NUMNOTEQUAL success (one empty, one padded zero = equal)",
    "OP_LESSTHAN success (empty < 01)",
    "OP_LESSTHAN success (01 < empty is false)",
    "OP_MIN success (empty and 01)",
    "OP_MIN success (empty and empty)",
    "OP_MIN success (normalizes selected result)",
    "OP_MAX success (equal values)",
    "OP_MAX success (empty and 01)",
    "OP_MAX success (empty and empty)",
    "OP_WITHIN success (2 in [1, 3))",
    "OP_WITHIN success (0 not in [1, 3))",
    "OP_WITHIN success (empty values treated as 0)",
    "OP_SHA256 success (empty string)",
    "OP_SHA256 success (short string)",
    "OP_SHA256 success (520 bytes)",
    "OP_HASH160 success (empty string)",
    "OP_HASH160 success (short string)",
    "OP_HASH160 success (520 bytes)",
    "OP_HASH256 success (empty string)",
    "OP_HASH256 success (short string)",
    "OP_HASH256 success (520 bytes)",
    "OP_LEFT - basic functionality",
    "OP_RIGHT - basic functionality",
    "OP_LEFT with zero offset",
    "OP_RIGHT with zero offset",
    "OP_LEFT with offset equal to string length",
    "OP_RIGHT with offset equal to string length",
    "OP_CAT - basic concatenation",
    "OP_CAT with both operands empty",
    "OP_SUBSTR - basic substring extraction",
    "OP_SUBSTR - extract from beginning",
    "OP_SUBSTR with empty string",
    "OP_INVERT - basic bitwise inversion",
    "OP_INVERT with empty element",
    "OP_INVERT with all ones",
    "OP_INVERT with alternating bit pattern",
    "OP_ROT: 0x01, 0x02, 0x03, 0x04",
    "OP_SWAP 0x01, 0x02, 0x03",
    "OP_SIZE 0x01, 0x02, 0x03",
    "OP_DEPTH 0x01, 0x02, 0x03, 0x04, 0x05",
    "OP_DIV: 10 / 3 = 3",
    "OP_DIV: 256 / 2 = 128",
    "OP_DIV: 1 / 1 = 1",
    "OP_DIV: 1 / 2 = 0",
    "OP_DIV: 4-byte / 2-byte (16777217 / 256 = 65536)",
    "OP_DIV: 8-byte / 1-byte",
    "OP_MOD: 10 % 3 = 1",
    "OP_MOD: 256 % 10 = 6",
    "OP_MOD: 1 % 2 = 1",
    "OP_MOD: 65535 % 256 = 255",
    "OP_MOD: 4-byte % 2-byte",
    "OP_LSHIFT: byte-aligned shift by 8 bits",
    "OP_LSHIFT: non-aligned shift by 1 bit",
    "OP_LSHIFT: shift by 0 bits (no-op)",
    "OP_LSHIFT: shift empty element by 8",
    "OP_LSHIFT: non-aligned shift by 9 bits",
    "OP_LSHIFT: multi-byte BITS operand (shift by 256)",
    "OP_RSHIFT: byte-aligned shift by 8 bits",
    "OP_RSHIFT: non-aligned shift by 1 bit",
    "OP_RSHIFT: shift by 0 bits (no-op)",
    "OP_RSHIFT: shift all bits out (result empty)",
    "OP_RSHIFT: shift more than element size (result empty)",
    "OP_RSHIFT: empty element shift",
    "OP_RSHIFT: non-aligned shift by 9 bits",
    "OP_2MUL: 0xFF overflows",
    "OP_2MUL: empty element stays empty",
    "OP_2MUL: overflow adds byte, result normalized",
    "OP_2DIV: 6 / 2 = 3",
    "OP_2DIV: 0xFF / 2 = 0x7F",
    "OP_2DIV: empty element stays empty",
    "OP_ADD: 0xFF + 0x01 carry to 2 bytes",
    "OP_ADD: 0 + 5 = 5",
    "OP_ADD: asymmetric lengths 1+2 bytes",
    "OP_ADD: large carry propagation",
    "OP_SUB: 5 - 3 = 2",
    "OP_SUB: 0x0001 (LE 256) - 0x01 = 0xFF",
    "OP_SUB: 0 - 0 = empty",
    "OP_SUB failure (zero minus one)",
    "OP_1ADD: 0xFF carry to 2 bytes",
    "OP_1ADD: 0 + 1 = 1",
    "OP_1ADD: 0xFFFF carry propagation",
    "OP_1SUB: 5 - 1 = 4",
    "OP_1SUB failure (zero)",
    "OP_MUL: 3 * 4 = 12",
    "OP_MUL: multiply by 0 = empty",
    "OP_MUL: 0 * value = empty",
    "OP_MUL: identity (multiply by 1)",
    "OP_MUL: 0xFF * 0xFF = 0x01FE",
    "OP_MUL: 2-byte * 2-byte",
    "OP_AND: 3-byte AND 1-byte zeros extended bytes",
    "OP_AND: 1-byte AND 3-byte (swapped internally)",
    "OP_OR: 3-byte OR 1-byte preserves longer",
    "OP_OR: 1-byte OR 3-byte (swapped internally)",
    "OP_XOR: 3-byte XOR 1-byte preserves longer",
}

# Former initial-stack limit vectors whose OP_NOP fails the same limit after it
# runs: with an empty script only the initial check can fail them.
EMPTY_SCRIPT = {'Initial element above the element size limit', 'Initial stack above the total size limit'}

# OP_SUCCESS opcodes of Tapleaf 0xc2 that no other BIP of the package assigns.
OP_SUCCESS = [79, 80, 98, 137, 138, 143, 144, 187, 188, 189] + list(range(192, 204)) + [205, 206] + list(range(210, 255))


def old_vectors(path):
    """The vectors of gsr's former JSON files, in the shared format."""
    text = open(os.path.join(SOURCES, os.path.basename(path))).read()
    categories, moved = [], []
    for old in json.loads(text):
        vectors = []
        for t in old['tests']:
            script = []
            for token in t['opcodes']:
                if token.startswith('OP_'):
                    script.append(token)
                    continue
                data = unhex(token)
                if len(data) == 1 and data[0] in OPNAMES and not 0 < data[0] <= 0x4e:
                    script.append(OPNAMES[data[0]])
                else:
                    script.extend(disassemble(data))
            if t['name'] in EMPTY_SCRIPT:
                script = []
            v = vector(t['name'], script, [hexruns(unhex(x)) for x in t.get('initial stack', [])])
            v['_old'] = {k: t[k] for k in ('final stack', 'varops cost', 'error') if k in t}
            if t['name'] in COVERED:
                continue
            (moved if t['name'] in MACRO_DEPENDENT else vectors).append(v)
        if vectors:
            categories.append(category(old['category'].removesuffix(' tests'), vectors))
    return categories, moved


def op_success():
    vs = []
    for op in OP_SUCCESS:
        name = OPNAMES.get(op, f'0x{op:02x}')
        vs.append(vector(f'{name} succeeds immediately', [raw(bytes([op]))]))
    one = raw(bytes([80]))
    vs += [
        vector('OP_SUCCESS precedes a later truncated push', [one, raw(b'\x4e')]),
        vector('A truncated push before OP_SUCCESS fails decoding', [raw(b'\x4e' + bytes([80]))]),
        vector('OP_SUCCESS in an inactive branch', ops('OP_0', 'OP_IF', [one], 'OP_ENDIF', 'OP_RETURN')),
        vector('OP_SUCCESS precedes the initial stack item limit', [one], [repeated(b'', MAX_STACK_ITEMS + 1)],
               budget=0, final=True),
        vector('OP_SUCCESS precedes the initial element size limit', [one], stack(b'\x01' * (MAX_ELEMENT + 1)),
               budget=0, final=True),
        vector('OP_SUCCESS precedes the initial total size limit', [one],
               stack(b'\x01' * MAX_ELEMENT, b'\x01' * MAX_ELEMENT, b'\x01'), budget=0, final=True),
        vector('OP_SUCCESS skips the final result rule', [one], stack(b'', b''), final=True),
    ]
    return category('OP_SUCCESS', vs)


def stack_items():
    full = [repeated(b'', MAX_STACK_ITEMS)]
    one_below = [repeated(b'', MAX_STACK_ITEMS - 1)]
    two_below = [repeated(b'', MAX_STACK_ITEMS - 2)]
    return category('Stack item limit', [
        vector('Initial stack at the item limit', ['OP_NOP'], full),
        vector('Initial stack above the item limit', [], [repeated(b'', MAX_STACK_ITEMS + 1)]),
        vector('OP_1 above the item limit', ['OP_1'], full),
        vector('OP_DEPTH at the item limit', ['OP_DEPTH'], one_below),
        vector('OP_2DUP above the item limit', ['OP_2DUP'], one_below),
        vector('OP_3DUP above the item limit', ['OP_3DUP'], two_below),
        vector('OP_IFDUP of a true value above the item limit', ['OP_IFDUP'],
               [repeated(b'', MAX_STACK_ITEMS - 1), '01']),
        vector('OP_IFDUP of a false value at the item limit', ['OP_IFDUP'], full),
        vector('The altstack counts toward the item limit', ['OP_TOALTSTACK', 'OP_1'], full),
    ])


def splice_ranges():
    abc = b'abcdef'
    large = bytes(8) + b'\x01'
    pad0 = bytes(3)
    return category('Splice operand ranges', [
        vector('OP_SUBSTR length beyond 64 bits is clamped', ['OP_SUBSTR'], stack(abc, num(2), large)),
        vector('OP_SUBSTR start beyond 64 bits gives an empty result', ['OP_SUBSTR'], stack(abc, large, large)),
        vector('OP_LEFT beyond 64 bits keeps everything', ['OP_LEFT'], stack(abc, large)),
        vector('OP_LEFT with a zero-padded length', ['OP_LEFT'], stack(abc, b'\x02\x00\x00')),
        vector('OP_RIGHT beyond 64 bits keeps everything', ['OP_RIGHT'], stack(abc, large)),
        vector('OP_RIGHT with a zero-padded length', ['OP_RIGHT'], stack(abc, b'\x02\x00\x00')),
        vector('OP_SUBSTR with zero-padded zeros', ['OP_SUBSTR'], stack(abc, pad0, pad0)),
        vector('OP_LSHIFT by a zero-padded zero', ['OP_LSHIFT'], stack(b'\x12\x34', pad0)),
        vector('OP_RSHIFT by a zero-padded zero', ['OP_RSHIFT'], stack(b'\x12\x34', pad0)),
    ])


def upgradable_nops():
    vs = [vector('OP_NOP4 ignores its operand', ops(bytes([1]) * 32, 'OP_NOP4'))]
    for name in ('OP_NOP1', 'OP_NOP5', 'OP_NOP6', 'OP_NOP7', 'OP_NOP8', 'OP_NOP9', 'OP_NOP10'):
        vs.append(vector(f'{name} does nothing', [name]))
    return category('Upgradable NOPs', vs)


def final_result():
    return category('Final result rule', [
        vector('0x80 is true', ops(b'\x80'), final=True),
        vector('An empty value is false', ops(b''), final=True),
        vector('Zero bytes are false', ops(b'\x00\x00'), final=True),
        vector('A nonzero high byte is true', ops(b'\x00\x01'), final=True),
        vector('Two values fail', ops('OP_1', 'OP_1'), final=True),
        vector('No value fails', [], final=True),
    ])


def signatures():
    """Signature checks with real signatures: the signature message commits to
    the 0xc2 leaf, the hash type, the annex and the OP_CODESEPARATOR position."""
    vs = []
    tx = spending_tx(2, sequences=[0xfffffffe, 0xfffffffd])
    spent = [CTxOut(5000, CScript(b'\x51\x20' + bytes([7]) * 32)), CTxOut(7000, CScript(b'\x51\x20' + bytes([9]) * 32))]
    key = xonly(1)

    def signed(comment, tokens, *, index=0, hash_type=0, codesep_pos=-1, annex=None, sign_with=None, tweak=None,
               extra=(), above=(), **fields):
        msg = leaf_sighash(tx, spent, index, tokens, hash_type=hash_type, codesep_pos=sign_with if sign_with is not None else codesep_pos,
                           annex=annex)
        sig = sign(1, msg) + (bytes([hash_type]) if hash_type else b'')
        if tweak:
            sig = tweak(sig)
        ctx = context(tx, spent, index, annex=annex)
        return vector(comment, tokens, stack(*extra, sig, *above), context=ctx, **fields)

    checksig = ops(key, 'OP_CHECKSIG')
    vs.append(signed('OP_CHECKSIG with a valid signature', checksig))
    vs.append(signed('OP_CHECKSIG of the second input', checksig, index=1))
    vs.append(signed('OP_CHECKSIG with hash type 0x01', checksig, hash_type=1))
    vs.append(signed('OP_CHECKSIG with an annex', checksig, annex=b'\x50\x01\x02'))
    vs.append(signed('OP_CHECKSIG with an invalid signature', checksig, tweak=lambda s: bytes([s[0] ^ 1]) + s[1:]))
    vs.append(signed('OP_CHECKSIG with a 63-byte signature', checksig, tweak=lambda s: s[:63]))
    vs.append(signed('OP_CHECKSIG with an invalid hash type', checksig, hash_type=1, tweak=lambda s: s[:64] + b'\x04'))
    vs.append(signed('OP_CHECKSIG with an explicit default hash type', checksig, hash_type=1,
                     tweak=lambda s: s[:64] + b'\x00'))
    vs.append(vector('OP_CHECKSIG with an empty public key', ops(b'', 'OP_CHECKSIG'), stack(b'\x01' * 64),
                     context=context(tx, spent)))
    vs.append(vector('OP_CHECKSIG with a 1-byte unknown public key type', ops(b'\x01', 'OP_CHECKSIG'),
                     stack(b'\x01' * 64), context=context(tx, spent)))
    vs.append(signed('OP_CHECKSIGVERIFY with a valid signature', ops(key, 'OP_CHECKSIGVERIFY', 'OP_1')))
    vs.append(vector('OP_CHECKSIGVERIFY with an empty signature', ops(key, 'OP_CHECKSIGVERIFY', 'OP_1'), stack(b''),
                     context=context(tx, spent)))
    add = ops(key, 'OP_CHECKSIGADD')
    vs.append(signed('OP_CHECKSIGADD adds one', add, above=[num(5)]))
    vs.append(signed('OP_CHECKSIGADD of a 4000000-byte zero', add, above=[bytes(MAX_ELEMENT)]))
    vs.append(signed('OP_CHECKSIGADD result above the element size limit', add, above=[b'\xff' * MAX_ELEMENT]))
    vs.append(vector('OP_CHECKSIGADD of a 4000000-byte zero with an empty signature', add,
                     stack(b'', bytes(MAX_ELEMENT)), context=context(tx, spent)))
    vs.append(vector('OP_CHECKSIGADD with an empty public key', ops(b'', 'OP_CHECKSIGADD'),
                     stack(b'\x01' * 64, b'\xff'), context=context(tx, spent)))
    sep = ops('OP_CODESEPARATOR', key, 'OP_CHECKSIG')
    vs.append(signed('OP_CODESEPARATOR at position 0 is signed', sep, sign_with=0))
    vs.append(signed('A signature without the OP_CODESEPARATOR position fails', sep, sign_with=-1))
    late = ops('OP_1', 'OP_DROP', 'OP_CODESEPARATOR', key, 'OP_CHECKSIG')
    vs.append(signed('OP_CODESEPARATOR at position 2 is signed', late, sign_with=2))
    skipped = ops('OP_0', 'OP_IF', 'OP_CODESEPARATOR', 'OP_ENDIF', key, 'OP_CHECKSIG')
    vs.append(signed('An OP_CODESEPARATOR in an inactive branch is not signed', skipped, sign_with=-1))
    return category('Signature checks', vs)


def locktimes():
    vs = []
    cltv_tx = spending_tx(locktime=0xffffffff, sequences=[0xfffffffe])
    spent = [CTxOut(5000, CScript(b'\x51\x20' + bytes(32)))]
    ctx = context(cltv_tx, spent)
    cltv = ['OP_CHECKLOCKTIMEVERIFY']
    vs.append(vector('OP_CHECKLOCKTIMEVERIFY with a zero-padded 0xffffffff', cltv, stack(b'\xff' * 4 + b'\x00'), context=ctx))
    vs.append(vector('OP_CHECKLOCKTIMEVERIFY above 32 bits', cltv, stack(bytes(4) + b'\x01'), context=ctx))
    low_tx = spending_tx(locktime=1, sequences=[0xfffffffe])
    low = context(low_tx, spent)
    vs.append(vector('OP_CHECKLOCKTIMEVERIFY with an empty operand is zero', cltv, stack(b''), context=low))
    vs.append(vector('OP_CHECKLOCKTIMEVERIFY with zero bytes beyond the eighth', cltv,
                     stack(b'\x01' + bytes(9)), context=low))
    vs.append(vector('OP_CHECKLOCKTIMEVERIFY above the lock time', cltv, stack(num(2)), context=low))
    final_tx = spending_tx(locktime=1, sequences=[0xffffffff])
    vs.append(vector('OP_CHECKLOCKTIMEVERIFY with a final sequence', cltv, stack(num(1)), context=context(final_tx, spent)))
    csv_tx = spending_tx(version=2, sequences=[1])
    csv_ctx = context(csv_tx, spent)
    csv = ['OP_CHECKSEQUENCEVERIFY']
    vs.append(vector('OP_CHECKSEQUENCEVERIFY with a zero-padded one', csv, stack(b'\x01' + bytes(4)), context=csv_ctx))
    vs.append(vector('OP_CHECKSEQUENCEVERIFY above 32 bits', csv, stack(bytes(4) + b'\x01'), context=csv_ctx))
    vs.append(vector('OP_CHECKSEQUENCEVERIFY above 32 bits with the disable flag', csv,
                     stack(b'\x00\x00\x00\x80\x01'), context=csv_ctx))
    vs.append(vector('OP_CHECKSEQUENCEVERIFY with the disable flag', csv, stack(b'\x00\x00\x00\x80'), context=csv_ctx))
    vs.append(vector('OP_CHECKSEQUENCEVERIFY with an empty operand is zero', csv, stack(b''), context=csv_ctx))
    vs.append(vector('OP_CHECKSEQUENCEVERIFY with zero bytes beyond the eighth', csv,
                     stack(b'\x01' + bytes(9)), context=csv_ctx))
    vs.append(vector('OP_CHECKSEQUENCEVERIFY above the sequence', csv, stack(num(2)), context=csv_ctx))
    v1_tx = spending_tx(version=1, sequences=[1])
    vs.append(vector('OP_CHECKSEQUENCEVERIFY in a version 1 transaction', csv, stack(num(1)), context=context(v1_tx, spent)))
    return category('Lock time and sequence', vs)


def added_vectors():
    """Vectors added to the converted categories, by category."""
    inactive = lambda op: ops('OP_0', 'OP_IF', op, 'OP_ENDIF', 'OP_1')
    return {
        'OP_SUB': [
            vector('OP_SUB failure (B longer than A)', ['OP_SUB'], stack(b'\x05', b'\x00\x01'), _expect='SUB_UNDERFLOW'),
        ],
        # As in BIP 342, OP_VERIF and OP_VERNOTIF fail even when not executed.
        'BIP 342 restrictions': [
            vector('OP_VERIF failure in an inactive branch', inactive('OP_VERIF'), _expect='BAD_OPCODE'),
            vector('OP_VERNOTIF failure in an inactive branch', inactive('OP_VERNOTIF'), _expect='BAD_OPCODE'),
        ],
        # The 0xc2 limits replace BIP 342's 520-byte push limit, which applies
        # even when not executed.
        'Size and budget limit': [
            vector('A 521-byte push in an inactive branch', inactive(b'\x01' * 521), _expect='valid'),
        ],
        # Each with one operand too few; sorted into the category by opcode.
        'Missing operands': [
            missing('OP_TOALTSTACK', 0),
            missing('OP_FROMALTSTACK', 0, 'INVALID_ALTSTACK_OPERATION'),
            missing('OP_2DROP', 1),
            missing('OP_2ROT', 5),
            missing('OP_2SWAP', 3),
            missing('OP_DROP', 0),
            missing('OP_NIP', 1),
            missing('OP_CHECKSIG', 1),
            missing('OP_CHECKSIGVERIFY', 1),
            missing('OP_CHECKSIGADD', 2),
        ],
    }


def missing(opcode, items, error='INVALID_STACK_OPERATION'):
    """opcode failing with only `items` operands, 61 62 ... in the converted style."""
    return vector(f'{opcode} failure (missing operand)', [opcode], stack(*(bytes([0x61 + i]) for i in range(items))),
                  _expect=error)


def script_vectors():
    varops_cats, moved_a = old_vectors('src/test/data/tapscript_v2_varops.json')
    restored_cats, moved_b = old_vectors('src/test/data/tapscript_v2_restored_ops.json')
    added = added_vectors()
    for cat in varops_cats + restored_cats:
        cat['vectors'] += added.pop(cat['category'], [])
        if cat['category'] == 'Missing operands':
            cat['vectors'].sort(key=lambda v: OPCODES[v['script'][0]])
    assert not added, added
    cats = varops_cats + restored_cats + [
        op_success(), stack_items(), splice_ranges(), upgradable_nops(),
        final_result(), signatures(), locktimes(),
    ]
    return cats, moved_a + moved_b


# Transactions: complete spends of Tapleaf 0xc0 and 0xc2 outputs.

def leaf_spend(scripts, spend, witness_items=(), *, annex=None, internal=None):
    """A one-input transaction spending leaf `spend` of a tree of (name, tokens, version)."""
    internal = internal or xonly(2)
    info = taproot_construct(internal, [(name, CScript(script_bytes(tokens)), version) for name, tokens, version in scripts])
    tokens = next(t for n, t, _ in scripts if n == spend)
    tx = spending_tx()
    spent = [CTxOut(10_000, info.scriptPubKey)]
    tx.wit.vtxinwit[0].scriptWitness.stack = list(witness_items) + [script_bytes(tokens), control_block_bytes(info, spend)] + \
        ([annex] if annex is not None else [])
    return tx, spent, info


def transaction(comment, tx, spent):
    return {'comment': comment, 'tx': tx_hex(tx), 'spent_outputs': [txout_hex(o) for o in spent]}


def transaction_vectors():
    vs = []
    for name, tokens, version in (
        ('OP_MUL is OP_SUCCESS in a 0xc0 leaf', ['OP_MUL', 'OP_7', 'OP_EQUAL'], LEAF_VERSION_TAPSCRIPT),
        ('OP_MUL executes in a 0xc2 leaf', ['OP_MUL', 'OP_6', 'OP_EQUAL'], LEAF_VERSION_0XC2),
    ):
        items = [b'\x02', b'\x03']
        tx, spent, _ = leaf_spend([('leaf', tokens, version)], 'leaf', items)
        vs.append(transaction(name, tx, spent))
    tree = [('c0', ['OP_1'], LEAF_VERSION_TAPSCRIPT), ('c2', ['OP_2', 'OP_DROP', 'OP_1'], LEAF_VERSION_0XC2)]
    for spend in ('c0', 'c2'):
        tx, spent, _ = leaf_spend(tree, spend)
        vs.append(transaction(f'The {spend} leaf of a tree with both versions', tx, spent))
    # A real signature in a complete spend.
    key = xonly(3)
    tokens = ops(key, 'OP_CHECKSIG')
    tx, spent, info = leaf_spend([('sig', tokens, LEAF_VERSION_0XC2)], 'sig', [b''])
    msg = leaf_sighash(tx, spent, 0, tokens)
    tx.wit.vtxinwit[0].scriptWitness.stack[0] = sign(3, msg)
    vs.append(transaction('A signed 0xc2 leaf', tx, spent))
    tx.wit.vtxinwit[0].scriptWitness.stack[0] = sign(3, leaf_sighash(tx, spent, 0, tokens, leaf_ver=LEAF_VERSION_TAPSCRIPT))
    vs.append(transaction('A signature for the 0xc0 leaf hash fails in a 0xc2 leaf', tx, spent))
    return [category('Complete spends', vs)]


def signing_vectors():
    vs = []
    trees = {
        'one 0xc2 leaf': [('a', ops(xonly(4), 'OP_CHECKSIG'), LEAF_VERSION_0XC2)],
        'a 0xc0 and a 0xc2 leaf': [('a', ops(xonly(4), 'OP_CHECKSIG'), LEAF_VERSION_TAPSCRIPT),
                                   ('b', ops(xonly(5), 'OP_CHECKSIG'), LEAF_VERSION_0XC2)],
        'three 0xc2 leaves': [('a', ops('OP_1'), LEAF_VERSION_0XC2),
                              [('b', ops(xonly(4), 'OP_CHECKSIG'), LEAF_VERSION_0XC2),
                               ('c', ops('OP_CODESEPARATOR', xonly(5), 'OP_CHECKSIG'), LEAF_VERSION_0XC2)]],
    }

    def leaves(tree, depth=0):
        out = []
        for item in tree:
            if isinstance(item, list):
                out += leaves(item, depth + 1)
            else:
                out.append((depth if len(tree) == 1 else depth + 1, item))
        return out

    cases = [
        ('one 0xc2 leaf', 'a', 0, -1, None),
        ('one 0xc2 leaf', 'a', 1, -1, None),
        ('one 0xc2 leaf', 'a', 0x83, -1, b'\x50\x01'),
        ('a 0xc0 and a 0xc2 leaf', 'b', 0, -1, None),
        ('a 0xc0 and a 0xc2 leaf', 'b', 2, -1, None),
        ('three 0xc2 leaves', 'c', 0, 0, None),
        ('three 0xc2 leaves', 'c', 0x81, 0, b'\x50'),
        ('three 0xc2 leaves', 'b', 3, -1, None),
    ]
    for tree_name, spend, hash_type, codesep, annex in cases:
        tree = trees[tree_name]
        flat = leaves(tree)
        internal = xonly(6)
        info = taproot_construct(internal, [
            [(n, CScript(script_bytes(t)), v) for n, t, v in item] if isinstance(item, list) else
            (item[0], CScript(script_bytes(item[1])), item[2]) for item in tree])
        tx = spending_tx(2)
        spent = [CTxOut(20_000, info.scriptPubKey), CTxOut(30_000, CScript(b'\x51\x20' + bytes([3]) * 32))]
        names = [item[0] for _, item in flat]
        v = {
            'comment': f'Leaf {spend} of {tree_name}, hash type {hash_type:#04x}' +
                       (f', OP_CODESEPARATOR at {codesep}' if codesep >= 0 else '') + (', with an annex' if annex else ''),
            'internal_key': internal.hex(),
            'leaves': [{'depth': depth, 'version': f'{item[2]:02x}', 'script': item[1]} for depth, item in flat],
            'spend_leaf': names.index(spend),
            'context': context(tx, spent, 0, annex=annex),
            'hash_type': hash_type,
        }
        if codesep >= 0:
            v['codesep_pos'] = codesep
        v['_check_script_pubkey'] = info.scriptPubKey.hex()
        vs.append(v)
    return [category('Signature messages', vs)]


def build():
    scripts, moved = script_vectors()
    data = {
        'bip': '441',
        'active': ['440', '441'],
        'scripts': scripts,
        'transactions': transaction_vectors(),
        'signing': signing_vectors(),
    }
    return data, moved
