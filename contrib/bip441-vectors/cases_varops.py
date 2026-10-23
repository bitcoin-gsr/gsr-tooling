"""BIP 440 vectors: cost primitives, the cost of every 440/441 opcode across
operand attributes, and the transaction budget."""
from common import (
    LEAF_VERSION_TAPSCRIPT, LEAF_VERSION_0XC2, MAX_ELEMENT, CScript, CTxOut, category, context,
    control_block_bytes, num, ops, repeated, script_bytes, sign, spending_tx, stack, taproot_construct,
    tx_hex, txout_hex, vector, xonly,
)
from test_framework.key import tweak_add_privkey
from test_framework.script import TaprootSignatureHash, hash160, sha256
from common import privkey

# Empty, one byte, both sides of the 8-byte word boundary of W(n), and a
# large value.
SIZES = [0, 1, 8, 9, 65536]
NONZERO_SIZES = [n for n in SIZES if n]


def ff(n):
    return b'\xff' * n


def padded_one(n):
    """The number 1 in n bytes."""
    return (b'\x01' + bytes(n - 1)) if n else b''


def label(n):
    return '1 byte' if n == 1 else f'{n} bytes'


def of_ff(n):
    return f'{label(n)} of ff' if n else 'An empty value'


def filled(n, count):
    """count n-byte values with distinct bytes, so moves and copies show."""
    return [bytes([0x11 * (i + 1)]) * n for i in range(count)]


def primitives():
    vs = []

    def p(name, **args):
        text = ', '.join(f'{k}={v}' for k, v in args.items())
        vs.append({'comment': f'{name}({text})' if args else name, 'primitive': name, **args})

    p('BASE')
    p('SIGCHECK')
    for name in ('READ', 'WRITE', 'ARITH'):
        for n in (0, 1, 8, 9, MAX_ELEMENT):
            p(name, n=n)
    for k in (0, 1, 1000):
        p('MOVE', k=k)
    for n, m in ((0, 0), (1, 1), (9, 8), (MAX_ELEMENT, MAX_ELEMENT)):
        p('MUL', n=n, m=m)
    for n, m in ((0, 0), (1, 9), (8, 8), (9, 8), (MAX_ELEMENT, 8), (MAX_ELEMENT, MAX_ELEMENT // 2)):
        p('DIV', n=n, m=m)
    for n in (0, 55, 56, 119, 120, MAX_ELEMENT):
        p('HASH', n=n)
    return [category('Cost primitives', vs)]


def sweep():
    cats = []

    def cat(name, vectors):
        cats.append(category(name, vectors))

    # Witness values cost nothing; literal pushes are written.
    cat('Initial stack', [vector(f'A {n}-byte value', [], stack(ff(n))) for n in (0, MAX_ELEMENT)])
    cat('Literal pushes', [vector(f'A {n}-byte push', ops(b'\x42' * n)) for n in
                           (0, 1, 75, 76, 255, 256, 65535, 65536)] +
        [vector('OP_1', ['OP_1'])])
    cat('Final result check',
        [vector(f'A true {n}-byte value', [], stack(padded_one(n)[::-1]), final=True) for n in (1, 65536)])

    # Control and simple examination (BIP 440 opcode tables).
    cat('OP_NOP and OP_CODESEPARATOR', [vector('OP_NOP', ['OP_NOP']), vector('OP_CODESEPARATOR', ['OP_CODESEPARATOR'])])
    cat('Upgradable NOPs', [vector(name, [name]) for name in
                            ['OP_NOP1'] + [f'OP_NOP{i}' for i in range(4, 11)]])
    cat('Conditionals', [
        vector('Skipped instructions are not charged', ops('OP_0', 'OP_IF', 'OP_1', 'OP_DROP', 'OP_SHA256', 'OP_ENDIF')),
        vector('Conditionals in an inactive branch are charged',
               ops('OP_0', 'OP_IF', 'OP_1', 'OP_IF', 'OP_ELSE', 'OP_ENDIF', 'OP_ENDIF')),
        vector('Skipped pushes are not charged', ops('OP_0', 'OP_IF', b'\x42' * 520, 'OP_ENDIF')),
        vector('OP_NOTIF of an empty value', ['OP_NOTIF', 'OP_ENDIF'], stack(b'')),
        vector('OP_NOTIF of 01', ['OP_NOTIF', 'OP_ENDIF'], stack(b'\x01')),
    ])
    cat('OP_VERIFY', [vector(of_ff(n), ['OP_VERIFY'], stack(ff(n))) for n in NONZERO_SIZES])
    for name in ('OP_NOT', 'OP_0NOTEQUAL'):
        cat(name, [vector(of_ff(n), [name], stack(ff(n))) for n in SIZES])
    for name in ('OP_EQUAL', 'OP_EQUALVERIFY'):
        vs = [vector(f'Equal {n}-byte values', [name], stack(ff(n), ff(n))) for n in SIZES]
        if name == 'OP_EQUAL':
            vs += [vector('Different 4096-byte values are read in full', [name], stack(ff(4096), padded_one(4096)))]
            vs += [vector('Different lengths are not read', [name], stack(ff(4096), ff(4095)))]
        cat(name, vs)

    # Stack manipulation.
    for name in ('OP_DUP', 'OP_OVER', 'OP_TUCK', 'OP_2DUP', 'OP_3DUP', 'OP_2OVER'):
        depth = {'OP_DUP': 1, 'OP_OVER': 2, 'OP_TUCK': 2, 'OP_2DUP': 2, 'OP_3DUP': 3, 'OP_2OVER': 4}[name]
        vs = [vector(f'{n}-byte values', [name], stack(*filled(n, depth))) for n in SIZES]
        if depth > 1:
            vs += [vector('Values of different lengths', [name], stack(*[ff(9 * (i + 1)) for i in range(depth)]))]
        cat(name, vs)
    cat('OP_IFDUP', [vector(f'A true {n}-byte value', ['OP_IFDUP'], stack(ff(n))) for n in NONZERO_SIZES] +
        [vector('A false 0-byte value', ['OP_IFDUP'], stack(b''))])
    for name in ('OP_DROP', 'OP_2DROP', 'OP_NIP'):
        depth = {'OP_DROP': 1, 'OP_2DROP': 2, 'OP_NIP': 2}[name]
        cat(name, [vector(f'{n}-byte values', [name], stack(*filled(n, depth))) for n in (0, 65536)])
    for name, depth in (('OP_SWAP', 2), ('OP_ROT', 3), ('OP_2SWAP', 4), ('OP_2ROT', 6)):
        cat(name, [vector(f'{n}-byte values', [name], stack(*filled(n, depth))) for n in (0, 65536)])
    cat('OP_TOALTSTACK and OP_FROMALTSTACK', [vector(f'A {n}-byte value', ['OP_TOALTSTACK', 'OP_FROMALTSTACK'],
                                                     stack(ff(n))) for n in (0, 65536)])
    cat('OP_DEPTH', [vector('0 values', ['OP_DEPTH']), vector('1 value', ['OP_DEPTH'], stack(b''))])

    def below(depth):
        return [repeated(b'\xaa', depth)] if depth >= 16 else stack(*[b'\xaa'] * depth)

    # OP_PICK's cost does not depend on the depth; OP_ROLL's does.
    pick = [vector(f'A {n}-byte value at depth {depth}', ['OP_PICK'], stack(ff(n)) + below(depth) + stack(num(depth)))
            for n, depth in ((0, 0), (65536, 0), (65536, 1000))]
    roll = [vector(f'Depth {depth}', ['OP_ROLL'], stack(ff(520)) + below(depth) + stack(num(depth))) for depth in (0, 1000)]
    pick.append(vector('Zero-padded index', ['OP_PICK'], stack(ff(9), b'\x00' * 9)))
    roll.append(vector('Zero-padded index', ['OP_ROLL'], stack(ff(9), b'\x00' * 9)))
    cat('OP_PICK', pick)
    cat('OP_ROLL', roll)
    cat('OP_SIZE', [vector(f'A {n}-byte value', ['OP_SIZE'], stack(ff(n))) for n in (0, 1, 65536)])

    # Comparison operators.
    for name in ('OP_BOOLAND', 'OP_BOOLOR', 'OP_NUMEQUAL', 'OP_NUMEQUALVERIFY', 'OP_NUMNOTEQUAL', 'OP_LESSTHAN',
                 'OP_GREATERTHAN', 'OP_LESSTHANOREQUAL', 'OP_GREATERTHANOREQUAL', 'OP_MIN', 'OP_MAX'):
        vs = [vector(f'{n}-byte operands', [name], stack(ff(n), ff(n))) for n in SIZES]
        vs += [vector('4096 bytes and 1 byte', [name], stack(ff(4096), ff(1))),
               vector('1 byte and 4096 bytes', [name], stack(ff(1), ff(4096)))]
        if name in ('OP_MIN', 'OP_MAX'):
            # The result is written normalized.
            vs += [vector('Padded ones of 4096 bytes', [name], stack(padded_one(4096), padded_one(4096)))]
        if name in ('OP_NUMEQUALVERIFY',):
            vs = [v for v in vs if '1 byte' not in v['comment']]
        cat(name, vs)
    cat('OP_WITHIN', [vector(f'{n}-byte operands', ['OP_WITHIN'], stack(padded_one(n), b'', ff(n))) for n in NONZERO_SIZES] +
        [vector('Outside the range', ['OP_WITHIN'], stack(ff(9), b'', ff(8)))])

    # Hashes.
    # Both sides of the first block boundary; OP_RIPEMD160 and OP_SHA1 take at
    # most 520 bytes, which tapleaf_0xc2.json tests.
    for name, sizes in (('OP_RIPEMD160', (0, 1, 55, 56)), ('OP_SHA1', (0, 1, 55, 56)),
                        ('OP_SHA256', (0, 1, 55, 56, 65536)), ('OP_HASH160', (0, 1, 55, 56, 65536)),
                        ('OP_HASH256', (0, 1, 55, 56, 65536))):
        cat(name, [vector(f'A {n}-byte message', [name], stack(b'\x42' * n)) for n in sizes])

    # Restored opcodes (BIP 441).
    cat('OP_CAT', [vector(f'{label(a)} and {label(b)}', ['OP_CAT'], stack(ff(a), b'\x01' * b)) for a, b in
                   ((0, 0), (1, 1), (7, 1), (8, 1), (65536, 1))])
    substr = [vector(f'First byte of {label(n)}', ['OP_SUBSTR'], stack(ff(n), b'', num(1))) for n in SIZES]
    substr += [vector('Half of 65536 bytes', ['OP_SUBSTR'], stack(ff(65536), num(65536 // 4), num(65536 // 2)))]
    cat('OP_SUBSTR', substr)
    for name in ('OP_LEFT', 'OP_RIGHT'):
        cat(name, [vector(f'Keep {kept} of 65536 bytes', [name], stack(b'\x42' * 65536, num(kept)))
                   for kept in (0, 1, 32768, 65536)])
    cat('OP_INVERT', [vector(f'A {n}-byte value', ['OP_INVERT'], stack(ff(n))) for n in SIZES])
    for name in ('OP_AND', 'OP_OR', 'OP_XOR'):
        vs = [vector(f'{n}-byte operands', [name], stack(ff(n), padded_one(n))) for n in SIZES]
        vs += [vector('4096 bytes and 1 byte', [name], stack(ff(4096), ff(1))),
               vector('1 byte and 4096 bytes', [name], stack(ff(1), ff(4096)))]
        cat(name, vs)
    for name in ('OP_1ADD', 'OP_2MUL', 'OP_2DIV', 'OP_1SUB'):
        sizes = NONZERO_SIZES if name == 'OP_1SUB' else SIZES
        vs = [vector(of_ff(n), [name], stack(ff(n))) for n in sizes]
        # A long number of small value: the result is short.
        vs += [vector('Padded one of 4096 bytes', [name], stack(padded_one(4096)))]
        cat(name, vs)
    # The result can be one byte longer than the longer operand: 7 and 8 bytes
    # plus 1 give 8 and 9 bytes.
    add = [vector(f'{label(n)} of ff plus a padded one', ['OP_ADD'], stack(ff(n), padded_one(n))) for n in NONZERO_SIZES]
    add += [vector(f'{of_ff(n)} plus 1', ['OP_ADD'], stack(ff(n), num(1))) for n in (0, 7, 8, 65536)]
    add += [vector('1 plus 65536 bytes of ff', ['OP_ADD'], stack(num(1), ff(65536)))]
    cat('OP_ADD', add)
    # The result can be one byte shorter: 2^64 - 1 is 9 bytes minus 1.
    sub = [vector(f'{label(n)} of ff minus a padded one', ['OP_SUB'], stack(ff(n), padded_one(n))) for n in NONZERO_SIZES]
    sub += [vector(f'2^{8 * n} minus 1', ['OP_SUB'], stack(bytes(n) + b'\x01', num(1))) for n in (1, 7, 8, 9, 65536)]
    cat('OP_SUB', sub)
    cat('OP_MUL', [vector(f'{label(a)} by {label(b)}', ['OP_MUL'], stack(ff(a), ff(b))) for a, b in
                   ((0, 0), (1, 0), (1, 1), (8, 8), (9, 9), (9, 1), (4096, 1), (1, 4096), (4096, 4096))] +
        [vector('Padded operands', ['OP_MUL'], stack(padded_one(4096), padded_one(4096)))])
    for name in ('OP_DIV', 'OP_MOD'):
        vs = [vector(f'{label(a)} by {label(b)}', [name], stack(ff(a), b'\x7f' * b)) for a, b in
              ((1, 1), (8, 1), (9, 8), (4096, 1), (1, 4096), (4096, 2048))]
        vs += [vector('4096 bytes by a 2048-byte divisor padded to 4096', [name],
                      stack(ff(4096), b'\x7f' * 2048 + bytes(2048)))]
        cat(name, vs)
    # Shifts by none, a bit, a byte, a word, and a word and a bit.
    for name in ('OP_LSHIFT', 'OP_RSHIFT'):
        vs = [vector(f'{label(n)} by {shift}', [name], stack(ff(n), num(shift))) for n in SIZES for shift in (0, 1, 8, 64, 65)]
        vs += [vector('520 bytes by 4160', [name], stack(ff(520), num(4160)))]
        cat(name, vs)

    # Lock time and sequence: the operand 1 in each size, or empty for 0.
    spent = [CTxOut(5000, CScript(b'\x51\x20' + bytes(32)))]
    for name, tx in (('OP_CHECKLOCKTIMEVERIFY', spending_tx(locktime=1, sequences=[0xfffffffe])),
                     ('OP_CHECKSEQUENCEVERIFY', spending_tx(version=2, sequences=[1]))):
        cat(name, [vector(f'1 in {label(n)}' if n else 'An empty operand', [name], stack(padded_one(n)),
                          context=context(tx, spent), _expect='valid') for n in SIZES])
    return cats


def signature_charges():
    """Signature charges without a transaction: empty signatures and unknown
    public key types never verify."""
    unknown = b'\x02' * 33
    xkey = b'\x02' * 32
    return [category('Signature charges', [
        vector('OP_CHECKSIG with an empty signature', ops(xkey, 'OP_CHECKSIG', 'OP_NOT'), stack(b''), final=True),
        vector('OP_CHECKSIG with an unknown public key type', ops(unknown, 'OP_CHECKSIG'), stack(b'\x01'), final=True),
        vector('OP_CHECKSIGVERIFY with an unknown public key type', ops(unknown, 'OP_CHECKSIGVERIFY', 'OP_1'),
               stack(b'\x01'), final=True),
        vector('OP_CHECKSIGADD with an empty signature', ops(xkey, 'OP_CHECKSIGADD', 'OP_NOT'), stack(b'', b''), final=True),
        vector('OP_CHECKSIGADD with an unknown public key type', ops(unknown, 'OP_CHECKSIGADD'), stack(b'\x01', b''),
               final=True),
        vector('Exhausted before an unknown public key type', ops(unknown, 'OP_CHECKSIG'), stack(b'\x01'), final=True,
               budget=500_000),
    ])]


# Transactions.

def v2_output(tokens, key=None):
    info = taproot_construct(key or xonly(10), [('leaf', CScript(script_bytes(tokens)), LEAF_VERSION_0XC2)])
    return info


def leaf_input(tx, i, info, items, *, annex=None, name='leaf'):
    leaf = info.leaves[name]
    tx.wit.vtxinwit[i].scriptWitness.stack = list(items) + [bytes(leaf.script), control_block_bytes(info, name)] + \
        ([annex] if annex is not None else [])


def tx_vector(comment, tx, spent, expect):
    return {'comment': comment, 'tx': tx_hex(tx), 'spent_outputs': [txout_hex(o) for o in spent], '_expect': expect}


def transactions():
    vs = []
    one = v2_output(['OP_1'])
    c0 = taproot_construct(xonly(11), [('leaf', CScript(b'\x51'), LEAF_VERSION_TAPSCRIPT)])
    drop = v2_output(['OP_DROP', 'OP_1'])

    tx = spending_tx(1)
    leaf_input(tx, 0, one, [])
    vs.append(tx_vector('One 0xc2 input: its weight funds the budget, less one SIGCHECK for its commitment check', tx, [CTxOut(10_000, one.scriptPubKey)], 'valid'))
    tx = spending_tx(1)
    leaf_input(tx, 0, one, [], annex=b'\x50' + bytes(100))
    vs.append(tx_vector('The annex counts toward the weight', tx, [CTxOut(10_000, one.scriptPubKey)], 'valid'))
    tx = spending_tx(2)
    leaf_input(tx, 0, one, [])
    leaf_input(tx, 1, c0, [])
    vs.append(tx_vector('A 0xc0 input is excluded', tx, [CTxOut(10_000, one.scriptPubKey), CTxOut(10_000, c0.scriptPubKey)], 'valid'))
    tx = spending_tx(1)
    leaf_input(tx, 0, c0, [])
    vs.append(tx_vector('Without a 0xc2 input there is no budget', tx, [CTxOut(10_000, c0.scriptPubKey)], 'valid'))
    # Key-path input.
    keypath = taproot_construct(xonly(12))
    tx = spending_tx(2)
    leaf_input(tx, 0, one, [])
    spent = [CTxOut(10_000, one.scriptPubKey), CTxOut(10_000, keypath.scriptPubKey)]
    tx.wit.vtxinwit[1].scriptWitness.stack = [b'']
    msg = TaprootSignatureHash(tx, spent, 0, 1)
    from test_framework.key import sign_schnorr
    tx.wit.vtxinwit[1].scriptWitness.stack = [sign_schnorr(tweak_add_privkey(privkey(12), keypath.tweak), msg, aux=bytes(32))]
    vs.append(tx_vector('A key-path input is excluded', tx, spent, 'valid'))
    # P2WSH input.
    wsh_script = CScript(b'\x51')
    wsh = CScript(b'\x00\x20' + sha256(bytes(wsh_script)))
    tx = spending_tx(2)
    leaf_input(tx, 0, one, [])
    tx.wit.vtxinwit[1].scriptWitness.stack = [bytes(wsh_script)]
    vs.append(tx_vector('A P2WSH input is excluded', tx, [CTxOut(10_000, one.scriptPubKey), CTxOut(10_000, wsh)], 'valid'))
    budget = [category('Transaction budget', vs)]

    # A multiplication of two 30,000-byte operands costs more than the weight
    # of its own input funds, and less than that and a 60,000-byte sibling fund.
    vs = []
    operand = b'\xff' * 30_000
    mul = v2_output(['OP_MUL', 'OP_DROP', 'OP_1'])
    pad = b'\x00' * 60_000
    tx = spending_tx(1)
    leaf_input(tx, 0, mul, [operand, operand])
    vs.append(tx_vector('An input cannot fund its multiplication alone', tx, [CTxOut(10_000, mul.scriptPubKey)], 'VAROP_COUNT'))
    tx = spending_tx(2)
    leaf_input(tx, 0, mul, [operand, operand])
    leaf_input(tx, 1, drop, [pad])
    vs.append(tx_vector('A sibling 0xc2 input funds the multiplication', tx,
                        [CTxOut(10_000, mul.scriptPubKey), CTxOut(10_000, drop.scriptPubKey)], 'valid'))
    tx = spending_tx(2)
    leaf_input(tx, 0, mul, [operand, operand])
    leaf_input(tx, 1, mul, [operand, operand])
    vs.append(tx_vector('Two multiplications share one budget', tx,
                        [CTxOut(10_000, mul.scriptPubKey), CTxOut(10_000, mul.scriptPubKey)], 'VAROP_COUNT'))
    # 0xc0 elements are limited to 520 bytes, so its weight is in its script.
    c0_heavy = taproot_construct(xonly(11), [('leaf', CScript((b'\x4d\x08\x02' + bytes(520) + b'\x75') * 116 + b'\x51'),
                                                LEAF_VERSION_TAPSCRIPT)])
    tx = spending_tx(2)
    leaf_input(tx, 0, mul, [operand, operand])
    leaf_input(tx, 1, c0_heavy, [])
    vs.append(tx_vector('A 0xc0 input does not fund the multiplication', tx,
                        [CTxOut(10_000, mul.scriptPubKey), CTxOut(10_000, c0_heavy.scriptPubKey)], 'VAROP_COUNT'))
    # Inputs of versions not yet defined fund the budget; legacy, witness v0 and
    # key-path inputs, whose signature checks other limits bound, do not.
    c4 = taproot_construct(xonly(11), [('leaf', CScript(b'\x51'), 0xc4)])
    tx = spending_tx(2)
    leaf_input(tx, 0, mul, [operand, operand])
    leaf_input(tx, 1, c4, [pad])
    vs.append(tx_vector('An unknown leaf version input funds the multiplication', tx,
                        [CTxOut(10_000, mul.scriptPubKey), CTxOut(10_000, c4.scriptPubKey)], 'valid'))
    tx = spending_tx(2)
    leaf_input(tx, 0, mul, [operand, operand])
    tx.wit.vtxinwit[1].scriptWitness.stack = [pad]
    vs.append(tx_vector('An unknown witness version input funds the multiplication', tx,
                        [CTxOut(10_000, mul.scriptPubKey), CTxOut(10_000, CScript(b'\x52\x20' + b'\x01' * 32))],
                        'valid'))
    tx = spending_tx(2)
    leaf_input(tx, 0, mul, [operand, operand])
    tx.wit.vtxinwit[1].scriptWitness.stack = [pad]
    vs.append(tx_vector('A P2A input funds the multiplication', tx,
                        [CTxOut(10_000, mul.scriptPubKey), CTxOut(10_000, CScript(b'\x51\x02\x4e\x73'))], 'valid'))
    # BIP 341 applies to native outputs only, so this one-element witness is not
    # a key-path spend.
    redeem = b'\x51\x20' + b'\x01' * 32
    tx = spending_tx(2)
    leaf_input(tx, 0, mul, [operand, operand])
    tx.vin[1].scriptSig = CScript([redeem])
    tx.wit.vtxinwit[1].scriptWitness.stack = [pad]
    vs.append(tx_vector('A P2SH-wrapped witness v1 input funds the multiplication', tx,
                        [CTxOut(10_000, mul.scriptPubKey), CTxOut(10_000, CScript(b'\xa9\x14' + hash160(redeem) + b'\x87'))],
                        'valid'))
    keypath = taproot_construct(xonly(12))
    annex = b'\x50' + pad
    tx = spending_tx(2)
    leaf_input(tx, 0, mul, [operand, operand])
    spent = [CTxOut(10_000, mul.scriptPubKey), CTxOut(10_000, keypath.scriptPubKey)]
    tx.wit.vtxinwit[1].scriptWitness.stack = [b'']
    msg = TaprootSignatureHash(tx, spent, 0, 1, annex=annex)
    tx.wit.vtxinwit[1].scriptWitness.stack = [sign_schnorr(tweak_add_privkey(privkey(12), keypath.tweak), msg,
                                                           aux=bytes(32)), annex]
    vs.append(tx_vector('A key-path input with an annex does not fund the multiplication', tx, spent, 'VAROP_COUNT'))
    # Witness v0 elements are limited to 520 bytes, so 116 of them carry the weight.
    wsh_script = CScript(b'\x6d' * 58 + b'\x51')
    redeem = b'\x00\x20' + sha256(bytes(wsh_script))
    tx = spending_tx(2)
    leaf_input(tx, 0, mul, [operand, operand])
    tx.vin[1].scriptSig = CScript([redeem])
    tx.wit.vtxinwit[1].scriptWitness.stack = [bytes(520)] * 116 + [bytes(wsh_script)]
    vs.append(tx_vector('A P2SH-wrapped witness v0 input does not fund the multiplication', tx,
                        [CTxOut(10_000, mul.scriptPubKey), CTxOut(10_000, CScript(b'\xa9\x14' + hash160(redeem) + b'\x87'))],
                        'VAROP_COUNT'))
    # A scriptSig is limited to 10,000 bytes, so a legacy input carries less
    # weight: it would fund the multiplication of two 30,000-byte operands.
    # It comes first, so that its own validity is checked.
    small = b'\xff' * 30_000
    tx = spending_tx(2)
    leaf_input(tx, 1, mul, [small, small])
    tx.vin[0].scriptSig = CScript([bytes(520)] * 18)
    vs.append(tx_vector('A legacy input does not fund the multiplication', tx,
                        [CTxOut(10_000, CScript(b'\x51')), CTxOut(10_000, mul.scriptPubKey)], 'VAROP_COUNT'))

    # 100 signature checks cost 50,000,000 varops, more than one input funds.
    checks = 100
    pub = xonly(13)
    sig_tokens = ops(pub, *(['OP_2DUP', 'OP_CHECKSIGVERIFY'] * (checks - 1)), 'OP_CHECKSIG')
    sig_v2 = v2_output(sig_tokens)
    sig_c0 = taproot_construct(xonly(10), [('leaf', CScript(script_bytes(sig_tokens)), LEAF_VERSION_TAPSCRIPT)])
    funding = v2_output(['OP_DROP', 'OP_1'], key=xonly(14))

    def signed_input(tx, spent, i, info, version):
        leaf = info.leaves['leaf']
        tx.wit.vtxinwit[i].scriptWitness.stack = [b'', bytes(leaf.script), control_block_bytes(info, 'leaf')]
        msg = TaprootSignatureHash(tx, spent, 0, i, scriptpath=True, leaf_script=leaf.script, leaf_ver=version,
                                   codeseparator_pos=0xffffffff)
        tx.wit.vtxinwit[i].scriptWitness.stack[0] = sign(13, msg)

    tx = spending_tx(1)
    spent = [CTxOut(10_000, sig_v2.scriptPubKey)]
    signed_input(tx, spent, 0, sig_v2, LEAF_VERSION_0XC2)
    vs.append(tx_vector('100 signature checks exceed their input\'s budget', tx, spent, 'VAROP_COUNT'))
    tx = spending_tx(2)
    spent = [CTxOut(10_000, sig_v2.scriptPubKey), CTxOut(10_000, funding.scriptPubKey)]
    leaf_input(tx, 1, funding, [b'\x00' * 12_000])
    signed_input(tx, spent, 0, sig_v2, LEAF_VERSION_0XC2)
    vs.append(tx_vector('A sibling 0xc2 input funds 100 signature checks', tx, spent, 'valid'))
    tx = spending_tx(2)
    spent = [CTxOut(10_000, sig_c0.scriptPubKey), CTxOut(10_000, funding.scriptPubKey)]
    leaf_input(tx, 1, funding, [b'\x00' * 12_000])
    signed_input(tx, spent, 0, sig_c0, LEAF_VERSION_TAPSCRIPT)
    vs.append(tx_vector('A 0xc2 input does not fund BIP 342 signature checks', tx, spent, 'TAPSCRIPT_VALIDATION_WEIGHT'))
    shared = [category('Shared budget', vs)]
    return budget + shared


def build():
    return {
        'bip': '440',
        'active': ['440', '441'],
        'primitives': primitives(),
        'scripts': sweep() + signature_charges(),
        'transactions': transactions(),
    }
