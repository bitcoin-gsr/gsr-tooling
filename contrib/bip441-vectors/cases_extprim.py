"""Extended Primitives vectors: OP_CHECKSIGFROMSTACK (BIP 348), OP_TWEAKADD
(BIP 449) and OP_BYTEREV."""
import csv
import json
import os

from common import MAX_ELEMENT, category, sign, stack, vector, xonly

# The bips repository (build.py --bips).
BIPS = os.environ.get('BIP441_BIPS', '')
BIP340_VECTORS = os.path.join(BIPS, 'bip-0340/test-vectors.csv')
BIP341_VECTORS = os.path.join(BIPS, 'bip-0341/wallet-test-vectors.json')


def checksigfromstack():
    key = xonly(20)
    msg = b'\x01' + bytes(31)
    sig = sign(20, msg)
    wrong = b'\x00' + msg[1:]
    unknown = b'\x02' * 33
    long_msg = b'\x42' * 4096
    # After the tag midstate the challenge hashes R || P || msg: a 55-byte message
    # is the longest that fits two SHA256 blocks, a 56-byte one needs three.
    msg55, msg56 = b'\x55' * 55, b'\x56' * 56
    csfs = ['OP_CHECKSIGFROMSTACK']
    vs = [
        vector('A valid signature', csfs, stack(sig, msg, key)),
        vector('A signature for another message', csfs, stack(sig, wrong, key)),
        vector('A 63-byte signature', csfs, stack(sig[:63], msg, key)),
        vector('A 65-byte signature', csfs, stack(sig + b'\x00', msg, key)),
        vector('An empty signature', csfs, stack(b'', msg, key)),
        vector('An empty public key', csfs, stack(b'', msg, b'')),
        vector('An empty public key with a signature', csfs, stack(sig, msg, b'')),
        vector('A missing operand', csfs, stack(sig, msg)),
        vector('An unknown public key type', csfs, stack(sig, msg, unknown)),
        vector('A 4096-byte message with an empty signature', csfs, stack(b'', long_msg, key)),
        vector('A valid signature of a 55-byte message', csfs, stack(sign(20, msg55), msg55, key)),
        vector('A valid signature of a 56-byte message', csfs, stack(sign(20, msg56), msg56, key)),
        vector('A 4000000-byte message with an unknown public key type', csfs, stack(sig, b'\x42' * MAX_ELEMENT, unknown)),
    ]
    bip340 = []
    with open(BIP340_VECTORS) as f:
        for row in csv.DictReader(f):
            comment = f"BIP 340 vector {row['index']}" + (f": {row['comment']}" if row['comment'] else '')
            bip340.append(vector(comment, csfs, stack(bytes.fromhex(row['signature']), bytes.fromhex(row['message']),
                                                      bytes.fromhex(row['public key']))))
    return [category('OP_CHECKSIGFROMSTACK', vs), category('OP_CHECKSIGFROMSTACK with the BIP 340 vectors', bip340)]


def tweakadd():
    tweak = ['OP_TWEAKADD']
    vectors = [
        ('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', '00' * 32),
        ('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', '00' * 31 + '01'),
        ('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', '00' * 31 + '02'),
        ('c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5', '00' * 31 + '03'),
        ('5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc', '00' * 31 + '09'),
        ('d415b187c6e7ce9da46ac888d20df20737d6f16a41639e68ea055311e1535dd9', '00' * 31 + '01'),
    ]
    vs = [vector(f'BIP 449 vector {i}', tweak, stack(bytes.fromhex(t), bytes.fromhex(p))) for i, (p, t) in enumerate(vectors)]
    g = bytes.fromhex(vectors[0][0])
    one = bytes.fromhex('00' * 31 + '01')
    order = bytes.fromhex('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141')
    order_minus_one = bytes.fromhex('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140')
    vs += [
        vector('A missing operand', tweak, stack(one)),
        vector('A 31-byte tweak', tweak, stack(bytes(31), g)),
        vector('A 31-byte public key', tweak, stack(bytes(32), bytes(31))),
        vector('A tweak equal to the curve order', tweak, stack(order, g)),
        vector('A public key not on the curve', tweak, stack(one, bytes(32))),
        vector('A result at infinity', tweak, stack(order_minus_one, g)),
    ]
    # A BIP 341 output key: the internal key tweaked by the TapTweak hash. The
    # others are the same operation.
    bip341 = []
    with open(BIP341_VECTORS) as f:
        for i, v in enumerate(json.load(f)['scriptPubKey'][:1]):
            bip341.append(vector(f'BIP 341 output key {i}', tweak, stack(bytes.fromhex(v['intermediary']['tweak']),
                                                                       bytes.fromhex(v['given']['internalPubkey']))))
            bip341[-1]['_expect_top'] = v['intermediary']['tweakedPubkey']
    return [category('OP_TWEAKADD', vs), category('OP_TWEAKADD with a BIP 341 output key', bip341)]


def byterev():
    value = bytes([0x00, 0x01, 0x02, 0x80, 0xff, 0x00, 0x42, 0x7f, 0x03])
    rev = ['OP_BYTEREV']
    vs = [
        vector('Nine bytes', rev, stack(value)),
        vector('An empty value', rev, stack(b'')),
        vector('One byte', rev, stack(b'\x42')),
        vector('An empty stack', rev, []),
    ]
    # Whole words and vectors of 8, 16 and 32 bytes, one byte more, and a tail.
    for n in (8, 16, 17, 32, 33, 200, MAX_ELEMENT):
        vs.append(vector(f'{n} bytes', rev, stack(bytes((i * 131 + 7) % 256 for i in range(min(n, 1024))) +
                                                   b'\x5a' * max(0, n - 1024))))
    order = ['OP_SWAP', 'OP_BYTEREV', 'OP_SWAP', 'OP_BYTEREV', 'OP_LESSTHAN']
    lower, higher = b'\x01' + bytes(31), b'\x02' + bytes(31)
    vs += [
        vector('Reversed hashes compare in TapBranch order', order, stack(lower, higher)),
    ]
    return [category('OP_BYTEREV', vs)]


def build():
    return {
        'bip': 'extended_primitives',
        'active': ['440', '441', 'extended_primitives'],
        'scripts': checksigfromstack() + tweakadd() + byterev(),
    }
