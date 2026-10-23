"""Extended Primitives examples: one passing spend of each construction in the
Examples section, with the leaf as the BIP prints it (TAPTWEAK and DATATWEAK
expanded, <tag:X> as its 64-byte push). Ported from gsr-projects
extended-primitives, which also has failing spends."""
import hashlib

from common import (
    LEAF_VERSION_0XC2, CScript, COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut,
    category, context, ops, script_bytes, sign, stack, taproot_construct, vector, xonly,
)
from test_framework.key import tweak_add_pubkey
from test_framework.messages import ser_compact_size

OUTPUT_SPK = bytes.fromhex('000000010002')
INTERNAL_KEY = bytes.fromhex('000020000000')
TAPTREE_ROOT = bytes.fromhex('000040000000')
CONTROL_BLOCK = bytes.fromhex('000010000000')
VERSION_LOCKTIME_OUTPUTS = bytes.fromhex('000700020003')
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
AMOUNT, FEE = 100_000, 1_000


def sha256(data):
    return hashlib.sha256(data).digest()


def tag(name):
    """<tag:X>: SHA256(X) || SHA256(X)."""
    return sha256(name.encode()) * 2


def num(n):
    return n.to_bytes((n.bit_length() + 7) // 8, 'little')


TAPTWEAK = ops('OP_OVER', 'OP_SWAP', 'OP_CAT', tag('TapTweak'), 'OP_SWAP', 'OP_CAT', 'OP_SHA256', 'OP_SWAP',
               'OP_TWEAKADD')
DATATWEAK = ops('OP_OVER', 'OP_SWAP', 'OP_CAT', 'OP_SHA256', 'OP_SWAP', 'OP_TWEAKADD')
# <51 20> OP_SWAP OP_CAT <00 00 00 01 00 02> OP_TX OP_EQUAL
PAYS = ops(b'\x51\x20', 'OP_SWAP', 'OP_CAT', OUTPUT_SPK, 'OP_TX', 'OP_EQUAL')


def taproot(internal_key, leaves):
    """A Taproot output whose (name, tokens) leaves are all Tapleaf 0xc2; nested
    lists set the tree shape."""
    def c2(item):
        if isinstance(item, list):
            return [c2(i) for i in item]
        return (item[0], CScript(script_bytes(item[1])), LEAF_VERSION_0XC2)
    return taproot_construct(internal_key, c2(leaves))


def control_block(info, name):
    leaf = info.leaves[name]
    return bytes([leaf.version + info.negflag]) + info.internal_pubkey + leaf.merklebranch


def spend(comment, info, name, tokens, items, outputs, *, locktime=0, sign_input=None):
    """A one-input transaction spending leaf `name` of `info` with witness items,
    as a scripts vector of that leaf. sign_input(tx, spent) returns items to
    prepend, for signatures over the transaction."""
    tx = CTransaction()
    tx.version = 2
    tx.nLockTime = locktime
    tx.vin = [CTxIn(COutPoint(int.from_bytes(sha256(b'bip441 example ' + comment.encode()), 'little'), 0),
                    nSequence=0xffffffff)]
    tx.vout = [CTxOut(amount, spk) for amount, spk in outputs]
    tx.wit.vtxinwit = [CTxInWitness()]
    spent = [CTxOut(AMOUNT, info.scriptPubKey)]
    if sign_input:
        items = sign_input(tx, spent) + items
    cb = control_block(info, name)
    tx.wit.vtxinwit[0].scriptWitness.stack = list(items) + [bytes(info.leaves[name].script), cb]
    return vector(comment, tokens, stack(*items), context=context(tx, spent, 0, control_block=cb),
                  final=True, _expect='valid')


def destination():
    return taproot(xonly(40), [('owner', ops(xonly(41), 'OP_CHECKSIG'))]).scriptPubKey


def state_carrying_output():
    n = xonly(44)
    update = ops('OP_1ADD')
    leaf = ops('OP_DUP', n, 'OP_SWAP', DATATWEAK,
               INTERNAL_KEY, 'OP_TX', 'OP_EQUALVERIFY',
               update,
               n, 'OP_SWAP', DATATWEAK,
               TAPTREE_ROOT, 'OP_TX', TAPTWEAK,
               PAYS)

    def carrying(d):
        return taproot(tweak_add_pubkey(n, sha256(n + num(d)))[0], [('update', leaf)])
    return spend('Updates 5 to 6, with OP_1ADD as UPDATE', carrying(5), 'update', leaf, [num(5)],
                 [(AMOUNT - FEE, carrying(6).scriptPubKey)])


def replacing_the_current_leaf():
    owner = xonly(45)
    p = xonly(46)
    template = script_bytes(ops('OP_DROP', owner, 'OP_CHECKSIG'))

    def new_leaf(d):
        return ops(d, 'OP_DROP', owner, 'OP_CHECKSIG')
    # BUILD [d'] -> [S']: checks that d' is 32 bytes and completes the template.
    build = ops('OP_SIZE', b'\x20', 'OP_EQUALVERIFY', b'\x20', 'OP_SWAP', 'OP_CAT', template, 'OP_CAT')
    leaf = ops(build,
               'OP_SIZE', 'OP_SWAP', 'OP_CAT',
               b'\xc2', 'OP_SWAP', 'OP_CAT',
               tag('TapLeaf'), 'OP_SWAP', 'OP_CAT', 'OP_SHA256',
               CONTROL_BLOCK, 'OP_TX', b'\x21', b'\x20', 'OP_SUBSTR',
               'OP_2DUP', 'OP_BYTEREV', 'OP_SWAP', 'OP_BYTEREV',
               'OP_LESSTHAN', 'OP_IF', 'OP_SWAP', 'OP_ENDIF', 'OP_CAT',
               tag('TapBranch'), 'OP_SWAP', 'OP_CAT', 'OP_SHA256',
               INTERNAL_KEY, 'OP_TX', 'OP_SWAP', TAPTWEAK,
               PAYS)
    sibling = ('sibling', ops(xonly(47), 'OP_CHECKSIG'))
    contract = taproot(p, [('replace', leaf), sibling])
    sibling_hash = contract.leaves['sibling'].leaf_hash
    d = next(d for d in (sha256(b'd %d' % i) for i in range(10))
             if taproot(p, [('new', new_leaf(d))]).merkle_root < sibling_hash)
    replaced = taproot(p, [('new', new_leaf(d)), sibling])
    return spend("Replaces the leaf; new leaf sorts before the sibling, with BUILD making "
                 "<d'> OP_DROP <owner> OP_CHECKSIG from a 32-byte d'", contract, 'replace', leaf, [d],
                 [(AMOUNT - FEE, replaced.scriptPubKey)])


def rebindable_signature():
    prefix = b'example/rebind'
    leaf = ops(VERSION_LOCKTIME_OUTPUTS, 'OP_TX', prefix, 'OP_SWAP', 'OP_CAT', xonly(48), 'OP_CHECKSIGFROMSTACK')
    contract = taproot(xonly(49), [('rebind', leaf)])

    def signature(tx, spent):
        fields = tx.version.to_bytes(4, 'little') + tx.nLockTime.to_bytes(4, 'little')
        for out in tx.vout:
            fields += out.nValue.to_bytes(8, 'little') + ser_compact_size(len(out.scriptPubKey)) + out.scriptPubKey
        return [sign(48, prefix + fields)]
    return spend('Spends A', contract, 'rebind', leaf, [], [(AMOUNT - FEE, destination())], locktime=500_000_001,
                 sign_input=signature)


def converting_between_encodings():
    p = xonly(52)
    to_tweak = ops(num(ORDER), 'OP_MOD', bytes(32), 'OP_CAT', b'\x20', 'OP_LEFT', 'OP_BYTEREV')
    leaf = ops('OP_SHA256', 'OP_BYTEREV', to_tweak, p, 'OP_TWEAKADD', PAYS)
    contract = taproot(xonly(53), [('convert', leaf)])
    x = next(c for c in (b'x %d' % i for i in range(1000)) if sha256(c)[0] != 0)
    tweak = (int.from_bytes(sha256(x), 'big') % ORDER).to_bytes(32, 'big')
    output = b'\x51\x20' + tweak_add_pubkey(p, tweak)[0]
    return spend('Pays to P tweaked by SHA256(x), in a leaf that converts the hash with both fragments', contract,
                 'convert', leaf, [x], [(AMOUNT - FEE, output)])


def build():
    return {
        'bip': 'extended_primitives',
        'active': ['440', '441', 'op_tx', 'extended_primitives'],
        'scripts': [
            category('State-Carrying Output', [state_carrying_output()]),
            category('Replacing the Current Leaf', [replacing_the_current_leaf()]),
            category('Rebindable Signature', [rebindable_signature()]),
            category('Converting Between Encodings', [converting_between_encodings()]),
        ],
    }
