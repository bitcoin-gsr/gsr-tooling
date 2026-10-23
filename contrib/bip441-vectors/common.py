"""Helpers for writing bip-0441 test vector inputs.

Scripts are token lists: opcode names ("OP_ADD") and raw bytes ("0x...").
Hex strings use "XX{n}" for n bytes XX. Results are filled in by the
reference implementation (gsr test_bitcoin with BIP441_VECTORS_FILL).
"""
import hashlib
import os
import re
import sys

# A Bitcoin Core gsr checkout (build.py --core): its opcode names, its
# test_framework and its test_bitcoin.
CORE = os.environ.get('BIP441_CORE')
if not CORE:
    sys.exit('BIP441_CORE is not set: run build.py --core <Bitcoin Core gsr checkout>')
sys.dont_write_bytecode = True  # leave the checkout as it is
sys.path.insert(0, os.path.join(CORE, 'test/functional'))

from test_framework.key import compute_xonly_pubkey, sign_schnorr  # noqa: E402
from test_framework.messages import (  # noqa: E402
    COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, ser_string,
)
from test_framework.script import (  # noqa: E402
    CScript, LEAF_VERSION_TAPSCRIPT, LEAF_VERSION_0XC2, TaggedHash,
    TaprootSignatureHash, taproot_construct,
)

MAX_ELEMENT = 4_000_000
MAX_STACK_ITEMS = 32_768
NUMS_KEY = bytes.fromhex('50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0')


def _opcodes():
    """Opcode names and values as Bitcoin Core's GetOpName() spells them."""
    header = open(os.path.join(CORE, 'src/script/script.h')).read()
    values = {}
    for name, value in re.findall(r'^\s+(OP_[A-Z0-9_]+) = (0x[0-9a-f]+|OP_[A-Z0-9_]+),', header, re.M):
        values[name] = int(value, 16) if value.startswith('0x') else values[value]
    source = open(os.path.join(CORE, 'src/script/script.cpp')).read()
    names = {}
    for case, name in re.findall(r'case (OP_[A-Z0-9_]+)\s*: return "([^"]+)";', source):
        if name.startswith('OP_') and name != 'OP_INVALIDOPCODE':
            names[name] = values[case]
    names['OP_0'] = 0x00
    names['OP_1NEGATE'] = 0x4f
    for n in range(1, 17):
        names[f'OP_{n}'] = 0x50 + n
    return names


OPCODES = _opcodes()
OPNAMES = {value: name for name, value in OPCODES.items()}


def hexruns(data):
    """Hex with runs of 16 or more equal bytes written as XX{n}."""
    out, i = [], 0
    while i < len(data):
        j = i
        while j < len(data) and data[j] == data[i]:
            j += 1
        run = j - i
        out.append(f'{data[i]:02x}{{{run}}}' if run >= 16 else data[i:j].hex())
        i = j
    return ''.join(out)


def unhex(text):
    """Bytes from hex with XX{n} runs, with or without a 0x prefix."""
    text = text[2:] if text.startswith('0x') else text
    out = bytearray()
    for literal, count in re.findall(r'([0-9a-fA-F]*)(?:\{(\d+)\})?', text):
        out += bytes.fromhex(literal)
        if count:
            out += bytes([out[-1]]) * (int(count) - 1)
    return bytes(out)


def push_bytes(data):
    """Serialized push of data (OP_0 for empty)."""
    n = len(data)
    if n == 0:
        return b'\x00'
    if n < 0x4c:
        return bytes([n]) + data
    if n <= 0xff:
        return b'\x4c' + bytes([n]) + data
    if n <= 0xffff:
        return b'\x4d' + n.to_bytes(2, 'little') + data
    return b'\x4e' + n.to_bytes(4, 'little') + data


def push(data):
    """Token pushing data."""
    return 'OP_0' if not data else '0x' + hexruns(push_bytes(data))


def raw(data):
    return '0x' + hexruns(data)


def num(value):
    """BIP 441 number: unsigned little-endian, without trailing zero bytes."""
    return value.to_bytes((value.bit_length() + 7) // 8, 'little')


def ops(*items):
    """Script tokens from opcode names (with or without OP_), ints (opcode
    values) and bytes (pushes)."""
    tokens = []
    for item in items:
        if isinstance(item, (bytes, bytearray)):
            tokens.append(push(bytes(item)))
        elif isinstance(item, int):
            tokens.append(OPNAMES[item] if item in OPNAMES else raw(bytes([item])))
        elif isinstance(item, list):
            tokens.extend(item)
        else:
            name = item if item.startswith(('OP_', '0x')) else 'OP_' + item
            assert name.startswith('0x') or name in OPCODES, name
            tokens.append(name)
    return tokens


def script_bytes(tokens):
    out = bytearray()
    for token in tokens:
        out += bytes([OPCODES[token]]) if token.startswith('OP_') else unhex(token)
    return bytes(out)


def compact_size(n):
    if n < 253:
        return bytes([n])
    if n <= 0xffff:
        return b'\xfd' + n.to_bytes(2, 'little')
    if n <= 0xffffffff:
        return b'\xfe' + n.to_bytes(4, 'little')
    return b'\xff' + n.to_bytes(8, 'little')


def disassemble(data, macros=False):
    """Tokens for script bytes; with macros, OP_MACRO and OP_CALLMACRO are
    followed by their CompactSize operand. Undecodable bytes stay raw."""
    tokens, i = [], 0

    def read_compact(i):
        if i >= len(data):
            return None
        prefix = data[i]
        width = {253: 2, 254: 4, 255: 8}.get(prefix, 0)
        if i + 1 + width > len(data):
            return None
        return i + 1 + width

    while i < len(data):
        op = data[i]
        if 0 < op <= 0x4e:
            size_width = {0x4c: 1, 0x4d: 2, 0x4e: 4}.get(op, 0)
            if i + 1 + size_width > len(data):
                tokens.append(raw(data[i:]))
                break
            size = op if not size_width else int.from_bytes(data[i + 1:i + 1 + size_width], 'little')
            end = i + 1 + size_width + size
            if end > len(data):
                tokens.append(raw(data[i:]))
                break
            tokens.append(raw(data[i:end]))
            i = end
        elif macros and op in (0xd0, 0xd1):
            end = read_compact(i + 1)
            if end is None:
                tokens.append(raw(data[i:]))
                break
            tokens.append(OPNAMES[op])
            tokens.append(raw(data[i + 1:end]))
            i = end
        else:
            tokens.append(OPNAMES.get(op, raw(bytes([op]))))
            i += 1
    return tokens


def stack(*items):
    return [hexruns(item) for item in items]


def repeated(element, count):
    return {'element': hexruns(element), 'count': count}


# Keys, transactions and contexts.

def privkey(i):
    return hashlib.sha256(b'bip441 vector key ' + bytes([i])).digest()


def xonly(i):
    return compute_xonly_pubkey(privkey(i))[0]


def sign(i, msg):
    return sign_schnorr(privkey(i), msg, aux=bytes(32))


def tx_hex(tx):
    return hexruns(tx.serialize())


def txout_hex(txout):
    return hexruns(txout.serialize())


def spending_tx(n_inputs=1, *, version=2, locktime=0, sequences=None, outputs=None):
    tx = CTransaction()
    tx.version = version
    tx.nLockTime = locktime
    for i in range(n_inputs):
        prevout = COutPoint(int.from_bytes(hashlib.sha256(b'bip441 prevout ' + bytes([i])).digest(), 'little'), i)
        tx.vin.append(CTxIn(prevout, b'', sequences[i] if sequences else 0xffffffff))
    tx.vout = outputs if outputs is not None else [CTxOut(1000, CScript(b'\x51'))]
    tx.wit.vtxinwit = [CTxInWitness() for _ in range(n_inputs)]
    return tx


def control_block_bytes(info, name):
    leaf = info.leaves[name]
    return bytes([leaf.version + info.negflag]) + info.internal_pubkey + leaf.merklebranch


def context(tx, spent_outputs, index=0, *, annex=None, control_block=None):
    ctx = {'tx': tx_hex(tx), 'spent_outputs': [txout_hex(o) for o in spent_outputs], 'input_index': index}
    if annex is not None:
        ctx['annex'] = annex.hex()
    if control_block is not None:
        ctx['control_block'] = control_block.hex()
    return ctx


def default_context():
    """One input spending a 0xc2 leaf output, one output."""
    tx = spending_tx()
    return context(tx, [CTxOut(2000, CScript(b'\x51\x20' + bytes(32)))])


def leaf_sighash(tx, spent_outputs, index, tokens, *, hash_type=0, codesep_pos=-1, annex=None,
                 leaf_ver=LEAF_VERSION_0XC2):
    return TaprootSignatureHash(tx, spent_outputs, hash_type, index, scriptpath=True,
                                leaf_script=CScript(script_bytes(tokens)),
                                codeseparator_pos=codesep_pos if codesep_pos >= 0 else 0xffffffff,
                                annex=annex, leaf_ver=leaf_ver)


def vector(comment, script, stack_items=(), **fields):
    v = {'comment': comment}
    if 'context' in fields:
        v['context'] = fields.pop('context')
    v['stack'] = list(stack_items)
    v['script'] = script
    v.update(fields)
    return v


def category(name, vectors):
    return {'category': name, 'vectors': vectors}
