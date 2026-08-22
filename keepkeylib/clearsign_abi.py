"""
Minimal, deterministic Solidity ABI encoder for STATIC types only.

Used to build REAL calldata for the clear-sign flow catalog from a function
signature + argument values, instead of hand-typing hex (which is how bugs
get shipped in a signing test suite). Selectors are always derived from
keccak256(signature) here — never trusted from an external source — so a
wrong/hallucinated selector fails loudly instead of silently producing a
plausible-looking but wrong test vector.

Deliberately does NOT support dynamic types (string, bytes, T[], tuples with
dynamic members) — those need offset/length ABI encoding that's easy to get
subtly wrong by hand. Calls with dynamic types are hand-built at the call
site (see clearsign_catalog.py's multicall/handleOps entries) using the
primitives here (_word/_addr_word) plus an explicit comment that the layout
is a representative simplification, not a literal captured mainnet tx.
"""

from .signed_metadata import keccak256


def parse_signature(signature):
    """'supply(address,uint256,address,uint16)' -> ('supply', ['address', 'uint256', 'address', 'uint16'])"""
    name, rest = signature.split('(', 1)
    rest = rest.rsplit(')', 1)[0]
    types = [t.strip() for t in rest.split(',')] if rest.strip() else []
    return name, types


def selector(signature):
    """4-byte function selector, always computed — never trusted as input."""
    return keccak256(signature.encode('ascii'))[:4]


def _word(value):
    if isinstance(value, str) and value.startswith('0x'):
        value = int(value, 16)
    return int(value).to_bytes(32, 'big')


def _addr_word(address):
    if isinstance(address, str):
        address = bytes.fromhex(address[2:] if address.startswith('0x') else address)
    assert len(address) == 20, 'address must be 20 bytes, got %d' % len(address)
    return b'\x00' * 12 + address


def encode_static_args(types, values):
    """ABI-encode STATIC Solidity types into concatenated 32-byte words.
    Raises on any dynamic type (string/bytes/arrays) — build those by hand."""
    assert len(types) == len(values), (
        'arg count mismatch: %d types, %d values' % (len(types), len(values)))
    out = bytearray()
    for typ, val in zip(types, values):
        if typ == 'address':
            out += _addr_word(val)
        elif typ.startswith('uint') or typ.startswith('int'):
            digits = typ[4:] if typ.startswith('uint') else typ[3:]
            bits = int(digits) if digits else 256
            n = int(val)
            assert 0 <= n < (1 << bits), 'value %r out of range for %s' % (val, typ)
            out += n.to_bytes(32, 'big')
        elif typ == 'bool':
            out += (1 if val else 0).to_bytes(32, 'big')
        elif typ.startswith('bytes') and typ != 'bytes' and not typ.endswith('[]'):
            n = int(typ[5:])
            b = val if isinstance(val, (bytes, bytearray)) else bytes.fromhex(
                val[2:] if val.startswith('0x') else val)
            assert len(b) == n, 'bytes%d value has wrong length' % n
            out += b.ljust(32, b'\x00')  # bytesN is left-aligned per ABI spec
        else:
            raise ValueError(
                'dynamic/unsupported type %r — build this call by hand '
                '(see module docstring)' % typ)
    return bytes(out)


def build_calldata(signature, values):
    """selector(signature) + ABI-encoded static args, in one call."""
    _, types = parse_signature(signature)
    return selector(signature) + encode_static_args(types, values)
