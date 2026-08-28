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


def _int_bits(digits, typ):
    """Validate and return the bit width of a Solidity intN/uintN type.

    Solidity defines uint8..uint256 and int8..int256 in steps of 8, plus the
    bare `uint`/`int` aliases for 256. Nothing else exists. Accepting `uint7`,
    `uint0` or `int264` here does not produce unusual calldata -- it produces
    32-byte words for a type no compiler will ever emit, so the fixture reads
    as a real ABI encoding while encoding a fiction. Fail loudly instead.
    """
    if digits == '':
        return 256
    if not digits.isdigit():
        raise ValueError(
            'unsupported type %r -- expected %s8..%s256 in steps of 8'
            % (typ, typ[:-len(digits)], typ[:-len(digits)]))
    bits = int(digits)
    if bits < 8 or bits > 256 or bits % 8 != 0:
        raise ValueError(
            'invalid Solidity integer width in %r -- must be 8..256 '
            'in steps of 8' % typ)
    return bits


def encode_static_args(types, values):
    """ABI-encode STATIC Solidity types into concatenated 32-byte words.
    Raises on any dynamic type (string/bytes/arrays) — build those by hand."""
    assert len(types) == len(values), (
        'arg count mismatch: %d types, %d values' % (len(types), len(values)))
    out = bytearray()
    for typ, val in zip(types, values):
        # Route arrays to the explicit dynamic-type error below rather than
        # letting 'uint256[]' reach the width parser as digits '256[]'.
        if typ.endswith(']'):
            raise ValueError(
                'dynamic/unsupported type %r — build this call by hand '
                '(see module docstring)' % typ)
        if typ == 'address':
            out += _addr_word(val)
        elif typ.startswith('uint'):
            bits = _int_bits(typ[4:], typ)
            n = int(val)
            assert 0 <= n < (1 << bits), (
                'value %r out of range for %s' % (val, typ))
            out += n.to_bytes(32, 'big')
        elif typ.startswith('int'):
            # Signed types are NOT unsigned ones with a wider range. intN holds
            # [-2^(N-1), 2^(N-1)-1] and is encoded two's-complement, sign-
            # extended to the full word. Treating it as unsigned both rejected
            # every negative value and silently accepted values at or above
            # 2^(N-1), which the EVM reads back as NEGATIVE -- calldata that
            # does not mean what the declared type says.
            bits = _int_bits(typ[3:], typ)
            n = int(val)
            lo, hi = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
            assert lo <= n <= hi, (
                'value %r out of range for %s (%d..%d)' % (val, typ, lo, hi))
            out += n.to_bytes(32, 'big', signed=True)
        elif typ == 'bool':
            # Require an actual bool. Coercing truthiness here silently turns
            # 'false', 0.0 or 2 into ABI true/false, and a fixture that says
            # bool should not be the place a type confusion is laundered.
            if not isinstance(val, bool):
                raise ValueError(
                    'bool argument must be a real bool, got %r (%s)'
                    % (val, type(val).__name__))
            out += (1 if val else 0).to_bytes(32, 'big')
        elif typ.startswith('bytes') and typ != 'bytes' and not typ.endswith('[]'):
            digits = typ[5:]
            # bytes1..bytes32 only. bytes0 is not a Solidity type, and bytes33
            # is worse than invalid: ljust() does not truncate, so a 33-byte
            # value emitted a 33-byte "word" and shifted every following
            # argument by one byte -- silently corrupt calldata.
            if not digits.isdigit() or not 1 <= int(digits) <= 32:
                raise ValueError(
                    'invalid fixed-bytes type %r -- must be bytes1..bytes32'
                    % typ)
            n = int(digits)
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
