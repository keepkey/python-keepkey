"""Host half of the device-driven structured EIP-712 walk.

The DEVICE leads. It asks for one struct definition, or one leaf value, at a
time, and hashes each value in the same pass that displays it. This module
answers whatever it asks until a signature comes back.

The host never chooses the order, and that is the property rather than an
accident of the API: a host that answered a different question than the one
asked would produce a digest that does not verify.

Mirrors packages/hdwallet-keepkey/src/eip712Streaming.ts. The two are
deliberately parallel so a divergence shows up as a test failure in one of
them rather than as a bad signature in the field.
"""

import re

from . import messages_ethereum_pb2 as eth_proto

DataType = eth_proto.EthereumTypedDataStructAck

UINT = DataType.UINT
INT = DataType.INT
BYTES = DataType.BYTES
STRING = DataType.STRING
BOOL = DataType.BOOL
ADDRESS = DataType.ADDRESS
STRUCT = DataType.STRUCT

# EthereumTypedDataValueAck.value max_size in messages-ethereum.options, and
# EIP712_MAX_LEAF on the device: one ValueAck, and one chunk of a longer value.
MAX_LEAF_BYTES = 1024
# EIP712_MAX_VALUE: the longest `bytes` or `string` value the device takes in
# chunks.
MAX_VALUE_BYTES = 1024 * 1024
# The Features capability (as common.capability_names() spells it) of
# firmware that takes chunked values.
CHUNKED_VALUES = 'eip712-chunked-values'
MAX_IDENTIFIER_BYTES = 31
# Struct type names (EIP712_MAX_STRUCT_NAME - 1 on the device) may also use
# ':' after the first character, as Hyperliquid's
# "HyperliquidTransaction:ApproveBuilderFee" does.
MAX_TYPE_NAME_BYTES = 47

_ARRAY_GROUP = re.compile(r'\[([0-9]*)\]')
_CANONICAL_DIGITS = re.compile(r'^[1-9][0-9]*$')
_IDENTIFIER = re.compile(r'^[A-Za-z_$][A-Za-z0-9_$]*$')
_TYPE_NAME = re.compile(r'^[A-Za-z_$][A-Za-z0-9_$:]*$')


class Eip712Error(Exception):
    pass


def _dimension(levels, used):
    """The declared size of the array level being entered.

    Solidity nests right-to-left: in `T[k][j]` the OUTER array has j elements,
    so `int16[2][][4]` parses to [2, 0, 4] but the first list a walker meets
    holds 4. Levels are therefore consumed from the END. With a single
    dimension both ends coincide, which is why this went unnoticed.
    """
    return levels[len(levels) - 1 - used]


def parse_solidity_type(type_str):
    """"uint256", "bytes32", "Person[3]", "int16[2][][4]" -> field descriptor.

    Raises rather than guessing. An unparseable type must never become a
    signature.
    """
    bracket = type_str.find('[')
    base = type_str if bracket == -1 else type_str[:bracket]
    suffix = '' if bracket == -1 else type_str[bracket:]

    levels = []
    if suffix:
        consumed = 0
        for m in _ARRAY_GROUP.finditer(suffix):
            if m.start() != consumed:
                raise Eip712Error('Malformed array type: %s' % type_str)
            digits = m.group(1)
            if digits == '':
                levels.append(0)  # dynamic
            else:
                # 0 is the wire's DYNAMIC sentinel, so a fixed dimension of 0
                # has no spelling and "[0]" would be hashed as "[]" -- a
                # different type string. Leading zeros re-spell the same way.
                if not _CANONICAL_DIGITS.match(digits):
                    raise Eip712Error('Malformed array dimension: %s' % type_str)
                levels.append(int(digits))
            consumed = m.end()
        if consumed != len(suffix):
            raise Eip712Error('Malformed array type: %s' % type_str)

    if base == 'string':
        return {'data_type': STRING, 'array_levels': levels}
    if base == 'bool':
        return {'data_type': BOOL, 'array_levels': levels}
    if base == 'address':
        return {'data_type': ADDRESS, 'array_levels': levels}
    if base == 'bytes':
        return {'data_type': BYTES, 'array_levels': levels}

    m = re.match(r'^bytes([0-9]*)$', base)
    if m:
        if not _CANONICAL_DIGITS.match(m.group(1)):
            raise Eip712Error('Non-canonical bytes width: %s' % base)
        n = int(m.group(1))
        if n < 1 or n > 32:
            raise Eip712Error('Invalid fixed bytes width: %s' % base)
        return {'data_type': BYTES, 'size': n, 'array_levels': levels}

    # Anchored to digits, so a struct named "interest" is not caught here.
    m = re.match(r'^(u?)int([0-9]*)$', base)
    if m:
        if m.group(2) == '':
            raise Eip712Error('Integer type must state its width: %s' % base)
        if not _CANONICAL_DIGITS.match(m.group(2)):
            raise Eip712Error('Non-canonical integer width: %s' % base)
        bits = int(m.group(2))
        if bits < 8 or bits > 256 or bits % 8:
            raise Eip712Error('Invalid integer width: %s' % base)
        return {
            'data_type': UINT if m.group(1) == 'u' else INT,
            'size': bits // 8,
            'array_levels': levels,
        }

    if not _TYPE_NAME.match(base) or len(base) > MAX_TYPE_NAME_BYTES:
        raise Eip712Error('Unparseable EIP-712 type: %s' % type_str)
    return {'data_type': STRUCT, 'struct_name': base, 'array_levels': levels}


def _to_int(value, what):
    if isinstance(value, bool):
        raise Eip712Error('%s is a bool, not an integer' % what)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        s = value.strip()
        if re.match(r'^-?[0-9]+$', s):
            return int(s, 10)
        if re.match(r'^0x[0-9a-fA-F]+$', s):
            return int(s, 16)
    raise Eip712Error('%s is not an integer: %r' % (what, value))


def _hex_bytes(value, what):
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if not isinstance(value, str):
        raise Eip712Error('%s must be hex or bytes' % what)
    h = value[2:] if value[:2] in ('0x', '0X') else value
    if len(h) % 2 or (h and not re.match(r'^[0-9a-fA-F]+$', h)):
        raise Eip712Error('%s is not valid hex: %s' % (what, value))
    return bytes(bytearray.fromhex(h))


def encode_value(field, value, max_bytes=MAX_LEAF_BYTES):
    """One leaf, as the exact bytes the device will hash and display.

    Raw big-endian at the declared width, never a decimal string: the device
    does no number parsing at all, which is what removes the old path's
    2**63-1 ceiling and any chance of the two sides disagreeing about what a
    decimal meant. A dynamic value may be up to `max_bytes` long; past
    MAX_LEAF_BYTES only value_ack() can put it on the wire.
    """
    dt = field['data_type']

    if dt in (UINT, INT):
        width = field.get('size')
        if width is None:
            raise Eip712Error('Integer field has no width')
        n = _to_int(value, 'Integer field')
        bits = width * 8
        if dt == INT:
            lo, hi = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
            if n < lo or n > hi:
                raise Eip712Error('Value out of range for int%d' % bits)
            if n < 0:
                n += 1 << bits
        else:
            if n < 0:
                raise Eip712Error('Negative value for uint%d' % bits)
            if n >= 1 << bits:
                raise Eip712Error('Value out of range for uint%d' % bits)
        out = bytearray(width)
        for i in range(width - 1, -1, -1):
            out[i] = n & 0xFF
            n >>= 8
        return bytes(out)

    if dt == BOOL:
        if not isinstance(value, bool):
            raise Eip712Error('Not a boolean: %r' % (value,))
        return b'\x01' if value else b'\x00'

    if dt == ADDRESS:
        b = _hex_bytes(value, 'Address')
        if len(b) != 20:
            raise Eip712Error('Address must be 20 bytes, got %d' % len(b))
        return b

    if dt == BYTES:
        b = _hex_bytes(value, 'bytes')
        size = field.get('size')
        if size is not None:
            if len(b) != size:
                raise Eip712Error('bytes%d must be %d bytes, got %d' % (size, size, len(b)))
            return b
        if len(b) > max_bytes:
            raise Eip712Error('bytes value is %d bytes, over the %d-byte limit'
                              % (len(b), max_bytes))
        return b

    if dt == STRING:
        if not isinstance(value, str):
            raise Eip712Error('string field must be a string')
        b = value.encode('utf-8')
        if len(b) > max_bytes:
            raise Eip712Error('string value is %d bytes, over the %d-byte limit'
                              % (len(b), max_bytes))
        return b

    raise Eip712Error('Cannot encode data type %r as a leaf' % (dt,))


def encode_array_length(n):
    """Big-endian uint16, the wire form of an array length."""
    if n < 0 or n > 0xFFFF:
        raise Eip712Error('Array length out of range: %d' % n)
    return bytes(bytearray([(n >> 8) & 0xFF, n & 0xFF]))


def struct_members(typed_data, name):
    """Member list for one struct, in DECLARATION order.

    Order is part of the signature: it sets both encodeType and the order
    encodeData concatenates members.
    """
    if not isinstance(name, str) or not _TYPE_NAME.match(name) or len(name) > MAX_TYPE_NAME_BYTES:
        raise Eip712Error('Struct name is not a canonical EIP-712 identifier')
    members = typed_data['types'].get(name)
    if members is None:
        raise Eip712Error('Unknown struct: %s' % name)
    result = []
    seen = set()
    for member in members:
        member_name = member.get('name')
        if (not isinstance(member_name, str) or not _IDENTIFIER.match(member_name)
                or len(member_name) > MAX_IDENTIFIER_BYTES):
            raise Eip712Error('Member name in %s is not a canonical EIP-712 identifier' % name)
        if member_name in seen:
            raise Eip712Error('Duplicate EIP-712 member %s.%s' % (name, member_name))
        seen.add(member_name)
        result.append({'name': member_name, 'type': parse_solidity_type(member['type'])})
    return result


def resolve_member_path(typed_data, path):
    """Resolve a device-supplied member_path against the document.

    path[0] is 0 for the domain and 1 for the message. A path stopping on an
    ARRAY is the device asking for its length; a path stopping on a STRUCT is a
    protocol error, because the device walks into structs.
    """
    if not path:
        raise Eip712Error('Empty member_path')
    root = path[0]
    if root not in (0, 1):
        raise Eip712Error('Unknown member_path root: %d' % root)

    field = {'data_type': STRUCT,
             'struct_name': 'EIP712Domain' if root == 0 else typed_data['primaryType'],
             'array_levels': []}
    value = typed_data['domain'] if root == 0 else typed_data.get('message', {})
    levels_used = 0

    for i in range(1, len(path)):
        index = path[i]
        if levels_used < len(field['array_levels']):
            declared = _dimension(field['array_levels'], levels_used)
            if not isinstance(value, list):
                raise Eip712Error('Expected an array at %r' % (path[:i],))
            if declared and len(value) != declared:
                raise Eip712Error('Fixed array declares %d elements, document has %d'
                                  % (declared, len(value)))
            if index >= len(value):
                raise Eip712Error('Array index %d out of range' % index)
            value = value[index]
            levels_used += 1
            continue

        if field['data_type'] != STRUCT:
            raise Eip712Error('Cannot descend into a leaf at %r' % (path[:i],))
        members = typed_data['types'].get(field['struct_name'])
        if members is None:
            raise Eip712Error('Unknown struct: %s' % field['struct_name'])
        if index >= len(members):
            raise Eip712Error('Member index %d out of range for %s'
                              % (index, field['struct_name']))
        member = members[index]
        field = parse_solidity_type(member['type'])
        levels_used = 0
        value = value[member['name']]

    if levels_used < len(field['array_levels']):
        declared = _dimension(field['array_levels'], levels_used)
        if not isinstance(value, list):
            raise Eip712Error('Expected an array for a length request')
        if declared and len(value) != declared:
            raise Eip712Error('Fixed array declares %d elements, document has %d'
                              % (declared, len(value)))
        return ('length', len(value))
    if field['data_type'] == STRUCT:
        raise Eip712Error('Device asked for a struct as a value')
    return ('value', field, value)


def build_struct_ack(members):
    """Members, in the shape EthereumTypedDataStructAck wants."""
    ack = eth_proto.EthereumTypedDataStructAck()
    for m in members:
        entry = ack.members.add()
        entry.name = m['name']
        entry.type.data_type = m['type']['data_type']
        if 'size' in m['type']:
            entry.type.size = m['type']['size']
        if 'struct_name' in m['type']:
            entry.type.struct_name = m['type']['struct_name']
        for lvl in m['type']['array_levels']:
            entry.type.array_levels.append(lvl)
    return ack


def value_ack(typed_data, request, chunked=False):
    """The EthereumTypedDataValueAck that answers a device ValueRequest.

    A value of up to MAX_LEAF_BYTES goes whole. A longer `bytes` or `string`
    goes in MAX_LEAF_BYTES chunks: the first carries value_total_length, and
    each later request names a value_offset that its answer echoes. The
    device may read a string twice from offset 0 (it counts and checks it
    before showing it), so every chunk is served by its offset alone.

    `chunked` must be True only when the firmware reports CHUNKED_VALUES.
    Older firmware skips the chunk fields and would hash the first chunk
    alone, so without the capability a long value is refused here.
    """
    resolved = resolve_member_path(typed_data, list(request.member_path))
    ack = eth_proto.EthereumTypedDataValueAck()
    if resolved[0] == 'length':
        if request.HasField('value_offset'):
            raise Eip712Error('Device asked for an array length in chunks')
        ack.value = encode_array_length(resolved[1])
        return ack
    value = encode_value(resolved[1], resolved[2], MAX_VALUE_BYTES)
    if len(value) > MAX_LEAF_BYTES and request.member_path[0] == 0:
        raise Eip712Error('A domain value of %d bytes cannot be signed; the '
                          'device takes at most %d' % (len(value), MAX_LEAF_BYTES))
    if request.HasField('value_offset'):
        offset = request.value_offset
        if len(value) <= MAX_LEAF_BYTES or offset >= len(value):
            raise Eip712Error('Device asked for offset %d of a %d-byte value'
                              % (offset, len(value)))
        ack.value = value[offset:offset + MAX_LEAF_BYTES]
        ack.value_offset = offset
        return ack
    if len(value) <= MAX_LEAF_BYTES:
        ack.value = value
        return ack
    if not chunked:
        raise Eip712Error('A %d-byte value needs firmware that takes chunked '
                          'values (%s); this one takes at most %d bytes'
                          % (len(value), CHUNKED_VALUES, MAX_LEAF_BYTES))
    ack.value = value[:MAX_LEAF_BYTES]
    ack.value_total_length = len(value)
    return ack
