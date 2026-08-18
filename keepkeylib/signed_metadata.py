"""
Canonical binary serializer for KeepKey EVM signed metadata.

Produces the exact binary format that firmware's parse_metadata_binary() expects.
Used for generating test vectors and by the Pioneer signing service.

Binary format:
  version(1) + chain_id(4 BE) + contract_address(20) + selector(4) +
  tx_hash(32) + method_name_len(2 BE) + method_name(var) + num_args(1) +
  [per arg: name_len(1) + name(var) + format(1) + value_len(2 BE) + value(var)] +
  classification(1) + timestamp(4 BE) + key_id(1) + signature(64) + recovery(1)
"""

import struct
import hashlib
import time

# Keep in sync with firmware signed_metadata.h
ARG_FORMAT_RAW = 0
ARG_FORMAT_ADDRESS = 1
ARG_FORMAT_AMOUNT = 2
ARG_FORMAT_BYTES = 3

CLASSIFICATION_OPAQUE = 0
CLASSIFICATION_VERIFIED = 1
CLASSIFICATION_MALFORMED = 2

# ── Test key derivation (BIP-39 + SignIdentity path) ──────────────────
# Uses KeepKey's standard SignIdentity operation for key derivation.
# Any KeepKey loaded with the same mnemonic derives the same key.
#
# Identity fields (what SignIdentity receives):
#   proto: "ssh"          — selects raw SHA256 signing (no prefix wrapping)
#   host:  "keepkey.com"  — the domain
#   path:  "/insight"     — the purpose
#   index: 0-3            — key slot
#
# The proto="ssh" is an internal detail that selects the firmware's
# sshMessageSign() code path (SHA256 + secp256k1, no prefix).
# Users interact with host + path only.

# Test mnemonic — loaded from INSIGHT_MNEMONIC env var, or falls back to
# the standard BIP-39 test vector. CI uses the test vector; production
# signing uses the env var which is never committed to source.
import os as _os
TEST_MNEMONIC = _os.environ.get('INSIGHT_MNEMONIC',
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about')

# Identity fields — must match pioneer-insight keygen exactly
INSIGHT_IDENTITY = {
    'proto': 'ssh',
    'host': 'keepkey.com',
    'path': '/insight',
}

def _identity_fingerprint(identity, index):
    """Match firmware's cryptoIdentityFingerprint() exactly.

    Firmware order: index(4 LE) + proto + "://" + host + path
    """
    import struct as _s
    ctx = hashlib.sha256()
    ctx.update(_s.pack('<I', index))
    if identity.get('proto'):
        ctx.update(identity['proto'].encode())
        ctx.update(b'://')
    if identity.get('user'):
        ctx.update(identity['user'].encode())
        ctx.update(b'@')
    if identity.get('host'):
        ctx.update(identity['host'].encode())
    if identity.get('port'):
        ctx.update(b':')
        ctx.update(identity['port'].encode())
    if identity.get('path'):
        ctx.update(identity['path'].encode())
    return ctx.digest()

def _derive_hardened(parent_key, parent_chain, index):
    """BIP-32 hardened child derivation."""
    import hmac as _hmac
    data = b'\x00' + parent_key + struct.pack('>I', index)
    I = _hmac.new(parent_chain, data, 'sha512').digest()
    il = int.from_bytes(I[:32], 'big')
    pk = int.from_bytes(parent_key, 'big')
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    child = (pk + il) % n
    return child.to_bytes(32, 'big'), I[32:]

def _mnemonic_to_seed(mnemonic, passphrase=''):
    import hmac as _hmac
    pw = mnemonic.encode('utf-8')
    salt = ('mnemonic' + passphrase).encode('utf-8')
    return hashlib.pbkdf2_hmac('sha512', pw, salt, 2048, dklen=64)

def _derive_insight_key(mnemonic, slot=0):
    """Derive the signing key matching KeepKey's SignIdentity for insight."""
    import hmac as _hmac
    seed = _mnemonic_to_seed(mnemonic)
    I = _hmac.new(b'Bitcoin seed', seed, 'sha512').digest()
    key, chain = I[:32], I[32:]

    # Path: m/13'/hash[0..3]'/hash[4..7]'/hash[8..11]'/hash[12..15]'
    fp = _identity_fingerprint(INSIGHT_IDENTITY, slot)
    path = [
        0x80000000 | 13,
        0x80000000 | int.from_bytes(fp[0:4], 'little'),
        0x80000000 | int.from_bytes(fp[4:8], 'little'),
        0x80000000 | int.from_bytes(fp[8:12], 'little'),
        0x80000000 | int.from_bytes(fp[12:16], 'little'),
    ]

    for idx in path:
        key, chain = _derive_hardened(key, chain, idx)

    return key

# Derive the test private key from the standard test mnemonic
TEST_PRIVATE_KEY = _derive_insight_key(TEST_MNEMONIC, slot=0)


def serialize_metadata(
    chain_id: int,
    contract_address: bytes,
    selector: bytes,
    tx_hash: bytes,
    method_name: str,
    args: list,
    classification: int = CLASSIFICATION_VERIFIED,
    timestamp: int = None,
    key_id: int = 3,
    version: int = 1,
) -> bytes:
    """Serialize metadata fields into canonical binary (unsigned).

    Args:
        chain_id: EIP-155 chain ID
        contract_address: 20-byte contract address
        selector: 4-byte function selector
        tx_hash: 32-byte keccak-256 sighash of the UNSIGNED tx. Firmware binds
            the emitted signature to this value (signed_metadata_enforce), so it
            MUST equal the real digest the device will sign. Compute it with
            eth_sighash_legacy() / eth_sighash_eip1559() below — never zero it.
        method_name: UTF-8 method name (max 64 bytes)
        args: list of dicts with keys: name, format, value (bytes)
        classification: 0=OPAQUE, 1=VERIFIED, 2=MALFORMED
        timestamp: Unix seconds (defaults to now)
        key_id: embedded public key slot. Defaults to 3, the DEBUG_LINK CI test
            slot whose pubkey == TEST_PRIVATE_KEY's pubkey (see
            assert_test_key_matches_slot3). The embedded key_id MUST equal both
            the protocol-level EthereumTxMetadata.key_id and the slot the
            signature verifies against, or firmware returns MALFORMED.
            PRODUCTION callers (Pioneer) MUST pass key_id=0 explicitly and sign
            with the offline production key.
        version: schema version (must be 1)

    Returns:
        Canonical binary payload (without signature — call sign_metadata next)
    """
    if timestamp is None:
        timestamp = int(time.time())

    assert len(contract_address) == 20
    assert len(selector) == 4
    assert len(tx_hash) == 32
    assert len(method_name.encode('utf-8')) <= 64
    assert len(args) <= 8

    buf = bytearray()

    # version
    buf.append(version)

    # chain_id (4 bytes BE)
    buf.extend(struct.pack('>I', chain_id))

    # contract_address (20 bytes)
    buf.extend(contract_address)

    # selector (4 bytes)
    buf.extend(selector)

    # tx_hash (32 bytes)
    buf.extend(tx_hash)

    # method_name (2-byte length prefix + UTF-8)
    name_bytes = method_name.encode('utf-8')
    buf.extend(struct.pack('>H', len(name_bytes)))
    buf.extend(name_bytes)

    # num_args
    buf.append(len(args))

    # args
    for arg in args:
        # name (1-byte length prefix + UTF-8)
        arg_name = arg['name'].encode('utf-8')
        assert len(arg_name) <= 32
        buf.append(len(arg_name))
        buf.extend(arg_name)

        # format
        buf.append(arg['format'])

        # value (2-byte length prefix + raw bytes)
        val = arg['value']
        assert len(val) <= 32  # METADATA_MAX_ARG_VALUE_LEN
        buf.extend(struct.pack('>H', len(val)))
        buf.extend(val)

    # classification
    buf.append(classification)

    # timestamp (4 bytes BE)
    buf.extend(struct.pack('>I', timestamp))

    # key_id
    buf.append(key_id)

    return bytes(buf)


def sign_metadata(payload: bytes, private_key: bytes = None) -> bytes:
    """Sign the canonical binary payload and return the complete signed blob.

    Signs SHA-256(payload) with secp256k1 ECDSA, appends signature(64) + recovery(1).

    Args:
        payload: canonical binary from serialize_metadata()
        private_key: 32-byte secp256k1 private key (defaults to test key)

    Returns:
        Complete signed blob: payload + signature(64) + recovery(1)
    """
    if private_key is None:
        private_key = TEST_PRIVATE_KEY

    digest = hashlib.sha256(payload).digest()

    # NOTE: firmware hashes the identical byte range — sha256 over
    # version..key_id (i.e. the whole serialize_metadata() output), excluding
    # the trailing signature(64)+recovery(1). See signed_metadata_process():
    # signed_len = payload_len - 64 - 1.
    try:
        from ecdsa import SigningKey, SECP256k1, util, VerifyingKey
    except ImportError as exc:
        # Fail loud. A zero signature would be silently rejected by firmware as
        # MALFORMED, disguising "ecdsa not installed" as a crypto/key mismatch.
        raise RuntimeError(
            "The 'ecdsa' package is required to sign metadata "
            "(pip install ecdsa)."
        ) from exc

    sk = SigningKey.from_string(private_key, curve=SECP256k1)
    sig = sk.sign_digest(digest, sigencode=util.sigencode_string)  # r(32)||s(32)
    r = sig[:32]
    s = sig[32:]

    # Recovery byte (27/28). Firmware verifies against the stored slot pubkey and
    # ignores this byte, but the canonical blob carries it.
    vk = sk.get_verifying_key()
    recovered = VerifyingKey.from_public_key_recovery_with_digest(
        sig, digest, SECP256k1, hashfunc=hashlib.sha256
    )
    recovery = 27
    for i, rk in enumerate(recovered):
        if rk.to_string() == vk.to_string():
            recovery = 27 + i
            break

    return payload + r + s + bytes([recovery])


def build_test_metadata(
    chain_id=1,
    contract_address=None,
    selector=None,
    tx_hash=None,
    method_name='supply',
    args=None,
    key_id=3,  # Slot 3: CI test key (DEBUG_LINK builds only)
    **kwargs,
) -> bytes:
    """Convenience: build a complete signed test metadata blob.

    Defaults to an Aave V3 supply() call on Ethereum mainnet.
    Uses key_id=3 (the DEBUG_LINK CI test slot) by default and signs with
    TEST_PRIVATE_KEY, whose pubkey == firmware METADATA_PUBKEYS[3].
    """
    if contract_address is None:
        contract_address = bytes.fromhex('7d2768de32b0b80b7a3454c06bdac94a69ddc7a9')
    if selector is None:
        selector = bytes.fromhex('617ba037')
    if tx_hash is None:
        tx_hash = b'\x00' * 32
    if args is None:
        args = [
            {
                'name': 'asset',
                'format': ARG_FORMAT_ADDRESS,
                'value': bytes.fromhex('6b175474e89094c44da98b954eedeac495271d0f'),
            },
            {
                'name': 'amount',
                'format': ARG_FORMAT_AMOUNT,
                'value': (10500000000000000000).to_bytes(32, 'big'),
            },
            {
                'name': 'onBehalfOf',
                'format': ARG_FORMAT_ADDRESS,
                'value': bytes.fromhex('d8da6bf26964af9d7eed9e03e53415d37aa96045'),
            },
        ]

    payload = serialize_metadata(
        chain_id=chain_id,
        contract_address=contract_address,
        selector=selector,
        tx_hash=tx_hash,
        method_name=method_name,
        args=args,
        key_id=key_id,
        **kwargs,
    )
    return sign_metadata(payload)


# ── Test-signer ↔ firmware slot binding ───────────────────────────────
# The only key the test suite can sign with is TEST_PRIVATE_KEY, derived via
# SignIdentity index 0 (see _derive_insight_key(slot=0)). Its compressed pubkey
# equals firmware METADATA_PUBKEYS[3] (the CI test slot, compiled only under
# #if DEBUG_LINK). The "0" and the "3" are DIFFERENT namespaces — derivation
# index vs firmware key_id array slot — and the mapping index0 -> slot3 is
# intentional. Do NOT "fix" it by deriving at slot=3 or embedding key_id=0.
FIRMWARE_SLOT3_PUBKEY = bytes.fromhex(
    '02e3b3015c47ddcaabe4f8e872f1ed8f09ca145a8d81770d92213d56da31ab5107'
)


def test_signer_compressed_pubkey(private_key: bytes = None) -> bytes:
    """Return the 33-byte compressed secp256k1 pubkey for the signer."""
    from ecdsa import SigningKey, SECP256k1
    if private_key is None:
        private_key = TEST_PRIVATE_KEY
    vk = SigningKey.from_string(private_key, curve=SECP256k1).get_verifying_key()
    point = vk.pubkey.point
    prefix = 0x02 if (point.y() % 2 == 0) else 0x03
    return bytes([prefix]) + point.x().to_bytes(32, 'big')


def assert_test_key_matches_slot3():
    """Prove pubkey(TEST_PRIVATE_KEY) == firmware METADATA_PUBKEYS[3].

    Guards the key_id=3 default: if this fails, every VERIFIED test vector would
    be rejected as MALFORMED by ecdsa_verify_digest against the wrong slot.
    """
    pub = test_signer_compressed_pubkey()
    if pub != FIRMWARE_SLOT3_PUBKEY:
        raise AssertionError(
            "Test signer pubkey %s != firmware slot 3 %s — key_id=3 vectors "
            "will not verify on device." % (pub.hex(), FIRMWARE_SLOT3_PUBKEY.hex())
        )
    return pub


# ── Ethereum sighash (keccak-256 over RLP) ─────────────────────────────
# Produces the EXACT digest firmware feeds to ecdsa_sign_digest, so that a
# metadata blob's tx_hash binds the real transaction. Cross-checked against the
# device: a known signed legacy tx recovers to its m/44'/60'/0'/0/0 signer.

_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_KECCAK_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]
_KECCAK_MASK = (1 << 64) - 1


def _rotl64(x, n):
    return ((x << n) | (x >> (64 - n))) & _KECCAK_MASK


def _keccak_f1600(st):
    for rc in _KECCAK_RC:
        c = [st[x][0] ^ st[x][1] ^ st[x][2] ^ st[x][3] ^ st[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                st[x][y] ^= d[x]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rotl64(st[x][y], _KECCAK_ROT[x][y])
        for x in range(5):
            for y in range(5):
                st[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
        st[0][0] ^= rc


def keccak256(data: bytes) -> bytes:
    """Keccak-256 (Ethereum), NOT NIST SHA3-256 (different padding)."""
    rate = 136  # 1088-bit rate for 256-bit output
    st = [[0] * 5 for _ in range(5)]
    msg = bytearray(data)
    msg.append(0x01)  # keccak pad10*1 (0x01 .. 0x80), distinct from SHA3's 0x06
    while len(msg) % rate != 0:
        msg.append(0x00)
    msg[-1] ^= 0x80
    for off in range(0, len(msg), rate):
        block = msg[off:off + rate]
        for i in range(rate // 8):
            st[i % 5][i // 5] ^= int.from_bytes(block[i * 8:i * 8 + 8], 'little')
        _keccak_f1600(st)
    out = bytearray()
    while len(out) < 32:
        for y in range(5):
            for x in range(5):
                if len(out) < 32:
                    out += st[x][y].to_bytes(8, 'little')
    return bytes(out[:32])


def _int_min_be(value: int) -> bytes:
    """Minimal big-endian (no leading zeros); 0 -> b'' (RLP integer encoding)."""
    if value == 0:
        return b''
    out = bytearray()
    while value > 0:
        out.insert(0, value & 0xFF)
        value >>= 8
    return bytes(out)


def _rlp_str(b: bytes) -> bytes:
    if len(b) == 1 and b[0] < 0x80:
        return b
    if len(b) <= 55:
        return bytes([0x80 + len(b)]) + b
    le = _int_min_be(len(b))
    return bytes([0xB7 + len(le)]) + le + b


def _rlp_list(items) -> bytes:
    body = b''.join(items)
    if len(body) <= 55:
        return bytes([0xC0 + len(body)]) + body
    le = _int_min_be(len(body))
    return bytes([0xF7 + len(le)]) + le + body


def eth_sighash_legacy(nonce, gas_price, gas_limit, to, value, data, chain_id):
    """keccak256(rlp([nonce, gasPrice, gasLimit, to, value, data, chainId,0,0])).

    `to` is 20 raw bytes (b'' for contract creation); ints are minimal-BE.
    Matches firmware ethereum.c legacy EIP-155 hashing exactly.
    """
    items = [
        _rlp_str(_int_min_be(nonce)),
        _rlp_str(_int_min_be(gas_price)),
        _rlp_str(_int_min_be(gas_limit)),
        _rlp_str(bytes(to)),
        _rlp_str(_int_min_be(value)),
        _rlp_str(bytes(data)),
    ]
    if chain_id:
        items += [_rlp_str(_int_min_be(chain_id)), _rlp_str(b''), _rlp_str(b'')]
    return keccak256(_rlp_list(items))


def eth_sighash_eip1559(chain_id, nonce, max_priority_fee_per_gas,
                        max_fee_per_gas, gas_limit, to, value, data):
    """keccak256(0x02 || rlp([chainId, nonce, maxPriorityFee, maxFee, gasLimit,
    to, value, data, []])) with an empty (0xC0) access list.

    Matches firmware ethereum.c EIP-1559 hashing exactly.
    """
    items = [
        _rlp_str(_int_min_be(chain_id)),
        _rlp_str(_int_min_be(nonce)),
        _rlp_str(_int_min_be(max_priority_fee_per_gas)),
        _rlp_str(_int_min_be(max_fee_per_gas)),
        _rlp_str(_int_min_be(gas_limit)),
        _rlp_str(bytes(to)),
        _rlp_str(_int_min_be(value)),
        _rlp_str(bytes(data)),
        _rlp_list([]),  # empty access list -> 0xC0
    ]
    return keccak256(b'\x02' + _rlp_list(items))
