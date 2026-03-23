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
    key_id: int = 0,
    version: int = 1,
) -> bytes:
    """Serialize metadata fields into canonical binary (unsigned).

    Args:
        chain_id: EIP-155 chain ID
        contract_address: 20-byte contract address
        selector: 4-byte function selector
        tx_hash: 32-byte keccak-256 of unsigned tx (can be zeroed for phase 1)
        method_name: UTF-8 method name (max 64 bytes)
        args: list of dicts with keys: name, format, value (bytes)
        classification: 0=OPAQUE, 1=VERIFIED, 2=MALFORMED
        timestamp: Unix seconds (defaults to now)
        key_id: embedded public key slot (0-3)
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

    try:
        from ecdsa import SigningKey, SECP256k1, util
        sk = SigningKey.from_string(private_key, curve=SECP256k1)
        sig_der = sk.sign_digest(digest, sigencode=util.sigencode_string)
        # sig_der is r(32) || s(32) = 64 bytes
        r = sig_der[:32]
        s = sig_der[32:]

        # Recovery: compute v (27 or 28)
        vk = sk.get_verifying_key()
        pubkey = b'\x04' + vk.to_string()
        # Try recovery with v=0 and v=1
        from ecdsa import VerifyingKey
        for v in (0, 1):
            try:
                recovered = VerifyingKey.from_public_key_recovery_with_digest(
                    sig_der, digest, SECP256k1, hashfunc=hashlib.sha256
                )
                for i, rk in enumerate(recovered):
                    if rk.to_string() == vk.to_string():
                        recovery = 27 + i
                        break
                else:
                    recovery = 27
                break
            except Exception:
                continue
        else:
            recovery = 27

    except ImportError:
        # Fallback: zero signature for struct-only testing
        r = b'\x00' * 32
        s = b'\x00' * 32
        recovery = 27

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
    Uses key_id=1 (CI test slot) by default.
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
