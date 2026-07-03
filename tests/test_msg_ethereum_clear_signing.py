"""
EVM Clear Signing — comprehensive test vectors.

Tests the EthereumTxMetadata / EthereumMetadataAck flow plus the
EthBlindSigning policy gate. Covers:

  1. Valid signed metadata → VERIFIED classification
  2. Invalid/malicious metadata → MALFORMED classification
  3. Policy: AdvancedMode disabled → hard reject on unknown contract data
  4. Backwards compat: no metadata sent → existing flow unchanged
  5. Adversarial: tampered fields, wrong key, replayed metadata, truncated payloads
  6. tx_hash binding: signature is refused unless the signed digest equals the
     metadata's committed tx_hash (signed_metadata_enforce)

Requires: pip install ecdsa
Metadata signer: TEST_PRIVATE_KEY (SignIdentity index 0 of the BIP-39 test
mnemonic). Phase 1 firmware ships with NO built-in verification keys — every
signer is loaded at runtime via LoadClearsignSigner (user-confirmed, RAM-only,
dropped on reboot/wipe), and metadata verified by a loaded signer shows a
warning screen naming the alias before every clearsign page. setUp() loads
the test pubkey into slot 3 with alias 'CI Test'; all metadata vectors use
key_id=3. NEVER use this key in production.
The device wallet (mnemonic12 from common.py) signs the actual transactions.
"""

import unittest
import hashlib
import struct

try:
    import common
except ImportError:
    import sys, os
    sys.path.insert(0, os.path.dirname(__file__))
    import common

from keepkeylib.signed_metadata import (
    serialize_metadata,
    serialize_schema_metadata,
    schema_calldata,
    sign_metadata,
    build_test_metadata,
    token_amount_value,
    ARG_FORMAT_RAW,
    ARG_FORMAT_ADDRESS,
    ARG_FORMAT_AMOUNT,
    ARG_FORMAT_BYTES,
    ARG_FORMAT_STRING,
    ARG_FORMAT_TOKEN_AMOUNT,
    METADATA_VERSION_SCHEMA,
    CLASSIFICATION_VERIFIED,
    CLASSIFICATION_OPAQUE,
    CLASSIFICATION_MALFORMED,
    TEST_PRIVATE_KEY,
    keccak256,
    eth_sighash_legacy,
    assert_test_key_matches_slot3,
    FIRMWARE_SLOT3_PUBKEY,
    test_signer_compressed_pubkey,
)
from keepkeylib.tools import parse_path
from keepkeylib.client import CallException

# The metadata CI slot. Must match: embedded payload key_id, protocol
# EthereumTxMetadata.key_id, and the slot LoadClearsignSigner loaded the
# test pubkey into (phase 1: all built-in METADATA_PUBKEYS slots are zero).
TEST_KEY_ID = 3

# Alias shown on the load confirm and on every per-tx warning screen.
CI_SIGNER_ALIAS = 'CI Test'

# ─── Test constants ────────────────────────────────────────────────────

AAVE_V3_POOL = bytes.fromhex('7d2768de32b0b80b7a3454c06bdac94a69ddc7a9')
AAVE_SUPPLY_SELECTOR = bytes.fromhex('617ba037')
DAI_ADDRESS = bytes.fromhex('6b175474e89094c44da98b954eedeac495271d0f')
UNISWAP_ROUTER = bytes.fromhex('68b3465833fb72a70ecdf485e0e4c7bd8665fc45')
VITALIK = bytes.fromhex('d8da6bf26964af9d7eed9e03e53415d37aa96045')
ZERO_TX_HASH = b'\x00' * 32

# Wrong key for adversarial tests (private key = 0x02)
WRONG_PRIVATE_KEY = b'\x00' * 31 + b'\x02'

# The decoded who/what/why for the Aave supply tx below. This is what the
# device screen should show the user, in human terms — NOT raw hex/wei:
#   protocol : Aave V3            (STRING  — "who": the attested protocol)
#   asset    : 0x6B17…1d0F (DAI)  (ADDRESS — "what": full, never truncated)
#   amount   : 10.5 DAI           (TOKEN_AMOUNT — decimals+symbol scaled)
#   onBehalfOf: 0xd8dA…6045       (ADDRESS)
# 10500000000000000000 raw / 1e18 = 10.5 DAI.
DEFAULT_ARGS = [
    {'name': 'protocol', 'format': ARG_FORMAT_STRING, 'value': b'Aave V3'},
    {'name': 'asset', 'format': ARG_FORMAT_ADDRESS, 'value': DAI_ADDRESS},
    {'name': 'amount', 'format': ARG_FORMAT_TOKEN_AMOUNT,
     'value': token_amount_value(10500000000000000000, 18, 'DAI')},
    {'name': 'onBehalfOf', 'format': ARG_FORMAT_ADDRESS, 'value': VITALIK},
]

# A token the firmware token list recognizes (CVC) — see
# test_msg_ethereum_erc20_approve.py, which signs to it with AdvancedMode OFF.
CVC_TOKEN = bytes.fromhex('41e5560054824ea6b0732e656e3ad64e20e94e45')

# Real mainnet contracts for the full clear-sign flow suite (mirrors the
# keepkey-sdk tests/evm-clearsign payload set).
USDC = bytes.fromhex('a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48')
WETH = bytes.fromhex('c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2')
UNISWAP_V2_ROUTER = bytes.fromhex('7a250d5630b4cf539739df2c5dacb4c659f2488d')
UNISWAP_V3_ROUTER = bytes.fromhex('e592427a0aece92de3edee1f18e0157c05861564')
UNISWAP_V3_ROUTER2 = bytes.fromhex('68b3465833fb72a70ecdf485e0e4c7bd8665fc45')
RECIPIENT_742 = bytes.fromhex('742d35cc6634c0532950a20547b231011e30c8e7')

def _word(v):
    return v.to_bytes(32, 'big')

def _addr_word(a):
    return b'\x00' * 12 + a

# Device wallet path. With mnemonic12 (common.KeepKeyTest) this is signer
# 0x3f2329c9adfbccd9a84f52c906e936a42da18cb8 — used to check recovered signer.
DEVICE_PATH = "44'/60'/0'/0/0"


def bound_metadata(tx_hash, contract=AAVE_V3_POOL, selector=AAVE_SUPPLY_SELECTOR,
                   chain_id=1, method_name='supply', args=None):
    """Signed VERIFIED metadata committing to a specific real tx sighash."""
    payload = serialize_metadata(
        chain_id=chain_id,
        contract_address=contract,
        selector=selector,
        tx_hash=tx_hash,
        method_name=method_name,
        args=DEFAULT_ARGS if args is None else args,
        key_id=TEST_KEY_ID,
    )
    return sign_metadata(payload)


def recover_eth_signer(sig_r, sig_s, sig_v, digest, chain_id):
    """Recover the 20-byte Ethereum signer from a legacy (EIP-155) signature."""
    from ecdsa import VerifyingKey, SECP256k1, util
    if chain_id:
        rec = sig_v - (35 + 2 * chain_id)
    else:
        rec = sig_v - 27
    keys = VerifyingKey.from_public_key_recovery_with_digest(
        sig_r + sig_s, digest, SECP256k1, hashfunc=None,
        sigdecode=util.sigdecode_string,
    )
    return keccak256(keys[rec].to_string())[-20:]


def aave_supply_calldata(amount, on_behalf=VITALIK, asset=DAI_ADDRESS,
                         referral=0):
    """Real Aave V3 supply(address asset, uint256 amount, address onBehalfOf,
    uint16 referralCode) calldata — selector 0x617ba037 + 4 x 32-byte words =
    132 bytes. Matches the on-chain ABI so the signed tx_hash binds a genuine
    transaction, not a toy payload."""
    return (AAVE_SUPPLY_SELECTOR
            + b'\x00' * 12 + asset
            + amount.to_bytes(32, 'big')
            + b'\x00' * 12 + on_behalf
            + referral.to_bytes(32, 'big'))


# ═══════════════════════════════════════════════════════════════════════
# CLEARSIGN_FLOWS — the canonical clear-sign payload catalog.
#
# This is the COMPLETE REFERENCE for building a clearsign signer: every
# real-world flow, its exact transaction bytes, and the decoded who/what/why
# the metadata must carry. Uses only the typed formats (ADDRESS / STRING /
# TOKEN_AMOUNT) so the device never renders calldata hex. THE catalog itself
# lives in keepkeylib/clearsign_catalog.py — a single source of truth shared
# with scripts/generate-test-report.py, so the PDF's V section is generated
# FROM these flows rather than hand-duplicated (which drifts). Consumed by:
#   - the per-flow device tests (full confirm + sign + recover)
#   - test_clearsign_batch_all_payloads (device validates every blob)
#   - TestClearsignReferenceVectors (offline: deterministic bytes, snapshots)
#   - print_clearsign_flows() --flows (hex dump for external implementations)
# All flows: chain 1, legacy gas, nonce/gas fixed => deterministic tx_hash;
# with REFERENCE_TIMESTAMP + RFC 6979 signing the blobs are byte-reproducible.
# ═══════════════════════════════════════════════════════════════════════

from keepkeylib.clearsign_catalog import (
    CLEARSIGN_FLOWS, CLEARSIGN_FLOWS_BY_KEY, FLOW_NONCE, FLOW_GAS_PRICE,
    FLOW_GAS_LIMIT, REFERENCE_TIMESTAMP,
    flow_tx_hash as _catalog_flow_tx_hash,
    flow_blob as _catalog_flow_blob,
)


def flow_tx_hash(flow, chain_id=1):
    """Deterministic legacy sighash for a catalog flow (fixed nonce/gas).
    Every catalog flow is chain_id=1; the param exists only so old call
    sites don't need updating, and mismatches fail loudly rather than
    silently signing the wrong chain."""
    assert flow['chain_id'] == chain_id, (
        'flow %s is chain_id=%d, not %d' % (flow['key'], flow['chain_id'], chain_id))
    return _catalog_flow_tx_hash(flow)


def flow_blob(flow, chain_id=1, timestamp=None):
    """Per-tx-bound signed metadata blob for a catalog flow, signed with
    TEST_KEY_ID (the CI signer loaded via LoadClearsignSigner in setUp).
    Pass timestamp=REFERENCE_TIMESTAMP for byte-reproducible reference
    vectors."""
    assert flow['chain_id'] == chain_id, (
        'flow %s is chain_id=%d, not %d' % (flow['key'], flow['chain_id'], chain_id))
    return _catalog_flow_blob(flow, key_id=TEST_KEY_ID, timestamp=timestamp)


# ═══════════════════════════════════════════════════════════════════════
# Test Vector Catalog — reference list of signed vs unsigned/invalid/
# malicious attempts to cheat the EVM clear signing system.
# ═══════════════════════════════════════════════════════════════════════

class TestVectorCatalog:
    """Static test vector generators. Each returns (blob, expected_classification, description)."""

    @staticmethod
    def valid_aave_supply():
        """Valid: Aave V3 supply() with correct signature."""
        blob = build_test_metadata(
            chain_id=1,
            contract_address=AAVE_V3_POOL,
            selector=AAVE_SUPPLY_SELECTOR,
            method_name='supply',
            args=DEFAULT_ARGS,
        )
        return blob, CLASSIFICATION_VERIFIED, 'Valid Aave V3 supply()'

    @staticmethod
    def valid_no_args():
        """Valid: method call with zero arguments."""
        blob = build_test_metadata(
            chain_id=1,
            contract_address=AAVE_V3_POOL,
            selector=bytes.fromhex('00000001'),
            method_name='pause',
            args=[],
        )
        return blob, CLASSIFICATION_VERIFIED, 'Valid zero-arg call'

    @staticmethod
    def valid_max_args():
        """Valid: method call with 8 arguments (max)."""
        args = [
            {'name': f'arg{i}', 'format': ARG_FORMAT_RAW,
             'value': bytes([i]) * 4}
            for i in range(8)
        ]
        blob = build_test_metadata(
            chain_id=1,
            contract_address=AAVE_V3_POOL,
            selector=bytes.fromhex('deadbeef'),
            method_name='complexCall',
            args=args,
        )
        return blob, CLASSIFICATION_VERIFIED, 'Valid 8-arg call (max)'

    @staticmethod
    def valid_polygon():
        """Valid: Polygon chain (chainId=137)."""
        blob = build_test_metadata(
            chain_id=137,
            contract_address=UNISWAP_ROUTER,
            selector=bytes.fromhex('04e45aaf'),
            method_name='exactInputSingle',
            args=[
                {'name': 'tokenIn', 'format': ARG_FORMAT_ADDRESS, 'value': DAI_ADDRESS},
                {'name': 'amountIn', 'format': ARG_FORMAT_AMOUNT,
                 'value': (1000000).to_bytes(32, 'big')},
            ],
        )
        return blob, CLASSIFICATION_VERIFIED, 'Valid Polygon Uniswap swap'

    # ── Invalid signature vectors ─────────────────────────────────────

    @staticmethod
    def wrong_signing_key():
        """Adversarial: signed with wrong private key."""
        payload = serialize_metadata(
            chain_id=1,
            contract_address=AAVE_V3_POOL,
            selector=AAVE_SUPPLY_SELECTOR,
            tx_hash=ZERO_TX_HASH,
            method_name='supply',
            args=DEFAULT_ARGS,
        )
        blob = sign_metadata(payload, private_key=WRONG_PRIVATE_KEY)
        return blob, CLASSIFICATION_MALFORMED, 'Wrong signing key'

    @staticmethod
    def tampered_method_name():
        """Adversarial: valid signature but method name changed after signing."""
        payload = serialize_metadata(
            chain_id=1,
            contract_address=AAVE_V3_POOL,
            selector=AAVE_SUPPLY_SELECTOR,
            tx_hash=ZERO_TX_HASH,
            method_name='supply',
            args=DEFAULT_ARGS,
        )
        blob = sign_metadata(payload)
        # Tamper: change 'supply' to 'xupply' in the blob
        tampered = bytearray(blob)
        idx = tampered.index(b'supply')
        tampered[idx] = ord('x')
        return bytes(tampered), CLASSIFICATION_MALFORMED, 'Tampered method name'

    @staticmethod
    def tampered_contract_address():
        """Adversarial: valid signature but contract address changed after signing."""
        payload = serialize_metadata(
            chain_id=1,
            contract_address=AAVE_V3_POOL,
            selector=AAVE_SUPPLY_SELECTOR,
            tx_hash=ZERO_TX_HASH,
            method_name='supply',
            args=DEFAULT_ARGS,
        )
        blob = sign_metadata(payload)
        # Tamper: flip first byte of contract address (offset 5)
        tampered = bytearray(blob)
        tampered[5] ^= 0xFF
        return bytes(tampered), CLASSIFICATION_MALFORMED, 'Tampered contract address'

    @staticmethod
    def tampered_amount():
        """Adversarial: valid signature but amount value changed (drain attack)."""
        payload = serialize_metadata(
            chain_id=1,
            contract_address=AAVE_V3_POOL,
            selector=AAVE_SUPPLY_SELECTOR,
            tx_hash=ZERO_TX_HASH,
            method_name='supply',
            args=DEFAULT_ARGS,
        )
        blob = sign_metadata(payload)
        # Tamper: change last byte of the blob (before signature) to alter amount
        tampered = bytearray(blob)
        # The amount is deep in the payload — any byte change invalidates sig
        tampered[80] ^= 0x01
        return bytes(tampered), CLASSIFICATION_MALFORMED, 'Tampered amount (drain attack)'

    @staticmethod
    def zero_signature():
        """Adversarial: valid payload but signature is all zeros."""
        payload = serialize_metadata(
            chain_id=1,
            contract_address=AAVE_V3_POOL,
            selector=AAVE_SUPPLY_SELECTOR,
            tx_hash=ZERO_TX_HASH,
            method_name='supply',
            args=DEFAULT_ARGS,
        )
        blob = payload + (b'\x00' * 64) + b'\x1b'  # zero sig + recovery=27
        return blob, CLASSIFICATION_MALFORMED, 'Zero signature'

    # ── Structural attack vectors ─────────────────────────────────────

    @staticmethod
    def truncated_payload():
        """Adversarial: payload truncated to less than minimum."""
        return b'\x01' * 50, CLASSIFICATION_MALFORMED, 'Truncated payload (50 bytes)'

    @staticmethod
    def empty_payload():
        """Adversarial: empty payload."""
        return b'', CLASSIFICATION_MALFORMED, 'Empty payload'

    @staticmethod
    def wrong_version():
        """Adversarial: version byte != 0x01."""
        payload = serialize_metadata(
            chain_id=1,
            contract_address=AAVE_V3_POOL,
            selector=AAVE_SUPPLY_SELECTOR,
            tx_hash=ZERO_TX_HASH,
            method_name='supply',
            args=DEFAULT_ARGS,
            version=2,  # Wrong!
        )
        blob = sign_metadata(payload)
        return blob, CLASSIFICATION_MALFORMED, 'Wrong version byte (0x02)'

    @staticmethod
    def too_many_args():
        """Adversarial: 9 args (exceeds METADATA_MAX_ARGS=8)."""
        args = [
            {'name': f'a{i}', 'format': ARG_FORMAT_RAW, 'value': b'\x00'}
            for i in range(9)
        ]
        payload = serialize_metadata(
            chain_id=1,
            contract_address=AAVE_V3_POOL,
            selector=AAVE_SUPPLY_SELECTOR,
            tx_hash=ZERO_TX_HASH,
            method_name='supply',
            args=args,
        )
        blob = sign_metadata(payload)
        return blob, CLASSIFICATION_MALFORMED, '9 args (exceeds max 8)'

    @staticmethod
    def invalid_arg_format():
        """Adversarial: arg format byte > 3 (ARG_FORMAT_BYTES)."""
        payload = serialize_metadata(
            chain_id=1,
            contract_address=AAVE_V3_POOL,
            selector=AAVE_SUPPLY_SELECTOR,
            tx_hash=ZERO_TX_HASH,
            method_name='supply',
            args=[{'name': 'bad', 'format': ARG_FORMAT_RAW, 'value': b'\x00'}],
        )
        blob = sign_metadata(payload)
        # Tamper: change the format byte to 0x05 (invalid)
        tampered = bytearray(blob)
        # Find the format byte: after method_name + num_args + arg_name
        # This is fragile but we know the exact position
        # version(1) + chain_id(4) + contract(20) + selector(4) + tx_hash(32)
        # + method_len(2) + "supply"(6) + num_args(1) + name_len(1) + "bad"(3)
        # = 74, then format byte at 74
        tampered[74] = 0x05
        return bytes(tampered), CLASSIFICATION_MALFORMED, 'Invalid arg format (0x05)'

    @staticmethod
    def wrong_key_id():
        """Adversarial: key_id=2 — slot 2 is empty (0x00)."""
        payload = serialize_metadata(
            chain_id=1,
            contract_address=AAVE_V3_POOL,
            selector=AAVE_SUPPLY_SELECTOR,
            tx_hash=ZERO_TX_HASH,
            method_name='supply',
            args=DEFAULT_ARGS,
            key_id=2,  # Slot 2 is empty (0x00)
        )
        blob = sign_metadata(payload)
        return blob, CLASSIFICATION_MALFORMED, 'Empty key slot (key_id=2)'

    @staticmethod
    def extra_trailing_bytes():
        """Adversarial: valid signed blob + extra bytes appended."""
        blob = build_test_metadata()
        return blob + b'\xDE\xAD', CLASSIFICATION_MALFORMED, 'Extra trailing bytes'

    # ── Chain/contract mismatch vectors (for matches_tx testing) ──────

    @staticmethod
    def wrong_chain_metadata():
        """Mismatch: metadata says chainId=137 but tx is on chainId=1."""
        blob = build_test_metadata(chain_id=137)
        return blob, CLASSIFICATION_VERIFIED, 'Wrong chain (sig valid, binding fails)'

    @staticmethod
    def wrong_contract_metadata():
        """Mismatch: metadata for Uniswap but tx goes to Aave."""
        blob = build_test_metadata(contract_address=UNISWAP_ROUTER)
        return blob, CLASSIFICATION_VERIFIED, 'Wrong contract (sig valid, binding fails)'

    @staticmethod
    def wrong_selector_metadata():
        """Mismatch: metadata for approve() but tx calls supply()."""
        blob = build_test_metadata(selector=bytes.fromhex('095ea7b3'))
        return blob, CLASSIFICATION_VERIFIED, 'Wrong selector (sig valid, binding fails)'


# ═══════════════════════════════════════════════════════════════════════
# Unit tests — can run offline (test the serializer/signer, not device)
# ═══════════════════════════════════════════════════════════════════════

class TestSerializerUnit(unittest.TestCase):
    """Test the canonical binary serializer round-trips correctly."""

    def test_minimum_payload_size(self):
        """Zero-arg metadata meets minimum 136-byte threshold."""
        payload = serialize_metadata(
            chain_id=1,
            contract_address=AAVE_V3_POOL,
            selector=AAVE_SUPPLY_SELECTOR,
            tx_hash=ZERO_TX_HASH,
            method_name='x',
            args=[],
        )
        # payload without sig: should be 136 - 65 (sig+recovery) = 71 bytes
        # Actually: 1+4+20+4+32+2+1+1+1+4+1 = 71
        self.assertEqual(len(payload), 71)

    def test_signed_blob_has_correct_structure(self):
        """Signed blob = payload + sig(64) + recovery(1)."""
        blob = build_test_metadata(args=[])
        # payload = 1+4+20+4+32+2+6("supply")+1+1+4+1 = 76
        # blob = 76 + 64(sig) + 1(recovery) = 141
        self.assertEqual(len(blob), 141)

    def test_version_byte(self):
        blob = build_test_metadata()
        self.assertEqual(blob[0], 0x01)

    def test_chain_id_encoding(self):
        blob = build_test_metadata(chain_id=137)
        self.assertEqual(struct.unpack('>I', blob[1:5])[0], 137)

    def test_contract_address_at_offset_5(self):
        blob = build_test_metadata(contract_address=AAVE_V3_POOL)
        self.assertEqual(blob[5:25], AAVE_V3_POOL)

    def test_selector_at_offset_25(self):
        blob = build_test_metadata(selector=AAVE_SUPPLY_SELECTOR)
        self.assertEqual(blob[25:29], AAVE_SUPPLY_SELECTOR)

    def test_tx_hash_at_offset_29(self):
        blob = build_test_metadata(tx_hash=ZERO_TX_HASH)
        self.assertEqual(blob[29:61], ZERO_TX_HASH)

    def test_signature_verification(self):
        """Signature verifies against test public key."""
        try:
            from ecdsa import VerifyingKey, SECP256k1, SigningKey
        except ImportError:
            self.skipTest('ecdsa library not installed')

        blob = build_test_metadata()
        payload = blob[:-65]
        sig = blob[-65:-1]
        digest = hashlib.sha256(payload).digest()

        sk = SigningKey.from_string(TEST_PRIVATE_KEY, curve=SECP256k1)
        vk = sk.get_verifying_key()
        self.assertTrue(vk.verify_digest(sig, digest))

    def test_tampered_blob_fails_verification(self):
        """Tampering any byte in payload invalidates signature."""
        try:
            from ecdsa import VerifyingKey, SECP256k1, SigningKey, BadSignatureError
        except ImportError:
            self.skipTest('ecdsa library not installed')

        blob = build_test_metadata()
        payload = bytearray(blob[:-65])
        sig = blob[-65:-1]

        # Tamper one byte
        payload[10] ^= 0xFF
        digest = hashlib.sha256(bytes(payload)).digest()

        sk = SigningKey.from_string(TEST_PRIVATE_KEY, curve=SECP256k1)
        vk = sk.get_verifying_key()
        with self.assertRaises(BadSignatureError):
            vk.verify_digest(sig, digest)

    def test_test_key_matches_firmware_slot3(self):
        """The signing key's pubkey == firmware METADATA_PUBKEYS[3].

        Guards the BLOCKER: if these diverge, every VERIFIED vector would be
        rejected as MALFORMED on device. This is why all vectors use key_id=3.
        """
        try:
            import ecdsa  # noqa: F401
        except ImportError:
            self.skipTest('ecdsa library not installed')
        self.assertEqual(test_signer_compressed_pubkey(), FIRMWARE_SLOT3_PUBKEY)
        # Must not raise.
        assert_test_key_matches_slot3()

    def test_default_key_id_is_slot3(self):
        """serialize_metadata embeds key_id=3 by default (matches the signer)."""
        blob = build_test_metadata(args=[])
        # key_id is the last byte of the payload, i.e. before sig(64)+recovery(1).
        self.assertEqual(blob[-66], TEST_KEY_ID)

    def test_keccak256_known_vectors(self):
        """keccak256 (not NIST SHA3) — empty string + function selectors."""
        self.assertEqual(
            keccak256(b'').hex(),
            'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
        )
        self.assertEqual(keccak256(b'transfer(address,uint256)')[:4].hex(),
                         'a9059cbb')
        self.assertEqual(keccak256(b'approve(address,uint256)')[:4].hex(),
                         '095ea7b3')


# ═══════════════════════════════════════════════════════════════════════
# Offline reference vectors — the signer contract, frozen in bytes.
# Any implementation (pioneer-insight, keepkey-sdk) that produces these
# exact blobs from the catalog inputs will be accepted by the firmware.
# ═══════════════════════════════════════════════════════════════════════

# sha256(blob) + blob length for every catalog flow, signed with
# TEST_PRIVATE_KEY at REFERENCE_TIMESTAMP using RFC 6979 deterministic ECDSA.
# Regenerate (only after an intentional format change):
#   python3 -c "import test_msg_ethereum_clear_signing as t, hashlib;
#     [print(f['key'], hashlib.sha256(t.flow_blob(f, timestamp=t.REFERENCE_TIMESTAMP)).hexdigest())
#      for f in t.CLEARSIGN_FLOWS]"
REFERENCE_BLOB_SNAPSHOTS = {
    'aave-v3-supply': ('434ee7389f099e8ab77a4274fd7da40918a74c719dd0bdb4a81c6259846bda2d', 246),
    'erc20-transfer': ('adbd1e054f8b59b1bb86af046951df53510c10dcc0ec0e3e46b19eaf6410cf05', 205),
    'erc20-approve': ('75e5108f578f27d60c572d12072fb4cf0455321c6f39445e1d59fe4d99713c91', 193),
    'erc20-approve-unlimited': ('a5c043a60da8f317975ee8f1b9f3a0718186f6bdce625b605ce71973b3fa3811', 221),
    'uniswap-v2-eth-to-token': ('ec5aac82aa9b03f043456e486d6bfc6cbd5cde507997fc07a122f9fb1fb32194', 229),
    'uniswap-v2-token-to-eth': ('d94e8842cde731f2dd77ea47a896618b1a317736744ac34f6cbdaf7367e794a7', 254),
    'uniswap-v3-exact-input': ('7186e5b902209bb68630a4ff360727df3696395c69782d1a94adc4ae58abfa59', 286),
    'uniswap-v3-multicall': ('e76f3d88be226a1cbd51923cf9753fed30bef1a8e830e5f5ea71a362dd7e43d9', 198),
    'aave-v3-pool-borrow': ('224af25cac14759def6a6272ad5572c991bb46beae8ad253ee2e9d9764674f0a', 263),
    'aave-v3-pool-repay': ('4cb1f4742731ba3c90a2c9a41e5dbe72ace0357d47726df6df1861ffd4b291b0', 262),
    'aave-v3-pool-withdraw': ('584234a72fb32c63ba70aeda1e21def382df6fa85c6e6d88291f8f8530975ef6', 222),
    'compound-v3-comet-supply': ('f7324ea680b02a9eb6b8274592195c048690081dd75ce77deaba69790155a045', 219),
    'compound-v3-comet-withdraw': ('a1a9ec8cb33e4f21c8e746ef805f44747a7b42aff26c3687f14aac145316135c', 225),
    'spark-protocol-supply': ('70e8a0f11ab1b8d12960442c2449b865860e93e2c6c9710473070774f38aba6f', 268),
    'lido-steth-submit': ('c1d0efa2dfdac3e824156ed891d8ac405d86a69dd9241608d5bb43c75e8c01c7', 200),
    'rocketpool-deposit-pool-deposit': ('31b67c47a72fc80dce6c54ff50d1eca0281e62ac34657892b00c3ef79ef1bf85', 193),
    'etherfi-liquiditypool-deposit': ('4a85922bf92ef1b6e0d6c6fbcf720a5240c037161dab18222ec73da255a34ea5', 221),
    'eigenlayer-strategymanager-deposit': ('2728fc859048bcc71288bfa04a6e3957638ebc8c841cea2d6bbfa802b3ebaf4d', 267),
    'eigenlayer-strategymanager-deposit-steth': ('688c636044e4572c4a2d02b38eb6d30277fc43d8852c06f489cbe41db961eb31', 274),
    'erc20-usdc-increase-allowance': ('e689183d751352f6f517bffe53028a1d497cf45c3e2c146ee470a9e21901df09', 208),
    'erc20-usdc-decrease-allowance': ('c4997d82e03bd748dab00dfcec0c2f673a2458634efada134b1ae57689fe66b6', 213),
    'eip2612-usdc-permit': ('06889bb26039122fd59f859196cc2d201c343c66bab3b6dba3bbc6860f4f7346', 288),
    'permit2-approve': ('02c762e1ac3c9b3974a4f5d26a48e7766fe139ba6dd803505be3da24d2f0b1ad', 292),
    'erc721-bayc-set-approval-for-all': ('6449489e8d0c6275d532ba40a99f4077a764a8687c10f2583f9a4dbe39da8ccb', 256),
    'erc1155-opensea-storefront-set-approval-for-all': ('a9acc53ea1f1b88a2679495d2e4e5e5f0f089e8daf073699d1504b0d92b974d3', 255),
    'usdt-approve': ('52a5aa020b2151ffb3694277026ea671c095fc7a59a4e37d29d2c9d3a5917302', 193),
    'dai-permit': ('a625ee696af3add431c6be7f6e870875432b726db3e951445ae0899f93a2777b', 269),
    'erc721-safe-transfer-from': ('57a50c128066e30a14ffbfe3ad6fbc913086d1678c6d6abcc9ab1aca48dde555', 231),
    'safe-addownerwiththreshold': ('12979ff0d05396be10daf6016eee0fa4da73f5d44c64899bfb43d09d75075dc7', 257),
    'hop-protocol-l1-bridge-sendtol2': ('2bf4be50ca05159780a8baf3dc73de7d88f4b9150a1331dfd4c4c6e5c11bb7d6', 250),
    'wormhole-token-bridge-transfertokens': ('b903447283627ea9f7dc051652fa26713d715193e2577ddcee99ae3892c0757c', 274),
    'compound-governor-bravo-castvote': ('869f2aaadb966cde633da10b9dd2fdc4419aa2c22d7bd5b0a98ef0a8777da8bd', 209),
    'ens-public-resolver-setaddr': ('38983de76989898d1bc1d6d07f2dfcb93141ac78f263588d67e7829fa7ea5f75', 194),
    'metamorpho-steakhouse-usdc-deposit': ('c965b8598311e92a1399503b9c69b52e6efe274de1b9a168a893c77bb7803a9e', 227),
    'metamorpho-steakhouse-usdc-withdraw': ('fb0415338d2733b46b72157623f0a4e153cb2baf9bc70911fefa001d98e35049', 224),
    'yearn-v2-yusdc-deposit': ('402cf60cf1b79d201e082ffb1c2c8ea4c26f375e2a2296fe258c820a52fc240a', 195),
    'yearn-v3-aave-usdc-lender-deposit': ('4222df2284f1ff9bcd767d5c38961b1687d8d3685aa655c28bbbe7a92346e21c', 224),
    'compound-iii-comet-usdc-supply': ('6419f4f524b6ce606aa822d15afed70b5dc56c92ebb62c691b07196fba3ef2bc', 220),
    'weth-deposit': ('a9d5f44091a616e2c226b40433bcac99ecb2e03b0936241c814d4c844772a387', 193),
    'weth-withdraw': ('6cfcda551f935439cb79b23c35625d5f6288be2f2fff420415018b012f78ef88', 164),
    'erc20-transferfrom': ('2c5e697d6e0c50eb9c256969e00790b5d56163159fa0f352e65d6445fd27e60b', 257),
    'uniswap-v3-exact-output-single': ('b86dc23deb60c3ef29328cf2567e2170ebb20fc2a6b937551e552aabda335a09', 322),
    'curve-3pool-exchange': ('a90e07ecc65c5e40427811a7580095e6278997125bc42ed324bdcf7bac8f1cff', 238),
    'erc1155-safe-transfer-from': ('4b4f46aa1f3be99c131103146120d3bcc72334758055292d5b792470a0240984', 267),
    'erc1155-safe-batch-transfer-from': ('1d9b41bc88b2b635327f5aa5a748a5705b59e6b8a5d3c30f39df48b4793f20a3', 272),
    'uniswap-v4-universal-router-swap': ('7e1584ce8615670ce54972fe6f538d806afa35803033bbe98e2ec75643f81dc1', 258),
    'permit2-permit-transfer-from': ('c0fde596537a6bf1e53b98d3746638b4249a7a90d8196fe4a9f40f711729ec84', 276),
    'across-spokepool-depositv3': ('ab185113f0b47ef5f6e1fab6a6839df8b71bf8d48796afee64a61ba8b336ac01', 311),
    'safe-exectransaction': ('00a523f8e02d196db7213813edfbeee2a707679b026c6c6b6f8af88d35bf4889', 274),
    'erc4337-entrypoint-v0.7-handleops': ('218c253b00780eeeb4f47b343feba7fafe2ecf3441f32afbd13e555cd56db6d2', 276),
    'eip7702-setcode-authorization': ('0518442c7172b8c57fcbd09ded11b54e1d20076c4b5e79a7490c4ae9c2096a18', 299),
}


class TestClearsignReferenceVectors(unittest.TestCase):
    """Offline (no device): the catalog signs deterministically, every
    signature self-verifies, and the bytes match the frozen snapshots."""

    def setUp(self):
        try:
            import ecdsa  # noqa: F401
        except ImportError:
            self.skipTest('ecdsa library not installed')

    def test_batch_sign_all_deterministic_and_verifies(self):
        from ecdsa import SigningKey, SECP256k1, util
        vk = SigningKey.from_string(
            TEST_PRIVATE_KEY, curve=SECP256k1).get_verifying_key()
        for flow in CLEARSIGN_FLOWS:
            with self.subTest(flow=flow['key']):
                blob = flow_blob(flow, timestamp=REFERENCE_TIMESTAMP)
                # RFC 6979: signing twice yields identical bytes.
                self.assertEqual(
                    blob, flow_blob(flow, timestamp=REFERENCE_TIMESTAMP))
                # Signature verifies over sha256(signed region).
                payload, sig = blob[:-65], blob[-65:-1]
                digest = hashlib.sha256(payload).digest()
                self.assertTrue(vk.verify_digest(
                    sig, digest, sigdecode=util.sigdecode_string))
                # Embedded key_id (last payload byte) is the CI slot.
                self.assertEqual(payload[-1], TEST_KEY_ID)

    def test_batch_matches_frozen_snapshots(self):
        self.assertEqual(set(REFERENCE_BLOB_SNAPSHOTS),
                         {f['key'] for f in CLEARSIGN_FLOWS})
        for flow in CLEARSIGN_FLOWS:
            with self.subTest(flow=flow['key']):
                blob = flow_blob(flow, timestamp=REFERENCE_TIMESTAMP)
                want_sha, want_len = REFERENCE_BLOB_SNAPSHOTS[flow['key']]
                self.assertEqual(len(blob), want_len)
                self.assertEqual(hashlib.sha256(blob).hexdigest(), want_sha)

    def test_catalog_uses_only_hexfree_formats(self):
        """The catalog is the no-hex reference: RAW/BYTES args (which render
        as hex on the OLED) are banned from it."""
        for flow in CLEARSIGN_FLOWS:
            for arg in flow['args']:
                self.assertIn(
                    arg['format'],
                    (ARG_FORMAT_ADDRESS, ARG_FORMAT_STRING,
                     ARG_FORMAT_TOKEN_AMOUNT),
                    '%s arg %s uses a hex-rendering format' %
                    (flow['key'], arg['name']))


# ═══════════════════════════════════════════════════════════════════════
# v2 static-schema blobs (offline) — no device required
#
# v2 attests only the decode SCHEMA (no tx_hash, no arg values); the device
# decodes the argument values from the calldata it signs. These offline tests
# pin the wire format serialize_schema_metadata() emits so it can never drift
# from firmware's parse_v2_args() / decode_v2_args() undetected.
# ═══════════════════════════════════════════════════════════════════════

# transfer(to, amount) on USDC — the canonical v2 fixture. amount is a token
# amount (6 decimals, "USDC"); the value is NOT in the blob, it is decoded from
# the calldata word by the device.
USDC_ADDRESS = bytes.fromhex('a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48')
ERC20_TRANSFER_SELECTOR = bytes.fromhex('a9059cbb')
V2_SCHEMA_ARGS = [
    {'name': 'to', 'format': ARG_FORMAT_ADDRESS},
    {'name': 'amount', 'format': ARG_FORMAT_TOKEN_AMOUNT,
     'decimals': 6, 'symbol': 'USDC'},
]


def _v2_transfer_blob():
    body = serialize_schema_metadata(
        chain_id=1, contract_address=USDC_ADDRESS,
        selector=ERC20_TRANSFER_SELECTOR, method_name='transfer',
        args=V2_SCHEMA_ARGS, timestamp=0, key_id=TEST_KEY_ID)
    return body, sign_metadata(body)


class TestClearSignV2SchemaOffline(unittest.TestCase):
    """Offline byte-format tests for the v2 static-schema serializer."""

    def test_version_byte_is_schema(self):
        body, _ = _v2_transfer_blob()
        self.assertEqual(body[0], METADATA_VERSION_SCHEMA)

    def test_layout_has_no_tx_hash(self):
        """v2 body = version(1)+chain(4)+contract(20)+selector(4)+method... —
        the selector sits at offset 25, immediately after the contract, with NO
        32-byte tx_hash in between (that is the whole point of v2)."""
        body, _ = _v2_transfer_blob()
        self.assertEqual(body[1:5], b'\x00\x00\x00\x01')            # chain_id
        self.assertEqual(body[5:25], USDC_ADDRESS)                  # contract
        self.assertEqual(body[25:29], ERC20_TRANSFER_SELECTOR)     # selector @25
        # method_len(2) + 'transfer'(8) then num_args
        self.assertEqual(body[29:31], b'\x00\x08')
        self.assertEqual(body[31:39], b'transfer')
        self.assertEqual(body[39], len(V2_SCHEMA_ARGS))

    def test_token_arg_carries_static_decimals_symbol_not_value(self):
        """The token arg encodes name + format + decimals + symbol, and NO
        value — decimals/symbol are static (a property of the contract), the
        amount is decoded on-device from the calldata."""
        body, _ = _v2_transfer_blob()
        # after num_args @39: arg0 'to' = len(1)+'to'(2)+format(1) = 4 bytes
        p = 40
        self.assertEqual(body[p], 2)                    # name_len 'to'
        self.assertEqual(body[p + 1:p + 3], b'to')
        self.assertEqual(body[p + 3], ARG_FORMAT_ADDRESS)
        p += 4
        # arg1 'amount' = len(1)+'amount'(6)+format(1)+decimals(1)+symlen(1)+'USDC'(4)
        self.assertEqual(body[p], 6)
        self.assertEqual(body[p + 1:p + 7], b'amount')
        self.assertEqual(body[p + 7], ARG_FORMAT_TOKEN_AMOUNT)
        self.assertEqual(body[p + 8], 6)                # decimals
        self.assertEqual(body[p + 9], 4)                # symbol_len
        self.assertEqual(body[p + 10:p + 14], b'USDC')

    def test_signed_blob_is_body_plus_65(self):
        body, blob = _v2_transfer_blob()
        self.assertEqual(len(blob), len(body) + 65)

    def test_frozen_body_snapshot(self):
        """Freeze the canonical v2 UNSIGNED body's length + sha256. The body is
        key-independent (no signature) and deterministic (timestamp=0), so this
        is a pure wire-format drift gate: it trips iff serialize_schema_metadata()
        changes the bytes, which must stay in lockstep with firmware's
        parse_v2_args(). (The signature is exercised separately.)"""
        body, _ = _v2_transfer_blob()
        got = (len(body), hashlib.sha256(body).hexdigest())
        self.assertEqual(got, V2_BODY_SNAPSHOT,
                         'v2 body drift: only update V2_BODY_SNAPSHOT if the wire '
                         'format intentionally changed (and firmware too)')

    def test_calldata_matches_schema_shape(self):
        """schema_calldata() builds selector + one 32-byte word per arg, so the
        device decodes exactly num_args words (the structural binding)."""
        cd = schema_calldata(ERC20_TRANSFER_SELECTOR, [
            {'format': ARG_FORMAT_ADDRESS, 'address': VITALIK},
            {'format': ARG_FORMAT_TOKEN_AMOUNT, 'amount': 1500000},
        ])
        self.assertEqual(len(cd), 4 + 32 * 2)
        self.assertEqual(cd[:4], ERC20_TRANSFER_SELECTOR)
        self.assertEqual(cd[4:16], b'\x00' * 12)     # address left-padding
        self.assertEqual(cd[16:36], VITALIK)
        self.assertEqual(int.from_bytes(cd[36:68], 'big'), 1500000)

    def test_rejects_dynamic_format(self):
        """v2 only encodes fixed single-word types; STRING/BYTES are rejected by
        the serializer (they have no fixed on-chain word)."""
        with self.assertRaises(AssertionError):
            serialize_schema_metadata(
                chain_id=1, contract_address=USDC_ADDRESS,
                selector=ERC20_TRANSFER_SELECTOR, method_name='x',
                args=[{'name': 'label', 'format': ARG_FORMAT_STRING}])


# Frozen len + sha256 of the canonical v2 UNSIGNED transfer body (timestamp=0,
# key-independent). Regenerate ONLY on an intentional wire-format change:
#   python3 -c "from tests.test_msg_ethereum_clear_signing import _v2_transfer_blob; \
#     import hashlib; b,_=_v2_transfer_blob(); print(len(b), hashlib.sha256(b).hexdigest())"
V2_BODY_SNAPSHOT = (
    64, '01a24001460f8a69684f3d2a10f75b14e7449d8912a3833f7f8758e8fccadc05')


# ═══════════════════════════════════════════════════════════════════════
# Device tests — require KeepKey connected with test firmware
# ═══════════════════════════════════════════════════════════════════════

class TestEthereumClearSigning(common.KeepKeyTest):
    """Device integration tests for EVM clear signing."""

    def setUp(self):
        super().setUp()
        self.requires_firmware("7.15.0")
        self.requires_message("EthereumTxMetadata")
        self.requires_message("LoadClearsignSigner")
        self.setup_mnemonic_nopin_nopassphrase()
        self._load_ci_signer()

    def _load_ci_signer(self):
        """Load the CI test signer through the production trust path (device
        confirm auto-acked by debuglink). Wipe drops it, so every test starts
        from an explicit, observable load."""
        self.client.load_clearsign_signer(
            key_id=TEST_KEY_ID,
            pubkey=test_signer_compressed_pubkey(),
            alias=CI_SIGNER_ALIAS,
        )
        # The load-confirm frame is setUp noise for the signing tests; drop it
        # so each test's own operation frames are what the report picks.
        self._drop_setup_screenshots()

    def test_valid_metadata_returns_verified(self):
        """Send valid signed metadata → device returns VERIFIED."""
        blob, expected, desc = TestVectorCatalog.valid_aave_supply()
        resp = self.client.ethereum_send_tx_metadata(
            signed_payload=blob,
            metadata_version=1,
            key_id=3,
        )
        self.assertEqual(resp.classification, expected)

    def test_wrong_key_returns_malformed(self):
        """Metadata signed with wrong key → MALFORMED."""
        blob, expected, desc = TestVectorCatalog.wrong_signing_key()
        resp = self.client.ethereum_send_tx_metadata(
            signed_payload=blob,
            metadata_version=1,
            key_id=3,
        )
        self.assertEqual(resp.classification, expected)

    def test_tampered_method_returns_malformed(self):
        """Tampered method name → signature invalid → MALFORMED."""
        blob, expected, desc = TestVectorCatalog.tampered_method_name()
        resp = self.client.ethereum_send_tx_metadata(
            signed_payload=blob,
            metadata_version=1,
            key_id=3,
        )
        self.assertEqual(resp.classification, expected)

    def test_tampered_contract_returns_malformed(self):
        """Tampered contract address → MALFORMED."""
        blob, expected, desc = TestVectorCatalog.tampered_contract_address()
        resp = self.client.ethereum_send_tx_metadata(
            signed_payload=blob,
            metadata_version=1,
            key_id=3,
        )
        self.assertEqual(resp.classification, expected)

    def test_zero_signature_returns_malformed(self):
        """All-zero signature → MALFORMED."""
        blob, expected, desc = TestVectorCatalog.zero_signature()
        resp = self.client.ethereum_send_tx_metadata(
            signed_payload=blob,
            metadata_version=1,
            key_id=3,
        )
        self.assertEqual(resp.classification, expected)

    def test_truncated_payload_returns_malformed(self):
        """Truncated payload → MALFORMED."""
        blob, expected, desc = TestVectorCatalog.truncated_payload()
        resp = self.client.ethereum_send_tx_metadata(
            signed_payload=blob,
            metadata_version=1,
            key_id=3,
        )
        self.assertEqual(resp.classification, expected)

    def test_empty_payload_returns_malformed(self):
        """Empty payload → MALFORMED."""
        blob, expected, desc = TestVectorCatalog.empty_payload()
        resp = self.client.ethereum_send_tx_metadata(
            signed_payload=blob,
            metadata_version=1,
            key_id=3,
        )
        self.assertEqual(resp.classification, expected)

    def test_wrong_version_returns_malformed(self):
        """Version != 0x01 → MALFORMED."""
        blob, expected, desc = TestVectorCatalog.wrong_version()
        resp = self.client.ethereum_send_tx_metadata(
            signed_payload=blob,
            metadata_version=1,
            key_id=3,
        )
        self.assertEqual(resp.classification, expected)

    def test_extra_trailing_bytes_returns_malformed(self):
        """Extra bytes appended → parse fails (cursor != end) → MALFORMED."""
        blob, expected, desc = TestVectorCatalog.extra_trailing_bytes()
        resp = self.client.ethereum_send_tx_metadata(
            signed_payload=blob,
            metadata_version=1,
            key_id=3,
        )
        self.assertEqual(resp.classification, expected)

    def test_empty_key_slot_returns_malformed(self):
        """key_id=2 (empty slot) → MALFORMED."""
        blob, expected, desc = TestVectorCatalog.wrong_key_id()
        resp = self.client.ethereum_send_tx_metadata(
            signed_payload=blob,
            metadata_version=1,
            key_id=2,
        )
        self.assertEqual(resp.classification, expected)

    def test_no_metadata_then_sign_unchanged(self):
        """No metadata sent → EthereumSignTx works as before (backwards compat)."""
        # Device already initialized by setUp()
        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=parse_path("44'/60'/0'/0/0"),
            nonce=0,
            gas_price=20000000000,
            gas_limit=21000,
            to=b'\xd8\xda\x6b\xf2\x69\x64\xaf\x9d\x7e\xed\x9e\x03\xe5\x34\x15\xd3\x7a\xa9\x60\x45',
            value=1000000000000000000,
            chain_id=1,
        )
        self.assertIsNotNone(sig_r)
        self.assertIsNotNone(sig_s)

    # ── tx_hash binding (the authoritative gate) ──────────────────────

    def test_binding_happy_path_signs_and_recovers(self):
        """Full who/what/why clear-sign of a REAL Aave V3 supply() transaction.

        The device is sent (1) an actual EthereumSignTx with genuine Aave
        supply(asset,amount,onBehalfOf,referralCode) calldata, and (2) a signed
        metadata blob whose tx_hash == the exact sighash of that tx. With
        AdvancedMode OFF, the VERIFIED blob is the ONLY reason this contract
        call may sign without the blind-sign gate.

        On device this renders, in order:
          WHO  -> Clearsign Warning (signer 'CI Test') + Contract: 0x7d27…c7a9
          WHAT -> Call: supply / protocol: Aave V3 / asset: 0x6B17…1d0F (DAI)
                  / amount: 10.5 DAI / onBehalfOf: 0xd8dA…6045
          WHY  -> the signature is REFUSED unless the signed digest equals the
                  metadata's committed tx_hash (asserted by the recover below).
        """
        self.client.apply_policy("AdvancedMode", 0)
        # Drop the AdvancedMode-toggle confirm frame so the captured OLED
        # sequence is exactly the who/what/why review screens.
        self._drop_setup_screenshots()
        n = parse_path(DEVICE_PATH)
        chain_id, nonce, gas_price, gas_limit, value = 1, 7, 20000000000, 200000, 0
        amount = 10500000000000000000  # 10.5 DAI (18 decimals)
        data = aave_supply_calldata(amount)
        # Byte-accurate real Aave supply calldata: selector + 4 x 32-byte words.
        self.assertEqual(data[:4], bytes.fromhex('617ba037'))
        self.assertEqual(len(data), 4 + 4 * 32)
        tx_hash = eth_sighash_legacy(nonce, gas_price, gas_limit, AAVE_V3_POOL,
                                     value, data, chain_id)

        # The metadata blob carries the decoded who/what/why (see DEFAULT_ARGS):
        # protocol=Aave V3, asset=DAI, amount=10.5 DAI, onBehalfOf.
        blob = bound_metadata(tx_hash)
        resp = self.client.ethereum_send_tx_metadata(
            signed_payload=blob, metadata_version=1, key_id=TEST_KEY_ID)
        self.assertEqual(resp.classification, CLASSIFICATION_VERIFIED)

        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=n, nonce=nonce, gas_price=gas_price, gas_limit=gas_limit,
            to=AAVE_V3_POOL, value=value, data=data, chain_id=chain_id)
        self.assertIsNotNone(sig_r)
        self.assertIsNotNone(sig_s)
        # WHY it's trustworthy: the signature recovers to THIS device's signer
        # over THIS tx's digest — the metadata was bound to the exact tx.
        signer = recover_eth_signer(sig_r, sig_s, sig_v, tx_hash, chain_id)
        self.assertEqual(signer, self.client.ethereum_get_address(n))

    def _clearsign_flow(self, flow, chain_id=1):
        """Run one catalog flow END-TO-END with AdvancedMode OFF: real tx,
        per-tx-bound metadata, who/what/why confirm screens (auto-acked),
        sign, and assert the signature recovers to the device signer over
        this exact digest. The user never sees calldata hex — with
        AdvancedMode OFF the VERIFIED metadata is the ONLY reason the
        contract data may sign at all."""
        self.client.apply_policy("AdvancedMode", 0)
        self._drop_setup_screenshots()
        n = parse_path(DEVICE_PATH)
        tx_hash = flow_tx_hash(flow, chain_id)
        resp = self.client.ethereum_send_tx_metadata(
            signed_payload=flow_blob(flow, chain_id),
            metadata_version=1, key_id=TEST_KEY_ID)
        self.assertEqual(resp.classification, CLASSIFICATION_VERIFIED)

        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=n, nonce=FLOW_NONCE, gas_price=FLOW_GAS_PRICE,
            gas_limit=FLOW_GAS_LIMIT, to=flow['to'], value=flow['value'],
            data=flow['data'], chain_id=chain_id)
        self.assertIsNotNone(sig_r)
        signer = recover_eth_signer(sig_r, sig_s, sig_v, tx_hash, chain_id)
        self.assertEqual(signer, self.client.ethereum_get_address(n))

    def test_clearsign_batch_all_payloads(self):
        """Sign the ENTIRE payload catalog in one batch and have the DEVICE
        validate every blob: each flow's metadata comes back VERIFIED, and a
        tampered byte in any blob comes back MALFORMED. This is the
        reference contract for signer implementations: produce these bytes
        and the device will accept them."""
        for flow in CLEARSIGN_FLOWS:
            with self.subTest(flow=flow['key']):
                blob = flow_blob(flow)
                resp = self.client.ethereum_send_tx_metadata(
                    signed_payload=blob, metadata_version=1,
                    key_id=TEST_KEY_ID)
                # NB: common.KeepKeyTest overrides assertEqual with a
                # 2-arg signature (no msg param); subTest names the flow.
                self.assertEqual(resp.classification, CLASSIFICATION_VERIFIED)

                # Adversarial cross-check: any single tampered byte in the
                # signed region must flip the SAME blob to MALFORMED.
                tampered = bytearray(blob)
                tampered[10] ^= 0xFF
                resp = self.client.ethereum_send_tx_metadata(
                    signed_payload=bytes(tampered), metadata_version=1,
                    key_id=TEST_KEY_ID)
                self.assertEqual(resp.classification,
                                 CLASSIFICATION_MALFORMED)

    def test_replay_rejected_when_digest_differs(self):
        """Metadata bound to tx A, then sign tx B (same contract+selector+chain,
        different calldata) → device aborts at send_signature, NO signature."""
        self.client.apply_policy("AdvancedMode", 0)
        n = parse_path(DEVICE_PATH)
        chain_id, gas_price, gas_limit = 1, 20000000000, 200000

        data_a = aave_supply_calldata(1000000000000000000)
        tx_hash_a = eth_sighash_legacy(0, gas_price, gas_limit, AAVE_V3_POOL,
                                       0, data_a, chain_id)
        resp = self.client.ethereum_send_tx_metadata(
            signed_payload=bound_metadata(tx_hash_a),
            metadata_version=1, key_id=TEST_KEY_ID)
        self.assertEqual(resp.classification, CLASSIFICATION_VERIFIED)

        # Same selector/contract/chain (matches_tx → screens shown), but the
        # amount differs so the real digest != committed tx_hash.
        data_b = aave_supply_calldata(500000000000000000000)
        try:
            self.client.ethereum_sign_tx(
                n=n, nonce=0, gas_price=gas_price, gas_limit=gas_limit,
                to=AAVE_V3_POOL, value=0, data=data_b, chain_id=chain_id)
            self.fail("Expected Failure — metadata committed to a different tx")
        except CallException as e:
            self.assertIn("Metadata does not match signed transaction", str(e))

    def test_advanced_mode_gate(self):
        """AdvancedMode OFF + unknown contract + no metadata → hard reject;
        ON → raw-data confirm path signs; recognized ERC-20 transfer unaffected."""
        n = parse_path(DEVICE_PATH)
        data = aave_supply_calldata(1000000000000000000)

        # OFF + unknown contract + no metadata → blocked
        self.client.apply_policy("AdvancedMode", 0)
        try:
            self.client.ethereum_sign_tx(
                n=n, nonce=0, gas_price=20000000000, gas_limit=200000,
                to=AAVE_V3_POOL, value=0, data=data, chain_id=1)
            self.fail("Expected Failure — blind signing disabled")
        except CallException as e:
            self.assertIn("Blind signing disabled", str(e))

        # ON → raw-data confirm path → signs
        self.client.apply_policy("AdvancedMode", 1)
        _, sig_r, _ = self.client.ethereum_sign_tx(
            n=n, nonce=0, gas_price=20000000000, gas_limit=200000,
            to=AAVE_V3_POOL, value=0, data=data, chain_id=1)
        self.assertIsNotNone(sig_r)
        self.client.apply_policy("AdvancedMode", 0)

        # Recognized ERC-20 transfer is decoded natively → NOT blind-gated even
        # with AdvancedMode OFF (token resolves via tokenByChainAddress).
        erc20 = (bytes.fromhex('a9059cbb') + b'\x00' * 12 + VITALIK
                 + (1000000).to_bytes(32, 'big'))
        _, sig_r, _ = self.client.ethereum_sign_tx(
            n=n, nonce=1, gas_price=20000000000, gas_limit=80000,
            to=CVC_TOKEN, value=0, data=erc20, chain_id=1)
        self.assertIsNotNone(sig_r)

    def test_cancel_clears_metadata_not_reused(self):
        """Cancel mid-confirm → metadata cleared; a later matching tx is NOT
        silently signed using the stale blob."""
        n = parse_path(DEVICE_PATH)
        chain_id, gas_price, gas_limit = 1, 20000000000, 200000
        data = aave_supply_calldata(1000000000000000000)
        tx_hash = eth_sighash_legacy(0, gas_price, gas_limit, AAVE_V3_POOL,
                                     0, data, chain_id)
        resp = self.client.ethereum_send_tx_metadata(
            signed_payload=bound_metadata(tx_hash),
            metadata_version=1, key_id=TEST_KEY_ID)
        self.assertEqual(resp.classification, CLASSIFICATION_VERIFIED)

        # Press NO on the first decoded confirm screen → signed_metadata_confirm
        # returns false → ActionCancelled + ethereum_signing_abort (clears blob).
        self.client.button = False
        try:
            self.client.ethereum_sign_tx(
                n=n, nonce=0, gas_price=gas_price, gas_limit=gas_limit,
                to=AAVE_V3_POOL, value=0, data=data, chain_id=chain_id)
            self.fail("Expected Failure — user cancelled the verified confirm")
        except CallException as e:
            self.assertIn("cancelled", str(e).lower())
        finally:
            self.client.button = True

        # Same tx, no new metadata, AdvancedMode OFF → blind-sign gate must fire.
        # If the stale blob were reused it would suppress the gate and sign.
        self.client.apply_policy("AdvancedMode", 0)
        try:
            self.client.ethereum_sign_tx(
                n=n, nonce=0, gas_price=gas_price, gas_limit=gas_limit,
                to=AAVE_V3_POOL, value=0, data=data, chain_id=chain_id)
            self.fail("Expected Failure — stale metadata must not be reused")
        except CallException as e:
            self.assertIn("Blind signing disabled", str(e))


    # ── LoadClearsignSigner — the phase-1 trust path ───────────────────

    def test_load_required_before_verify(self):
        """Fresh (wiped) device: a VERIFIED blob is MALFORMED until the signer
        is loaded — proves there is no built-in trust path in phase 1."""
        self.client.wipe_device()  # factory reset drops loaded signers
        self.setup_mnemonic_nopin_nopassphrase()

        blob, _, _ = TestVectorCatalog.valid_aave_supply()
        resp = self.client.ethereum_send_tx_metadata(
            signed_payload=blob, metadata_version=1, key_id=TEST_KEY_ID)
        self.assertEqual(resp.classification, CLASSIFICATION_MALFORMED)

        self._load_ci_signer()
        resp = self.client.ethereum_send_tx_metadata(
            signed_payload=blob, metadata_version=1, key_id=TEST_KEY_ID)
        self.assertEqual(resp.classification, CLASSIFICATION_VERIFIED)

    def test_load_signer_cancel_refuses(self):
        """Pressing NO on the load confirm must refuse the signer."""
        pub = test_signer_compressed_pubkey()
        self.client.button = False
        try:
            with self.assertRaises(CallException):
                self.client.load_clearsign_signer(
                    key_id=1, pubkey=pub, alias=CI_SIGNER_ALIAS)
        finally:
            self.client.button = True

        # Slot 1 must still be empty: a blob signed for slot 1 is MALFORMED.
        payload = serialize_metadata(
            chain_id=1, contract_address=AAVE_V3_POOL,
            selector=AAVE_SUPPLY_SELECTOR, tx_hash=ZERO_TX_HASH,
            method_name='supply', args=DEFAULT_ARGS, key_id=1)
        resp = self.client.ethereum_send_tx_metadata(
            signed_payload=sign_metadata(payload), metadata_version=1, key_id=1)
        self.assertEqual(resp.classification, CLASSIFICATION_MALFORMED)

    def test_load_signer_invalid_pubkey_rejected(self):
        """Uncompressed / zero / truncated pubkeys refused without a confirm."""
        for bad in (b'\x04' + b'\x00' * 32,   # uncompressed prefix
                    b'\x00' * 33,               # zero key (empty-slot sentinel)
                    test_signer_compressed_pubkey()[:32]):  # short
            with self.assertRaises(CallException):
                self.client.load_clearsign_signer(
                    key_id=1, pubkey=bad, alias=CI_SIGNER_ALIAS)

    def test_load_signer_bad_alias_rejected(self):
        """Empty/oversized aliases, control/'%' chars, and semantic-injection
        punctuation are rejected. The alias renders inside quotes on the trust
        screen, so a quote-breakout or a "." / "(" that appends a false
        "verified by KeepKey." claim must not pass validation."""
        pub = test_signer_compressed_pubkey()
        for alias in ('', 'x' * 32, 'evil\nalias', 'a%sb',
                      "x' verified by KeepKey. Safe (", 'safe.KeepKey',
                      'trust(me)'):
            with self.assertRaises(CallException):
                self.client.load_clearsign_signer(
                    key_id=1, pubkey=pub, alias=alias)

    def test_load_signer_key_id_out_of_range_rejected(self):
        with self.assertRaises(CallException):
            self.client.load_clearsign_signer(
                key_id=4, pubkey=test_signer_compressed_pubkey(),
                alias=CI_SIGNER_ALIAS)


class TestClearSignV2Device(common.KeepKeyTest):
    """Device integration for v2 (static schema) blobs.

    A v2 blob attests only the decode schema; the device decodes the argument
    values from the calldata it signs. This exercises the full round-trip: load
    signer -> send v2 metadata -> sign a matching transfer() tx -> the signature
    recovers to this device's signer over the tx digest (so the who/what/why
    shown was bound to the exact tx, with no committed tx_hash).

    v2 (METADATA_VERSION_SCHEMA) lands in the in-progress 7.15.0 line, so this
    runs against the develop firmware alongside the v1 clear-sign device tests.
    """

    V2_FIRMWARE = "7.15.0"

    def setUp(self):
        super().setUp()
        self.requires_firmware(self.V2_FIRMWARE)
        self.requires_message("EthereumTxMetadata")
        self.requires_message("LoadClearsignSigner")
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.load_clearsign_signer(
            key_id=TEST_KEY_ID, pubkey=test_signer_compressed_pubkey(),
            alias=CI_SIGNER_ALIAS)
        self._drop_setup_screenshots()

    def test_v2_transfer_decodes_signs_and_recovers(self):
        self.client.apply_policy("AdvancedMode", 0)
        self._drop_setup_screenshots()
        n = parse_path(DEVICE_PATH)
        chain_id, nonce, gas_price, gas_limit, value = 1, 3, 20000000000, 250000, 0
        # transfer(to=VITALIK, amount=1.5 USDC) — the device decodes both from
        # the calldata using the v2 schema (address word + token-amount word).
        args = [
            {'format': ARG_FORMAT_ADDRESS, 'address': VITALIK},
            {'format': ARG_FORMAT_TOKEN_AMOUNT, 'amount': 1500000},
        ]
        data = schema_calldata(ERC20_TRANSFER_SELECTOR, args)
        _, blob = _v2_transfer_blob()

        resp = self.client.ethereum_send_tx_metadata(
            signed_payload=blob, metadata_version=1, key_id=TEST_KEY_ID)
        self.assertEqual(resp.classification, CLASSIFICATION_VERIFIED)

        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=n, nonce=nonce, gas_price=gas_price, gas_limit=gas_limit,
            to=USDC_ADDRESS, value=value, data=data, chain_id=chain_id)
        self.assertIsNotNone(sig_r)
        self.assertIsNotNone(sig_s)
        tx_hash = eth_sighash_legacy(nonce, gas_price, gas_limit, USDC_ADDRESS,
                                     value, data, chain_id)
        signer = recover_eth_signer(sig_r, sig_s, sig_v, tx_hash, chain_id)
        self.assertEqual(signer, self.client.ethereum_get_address(n))

    def test_v2_calldata_length_mismatch_falls_back_to_blind_sign_gate(self):
        """The headline v2 security property: a blob's schema says 2 words,
        but the calldata actually being signed carries 3. decode_v2_args'
        structural completeness check (total calldata bytes must equal
        exactly 4 + 32*num_args) fails, matches_tx returns false, and the tx
        falls through to the ordinary blind-sign path — with AdvancedMode
        OFF that is a hard reject, never a clear-signed-but-wrong display."""
        self.client.apply_policy("AdvancedMode", 0)
        self._drop_setup_screenshots()
        n = parse_path(DEVICE_PATH)
        chain_id, nonce, gas_price, gas_limit, value = 1, 3, 20000000000, 250000, 0
        args = [
            {'format': ARG_FORMAT_ADDRESS, 'address': VITALIK},
            {'format': ARG_FORMAT_TOKEN_AMOUNT, 'amount': 1500000},
        ]
        # calldata carries one EXTRA 32-byte word beyond the 2-arg schema.
        data = schema_calldata(ERC20_TRANSFER_SELECTOR, args) + (b'\x00' * 32)
        _, blob = _v2_transfer_blob()

        resp = self.client.ethereum_send_tx_metadata(
            signed_payload=blob, metadata_version=1, key_id=TEST_KEY_ID)
        self.assertEqual(resp.classification, CLASSIFICATION_VERIFIED)

        with self.assertRaises(CallException) as ctx:
            self.client.ethereum_sign_tx(
                n=n, nonce=nonce, gas_price=gas_price, gas_limit=gas_limit,
                to=USDC_ADDRESS, value=value, data=data, chain_id=chain_id)
        self.assertIn("Blind signing disabled", str(ctx.exception))

    def test_v2_unsupported_arg_format_returns_malformed(self):
        """v2 supports only fixed single-word ADDRESS/AMOUNT/TOKEN_AMOUNT arg
        formats (decode_v2_args has no dynamic-type support, by design). The
        Python serializer refuses to BUILD a STRING-format v2 blob (see the
        offline test_rejects_dynamic_format), but a malicious or buggy host
        could still hand-craft the raw bytes — the device's own parser must
        independently reject an unsupported v2 arg format as MALFORMED at
        blob-load time, before any calldata is even seen."""
        self._drop_setup_screenshots()
        body = bytearray()
        body.append(METADATA_VERSION_SCHEMA)
        body.extend((1).to_bytes(4, 'big'))                  # chain_id
        body.extend(USDC_ADDRESS)
        body.extend(ERC20_TRANSFER_SELECTOR)
        name = b'transfer'
        body.extend(len(name).to_bytes(2, 'big'))
        body.extend(name)
        body.append(1)                                        # num_args
        arg_name = b'label'
        body.append(len(arg_name))
        body.extend(arg_name)
        body.append(ARG_FORMAT_STRING)                         # unsupported in v2
        body.append(CLASSIFICATION_VERIFIED)
        body.extend((0).to_bytes(4, 'big'))                    # timestamp
        body.append(TEST_KEY_ID)
        blob = sign_metadata(bytes(body))

        resp = self.client.ethereum_send_tx_metadata(
            signed_payload=blob, metadata_version=1, key_id=TEST_KEY_ID)
        self.assertEqual(resp.classification, CLASSIFICATION_MALFORMED)


# ═══════════════════════════════════════════════════════════════════════
# Dynamically generate one full-confirm device test per CLEARSIGN_FLOWS
# entry (mirrors keepkey-sdk tests/evm-clearsign): every real-world flow a
# user actually performs, each confirmed end-to-end with AdvancedMode OFF
# and ZERO calldata hex on the OLED — only who/what/why screens. Avoids
# hand-writing 50+ near-identical test methods; the catalog IS the test
# list, so growing it (see keepkeylib/clearsign_catalog.py) needs no
# changes here. 'aave-v3-supply' is excluded — it's the flagship full-
# sequence walkthrough in test_binding_happy_path_signs_and_recovers above.
# ═══════════════════════════════════════════════════════════════════════

def _make_clearsign_flow_test(flow_key):
    def test(self):
        self._clearsign_flow(CLEARSIGN_FLOWS_BY_KEY[flow_key])
    f = CLEARSIGN_FLOWS_BY_KEY[flow_key]
    test.__doc__ = '%s.%s (%s): %s' % (f['protocol'], f['method'], f['category'], f.get('why', ''))
    return test


for _flow in CLEARSIGN_FLOWS:
    if _flow['key'] == 'aave-v3-supply':
        continue
    setattr(TestEthereumClearSigning,
           'test_clearsign_' + _flow['key'].replace('-', '_').replace('.', '_'),
           _make_clearsign_flow_test(_flow['key']))
del _flow


# ═══════════════════════════════════════════════════════════════════════
# Print all test vectors (for documentation / external verification)
# ═══════════════════════════════════════════════════════════════════════

def print_clearsign_flows():
    """Dump the complete clear-sign flow catalog: tx params, calldata hex and
    the deterministic reference blob hex. THE external reference for signer
    implementations (pioneer-insight, keepkey-sdk)."""
    print('=' * 70)
    print('CLEARSIGN FLOW CATALOG (chain 1, nonce=%d, gas_price=%d, gas_limit=%d,' %
          (FLOW_NONCE, FLOW_GAS_PRICE, FLOW_GAS_LIMIT))
    print('timestamp=%d, key_id=%d, RFC6979 deterministic ECDSA)' %
          (REFERENCE_TIMESTAMP, TEST_KEY_ID))
    print('=' * 70)
    for flow in CLEARSIGN_FLOWS:
        print()
        print('[%s] %s' % (flow['key'], flow['method']))
        shows = ', '.join('%s=%r' % (a['name'], a.get('value')) for a in flow['args'])
        print('  shows      : %s' % shows)
        print('  to         : 0x%s' % flow['to'].hex())
        print('  value      : %d' % flow['value'])
        print('  calldata   : 0x%s' % flow['data'].hex())
        print('  tx_hash    : 0x%s' % flow_tx_hash(flow).hex())
        print('  blob       : %s' % flow_blob(flow, TEST_KEY_ID, timestamp=REFERENCE_TIMESTAMP).hex())


def print_test_vectors():
    """Print all test vectors as hex for external verification."""
    vectors = [
        TestVectorCatalog.valid_aave_supply,
        TestVectorCatalog.valid_no_args,
        TestVectorCatalog.valid_max_args,
        TestVectorCatalog.valid_polygon,
        TestVectorCatalog.wrong_signing_key,
        TestVectorCatalog.tampered_method_name,
        TestVectorCatalog.tampered_contract_address,
        TestVectorCatalog.tampered_amount,
        TestVectorCatalog.zero_signature,
        TestVectorCatalog.truncated_payload,
        TestVectorCatalog.empty_payload,
        TestVectorCatalog.wrong_version,
        TestVectorCatalog.too_many_args,
        TestVectorCatalog.invalid_arg_format,
        TestVectorCatalog.wrong_key_id,
        TestVectorCatalog.extra_trailing_bytes,
        TestVectorCatalog.wrong_chain_metadata,
        TestVectorCatalog.wrong_contract_metadata,
        TestVectorCatalog.wrong_selector_metadata,
    ]

    print('═' * 72)
    print('  EVM Clear Signing — Test Vector Catalog')
    print('  Metadata signer: SignIdentity idx0 == firmware slot 3 (key_id=3)')
    print('═' * 72)

    for i, gen in enumerate(vectors):
        blob, expected, desc = gen()
        cls_name = ['OPAQUE', 'VERIFIED', 'MALFORMED'][expected]
        print(f'\n── Vector {i+1}: {desc}')
        print(f'   Expected: {cls_name} ({expected})')
        print(f'   Size: {len(blob)} bytes')
        print(f'   Hex: {blob.hex()}')

    print('\n' + '═' * 72)


if __name__ == '__main__':
    import sys
    if '--vectors' in sys.argv:
        print_test_vectors()
    elif '--flows' in sys.argv:
        print_clearsign_flows()
    else:
        unittest.main()
