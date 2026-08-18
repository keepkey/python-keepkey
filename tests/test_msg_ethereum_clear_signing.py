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
mnemonic); its pubkey == firmware METADATA_PUBKEYS[3], the DEBUG_LINK CI slot.
All metadata vectors therefore use key_id=3. NEVER use in production.
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
    sign_metadata,
    build_test_metadata,
    ARG_FORMAT_RAW,
    ARG_FORMAT_ADDRESS,
    ARG_FORMAT_AMOUNT,
    ARG_FORMAT_BYTES,
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
# EthereumTxMetadata.key_id, and the firmware slot the signature verifies
# against (METADATA_PUBKEYS[3], compiled only under #if DEBUG_LINK).
TEST_KEY_ID = 3

# ─── Test constants ────────────────────────────────────────────────────

AAVE_V3_POOL = bytes.fromhex('7d2768de32b0b80b7a3454c06bdac94a69ddc7a9')
AAVE_SUPPLY_SELECTOR = bytes.fromhex('617ba037')
DAI_ADDRESS = bytes.fromhex('6b175474e89094c44da98b954eedeac495271d0f')
UNISWAP_ROUTER = bytes.fromhex('68b3465833fb72a70ecdf485e0e4c7bd8665fc45')
VITALIK = bytes.fromhex('d8da6bf26964af9d7eed9e03e53415d37aa96045')
ZERO_TX_HASH = b'\x00' * 32

# Wrong key for adversarial tests (private key = 0x02)
WRONG_PRIVATE_KEY = b'\x00' * 31 + b'\x02'

DEFAULT_ARGS = [
    {'name': 'asset', 'format': ARG_FORMAT_ADDRESS, 'value': DAI_ADDRESS},
    {'name': 'amount', 'format': ARG_FORMAT_AMOUNT,
     'value': (10500000000000000000).to_bytes(32, 'big')},
    {'name': 'onBehalfOf', 'format': ARG_FORMAT_ADDRESS, 'value': VITALIK},
]

# A token the firmware token list recognizes (CVC) — see
# test_msg_ethereum_erc20_approve.py, which signs to it with AdvancedMode OFF.
CVC_TOKEN = bytes.fromhex('41e5560054824ea6b0732e656e3ad64e20e94e45')

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


def aave_supply_calldata(amount, on_behalf=VITALIK, asset=DAI_ADDRESS):
    """supply(asset,amount,onBehalfOf) calldata — 100 bytes, leads with the
    AAVE supply selector so signed_metadata_matches_tx() binds it."""
    return (AAVE_SUPPLY_SELECTOR
            + b'\x00' * 12 + asset
            + amount.to_bytes(32, 'big')
            + b'\x00' * 12 + on_behalf)


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
# Device tests — require KeepKey connected with test firmware
# ═══════════════════════════════════════════════════════════════════════

class TestEthereumClearSigning(common.KeepKeyTest):
    """Device integration tests for EVM clear signing."""

    def setUp(self):
        super().setUp()
        self.requires_firmware("7.15.0")
        self.requires_message("EthereumTxMetadata")
        self.setup_mnemonic_nopin_nopassphrase()

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
        """Metadata.tx_hash = real sighash of the SignTx → signing completes and
        the signature recovers to the device's own signer (binds THIS tx)."""
        # AdvancedMode OFF on purpose: a VERIFIED blob is the *only* reason this
        # contract call is allowed to sign without the blind-sign gate.
        self.client.apply_policy("AdvancedMode", 0)
        n = parse_path(DEVICE_PATH)
        chain_id, nonce, gas_price, gas_limit, value = 1, 7, 20000000000, 200000, 0
        data = aave_supply_calldata(10500000000000000000)
        tx_hash = eth_sighash_legacy(nonce, gas_price, gas_limit, AAVE_V3_POOL,
                                     value, data, chain_id)

        resp = self.client.ethereum_send_tx_metadata(
            signed_payload=bound_metadata(tx_hash),
            metadata_version=1, key_id=TEST_KEY_ID)
        self.assertEqual(resp.classification, CLASSIFICATION_VERIFIED)

        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=n, nonce=nonce, gas_price=gas_price, gas_limit=gas_limit,
            to=AAVE_V3_POOL, value=value, data=data, chain_id=chain_id)
        self.assertIsNotNone(sig_r)
        self.assertIsNotNone(sig_s)
        signer = recover_eth_signer(sig_r, sig_s, sig_v, tx_hash, chain_id)
        self.assertEqual(signer, self.client.ethereum_get_address(n))

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


# ═══════════════════════════════════════════════════════════════════════
# Print all test vectors (for documentation / external verification)
# ═══════════════════════════════════════════════════════════════════════

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
    else:
        unittest.main()
