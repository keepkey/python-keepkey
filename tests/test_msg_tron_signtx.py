# This file is part of the KeepKey project.
#
# Copyright (C) 2025 KeepKey
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.

import pytest
import unittest

try:
    from keepkeylib import messages_tron_pb2 as _tron_msgs
    _has_tron = hasattr(_tron_msgs, 'TronGetAddress')
except Exception:
    _has_tron = False
import common
import binascii
import hashlib
import struct

from ecdsa import SECP256k1, VerifyingKey
from ecdsa.util import sigdecode_string

from keepkeylib import messages_pb2 as messages
from keepkeylib import messages_tron_pb2 as tron_messages
from keepkeylib import types_pb2 as types
from keepkeylib.client import CallException
from keepkeylib.signed_metadata import keccak256
from keepkeylib.tools import b58decode, b58encode, parse_path


USDT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"  # tether.to supported-protocols
TRIGGER_URL = b"type.googleapis.com/protocol.TriggerSmartContract"


def _varint(value):
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _field(number, payload):
    """Length-delimited protobuf field."""
    return _varint(number << 3 | 2) + _varint(len(payload)) + payload


def _uint(number, value):
    return _varint(number << 3) + _varint(value)


def _tron_raw(address):
    """21-byte TRON address from Base58Check."""
    raw = b58decode(address, None)
    payload, checksum = raw[:-4], raw[-4:]
    assert hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] == checksum
    assert len(payload) == 21 and payload[0] == 0x41
    return payload


def _tron_address(raw21):
    checksum = hashlib.sha256(hashlib.sha256(raw21).digest()).digest()[:4]
    return b58encode(raw21 + checksum)


def _trc20_transfer_raw_data(owner, contract, to, amount, fee_limit):
    """protocol.Transaction.raw for one TriggerSmartContract transfer()."""
    calldata = (binascii.unhexlify("a9059cbb") + b"\0" * 12 + to[1:] +
                amount.to_bytes(32, "big"))
    trigger = _field(1, owner) + _field(2, contract) + _field(4, calldata)
    contract_msg = _uint(1, 31) + _field(2, _field(1, TRIGGER_URL) +
                                         _field(2, trigger))
    return (_field(1, b"\xab\xcd") + _field(4, b"\x42" * 8) +
            _uint(8, 1700000000000) + _field(11, contract_msg) +
            _uint(14, 1699999990000) + _uint(18, fee_limit))


@unittest.skipUnless(_has_tron, "TRON protobuf messages not available in this build")
class TestMsgTronSignTx(common.KeepKeyTest):

    def setUp(self):
        super().setUp()
        self.requires_firmware("7.14.0")
        self.requires_message("TronGetAddress")

    def test_tron_get_address(self):
        """Test TRON address derivation from device."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        msg = tron_messages.TronGetAddress(
            address_n=parse_path("m/44'/195'/0'/0/0"),
            show_display=False,
        )
        resp = self.client.call(msg)

        # Address should start with 'T'
        self.assertTrue(resp.address.startswith('T'))
        self.assertEqual(len(resp.address), 34)

    @unittest.skip("Structured TRON signing deferred to 7.15+; firmware only supports raw_data blind-sign")
    def test_tron_sign_transfer_structured(self):
        """Test TRX transfer using structured fields (reconstruct-then-sign).
        Deferred to 7.15+ — firmware currently only supports raw_data path.
        """
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        msg = tron_messages.TronSignTx(
            address_n=parse_path("m/44'/195'/0'/0/0"),
            ref_block_bytes=b'\xab\xcd',
            ref_block_hash=b'\x42' * 8,
            expiration=1700000000000,
            timestamp=1699999990000,
            transfer=tron_messages.TronTransferContract(
                to_address="TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
                amount=1000000,  # 1 TRX
            ),
        )
        resp = self.client.call(msg)

        # Should have a 65-byte signature (r + s + v)
        self.assertEqual(len(resp.signature), 65)

        # Should return the reconstructed serialized_tx
        self.assertGreater(len(resp.serialized_tx), 0)

        # Verify signature is not all zeros
        self.assertFalse(all(b == 0 for b in resp.signature))

    def test_tron_sign_transfer_legacy_raw_data(self):
        """Test legacy blind-sign with raw_data field.

        This raw_data is a hand-rolled blob, not a real TransferContract, so
        the raw_data clear-sign parser can't decode it — it falls to the
        opaque blind-sign path, which requires AdvancedMode."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        # 7.14.2 gates TronSignTx behind AdvancedMode: this line has no raw_data
        # parser, so the device cannot vouch for amount or destination and
        # discloses it as a blind signature. Opt in explicitly here.
        self.client.apply_policy("AdvancedMode", 1)

        # Provide raw_data (pre-serialized transaction)
        # This is a minimal valid protobuf for a TransferContract
        raw_data = binascii.unhexlify(
            '0a02abcd2208424242424242424240'  # ref_block + expiration (simplified)
            '80e8ded785315a67'                   # dummy contract data
        )

        msg = tron_messages.TronSignTx(
            address_n=parse_path("m/44'/195'/0'/0/0"),
            raw_data=raw_data,
        )
        self.client.apply_policy('AdvancedMode', True)
        resp = self.client.call(msg)
        self.client.apply_policy('AdvancedMode', False)

        # Should have a 65-byte signature
        self.assertEqual(len(resp.signature), 65)

    def test_tron_sign_missing_fields_rejected(self):
        """Test that missing required fields are rejected."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        # No raw_data and no transfer/trigger_smart
        msg = tron_messages.TronSignTx(
            address_n=parse_path("m/44'/195'/0'/0/0"),
            ref_block_bytes=b'\xab\xcd',
            ref_block_hash=b'\x42' * 8,
            expiration=1700000000000,
        )

        with pytest.raises(CallException) as exc:
            self.client.call(msg)

    @unittest.skip("Structured TRON TRC-20 signing deferred to 7.15+; firmware only supports raw_data blind-sign")
    def test_tron_sign_trc20_transfer(self):
        """Test TRC-20 USDT transfer using trigger_smart.
        Deferred to 7.15+ — firmware currently only supports raw_data path.
        """
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        # ABI-encode transfer(address,uint256) for USDT
        # Selector: 0xa9059cbb
        # Address: padded 32 bytes (0x41 prefix at byte 11)
        # Amount: 1000000 USDT (6 decimals) = 0xF4240
        abi_data = bytearray(68)
        abi_data[0:4] = b'\xa9\x05\x9c\xbb'  # selector
        # Recipient address (padded)
        abi_data[15] = 0x41
        for i in range(20):
            abi_data[16 + i] = 0x10 + i
        # Amount
        struct.pack_into('>Q', abi_data, 60, 1000000)

        msg = tron_messages.TronSignTx(
            address_n=parse_path("m/44'/195'/0'/0/0"),
            ref_block_bytes=b'\xab\xcd',
            ref_block_hash=b'\x42' * 8,
            expiration=1700000000000,
            timestamp=1699999990000,
            trigger_smart=tron_messages.TronTriggerSmartContract(
                contract_address="TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
                data=bytes(abi_data),
            ),
            fee_limit=10000000,  # 10 TRX
        )
        resp = self.client.call(msg)

        self.assertEqual(len(resp.signature), 65)
        self.assertGreater(len(resp.serialized_tx), 0)


    def _walk_sign(self, msg):
        """Approve every screen, recording (title, body) as the device drew it."""
        screens = []
        response = self.client.call_raw(msg)
        while isinstance(response, messages.ButtonRequest):
            screens.append(self.client.debug.read_confirm_text())
            self.client.capture_oled()
            self.client.debug.press_yes()
            response = self.client.call_raw(messages.ButtonAck())
        return response, screens

    def _trc20_request(self, contract):
        path = parse_path("m/44'/195'/0'/0/0")
        owner = self.client.call(tron_messages.TronGetAddress(
            address_n=path, show_display=False)).address
        to = b"\x41" + b"\x22" * 20
        raw_data = _trc20_transfer_raw_data(_tron_raw(owner), contract, to,
                                            1500000, 30000000)
        return owner, to, raw_data, tron_messages.TronSignTx(
            address_n=path, raw_data=raw_data)

    def test_tron_sign_trc20_usdt_clear_signs(self):
        """USDT is in the firmware's trusted TRC-20 table: the transfer
        clear-signs without AdvancedMode, in token units, and the signature
        covers sha256(raw_data) under the account's own key."""
        self.requires_fullFeature()
        self.requires_firmware("7.15.0")
        self.requires_release_capability("tron-trc20-review")
        self.setup_mnemonic_allallall()
        self.client.apply_policy("AdvancedMode", 0)

        owner, to, raw_data, msg = self._trc20_request(_tron_raw(USDT))
        response, screens = self._walk_sign(msg)

        self.assertIsInstance(response, tron_messages.TronSignedTx)
        self.assertEqual(screens[0], ("TRC-20 Transfer",
                                      "Send 1.5 USDT to %s?" % _tron_address(to)))
        self.assertEqual(screens[1][1],
                         "Energy fee limit 30 TRX\nBandwidth fees are extra")
        self.assertEqual(len(screens), 2)

        signature = response.signature
        self.assertEqual(len(signature), 65)
        digest = hashlib.sha256(raw_data).digest()
        candidates = VerifyingKey.from_public_key_recovery_with_digest(
            signature[:64], digest, SECP256k1, sigdecode=sigdecode_string)
        signers = set()
        for key in candidates:
            point = key.to_string()  # 64-byte uncompressed X || Y
            signers.add(_tron_address(b"\x41" + keccak256(point)[-20:]))
        self.assertIn(owner, signers)

    def test_tron_sign_trc20_unknown_contract_needs_advanced_mode(self):
        """A transfer() call to a contract outside the trusted table is not
        clear-signed: without AdvancedMode it is refused before any screen."""
        self.requires_fullFeature()
        self.requires_firmware("7.15.0")
        self.requires_release_capability("tron-trc20-review")
        self.setup_mnemonic_allallall()
        self.client.apply_policy("AdvancedMode", 0)

        _, _, _, msg = self._trc20_request(b"\x41" + b"\x33" * 20)
        response = self.client.call_raw(msg)
        self.assertIsInstance(response, messages.Failure)
        self.assertEqual(response.message, "Enable AdvancedMode to blind-sign")

    def test_tron_sign_empty_raw_data(self):
        """Signing with empty raw_data should be rejected by firmware."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        msg = tron_messages.TronSignTx(
            address_n=parse_path("m/44'/195'/0'/0/0"),
            raw_data=b'',
        )

        with pytest.raises(CallException):
            self.client.call(msg)

    def test_tron_sign_oversized_raw_data(self):
        """Signing with raw_data over proto max (2049 bytes) should be rejected."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        oversized = b'\xab' * 2049

        msg = tron_messages.TronSignTx(
            address_n=parse_path("m/44'/195'/0'/0/0"),
            raw_data=oversized,
        )

        with pytest.raises(CallException):
            self.client.call(msg)

    def test_tron_sign_deterministic(self):
        """Signing the same raw_data twice must produce identical 65-byte signatures."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        # 7.14.2 gates TronSignTx behind AdvancedMode: this line has no raw_data
        # parser, so the device cannot vouch for amount or destination and
        # discloses it as a blind signature. Opt in explicitly here.
        self.client.apply_policy("AdvancedMode", 1)

        raw_data = binascii.unhexlify(
            '0a02abcd2208424242424242424240'
            '80e8ded785315a67'
        )

        msg1 = tron_messages.TronSignTx(
            address_n=parse_path("m/44'/195'/0'/0/0"),
            raw_data=raw_data,
        )
        # Not a decodable TransferContract — opaque blind-sign, needs AdvancedMode.
        self.client.apply_policy('AdvancedMode', True)
        resp1 = self.client.call(msg1)

        msg2 = tron_messages.TronSignTx(
            address_n=parse_path("m/44'/195'/0'/0/0"),
            raw_data=raw_data,
        )
        resp2 = self.client.call(msg2)
        self.client.apply_policy('AdvancedMode', False)

        self.assertEqual(len(resp1.signature), 65)
        self.assertEqual(len(resp2.signature), 65)
        self.assertTrue(
            resp1.signature == resp2.signature,
            "Same raw_data must produce identical signatures"
        )

    def test_tron_sign_different_accounts(self):
        """Signing the same raw_data with different account paths must produce different signatures."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        # 7.14.2 gates TronSignTx behind AdvancedMode: this line has no raw_data
        # parser, so the device cannot vouch for amount or destination and
        # discloses it as a blind signature. Opt in explicitly here.
        self.client.apply_policy("AdvancedMode", 1)

        raw_data = binascii.unhexlify(
            '0a02abcd2208424242424242424240'
            '80e8ded785315a67'
        )

        msg_acct0 = tron_messages.TronSignTx(
            address_n=parse_path("m/44'/195'/0'/0/0"),
            raw_data=raw_data,
        )
        # Not a decodable TransferContract — opaque blind-sign, needs AdvancedMode.
        self.client.apply_policy('AdvancedMode', True)
        resp_acct0 = self.client.call(msg_acct0)

        msg_acct1 = tron_messages.TronSignTx(
            address_n=parse_path("m/44'/195'/1'/0/0"),
            raw_data=raw_data,
        )
        resp_acct1 = self.client.call(msg_acct1)
        self.client.apply_policy('AdvancedMode', False)

        self.assertEqual(len(resp_acct0.signature), 65)
        self.assertEqual(len(resp_acct1.signature), 65)
        self.assertNotEqual(
            resp_acct0.signature, resp_acct1.signature,
            "Different account paths must produce different signatures"
        )


# Real TRON mainnet transactions, raw_data_hex as TronGrid returns it
# (_source: POST https://api.trongrid.io/wallet/gettransactionbyid
# {"value": <txID>}; all contractRet SUCCESS, 2026-10-29). The firmware tree
# keeps the full set in unittests/firmware/tron_vectors.json.
REAL_TRON_TXS = {
    # 753e3529...7840: USDT approve(TKwNfJYb..., 2^256-1)
    "usdt_approve_unlimited": (
        "41d20b07706310934bec19447644256b693791b966",
        "0a02da852208235d8b17a756a57940d0dca5ce98345aae01081f12a9010a3174797065"
        "2e676f6f676c65617069732e636f6d2f70726f746f636f6c2e54726967676572536d61"
        "7274436f6e747261637412740a1541d20b07706310934bec19447644256b693791b966"
        "121541a614f803b6fd780986a42c78ec9c7f77e6ded13c2244095ea7b3000000000000"
        "0000000000006d587d39c016bf456fd95107b6c9204884052042ffffffffffffffffff"
        "ffffffffffffffffffffffffffffffffffffffffffffff70fcbe9ece9834900180a3c3"
        "47"),
    # 50e8b8d9...bc74: USDT approve(TJ4KeiGT..., 100 USDT), 0x41 address word
    "usdt_approve_100": (
        "41b0e06ce319c853971f02f10dc01a7e5930b96032",
        "0a02dad92208ec7a5c7dba80cb684080e0bfdf98345aae01081f12a9010a3174797065"
        "2e676f6f676c65617069732e636f6d2f70726f746f636f6c2e54726967676572536d61"
        "7274436f6e747261637412740a1541b0e06ce319c853971f02f10dc01a7e5930b96032"
        "121541a614f803b6fd780986a42c78ec9c7f77e6ded13c2244095ea7b3000000000000"
        "00000000004158b8a2f4c954a0c54c8e392feee612ec2dbe1585000000000000000000"
        "0000000000000000000000000000000000000005f5e1007080beaace98349001eca5e1"
        "04"),
    # 6074566e...b7ec: FreezeBalanceV2 13 TRX for ENERGY
    "freeze_energy": (
        "41d2a8b759235a3a1f4c644f1f27f0288fb970c563",
        "0a02da852208235d8b17a756a5794080e29ece98345a5a083612560a34747970652e67"
        "6f6f676c65617069732e636f6d2f70726f746f636f6c2e467265657a6542616c616e63"
        "655632436f6e7472616374121e0a1541d2a8b759235a3a1f4c644f1f27f0288fb970c5"
        "6310c0ba9906180170a08d9bce9834"),
    # 9334deff...8fdd: VoteWitness, three votes
    "vote_3": (
        "41728118849b1fdf3173e9d2837c0de3b3af4d19a2",
        "0a02dae32208cd97162a94a4ade74090fdafce98345aa701080412a2010a3074797065"
        "2e676f6f676c65617069732e636f6d2f70726f746f636f6c2e566f74655769746e6573"
        "73436f6e7472616374126e0a1541728118849b1fdf3173e9d2837c0de3b3af4d19a212"
        "1b0a154167e39013be3cdd3814bed152d7439fb5b679140910ea8a05121b0a15418b03"
        "59acac03bac62cbf89c4b787cb10b3c3f51310e88a05121b0a1541beab998551416b02"
        "f6721129bb01b51fceceba0810e88a0570b0a8acce9834"),
}


@unittest.skipUnless(_has_tron, "TRON protobuf messages not available in this build")
class TestMsgTronClearSign717(common.KeepKeyTest):
    """7.17 decodes TRC-20 approve, Stake 2.0 and votes from raw_data."""

    _walk_sign = TestMsgTronSignTx._walk_sign

    def setUp(self):
        super().setUp()
        self.requires_firmware("7.17.0")

    def _sign_real(self, name):
        """The real transaction with its owner swapped for this device's
        account (same length, so the protobuf framing is unchanged)."""
        path = parse_path("m/44'/195'/0'/0/0")
        owner = self.client.call(tron_messages.TronGetAddress(
            address_n=path, show_display=False)).address
        chain_owner, raw_hex = REAL_TRON_TXS[name]
        raw = binascii.unhexlify(raw_hex)
        assert raw.count(binascii.unhexlify(chain_owner)) == 1
        raw = raw.replace(binascii.unhexlify(chain_owner), _tron_raw(owner))
        response, screens = self._walk_sign(
            tron_messages.TronSignTx(address_n=path, raw_data=raw))
        self.assertIsInstance(response, tron_messages.TronSignedTx)
        digest = hashlib.sha256(raw).digest()
        signers = set()
        for key in VerifyingKey.from_public_key_recovery_with_digest(
                response.signature[:64], digest, SECP256k1,
                sigdecode=sigdecode_string):
            signers.add(_tron_address(b"\x41" + keccak256(key.to_string())[-20:]))
        self.assertIn(owner, signers)
        return screens

    def test_tron_usdt_unlimited_approve_names_spender(self):
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        self.client.apply_policy("AdvancedMode", 0)
        self.assertEqual(self._sign_real("usdt_approve_unlimited"), [
            ("UNLIMITED approval",
             "Allow TKwNfJYb2iyouByKpNdxQ6tryXK8KhTPT9 to spend ALL your USDT?"),
            ("TRON", "Energy fee limit 150 TRX\nBandwidth fees are extra"),
        ])

    def test_tron_usdt_approve_shows_amount(self):
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        self.client.apply_policy("AdvancedMode", 0)
        self.assertEqual(self._sign_real("usdt_approve_100"), [
            ("TRC-20 Approve",
             "Allow TJ4KeiGTvTX4wRUgLARiwr8rGLaurmVkdZ to spend up to 100 USDT?"),
            ("TRON", "Energy fee limit 9.9827 TRX\nBandwidth fees are extra"),
        ])

    def test_tron_freeze_v2(self):
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        self.client.apply_policy("AdvancedMode", 0)
        self.assertEqual(self._sign_real("freeze_energy"),
                         [("TRON Stake", "Stake 13 TRX for ENERGY?")])

    def test_tron_vote_witness(self):
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        self.client.apply_policy("AdvancedMode", 0)
        self.assertEqual(self._sign_real("vote_3"), [
            ("TRON Vote", "Vote for 3 SRs? This replaces all your current votes."),
            ("Vote 1/3", "83306 votes for TKSXDA8HfE9E1y39RczVQ1ZascUEtaSToF"),
            ("Vote 2/3", "83304 votes for TNeEwWHXLLUgEtfzTnYN8wtVenGxuMzZCE"),
            ("Vote 3/3", "83304 votes for TTMNxTmRpBZnjtUnohX84j25NLkTqDga7j"),
        ])


if __name__ == '__main__':
    unittest.main()
