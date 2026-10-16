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


if __name__ == '__main__':
    unittest.main()
