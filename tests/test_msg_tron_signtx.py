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
    from keepkeylib import messages_pb2 as _msgs
    _has_tron = hasattr(_msgs, 'TronGetAddress')
except Exception:
    _has_tron = False
import common
import binascii
import struct

from keepkeylib import messages_pb2 as messages
from keepkeylib import types_pb2 as types
from keepkeylib.client import CallException
from keepkeylib.tools import parse_path


@unittest.skipUnless(_has_tron, "TRON protobuf messages not available in this build")
class TestMsgTronSignTx(common.KeepKeyTest):

    def setUp(self):
        super().setUp()
        self.requires_firmware("7.14.0")

    def test_tron_get_address(self):
        """Test TRON address derivation from device."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        msg = messages.TronGetAddress(
            address_n=parse_path("m/44'/195'/0'/0/0"),
            show_display=False,
        )
        resp = self.client.call(msg)

        # Address should start with 'T'
        self.assertTrue(resp.address.startswith('T'))
        self.assertEqual(len(resp.address), 34)

    def test_tron_sign_transfer_structured(self):
        """Test TRX transfer using structured fields (reconstruct-then-sign)."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        msg = messages.TronSignTx(
            address_n=parse_path("m/44'/195'/0'/0/0"),
            ref_block_bytes=b'\xab\xcd',
            ref_block_hash=b'\x42' * 8,
            expiration=1700000000000,
            timestamp=1699999990000,
            transfer=messages.TronTransferContract(
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
        """Test legacy blind-sign with raw_data field."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        # Provide raw_data (pre-serialized transaction)
        # This is a minimal valid protobuf for a TransferContract
        raw_data = binascii.unhexlify(
            '0a02abcd2208424242424242424240'  # ref_block + expiration (simplified)
            '80e8ded785315a67'                   # dummy contract data
        )

        msg = messages.TronSignTx(
            address_n=parse_path("m/44'/195'/0'/0/0"),
            raw_data=raw_data,
        )
        resp = self.client.call(msg)

        # Should have a 65-byte signature
        self.assertEqual(len(resp.signature), 65)

    def test_tron_sign_missing_fields_rejected(self):
        """Test that missing required fields are rejected."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        # No raw_data and no transfer/trigger_smart
        msg = messages.TronSignTx(
            address_n=parse_path("m/44'/195'/0'/0/0"),
            ref_block_bytes=b'\xab\xcd',
            ref_block_hash=b'\x42' * 8,
            expiration=1700000000000,
        )

        with pytest.raises(CallException) as exc:
            self.client.call(msg)

    def test_tron_sign_trc20_transfer(self):
        """Test TRC-20 USDT transfer using trigger_smart."""
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

        msg = messages.TronSignTx(
            address_n=parse_path("m/44'/195'/0'/0/0"),
            ref_block_bytes=b'\xab\xcd',
            ref_block_hash=b'\x42' * 8,
            expiration=1700000000000,
            timestamp=1699999990000,
            trigger_smart=messages.TronTriggerSmartContract(
                contract_address="TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
                data=bytes(abi_data),
            ),
            fee_limit=10000000,  # 10 TRX
        )
        resp = self.client.call(msg)

        self.assertEqual(len(resp.signature), 65)
        self.assertGreater(len(resp.serialized_tx), 0)


if __name__ == '__main__':
    unittest.main()
