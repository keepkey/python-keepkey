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
    _has_ton = hasattr(_msgs, 'TonGetAddress')
except Exception:
    _has_ton = False
import common
import binascii
import struct
import hashlib
import base64

from keepkeylib import messages_pb2 as messages
from keepkeylib import types_pb2 as types
from keepkeylib.client import CallException
from keepkeylib.tools import parse_path


def make_ton_address(workchain=0, hash_bytes=None, bounceable=True, testnet=False):
    """Construct a TON user-friendly address (48-char base64)."""
    if hash_bytes is None:
        hash_bytes = b'\xBB' * 32

    if bounceable:
        flags = 0x11
    else:
        flags = 0x51

    if testnet:
        flags |= 0x80

    raw = bytes([flags, workchain & 0xFF]) + hash_bytes

    # CRC16-XMODEM
    crc = 0
    for byte in raw:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc <<= 1
            crc &= 0xFFFF

    raw += struct.pack('>H', crc)
    return base64.b64encode(raw).decode('ascii')


@unittest.skipUnless(_has_ton, "TON protobuf messages not available in this build")
class TestMsgTonSignTx(common.KeepKeyTest):

    def setUp(self):
        super().setUp()
        self.requires_firmware("7.14.0")

    def test_ton_get_address(self):
        """Test TON address derivation from device."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        msg = messages.TonGetAddress(
            address_n=parse_path("m/44'/607'/0'/0/0"),
            show_display=False,
        )
        resp = self.client.call(msg)

        # Should return a raw address
        self.assertTrue(resp.raw_address is not None or resp.address is not None)

    def test_ton_sign_structured(self):
        """Test TON transfer using structured fields (reconstruct-then-sign)."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        dest_addr = make_ton_address(
            workchain=0,
            hash_bytes=b'\xCC' * 32,
            bounceable=True
        )

        msg = messages.TonSignTx(
            address_n=parse_path("m/44'/607'/0'/0/0"),
            destination=dest_addr,
            ton_amount=1000000000,  # 1 TON
            seqno=1,
            expire_at=1700000000,
            bounce=True,
            mode=3,
        )
        resp = self.client.call(msg)

        # Should have a 64-byte Ed25519 signature
        self.assertEqual(len(resp.signature), 64)

        # Should return the cell hash
        self.assertEqual(len(resp.cell_hash), 32)

        # Verify signature is not all zeros
        self.assertFalse(all(b == 0 for b in resp.signature))

    def test_ton_sign_with_comment(self):
        """Test TON transfer with a text comment."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        dest_addr = make_ton_address()

        msg = messages.TonSignTx(
            address_n=parse_path("m/44'/607'/0'/0/0"),
            destination=dest_addr,
            ton_amount=500000000,  # 0.5 TON
            seqno=2,
            expire_at=1700000000,
            comment="Hello TON!",
        )
        resp = self.client.call(msg)

        self.assertEqual(len(resp.signature), 64)
        self.assertEqual(len(resp.cell_hash), 32)

    def test_ton_sign_legacy_raw_tx(self):
        """Test legacy blind-sign with raw_tx field."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        # Provide arbitrary raw_tx bytes (simulating a pre-built signing message)
        raw_tx = b'\x00' * 64  # dummy signing message

        msg = messages.TonSignTx(
            address_n=parse_path("m/44'/607'/0'/0/0"),
            raw_tx=raw_tx,
        )
        resp = self.client.call(msg)

        # Should have a 64-byte Ed25519 signature
        self.assertEqual(len(resp.signature), 64)

    def test_ton_sign_missing_fields_rejected(self):
        """Test that incomplete structured fields are rejected."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        # Has destination but no amount or seqno
        msg = messages.TonSignTx(
            address_n=parse_path("m/44'/607'/0'/0/0"),
            destination=make_ton_address(),
        )

        with pytest.raises(CallException):
            self.client.call(msg)

    def test_ton_sign_deterministic(self):
        """Test that signing the same message produces same cell hash."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        dest_addr = make_ton_address()

        msg1 = messages.TonSignTx(
            address_n=parse_path("m/44'/607'/0'/0/0"),
            destination=dest_addr,
            ton_amount=1000000000,
            seqno=1,
            expire_at=1700000000,
        )
        resp1 = self.client.call(msg1)

        msg2 = messages.TonSignTx(
            address_n=parse_path("m/44'/607'/0'/0/0"),
            destination=dest_addr,
            ton_amount=1000000000,
            seqno=1,
            expire_at=1700000000,
        )
        resp2 = self.client.call(msg2)

        # Cell hash should be identical for same inputs
        self.assertEqual(resp1.cell_hash, resp2.cell_hash)


if __name__ == '__main__':
    unittest.main()
