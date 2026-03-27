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
    from keepkeylib import messages_ton_pb2 as _ton_msgs
    _has_ton = hasattr(_ton_msgs, 'TonGetAddress')
except Exception:
    _has_ton = False
import common
import binascii
import struct
import hashlib
import base64

from keepkeylib import messages_pb2 as messages
from keepkeylib import messages_ton_pb2 as ton_messages
from keepkeylib.client import CallException
from keepkeylib.tools import parse_path

TON_PATH = "m/44'/607'/0'/0'/0'/0'"


def make_ton_address(workchain=0, hash_bytes=None, bounceable=True):
    """Build a base64url TON address string."""
    if hash_bytes is None:
        hash_bytes = b'\xAA' * 32
    tag = 0x11 if bounceable else 0x51
    raw = bytes([tag, workchain & 0xFF]) + hash_bytes
    crc = binascii.crc_hqx(raw, 0)
    raw += struct.pack('>H', crc)
    return base64.b64encode(raw).decode('ascii')


@unittest.skipUnless(_has_ton, "TON protobuf messages not available in this build")
class TestMsgTonSignTx(common.KeepKeyTest):

    def setUp(self):
        super().setUp()
        self.requires_firmware("7.14.0")
        self.requires_message("TonGetAddress")

    def test_ton_get_address(self):
        """Test TON address derivation from device."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        msg = ton_messages.TonGetAddress(
            address_n=parse_path(TON_PATH),
            show_display=False,
        )
        resp = self.client.call(msg)

        self.assertTrue(resp.raw_address is not None or resp.address is not None)

    def test_ton_sign_structured(self):
        """Test TON transfer with structured fields + raw_tx hash.

        The firmware requires raw_tx even when structured fields are present.
        Clear-sign mode activates when raw_tx is exactly 32 bytes (a SHA-256
        hash of the unsigned body cell tree).  The firmware reconstructs the
        cell tree from the structured fields and verifies the hash matches.

        Without a Python cell-hash implementation, we send a non-matching
        32-byte raw_tx which causes the firmware to fall back to blind-sign
        with the structured fields shown as display context.
        """
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        dest_addr = make_ton_address(workchain=0, hash_bytes=b'\xCC' * 32, bounceable=True)

        # 64-byte raw_tx triggers blind-sign path (not 32-byte hash path)
        # Structured fields (to_address, amount) are used for display context
        raw_tx = hashlib.sha256(b'test-ton-structured').digest() * 2  # 64 bytes

        msg = ton_messages.TonSignTx(
            address_n=parse_path(TON_PATH),
            raw_tx=raw_tx,
            to_address=dest_addr,
            amount=1000000000,  # 1 TON in nanotons
            seqno=1,
            expire_at=1700000000,
            bounce=True,
        )
        resp = self.client.call(msg)

        self.assertEqual(len(resp.signature), 64)
        self.assertFalse(all(b == 0 for b in resp.signature))

    def test_ton_sign_with_memo(self):
        """Test TON transfer with a text memo (blind-sign path)."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        dest_addr = make_ton_address()

        # raw_tx required; 64 bytes = blind-sign path with display context
        raw_tx = hashlib.sha256(b'test-ton-memo').digest() * 2

        msg = ton_messages.TonSignTx(
            address_n=parse_path(TON_PATH),
            raw_tx=raw_tx,
            to_address=dest_addr,
            amount=500000000,  # 0.5 TON
            seqno=2,
            expire_at=1700000000,
            memo="Hello TON!",
        )
        resp = self.client.call(msg)

        self.assertEqual(len(resp.signature), 64)

    def test_ton_sign_legacy_raw_tx(self):
        """Test legacy blind-sign with raw_tx field."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        raw_tx = b'\x00' * 64

        msg = ton_messages.TonSignTx(
            address_n=parse_path(TON_PATH),
            raw_tx=raw_tx,
        )
        resp = self.client.call(msg)

        self.assertEqual(len(resp.signature), 64)

    def test_ton_sign_missing_fields_rejected(self):
        """Test that incomplete structured fields are rejected."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        msg = ton_messages.TonSignTx(
            address_n=parse_path(TON_PATH),
            to_address=make_ton_address(),
        )

        with pytest.raises(CallException):
            self.client.call(msg)

    def test_ton_sign_deterministic(self):
        """Test that signing the same message produces same signature."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        dest_addr = make_ton_address()
        raw_tx = hashlib.sha256(b'test-ton-deterministic').digest() * 2  # 64 bytes

        msg1 = ton_messages.TonSignTx(
            address_n=parse_path(TON_PATH),
            raw_tx=raw_tx,
            to_address=dest_addr,
            amount=1000000000,
            seqno=1,
            expire_at=1700000000,
        )
        resp1 = self.client.call(msg1)

        msg2 = ton_messages.TonSignTx(
            address_n=parse_path(TON_PATH),
            raw_tx=raw_tx,
            to_address=dest_addr,
            amount=1000000000,
            seqno=1,
            expire_at=1700000000,
        )
        resp2 = self.client.call(msg2)

        self.assertEqual(resp1.signature, resp2.signature)


if __name__ == '__main__':
    unittest.main()
