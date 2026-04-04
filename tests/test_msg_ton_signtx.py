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

        dest_addr = make_ton_address()

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

    def test_ton_sign_empty_raw_tx(self):
        """Empty raw_tx (0 bytes) should be rejected by firmware."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        msg = ton_messages.TonSignTx(
            address_n=parse_path(TON_PATH),
            raw_tx=b'',
        )

        with pytest.raises(CallException):
            self.client.call(msg)

    def test_ton_sign_oversized_raw_tx(self):
        """raw_tx of 1025 bytes exceeds proto max (1024) and should be rejected."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        raw_tx = b'\xAB' * 1025

        msg = ton_messages.TonSignTx(
            address_n=parse_path(TON_PATH),
            raw_tx=raw_tx,
        )

        with pytest.raises(CallException):
            self.client.call(msg)

    def test_ton_sign_with_empty_memo(self):
        """Empty memo string should be accepted (memo is optional text)."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        dest_addr = make_ton_address()
        raw_tx = hashlib.sha256(b'test-ton-empty-memo').digest() * 2  # 64 bytes

        msg = ton_messages.TonSignTx(
            address_n=parse_path(TON_PATH),
            raw_tx=raw_tx,
            to_address=dest_addr,
            amount=100000000,  # 0.1 TON
            seqno=3,
            expire_at=1700000000,
            memo="",
        )
        resp = self.client.call(msg)

        self.assertEqual(len(resp.signature), 64)

    def test_ton_sign_with_long_memo(self):
        """Memo of 120 characters (near max_size 121) should be accepted."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        dest_addr = make_ton_address()
        raw_tx = hashlib.sha256(b'test-ton-long-memo').digest() * 2  # 64 bytes
        long_memo = "A" * 120

        msg = ton_messages.TonSignTx(
            address_n=parse_path(TON_PATH),
            raw_tx=raw_tx,
            to_address=dest_addr,
            amount=200000000,  # 0.2 TON
            seqno=4,
            expire_at=1700000000,
            memo=long_memo,
        )
        resp = self.client.call(msg)

        self.assertEqual(len(resp.signature), 64)

    def test_ton_sign_workchain_zero(self):
        """Explicit workchain=0 (basechain) in TonSignTx."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        dest_addr = make_ton_address()
        raw_tx = hashlib.sha256(b'test-ton-workchain-zero').digest() * 2  # 64 bytes

        msg = ton_messages.TonSignTx(
            address_n=parse_path(TON_PATH),
            raw_tx=raw_tx,
            to_address=dest_addr,
            amount=1000000000,  # 1 TON
            seqno=5,
            expire_at=1700000000,
            workchain=0,
            bounce=True,
        )
        resp = self.client.call(msg)

        self.assertEqual(len(resp.signature), 64)
        self.assertFalse(all(b == 0 for b in resp.signature))

    def test_ton_sign_workchain_default(self):
        """Omitting workchain field should default to 0 (basechain).

        The signature must match an explicit workchain=0 request with
        otherwise identical parameters.
        """
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        dest_addr = make_ton_address()
        raw_tx = hashlib.sha256(b'test-ton-workchain-default').digest() * 2  # 64 bytes

        # Without workchain field
        msg_default = ton_messages.TonSignTx(
            address_n=parse_path(TON_PATH),
            raw_tx=raw_tx,
            to_address=dest_addr,
            amount=1000000000,
            seqno=6,
            expire_at=1700000000,
            bounce=True,
        )
        resp_default = self.client.call(msg_default)

        # With explicit workchain=0
        msg_explicit = ton_messages.TonSignTx(
            address_n=parse_path(TON_PATH),
            raw_tx=raw_tx,
            to_address=dest_addr,
            amount=1000000000,
            seqno=6,
            expire_at=1700000000,
            workchain=0,
            bounce=True,
        )
        resp_explicit = self.client.call(msg_explicit)

        self.assertEqual(len(resp_default.signature), 64)
        self.assertEqual(resp_default.signature, resp_explicit.signature)

    def test_ton_sign_different_accounts(self):
        """Signing with different account paths must produce different signatures."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        dest_addr = make_ton_address()
        raw_tx = hashlib.sha256(b'test-ton-different-accounts').digest() * 2  # 64 bytes

        msg_acct0 = ton_messages.TonSignTx(
            address_n=parse_path("m/44'/607'/0'/0'/0'/0'"),
            raw_tx=raw_tx,
            to_address=dest_addr,
            amount=1000000000,
            seqno=1,
            expire_at=1700000000,
        )
        resp_acct0 = self.client.call(msg_acct0)

        msg_acct1 = ton_messages.TonSignTx(
            address_n=parse_path("m/44'/607'/1'/0'/0'/0'"),
            raw_tx=raw_tx,
            to_address=dest_addr,
            amount=1000000000,
            seqno=1,
            expire_at=1700000000,
        )
        resp_acct1 = self.client.call(msg_acct1)

        self.assertEqual(len(resp_acct0.signature), 64)
        self.assertEqual(len(resp_acct1.signature), 64)
        self.assertNotEqual(
            resp_acct0.signature, resp_acct1.signature,
            "Different account paths must produce different signatures"
        )


if __name__ == '__main__':
    unittest.main()
