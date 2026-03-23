# This file is part of the KeepKey project.
#
# Copyright (C) 2025 KeepKey
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.

import pytest
import unittest
import common
import binascii
import struct

from keepkeylib import messages_solana_pb2 as messages
from keepkeylib import types_pb2 as types
from keepkeylib.client import CallException
from keepkeylib.tools import parse_path


def build_system_transfer_tx(from_pubkey, to_pubkey, lamports, blockhash=None):
    """Build a minimal Solana system transfer transaction."""
    if blockhash is None:
        blockhash = b'\xBB' * 32

    system_program = b'\x00' * 32

    tx = bytearray()

    # Header
    tx.append(1)   # num_required_sigs
    tx.append(0)   # num_readonly_signed
    tx.append(1)   # num_readonly_unsigned

    # 3 accounts (compact-u16)
    tx.append(3)

    # Account keys
    tx.extend(from_pubkey)
    tx.extend(to_pubkey)
    tx.extend(system_program)

    # Recent blockhash
    tx.extend(blockhash)

    # 1 instruction (compact-u16)
    tx.append(1)

    # Instruction: system transfer
    tx.append(2)    # program_id index (system program at index 2)
    tx.append(2)    # 2 account indices
    tx.append(0)    # from
    tx.append(1)    # to
    tx.append(12)   # data length

    # Transfer instruction: type=2 (LE u32) + lamports (LE u64)
    tx.extend(struct.pack('<I', 2))
    tx.extend(struct.pack('<Q', lamports))

    return bytes(tx)


class TestMsgSolanaSignTx(common.KeepKeyTest):

    def test_solana_get_address(self):
        """Test Solana address derivation from device."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        msg = messages.SolanaGetAddress(
            address_n=parse_path("m/44'/501'/0'/0'"),
            show_display=False,
        )
        resp = self.client.call(msg)

        # Address should be a Base58-encoded 32-byte pubkey
        self.assertIsNotNone(resp.address)
        self.assertGreater(len(resp.address), 30)

    def test_solana_sign_system_transfer(self):
        """Test Solana system transfer signing."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        from_pubkey = b'\x11' * 32
        to_pubkey = b'\x22' * 32
        raw_tx = build_system_transfer_tx(from_pubkey, to_pubkey, 1000000000)

        msg = messages.SolanaSignTx(
            address_n=parse_path("m/44'/501'/0'/0'"),
            raw_tx=raw_tx,
        )
        resp = self.client.call(msg)

        # Should have a 64-byte Ed25519 signature
        self.assertEqual(len(resp.signature), 64)
        self.assertFalse(all(b == 0 for b in resp.signature))

    def test_solana_sign_message(self):
        """Test Solana arbitrary message signing."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        msg = messages.SolanaSignMessage(
            address_n=parse_path("m/44'/501'/0'/0'"),
            message=b"Hello Solana!",
            show_display=True,
        )
        resp = self.client.call(msg)

        self.assertEqual(len(resp.signature), 64)
        self.assertEqual(len(resp.public_key), 32)

    def test_solana_sign_empty_rejected(self):
        """Test that empty raw_tx is rejected."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        msg = messages.SolanaSignTx(
            address_n=parse_path("m/44'/501'/0'/0'"),
        )

        with pytest.raises(CallException):
            self.client.call(msg)

    def test_solana_sign_deterministic(self):
        """Test that signing same transaction produces same signature."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        from_pubkey = b'\x11' * 32
        to_pubkey = b'\x22' * 32
        raw_tx = build_system_transfer_tx(from_pubkey, to_pubkey, 1000000000)

        msg1 = messages.SolanaSignTx(
            address_n=parse_path("m/44'/501'/0'/0'"),
            raw_tx=raw_tx,
        )
        resp1 = self.client.call(msg1)

        msg2 = messages.SolanaSignTx(
            address_n=parse_path("m/44'/501'/0'/0'"),
            raw_tx=raw_tx,
        )
        resp2 = self.client.call(msg2)

        # Ed25519 signatures are deterministic
        self.assertEqual(resp1.signature, resp2.signature)


if __name__ == '__main__':
    unittest.main()
