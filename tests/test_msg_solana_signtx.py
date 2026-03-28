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

    def setUp(self):
        super().setUp()
        self.requires_firmware("7.14.0")
        self.requires_message("SolanaGetAddress")

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

        # Get the actual derived pubkey from the device (must match the tx signer)
        addr_resp = self.client.call(messages.SolanaGetAddress(
            address_n=parse_path("m/44'/501'/0'/0'"),
            show_display=False,
        ))
        # Decode base58 address to raw 32-byte pubkey
        ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        n = 0
        for c in addr_resp.address:
            n = n * 58 + ALPHABET.index(c)
        from_pubkey = n.to_bytes(32, 'big')
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

        # Get the actual derived pubkey from the device
        addr_resp = self.client.call(messages.SolanaGetAddress(
            address_n=parse_path("m/44'/501'/0'/0'"),
            show_display=False,
        ))
        ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        n = 0
        for c in addr_resp.address:
            n = n * 58 + ALPHABET.index(c)
        from_pubkey = n.to_bytes(32, 'big')
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

    # --- Helper: get from_pubkey from device ---
    def _get_from_pubkey(self):
        addr_resp = self.client.call(messages.SolanaGetAddress(
            address_n=parse_path("m/44'/501'/0'/0'"),
            show_display=False,
        ))
        ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        n = 0
        for c in addr_resp.address:
            n = n * 58 + ALPHABET.index(c)
        return n.to_bytes(32, 'big')

    # --- Helper: build transaction with arbitrary instruction ---
    def _build_tx(self, from_pubkey, accounts, program_id, instr_data, extra_accounts=None):
        """Build a Solana transaction with one instruction.
        accounts: list of 32-byte pubkeys (in addition to from_pubkey and program_id)
        """
        all_accounts = [from_pubkey] + (extra_accounts or []) + accounts + [program_id]
        blockhash = b'\xBB' * 32
        tx = bytearray()
        tx.append(1)  # num_required_sigs
        tx.append(0)  # num_readonly_signed
        tx.append(1 + len(accounts) + (len(extra_accounts) if extra_accounts else 0))  # num_readonly_unsigned
        tx.append(len(all_accounts))  # num accounts
        for acc in all_accounts:
            tx.extend(acc)
        tx.extend(blockhash)
        tx.append(1)  # 1 instruction
        tx.append(len(all_accounts) - 1)  # program_id index (last)
        num_acc_indices = 1 + len(accounts) + (len(extra_accounts) if extra_accounts else 0)
        tx.append(num_acc_indices)  # num account indices
        for i in range(num_acc_indices):
            tx.append(i)  # account indices
        tx.append(len(instr_data))
        tx.extend(instr_data)
        return bytes(tx)

    # --- Program ID constants ---
    SYSTEM_PROGRAM = b'\x00' * 32
    TOKEN_PROGRAM = bytes([0x06, 0xdd, 0xf6, 0xe1, 0xd7, 0x65, 0xa1, 0x93,
        0xd9, 0xcb, 0xe1, 0x46, 0xce, 0xeb, 0x79, 0xac,
        0x1c, 0xb4, 0x85, 0xed, 0x5f, 0x5b, 0x37, 0x91,
        0x3a, 0x8c, 0xf5, 0x85, 0x7e, 0xff, 0x00, 0xa9])
    STAKE_PROGRAM = bytes([0x06, 0xa1, 0xd8, 0x17, 0x91, 0x37, 0x54, 0x2a,
        0x98, 0x34, 0x37, 0xbd, 0xfe, 0x2a, 0x7a, 0xb2,
        0x55, 0x7f, 0x53, 0x5c, 0x8a, 0x78, 0x72, 0x2b,
        0x68, 0xa4, 0x9d, 0xc0, 0x00, 0x00, 0x00, 0x00])
    COMPUTE_BUDGET_PROGRAM = bytes([0x03, 0x06, 0x46, 0x6f, 0xe5, 0x21, 0x17, 0x32,
        0xff, 0xec, 0xad, 0xba, 0x72, 0xc3, 0x9b, 0xe7,
        0xbc, 0x8c, 0xe5, 0xbb, 0xc5, 0xf7, 0x12, 0x6b,
        0x2c, 0x43, 0x9b, 0x3a, 0x40, 0x00, 0x00, 0x00])
    MEMO_PROGRAM = bytes([0x05, 0x4a, 0x53, 0x5a, 0x99, 0x29, 0x21, 0x06,
        0x4d, 0x24, 0xe8, 0x71, 0x60, 0xda, 0x38, 0x7c,
        0x7c, 0x35, 0xb5, 0xdd, 0xbc, 0x92, 0xbb, 0x81,
        0xe4, 0x1f, 0xa8, 0x40, 0x41, 0x05, 0x44, 0x8d])
    ATA_PROGRAM = bytes([0x8c, 0x97, 0x25, 0x8f, 0x4e, 0x24, 0x89, 0xf1,
        0xbb, 0x3d, 0x10, 0x29, 0x14, 0x8e, 0x0d, 0x83,
        0x0b, 0x5a, 0x13, 0x99, 0xda, 0xff, 0x10, 0x84,
        0x04, 0x8e, 0x7b, 0xd8, 0xdb, 0xe9, 0xf8, 0x59])

    # ================================================================
    # Clear-sign instruction tests — one per program type
    # Each test produces OLED screenshots showing the parsed instruction
    # ================================================================

    def test_solana_sign_token_transfer(self):
        """SPL Token transfer — OLED shows 'Send [amount] tokens to [address]'."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        from_pubkey = self._get_from_pubkey()
        to_account = b'\x33' * 32  # destination token account
        owner = from_pubkey  # token owner = signer
        # SPL Token Transfer instruction: opcode=3 (u8) + amount (LE u64)
        instr_data = bytes([3]) + struct.pack('<Q', 50000000)  # 50M tokens
        raw_tx = self._build_tx(from_pubkey, [to_account], self.TOKEN_PROGRAM, instr_data)
        resp = self.client.call(messages.SolanaSignTx(
            address_n=parse_path("m/44'/501'/0'/0'"), raw_tx=raw_tx))
        self.assertEqual(len(resp.signature), 64)

    def test_solana_sign_token_approve(self):
        """SPL Token approve — OLED shows 'Approve [amount] tokens to [delegate]'."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        from_pubkey = self._get_from_pubkey()
        delegate = b'\x44' * 32
        # SPL Token Approve: opcode=4 (u8) + amount (LE u64)
        instr_data = bytes([4]) + struct.pack('<Q', 100000000)
        raw_tx = self._build_tx(from_pubkey, [delegate], self.TOKEN_PROGRAM, instr_data)
        resp = self.client.call(messages.SolanaSignTx(
            address_n=parse_path("m/44'/501'/0'/0'"), raw_tx=raw_tx))
        self.assertEqual(len(resp.signature), 64)

    def test_solana_sign_stake_delegate(self):
        """Stake delegate — OLED shows 'Delegate stake?'."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        from_pubkey = self._get_from_pubkey()
        stake_account = b'\x55' * 32
        vote_account = b'\x66' * 32
        # Stake Delegate: type=2 (LE u32)
        instr_data = struct.pack('<I', 2)
        raw_tx = self._build_tx(from_pubkey, [stake_account, vote_account],
                                self.STAKE_PROGRAM, instr_data)
        resp = self.client.call(messages.SolanaSignTx(
            address_n=parse_path("m/44'/501'/0'/0'"), raw_tx=raw_tx))
        self.assertEqual(len(resp.signature), 64)

    def test_solana_sign_stake_withdraw(self):
        """Stake withdraw — OLED shows 'Withdraw [amount] from stake?'."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        from_pubkey = self._get_from_pubkey()
        stake_account = b'\x55' * 32
        # Stake Withdraw: type=4 (LE u32) + lamports (LE u64)
        instr_data = struct.pack('<I', 4) + struct.pack('<Q', 2000000000)  # 2 SOL
        raw_tx = self._build_tx(from_pubkey, [stake_account], self.STAKE_PROGRAM, instr_data)
        resp = self.client.call(messages.SolanaSignTx(
            address_n=parse_path("m/44'/501'/0'/0'"), raw_tx=raw_tx))
        self.assertEqual(len(resp.signature), 64)

    def test_solana_sign_stake_deactivate(self):
        """Stake deactivate — OLED shows 'Deactivate stake?'."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        from_pubkey = self._get_from_pubkey()
        stake_account = b'\x55' * 32
        # Stake Deactivate: type=5 (LE u32)
        instr_data = struct.pack('<I', 5)
        raw_tx = self._build_tx(from_pubkey, [stake_account], self.STAKE_PROGRAM, instr_data)
        resp = self.client.call(messages.SolanaSignTx(
            address_n=parse_path("m/44'/501'/0'/0'"), raw_tx=raw_tx))
        self.assertEqual(len(resp.signature), 64)

    def test_solana_sign_compute_budget_unit_price(self):
        """Compute budget set unit price — OLED shows 'Set unit price to [N] microlamports?'."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        from_pubkey = self._get_from_pubkey()
        # ComputeBudget SetComputeUnitPrice: type=3 (u8) + price (LE u64)
        instr_data = bytes([3]) + struct.pack('<Q', 50000)  # 50000 microlamports
        raw_tx = self._build_tx(from_pubkey, [], self.COMPUTE_BUDGET_PROGRAM, instr_data)
        resp = self.client.call(messages.SolanaSignTx(
            address_n=parse_path("m/44'/501'/0'/0'"), raw_tx=raw_tx))
        self.assertEqual(len(resp.signature), 64)

    def test_solana_sign_memo(self):
        """Memo program — OLED shows memo text."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        from_pubkey = self._get_from_pubkey()
        memo_text = b"KeepKey 7.14.0 test memo"
        raw_tx = self._build_tx(from_pubkey, [], self.MEMO_PROGRAM, memo_text)
        resp = self.client.call(messages.SolanaSignTx(
            address_n=parse_path("m/44'/501'/0'/0'"), raw_tx=raw_tx))
        self.assertEqual(len(resp.signature), 64)


if __name__ == '__main__':
    unittest.main()
