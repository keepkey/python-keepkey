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

    # Signature count (compact-u16: 0 signatures for unsigned tx)
    tx.append(0)

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
        """Test Solana message signing -- requires AdvancedMode (7.15+).
        Solana message signing has no domain separation (trezor #4371),
        so it's gated behind AdvancedMode to prevent blind-sign attacks."""
        self.requires_fullFeature()
        self.requires_message("SolanaSignMessage")
        self.setup_mnemonic_allallall()
        self.client.apply_policy('AdvancedMode', True)

        msg = messages.SolanaSignMessage(
            address_n=parse_path("m/44'/501'/0'/0'"),
            message=b"Hello Solana!",
            show_display=True,
        )
        resp = self.client.call(msg)

        self.assertEqual(len(resp.signature), 64)
        self.assertEqual(len(resp.public_key), 32)
        self.client.apply_policy('AdvancedMode', False)

    def test_solana_sign_message_blocked_without_advanced_mode(self):
        """Solana message signing BLOCKED without AdvancedMode.
        Without domain separation, a signed message is indistinguishable from
        a signed transaction. Device refuses to sign without explicit opt-in."""
        self.requires_firmware("7.14.0")
        self.requires_fullFeature()
        self.requires_message("SolanaSignMessage")
        self.setup_mnemonic_allallall()
        self.client.apply_policy('AdvancedMode', False)

        with pytest.raises(CallException) as exc:
            self.client.call(messages.SolanaSignMessage(
                address_n=parse_path("m/44'/501'/0'/0'"),
                message=b"Hello Solana!",
            ))
        self.assertIn("disabled by policy", str(exc.value))

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
        tx.append(0)  # signature count (compact-u16: 0 = unsigned)
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
        """Unchecked SPL Transfer has no signed mint (the token being moved is
        not provable), so it now requires AdvancedMode (blind-sign); only the
        TransferChecked variant clear-signs."""
        self.requires_fullFeature()
        self.requires_firmware("7.14.2")
        self.setup_mnemonic_allallall()
        from keepkeylib.client import CallException
        from_pubkey = self._get_from_pubkey()
        to_account = b'\x33' * 32  # destination token account
        # SPL Token Transfer instruction: opcode=3 (u8) + amount (LE u64)
        instr_data = bytes([3]) + struct.pack('<Q', 50000000)  # 50M tokens
        raw_tx = self._build_tx(
            from_pubkey, [to_account, from_pubkey], self.TOKEN_PROGRAM,
            instr_data)
        tx = messages.SolanaSignTx(
            address_n=parse_path("m/44'/501'/0'/0'"), raw_tx=raw_tx)

        self.client.apply_policy('AdvancedMode', False)
        with self.assertRaises(CallException):
            self.client.call(tx)

        self.client.apply_policy('AdvancedMode', True)
        resp = self.client.call(tx)
        self.assertEqual(len(resp.signature), 64)
        self.client.apply_policy('AdvancedMode', False)

    def test_solana_sign_token_approve(self):
        """Unchecked SPL Approve hides the delegated token's mint, so it now
        requires AdvancedMode (blind-sign)."""
        self.requires_fullFeature()
        self.requires_firmware("7.14.2")
        self.setup_mnemonic_allallall()
        from keepkeylib.client import CallException
        from_pubkey = self._get_from_pubkey()
        delegate = b'\x44' * 32
        # SPL Token Approve: opcode=4 (u8) + amount (LE u64)
        instr_data = bytes([4]) + struct.pack('<Q', 100000000)
        raw_tx = self._build_tx(
            from_pubkey, [delegate, from_pubkey], self.TOKEN_PROGRAM,
            instr_data)
        tx = messages.SolanaSignTx(
            address_n=parse_path("m/44'/501'/0'/0'"), raw_tx=raw_tx)

        self.client.apply_policy('AdvancedMode', False)
        with self.assertRaises(CallException):
            self.client.call(tx)

        self.client.apply_policy('AdvancedMode', True)
        resp = self.client.call(tx)
        self.assertEqual(len(resp.signature), 64)
        self.client.apply_policy('AdvancedMode', False)

    def test_solana_sign_create_account_requires_advanced_mode(self):
        """SystemProgram CreateAccount assigns the new account's owner program
        and space (not shown on-screen), so it is gated behind AdvancedMode."""
        self.requires_firmware("7.15.0")  # unchecked-SPL AdvancedMode gating landed in 7.15
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        from keepkeylib.client import CallException
        from_pubkey = self._get_from_pubkey()
        new_account = b'\x55' * 32
        instr_data = struct.pack('<I', 0) + struct.pack('<Q', 1000000)  # create + lamports
        raw_tx = self._build_tx(from_pubkey, [new_account], self.SYSTEM_PROGRAM, instr_data)
        tx = messages.SolanaSignTx(
            address_n=parse_path("m/44'/501'/0'/0'"), raw_tx=raw_tx)
        self.client.apply_policy('AdvancedMode', False)
        with self.assertRaises(CallException):
            self.client.call(tx)
        self.client.apply_policy('AdvancedMode', True)
        resp = self.client.call(tx)
        self.assertEqual(len(resp.signature), 64)
        self.client.apply_policy('AdvancedMode', False)

    def test_solana_sign_set_authority_requires_advanced_mode(self):
        """SPL SetAuthority hands over control of a mint/account; the target and
        the 'clear authority' (None) case are not fully disclosed, so it is
        gated behind AdvancedMode."""
        self.requires_firmware("7.15.0")  # unchecked-SPL AdvancedMode gating landed in 7.15
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        from keepkeylib.client import CallException
        from_pubkey = self._get_from_pubkey()
        authority = b'\x66' * 32
        instr_data = bytes([6, 2])  # SetAuthority, authority_type=AccountOwner
        raw_tx = self._build_tx(from_pubkey, [authority], self.TOKEN_PROGRAM, instr_data)
        tx = messages.SolanaSignTx(
            address_n=parse_path("m/44'/501'/0'/0'"), raw_tx=raw_tx)
        self.client.apply_policy('AdvancedMode', False)
        with self.assertRaises(CallException):
            self.client.call(tx)
        self.client.apply_policy('AdvancedMode', True)
        resp = self.client.call(tx)
        self.assertEqual(len(resp.signature), 64)
        self.client.apply_policy('AdvancedMode', False)

    def test_solana_sign_stake_authorize_clearsigns(self):
        """StakeAuthorize clear-signs, showing the role (staker/withdrawer) and
        the new authority."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        from_pubkey = self._get_from_pubkey()
        clock_sysvar = b'\x66' * 32
        current_auth = b'\x77' * 32
        new_auth = b'\x88' * 32
        # Authorize (type=1 LE u32) + new authority(32) + StakeAuthorize role (0=staker)
        instr_data = struct.pack('<I', 1) + new_auth + struct.pack('<I', 0)
        # Canonical account order: stake, clock sysvar, current authority.
        raw_tx = self._build_tx(
            from_pubkey, [clock_sysvar, current_auth], self.STAKE_PROGRAM, instr_data)
        resp = self.client.call(messages.SolanaSignTx(
            address_n=parse_path("m/44'/501'/0'/0'"), raw_tx=raw_tx))
        self.assertEqual(len(resp.signature), 64)

    def test_solana_sign_stake_delegate(self):
        """Stake delegate — OLED shows 'Delegate stake?'."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        from_pubkey = self._get_from_pubkey()
        vote_account = b'\x66' * 32
        # Stake Delegate: type=2 (LE u32)
        instr_data = struct.pack('<I', 2)
        raw_tx = self._build_tx(
            from_pubkey,
            [vote_account, b'\x77' * 32, b'\x88' * 32, b'\x99' * 32,
             from_pubkey],
            self.STAKE_PROGRAM,
            instr_data,
        )
        resp = self.client.call(messages.SolanaSignTx(
            address_n=parse_path("m/44'/501'/0'/0'"), raw_tx=raw_tx))
        self.assertEqual(len(resp.signature), 64)

    def test_solana_sign_stake_withdraw(self):
        """Stake withdraw — OLED shows 'Withdraw [amount] from stake?'."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        from_pubkey = self._get_from_pubkey()
        destination = b'\x55' * 32
        # Stake Withdraw: type=4 (LE u32) + lamports (LE u64)
        instr_data = struct.pack('<I', 4) + struct.pack('<Q', 2000000000)  # 2 SOL
        raw_tx = self._build_tx(
            from_pubkey,
            [destination, b'\x77' * 32, b'\x88' * 32, from_pubkey],
            self.STAKE_PROGRAM,
            instr_data,
        )
        resp = self.client.call(messages.SolanaSignTx(
            address_n=parse_path("m/44'/501'/0'/0'"), raw_tx=raw_tx))
        self.assertEqual(len(resp.signature), 64)

    def test_solana_sign_stake_deactivate(self):
        """Stake deactivate — OLED shows 'Deactivate stake?'."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        from_pubkey = self._get_from_pubkey()
        # Stake Deactivate: type=5 (LE u32)
        instr_data = struct.pack('<I', 5)
        raw_tx = self._build_tx(
            from_pubkey, [b'\x55' * 32, from_pubkey], self.STAKE_PROGRAM,
            instr_data
        )
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


    # ================================================================
    # Negative / rejection tests
    # ================================================================

    def test_solana_sign_malformed_truncated(self):
        """Reject raw_tx that is too short to contain header + accounts."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        raw_tx = b'\x00\x01\x00\x01\x01'  # 5 bytes — header says 1 account but no data

        with pytest.raises(CallException):
            self.client.call(messages.SolanaSignTx(
                address_n=parse_path("m/44'/501'/0'/0'"),
                raw_tx=raw_tx,
            ))

    def test_solana_sign_malformed_bad_account_count(self):
        """Reject raw_tx whose header claims 33 accounts (exceeds 32 limit)."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        tx = bytearray()
        tx.append(0)    # sig count
        tx.append(1)    # num_required_sigs
        tx.append(0)    # num_readonly_signed
        tx.append(1)    # num_readonly_unsigned
        tx.append(33)   # 33 accounts — over the 32-account parser limit
        # Pad 33 fake 32-byte account keys
        for _ in range(33):
            tx.extend(b'\xAA' * 32)
        tx.extend(b'\xBB' * 32)  # blockhash
        tx.append(0)    # 0 instructions

        with pytest.raises(CallException):
            self.client.call(messages.SolanaSignTx(
                address_n=parse_path("m/44'/501'/0'/0'"),
                raw_tx=bytes(tx),
            ))

    def test_solana_sign_malformed_trailing_bytes(self):
        """Reject a valid transaction that has extra trailing bytes."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        from_pubkey = self._get_from_pubkey()
        to_pubkey = b'\x22' * 32
        raw_tx = build_system_transfer_tx(from_pubkey, to_pubkey, 1000000000)

        # Append 10 trailing garbage bytes
        raw_tx_bad = raw_tx + b'\xFF' * 10

        with pytest.raises(CallException):
            self.client.call(messages.SolanaSignTx(
                address_n=parse_path("m/44'/501'/0'/0'"),
                raw_tx=raw_tx_bad,
            ))

    def test_solana_sign_oversized_raw_tx(self):
        """Reject raw_tx that exceeds the proto max_size (1232 bytes)."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        # 1233 bytes — one byte over the nanopb field limit
        raw_tx = b'\x00' * 1233

        with pytest.raises(CallException):
            self.client.call(messages.SolanaSignTx(
                address_n=parse_path("m/44'/501'/0'/0'"),
                raw_tx=raw_tx,
            ))

    # ================================================================
    # Multi-instruction tests
    # ================================================================

    def test_solana_sign_multi_instruction_2x_transfer(self):
        """Two system transfers in a single transaction."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        from_pubkey = self._get_from_pubkey()
        to_pubkey_1 = b'\x22' * 32
        to_pubkey_2 = b'\x33' * 32
        system_program = self.SYSTEM_PROGRAM
        blockhash = b'\xBB' * 32

        tx = bytearray()
        tx.append(0)    # sig count
        tx.append(1)    # num_required_sigs
        tx.append(0)    # num_readonly_signed
        tx.append(1)    # num_readonly_unsigned (system program)

        # 4 accounts: from, to_1, to_2, system_program
        tx.append(4)
        tx.extend(from_pubkey)
        tx.extend(to_pubkey_1)
        tx.extend(to_pubkey_2)
        tx.extend(system_program)

        tx.extend(blockhash)

        # 2 instructions
        tx.append(2)

        # Instruction 1: transfer 1 SOL to to_1
        tx.append(3)    # program_id index (system program)
        tx.append(2)    # 2 account indices
        tx.append(0)    # from
        tx.append(1)    # to_1
        instr1 = struct.pack('<I', 2) + struct.pack('<Q', 1000000000)
        tx.append(len(instr1))
        tx.extend(instr1)

        # Instruction 2: transfer 2 SOL to to_2
        tx.append(3)    # program_id index (system program)
        tx.append(2)    # 2 account indices
        tx.append(0)    # from
        tx.append(2)    # to_2
        instr2 = struct.pack('<I', 2) + struct.pack('<Q', 2000000000)
        tx.append(len(instr2))
        tx.extend(instr2)

        resp = self.client.call(messages.SolanaSignTx(
            address_n=parse_path("m/44'/501'/0'/0'"),
            raw_tx=bytes(tx),
        ))
        self.assertEqual(len(resp.signature), 64)
        self.assertFalse(all(b == 0 for b in resp.signature))

    def test_solana_sign_multi_instruction_transfer_and_memo(self):
        """System transfer + memo instruction in a single transaction."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        from_pubkey = self._get_from_pubkey()
        to_pubkey = b'\x22' * 32
        system_program = self.SYSTEM_PROGRAM
        memo_program = self.MEMO_PROGRAM
        blockhash = b'\xBB' * 32

        tx = bytearray()
        tx.append(0)    # sig count
        tx.append(1)    # num_required_sigs
        tx.append(0)    # num_readonly_signed
        tx.append(2)    # num_readonly_unsigned (system_program + memo_program)

        # 4 accounts: from, to, system_program, memo_program
        tx.append(4)
        tx.extend(from_pubkey)
        tx.extend(to_pubkey)
        tx.extend(system_program)
        tx.extend(memo_program)

        tx.extend(blockhash)

        # 2 instructions
        tx.append(2)

        # Instruction 1: system transfer 1 SOL
        tx.append(2)    # program_id index (system program)
        tx.append(2)    # 2 account indices
        tx.append(0)    # from
        tx.append(1)    # to
        instr1 = struct.pack('<I', 2) + struct.pack('<Q', 1000000000)
        tx.append(len(instr1))
        tx.extend(instr1)

        # Instruction 2: memo
        tx.append(3)    # program_id index (memo program)
        tx.append(1)    # 1 account index (signer)
        tx.append(0)    # from (signer)
        memo_data = b"payment for services"
        tx.append(len(memo_data))
        tx.extend(memo_data)

        resp = self.client.call(messages.SolanaSignTx(
            address_n=parse_path("m/44'/501'/0'/0'"),
            raw_tx=bytes(tx),
        ))
        self.assertEqual(len(resp.signature), 64)
        self.assertFalse(all(b == 0 for b in resp.signature))

    # ================================================================
    # Token metadata (token_info) tests
    # ================================================================

    def test_solana_sign_token_transfer_with_metadata(self):
        """Host SolanaTokenInfo does NOT make an unchecked transfer clear-signable:
        the mint is not signed, so the metadata is unauthenticated and the tx
        still requires AdvancedMode. (TransferChecked binds the mint on-chain.)"""
        self.requires_firmware("7.15.0")  # unchecked-SPL AdvancedMode gating landed in 7.15
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        from keepkeylib.client import CallException

        from_pubkey = self._get_from_pubkey()
        to_account = b'\x33' * 32  # destination token account

        # USDC mint (EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v)
        usdc_mint = bytes([
            0xc6, 0xfa, 0x7a, 0xf3, 0xbe, 0xdb, 0xad, 0x3a,
            0x3d, 0x65, 0xf3, 0x6a, 0xab, 0xc9, 0x74, 0x31,
            0xb1, 0xbb, 0xe4, 0xc2, 0xd2, 0xf6, 0xe0, 0xe4,
            0x7c, 0xa6, 0x02, 0x03, 0x45, 0x2f, 0x5d, 0x61,
        ])

        # TransferChecked signs the mint and decimals. Unchecked Transfer is
        # deliberately opaque because it carries neither.
        instr_data = bytes([12]) + struct.pack('<Q', 1000000) + bytes([6])
        raw_tx = self._build_tx(
            from_pubkey,
            [usdc_mint, to_account, from_pubkey],
            self.TOKEN_PROGRAM,
            instr_data,
        )

        token_info = messages.SolanaTokenInfo(
            mint=usdc_mint,
            symbol="USDC",
            decimals=6,
        )

        tx = messages.SolanaSignTx(
            address_n=parse_path("m/44'/501'/0'/0'"),
            raw_tx=raw_tx,
            token_info=[token_info],
        )
        self.client.apply_policy('AdvancedMode', False)
        with self.assertRaises(CallException):
            self.client.call(tx)

        self.client.apply_policy('AdvancedMode', True)
        resp = self.client.call(tx)
        self.assertEqual(len(resp.signature), 64)
        self.assertFalse(all(b == 0 for b in resp.signature))
        self.client.apply_policy('AdvancedMode', False)

    def test_solana_sign_token_transfer_checked(self):
        """TransferChecked (op 12) CLEAR-SIGNS with AdvancedMode OFF: the mint
        is part of the signed instruction bytes, so the device shows it on its
        own dedicated OLED screen ("Token mint <base58>") before the amount —
        the authenticated token identity cannot be pushed off-view by a
        host-controlled symbol. The (unattested) host token_info symbol is
        shown next to the amount, and decimals come from the signed
        instruction, never from the host."""
        self.requires_firmware("7.15.0")
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        from_pubkey = self._get_from_pubkey()
        to_account = b'\x33' * 32   # destination token account
        authority = b'\x44' * 32    # transfer authority

        # USDC mint (EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v)
        usdc_mint = bytes([
            0xc6, 0xfa, 0x7a, 0xf3, 0xbe, 0xdb, 0xad, 0x3a,
            0x3d, 0x65, 0xf3, 0x6a, 0xab, 0xc9, 0x74, 0x31,
            0xb1, 0xbb, 0xe4, 0xc2, 0xd2, 0xf6, 0xe0, 0xe4,
            0x7c, 0xa6, 0x02, 0x03, 0x45, 0x2f, 0x5d, 0x61,
        ])

        # TransferChecked: opcode=12 (u8) + amount (LE u64) + decimals (u8);
        # accounts [source, mint, destination, authority]
        instr_data = bytes([12]) + struct.pack('<Q', 1500000) + bytes([6])
        raw_tx = self._build_tx(from_pubkey, [usdc_mint, to_account, authority],
                                self.TOKEN_PROGRAM, instr_data)

        token_info = messages.SolanaTokenInfo(
            mint=usdc_mint,
            symbol="USDC",
            decimals=6,
        )

        self.client.apply_policy('AdvancedMode', False)
        resp = self.client.call(messages.SolanaSignTx(
            address_n=parse_path("m/44'/501'/0'/0'"),
            raw_tx=raw_tx,
            token_info=[token_info],
        ))
        self.assertEqual(len(resp.signature), 64)
        self.assertFalse(all(b == 0 for b in resp.signature))

    def test_solana_sign_token_transfer_checked_attested_symbol(self):
        """Signed token definition: the token_info carries a secp256k1
        attestation over (mint, decimals, symbol) by a signer the user loaded
        via LoadClearsignSigner — the same chain-agnostic trust anchor EVM
        clear-sign metadata uses. The device verifies it and shows an extra
        'Token "USDC" signed by <alias> <fingerprint>' screen; decimals must
        also match the signed instruction bytes or the symbol is not trusted.
        Runtime identities require AdvancedMode."""
        self.requires_firmware("7.15.0")
        self.requires_fullFeature()
        self.requires_message("LoadClearsignSigner")
        self.setup_mnemonic_allallall()
        import hashlib
        from ecdsa import SigningKey, SECP256k1
        from ecdsa.util import sigencode_string
        from keepkeylib.signed_metadata import (
            TEST_PRIVATE_KEY, test_signer_compressed_pubkey,
            assert_test_key_matches_slot3)

        # Load the CI signer into slot 3 through the production trust path
        # (device confirm auto-acked by debuglink) — phase 1 has no built-ins.
        assert_test_key_matches_slot3()
        self.client.apply_policy('AdvancedMode', True)
        self.client.load_clearsign_signer(
            key_id=3,
            pubkey=test_signer_compressed_pubkey(),
            alias="CI Test",
        )

        from_pubkey = self._get_from_pubkey()
        to_account = b'\x33' * 32
        authority = b'\x44' * 32
        usdc_mint = bytes([
            0xc6, 0xfa, 0x7a, 0xf3, 0xbe, 0xdb, 0xad, 0x3a,
            0x3d, 0x65, 0xf3, 0x6a, 0xab, 0xc9, 0x74, 0x31,
            0xb1, 0xbb, 0xe4, 0xc2, 0xd2, 0xf6, 0xe0, 0xe4,
            0x7c, 0xa6, 0x02, 0x03, 0x45, 0x2f, 0x5d, 0x61,
        ])
        decimals = 6
        symbol = "USDC"

        # TransferChecked with decimals matching the attested value.
        instr_data = bytes([12]) + struct.pack('<Q', 1500000) + bytes([decimals])
        raw_tx = self._build_tx(from_pubkey, [usdc_mint, to_account, authority],
                                self.TOKEN_PROGRAM, instr_data)

        # Attestation preimage exactly as solana_token_info_trusted() builds it:
        # "KeepKeySolanaTokenDef/1" || mint(32) || decimals(le32) || symbol.
        preimage = (b"KeepKeySolanaTokenDef/1" + usdc_mint +
                    struct.pack('<I', decimals) + symbol.encode('ascii'))
        digest = hashlib.sha256(preimage).digest()
        sk = SigningKey.from_string(TEST_PRIVATE_KEY, curve=SECP256k1)
        # RFC 6979 deterministic; 64-byte compact r||s, what
        # signed_metadata_verify_attestation feeds ecdsa_verify_digest.
        sig64 = sk.sign_digest_deterministic(
            digest, hashfunc=hashlib.sha256, sigencode=sigencode_string)

        token_info = messages.SolanaTokenInfo(
            mint=usdc_mint,
            symbol=symbol,
            decimals=decimals,
            signature=sig64,
            signer_key_id=3,
        )

        self.client.apply_policy('AdvancedMode', True)
        resp = self.client.call(messages.SolanaSignTx(
            address_n=parse_path("m/44'/501'/0'/0'"),
            raw_tx=raw_tx,
            token_info=[token_info],
        ))
        self.assertEqual(len(resp.signature), 64)
        self.assertFalse(all(b == 0 for b in resp.signature))

    # ================================================================
    # Path edge-case tests
    # ================================================================

    def test_solana_path_3_elements(self):
        """Non-standard 3-element path m/44'/501'/0' — should still derive and sign."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        # Get address with 3-element path
        addr_resp = self.client.call(messages.SolanaGetAddress(
            address_n=parse_path("m/44'/501'/0'"),
            show_display=False,
        ))
        ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        n = 0
        for c in addr_resp.address:
            n = n * 58 + ALPHABET.index(c)
        from_pubkey = n.to_bytes(32, 'big')
        to_pubkey = b'\x22' * 32

        raw_tx = build_system_transfer_tx(from_pubkey, to_pubkey, 500000000)

        resp = self.client.call(messages.SolanaSignTx(
            address_n=parse_path("m/44'/501'/0'"),
            raw_tx=raw_tx,
        ))
        self.assertEqual(len(resp.signature), 64)
        self.assertFalse(all(b == 0 for b in resp.signature))

    def test_solana_path_wrong_coin_type(self):
        """Path with Ethereum coin type m/44'/60'/0'/0' — firmware should reject or warn."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        # Build a minimal valid-looking tx with a dummy from_pubkey
        from_pubkey = b'\x11' * 32
        to_pubkey = b'\x22' * 32
        raw_tx = build_system_transfer_tx(from_pubkey, to_pubkey, 100000000)

        with pytest.raises(CallException):
            self.client.call(messages.SolanaSignTx(
                address_n=parse_path("m/44'/60'/0'/0'"),
                raw_tx=raw_tx,
            ))

    # ================================================================
    # Versioned transaction test
    # ================================================================

    def test_solana_sign_versioned_v0_static_verified(self):
        """Versioned v0 transaction whose instructions only touch static
        accounts (no address lookup table references) is exactly as
        verifiable as a legacy message — it clear-signs without requiring
        AdvancedMode."""
        self.requires_firmware("7.15.0")  # Solana versioned (v0) parsing landed in 7.15
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        from_pubkey = self._get_from_pubkey()

        # Build a versioned v0 transaction:
        # byte 0x80 = version prefix (bit 7 set = versioned, bits 0-6 = version 0)
        # Then a minimal legacy-format body after the version byte
        to_pubkey = b'\x22' * 32
        system_program = self.SYSTEM_PROGRAM
        blockhash = b'\xBB' * 32

        tx = bytearray()
        tx.append(0x80)  # version prefix: v0

        # Header
        tx.append(1)    # num_required_sigs
        tx.append(0)    # num_readonly_signed
        tx.append(1)    # num_readonly_unsigned

        # 3 accounts
        tx.append(3)
        tx.extend(from_pubkey)
        tx.extend(to_pubkey)
        tx.extend(system_program)

        # Recent blockhash
        tx.extend(blockhash)

        # 1 instruction
        tx.append(1)
        tx.append(2)    # program_id index
        tx.append(2)    # 2 account indices
        tx.append(0)    # from
        tx.append(1)    # to
        instr_data = struct.pack('<I', 2) + struct.pack('<Q', 1000000000)
        tx.append(len(instr_data))
        tx.extend(instr_data)

        # Address table lookups: 0 entries
        tx.append(0)

        raw_tx = bytes(tx)

        self.client.apply_policy('AdvancedMode', False)
        resp = self.client.call(messages.SolanaSignTx(
            address_n=parse_path("m/44'/501'/0'/0'"),
            raw_tx=raw_tx,
        ))
        self.assertEqual(len(resp.signature), 64)
        self.assertFalse(all(b == 0 for b in resp.signature))

    def test_solana_sign_x402_zero_lut_usdc_payment(self):
        """Official x402 SVM shape clear-signs without blind signing.

        The sponsor is fee payer, the KeepKey key is the token authority, the
        payment is TransferChecked, and payTo is supplied separately so the
        device must derive and verify its associated token account itself.
        """
        self.requires_firmware("7.15.0")
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        authority = self._get_from_pubkey()
        sponsor = b'\x10' * 32
        source = b'\x30' * 32
        pay_to = bytes([
            0xea, 0x4a, 0x6c, 0x63, 0xe2, 0x9c, 0x52, 0x0a,
            0xbe, 0xf5, 0x50, 0x7b, 0x13, 0x2e, 0xc5, 0xf9,
            0x95, 0x47, 0x76, 0xae, 0xbe, 0xbe, 0x7b, 0x92,
            0x42, 0x1e, 0xea, 0x69, 0x14, 0x46, 0xd2, 0x2c,
        ])
        destination_ata = bytes([
            0x67, 0x30, 0x2e, 0x49, 0x18, 0x94, 0xd7, 0x49,
            0x2e, 0xa6, 0xbe, 0x4f, 0x91, 0x4e, 0xa4, 0xf4,
            0x5f, 0xa1, 0x42, 0xe6, 0x45, 0x86, 0x7c, 0x91,
            0x64, 0xa2, 0x76, 0xd5, 0xdd, 0x76, 0xf0, 0x76,
        ])
        usdc_mint = bytes([
            0xc6, 0xfa, 0x7a, 0xf3, 0xbe, 0xdb, 0xad, 0x3a,
            0x3d, 0x65, 0xf3, 0x6a, 0xab, 0xc9, 0x74, 0x31,
            0xb1, 0xbb, 0xe4, 0xc2, 0xd2, 0xf6, 0xe0, 0xe4,
            0x7c, 0xa6, 0x02, 0x03, 0x45, 0x2f, 0x5d, 0x61,
        ])

        accounts = [
            sponsor, authority, source, destination_ata, usdc_mint,
            self.COMPUTE_BUDGET_PROGRAM, self.TOKEN_PROGRAM,
            self.MEMO_PROGRAM,
        ]
        raw_tx = bytearray([0x80, 2, 0, 3, len(accounts)])
        for account in accounts:
            raw_tx.extend(account)
        raw_tx.extend(b'\xbb' * 32)
        raw_tx.append(4)

        # ComputeBudget::SetComputeUnitLimit(120000)
        raw_tx.extend(bytes([5, 0, 5, 2]))
        raw_tx.extend(struct.pack('<I', 120000))
        # ComputeBudget::SetComputeUnitPrice(1000 micro-lamports)
        raw_tx.extend(bytes([5, 0, 9, 3]))
        raw_tx.extend(struct.pack('<Q', 1000))
        # SPL TransferChecked(source, mint, destination ATA, authority)
        raw_tx.extend(bytes([6, 4, 2, 4, 3, 1, 10, 12]))
        raw_tx.extend(struct.pack('<Q', 2000))
        raw_tx.append(6)
        # Required x402 uniqueness memo: a 16-byte nonce encoded as hex.
        memo = b'00112233445566778899aabbccddeeff'
        raw_tx.extend(bytes([7, 1, 1, len(memo)]))
        raw_tx.extend(memo)
        raw_tx.append(0)  # zero address-lookup tables

        token_info = messages.SolanaTokenInfo(
            mint=usdc_mint, symbol="USDC", decimals=6)
        self.client.apply_policy('AdvancedMode', False)
        response = self.client.solana_sign_tx(
            parse_path("m/44'/501'/0'/0'"), bytes(raw_tx),
            token_info=[token_info], token_recipient_owner=[pay_to])
        self.assertEqual(len(response.signature), 64)
        self.assertFalse(all(b == 0 for b in response.signature))

    def test_solana_sign_versioned_v0_opaque(self):
        """Versioned v0 transaction whose instruction reaches into an address
        lookup table (an account index at or beyond the static account
        count) cannot be verified on-device — requires AdvancedMode for
        blind/opaque signing."""
        self.requires_firmware("7.15.0")  # Solana versioned (v0) parsing landed in 7.15
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        from_pubkey = self._get_from_pubkey()

        system_program = self.SYSTEM_PROGRAM
        blockhash = b'\xBB' * 32
        lookup_table = b'\x33' * 32

        tx = bytearray()
        tx.append(0x80)  # version prefix: v0

        # Header
        tx.append(1)    # num_required_sigs
        tx.append(0)    # num_readonly_signed
        tx.append(1)    # num_readonly_unsigned

        # 2 static accounts — the transfer destination is resolved via the
        # address lookup table below, not listed here.
        tx.append(2)
        tx.extend(from_pubkey)
        tx.extend(system_program)

        # Recent blockhash
        tx.extend(blockhash)

        # 1 instruction referencing account index 2 — beyond the 2 static
        # accounts, so it resolves via the address lookup table.
        tx.append(1)
        tx.append(1)    # program_id index (system_program)
        tx.append(2)    # 2 account indices
        tx.append(0)    # from (static)
        tx.append(2)    # to (external — loaded from the ALT)
        instr_data = struct.pack('<I', 2) + struct.pack('<Q', 1000000000)
        tx.append(len(instr_data))
        tx.extend(instr_data)

        # Address table lookups: 1 entry, 1 writable index
        tx.append(1)
        tx.extend(lookup_table)
        tx.append(1)    # writable_count
        tx.append(0)    # writable index 0 (into the ALT)
        tx.append(0)    # readonly_count

        raw_tx = bytes(tx)

        # Without AdvancedMode, an ALT-referencing versioned tx should be rejected
        self.client.apply_policy('AdvancedMode', False)
        with pytest.raises(CallException):
            self.client.call(messages.SolanaSignTx(
                address_n=parse_path("m/44'/501'/0'/0'"),
                raw_tx=raw_tx,
            ))

        # With AdvancedMode, it should succeed (opaque/blind sign)
        self.client.apply_policy('AdvancedMode', True)
        resp = self.client.call(messages.SolanaSignTx(
            address_n=parse_path("m/44'/501'/0'/0'"),
            raw_tx=raw_tx,
        ))
        self.assertEqual(len(resp.signature), 64)
        self.assertFalse(all(b == 0 for b in resp.signature))
        self.client.apply_policy('AdvancedMode', False)


if __name__ == '__main__':
    unittest.main()
