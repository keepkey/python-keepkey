# This file is part of the KeepKey project.
#
# Copyright (C) 2026 KeepKey
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.

"""Adversarial disclosure tests for security-relevant Solana instructions."""

import struct

import common
import pytest

from keepkeylib import messages_solana_pb2 as solana
from keepkeylib.client import CallException
from keepkeylib.tools import parse_path
from test_msg_display_disclosure import ScreenRecorder


PATH = parse_path("m/44'/501'/0'/0'")
TOKEN_PROGRAM = bytes.fromhex(
    "06ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a9"
)
TOKEN_2022_PROGRAM = bytes.fromhex(
    "06ddf6e1ee758fde18425dbce46ccddab61afc4d83b90d27febdf928d8a18bfc"
)
SYSTEM_PROGRAM = b"\x00" * 32
STAKE_PROGRAM = bytes.fromhex(
    "06a1d8179137542a983437bdfe2a7ab2557f535c8a78722b68a49dc000000000"
)
COMPUTE_BUDGET_PROGRAM = bytes.fromhex(
    "0306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a40000000"
)
VOTE_PROGRAM = bytes.fromhex(
    "0761481d357474bb7c4d7624ebd3bdb3d8355e73d11043fc0da3538000000000"
)
ATA_PROGRAM = bytes.fromhex(
    "8c97258f4e2489f1bb3d1029148e0d830b5a1399daff1084048e7bd8dbe9f859"
)


def build_tx(account_keys, required_signatures, instructions,
             readonly_unsigned=1):
    """Build an unsigned legacy message with explicit instruction indices."""
    tx = bytearray([0, required_signatures, 0, readonly_unsigned])
    tx.append(len(account_keys))
    for account in account_keys:
        tx.extend(account)
    tx.extend(b"\xbb" * 32)
    tx.append(len(instructions))
    for program_index, account_indices, data in instructions:
        tx.append(program_index)
        tx.append(len(account_indices))
        tx.extend(account_indices)
        tx.append(len(data))
        tx.extend(data)
    return bytes(tx)


class TestSolanaInstructionDisclosure(common.KeepKeyTest):
    def setUp(self):
        super(TestSolanaInstructionDisclosure, self).setUp()
        self.requires_fullFeature()
        self.requires_firmware("7.14.2")
        self.setup_mnemonic_allallall()
        response = self.client.call(solana.SolanaGetAddress(
            address_n=PATH, show_display=False
        ))
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        value = 0
        for char in response.address:
            value = value * 58 + alphabet.index(char)
        self.signer = value.to_bytes(32, "big")

    def _request(self, raw_tx):
        return solana.SolanaSignTx(address_n=PATH, raw_tx=raw_tx)

    def _capture(self, raw_tx, group):
        recorder = ScreenRecorder(
            self.client, answer=True, screenshot_group=group
        )
        try:
            with recorder:
                self.client.call(self._request(raw_tx))
        except CallException:
            return None
        return recorder.fingerprint

    def _assert_pair(self, label, raw_a, raw_b):
        screens_a = self._capture(raw_a, label + "-a")
        screens_b = self._capture(raw_b, label + "-b")
        self.assertIsNotNone(screens_a, label + " A was refused")
        self.assertIsNotNone(screens_b, label + " B was refused")
        self.assertNotEqual(
            screens_a, screens_b,
            label + " changed signed semantics without changing OLED review",
        )

    def test_set_authority_roles_require_opaque_mode(self):
        target = b"\x31" * 32
        new_authority = b"\x42" * 32
        keys = [self.signer, target, TOKEN_PROGRAM]
        for role in (0, 1, 2, 3):
            data = bytes([6, role, 1]) + new_authority
            raw_tx = build_tx(keys, 1, [(2, [1, 0], data)])
            with pytest.raises(CallException):
                self.client.call(self._request(raw_tx))

    def test_token_2022_transfer_checked_with_hook_accounts_is_opaque(self):
        mint = b"\x21" * 32
        destination = b"\x32" * 32
        hook_a = b"\x43" * 32
        hook_b = b"\x54" * 32
        data = bytes([12]) + struct.pack("<Q", 1000000) + bytes([6])
        for hook in (hook_a, hook_b):
            keys = [self.signer, mint, destination, hook, TOKEN_2022_PROGRAM]
            raw_tx = build_tx(keys, 1, [(4, [0, 1, 2, 0, 3], data)])
            with pytest.raises(CallException):
                self.client.call(self._request(raw_tx))

    def test_mint_and_burn_require_opaque_mode(self):
        mint = b"\x21" * 32
        account = b"\x32" * 32
        keys = [self.signer, mint, account, TOKEN_PROGRAM]
        instructions = (
            bytes([7]) + struct.pack("<Q", 1),
            bytes([14]) + struct.pack("<Q", 1) + bytes([6]),
            bytes([8]) + struct.pack("<Q", 1),
            bytes([15]) + struct.pack("<Q", 1) + bytes([6]),
        )
        for data in instructions:
            raw_tx = build_tx(keys, 1, [(3, [1, 2, 0], data)])
            with pytest.raises(CallException):
                self.client.call(self._request(raw_tx))

    def test_close_account_destination_changes_oled_review(self):
        source = b"\x25" * 32
        destination_a = b"\x36" * 32
        destination_b = b"\x47" * 32

        def make(destination):
            keys = [self.signer, source, destination, TOKEN_PROGRAM]
            return build_tx(keys, 1, [(3, [1, 2, 0], bytes([9]))])

        screens_a = self._capture(make(destination_a), "destination-a")
        screens_b = self._capture(make(destination_b), "destination-b")
        self.assertIsNotNone(screens_a)
        self.assertIsNotNone(screens_b)
        self.assertNotEqual(screens_a, screens_b)

    def test_priority_fee_payer_changes_oled_review(self):
        payer_a = b"\x18" * 32
        payer_b = b"\x29" * 32
        price = bytes([3]) + struct.pack("<Q", 50000000)
        limit = bytes([2]) + struct.pack("<I", 1400000)

        def make(payer):
            keys = [payer, self.signer, COMPUTE_BUDGET_PROGRAM]
            return build_tx(keys, 2, [(2, [], limit), (2, [], price)])

        screens_a = self._capture(make(payer_a), "payer-a")
        screens_b = self._capture(make(payer_b), "payer-b")
        self.assertIsNotNone(screens_a)
        self.assertIsNotNone(screens_b)
        self.assertNotEqual(screens_a, screens_b)

    def test_invalid_priority_fee_is_rejected_before_confirmation(self):
        price_a = bytes([3]) + struct.pack("<Q", 1)
        price_b = bytes([3]) + struct.pack("<Q", 2)
        raw_tx = build_tx(
            [self.signer, COMPUTE_BUDGET_PROGRAM],
            1,
            [(1, [], price_a), (1, [], price_b)],
        )
        recorder = ScreenRecorder(self.client, answer=True)
        with recorder:
            with pytest.raises(CallException):
                self.client.call(self._request(raw_tx))
        self.assertEqual(recorder.fingerprint, ())

    def test_vote_validator_uses_account_not_trailing_data(self):
        validator_a = b"\x61" * 32
        validator_b = b"\x72" * 32

        def make(validator):
            keys = [self.signer, validator, b"\x83" * 32, VOTE_PROGRAM]
            return build_tx(keys, 1, [(3, [0, 1, 2], struct.pack("<I", 4))])

        screens_a = self._capture(make(validator_a), "validator-a")
        screens_b = self._capture(make(validator_b), "validator-b")
        self.assertIsNotNone(screens_a)
        self.assertIsNotNone(screens_b)
        self.assertNotEqual(screens_a, screens_b)

        noncanonical = build_tx(
            [self.signer, validator_a, b"\x83" * 32, VOTE_PROGRAM],
            1,
            [(3, [0, 1, 2], struct.pack("<I", 4) + b"\x99" * 32)],
        )
        with pytest.raises(CallException):
            self.client.call(self._request(noncanonical))

    def test_all_verified_instruction_fields_change_oled_review(self):
        """Every newly disclosed clear-sign field has an independent A/B.

        Each pair changes exactly one signed semantic field while keeping the
        rest of the transaction fixed. A generic final confirmation cannot
        satisfy these comparisons; the changed account, role, mint or target
        must survive into the complete framebuffer sequence.
        """
        key = lambda value: bytes([value]) * 32
        u32 = lambda value: struct.pack("<I", value)
        u64 = lambda value: struct.pack("<Q", value)

        def one(program, accounts, indices, data, required=1):
            keys = list(accounts) + [program]
            return build_tx(
                keys, required, [(len(keys) - 1, indices, data)]
            )

        signer = self.signer
        cases = []

        # System program: acted-on accounts and nonce authority.
        cases.extend([
            ("system-transfer-source",
             one(SYSTEM_PROGRAM, [signer, key(10), key(11)], [1, 2],
                 u32(2) + u64(1), 2),
             one(SYSTEM_PROGRAM, [signer, key(12), key(11)], [1, 2],
                 u32(2) + u64(1), 2)),
            ("create-account-funder",
             one(SYSTEM_PROGRAM, [signer, key(13), key(14)], [1, 2],
                 u32(0) + u64(1) + u64(64) + key(15), 2),
             one(SYSTEM_PROGRAM, [signer, key(16), key(14)], [1, 2],
                 u32(0) + u64(1) + u64(64) + key(15), 2)),
            ("advance-nonce-account",
             one(SYSTEM_PROGRAM, [signer, key(17), key(18)], [1, 2, 0],
                 u32(4)),
             one(SYSTEM_PROGRAM, [signer, key(19), key(18)], [1, 2, 0],
                 u32(4))),
            ("withdraw-nonce-account",
             one(SYSTEM_PROGRAM,
                 [signer, key(20), key(21), key(22), key(23)],
                 [1, 2, 3, 4, 0], u32(5) + u64(1)),
             one(SYSTEM_PROGRAM,
                 [signer, key(24), key(21), key(22), key(23)],
                 [1, 2, 3, 4, 0], u32(5) + u64(1))),
            ("initialize-nonce-account",
             one(SYSTEM_PROGRAM, [signer, key(25), key(26), key(27)],
                 [1, 2, 3], u32(6) + key(28)),
             one(SYSTEM_PROGRAM, [signer, key(29), key(26), key(27)],
                 [1, 2, 3], u32(6) + key(28))),
            ("initialize-nonce-authority",
             one(SYSTEM_PROGRAM, [signer, key(25), key(26), key(27)],
                 [1, 2, 3], u32(6) + key(28)),
             one(SYSTEM_PROGRAM, [signer, key(25), key(26), key(27)],
                 [1, 2, 3], u32(6) + key(29))),
            ("authorize-nonce-account",
             one(SYSTEM_PROGRAM, [signer, key(30)], [1, 0],
                 u32(7) + key(31)),
             one(SYSTEM_PROGRAM, [signer, key(32)], [1, 0],
                 u32(7) + key(31))),
            ("assign-account",
             one(SYSTEM_PROGRAM, [signer, key(33)], [1],
                 u32(1) + key(34), 2),
             one(SYSTEM_PROGRAM, [signer, key(35)], [1],
                 u32(1) + key(34), 2)),
            ("allocate-account",
             one(SYSTEM_PROGRAM, [signer, key(36)], [1],
                 u32(8) + u64(64), 2),
             one(SYSTEM_PROGRAM, [signer, key(37)], [1],
                 u32(8) + u64(64), 2)),
        ])

        # Legacy SPL Token: source, mint and acted-on account binding.
        checked = bytes([12]) + u64(1000000) + bytes([6])
        cases.extend([
            ("token-checked-source",
             one(TOKEN_PROGRAM, [signer, key(38), key(39), key(40)],
                 [1, 2, 3, 0], checked),
             one(TOKEN_PROGRAM, [signer, key(41), key(39), key(40)],
                 [1, 2, 3, 0], checked)),
            ("token-revoke-account",
             one(TOKEN_PROGRAM, [signer, key(42)], [1, 0], bytes([5])),
             one(TOKEN_PROGRAM, [signer, key(43)], [1, 0], bytes([5]))),
            ("token-freeze-account",
             one(TOKEN_PROGRAM, [signer, key(52), key(53)], [1, 2, 0],
                 bytes([10])),
             one(TOKEN_PROGRAM, [signer, key(54), key(53)], [1, 2, 0],
                 bytes([10]))),
            ("token-freeze-mint",
             one(TOKEN_PROGRAM, [signer, key(52), key(53)], [1, 2, 0],
                 bytes([10])),
             one(TOKEN_PROGRAM, [signer, key(52), key(55)], [1, 2, 0],
                 bytes([10]))),
            ("token-thaw-account",
             one(TOKEN_PROGRAM, [signer, key(56), key(57)], [1, 2, 0],
                 bytes([11])),
             one(TOKEN_PROGRAM, [signer, key(58), key(57)], [1, 2, 0],
                 bytes([11]))),
            ("token-thaw-mint",
             one(TOKEN_PROGRAM, [signer, key(56), key(57)], [1, 2, 0],
                 bytes([11])),
             one(TOKEN_PROGRAM, [signer, key(56), key(59)], [1, 2, 0],
                 bytes([11]))),
            ("token-sync-native-account",
             one(TOKEN_PROGRAM, [signer, key(60)], [1], bytes([17])),
             one(TOKEN_PROGRAM, [signer, key(61)], [1], bytes([17]))),
        ])

        # Stake and vote program authority roles and acted-on accounts.
        cases.extend([
            ("stake-delegate-account",
             one(STAKE_PROGRAM,
                 [signer, key(62), key(63), key(64), key(65), key(66)],
                 [1, 2, 3, 4, 5, 0], u32(2)),
             one(STAKE_PROGRAM,
                 [signer, key(67), key(63), key(64), key(65), key(66)],
                 [1, 2, 3, 4, 5, 0], u32(2))),
            ("stake-delegate-vote",
             one(STAKE_PROGRAM,
                 [signer, key(62), key(63), key(64), key(65), key(66)],
                 [1, 2, 3, 4, 5, 0], u32(2)),
             one(STAKE_PROGRAM,
                 [signer, key(62), key(68), key(64), key(65), key(66)],
                 [1, 2, 3, 4, 5, 0], u32(2))),
            ("stake-withdraw-account",
             one(STAKE_PROGRAM,
                 [signer, key(69), key(70), key(71), key(72)],
                 [1, 2, 3, 4, 0], u32(4) + u64(1)),
             one(STAKE_PROGRAM,
                 [signer, key(73), key(70), key(71), key(72)],
                 [1, 2, 3, 4, 0], u32(4) + u64(1))),
            ("stake-authorize-account",
             one(STAKE_PROGRAM, [signer, key(74), key(75)], [1, 2, 0],
                 u32(1) + key(76) + u32(0)),
             one(STAKE_PROGRAM, [signer, key(77), key(75)], [1, 2, 0],
                 u32(1) + key(76) + u32(0))),
            ("stake-authorize-role",
             one(STAKE_PROGRAM, [signer, key(74), key(75)], [1, 2, 0],
                 u32(1) + key(76) + u32(0)),
             one(STAKE_PROGRAM, [signer, key(74), key(75)], [1, 2, 0],
                 u32(1) + key(76) + u32(1))),
            ("stake-split-account",
             one(STAKE_PROGRAM, [signer, key(78), key(79)], [1, 2, 0],
                 u32(3) + u64(1)),
             one(STAKE_PROGRAM, [signer, key(80), key(79)], [1, 2, 0],
                 u32(3) + u64(1))),
            ("stake-deactivate-account",
             one(STAKE_PROGRAM, [signer, key(81), key(82)], [1, 2, 0],
                 u32(5)),
             one(STAKE_PROGRAM, [signer, key(83), key(82)], [1, 2, 0],
                 u32(5))),
            ("stake-merge-source",
             one(STAKE_PROGRAM,
                 [signer, key(84), key(85), key(86), key(87)],
                 [1, 2, 3, 4, 0], u32(7)),
             one(STAKE_PROGRAM,
                 [signer, key(84), key(88), key(86), key(87)],
                 [1, 2, 3, 4, 0], u32(7))),
            ("stake-merge-destination",
             one(STAKE_PROGRAM,
                 [signer, key(84), key(85), key(86), key(87)],
                 [1, 2, 3, 4, 0], u32(7)),
             one(STAKE_PROGRAM,
                 [signer, key(89), key(85), key(86), key(87)],
                 [1, 2, 3, 4, 0], u32(7))),
            ("vote-authorize-account",
             one(VOTE_PROGRAM, [signer, key(90), key(91)], [1, 2, 0],
                 u32(1) + key(92) + u32(0)),
             one(VOTE_PROGRAM, [signer, key(93), key(91)], [1, 2, 0],
                 u32(1) + key(92) + u32(0))),
            ("vote-authorize-role",
             one(VOTE_PROGRAM, [signer, key(90), key(91)], [1, 2, 0],
                 u32(1) + key(92) + u32(0)),
             one(VOTE_PROGRAM, [signer, key(90), key(91)], [1, 2, 0],
                 u32(1) + key(92) + u32(1))),
            ("vote-withdraw-account",
             one(VOTE_PROGRAM, [signer, key(94), key(95)], [1, 2, 0],
                 u32(3) + u64(1)),
             one(VOTE_PROGRAM, [signer, key(96), key(95)], [1, 2, 0],
                 u32(3) + u64(1))),
            ("vote-validator-account",
             one(VOTE_PROGRAM, [signer, key(97), key(98)], [1, 2, 0],
                 u32(4)),
             one(VOTE_PROGRAM, [signer, key(99), key(98)], [1, 2, 0],
                 u32(4))),
            ("vote-commission-account",
             one(VOTE_PROGRAM, [signer, key(100)], [1, 0],
                 u32(5) + bytes([5])),
             one(VOTE_PROGRAM, [signer, key(101)], [1, 0],
                 u32(5) + bytes([5]))),
        ])

        # Associated token account: resulting account, owner, and mint.
        def ata(ata_account, owner, mint):
            accounts = [signer, ata_account, owner, mint,
                        SYSTEM_PROGRAM, TOKEN_PROGRAM]
            return one(ATA_PROGRAM, accounts, [0, 1, 2, 3, 4, 5], b"")

        cases.extend([
            ("ata-account", ata(key(102), key(103), key(104)),
             ata(key(105), key(103), key(104))),
            ("ata-owner", ata(key(102), key(103), key(104)),
             ata(key(102), key(106), key(104))),
            ("ata-mint", ata(key(102), key(103), key(104)),
             ata(key(102), key(103), key(107))),
        ])

        for label, raw_a, raw_b in cases:
            self._assert_pair(label, raw_a, raw_b)

    def test_token_2022_associated_account_is_opaque(self):
        accounts = [self.signer, b"\x41" * 32, b"\x42" * 32,
                    b"\x43" * 32, SYSTEM_PROGRAM, TOKEN_2022_PROGRAM,
                    ATA_PROGRAM]
        raw_tx = build_tx(
            accounts, 1, [(6, [0, 1, 2, 3, 4, 5], b"")]
        )
        with pytest.raises(CallException):
            self.client.call(self._request(raw_tx))
