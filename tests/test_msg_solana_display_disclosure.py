# This file is part of the KeepKey project.
#
# Copyright (C) 2026 KeepKey
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.

"""Solana display/sign disclosure regressions for firmware 7.14.2."""

from __future__ import print_function

import common

from keepkeylib import messages_solana_pb2 as solana
from keepkeylib.client import CallException
from keepkeylib.tools import parse_path
from test_msg_display_disclosure import ScreenRecorder


ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
PATH = parse_path("m/44'/501'/0'/0'")


def b58decode_pubkey(value):
    number = 0
    for char in value:
        number = number * 58 + ALPHABET.index(char)
    return number.to_bytes(32, "big")


def compact_u16(value):
    encoded = []
    while True:
        byte = value & 0x7f
        value >>= 7
        encoded.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(encoded)


def build_memo_tx(signer, memo):
    memo_program = b58decode_pubkey(
        "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
    )
    return (
        bytes([1, 0, 1, 2])
        + signer
        + memo_program
        + bytes([0xbb]) * 32
        + bytes([1, 1, 0])
        + compact_u16(len(memo))
        + memo
    )


class TestSolanaDisplayDisclosure(common.KeepKeyTest):
    def setUp(self):
        super(TestSolanaDisplayDisclosure, self).setUp()
        self.requires_fullFeature()
        self.requires_firmware("7.14.2")
        self.setup_mnemonic_allallall()

    def _capture(self, request, screenshot_group):
        recorder = ScreenRecorder(
            self.client,
            answer=True,
            screenshot_group=screenshot_group,
        )
        try:
            with recorder:
                self.client.call(request)
        except CallException:
            return None
        return recorder.fingerprint

    def _assert_tail_mutation_changes_review(self, make_request):
        payload_a = b"A" * 160
        payload_b = payload_a[:96] + b"B" + payload_a[97:]
        self.assertEqual(payload_a[:32], payload_b[:32])

        screens_a = self._capture(make_request(payload_a), "payload-a")
        screens_b = self._capture(make_request(payload_b), "payload-b")
        self.assertIsNotNone(screens_a)
        self.assertIsNotNone(screens_b)
        self.assertGreater(len(screens_a), 1)
        self.assertGreater(len(screens_b), 1)
        self.assertNotEqual(
            screens_a,
            screens_b,
            "a signed byte after the old 32-byte preview was not disclosed",
        )

    def test_raw_message_tail_changes_oled_review(self):
        self.client.apply_policy("AdvancedMode", True)
        self._assert_tail_mutation_changes_review(
            lambda payload: solana.SolanaSignMessage(
                address_n=PATH,
                message=payload,
            )
        )

    def test_offchain_message_tail_changes_oled_review(self):
        self._assert_tail_mutation_changes_review(
            lambda payload: solana.SolanaSignOffchainMessage(
                address_n=PATH,
                version=0,
                message_format=0,
                message=payload,
            )
        )

    def test_offchain_format_changes_oled_review(self):
        payload = b"same signed message"
        screens_ascii = self._capture(
            solana.SolanaSignOffchainMessage(
                address_n=PATH,
                version=0,
                message_format=0,
                message=payload,
            ),
            "format-ascii",
        )
        screens_utf8 = self._capture(
            solana.SolanaSignOffchainMessage(
                address_n=PATH,
                version=0,
                message_format=1,
                message=payload,
            ),
            "format-utf8",
        )
        self.assertIsNotNone(screens_ascii)
        self.assertIsNotNone(screens_utf8)
        self.assertNotEqual(
            screens_ascii,
            screens_utf8,
            "the signed off-chain format was not bound to the OLED review",
        )

    def test_memo_tail_changes_oled_review(self):
        address = self.client.call(
            solana.SolanaGetAddress(address_n=PATH, show_display=False)
        ).address
        signer = b58decode_pubkey(address)
        self._assert_tail_mutation_changes_review(
            lambda payload: solana.SolanaSignTx(
                address_n=PATH,
                raw_tx=build_memo_tx(signer, payload),
            )
        )
