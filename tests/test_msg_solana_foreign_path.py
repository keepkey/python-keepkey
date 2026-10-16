# This file is part of the KeepKey project.
#
# Copyright (C) 2026 KeepKey
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
"""Solana's handlers sign with the key at the path the host names.

Outside m/44'/501' that is another coin's key. A TON wallet authorizes a
transfer with a raw Ed25519 signature over a 32-byte hash, so a "Solana
message" of 32 bytes signed on m/44'/607'/0' is a TON signature, shown under
Solana's screens. The handlers refuse such a path in every mode.
"""

import unittest

import common

from keepkeylib import messages_pb2 as proto
from keepkeylib import messages_solana_pb2 as solana_proto
from keepkeylib import types_pb2 as types
from keepkeylib.tools import parse_path

REFUSAL = "Invalid Solana path (expected m/44'/501'/...)"
FOREIGN = ("m/44'/607'/0'",      # TON
           "m/44'/60'/0'/0/0",   # Ethereum
           "m/501'/0'/0/0")      # no coin type at all


class TestMsgSolanaForeignPath(common.KeepKeyTest):

    def _ready(self):
        self.requires_firmware("7.15.0")
        self.requires_fullFeature()
        self.requires_message("SolanaSignMessage")
        self.requires_release_capability("solana-runtime-review")
        self.setup_mnemonic_allallall()

    def _refused(self, msg):
        # call_raw answers nothing: a ButtonRequest here would mean the
        # device started a review, or showed only a warning.
        resp = self.client.call_raw(msg)
        self.assertIsInstance(resp, proto.Failure)
        self.assertEqual(resp.code, types.Failure_SyntaxError)
        self.assertEqual(resp.message, REFUSAL)

    def test_a_message_is_not_signed_with_another_coins_key(self):
        self._ready()
        printable = b"A" * 32  # needs no AdvancedMode on a Solana path
        for advanced in (False, True):
            if advanced:
                self.client.apply_policy("AdvancedMode", 1)
            for path in FOREIGN:
                with self.subTest("%s advanced=%s" % (path, advanced)):
                    self._refused(solana_proto.SolanaSignMessage(
                        address_n=parse_path(path), message=printable))

    def test_an_address_is_not_derived_from_another_coins_key(self):
        self._ready()
        for path in FOREIGN:
            with self.subTest(path):
                self._refused(solana_proto.SolanaGetAddress(
                    address_n=parse_path(path)))

    def test_a_solana_path_still_signs_a_plain_message(self):
        self._ready()
        resp = self.client.solana_sign_message(
            parse_path("m/44'/501'/0'/0'"), b"A" * 32)
        self.assertEqual(len(resp.signature), 64)


if __name__ == '__main__':
    unittest.main()
