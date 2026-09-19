# This file is part of the KeepKey project.

"""Arbitrary Ethereum calldata approval must bind to every streamed byte."""

from __future__ import print_function

import binascii
import unittest

import common

from keepkeylib.tools import parse_path
from test_msg_display_disclosure import ScreenRecorder


class TestEthereumDataDisclosure(common.KeepKeyTest):
    PATH = parse_path("m/44'/60'/0'/0/0")
    CONTRACT = binascii.unhexlify(
        "4c82d1fbfe28c977cbb58d8c7ff8fcf9f70a2cca"
    )

    def setUp(self):
        super(TestEthereumDataDisclosure, self).setUp()
        self.requires_firmware("7.14.2")
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        self.client.apply_policy("AdvancedMode", 1)

    def _capture(self, data, group):
        recorder = ScreenRecorder(
            self.client, answer=True, screenshot_group=group
        )
        with recorder:
            signature = self.client.ethereum_sign_tx(
                n=self.PATH,
                nonce=0,
                gas_price=20000000000,
                gas_limit=200000,
                to=self.CONTRACT,
                value=0,
                chain_id=1,
                data=data,
            )
        return recorder.fingerprint, signature

    def _assert_pair(self, data_a, data_b, group_a, group_b):
        screens_a, signature_a = self._capture(data_a, group_a)
        self.client.wipe_device()
        self.setup_mnemonic_allallall()
        self.client.apply_policy("AdvancedMode", 1)
        screens_b, signature_b = self._capture(data_b, group_b)
        self.assertNotEqual(signature_a, signature_b)
        self.assertGreater(len(screens_a), 1)
        self.assertGreater(len(screens_b), 1)
        self.assertNotEqual(
            screens_a, screens_b,
            "different calldata produced identical complete OLED approval",
        )

    def test_initial_chunk_tail_changes_data_hash_screen(self):
        prefix = b"\xde\xad\xbe\xef" + b"A" * 60
        self._assert_pair(
            prefix + b"X" * 32,
            prefix + b"Y" + b"X" * 31,
            "initial-a", "initial-b",
        )

    def test_streamed_tail_changes_data_hash_screen(self):
        prefix = b"\xde\xad\xbe\xef" + b"A" * 1296
        self._assert_pair(
            prefix + b"X" * 32,
            prefix + b"Y" + b"X" * 31,
            "streamed-a", "streamed-b",
        )


if __name__ == "__main__":
    unittest.main()
