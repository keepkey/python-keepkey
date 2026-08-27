# This file is part of the KeepKey project.
#
# Copyright (C) 2026 KeepKey
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.

"""Every byte passed through firmware ``confirm_data`` must reach the OLED."""

from __future__ import print_function

import binascii

import common

from keepkeylib import messages_eos_pb2 as eos_messages
from keepkeylib import types_pb2 as types
from keepkeylib.tools import parse_path
from test_msg_display_disclosure import ScreenRecorder


PREV_HASH = binascii.unhexlify(
    "d5f65ee80147b4bcc70b75e4bbf2d738"
    "2021b871bd8867ef8fa525ef50864882"
)
EOS_PATH = parse_path("m/44'/194'/0'/0/0")


class TestConfirmDataDisclosure(common.KeepKeyTest):
    def setUp(self):
        super(TestConfirmDataDisclosure, self).setUp()
        self.requires_firmware("7.14.2")
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()

    def _capture_op_return(self, payload, group):
        tx_input = types.TxInputType(
            address_n=[0], prev_hash=PREV_HASH, prev_index=0
        )
        payment = types.TxOutputType(
            address="1MJ2tj2ThBE62zXbBYA5ZaN3fdve5CPAz1",
            amount=380000,
            script_type=types.PAYTOADDRESS,
        )
        data_output = types.TxOutputType(
            op_return_data=payload,
            amount=0,
            script_type=types.PAYTOOPRETURN,
        )
        recorder = ScreenRecorder(
            self.client, answer=True, screenshot_group=group
        )
        with recorder:
            _, serialized = self.client.sign_tx(
                "Bitcoin", [tx_input], [payment, data_output]
            )
        return recorder.fingerprint, serialized

    def _capture_eos_memo(self, memo, group):
        transaction = {
            "chain_id": (
                "cf057bbfb72640471fd910bcb67639c22"
                "df9f92470936cddc1ade0e2f2e7dc4f"
            ),
            "transaction": {
                "expiration": "2018-07-14T07:43:28",
                "ref_block_num": 6439,
                "ref_block_prefix": 2995713264,
                "max_net_usage_words": 0,
                "max_cpu_usage_ms": 0,
                "delay_sec": 0,
                "context_free_actions": [],
                "actions": [{
                    "account": "eosio.token",
                    "name": "transfer",
                    "authorization": [{
                        "actor": "miniminimini",
                        "permission": "active",
                    }],
                    "data": {
                        "from": "miniminimini",
                        "to": "maximaximaxi",
                        "quantity": "1.0000 EOS",
                        "memo": memo,
                    },
                }],
                "transaction_extensions": [],
            },
        }
        recorder = ScreenRecorder(
            self.client, answer=True, screenshot_group=group
        )
        with recorder:
            signed = self.client.eos_sign_tx(EOS_PATH, transaction)
        signature = (
            bytes(signed.signature_r),
            bytes(signed.signature_s),
            signed.signature_v,
        )
        return recorder.fingerprint, signature

    def test_binary_op_return_tail_changes_oled_review(self):
        """A byte after the old 50-byte binary preview must be displayed."""
        common_prefix = b"\x80" + b"A" * 79
        payload_a = common_prefix + b"X" * 16
        payload_b = common_prefix + b"Y" + b"X" * 15

        screens_a, signed_a = self._capture_op_return(payload_a, "opreturn-a")
        # Run each member of the A/B pair from the same clean device state.
        # Multi-page review ends with a held confirmation, so merely opening a
        # new protocol session can retain a trailing emulator button event.
        self.client.wipe_device()
        self.setup_mnemonic_nopin_nopassphrase()
        screens_b, signed_b = self._capture_op_return(payload_b, "opreturn-b")

        self.assertNotEqual(signed_a, signed_b)
        self.assertGreater(len(screens_a), 1)
        self.assertGreater(len(screens_b), 1)
        self.assertNotEqual(
            screens_a, screens_b,
            "different signed OP_RETURN tails produced identical OLED review",
        )

    def test_non_ascii_eos_memo_tail_changes_oled_review(self):
        """A UTF-8 memo byte after the old 50-byte preview must be displayed."""
        common_prefix = "\u00e9" + "A" * 79
        memo_a = common_prefix + "X" * 16
        memo_b = common_prefix + "Y" + "X" * 15

        screens_a, signed_a = self._capture_eos_memo(memo_a, "eos-a")
        self.client.wipe_device()
        self.setup_mnemonic_nopin_nopassphrase()
        screens_b, signed_b = self._capture_eos_memo(memo_b, "eos-b")

        self.assertNotEqual(signed_a, signed_b)
        self.assertGreater(len(screens_a), 1)
        self.assertGreater(len(screens_b), 1)
        self.assertNotEqual(
            screens_a, screens_b,
            "different signed EOS memo tails produced identical OLED review",
        )

    def test_unknown_omni_property_changes_oled_review(self):
        """Unsupported Omni assets must disclose bytes, not a shared ticker."""
        header = b"omni\x00\x00\x00\x00" + (999999).to_bytes(4, "big")
        payload_a = header + (1).to_bytes(8, "big")
        payload_b = header + (2).to_bytes(8, "big")

        screens_a, signed_a = self._capture_op_return(payload_a, "omni-prop-a")
        self.client.wipe_device()
        self.setup_mnemonic_nopin_nopassphrase()
        screens_b, signed_b = self._capture_op_return(payload_b, "omni-prop-b")

        self.assertNotEqual(signed_a, signed_b)
        self.assertNotEqual(
            screens_a, screens_b,
            "different unsupported Omni assets produced identical OLED review",
        )

    def test_unknown_omni_type_changes_oled_review(self):
        """Unsupported Omni operations must disclose the complete payload."""
        header = b"omni\x00\x00\x00\x01" + (31).to_bytes(4, "big")
        payload_a = header + (1).to_bytes(8, "big")
        payload_b = header + (2).to_bytes(8, "big")

        screens_a, signed_a = self._capture_op_return(payload_a, "omni-type-a")
        self.client.wipe_device()
        self.setup_mnemonic_nopin_nopassphrase()
        screens_b, signed_b = self._capture_op_return(payload_b, "omni-type-b")

        self.assertNotEqual(signed_a, signed_b)
        self.assertNotEqual(
            screens_a, screens_b,
            "different unsupported Omni operations produced identical review",
        )


if __name__ == "__main__":
    import unittest
    unittest.main()
