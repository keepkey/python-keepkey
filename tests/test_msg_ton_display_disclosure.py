# This file is part of the KeepKey project.
#
# Copyright (C) 2026 KeepKey
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.

"""TON raw-message review must disclose every signed byte."""

import common

from keepkeylib import messages_ton_pb2 as ton
from keepkeylib.client import CallException
from keepkeylib.tools import parse_path
from test_msg_display_disclosure import ScreenRecorder


PATH = parse_path("m/44'/607'/0'/0'/0'/0'")


class TestTonDisplayDisclosure(common.KeepKeyTest):
    def setUp(self):
        super(TestTonDisplayDisclosure, self).setUp()
        self.requires_firmware("7.14.2")
        self.requires_message("TonSignMessage")
        self.setup_mnemonic_allallall()
        self.client.apply_policy("AdvancedMode", True)

    def _capture(self, payload, group):
        recorder = ScreenRecorder(
            self.client, answer=True, screenshot_group=group
        )
        try:
            with recorder:
                self.client.call(ton.TonSignMessage(
                    address_n=PATH,
                    message=payload,
                ))
        except CallException:
            return None
        return recorder.fingerprint

    def test_raw_message_tail_changes_oled_review(self):
        payload_a = b"A" * 192
        payload_b = payload_a[:96] + b"B" + payload_a[97:]
        self.assertEqual(payload_a[:32], payload_b[:32])

        screens_a = self._capture(payload_a, "payload-a")
        screens_b = self._capture(payload_b, "payload-b")
        self.assertIsNotNone(screens_a)
        self.assertIsNotNone(screens_b)
        self.assertGreater(len(screens_a), 1)
        self.assertGreater(len(screens_b), 1)
        self.assertNotEqual(
            screens_a,
            screens_b,
            "a TON byte after the old 32-byte preview was not disclosed",
        )
