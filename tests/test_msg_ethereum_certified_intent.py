# This file is part of the KeepKey project.
#
# Copyright (C) 2026 KeepKey
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
"""SRS-7.16 §3.7: the certified EVM review states who, what, why and limits.

RELAY_ENVELOPE is the exact signedPayload the deployed ClearSign Worker
returned on 2026-10-02 (source revision 6a33fd944) for POST /v1/evm/schema
with the chainId 1 Relay bridgeDeposit shape. It is deterministic: the same
request returns the same bytes. Its inner schema is version 0x05.
"""

import unittest

import common
from keepkeylib.tools import parse_path
from oled_text import TITLE_FONT, find_line, find_text, shows
from test_msg_display_disclosure import ScreenRecorder

RELAY_ENVELOPE = bytes.fromhex(
    "030101000000016b359b004b6565704b657920416c7068612037313600000000"
    "00000000000000000000000342f5f9704494b3f9bd72295eecaf29d783d23ea0"
    "2b2dc9f48abcd2e46d4850cffc4364672f0172aa70ed21eacc2ea8bd0d333119"
    "ddf048b096686e1a8e56bda438f9e70b9cfc229a1e93e2d91846c31c4083d8b1"
    "76e225d76341069dd22826cf05000000014cd00e387622c35bddb9b4c962c136"
    "462338bc3149290c1c000d6272696467654465706f73697402096465706f7369"
    "746f720100076f7264657249640300030552656c617936427269646765207b76"
    "7d207468726f7567682052656c617920666f72207b307d3b2064656c69766572"
    "792069732062792052656c6179010000000080dd0b0e67378e8447342c826ef3"
    "89149bb5adf8e2bab1e51cfe1ebc561b547acd1ad3360a774730273035fd962f"
    "bb3d01dc75044ffee8d26680558957c6a5db521c")
RELAY = bytes.fromhex("4cd00e387622c35bddb9b4c962c136462338bc31")
DEPOSITOR = bytes.fromhex("909ef6b32dfdc12ca86aa710b54c991af3c5f82e")
ORDER_ID = bytes.fromhex(
    "8a2c121197efc95c42f53142ab409735ee353287f877ed4d351f63094d5bfcb1")
VALUE = 7988 * 10**12  # 0.007988 ETH
CLASSIFICATION_VERIFIED = 1
KEYID_DELEGATE = 0x80


class TestEthereumCertifiedIntent(common.KeepKeyTest):

    def setUp(self):
        super(TestEthereumCertifiedIntent, self).setUp()
        self.requires_firmware("7.16.0")
        self.requires_message("EthereumTxMetadata")
        self.setup_mnemonic_allallall()

    def _sign(self):
        data = (bytes.fromhex("49290c1c") + b"\0" * 12 + DEPOSITOR + ORDER_ID)
        recorder = ScreenRecorder(self.client, answer=True,
                                  screenshot_group="eth-certified-intent")
        with recorder:
            sig = self.client.ethereum_sign_tx(
                n=parse_path("m/44'/60'/0'/0/0"), nonce=0, gas_price=20 * 10**9,
                gas_limit=100000, to=RELAY, value=VALUE, data=data, chain_id=1)
        return sig, recorder.screens

    def assertShows(self, screens, title, body):
        for i, screen in enumerate(screens):
            if (find_line(screen, title, TITLE_FONT) is not None and
                    shows(screen, body)):
                return i
        self.fail("no screen titled %r shows %r" % (title, body))

    def test_relay_bridge_deposit_reads_as_a_sentence_with_limits(self):
        resp = self.client.ethereum_send_tx_metadata(
            signed_payload=RELAY_ENVELOPE, metadata_version=3,
            key_id=KEYID_DELEGATE)
        self.assertEqual(resp.classification, CLASSIFICATION_VERIFIED)
        sig, screens = self._sign()
        self.assertEqual(len(sig[1]), 32)

        summary = self.assertShows(
            screens, "RELAY",
            "Bridge 0.007988 ETH through Relay for 0x909E...F82E; "
            "delivery is by Relay")
        limits = self.assertShows(screens, "LIMITS", "You spend\n0.007988 ETH")
        contract = self.assertShows(
            screens, "CONTRACT",
            "bridgeDeposit\n0x4cD00E387622C35bDDB9b4c962C136462338BC31")
        # Shortened in the sentence, so shown in full on its own screen.
        depositor = self.assertShows(
            screens, "DEPOSITOR", "0x909Ef6B32DfDc12CA86aA710b54c991af3C5F82E")
        who = next(i for i, sc in enumerate(screens)
                   if find_line(sc, "KEEPKEY CLEARSIGN", TITLE_FONT))
        for line in ("Described by KeepKey Alpha 716", "A9531B9D",
                     "certified by KeepKey"):
            self.assertIsNotNone(find_line(screens[who], line), line)
        # Summary, limits, contract, depositor, orderId x2, who, fee.
        self.assertEqual(len(screens), 8)
        self.assertEqual([summary, limits, contract, depositor],
                         sorted([summary, limits, contract, depositor]))
        self.assertLess(depositor, who)
        # msg.value has a role: no separate ETH amount screen.
        self.assertIsNone(find_text(screens, "Send 0.007988 ETH"))

if __name__ == "__main__":
    unittest.main()
