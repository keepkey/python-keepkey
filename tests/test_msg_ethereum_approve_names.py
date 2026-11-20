# This file is part of the KeepKey project.
#
# Copyright (C) 2026 KeepKey
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
"""7.18: a KeepKey-certified 0x06 name record names the spender of a native
ERC-20 approve, or the recipient of a plain send, on one screen of its own
right after the screen with the full address. That screen stays exactly the
7.16 one, and nothing signed changes.

The fixtures name Uniswap's Universal Router on Ethereum under the production
root and the emulator alpha root. The production record is shared with the
firmware unit test ApproveNameTest. COW_APPROVE is the calldata swaps.pro sent
through Desktop on 2026-10-29: approve 25000 USDC to CoW's GPv2VaultRelayer.
"""

import os
import unittest

import common
from keepkeylib.client import CallException
from keepkeylib.tools import parse_path
from oled_text import TITLE_FONT, find_line, shows
from test_msg_display_disclosure import ScreenRecorder

# signedPayload from the deployed ClearSign Worker (source d2849aaf8),
# POST /v1/evm/name {chainId 1, address 0x66a9...a8af}: the same record as
# test_msg_eip712_streaming.UR_V2_NAME. It chains to the alpha root, which
# CI's emulator trusts through KK_CLEARSIGN_TEST_ROOT.
ALPHA_UR_NAME = bytes.fromhex(
    "030101000000016b359b004b6565704b657920416c7068612037313600000000"
    "00000000000000000000000342f5f9704494b3f9bd72295eecaf29d783d23ea0"
    "2b2dc9f48abcd2e46d4850cffc4364672f0172aa70ed21eacc2ea8bd0d333119"
    "ddf048b096686e1a8e56bda438f9e70b9cfc229a1e93e2d91846c31c4083d8b1"
    "76e225d76341069dd22826cf060000000166a9893cc07d91d95644aedd05d03f"
    "95e1dba8af18556e697377617020556e6976657273616c20526f757465720100"
    "000000806d645ca60ffadfd620a8abda7a77f84dbbf4770644e51c234937f715"
    "12d2019b30068dfd95e88e2ebbdd2186db629012a9d861b55b14d3ef9000c99f"
    "ef5de4811b")
# Published Ethereum Universal Router record from the production batch 2 ceremony.
PRODUCTION_UR_NAME = bytes.fromhex(
    "030101000000016cb3ad994b6565704b657920436c6561725369676e00000000"
    "000000000000000000000003bb5314410309cc4e56b8140565106714e4dbf33f"
    "6d75e2c89b78e0e6cb1cd1655c9f942208d3b4812e1a9434993f65d9c05990cb"
    "e379faade132d14987cbfaeb387f0dd3e015210934fe1103770b89272e64a653"
    "97d5d22a3501aa089ea13000060000000166a9893cc07d91d95644aedd05d03f"
    "95e1dba8af18556e697377617020556e6976657273616c20526f757465720100"
    "00000080362cd9a3aa09724ff3758120fc36f96c207a28f4290d7f7415976b75"
    "d090f87d758ad594ec569c63736cc94f4bd63af4d66edd778f6472cd8e8f28e8"
    "860c52be01")
ALPHA_ROOT = "02de9231b2094433235532fb1932e324a2c7304195e12e610c675cccbbd606dae7"
USDC = bytes.fromhex("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
COW_APPROVE = bytes.fromhex(
    "095ea7b3000000000000000000000000c92e8bdf79f0507f65a392b0ab4667716bfe0110"
    "00000000000000000000000000000000000000000000000000000005d21dba00")


def approve_to(spender_hex):
    return COW_APPROVE[:16] + bytes.fromhex(spender_hex) + COW_APPROVE[36:]


UR_APPROVE = approve_to("66a9893cc07d91d95644aedd05d03f95e1dba8af")
UR = bytes.fromhex("66a9893cc07d91d95644aedd05d03f95e1dba8af")
COW_RELAYER = bytes.fromhex("c92e8bdf79f0507f65a392b0ab4667716bfe0110")


class TestEthereumApproveNames(common.KeepKeyTest):

    def setUp(self):
        super(TestEthereumApproveNames, self).setUp()
        self.requires_firmware("7.17.0")
        self.requires_message("EthereumTxMetadata")
        self.supports_display_names = self.firmware_at_least("7.18.0")
        alpha = (self.client.features.firmware_variant.startswith("Emulator") and
                 os.environ.get("KK_CLEARSIGN_TEST_ROOT") == ALPHA_ROOT)
        self.name_record = ALPHA_UR_NAME if alpha else PRODUCTION_UR_NAME
        signer = "KeepKey Alpha 716 A9531B9D" if alpha else "KeepKey ClearSign FDD258EC"
        self.attribution = "named by %s\ncertified by KeepKey" % signer
        self.setup_mnemonic_allallall()

    def _approve(self, data, record=None, save_frames=True):
        return self._sign(USDC, 0, data, record, save_frames=save_frames)

    def _send(self, to, record=None, chain_id=1, save_frames=True):
        return self._sign(to, 10**18, b"", record, chain_id, save_frames)

    def _sign(self, to, value, data, record, chain_id=1, save_frames=True):
        if record is not None:
            resp = self.client.ethereum_send_tx_metadata(
                signed_payload=record, metadata_version=3, key_id=0x80)
            self.assertEqual(resp.classification, 1)  # VERIFIED
        recorder = ScreenRecorder(self.client, answer=True, save_frames=save_frames)
        with recorder:
            sig = self.client.ethereum_sign_tx(
                n=parse_path("m/44'/60'/0'/0/0"), nonce=7, gas_limit=60000,
                max_fee_per_gas=0xd52bef138, max_priority_fee_per_gas=10**9,
                value=value, to=to, data=data, chain_id=chain_id)
        return sig, recorder.screens

    def _titled(self, screens, title):
        return [s for s in screens
                if find_line(s, title, TITLE_FONT) is not None]

    def _assert_named_after(self, screens, plain, after, text):
        """`screens` is `plain` plus one KeepKey ClearSign screen showing
        `text`, right after plain[after]."""
        if not self.supports_display_names:
            self.assertEqual(screens, plain)
            self.assertEqual(self._titled(screens, "KEEPKEY CLEARSIGN"), [])
            return
        vouched = self._titled(screens, "KEEPKEY CLEARSIGN")
        self.assertEqual(len(vouched), 1)
        self.assertIs(vouched[0], screens[after + 1])
        self.assertTrue(shows(vouched[0], text))
        self.assertEqual(screens[:after + 1] + screens[after + 2:], plain)
        self.assertEqual(self._titled(plain, "KEEPKEY CLEARSIGN"), [])

    def test_vouched_spender_is_named_after_its_address(self):
        plain_sig, plain = self._approve(UR_APPROVE, save_frames=False)
        sig, screens = self._approve(UR_APPROVE, self.name_record)
        self.assertEqual(sig, plain_sig)  # nothing signed changes
        # The 7.16 approve screen, whole address on one page, then the name.
        self.assertTrue(shows(
            plain[0], "Approve withdrawal of up to 25000 USDC by "
                      "0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af?"))
        self._assert_named_after(screens, plain, 0,
                                 "Spender: Uniswap Universal Router\n" + self.attribution)
        # One request per record: the next approve is not named.
        _, again = self._approve(UR_APPROVE, save_frames=False)
        self.assertEqual(again, plain)

    def test_vouched_send_recipient_is_named_after_its_address(self):
        plain_sig, plain = self._send(UR, save_frames=False)
        sig, screens = self._send(UR, self.name_record)
        self.assertEqual(sig, plain_sig)
        self.assertTrue(shows(
            plain[0], "Send 1 ETH to "
                      "0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af"))
        self._assert_named_after(screens, plain, 0,
                                 "Recipient: Uniswap Universal Router\n" + self.attribution)
        # Control: the same record on a send to another address names nothing.
        other_sig, other_plain = self._send(COW_RELAYER, save_frames=False)
        sig, screens = self._send(COW_RELAYER, self.name_record, save_frames=False)
        self.assertEqual(sig, other_sig)
        self.assertEqual(screens, other_plain)

    def test_name_for_another_spender_is_ignored(self):
        self.requires_firmware("7.18.0")
        plain_sig, plain = self._approve(COW_APPROVE)
        sig, screens = self._approve(COW_APPROVE, self.name_record)
        self.assertEqual(sig, plain_sig)
        self.assertEqual(screens, plain)

    def test_name_for_another_chain_is_ignored(self):
        self.requires_firmware("7.18.0")
        # The Ethereum record, on a BNB Chain send to the same address.
        plain_sig, plain = self._send(UR, chain_id=56)
        sig, screens = self._send(UR, self.name_record, chain_id=56)
        self.assertEqual(sig, plain_sig)
        self.assertEqual(screens, plain)
        # Control: on Ethereum the same record names that send.
        _, named = self._send(UR, self.name_record)
        self.assertEqual(len(self._titled(named, "KEEPKEY CLEARSIGN")), 1)

    def test_malformed_name_record_refuses_the_approve(self):
        self.requires_firmware("7.18.0")
        bad = bytearray(self.name_record)
        bad[-10] ^= 1  # inside the delegate's signature
        resp = self.client.ethereum_send_tx_metadata(
            signed_payload=bytes(bad), metadata_version=3, key_id=0x80)
        self.assertEqual(resp.classification, 2)  # MALFORMED
        with self.assertRaises(CallException) as e:
            self._approve(UR_APPROVE)
        self.assertEqual(e.exception.args[1],
                         "Certified description invalid or not for this tx")
        # The refused record does not carry over to the next request.
        _, plain = self._approve(UR_APPROVE)
        self.assertTrue(shows(
            plain[0], "Approve withdrawal of up to 25000 USDC by "
                      "0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af?"))
        self.assertEqual(self._titled(plain, "KEEPKEY CLEARSIGN"), [])


if __name__ == '__main__':
    unittest.main()
