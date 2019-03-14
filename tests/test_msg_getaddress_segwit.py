# This file is part of the Trezor project.
#
# Copyright (C) 2012-2018 SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

import common
import unittest

import keepkeylib.ckd_public as bip32
from keepkeylib import messages_pb2 as proto
from keepkeylib import types_pb2 as proto
from keepkeylib.tools import parse_path


class TestMsgGetaddressSegwit(common.KeepKeyTest):

    def test_show_segwit(self):
        self.setup_mnemonic_allallall()
        self.client.clear_session()
        self.assertEquals(self.client.get_address("Testnet", parse_path("49'/1'/0'/1/0"), True, None, script_type=proto.SPENDP2SHWITNESS), '2N1LGaGg836mqSQqiuUBLfcyGBhyZbremDX')
        self.assertEquals(self.client.get_address("Testnet", parse_path("49'/1'/0'/0/0"), False, None, script_type=proto.SPENDP2SHWITNESS), '2N4Q5FhU2497BryFfUgbqkAJE87aKHUhXMp')
        self.assertEquals(self.client.get_address("Testnet", parse_path("44'/1'/0'/0/0"), False, None, script_type=proto.SPENDP2SHWITNESS), '2N6UeBoqYEEnybg4cReFYDammpsyDw8R2Mc')
        self.assertEquals(self.client.get_address("Testnet", parse_path("44'/1'/0'/0/0"), False, None, script_type=proto.SPENDADDRESS), 'mvbu1Gdy8SUjTenqerxUaZyYjmveZvt33q')

    def test_grs(self):
        self.setup_mnemonic_allallall()
        self.client.clear_session()
        self.assertEqual(self.client.get_address('Groestlcoin', parse_path("49'/17'/0'/0/0"), True, None, script_type=proto.SPENDP2SHWITNESS), '31inaRqambLsd9D7Ke4USZmGEVd3PHkh7P')
        self.assertEqual(self.client.get_address('Groestlcoin', parse_path("49'/17'/0'/1/0"), False, None, script_type=proto.SPENDP2SHWITNESS), '3NH9SuUAjw1ZocQdTDMuqm3My3Mcg3ovEV')
        self.assertEqual(self.client.get_address('Groestlcoin', parse_path("49'/17'/0'/1/1"), False, None, script_type=proto.SPENDP2SHWITNESS), '3D65LEJYJ2Yda6UJr8tYBWspP5MZSeR5wz')

    def test_tgrs(self):
        self.setup_mnemonic_allallall()
        self.client.clear_session()
        self.assertEqual(self.client.get_address('GRS Testnet', parse_path("49'/1'/0'/0/0"), True, None, script_type=proto.SPENDP2SHWITNESS), '2N4Q5FhU2497BryFfUgbqkAJE87aKDv3V3e')
        self.assertEqual(self.client.get_address('GRS Testnet', parse_path("49'/1'/0'/1/0"), False, None, script_type=proto.SPENDP2SHWITNESS), '2N1LGaGg836mqSQqiuUBLfcyGBhyZYBtBZ7')
        self.assertEqual(self.client.get_address('GRS Testnet', parse_path("49'/1'/0'/1/1"), False, None, script_type=proto.SPENDP2SHWITNESS), '2NFWLCJQBSpz1oUJwwLpX8ECifFWGxQyzGu')

    def test_show_multisig_3(self):
        self.setup_mnemonic_allallall()
        self.client.clear_session()
        nodes = map(lambda index: self.client.get_public_node(parse_path("999'/1'/%d'" % index)), range(1, 4))
        multisig1 = proto.MultisigRedeemScriptType(
            pubkeys=list(map(lambda n: proto.HDNodePathType(node=bip32.deserialize(n.xpub), address_n=[2, 0]), nodes)),
            signatures=[b'', b'', b''],
            m=2,
        )
        # multisig2 = proto.MultisigRedeemScriptType(
        #     pubkeys=map(lambda n: proto.HDNodePathType(node=bip32.deserialize(n.xpub), address_n=[2, 1]), nodes),
        #     signatures=[b'', b'', b''],
        #     m=2,
        # )
        for i in [1, 2, 3]:
            self.assertEquals(self.client.get_address("Testnet", parse_path("999'/1'/%d'/2/0" % i), False, multisig1, script_type=proto.SPENDP2SHWITNESS), '2N2MxyAfifVhb3AMagisxaj3uij8bfXqf4Y')

if __name__ == '__main__':
    unittest.main()
