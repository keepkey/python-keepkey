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


class TestMsgGetaddressSegwitNative(common.KeepKeyTest):

    def test_show_segwit(self):
        self.setup_mnemonic_allallall()
        self.client.clear_session()
        self.assertEquals(self.client.get_address("Testnet", parse_path("49'/1'/0'/0/0"), True, None, script_type=proto.SPENDWITNESS), 'tb1qqzv60m9ajw8drqulta4ld4gfx0rdh82un5s65s')
        self.assertEquals(self.client.get_address("Testnet", parse_path("49'/1'/0'/1/0"), False, None, script_type=proto.SPENDWITNESS), 'tb1q694ccp5qcc0udmfwgp692u2s2hjpq5h407urtu')
        self.assertEquals(self.client.get_address("Testnet", parse_path("44'/1'/0'/0/0"), False, None, script_type=proto.SPENDWITNESS), 'tb1q54un3q39sf7e7tlfq99d6ezys7qgc62a6rxllc')
        self.assertEquals(self.client.get_address("Testnet", parse_path("44'/1'/0'/0/0"), False, None, script_type=proto.SPENDADDRESS), 'mvbu1Gdy8SUjTenqerxUaZyYjmveZvt33q')
        self.assertEquals(self.client.get_address("Groestlcoin", parse_path("84'/17'/0'/0/0"), False, None, script_type=proto.SPENDWITNESS), 'grs1qw4teyraux2s77nhjdwh9ar8rl9dt7zww8r6lne')
        self.assertEquals(self.client.get_address("GRS Testnet", parse_path("84'/1'/0'/0/0"), False, None, script_type=proto.SPENDWITNESS), 'tgrs1qkvwu9g3k2pdxewfqr7syz89r3gj557l3ued7ja')

    def test_show_multisig_3(self):
        self.setup_mnemonic_allallall()
        self.client.clear_session()
        nodes = [self.client.get_public_node(parse_path("999'/1'/%d'" % index)) for index in range(1, 4)]
        multisig1 = proto.MultisigRedeemScriptType(
            pubkeys=list(map(lambda n: proto.HDNodePathType(node=bip32.deserialize(n.xpub), address_n=[2, 0]), nodes)),
            signatures=[b'', b'', b''],
            m=2,
        )
        multisig2 = proto.MultisigRedeemScriptType(
            pubkeys=list(map(lambda n: proto.HDNodePathType(node=bip32.deserialize(n.xpub), address_n=[2, 1]), nodes)),
            signatures=[b'', b'', b''],
            m=2,
        )
        for i in [1, 2, 3]:
            self.assertEquals(self.client.get_address("Testnet", parse_path("999'/1'/%d'/2/1" % i), False, multisig2, script_type=proto.SPENDWITNESS), 'tb1qch62pf820spe9mlq49ns5uexfnl6jzcezp7d328fw58lj0rhlhasge9hzy')
            self.assertEquals(self.client.get_address("Testnet", parse_path("999'/1'/%d'/2/0" % i), False, multisig1, script_type=proto.SPENDWITNESS), 'tb1qr6xa5v60zyt3ry9nmfew2fk5g9y3gerkjeu6xxdz7qga5kknz2ssld9z2z')

if __name__ == '__main__':
    unittest.main()
