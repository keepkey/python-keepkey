# This file is part of the TREZOR project.
#
# Copyright (C) 2012-2016 Marek Palatinus <slush@satoshilabs.com>
# Copyright (C) 2012-2016 Pavol Rusnak <stick@satoshilabs.com>
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this library.  If not, see <http://www.gnu.org/licenses/>.
#
# The script has been modified for KeepKey Device.

import unittest
import common
import keepkeylib.ckd_public as bip32
import keepkeylib.types_pb2 as proto_types

class TestMsgGetaddress(common.KeepKeyTest):

    def test_btc(self):
        self.setup_mnemonic_nopin_nopassphrase()
        self.assertEqual(self.client.get_address('Bitcoin', []), '1EfKbQupktEMXf4gujJ9kCFo83k1iMqwqK')
        self.assertEqual(self.client.get_address('Bitcoin', [1]), '1CK7SJdcb8z9HuvVft3D91HLpLC6KSsGb')
        self.assertEqual(self.client.get_address('Bitcoin', [0, -1]), '1JVq66pzRBvqaBRFeU9SPVvg3er4ZDgoMs')
        self.assertEqual(self.client.get_address('Bitcoin', [-9, 0]), '1F4YdQdL9ZQwvcNTuy5mjyQxXkyCfMcP2P')
        self.assertEqual(self.client.get_address('Bitcoin', [0, 9999999]), '1GS8X3yc7ntzwGw9vXwj9wqmBWZkTFewBV')

    def test_ltc(self):
        self.setup_mnemonic_nopin_nopassphrase()
        self.assertEqual(self.client.get_address('Litecoin', []), 'LYtGrdDeqYUQnTkr5sHT2DKZLG7Hqg7HTK')
        self.assertEqual(self.client.get_address('Litecoin', [1]), 'LKRGNecThFP3Q6c5fosLVA53Z2hUDb1qnE')
        self.assertEqual(self.client.get_address('Litecoin', [0, -1]), 'LcinMK8pVrAtpz7Qpc8jfWzSFsDLgLYfG6')
        self.assertEqual(self.client.get_address('Litecoin', [-9, 0]), 'LZHVtcwAEDf1BR4d67551zUijyLUpDF9EX')
        self.assertEqual(self.client.get_address('Litecoin', [0, 9999999]), 'Laf5nGHSCT94C5dK6fw2RxuXPiw2ZuRR9S')

    def test_grs(self):
        self.setup_mnemonic_allallall()
        self.assertEqual(self.client.get_address('Groestlcoin', [44 | 0x80000000, 17 | 0x80000000, 0 | 0x80000000, 0, 0]), 'Fj62rBJi8LvbmWu2jzkaUX1NFXLEqDLoZM')
        self.assertEqual(self.client.get_address('Groestlcoin', [44 | 0x80000000, 17 | 0x80000000, 0 | 0x80000000, 1, 0]), 'FmRaqvVBRrAp2Umfqx9V1ectZy8gw54QDN')
        self.assertEqual(self.client.get_address('Groestlcoin', [44 | 0x80000000, 17 | 0x80000000, 0 | 0x80000000, 1, 1]), 'Fmhtxeh7YdCBkyQF7AQG4QnY8y3rJg89di')

    def test_tgrs(self):
        self.setup_mnemonic_allallall()
        self.assertEqual(self.client.get_address('GRS Testnet', [44 | 0x80000000, 1 | 0x80000000, 0 | 0x80000000, 0, 0]), 'mvbu1Gdy8SUjTenqerxUaZyYjmvedc787y')
        self.assertEqual(self.client.get_address('GRS Testnet', [44 | 0x80000000, 1 | 0x80000000, 0 | 0x80000000, 1, 0]), 'mm6kLYbGEL1tGe4ZA8xacfgRPdW1LMq8cN')
        self.assertEqual(self.client.get_address('GRS Testnet', [44 | 0x80000000, 1 | 0x80000000, 0 | 0x80000000, 1, 1]), 'mjXZwmEi1z1MzveZrKUAo4DBgbdq6ZhGD6')

    def test_ltc_m_address(self):
        # generate a 1 of 1 multisig and make sure we get an M address
        self.setup_mnemonic_nopin_nopassphrase()
        node = bip32.deserialize('xpub661MyMwAqRbcF1zGijBb2K6x9YiJPh58xpcCeLvTxMX6spkY3PcpJ4ABcCyWfskq5DDxM3e6Ez5ePCqG5bnPUXR4wL8TZWyoDaUdiWW7bKy')
        multisig = proto_types.MultisigRedeemScriptType(
                            pubkeys=[proto_types.HDNodePathType(node=node, address_n=[])],
                            signatures=[''],
                            m=1,
                            )
        self.assertEqual(self.client.get_address('Litecoin', [], multisig=multisig), 'MBFFn5LyWatMVt2aoXbLkFJHRsnNJcaxba')


    def test_tbtc(self):
         self.setup_mnemonic_nopin_nopassphrase()
         self.assertEqual(self.client.get_address('Testnet', [111, 42]), 'moN6aN6NP1KWgnPSqzrrRPvx2x1UtZJssa')

    def test_public_ckd(self):
        self.setup_mnemonic_nopin_nopassphrase()

        node = self.client.get_public_node([]).node
        node_sub1 = self.client.get_public_node([1]).node
        node_sub2 = bip32.public_ckd(node, [1])

        self.assertEqual(node_sub1.chain_code, node_sub2.chain_code)
        self.assertEqual(node_sub1.public_key, node_sub2.public_key)

        address1 = self.client.get_address('Bitcoin', [1])
        address2 = bip32.get_address(node_sub2, 0)

        self.assertEqual(address2, '1CK7SJdcb8z9HuvVft3D91HLpLC6KSsGb')
        self.assertEqual(address1, address2)

if __name__ == '__main__':
    unittest.main()
