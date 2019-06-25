# This file is part of the KeepKey project.
#
# Copyright (C) 2019 ShapeShift
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

import unittest
import common
import binascii
import struct

import keepkeylib.messages_pb2 as proto
import keepkeylib.types_pb2 as proto_types
import keepkeylib.exchange_pb2 as proto_exchange
from keepkeylib.client import CallException

class TestMsgEthereumtxMakerDAO(common.KeepKeyTest):

    def test_generate(self):
        self.setup_mnemonic_nopin_nopassphrase()

        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[2147483692,2147483708,2147483648,0,0],
            nonce=01,
            gas_price=20,
            gas_limit=20,
            value=0,
            to=binascii.unhexlify('acd00d9ac466cfbb14fd94798d73d9bb4bc446a4'),
            address_type=0,
            chain_id=1,
            data=binascii.unhexlify("1cff79cd000000000000000000000000190c2cfc69e68a8e8d5e2b9e2b9cc3332caff77b000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000640344a36f000000000000000000000000448a5065aebb8e423f0896e6c5d525c040f59af300000000000000000000000000000000000000000000000000000000000048800000000000000000000000000000000000000000000000000853a0d2313c000000000000000000000000000000000000000000000000000000000000")
            )

        self.assertEqual(sig_v, 37)
        self.assertEqual(binascii.hexlify(sig_r), '82d372ea156aae7903f677ef3ed514cb12e9caea349431645859761cdebe8277')
        self.assertEqual(binascii.hexlify(sig_s), '645568ec1d8f270069c5f08a82e1e5a3efee817a347d70f336408a99973b6650')

    def test_deposit(self):
        self.setup_mnemonic_nopin_nopassphrase()

        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[2147483692,2147483708,2147483648,0,0],
            nonce=01,
            gas_price=20,
            gas_limit=20,
            value=2000000000000000,
            to=binascii.unhexlify('acd00d9ac466cfbb14fd94798d73d9bb4bc446a4'),
            address_type=0,
            chain_id=1,
            data=binascii.unhexlify("1cff79cd000000000000000000000000190c2cfc69e68a8e8d5e2b9e2b9cc3332caff77b00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000044bc25a810000000000000000000000000448a5065aebb8e423f0896e6c5d525c040f59af3000000000000000000000000000000000000000000000000000000000000488000000000000000000000000000000000000000000000000000000000")
            )

        self.assertEqual(sig_v, 38)
        self.assertEqual(binascii.hexlify(sig_r), 'd50499223d5608a1aed7108e21b4446a26cb5c78592357ec1d84805c055c6b95')
        self.assertEqual(binascii.hexlify(sig_s), '20a93c5a761c7107b81bb9747e3a85313fc90be9ad733c0e32e8ce3c21a6a3ba')


    def test_close(self):
        self.setup_mnemonic_nopin_nopassphrase()

        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[2147483692,2147483708,2147483648,0,0],
            nonce=01,
            gas_price=20,
            gas_limit=20,
            value=0,
            to=binascii.unhexlify('acd00d9ac466cfbb14fd94798d73d9bb4bc446a4'),
            address_type=0,
            chain_id=1,
            data=binascii.unhexlify("1cff79cd000000000000000000000000190c2cfc69e68a8e8d5e2b9e2b9cc3332caff77b00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000044bc244c11000000000000000000000000448a5065aebb8e423f0896e6c5d525c040f59af3000000000000000000000000000000000000000000000000000000000000488000000000000000000000000000000000000000000000000000000000")
            )

        self.assertEqual(sig_v, 38)
        self.assertEqual(binascii.hexlify(sig_r), 'c3f8ddc49aa356374758caf0e5ec61d28813450afbaf533198bf4432c4a8be6a')
        self.assertEqual(binascii.hexlify(sig_s), '7109f24af62d62eece2621ae485f6aa2c3ba4561ed996c692460ab5dbf357f21')


    def test_free(self):
        self.setup_mnemonic_nopin_nopassphrase()

        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[2147483692,2147483708,2147483648,0,0],
            nonce=01,
            gas_price=20,
            gas_limit=20,
            value=0,
            to=binascii.unhexlify('acd00d9ac466cfbb14fd94798d73d9bb4bc446a4'),
            address_type=0,
            chain_id=1,
            data=binascii.unhexlify("1cff79cd000000000000000000000000190c2cfc69e68a8e8d5e2b9e2b9cc3332caff77b00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000064f9ef04be000000000000000000000000448a5065aebb8e423f0896e6c5d525c040f59af3000000000000000000000000000000000000000000000000000000000000489c00000000000000000000000000000000000000000000000000049e57d635400000000000000000000000000000000000000000000000000000000000")
            )

        self.assertEqual(sig_v, 38)
        self.assertEqual(binascii.hexlify(sig_r), '12eb344a86a04ce843827a7acd164a5629422a194fd169029c905123c10fc5a9')
        self.assertEqual(binascii.hexlify(sig_s), '0ba6c4960c24dbe856e5e94c7810ac872b3766772a348ece155e363b28dbf98e')

if __name__ == '__main__':
    unittest.main()

