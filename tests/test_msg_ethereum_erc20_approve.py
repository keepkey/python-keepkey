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

from rlp.utils import int_to_big_endian

class TestMsgEthereumtxERC20_approve(common.KeepKeyTest):

    def test_approve_cvc_100(self):
        self.setup_mnemonic_nopin_nopassphrase()

        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[2147483692,2147483708,2147483648,0,0],
            nonce=01,
            gas_price=20,
            gas_limit=20,
            value=0,
            to=binascii.unhexlify('41e5560054824ea6b0732e656e3ad64e20e94e45'),
            address_type=0,
            chain_id=1,
            data=binascii.unhexlify('095ea7b3' + '0000000000000000000000001d8ce9022f6284c3a5c317f8f34620107214e545' + '00000000000000000000000000000000000000000000000000000002540be400')
            )

        self.assertEqual(sig_v, 38)
        self.assertEqual(binascii.hexlify(sig_r), 'ca32b0dbaf3efa4536c406874879c2a892b77f50e376d19a8c9484d984f94ce3')
        self.assertEqual(binascii.hexlify(sig_s), '093b9e3cff2cb73d563fe123aa88e09f197a08a250f68b69fec15c86657b43d8')

    def test_approve_cvc_0(self):
        self.setup_mnemonic_nopin_nopassphrase()

        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[2147483692,2147483708,2147483648,0,0],
            nonce=01,
            gas_price=20,
            gas_limit=20,
            value=0,
            to=binascii.unhexlify('41e5560054824ea6b0732e656e3ad64e20e94e45'),
            address_type=0,
            chain_id=1,
            data=binascii.unhexlify('095ea7b3' + '0000000000000000000000001d8ce9022f6284c3a5c317f8f34620107214e545' + '0000000000000000000000000000000000000000000000000000000000000000')
            )

        self.assertEqual(sig_v, 37)
        self.assertEqual(binascii.hexlify(sig_r), 'b37dbfa65c37906de2037f4684941c7144773786621037962d43db7836170ac0')
        self.assertEqual(binascii.hexlify(sig_s), '0bc7319762281d839c436adb41c35f8de5f4db1aec953f677c3a83062d93fc51')

    def test_approve_cvc_all(self):
        self.setup_mnemonic_nopin_nopassphrase()

        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[2147483692,2147483708,2147483648,0,0],
            nonce=01,
            gas_price=20,
            gas_limit=20,
            value=0,
            to=binascii.unhexlify('41e5560054824ea6b0732e656e3ad64e20e94e45'),
            address_type=0,
            chain_id=1,
            data=binascii.unhexlify('095ea7b3' + '0000000000000000000000001d8ce9022f6284c3a5c317f8f34620107214e545' + 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
            )

        self.assertEqual(sig_v, 37)
        self.assertEqual(binascii.hexlify(sig_r), 'bb4c640b79f946e1399450dfc615b0a6024b6724f167cef70cf2530408fc6339')
        self.assertEqual(binascii.hexlify(sig_s), '4ca7dcf697482aeaafef1108e899e571f4b63272b29852b05a49d46ea143c642')


if __name__ == '__main__':
    unittest.main()
