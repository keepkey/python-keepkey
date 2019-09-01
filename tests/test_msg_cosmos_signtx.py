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
# The script has been modified for KeepKey device.

import unittest
import common
import binascii

import keepkeylib.messages_pb2 as proto
import keepkeylib.types_pb2 as proto_types
from keepkeylib.client import CallException
from keepkeylib.tools import int_to_big_endian

class TestMsgCosmosSigntx(common.KeepKeyTest):

    def test_cosmos_signtx_nodata(self):
        #self.skipTest("Broke because I suck")

        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy('AdvancedMode', 0)

        sig_v, sig_r, sig_s = self.client.cosmos_sign_tx(
            n=[0, 0],
            nonce=0,
            gas_price=20,
            gas_limit=20,
            to=binascii.unhexlify('1d1c328764a41bda0492b66baa30c4a339ff85ef'),
            value=10)
        self.assertEqual(sig_v, 27)
        self.assertEqual(binascii.hexlify(sig_r), '9b61192a161d056c66cfbbd331edb2d783a0193bd4f65f49ee965f791d898f72')
        self.assertEqual(binascii.hexlify(sig_s), '49c0bbe35131592c6ed5c871ac457feeb16a1493f64237387fab9b83c1a202f7')

        sig_v, sig_r, sig_s = self.client.cosmos_sign_tx(
            n=[0, 0],
            nonce=123456,
            gas_price=20000,
            gas_limit=20000,
            to=binascii.unhexlify('1d1c328764a41bda0492b66baa30c4a339ff85ef'),
            value=12345678901234567890)
        self.assertEqual(sig_v, 28)
        self.assertEqual(binascii.hexlify(sig_r), '6de597b8ec1b46501e5b159676e132c1aa78a95bd5892ef23560a9867528975a')
        self.assertEqual(binascii.hexlify(sig_s), '6e33c4230b1ecf96a8dbb514b4aec0a6d6ba53f8991c8143f77812aa6daa993f')


if __name__ == '__main__':
    unittest.main()
