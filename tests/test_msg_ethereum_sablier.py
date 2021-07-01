# This file is part of the KEEPKEY project.
#
# Copyright (C) 2021 Shapeshift
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

from base64 import b64encode
import unittest
import common
import binascii
import struct

import keepkeylib.messages_pb2 as proto
import keepkeylib.types_pb2 as proto_types
import keepkeylib.exchange_pb2 as proto_exchange
from keepkeylib.client import CallException
from keepkeylib.tools import int_to_big_endian

class TestMsgEthereumSablier(common.KeepKeyTest):
    
    def test_sign_salarywithdrawl(self):
        self.requires_firmware("7.1.5")
        self.setup_mnemonic_nopin_nopassphrase()

        # withdraw some fox
        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[2147483692,2147483708,2147483648,0,0],
            nonce=0xab,
            gas_price=0x24c988ac00,
            gas_limit=0x26249,
            value=0x0,
            to=binascii.unhexlify('bd6a40bb904aea5a49c59050b5395f7484a4203d'),  # sablier proxy
            address_type=0,
            chain_id=1,
            # The data below is generally broken into 32-byte chunks except for the function selector (4 bytes_ and 
            # keccak signatures (4 bytes)            
            data=binascii.unhexlify('fea7c53f' +                                        # withdrawFromSalary
                '0000000000000000000000000000000000000000000000000000000000001210' +    # salary ID
                '0000000000000000000000000000000000000000000000000000000000000001')     # amount

        )       
        self.assertEqual(sig_v, 38)
        self.assertEqual(binascii.hexlify(sig_r), '041bd4dc9a4a8a72e7200285ab7b66c93381bddc7e3b6f8312abdb7ff38a96b0')
        self.assertEqual(binascii.hexlify(sig_s), '5583946f7ff63187ecdb725e33298e05c41b0fd08ebcc80e2f424944ad6b7c78')


if __name__ == '__main__':
    unittest.main()
