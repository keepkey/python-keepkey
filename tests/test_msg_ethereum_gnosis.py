# This file is part of the KEEPKEY project.
#
# Copyright (C) 2022 markrypto
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
from keepkeylib.client import CallException
from keepkeylib.tools import int_to_big_endian

class TestMsgEthereumSablier(common.KeepKeyTest):
    
    def test_sign_execTx(self):
        self.requires_firmware("7.5.2")
        self.setup_mnemonic_nopin_nopassphrase()

        # withdraw some fox
        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[2147483692,2147483708,2147483648,0,0],
            nonce=0xab,
            gas_price=0x24c988ac00,
            gas_limit=0x26249,
            value=0x0,
            to=binascii.unhexlify('c8fff0d944406a40475a0a8264328aac8d64927b'),  # gnosis proxy
            address_type=0,
            chain_id=1,
            # The data below is generally broken into 32-byte chunks except for the function selector (4 bytes_ and 
            # keccak signatures (4 bytes)
            
            # Function: execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, 
            # uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures)    
            data=binascii.unhexlify('6a761202' +                                        # execTransaction
                '000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48' +    # to address
                '0000000000000000000000000000000000000000000000000000000000000000' +    # value in eth
                '0000000000000000000000000000000000000000000000000000000000000140' +    # offset to data
                '0000000000000000000000000000000000000000000000000000000000000000' +    # operation {Call, DelegateCall}
                '0000000000000000000000000000000000000000000000000000000000000000' +    # safeTxGas
                '0000000000000000000000000000000000000000000000000000000000000000' +    # baseGas
                '0000000000000000000000000000000000000000000000000000000000000000' +    # gasPrice
                '0000000000000000000000000000000000000000000000000000000000000000' +    # gasToken (0 if eth)
                '0000000000000000000000000000000000000000000000000000000000000000' +    # refundReceiver of gas payment (0 if tx.origin)
                '00000000000000000000000000000000000000000000000000000000000001c0' +    # offset to signatures data
                '0000000000000000000000000000000000000000000000000000000000000044' +    # data: len of data
                'a9059cbb000000000000000000000000b5bd898fadf4dc19313bc70c932bcee7' +    # data payload bytes
                'a90d9bb300000000000000000000000000000000000000000000000000000000' +
                '0ee6b28000000000000000000000000000000000000000000000000000000000' +
                '0000000000000000000000000000000000000000000000000000000000000041' +    # signatures: len of signatures
                '00000000000000000000000021c9a94af76b59b171b32fd125a4edf0e9a2ad3e' +    # signatures bytes
                '0000000000000000000000000000000000000000000000000000000000000000' +    
                '0100000000000000000000000000000000000000000000000000000000000000')     
            )       
        print(binascii.hexlify(sig_r))
        print(binascii.hexlify(sig_s))
        print(sig_v)
        # self.assertEqual(sig_v, 38)
        # self.assertEqual(binascii.hexlify(sig_r), '041bd4dc9a4a8a72e7200285ab7b66c93381bddc7e3b6f8312abdb7ff38a96b0')
        # self.assertEqual(binascii.hexlify(sig_s), '5583946f7ff63187ecdb725e33298e05c41b0fd08ebcc80e2f424944ad6b7c78')


if __name__ == '__main__':
    unittest.main()
