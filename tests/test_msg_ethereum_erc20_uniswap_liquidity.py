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

import unittest
import common
import binascii
import struct

import keepkeylib.messages_pb2 as proto
import keepkeylib.types_pb2 as proto_types
from keepkeylib.client import CallException
from keepkeylib.tools import int_to_big_endian

class TestMsgEthereumUniswaptxERC20(common.KeepKeyTest):
    
    def test_sign_uni_approve_liquidity_ETH(self):
        self.requires_fullFeature()
        self.requires_firmware("7.1.0")
        self.setup_mnemonic_nopin_nopassphrase()

        # Approval tx for the ETH/FOX pool
        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[2147483692,2147483708,2147483648,0,0],
            nonce=0xf,
            gas_price=0x2980872680,
            gas_limit=0xbd0e,
            value=0x0,
            to=binascii.unhexlify('470e8de2ebaef52014a47cb5e6af86884947f08c'),     # fox pool
            address_type=0,
            chain_id=1,
            # The data below is generally broken into 32-byte chunks except for the function selector (4 bytes_ and 
            # keccak signatures (4 bytes)
            data=binascii.unhexlify('095ea7b3' +                                      # approve
                '0000000000000000000000007a250d5630b4cf539739df2c5dacb4c659f2488d' +  # uniswap v2: router 2 contract address
                'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')   # approve amount

        )        
        self.assertEqual(sig_v, 38)
        self.assertEqual(binascii.hexlify(sig_r), '7f7a5ce501371a01ead394d2186385742d5fbdc3d85da98249d2a05043ac6d5a')
        self.assertEqual(binascii.hexlify(sig_s), '329954b284ed1df9a6242820e793b9719c0c6c21cae5f90190ce61c7f73c731e')
                 
    def test_sign_uni_add_liquidity_ETH(self):
        self.requires_fullFeature()
        if self.client.features.firmware_variant[0:8] == "Emulator":
            self.skipTest("Skip until emulator issue resolved")
            return
        self.requires_firmware("7.1.0")
        self.setup_mnemonic_nopin_nopassphrase()

        # Add liquidity to ETH/FOX pool
        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[2147483692,2147483708,2147483648,0,0],
            nonce=0xf,
            gas_price=0x25d5c13900,
            gas_limit=0x2b28b,
            value=0x9d3f71f8b4680,
            to=binascii.unhexlify('7a250d5630B4cF539739dF2C5dAcb4c659F2488D'),     # UNISWAP router
            address_type=0,
            chain_id=1,
            # The data below is generally broken into 32-byte chunks except for the function selector (4 bytes_ and 
            # keccak signatures (4 bytes)
            data=binascii.unhexlify('f305d719' +                                      # addLiquidityETH
                '000000000000000000000000c770eefad204b5180df6a14ee197d99d808ee52d' +  # FOX token
                '000000000000000000000000000000000000000000000000a688906bd8b00000' +  # amount of fox token
                '00000000000000000000000000000000000000000000000001aa535d3d0c0000' +  # min amount of fox token
                '0000000000000000000000000000000000000000000000000000fb98b65aba40' +  # min amount of eth token
                '0000000000000000000000003f2329C9ADFbcCd9A84f52c906E936A42dA18CB8' +  # eth address (self)
                '00000000000000000000000000000000000000000000000000000178a9380e5f')   # deadline
        )        
        self.assertEqual(sig_v, 37)
        self.assertEqual(binascii.hexlify(sig_r), '8547542bc74c0dcc6ca8b02a79e0dccd336856d8c48376289a2a697d864a5892')
        self.assertEqual(binascii.hexlify(sig_s), '0a8eec6856aef8caa234240b06862976f8e238e8b24f5c989279507dd7e51ccd')

    def test_sign_uni_remove_liquidity_ETH(self):
        self.requires_fullFeature()
        if self.client.features.firmware_variant[0:8] == "Emulator":
            self.skipTest("Skip until emulator issue resolved")
            return
        self.requires_firmware("7.1.0")
        self.setup_mnemonic_nopin_nopassphrase()

        # remove liquidity from the ETH/FOX pool
        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[2147483692,2147483708,2147483648,0,0],
            nonce=0xf,
            gas_price=0x320313e400,
            gas_limit=0x3b754,
            value=0x0,
            to=binascii.unhexlify('7a250d5630B4cF539739dF2C5dAcb4c659F2488D'),     # UNISWAP router
            address_type=0,
            chain_id=1,
            # The data below is generally broken into 32-byte chunks except for the function selector (4 bytes_ and 
            # keccak signatures (4 bytes)
            data=binascii.unhexlify('02751cec' +                                      # addLiquidityETH
                '000000000000000000000000c770eefad204b5180df6a14ee197d99d808ee52d' +  # FOX token
                '00000000000000000000000000000000000000000000000002684b14a52bcefc' +  # liquidity amount
                '000000000000000000000000000000000000000000000000010a741a46278000' +  # min amount of fox token
                '0000000000000000000000000000000000000000000000000000fb04c77f3e94' +  # min amount of eth token
                '0000000000000000000000005028d647b74f12903e6d5f3969f8f624e6a9a93d' +  # to address (not self)
                '00000000000000000000000000000000000000000000000000000178b2062f3d')   # deadline
        )        
        self.assertEqual(sig_v, 37)
        self.assertEqual(binascii.hexlify(sig_r), '7143f0d8e5505a8cfb1df55e9c5d7433eba33a61959137c08cc5c088ec12ab5d')
        self.assertEqual(binascii.hexlify(sig_s), '20b456d6c13295f5abb6109d7ade2c5d5fc395963b1e45d92e6dc8c33749c517')

if __name__ == '__main__':
    unittest.main()
