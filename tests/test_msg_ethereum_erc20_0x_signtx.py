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
import keepkeylib.exchange_pb2 as proto_exchange
from keepkeylib.client import CallException
from keepkeylib.tools import int_to_big_endian

class TestMsgEthereum0xtxERC20(common.KeepKeyTest):

    def test_sign_0x_swap_ERC20_to_ERC20(self):
        self.setup_mnemonic_nopin_nopassphrase()

        # swap 1 USDC for FOX
        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[2147483692,2147483708,2147483648,0,0],
            nonce=0x3,
            gas_price=0x3b23946c00,
            gas_limit=0x34c7f,
            value=0x0,
            to=binascii.unhexlify('def1c0ded9bec7f1a1670819833240f027b25eff'),
            address_type=0,
            chain_id=1,
            # The data below is generally broken into 32-byte chunks except for the function selector (4 bytes_ and 
            # keccak signatures (4 bytes)
            data=binascii.unhexlify('d9627aa4' +                                        # SellToUniswap
                '0000000000000000000000000000000000000000000000000000000000000080' +    # offset of dynamic params
                '00000000000000000000000000000000000000000000000000000000000f4240' +    # sell amount
                '000000000000000000000000000000000000000000000000160fcc023c539cf9' +    # min buy amount
                '0000000000000000000000000000000000000000000000000000000000000000' +    # isSushi
                '0000000000000000000000000000000000000000000000000000000000000003' +    # number of dynamic params
                '000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48' +    # USDC contract
                '000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2' +    # WETH (Wrapped ether) contract
                '000000000000000000000000c770eefad204b5180df6a14ee197d99d808ee52d' +    # FOX contract
                '869584cd' +
                '000000000000000000000000c770eefad204b5180df6a14ee197d99d808ee52d' +    # Affiliate address? (FOX)
                '00000000000000000000000000000000000000000000005173811ab76050e805')
        )        
        self.assertEqual(sig_v, 38)
        self.assertEqual(binascii.hexlify(sig_r), 'fea073853877532315cad4cc17b04982dd5af62f8af79b8ed4fa568ed094760b')
        self.assertEqual(binascii.hexlify(sig_s), '70f1150d5cabeb15d719d33e370fdbdea0a641ae11774fa2cff2aad29ef461cb')

    def test_sign_0x_swap_ETH_to_ERC20(self):
        self.setup_mnemonic_nopin_nopassphrase()

        # swap $2 of ETH to USDC
        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[2147483692,2147483708,2147483648,0,0],
            nonce=0xab,
            gas_price=0x24c988ac00,
            gas_limit=0x26249,
            value=0x2386f26fc10000,
            to=binascii.unhexlify('def1c0ded9bec7f1a1670819833240f027b25eff'),
            address_type=0,
            chain_id=1,
            # The data below is generally broken into 32-byte chunks except for the function selector (4 bytes_ and 
            # keccak signatures (4 bytes)
            data=binascii.unhexlify('d9627aa4' +                                        # SellToUniswap
                '0000000000000000000000000000000000000000000000000000000000000080' +    # offset of dynamic params
                '0000000000000000000000000000000000000000000000000003fb33ddbf39e4' +    # sell amount
                '0000000000000000000000000000000000000000000000000000000000155cbf' +    # min buy amount
                '0000000000000000000000000000000000000000000000000000000000000001' +    # isSushi
                '0000000000000000000000000000000000000000000000000000000000000002' +    # number of dynamic params
                '000000000000000000000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee' +    # ETH as an ERC20 test address
                '000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48' +    # USDC contract
                '869584cd' +
                '000000000000000000000000c770eefad204b5180df6a14ee197d99d808ee52d' +    # Affiliate address? (FOX)
                '000000000000000000000000000000000000000000000033df43e4f8604fcda6')
        )       
        self.assertEqual(sig_v, 38)
        self.assertEqual(binascii.hexlify(sig_r), 'd1799685f3080956e7abf03a7891eabd691034e52a8a240f3341fb10d008593c')
        self.assertEqual(binascii.hexlify(sig_s), '51ef1578d4f4bece1ffe3759209088f02cb9d2b21e64d5c32c8b4ebce95417e0')

    def test_sign_0x_swap_ERC20_to_ETH(self):
        self.setup_mnemonic_nopin_nopassphrase()

        # swap $2 to USDC to ETH
        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[2147483692,2147483708,2147483648,0,0],
            nonce=0x3,
            gas_price=0x349ea65400,
            gas_limit=0x26cab,
            value=0x0,
            to=binascii.unhexlify('def1c0ded9bec7f1a1670819833240f027b25eff'),
            address_type=0,
            chain_id=1,
            # The data below is generally broken into 32-byte chunks except for the function selector (4 bytes_ and 
            # keccak signatures (4 bytes)
            data=binascii.unhexlify('d9627aa4' +                                        # SellToUniswap
                '0000000000000000000000000000000000000000000000000000000000000080' +    # offset of dynamic params
                '00000000000000000000000000000000000000000000000000000000000f4240' +    # sell amount
                '00000000000000000000000000000000000000000000000000016250ede2181c' +    # min buy amount
                '0000000000000000000000000000000000000000000000000000000000000000' +    # isSushi
                '0000000000000000000000000000000000000000000000000000000000000002' +    # number of dynamic params
                '000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48' +    # USDC contract
                '000000000000000000000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee' +    # ETH as an ERC20 test address
                '869584cd' +
                '000000000000000000000000c770eefad204b5180df6a14ee197d99d808ee52d' +    # Affiliate address? (FOX)
                '000000000000000000000000000000000000000000000033df43e4f8604fcda6')
        )            
     
        self.assertEqual(sig_v, 37)
        self.assertEqual(binascii.hexlify(sig_r), 'e68f598fc7aad959c2a389de1f0d9a5a47dc374c112b57c8afede4da0d1a6b83')
        self.assertEqual(binascii.hexlify(sig_s), '1ec122b3e92daa3b5e5e17e9c775644448831f8af3228d80c2de0cec301715a5')

    def test_sign_longdata_swap(self):
        self.setup_mnemonic_nopin_nopassphrase()

        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[2147483692,2147483708,2147483648,0,0],
            nonce=0xab,
            gas_price=0x24c988ac00,
            gas_limit=0x26249,
            value=0x2386f26fc10000,
            to=binascii.unhexlify('def1c0ded9bec7f1a1670819833240f027b25eff'),
            address_type=0,
            chain_id=1,
            # func sel: tradeAndSend(address from,address to,address recipient,uint256 fromAmount,address[] exchanges,address[] approvals,bytes data,uint256[] offsets,uint256[] etherValues,uint256 limitAmount,uint256 tradeType )
            data=binascii.unhexlify('ef3f3d0b' +
              '000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48' +
              '000000000000000000000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee' +
              '000000000000000000000000b25c9552a91dd8c7e64ed444fb4aa5ac4dca5c9d' +
              '00000000000000000000000000000000000000000000000000000000000f4240' +
              '0000000000000000000000000000000000000000000000000000000000000160' +
              '00000000000000000000000000000000000000000000000000000000000001e0' +
              '0000000000000000000000000000000000000000000000000000000000000260' +
              '0000000000000000000000000000000000000000000000000000000000000420' +
              '00000000000000000000000000000000000000000000000000000000000004c0' +
              '0000000000000000000000000000000000000000000000000001fde92d4e8a1d' +
              '0000000000000000000000000000000000000000000000000000000000000000' +
              '0000000000000000000000000000000000000000000000000000000000000003' +
              '000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48' +
              '000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48' +
              '0000000000000000000000007a250d5630b4cf539739df2c5dacb4c659f2488d' +
              '0000000000000000000000000000000000000000000000000000000000000003' +
              '0000000000000000000000000000000000000000000000000000000000000000' +
              '0000000000000000000000000000000000000000000000000000000000000000' +
              '0000000000000000000000007a250d5630b4cf539739df2c5dacb4c659f2488d' +
              '000000000000000000000000000000000000000000000000000000000000018c' +
              '095ea7b3' +
              '0000000000000000000000007a250d5630b4cf539739df2c5dacb4c659f2488d' +
              '0000000000000000000000000000000000000000000000000000000000000000' +
              '095ea7b3' +
              '0000000000000000000000007a250d5630b4cf539739df2c5dacb4c659f2488d' +
              'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' +
              '18cbafe5' +
              '00000000000000000000000000000000000000000000000000000000000f4240' +
              '0000000000000000000000000000000000000000000000000000000000000001' +
              '00000000000000000000000000000000000000000000000000000000000000a0' +
              '000000000000000000000000b76c291871b92a7c9e020b2511a3402a3bf0499d' +
              '00000000000000000000000000000000000000000000000000000000602cb5fe' +
              '0000000000000000000000000000000000000000000000000000000000000002' +
              '000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48' +
              '000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2' +
              '0000000000000000000000000000000000000000000000000000000000000000' +
              '0000000000000000000000000000000000000004000000000000000000000000' +
              '0000000000000000000000000000000000000000000000000000000000000000' +
              '0000000000000000000000000000000000000044000000000000000000000000' +
              '0000000000000000000000000000000000000088000000000000000000000000' +
              '000000000000000000000000000000000000018c000000000000000000000000' +
              '0000000000000000000000000000000000000003000000000000000000000000' +
              '0000000000000000000000000000000000000000000000000000000000000000' +
              '0000000000000000000000000000000000000000000000000000000000000000' +
              '0000000000000000000000000000000000000000')
        )
        self.assertEqual(sig_v, 38)
        self.assertEqual(binascii.hexlify(sig_r), 'fc7f619f0b7d2b59757bbad8a5e5943fb49b1f67fe8eada1329435af48f4c119')
        self.assertEqual(binascii.hexlify(sig_s), '75afaec8233d4297d28cf63b23e593ffe4896bf53e3d156d6f13ae2ba6b4dae4')

if __name__ == '__main__':
    unittest.main()
