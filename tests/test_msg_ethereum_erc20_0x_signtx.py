# This file is part of the KEEPKEY project.
#
# Copyright (C) 2022 markrypto
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
from addSignedData import addSignedToken, addSignedIcon

class TestMsgEthereum0xtxERC20(common.KeepKeyTest):
    
    def test_fake_gnosis_swap(self):
        # NOTE: This test is completely made up data based on an eth tx/contract and would not work on the gnosis chain.
        # The signature, especially V, needs to be verified with an actual gnosis chain tx.
        # This test is just used to check the chain id and icon of gnosis chain

        self.requires_firmware("7.7.0")
        self.setup_mnemonic_nopin_nopassphrase()

        # add icon data
        retval = addSignedIcon(self, 'iconGnosis')
        self.assertEqual(retval.message, "Signed icon data received")

        # reset the token list
        retval = addSignedToken(self, 'resetToken')
        self.assertEqual(retval.message, "token list reset successfully")

        # add USDC gnosis token
        retval = addSignedToken(self, 'usdcTokenGnosis')
        self.assertEqual(retval.message, "Signed token received")

        # swap $2 of ETH to USDC
        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[2147483692,2147483708,2147483648,0,0],
            nonce=0xab,
            gas_price=0x24c988ac00,
            gas_limit=0x26249,
            value=0x2386f26fc10000,
            to=binascii.unhexlify('def1c0ded9bec7f1a1670819833240f027b25eff'),
            address_type=0,
            chain_id=0x64,
            # The data below is generally broken into 32-byte chunks except for the function selector (4 bytes_ and 
            # keccak signatures (4 bytes)
            data=binascii.unhexlify('d9627aa4' +                                        # SellToUniswap
                '0000000000000000000000000000000000000000000000000000000000000080' +    # offset of dynamic params
                '0000000000000000000000000000000000000000000000000003fb33ddbf39e4' +    # sell amount
                '0000000000000000000000000000000000000000000000000000000000155cbf' +    # min buy amount
                '0000000000000000000000000000000000000000000000000000000000000001' +    # isSushi
                '0000000000000000000000000000000000000000000000000000000000000002' +    # number of dynamic params
                '000000000000000000000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee' +    # ETH as an ERC20 test address
                '000000000000000000000000ddafbb505ad214d7b80b1f830fccc89b60fb7a83' +    # gnosis USDC contract
                '869584cd' +
                '000000000000000000000000c770eefad204b5180df6a14ee197d99d808ee52d' +    # Affiliate address? (FOX)
                '000000000000000000000000000000000000000000000033df43e4f8604fcda6')
        )
        self.assertEqual(sig_v, 236)
        self.assertEqual(binascii.hexlify(sig_r), 'eda97588fab7b148879e0e4da7feaa487883f41ffbe66c1a337fe51c465bca93')
        self.assertEqual(binascii.hexlify(sig_s), '5efc8d59e92a1486d7289223c5d5d48408ac9cbe0a450717efc1af0016d3eaea')

    def test_sign_0x_swap_ETH_to_ERC20(self):
        self.requires_firmware("7.7.0")
        self.setup_mnemonic_nopin_nopassphrase()

        # add icon data
        retval = addSignedIcon(self, 'iconEthereum')
        self.assertEqual(retval.message, "Signed icon data received")

        # reset the token list
        retval = addSignedToken(self, 'resetToken')
        self.assertEqual(retval.message, "token list reset successfully")

        # add USDC and USDT
        retval = addSignedToken(self, 'usdcToken')
        self.assertEqual(retval.message, "Signed token received")

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
        self.requires_firmware("7.7.0")
        self.setup_mnemonic_nopin_nopassphrase()

        # add icon data
        retval = addSignedIcon(self, 'iconEthereum')
        self.assertEqual(retval.message, "Signed icon data received")

        # reset the token list
        retval = addSignedToken(self, 'resetToken')
        self.assertEqual(retval.message, "token list reset successfully")

        # add USDC gnosis token
        retval = addSignedToken(self, 'usdcToken')
        self.assertEqual(retval.message, "Signed token received")

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
        self.requires_firmware("7.0.2")
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

    def test__sign_transformERC20(self):
        self.requires_firmware("7.7.0")
        self.setup_mnemonic_nopin_nopassphrase()

        # add icon data
        retval = addSignedIcon(self, 'iconEthereum')
        self.assertEqual(retval.message, "Signed icon data received")

        # reset the token list
        retval = addSignedToken(self, 'resetToken')
        self.assertEqual(retval.message, "token list reset successfully")

        # add USDC and USDT
        retval = addSignedToken(self, 'usdcToken')
        self.assertEqual(retval.message, "Signed token received")
        retval = addSignedToken(self, 'usdtToken')
        self.assertEqual(retval.message, "Signed token received")

        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            # Data from:
            # https://etherscan.io/tx/0xcf94f79dca849e5e386fc057d603058266a71f536c8dfa39cc9b1f3c619bbb40
            # (this tx will have a different signature of course)
            n=[2147483692,2147483708,2147483648,0,0],
            nonce=0xab,
            gas_price=0x55ae82600,
            gas_limit=0x5140e,
            value=0x0,
            to=binascii.unhexlify('def1c0ded9bec7f1a1670819833240f027b25eff'),
            address_type=0,
            chain_id=1,
            # The data below is generally broken into 32-byte chunks except for the function selector (4 bytes_ and 
            # keccak signatures (4 bytes)            
            data=binascii.unhexlify(
                '415565b0' +                                                         # transformERC20
                '000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7' + # input token USDT
                '000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48' + # output token USDC
                '0000000000000000000000000000000000000000000000000000000c5c360b9c' + # input token amount 53,086
                '0000000000000000000000000000000000000000000000000000000c58cb06ec' + # output token amount 53,029
                '00000000000000000000000000000000000000000000000000000000000000a0' + # The rest are transformations
                '0000000000000000000000000000000000000000000000000000000000000002' +
                '0000000000000000000000000000000000000000000000000000000000000040' +
                '0000000000000000000000000000000000000000000000000000000000000360' +
                '0000000000000000000000000000000000000000000000000000000000000013' +
                '0000000000000000000000000000000000000000000000000000000000000040' +
                '00000000000000000000000000000000000000000000000000000000000002c0' +
                '0000000000000000000000000000000000000000000000000000000000000020' +
                '0000000000000000000000000000000000000000000000000000000000000000' +
                '000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7' +
                '000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48' +
                '0000000000000000000000000000000000000000000000000000000000000120' +
                '0000000000000000000000000000000000000000000000000000000000000280' +
                '0000000000000000000000000000000000000000000000000000000000000280' +
                '0000000000000000000000000000000000000000000000000000000000000260' +
                '0000000000000000000000000000000000000000000000000000000c5c360b9c' +
                '0000000000000000000000000000000000000000000000000000000000000000' +
                '0000000000000000000000000000000000000000000000000000000000000001' +
                '0000000000000000000000000000000000000000000000000000000000000020' +
                '0000000000000000000000000000000a446f646f000000000000000000000000' +
                '0000000000000000000000000000000000000000000000000000000c5c360b9c' +
                '0000000000000000000000000000000000000000000000000000000c58cb06ec' +
                '0000000000000000000000000000000000000000000000000000000000000080' +
                '0000000000000000000000000000000000000000000000000000000000000060' +
                '000000000000000000000000533da777aedce766ceae696bf90f8541a4ba80eb' +
                '000000000000000000000000c9f93163c99695c6526b799ebca2207fdf7d61ad' +
                '0000000000000000000000000000000000000000000000000000000000000001' +
                '0000000000000000000000000000000000000000000000000000000000000001' +
                '0000000000000000000000000000000000000000000000000000000000000000' +
                '0000000000000000000000000000000000000000000000000000000000000007' +
                '0000000000000000000000000000000000000000000000000000000000000040' +
                '0000000000000000000000000000000000000000000000000000000000000100' +
                '0000000000000000000000000000000000000000000000000000000000000020' +
                '0000000000000000000000000000000000000000000000000000000000000040' +
                '00000000000000000000000000000000000000000000000000000000000000c0' +
                '0000000000000000000000000000000000000000000000000000000000000003' +
                '000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7' +
                '000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48' +
                '000000000000000000000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee' +
                '0000000000000000000000000000000000000000000000000000000000000000' +
                '869584cd000000000000000000000000c770eefad204b5180df6a14ee197d99d' +
                '808ee52d0000000000000000000000000000000000000000000000da413736cc' +
                '60c8dd4e')
        )       
        self.assertEqual(sig_v, 37)
        self.assertEqual(binascii.hexlify(sig_r), '5ea245ddd00fdf3958d6223255e37dcb0c61fa62cfa9cfb25e507da16ec8d96a')
        self.assertEqual(binascii.hexlify(sig_s), '6c428730776958b80fd2b2201600420bb49059f9b34ee3b960cdcce45d4a1e09')

if __name__ == '__main__':
    unittest.main()
