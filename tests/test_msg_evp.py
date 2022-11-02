#
# Copyright (C) 2022 markrypto <cryptoakorn@gmail.com>
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
import json

from keepkeylib import tools
from addSignedData import addSignedToken, addSignedIcon

class TestMsgEthvm(common.KeepKeyTest): 
    def test_ethereum_verify_message_token(self):  
             
        # if self.client.features.firmware_variant == "Emulator":
        #     self.skipTest("Skip until emulator issue resolved")
        #     return
        
        self.requires_firmware("7.6.0")
        f = open('evptests.json')
        test = json.load(f)
        f.close()
        
        self.client.load_device_by_mnemonic(mnemonic=test['mnemonic'], pin='', passphrase_protection=False, label='test', language='english')
        
        # add icon data
        retval = addSignedIcon(self, 'iconEthereum')
        self.assertEqual(retval.message, "Signed icon data received")
        
        # reset the token list
        retval = addSignedToken(self, 'resetToken')
        self.assertEqual(retval.message, 'token list reset successfully')

        # add USDC and USDT
        retval = addSignedToken(self, 'usdcToken')
        self.assertEqual(retval.message, "Signed token received")
        retval = addSignedToken(self, 'usdtToken')
        self.assertEqual(retval.message, "Signed token received")
        
        # sign a transaction using USDC and USDT            
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


if __name__ == "__main__":
    unittest.main()
