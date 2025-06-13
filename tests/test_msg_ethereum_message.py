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

from keepkeylib import tools


class TestMsgEthereumMessage(common.KeepKeyTest):
    def test_ethereum_sign_message(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()

        retval = self.client.ethereum_sign_message(
            n = tools.parse_path("m/44'/60'/0'/0/0"),
            message = b'\xee\xf8\x1f\x6d\x25\x17\xf4\x20\xfc\x0f\x59\x68\x4f\xb3\xd4\xcb\x9e\xbd\xf0\xbb\x3a\x8f\x60\x75\xb9\xc5\xe1\xf3\x21\x02\x31\xf0'
            
        ) 
        self.assertEqual(retval.address.hex(), '3f2329c9adfbccd9a84f52c906e936a42da18cb8')
        self.assertEqual(binascii.hexlify(retval.signature), '040e7fb8c22e401828380daac1cff745dc7f8a6993009f06c3de83ef63ba33de54a735cbbba174b2527b85a116205e4cda442d439ecb784006d960a612900e3c1b')

    def test_ethereum_sign_message_from_metamask(self):
        # This test data is what is used on the Shapeshift native wallet
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()

        retval = self.client.ethereum_sign_message(
            n = tools.parse_path("m/44'/60'/0'/0/0"),
            message = bytes("Hello, world!", 'utf8')
        )         
        self.assertEqual(retval.address.hex(), '3f2329c9adfbccd9a84f52c906e936a42da18cb8')
        self.assertEqual(binascii.hexlify(retval.signature), '111128bb8685b85843d423fa4844f2b4521b6e5aae8a5f7e1cc09bf9da116d5e27df6c7abb170853ca874fd9c4b413dd35a3c63e5a7d47594391a758b09d000f1b')
 
    def test_ethereum_verify_message(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()

        retval = self.client.ethereum_verify_message(
            addr = b'\x3f\x23\x29\xc9\xad\xfb\xcc\xd9\xa8\x4f\x52\xc9\x06\xe9\x36\xa4\x2d\xa1\x8c\xb8',
            signature = b'KCuM\xde\\=>X8\xa7\\\xbf\xdb\xa7.u\xb3\x159\x7f\xb5\xd9X\x01\x96\x1a\xf0N\xa5\xf2*R\x8f\xa4.\xc8\x8an~\xaa\xdb[\xe3\x97:\x1b\x8cqI\x97L\x8a \xf3\xac\x18\xa5F/\xf5\x8e^\xba\x1b',
            message = bytes("Good evening markrypto, want to play a game?", 'utf8')
        )

        retval = self.client.ethereum_sign_message(
            n = tools.parse_path("m/44'/60'/0'/0/0"),
            message = bytes("Good evening markrypto, want to play a game?", 'utf8')
        )            
        self.assertEqual(retval.address.hex(), '3f2329c9adfbccd9a84f52c906e936a42da18cb8')
        self.assertEqual(binascii.hexlify(retval.signature), '4b43754dde5c3d3e5838a75cbfdba72e75b315397fb5d95801961af04ea5f22a528fa42ec88a6e7eaadb5be3973a1b8c7149974c8a20f3ac18a5462ff58e5eba1b')
   
    def test_ethereum_sign_message_from_nativedata(self):
        # This test data is what is used on the Shapeshift native wallet
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()

        retval = self.client.ethereum_sign_message(
            n = tools.parse_path("m/44'/60'/0'/0/0"),
            message = bytes("Hello world 111", 'utf8')
        )         
        self.assertEqual(retval.address.hex(), '3f2329c9adfbccd9a84f52c906e936a42da18cb8')
        self.assertEqual(binascii.hexlify(retval.signature), '05a0edb4b98fe6b6ed270bf55aef84ddcb641512e19e340bf9eed3427854a7a4734fe45551dc24f1843cf2c823a73aa2454e3785eb15120573c522cc114e472d1c')
   
    def test_ethereum_sign_bytes(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()

        retval = self.client.ethereum_sign_message(
            n = tools.parse_path("m/44'/60'/0'/0/0"),
            message = b'\x1d\xf3\xd1\x0b\xe9\x35\xab\xc6\x3b\x65\x61\xcb\x61\x48\xb7\x45'
        )
            
        self.assertEqual(retval.address.hex(), '3f2329c9adfbccd9a84f52c906e936a42da18cb8')
        self.assertEqual(binascii.hexlify(retval.signature), 'fc44af700a747a68b1b79170dd46fb5aad2ffe2aee2a6a9ef653a29350967daf1bf62ffb84a3523356baff572d1b1285a14036212e69a26ca194adb53a0e22a61b')

    def test_ethereum_verify_message(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()

        retval = self.client.ethereum_verify_message(
            addr = b'\x3f\x23\x29\xc9\xad\xfb\xcc\xd9\xa8\x4f\x52\xc9\x06\xe9\x36\xa4\x2d\xa1\x8c\xb8',
            signature = b'KCuM\xde\\=>X8\xa7\\\xbf\xdb\xa7.u\xb3\x159\x7f\xb5\xd9X\x01\x96\x1a\xf0N\xa5\xf2*R\x8f\xa4.\xc8\x8an~\xaa\xdb[\xe3\x97:\x1b\x8cqI\x97L\x8a \xf3\xac\x18\xa5F/\xf5\x8e^\xba\x1b',
            message = bytes("Good evening markrypto, want to play a game?", 'utf8')
        )
        
        self.assertEqual(retval.message, 'Message verified')

    def test_ethereum_verify_bytes(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()

        retval = self.client.ethereum_verify_message(
            addr = b'\x3f\x23\x29\xc9\xad\xfb\xcc\xd9\xa8\x4f\x52\xc9\x06\xe9\x36\xa4\x2d\xa1\x8c\xb8',
            signature = b'\xfcD\xafp\ntzh\xb1\xb7\x91p\xddF\xfbZ\xad/\xfe*\xee*j\x9e\xf6S\xa2\x93P\x96}\xaf\x1b\xf6/\xfb\x84\xa3R3V\xba\xffW-\x1b\x12\x85\xa1@6!.i\xa2l\xa1\x94\xad\xb5:\x0e"\xa6\x1b',
            message = b'\x1d\xf3\xd1\x0b\xe9\x35\xab\xc6\x3b\x65\x61\xcb\x61\x48\xb7\x45'
        )
        
        self.assertEqual(retval.message, 'Message verified')

if __name__ == "__main__":
    unittest.main()
